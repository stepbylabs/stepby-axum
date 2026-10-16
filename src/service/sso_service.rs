//! 单点登录 / OIDC Provider（SSO server 角色）Service 层
//!
//! 本系统作为**授权服务器**，向企业内部已注册应用（sys_oauth_client）签发令牌。
//! 采用 OAuth2.1 风格的授权码流程 + **强制 PKCE(S256)**，ID Token 以 **HS256 对称密钥**
//! （每客户端独立 `id_token_secret`）签发，无 JWKS。
//!
//! 端点：
//! - `discovery(base)`            → OIDC 发现文档（bare JSON）
//! - `authorize(params, ...)`     → 解析会话 Cookie → 校验 client/redirect_uri/PKCE/scope →
//!   需要同意则引导至同意页，否则签发一次性授权码 → 302 回跳
//! - `token(params, ...)`         → 校验 client_secret + 一次性授权码 + PKCE → 签发 access/id token
//! - `userinfo(bearer, ...)`      → 校验 access_token（须为本模块签发）→ 按 scope 返回身份声明
//! - `consent_redirect(user, ...)`→ 同意页批准：记录授权 + 签发授权码 → 回跳
//! - 客户端 CRUD：分页 / 详情 / 新增 / 修改 / 批量删除 / 启停
//!
//! 安全红线：
//! - 明文 client_secret 仅创建时返回一次，落库只存 SHA-256 摘要；id_token_secret 永不外泄；
//! - 授权码一次性（共享态原子 GETDEL + 短 TTL），绑定 client_id + redirect_uri + code_challenge；
//! - PKCE 强制 S256（拒绝 plain / 缺失）；redirect_uri **精确匹配**白名单（防开放重定向）；
//! - token / userinfo 错误按 RFC 6749/7591 返回 `{"error","error_description"}`（bare JSON，非信封）。
//!
//! 分层约束：不依赖 axum/tower；SharedStore / JwtConfig / SsoConfig 由调用方注入。

use base64::Engine as _;
use sea_orm::DatabaseConnection;
use sea_orm::Set;
// B-1：delete_clients 需在单事务内完成级联（begin/commit），故引入 TransactionTrait
use sea_orm::TransactionTrait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ts_rs::TS;
use utoipa::{IntoParams, ToSchema};

use crate::common::datetime;
use crate::common::error::ServiceError;
use crate::config::settings::SsoConsentTicketMode;
use crate::config::{JwtConfig, SsoConfig};
use crate::entity::sys_oauth_client::{ActiveModel as ClientActiveModel, Model as ClientModel};
use crate::jwt::claims::JwtUtils;
use crate::repository::sys_oauth_client::SysOauthClientRepository;
use crate::repository::sys_oauth_consent::SysOauthConsentRepository;
use crate::shared_store::SharedStore;

/// 授权码 Redis key 前缀
const CODE_KEY_PREFIX: &str = "sso:code:";
/// access_token（不透明令牌，v4-P0-A）Redis key 前缀：key = `sso:at:{sha256(token)}`
const AT_KEY_PREFIX: &str = "sso:at:";
/// 用户 → 已签发 SSO access_token 集合（v4-F2）：登出/强退/改密时按用户全量吊销
const USER_AT_KEY_PREFIX: &str = "sso:user_at:";
/// 登录会话索引（v3-P0-B）：`sso:sess:{uid}` = Set(token_hash)，end_session 时定位该用户全部登录会话
const SESS_KEY_PREFIX: &str = "sso:sess:";
/// v5-D3：refresh_token（不透明令牌）Redis key 前缀：key = `sso:rt:{sha256(token)}`
const RT_KEY_PREFIX: &str = "sso:rt:";
/// v5-D3：用户 → 已签发 refresh_token 集合：登出/强退/改密时按用户全量吊销
const USER_RT_KEY_PREFIX: &str = "sso:user_rt:";
/// v5-D9：同意票据 Redis key 前缀（`key = sso:consent_ticket:{ticketId}`）。
///
/// 票据是**服务端真相**（随机 id + 票面 JSON + TTL），不引入新的签名密钥——
/// 与 webauthn 挑战态"SETEX + TTL"同法，避免"多一把密钥要轮换/要保管"的额外负担。
const CONSENT_TICKET_KEY_PREFIX: &str = "sso:consent_ticket:";
/// client_id 保留字（v4 §1.3）：禁止与协议自身命名空间/常见系统字冲突。
/// 注意：与平台 jwt.audience / jwt.issuer 的碰撞校验是**动态比对配置**（见 add_client），
/// 静态表只兜底通用保留字，不兜底可配置值。
const RESERVED_CLIENT_IDS: &[&str] = &[
    "sso", "oidc", "oauth", "oauth2", "admin", "system", "api", "internal", "stepby",
];

// ==================== 对外 DTO / VO ====================

/// 客户端出参 VO（脱敏：不含 client_secret / client_secret_hash / id_token_secret）
///
/// 属「应用私有 API」（我方 SPA 消费）→ camelCase + ts-rs 导出，前端复用生成类型。
#[derive(Debug, Clone, Serialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SsoClientVo.ts", rename_all = "camelCase")]
#[schema(as = SsoClientVo)]
pub struct SsoClientVo {
    pub sso_client_id: i64,
    pub client_id: String,
    pub client_name: String,
    pub logo_uri: String,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub grant_types: Vec<String>,
    /// v5-D2：ID Token 签名算法（RS256/HS256）
    pub id_token_alg: String,
    /// v5-D5：subject 标识类型（public/pairwise）
    pub subject_type: String,
    /// v5-D5：sector 聚合标识（https URL；NULL = 以 client_id 为 salt）
    pub sector_identifier_uri: Option<String>,
    pub consent_required: String,
    pub enabled: String,
    pub remark: Option<String>,
    pub create_time: Option<String>,
}

/// 客户端分页查询条件
#[derive(Debug, Clone, Deserialize, ToSchema, TS, IntoParams)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SsoClientQueryDto.ts", rename_all = "camelCase")]
#[schema(as = SsoClientQueryDto)]
pub struct SsoClientQueryDto {
    #[serde(default)]
    #[ts(optional)]
    pub page_num: Option<u64>,
    #[serde(default)]
    #[ts(optional)]
    pub page_size: Option<u64>,
    #[serde(default)]
    #[ts(optional)]
    pub client_name: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub client_id: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub enabled: Option<String>,
}

/// 客户端新增/修改入参
#[derive(Debug, Clone, Deserialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SsoClientUpsertDto.ts", rename_all = "camelCase")]
#[schema(as = SsoClientUpsertDto)]
pub struct SsoClientUpsertDto {
    /// 修改时必填（内部主键）；新增时忽略
    #[serde(default)]
    pub sso_client_id: i64,
    /// 公开标识：新增可留空自动生成；修改必填且不可改
    #[serde(default)]
    #[ts(optional)]
    pub client_id: Option<String>,
    pub client_name: String,
    #[serde(default)]
    #[ts(optional)]
    pub logo_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    #[serde(default)]
    #[ts(optional)]
    pub grant_types: Option<Vec<String>>,
    /// v5-D2：ID Token 签名算法（RS256/HS256，默认 RS256；改回 HS256 用 id_token_secret 对称验签）
    #[serde(default)]
    #[ts(optional)]
    pub id_token_alg: Option<String>,
    /// v5-D5：subject 标识类型（public/pairwise，默认 public；**切换会使已发令牌的
    /// sub 变化，RP 侧视为新用户**——修改时后端强制确认提示由前端承担）
    #[serde(default)]
    #[ts(optional)]
    pub subject_type: Option<String>,
    /// v5-D5：sector 聚合标识（https URL；pairwise 下同 sector 的多个 RP 获得相同
    /// sub；留空 = 以 client_id 为 salt）
    #[serde(default)]
    #[ts(optional)]
    pub sector_identifier_uri: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub consent_required: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub enabled: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub remark: Option<String>,
}

/// 新增结果：明文 client_secret 仅此一次返回
#[derive(Debug, Clone, Serialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    export_to = "SsoClientCreateResult.ts",
    rename_all = "camelCase"
)]
#[schema(as = SsoClientCreateResult)]
pub struct SsoClientCreateResult {
    pub client_id: String,
    pub client_secret: String,
    pub client: SsoClientVo,
}

/// SSO D9：`client_secret` 轮换结果（**新密钥明文仅此一次返回**，不落库）。
///
/// 与 [`SsoClientCreateResult`] 刻意分开：轮换**不**回带 client 详情（避免与
/// `edit` 语义混淆），调用方拿到明文后应立即写入 RP 配置。
#[derive(Debug, Clone, Serialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    export_to = "SsoClientRotateResult.ts",
    rename_all = "camelCase"
)]
#[schema(as = SsoClientRotateResult)]
pub struct SsoClientRotateResult {
    pub client_id: String,
    pub client_secret: String,
}

// ==================== OIDC 端点内部结构 ====================

/// 授权码 Redis 绑定（一次性，绑定 client + redirect_uri + PKCE challenge）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodeBinding {
    client_id: String,
    user_id: i64,
    username: String,
    /// 昵称（v4 §6，issue_code_redirect 时查 sys_user 填充；旧绑定 JSON 缺省空串）
    #[serde(default)]
    nick_name: String,
    /// 邮箱（v4 §6，email scope 数据链路）
    #[serde(default)]
    email: String,
    /// access_token 的 SHA-256 哈希（v4 C7：ID Token 的 at_hash 计算用；兑换时写入）
    #[serde(default)]
    access_token_hash: String,
    /// v5-E5：用户是否启用 TOTP（authorize 时点快照 → ID Token acr/amr claim；
    /// 旧绑定 JSON 缺省 false）
    #[serde(default)]
    totp_enabled: bool,
    /// v5-N2 Phase 1：租户 ID（会话用户所属租户，当前恒 0；Phase 2 隔离过滤键）
    #[serde(default)]
    tid: i64,
    redirect_uri: String,
    scope: Vec<String>,
    code_challenge: String,
    nonce: Option<String>,
    auth_time: i64,
}

/// access_token 绑定（v4-P0-A：access_token 为**不透明令牌**，本结构是其唯一载体，
/// 存于 `sso:at:{sha256(token)}`；平台业务路由对不透明串在 JWT 解码阶段即 401，天然隔离）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessBinding {
    client_id: String,
    user_id: i64,
    username: String,
    /// 昵称（v4 §6：name claim 用昵称而非登录名，避免向 RP 泄漏工号/内部登录名）
    #[serde(default)]
    nick_name: String,
    /// 邮箱（v4 §6：email scope 的真实数据链路，token 签发时查 sys_user 写入）
    #[serde(default)]
    email: String,
    scope: Vec<String>,
    /// 用户认证时刻（UTC 秒，v3 P1'-1：取登录 JWT 的 iat，而非授权时刻）
    #[serde(default)]
    auth_time: i64,
    /// v5-N2 Phase 1：租户 ID（随码继承；旧绑定 JSON 缺省 0）
    #[serde(default)]
    tid: i64,
    /// 绝对过期时刻（UTC 秒；SharedStore trait 无 TTL 读取语义，内省/exp 判定改由
    /// 绑定值自带：issue_access_token 写入 now + at_ttl）。旧绑定 JSON 缺省 None——
    /// 内省按 fail-safe 返回 inactive（RFC 7662 允许保守不报告），RT 校验放行
    /// （底层键 TTL / expire_at 列仍在物理过期该键，兜底不缺失）。
    #[serde(default)]
    exp_at: Option<i64>,
}

/// v5-D3：refresh_token 绑定（不透明令牌，存于 `sso:rt:{sha256(token)}`）。
/// 与 AccessBinding 同构（scope/身份快照），轮换式使用：每次刷新旧 RT 原子作废、签发新 RT。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RefreshBinding {
    client_id: String,
    /// 用户 ID（租户踢线按 legacy 回查 `sys_user.tenant_id` 时需要）
    pub(crate) user_id: i64,
    username: String,
    #[serde(default)]
    nick_name: String,
    #[serde(default)]
    email: String,
    scope: Vec<String>,
    /// 用户认证时刻（继承授权码绑定的 auth_time，id_token 重签保持一致）
    #[serde(default)]
    auth_time: i64,
    /// 租户 ID（租户踢线按此精确匹配；旧绑定缺省 0 时回退用户归属查询）
    #[serde(default)]
    pub(crate) tid: i64,
    /// 绝对过期时刻（UTC 秒；issue_refresh_token 写入 now + rt_ttl）。RT 轮换消费时
    /// 与 now 比对即可判定过期（原 Redis TTL 自动过期的等价承载）。旧绑定缺省 None
    /// 时放行——redis 档键 TTL 与 local 档 expire_at 列仍负责物理过期，兜底不缺失。
    #[serde(default)]
    exp_at: Option<i64>,
}

/// authorize 请求参数（由 handler 从 query 解出后传入）
#[derive(Debug, Clone)]
pub struct AuthorizeParams {
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub response_type: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// v5-D4：OIDC Core §3.1.2.1 prompt（空格分隔；`login`=强制重认证，
    /// `none`=纯静默模式——任何交互需求都以 error 回跳，绝不出现登录/同意页）
    pub prompt: Option<String>,
    /// v5-D4：重认证阈值（秒）——auth_time 距今超过该值须重新认证（RFC 6749 扩展）
    pub max_age: Option<i64>,
    /// v5-D4：期望认证强度（宽松语义：acr 满足度以 id_token.acr 真实声明为准——v5-E5
    /// 已按用户 TOTP 启用状态真实签发 acr/amr；不满足时 RP 可依 claims essential 拒绝）
    pub acr_values: Option<String>,
}

/// consent 批准入参（同意页回传，属「应用私有 API」→ camelCase + ts-rs 导出；
/// 其字段值最终须与 authorize 的 OIDC 参数对齐，故在 service 内以 snake_case 落库）
#[derive(Debug, Clone, Deserialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SsoConsentDto.ts", rename_all = "camelCase")]
#[schema(as = SsoConsentDto)]
pub struct ConsentDto {
    pub client_id: String,
    #[serde(default)]
    #[ts(optional)]
    pub redirect_uri: Option<String>,
    pub scope: String,
    #[serde(default)]
    #[ts(optional)]
    pub state: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub nonce: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub code_challenge_method: Option<String>,
    pub approved: bool,
    /// 用户认证时刻（登录 JWT 的 iat，v3 P1'-1）：由前端从 Operator 身份透传；
    /// 缺省回退为当前时间（仅影响存量旧前端的 auth_time 精度，不阻断流程）
    #[serde(default)]
    #[ts(optional)]
    pub auth_time: Option<i64>,
    /// v5-D9：同意票据（`[sso].consent_ticket = required` 时必填；`off` 档被完全忽略）。
    ///
    /// 由 `authorize` 在判定需同意时签发、经 `/sso-consent?ticket=...` 交前端回传；
    /// 服务端据此比对"回显参数是否与票面逐字一致"，从而封堵"同意参数被中间人篡改"。
    #[serde(default)]
    #[ts(optional)]
    pub ticket: Option<String>,
}

/// v5-D9 同意票据的**票面**（存 Redis；`off` 档不产生）。
///
/// 只放"需要与提交值逐字比对"的参数 + 发起用户：票据**不携带**任何可被外部推导的密钥材料，
/// 校验完全在服务端完成（`redirect_uri` 存**已解析**值，`scope` 存**规范化**串）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentTicket {
    /// 发起 authorize 的用户（防"拿别人的票"）
    user_id: i64,
    client_id: String,
    /// **已解析**的回调地址（经白名单精确匹配后的服务端权威值）
    redirect_uri: String,
    /// **规范化**的 scope（空格连接的已授予集合）
    scope: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
}

/// 票面与本次提交参数的**逐字比对**（纯函数，便于不依赖 Redis 直接单测）。
///
/// 归一规则仅有"`None` 与空串等价"（前端 `q()` 对缺失 query 返回空串/undefined，二者语义相同）；
/// **不做**大小写/顺序/子集等模糊等价——任何实质差异都必须拒绝（可证伪"改了参数即 400"）。
#[allow(clippy::too_many_arguments)]
fn consent_ticket_matches(
    ticket: &ConsentTicket,
    user_id: i64,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: Option<&str>,
    nonce: Option<&str>,
    code_challenge: &str,
    code_challenge_method: &str,
) -> bool {
    let norm = |v: Option<&str>| v.unwrap_or_default().to_string();
    ticket.user_id == user_id
        && ticket.client_id == client_id
        && ticket.redirect_uri == redirect_uri
        && ticket.scope == scope
        && norm(ticket.state.as_deref()) == norm(state)
        && norm(ticket.nonce.as_deref()) == norm(nonce)
        && ticket.code_challenge == code_challenge
        && ticket.code_challenge_method == code_challenge_method
}

/// /sso/token 请求参数 —— **OAuth2/OIDC 协议面**（外部 RP 用标准客户端库调用），
/// 参数名由 RFC 6749 强制固定为 snake_case，不参与 camelCase / ts-rs 转换。
#[derive(Debug, Clone, Deserialize, Default, ToSchema)]
pub struct TokenParams {
    /// grant_type：token 端点必填；revoke 端点无此字段（serde default 兼容共用结构）
    #[serde(default)]
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// client_id / client_secret 支持两种认证方式（RFC 6749 §2.3）：
    /// `client_secret_post`（表单字段）与 `client_secret_basic`（Authorization: Basic 头，
    /// 由 handler 解析合并进本结构，v3 P1'-5）。二者均可能为 None，由 token() 统一校验。
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    /// v5-D3：refresh_token grant 的刷新令牌（grant_type=refresh_token 时必填）
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// v5-D3：RFC 7009 吊销请求的 token 参数（/sso/revoke 用）
    #[serde(default)]
    pub token: Option<String>,
}

/// /sso/token 成功响应（bare JSON）—— **协议面**，字段名由 OIDC 规范固定为 snake_case。
#[derive(Debug, Clone, Serialize)]
pub struct TokenResult {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
    pub id_token: String,
    /// v5-E2：授权用户名（审计用，登录日志记录"SSO 令牌签发"事件的主体；
    /// 多一个响应字段对标准 RP 客户端无害）
    pub user_name: String,
    /// v5-N2 Phase 2：授权用户的租户 ID（**仅服务端审计使用**，写入 sys_logininfor；
    /// `skip_serializing` 保证不改变 /sso/token 协议响应体）
    #[serde(skip_serializing)]
    pub tenant_id: i64,
    /// 台账 F-8：授权用户主键（**仅服务端审计使用**，写入 sys_logininfor.user_id 做不可变强关联；
    /// `skip_serializing` 保证不改变 /sso/token 协议响应体）
    #[serde(skip_serializing)]
    pub user_id: i64,
    /// v5-D3：刷新令牌（不透明串；仅 grant_types 含 refresh_token 的客户端签发时出现）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// v5-D3：refresh_token 有效期（秒；与 refresh_token 成对出现）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_expires_in: Option<u64>,
}

/// OAuth/OIDC 错误（bare JSON：`{"error","error_description"}`），非信封、非 ServiceError
#[derive(Debug, Clone)]
pub struct OidcError {
    pub code: &'static str,
    pub description: String,
}

impl OidcError {
    pub(crate) fn new(code: &'static str, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
        }
    }
}

/// authorize 处理结果（供 handler 决定跳转 / 报错）
#[derive(Debug)]
pub enum AuthorizeOutcome {
    /// 302 到给定绝对/相对 URL（携带 code 或 error 参数）
    Redirect(String),
    /// 未登录：302 到前端登录页（handler 负责拼 `/login?redirect=<相对 authorize 路径>`）
    NeedLogin,
    /// 需用户同意：携带同意页所需的回显参数（handler 拼前端 /sso-consent URL）
    NeedConsent(Box<ConsentEcho>),
    /// 不可回跳的硬错误（client_id 不存在 / redirect_uri 不在白名单等）
    HardError(ServiceError),
}

/// 同意页回显参数
#[derive(Debug, Clone)]
pub struct ConsentEcho {
    pub client_id: String,
    pub client_name: String,
    pub logo_uri: String,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    /// v5-D9：同意票据（仅 `[sso].consent_ticket = required` 时下发；`off` 恒 `None`
    /// ⇒ 关闭态同意页查询串与改造前逐字一致）。
    pub ticket: Option<String>,
}

/// 用户"已授权应用"条目（v4-R8 自助撤销授权页）。
/// client_name 取同意时的**快照**（客户端改名不追溯篡改用户已见的授权对象）。
#[derive(Debug, Clone, Serialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SsoGrantVo.ts", rename_all = "camelCase")]
pub struct SsoGrantVo {
    pub client_id: String,
    pub client_name: String,
    pub scopes: Vec<String>,
    /// 授权时刻（yyyy-MM-dd HH:mm:ss）；存量旧记录可能为空
    pub consented_at: Option<String>,
}

// ==================== Service ====================

/// SSO / OIDC Provider 服务。
///
/// `Clone`：仅由 `DatabaseConnection` + `String`/`Vec<String>` 组成（仓储与连接均已 `Clone`），
/// 克隆即共享同一连接池句柄，无状态复制语义 —— 供 `AppState` 同时注入多个消费方
/// （如 GDPR 匿名化服务复用其令牌吊销链路）使用。
#[derive(Clone)]
pub struct SsoService {
    client_repo: SysOauthClientRepository,
    consent_repo: SysOauthConsentRepository,
    /// 主密钥（CONFIG_ENC_KEY，v3-P1'-4：id_token_secret 以 enc2: 信封加密存储）
    enc_key: String,
    /// 动态保留字（v4 §1.3）：平台 jwt.audience / jwt.issuer 等可配置值，
    /// 构造时由调用方从配置注入，add_client 时与静态表一并比对。
    reserved_ids: Vec<String>,
}

impl SsoService {
    pub fn new(db: DatabaseConnection, enc_key: String, reserved_ids: Vec<String>) -> Self {
        Self {
            client_repo: SysOauthClientRepository::new(db.clone()),
            consent_repo: SysOauthConsentRepository::new(db),
            enc_key,
            reserved_ids,
        }
    }

    /// 查询用户资料（昵称/邮箱，v4 §6 email scope 数据链路；查不到返回空串，
    /// 不阻断授权流程——scope 按最小化原则不输出空 claim 之外的敏感信息）
    async fn lookup_user_profile(&self, user_id: i64) -> (String, String) {
        use sea_orm::EntityTrait;
        match crate::entity::sys_user::Entity::find_by_id(user_id)
            .one(self.client_repo.base().db())
            .await
        {
            Ok(Some(u)) => (u.nick_name.clone(), u.email.clone().unwrap_or_default()),
            _ => (String::new(), String::new()),
        }
    }

    /// 解密客户端 id_token_secret（v3-P1'-4）。
    /// - `enc2:` 前缀 → AES-256-GCM 解密（主密钥 CONFIG_ENC_KEY）；
    /// - 明文（迁移期存量）→ 直接返回并记 warn，等待启动回填任务加密；
    /// - 主密钥未配置且存量明文 → 明文返回（与 config_enc_key 的 fail-open 策略一致）。
    fn decrypt_client_secret(&self, stored: &str) -> String {
        if crate::utils::crypto::is_encrypted(stored) {
            match crate::utils::crypto::decrypt_config_value(stored, &self.enc_key) {
                Ok(v) => return v,
                Err(e) => {
                    tracing::error!("id_token_secret 解密失败（主密钥错误或数据损坏）: {}", e)
                }
            }
        } else if !self.enc_key.is_empty() {
            tracing::warn!("检测到未加密的存量 id_token_secret，等待启动回填任务处理");
            return stored.to_string();
        }
        stored.to_string()
    }

    // -------------------- 发现文档 --------------------

    /// 构造 OIDC 发现文档（bare JSON）
    ///
    /// v4 §5：本函数仅在 SSO enabled 时被调用（handler 层已拦截 disabled → 404），
    /// 非标准字段 `sso_enabled` 已移除（不再向匿名调用者暴露内部开关状态）。
    pub fn discovery(&self, issuer: &str, config: &SsoConfig) -> serde_json::Value {
        let issuer = issuer.trim_end_matches('/');
        let mut doc = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}/sso/authorize", issuer),
            "token_endpoint": format!("{}/sso/token", issuer),
            "userinfo_endpoint": format!("{}/sso/userinfo", issuer),
            "end_session_endpoint": format!("{}/sso/logout", issuer),
            // v5-D2：RS256 客户端公钥经 /sso/jwks 真实发布（kid=client_id）；
            // HS256 客户端仍按规范不发布公钥（对称密钥经注册通道分发）。
            "jwks_uri": format!("{}/sso/jwks", issuer),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            // v5-D3：refresh_token grant 与 RFC 7009 吊销端点声明
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "revocation_endpoint": format!("{}/sso/revoke", issuer),
            "revocation_endpoint_auth_methods_supported": [
                "client_secret_basic", "client_secret_post"
            ],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "HS256"],
            "scopes_supported": ["openid", "profile", "email"],
            // v3-P1-7：同时声明 client_secret_basic（大量 RP 客户端库默认 Basic）
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            // v4 §6：claims_supported 与 scopes_supported 自洽（email scope 有对应 claim）
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
                "acr", "amr", "tid", "preferred_username", "name", "email", "email_verified"
            ],
        });
        // v5-D3 尾项（批次 4）：内省端点仅在开启时广告（RFC 8414 要求"广告了的端点必须真实可用"，
        // 故关闭态不出现——与端点本身 404 保持一致）。
        if config.introspection_enabled {
            doc["introspection_endpoint"] = serde_json::json!(format!("{}/sso/introspect", issuer));
            doc["introspection_endpoint_auth_methods_supported"] =
                serde_json::json!(["client_secret_basic", "client_secret_post"]);
        }
        doc
    }

    /// 解析 issuer：配置优先，回退请求 base_url
    pub fn resolve_issuer(&self, config: &SsoConfig, base_url: &str) -> String {
        if !config.issuer.trim().is_empty() {
            config.issuer.trim().to_string()
        } else {
            base_url.trim_end_matches('/').to_string()
        }
    }

    // -------------------- 授权端点 --------------------

    /// 处理 GET /sso/authorize
    ///
    /// `session_token` 为浏览器 `Admin-Token` Cookie 中的 JWT（未登录时为 None）。
    pub async fn authorize(
        &self,
        params: AuthorizeParams,
        session_token: Option<&str>,
        store: &Arc<dyn SharedStore>,
        jwt: &JwtConfig,
        config: &SsoConfig,
    ) -> Result<AuthorizeOutcome, ServiceError> {
        if !config.enabled {
            return Err(ServiceError::bad_request(&crate::tr!("error.sso.disabled")));
        }

        // 1. 解析会话（JWT 校验 + 黑名单）；未登录 → 引导登录。
        //    v5-D4：prompt=none 时改为向 RP 回跳 login_required（redirect_uri 可信前提下）。
        let identity = match self.resolve_session(session_token, store, jwt).await? {
            Some(id) => id,
            None => {
                if prompt_contains(&params, "none") {
                    // 回跳 error 前必须先确保 redirect_uri 可信（防开放重定向）
                    if let Some(ru) = self.validate_client_redirect_quiet(&params).await? {
                        return Ok(AuthorizeOutcome::Redirect(redirect_error_url(
                            Some(&ru),
                            &params.state,
                            "login_required",
                            &crate::tr!("error.sso.login_required"),
                        )));
                    }
                }
                return Ok(AuthorizeOutcome::NeedLogin);
            }
        };

        // 2. 校验客户端存在且启用
        let client = self
            .client_repo
            .find_by_client_id(&params.client_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.sso.client_not_found")))?;
        if client.enabled != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.client_disabled"
            )));
        }

        let whitelist: Vec<String> =
            serde_json::from_str(&client.redirect_uris).unwrap_or_default();
        let client_scopes: Vec<String> = serde_json::from_str(&client.scopes).unwrap_or_default();

        // 3. redirect_uri 解析（精确匹配白名单）；缺失/不匹配均不可信 → 硬错误，
        //    遵循 RFC 6749 §4.1.2.1：redirect_uri 缺失或不匹配时 MUST NOT 自动回跳。
        let redirect_uri =
            match self.resolve_redirect_uri(params.redirect_uri.as_deref(), &whitelist) {
                Some(u) => u,
                None => {
                    return Ok(AuthorizeOutcome::HardError(ServiceError::bad_request(
                        &crate::tr!("error.sso.redirect_uri_not_allowed"),
                    )));
                }
            };

        // 4. response_type / PKCE / scope 校验（此时 redirect_uri 已可信，错误回跳给 RP）
        if params.response_type != "code" {
            return Ok(AuthorizeOutcome::Redirect(redirect_error_url(
                Some(&redirect_uri),
                &params.state,
                "unsupported_response_type",
                &crate::tr!("error.sso.response_type_unsupported"),
            )));
        }
        let code_challenge = match params.code_challenge.as_deref() {
            Some(c) if !c.is_empty() => c.to_string(),
            _ => {
                return Ok(AuthorizeOutcome::Redirect(redirect_error_url(
                    Some(&redirect_uri),
                    &params.state,
                    "invalid_request",
                    &crate::tr!("error.sso.pkce_required"),
                )));
            }
        };
        if params.code_challenge_method.as_deref() != Some("S256") {
            return Ok(AuthorizeOutcome::Redirect(redirect_error_url(
                Some(&redirect_uri),
                &params.state,
                "invalid_request",
                &crate::tr!("error.sso.pkce_method_unsupported"),
            )));
        }
        let requested_all: Vec<String> = split_scope(&params.scope);
        if !requested_all.iter().any(|s| s == "openid") {
            return Ok(AuthorizeOutcome::Redirect(redirect_error_url(
                Some(&redirect_uri),
                &params.state,
                "invalid_scope",
                &crate::tr!("error.sso.openid_scope_required"),
            )));
        }
        // v3-P1'-6（互操作）：未注册/未知 scope **忽略**而非整体拒绝——主流 OIDC 客户端库
        // 默认请求 offline_access/address/phone 等，严格子集校验会让授权莫名失败。
        // 仅当忽略后没有任何有效 scope 时才报 invalid_scope。实际授予集合必须与
        // 同意页展示、code 绑定、token 响应三处一致（v4 §R4）。
        let requested: Vec<String> = requested_all
            .into_iter()
            .filter(|r| client_scopes.iter().any(|a| a == r))
            .collect();
        if requested.is_empty() {
            return Ok(AuthorizeOutcome::Redirect(redirect_error_url(
                Some(&redirect_uri),
                &params.state,
                "invalid_scope",
                &crate::tr!("error.sso.scope_invalid"),
            )));
        }

        // 4.5 v5-D4：重认证判定（prompt=login 强制；max_age 超龄强制）——
        //     prompt=none 回跳 login_required，否则引导重新登录。
        //     acr_values 宽松语义：本系统恒按用户 TOTP 状态签发真实 acr（v5-E5），
        //     RP 依 id_token.acr 自行判断满足度，此处不做硬拒绝。
        let needs_reauth = prompt_contains(&params, "login")
            || params
                .max_age
                .map(|ma| chrono::Utc::now().timestamp() - identity.auth_time > ma)
                .unwrap_or(false);
        if needs_reauth {
            if prompt_contains(&params, "none") {
                return Ok(AuthorizeOutcome::Redirect(redirect_error_url(
                    Some(&redirect_uri),
                    &params.state,
                    "login_required",
                    &crate::tr!("error.sso.login_required"),
                )));
            }
            return Ok(AuthorizeOutcome::NeedLogin);
        }

        // 5. 同意判定
        if client.consent_required == "1" {
            let granted = self
                .consent_repo
                .find_by_user_client(identity.user_id, &client.client_id)
                .await?;
            let need = match granted {
                None => true,
                Some(row) => {
                    let gv: Vec<String> = serde_json::from_str(&row.scopes).unwrap_or_default();
                    !scopes_subset(&requested, &gv)
                }
            };
            if need {
                // v5-D4：prompt=none 需要用户同意 → 回跳 consent_required（不出同意页）
                if prompt_contains(&params, "none") {
                    return Ok(AuthorizeOutcome::Redirect(redirect_error_url(
                        Some(&redirect_uri),
                        &params.state,
                        "consent_required",
                        &crate::tr!("error.sso.consent_required"),
                    )));
                }
                // v5-D9：同意票（`required` 才签发；`off` 恒 None ⇒ 关闭态零行为变更）
                let ticket = if config.consent_ticket_mode() == SsoConsentTicketMode::Required {
                    Some(
                        self.issue_consent_ticket(
                            store,
                            config,
                            identity.user_id,
                            &client.client_id,
                            &redirect_uri,
                            &requested,
                            params.state.as_deref(),
                            params.nonce.as_deref(),
                            &code_challenge,
                        )
                        .await?,
                    )
                } else {
                    None
                };
                return Ok(AuthorizeOutcome::NeedConsent(Box::new(ConsentEcho {
                    client_id: client.client_id.clone(),
                    client_name: client.client_name.clone(),
                    logo_uri: client.logo_uri.clone(),
                    scopes: requested.clone(),
                    redirect_uri,
                    state: params.state.clone(),
                    nonce: params.nonce.clone(),
                    code_challenge,
                    ticket,
                })));
            }
        }

        // 6. 直接签发授权码并回跳（auth_time 取登录会话的认证时刻，v3 P1'-1）
        let url = self
            .issue_code_redirect(
                identity.auth_time,
                identity.user_id,
                &identity.username,
                identity.tid,
                &client.client_id,
                &redirect_uri,
                &requested,
                &code_challenge,
                params.nonce.as_deref(),
                params.state.as_deref(),
                store,
                config,
            )
            .await?;
        Ok(AuthorizeOutcome::Redirect(url))
    }

    /// v5-D4：prompt=none 无会话时的静默校验——client 存在/启用 + redirect_uri 命中白名单
    /// 才允许向 RP 回跳 error（防开放重定向）。返回可信的 redirect_uri；校验不过返回 None。
    async fn validate_client_redirect_quiet(
        &self,
        params: &AuthorizeParams,
    ) -> Result<Option<String>, ServiceError> {
        let Some(client) = self
            .client_repo
            .find_by_client_id(&params.client_id)
            .await?
            .filter(|c| c.enabled == "1")
        else {
            return Ok(None);
        };
        let whitelist: Vec<String> =
            serde_json::from_str(&client.redirect_uris).unwrap_or_default();
        Ok(self.resolve_redirect_uri(params.redirect_uri.as_deref(), &whitelist))
    }

    /// v5-D9：签发**一次性同意票据**（随机 id 落 Redis，票面 = 回显参数 + 发起用户）。
    ///
    /// 只在 `[sso].consent_ticket = required` 时被调用；Redis 写入失败按内部错误返回
    /// （**fail-closed**：宁可让用户重来，也不能降级成"无票也放行"）。
    #[allow(clippy::too_many_arguments)]
    async fn issue_consent_ticket(
        &self,
        store: &Arc<dyn SharedStore>,
        config: &SsoConfig,
        user_id: i64,
        client_id: &str,
        redirect_uri: &str,
        requested: &[String],
        state: Option<&str>,
        nonce: Option<&str>,
        code_challenge: &str,
    ) -> Result<String, ServiceError> {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let ticket = ConsentTicket {
            user_id,
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: requested.join(" "),
            state: state.map(str::to_string),
            nonce: nonce.map(str::to_string),
            code_challenge: code_challenge.to_string(),
            // authorize 已强校验 code_challenge_method == S256（见上文第 4 步），此处随之固化
            code_challenge_method: "S256".to_string(),
        };
        let json = serde_json::to_string(&ticket)
            .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))?;
        let key = format!("{CONSENT_TICKET_KEY_PREFIX}{id}");
        store
            .set_ex(&key, &json, config.consent_ticket_ttl())
            .await
            .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))?;
        Ok(id)
    }

    /// 同意页批准 / 拒绝（受保护接口，用户身份来自登录态 Operator）
    pub async fn consent(
        &self,
        user_id: i64,
        username: &str,
        tid: i64,
        dto: ConsentDto,
        store: &Arc<dyn SharedStore>,
        config: &SsoConfig,
    ) -> Result<String, ServiceError> {
        if !config.enabled {
            return Err(ServiceError::bad_request(&crate::tr!("error.sso.disabled")));
        }
        let client = self
            .client_repo
            .find_by_client_id(&dto.client_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.sso.client_not_found")))?;
        if client.enabled != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.client_disabled"
            )));
        }
        let whitelist: Vec<String> =
            serde_json::from_str(&client.redirect_uris).unwrap_or_default();
        let client_scopes: Vec<String> = serde_json::from_str(&client.scopes).unwrap_or_default();
        let redirect_uri = self
            .resolve_redirect_uri(dto.redirect_uri.as_deref(), &whitelist)
            .ok_or_else(|| {
                ServiceError::bad_request(&crate::tr!("error.sso.redirect_uri_not_allowed"))
            })?;
        let requested: Vec<String> = split_scope(&dto.scope);
        if !scopes_subset(&requested, &client_scopes) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.scope_invalid"
            )));
        }

        // v5-D9：同意票校验（`required` 档才生效；`off` 档**完全跳过** = 改造前行为）。
        // 位置在"白名单/scopes 已收敛"之后、"批准/拒绝分流"之前 ⇒ **批准与拒绝都必须带票**。
        // 校验顺序刻意与错误文案解耦：所有失败一律返回同一条通用文案（不泄漏"票不存在"
        // 与"参数不符"的区别，避免成为票据探测侧信道）。
        if config.consent_ticket_mode() == SsoConsentTicketMode::Required {
            let invalid =
                || ServiceError::bad_request(&crate::tr!("error.sso.consent_ticket_invalid"));
            let ticket_id = dto.ticket.as_deref().unwrap_or_default().trim();
            if ticket_id.is_empty() {
                return Err(invalid());
            }
            let key = format!("{CONSENT_TICKET_KEY_PREFIX}{ticket_id}");
            let raw: Option<String> = store.get(&key).await.map_err(|_| invalid())?;
            let Some(ticket) = raw.and_then(|s| serde_json::from_str::<ConsentTicket>(&s).ok())
            else {
                return Err(invalid());
            };
            // 逐字比对（scope / redirect_uri 均用**服务端已解析/规范化**的值，
            // 从而同时封堵"改 redirectUri 到另一条白名单地址"与"改 scope"）
            if !consent_ticket_matches(
                &ticket,
                user_id,
                &dto.client_id,
                &redirect_uri,
                &requested.join(" "),
                dto.state.as_deref(),
                dto.nonce.as_deref(),
                dto.code_challenge.as_deref().unwrap_or_default(),
                dto.code_challenge_method.as_deref().unwrap_or_default(),
            ) {
                return Err(invalid());
            }
            // 校验通过 ⇒ **一次性消费**（批准与拒绝都消费；重放必然失败）。
            // DEL 失败不影响本次结果（票已通过校验），但会记 WARN 供运维发现存储异常。
            if let Err(e) = store.del(std::slice::from_ref(&key)).await {
                tracing::warn!(error = %e, "同意票据消费失败（DEL）；该票据在 TTL 内可能仍可重放");
            }
        }

        // 拒绝：回跳携带 access_denied（v3-P2'-3：错误描述不得误用"未登录"文案）
        if !dto.approved {
            return Ok(redirect_error_url(
                Some(&redirect_uri),
                &dto.state,
                "access_denied",
                &crate::tr!("error.sso.access_denied"),
            ));
        }

        let code_challenge = dto.code_challenge.clone().unwrap_or_default();
        if code_challenge.is_empty() || dto.code_challenge_method.as_deref() != Some("S256") {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.pkce_required"
            )));
        }

        // 记录同意（consented_at = 批准时刻；client_name 快照供"已授权应用"展示，v4-R6）
        let now = datetime::now_naive();
        self.consent_repo
            .upsert(
                user_id,
                tid,
                &client.client_id,
                &client.client_name,
                &serde_json::to_string(&requested)
                    .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))?,
                now,
            )
            .await?;

        // auth_time：同意页批准路径的身份来自登录态 Operator，其认证时刻由 handler 从
        // Claims.iat 传入（v3 P1'-1）；tid 随会话携带（v5-N2 Phase 1）
        self.issue_code_redirect(
            dto.auth_time
                .unwrap_or_else(|| chrono::Utc::now().timestamp()),
            user_id,
            username,
            tid,
            &client.client_id,
            &redirect_uri,
            &requested,
            &code_challenge,
            dto.nonce.as_deref(),
            dto.state.as_deref(),
            store,
            config,
        )
        .await
    }

    /// 解析一次性授权码并签发回跳 URL（供 authorize 直发与 consent 批准复用）
    ///
    /// `auth_time`：用户认证时刻（登录 JWT 的 iat，v3 P1'-1），随码绑定写入 ID Token。
    #[allow(clippy::too_many_arguments)]
    async fn issue_code_redirect(
        &self,
        auth_time: i64,
        user_id: i64,
        username: &str,
        tid: i64,
        client_id: &str,
        redirect_uri: &str,
        scope: &[String],
        code_challenge: &str,
        nonce: Option<&str>,
        state: Option<&str>,
        store: &Arc<dyn SharedStore>,
        config: &SsoConfig,
    ) -> Result<String, ServiceError> {
        let code = random_urlsafe(32);
        // v4 §6：查一次用户资料填充 email/nick_name（email scope 的真实数据链路；
        // 绑定随码缓存，token 兑换与 userinfo 无需再查库）
        let (nick_name, email) = self.lookup_user_profile(user_id).await;
        // v5-E5：TOTP 启用状态快照（totp:enabled:{uid}；fail-open 查询失败视为未启用，
        // 与登录链路 fail-closed 不同——此处仅影响 acr 声明强度，不涉放行决策）。
        // 原实现为 EXISTS：等价改写为 GET 命中即存在（键值不被消费）。
        let totp_enabled: bool = store
            .get(&format!("totp:enabled:{}", user_id))
            .await
            .map(|v| v.is_some())
            .unwrap_or(false);
        let binding = CodeBinding {
            client_id: client_id.to_string(),
            user_id,
            username: username.to_string(),
            nick_name,
            email,
            totp_enabled,
            tid,
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_vec(),
            code_challenge: code_challenge.to_string(),
            nonce: nonce.map(|s| s.to_string()),
            // v3 P1'-1：认证时刻（登录时点）而非授权时点
            auth_time,
            // v4 C7：授权码阶段尚未签发 AT，占位空串；token 端点签发后回填
            access_token_hash: String::new(),
        };
        let json = serde_json::to_string(&binding)
            .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))?;
        let key = format!("{}{}", CODE_KEY_PREFIX, code);
        store
            .set_ex(&key, &json, config.code_ttl_secs.max(1))
            .await
            .map_err(|e| {
                tracing::error!("SSO 授权码写入共享态存储失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.cache_failed"))
            })?;

        let sep = if redirect_uri.contains('?') { "&" } else { "?" };
        let mut url = format!("{}{}code={}", redirect_uri, sep, url_encode(&code));
        if let Some(st) = state
            && !st.is_empty()
        {
            url.push_str(&format!("&state={}", url_encode(st)));
        }
        Ok(url)
    }

    // -------------------- 令牌端点 --------------------

    /// 处理 POST /sso/token（authorization_code 交换 / refresh_token 刷新）
    ///
    /// v4-P0-A：`jwt` 参数已移除——access_token 不再是平台 JWT，无需平台签名密钥。
    /// v5-D3：新增 refresh_token grant（RFC 6749 §6）——RT 轮换式使用，
    /// 每次刷新旧 RT 原子作废（GETDEL 防并发双用）、签发新 AT + 新 RT + 重签 id_token。
    pub async fn token(
        &self,
        params: TokenParams,
        store: &Arc<dyn SharedStore>,
        config: &SsoConfig,
        base_url: &str,
    ) -> Result<TokenResult, OidcError> {
        if !config.enabled {
            return Err(OidcError::new(
                "invalid_request",
                crate::tr!("error.sso.disabled"),
            ));
        }
        match params.grant_type.as_str() {
            "authorization_code" => {
                self.token_authorization_code(params, store, config, base_url)
                    .await
            }
            "refresh_token" => self.token_refresh(params, store, config, base_url).await,
            _ => Err(OidcError::new(
                "unsupported_grant_type",
                crate::tr!("error.sso.grant_type_unsupported"),
            )),
        }
    }

    /// 客户端凭据校验（token/revoke 共用）：client_id/secret 来自表单或 Basic 头
    /// （handler 已合并），缺失/错误按 RFC 6749 §5.2 返回 invalid_client（401）。
    async fn verify_token_client(&self, params: &TokenParams) -> Result<ClientModel, OidcError> {
        let client_id = params
            .client_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                OidcError::new("invalid_client", crate::tr!("error.sso.client_not_found"))
            })?;
        let client = self
            .client_repo
            .find_by_client_id(client_id)
            .await
            .map_err(|_| {
                // v5 核查：DB 故障不是 invalid_grant（误导 RP 重试语义），按 server_error
                OidcError::new("server_error", crate::tr!("error.sso.client_auth_failed"))
            })?
            .ok_or_else(|| {
                OidcError::new("invalid_client", crate::tr!("error.sso.client_not_found"))
            })?;
        if client.enabled != "1" {
            return Err(OidcError::new(
                "invalid_client",
                crate::tr!("error.sso.client_disabled"),
            ));
        }
        let client_secret = params
            .client_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                OidcError::new("invalid_client", crate::tr!("error.sso.client_auth_failed"))
            })?;
        let expected_hash = crate::utils::crypto::token_hash(client_secret);
        // D9 双密钥读取期：轮换后**新密钥立即生效**，旧密钥摘要暂存 `previous_client_secret_hash`，
        // 过渡期内两把均可通过客户端鉴权（RP 换配置期间不断服）；过渡期结束清空该列即失效。
        // 两把均走等时比较，且**不短路**为"先比当前再比旧"的分支差异（两次比较恒发生）。
        let matches_current = secret_eq(&expected_hash, &client.client_secret_hash);
        let matches_previous = client
            .previous_client_secret_hash
            .as_deref()
            .map(|prev| secret_eq(&expected_hash, prev))
            .unwrap_or(false);
        if !matches_current && !matches_previous {
            return Err(OidcError::new(
                "invalid_client",
                crate::tr!("error.sso.client_auth_failed"),
            ));
        }
        if matches_previous {
            // 可观测信号：该 RP 仍在用旧密钥 ⇒ 提示运维"过渡期尚未结束"。
            tracing::warn!(
                client_id = %client.client_id,
                "SSO 客户端使用轮换前的旧 client_secret 完成鉴权（双密钥读取期内），请尽快为 RP 换配新密钥并结束过渡期"
            );
        }
        Ok(client)
    }

    /// v5-D3：签发 refresh_token（grant_types 含 refresh_token 的客户端才签发）。
    /// 返回 `Some((refresh_token, refresh_expires_in))`；不支持刷新的客户端返回 None。
    async fn issue_refresh_token(
        &self,
        client: &ClientModel,
        binding: &CodeBinding,
        store: &Arc<dyn SharedStore>,
        config: &SsoConfig,
    ) -> Result<Option<(String, u64)>, OidcError> {
        let grant_types: Vec<String> =
            serde_json::from_str(&client.grant_types).unwrap_or_default();
        if !grant_types.iter().any(|g| g == "refresh_token") {
            return Ok(None);
        }
        let rt = random_urlsafe(32);
        let rt_hash = crate::utils::crypto::token_hash(&rt);
        let rt_ttl = config.refresh_token_ttl_secs.max(1);
        let rt_binding = RefreshBinding {
            client_id: client.client_id.clone(),
            user_id: binding.user_id,
            username: binding.username.clone(),
            nick_name: binding.nick_name.clone(),
            email: binding.email.clone(),
            scope: binding.scope.clone(),
            auth_time: binding.auth_time,
            tid: binding.tid,
            // 绝对过期时刻随绑定写入：RT 轮换消费时比对即得「原 TTL 自动过期」等价语义
            exp_at: Some(chrono::Utc::now().timestamp() + rt_ttl as i64),
        };
        let json = serde_json::to_string(&rt_binding)
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;
        let rt_key = format!("{}{}", RT_KEY_PREFIX, rt_hash);
        store
            .set_ex(&rt_key, &json, rt_ttl)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;
        // 登记「用户 → RT」集合（登出/强退/改密全量吊销用），TTL 稍大于 RT TTL
        let user_rt_key = format!("{}{}", USER_RT_KEY_PREFIX, binding.user_id);
        store
            .set_add(&user_rt_key, &rt_hash, rt_ttl + 60)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;
        Ok(Some((rt, rt_ttl)))
    }

    /// v5-D3：签发 access_token（AT 绑定 + 在线会话 + 用户集合），authorization_code
    /// 与 refresh_token 两条 grant 共用。`binding.access_token_hash` 必须已由调用方回填。
    async fn issue_access_token(
        &self,
        client: &ClientModel,
        binding: &CodeBinding,
        store: &Arc<dyn SharedStore>,
        at_ttl: u64,
    ) -> Result<(), OidcError> {
        let at_binding = AccessBinding {
            client_id: client.client_id.clone(),
            user_id: binding.user_id,
            username: binding.username.clone(),
            nick_name: binding.nick_name.clone(),
            email: binding.email.clone(),
            scope: binding.scope.clone(),
            auth_time: binding.auth_time,
            tid: binding.tid,
            // 绝对过期时刻随绑定写入：内省据此计算 exp（trait 无 TTL 读取语义）
            exp_at: Some(chrono::Utc::now().timestamp() + at_ttl as i64),
        };
        let at_json = serde_json::to_string(&at_binding)
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;
        let at_key = format!("{}{}", AT_KEY_PREFIX, binding.access_token_hash);
        store
            .set_ex(&at_key, &at_json, at_ttl)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;
        // v4-F2：登记「用户 → 已签发 SSO AT」集合（登出/强退/改密全量吊销用）+ 在线可见。
        // 读路径有 EXISTS 悬空自愈（见 revoke_all_for_user），集合 TTL 稍大于 AT TTL。
        let user_at_key = format!("{}{}", USER_AT_KEY_PREFIX, binding.user_id);
        store
            .set_add(&user_at_key, &binding.access_token_hash, at_ttl + 60)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;
        // F2：写 online:{hash}（source=sso）→ 在线用户列表可见、管理员可强退
        let online = crate::utils::crypto::OnlineSession {
            user_id: binding.user_id,
            username: binding.username.clone(),
            ip: "sso".to_string(),
            login_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            browser: "SSO".to_string(),
            os: "-".to_string(),
            jti: format!("sso-at-{}", client.client_id),
            dept_name: String::new(),
            exp: chrono::Utc::now().timestamp() + at_ttl as i64,
            source: "sso".to_string(),
            // Phase 3：SSO 在线会话携带租户 ID（随授权码绑定继承，供租户分层展示/定向踢线）
            tenant_id: binding.tid,
        };
        if let Ok(json) = serde_json::to_string(&online) {
            let online_key = format!("online:{}", binding.access_token_hash);
            store
                .set_ex(&online_key, &json, at_ttl)
                .await
                .map_err(|_| {
                    OidcError::new("server_error", crate::tr!("error.sso.token_failed"))
                })?;
        }
        Ok(())
    }

    /// grant_type=authorization_code（RFC 6749 §4.1.3）
    async fn token_authorization_code(
        &self,
        params: TokenParams,
        store: &Arc<dyn SharedStore>,
        config: &SsoConfig,
        base_url: &str,
    ) -> Result<TokenResult, OidcError> {
        let code = params
            .code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| {
                OidcError::new("invalid_request", crate::tr!("error.sso.code_invalid"))
            })?;

        let client = self.verify_token_client(&params).await?;
        let client_id = client.client_id.clone();

        // 一次性取码（原子 GETDEL，防重放）
        let key = format!("{}{}", CODE_KEY_PREFIX, code);
        let binding_json = self
            .getdel_code(&key, store)
            .await?
            .ok_or_else(|| OidcError::new("invalid_grant", crate::tr!("error.sso.code_invalid")))?;
        let binding: CodeBinding = serde_json::from_str(&binding_json)
            .map_err(|_| OidcError::new("invalid_grant", crate::tr!("error.sso.code_invalid")))?;

        // 绑定一致性：client_id / redirect_uri。
        // v4 §7：authorize 携带了 redirect_uri 时，token 请求**必须**携带完全相同的值
        // （RFC 6749 §10.6），不留"未提供即通过"的口子——否则多回调地址的 RP 在 token
        // 阶段失去 redirect_uri 绑定防线。
        if binding.client_id != client_id {
            return Err(OidcError::new(
                "invalid_grant",
                crate::tr!("error.sso.code_invalid"),
            ));
        }
        match params.redirect_uri.as_deref().filter(|s| !s.is_empty()) {
            None => {
                return Err(OidcError::new(
                    "invalid_grant",
                    "redirect_uri required".to_string(),
                ));
            }
            Some(ru) if ru != binding.redirect_uri => {
                return Err(OidcError::new(
                    "invalid_grant",
                    crate::tr!("error.sso.redirect_uri_not_allowed"),
                ));
            }
            _ => {}
        }

        // PKCE 校验
        let verifier = params.code_verifier.as_deref().unwrap_or_default();
        if !pkce_verify(verifier, &binding.code_challenge) {
            return Err(OidcError::new(
                "invalid_grant",
                crate::tr!("error.sso.pkce_verify_failed"),
            ));
        }
        let mut binding = binding;
        // v4 C7：为 ID Token 的 at_hash 记录 access_token 哈希（在下方生成令牌后写入）

        // v4-P0-A：access_token 改为**不透明令牌**（random 32B，base64url）。
        // 旧实现复用平台 JWT（iss/aud 与登录令牌同构），可被用于横扫全站受保护 API（越权）；
        // 不透明令牌：① 平台路由在 JWT 解码阶段即 401（天然隔离，零中间件改动）；
        // ② DEL 绑定即即时吊销；③ 泄漏不暴露 claims。RP 一律通过 /sso/userinfo 消费。
        let access_token = random_urlsafe(32);
        let at_ttl = config.access_token_ttl_secs.max(1);
        let at_hash = crate::utils::crypto::token_hash(&access_token);
        binding.access_token_hash = at_hash.clone();
        // v5-D3：AT 签发（绑定 + 在线会话 + 用户集合）抽公共 helper 与 refresh grant 共用
        self.issue_access_token(&client, &binding, store, at_ttl)
            .await?;

        // 签发 id_token（v5-D2：按客户端声明算法 RS256/HS256）
        let id_token = self
            .build_id_token(&client, &binding, config, base_url)
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;

        // v5-D3：grant_types 含 refresh_token 的客户端签发 RT（轮换式）
        let (refresh_token, refresh_expires_in) = self
            .issue_refresh_token(&client, &binding, store, config)
            .await?
            .unzip();

        Ok(TokenResult {
            access_token,
            token_type: "Bearer",
            // v4-P0-A：expires_in 必须等于 access_token 的真实生命周期
            //（旧实现错用 id_token_ttl_secs，而 JWT exp 由 jwt.expire_hours 决定，两者严重不一致）
            expires_in: at_ttl,
            scope: binding.scope.join(" "),
            id_token,
            user_name: binding.username.clone(),
            // v5-N2 Phase 2：登录用户租户（写入登录日志用，不参与响应序列化）
            tenant_id: binding.tid,
            // 台账 F-8：登录用户主键（写入登录日志做不可变强关联，不参与响应序列化）
            user_id: binding.user_id,
            refresh_token,
            refresh_expires_in,
        })
    }

    /// grant_type=refresh_token（RFC 6749 §6 + v5-D3 轮换语义）
    ///
    /// 流程：客户端认证 → RT 原子取删（GETDEL，防并发双用/重放）→ 绑定校验
    /// → 签发新 AT + 新 RT（轮换）+ 重签 id_token。旧 RT 一经使用立即作废。
    async fn token_refresh(
        &self,
        params: TokenParams,
        store: &Arc<dyn SharedStore>,
        config: &SsoConfig,
        base_url: &str,
    ) -> Result<TokenResult, OidcError> {
        let rt = params
            .refresh_token
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OidcError::new("invalid_request", crate::tr!("error.sso.rt_invalid")))?;

        let client = self.verify_token_client(&params).await?;

        // RT 原子取删：并发双用/重放场景下只有第一次能取到（invalid_grant）
        let rt_hash = crate::utils::crypto::token_hash(rt);
        let rt_key = format!("{}{}", RT_KEY_PREFIX, rt_hash);
        let binding_json: Option<String> = store
            .consume(&rt_key)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.common.cache_failed")))?;
        let binding_json = binding_json
            .ok_or_else(|| OidcError::new("invalid_grant", crate::tr!("error.sso.rt_invalid")))?;
        let rt_binding: RefreshBinding = serde_json::from_str(&binding_json)
            .map_err(|_| OidcError::new("invalid_grant", crate::tr!("error.sso.rt_invalid")))?;

        // RT 过期校验（原 Redis TTL 自动过期的等价承载）：绑定 JSON 携带绝对过期时刻
        // exp_at（issue_refresh_token 写入 now + rt_ttl），已过即拒绝。exp_at 缺失
        // （迁移期存量绑定）放行——redis 档键 TTL / local 档 expire_at 列仍在物理
        // 过期该键，兜底不缺失。
        if let Some(exp_at) = rt_binding.exp_at
            && exp_at <= chrono::Utc::now().timestamp()
        {
            return Err(OidcError::new(
                "invalid_grant",
                crate::tr!("error.sso.rt_invalid"),
            ));
        }

        // RT 与请求客户端必须一致（防跨客户端盗用刷新）
        if rt_binding.client_id != client.client_id {
            return Err(OidcError::new(
                "invalid_grant",
                crate::tr!("error.sso.rt_invalid"),
            ));
        }

        // P0-1-c：租户运行时态闸门——RT 虽绑定租户，但停用/超期后存量 RT 不一定已清除
        // （会话踢线为 best-effort）。此处与鉴权中间件同口径复检（核对刚才即时的踢线结果）；
        // Redis 异常 **fail-closed**：宁可拒绝刷新，也绝不放行已停用租户的身份续期。
        // 宽限（Grace）**放行**：只读约束由业务中间件按写方法拦截，刷新端点不自创写拦截。
        if rt_binding.tid != 0 {
            let state_key = crate::common::tenant::tenant_state_key(rt_binding.tid);
            let exp_key = crate::common::tenant::tenant_expire_key(rt_binding.tid);
            let vals: Vec<Option<String>> =
                store.get_many(&[state_key, exp_key]).await.map_err(|_| {
                    OidcError::new("server_error", crate::tr!("error.common.cache_failed"))
                })?;
            let expire_epoch = vals
                .get(1)
                .and_then(|v| v.as_deref())
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            let runtime = crate::common::tenant::eval_tenant_runtime_state(
                vals.first().and_then(|v| v.as_deref()),
                expire_epoch,
                chrono::Utc::now().timestamp(),
            );
            if runtime == crate::common::tenant::TenantRuntimeState::Disabled {
                return Err(OidcError::new(
                    "invalid_grant",
                    crate::tr!("error.tenant.disabled"),
                ));
            }
        }

        // 由 RT 绑定还原 CodeBinding（id_token/AT 签发复用同一身份快照）
        let binding = CodeBinding {
            client_id: rt_binding.client_id.clone(),
            user_id: rt_binding.user_id,
            username: rt_binding.username.clone(),
            nick_name: rt_binding.nick_name.clone(),
            email: rt_binding.email.clone(),
            access_token_hash: String::new(),
            totp_enabled: false,
            tid: rt_binding.tid,
            redirect_uri: String::new(),
            scope: rt_binding.scope.clone(),
            code_challenge: String::new(),
            nonce: None,
            auth_time: rt_binding.auth_time,
        };

        // 签发新 AT（绑定 + 在线会话 + 用户集合）
        let access_token = random_urlsafe(32);
        let at_ttl = config.access_token_ttl_secs.max(1);
        let mut new_binding = binding;
        new_binding.access_token_hash = crate::utils::crypto::token_hash(&access_token);
        self.issue_access_token(&client, &new_binding, store, at_ttl)
            .await?;

        // 签发新 id_token
        let id_token = self
            .build_id_token(&client, &new_binding, config, base_url)
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;

        // RT 轮换：签发新 RT（旧 RT 已 GETDEL 作废）
        let (refresh_token, refresh_expires_in) = self
            .issue_refresh_token(&client, &new_binding, store, config)
            .await?
            .unzip();

        Ok(TokenResult {
            access_token,
            token_type: "Bearer",
            expires_in: at_ttl,
            scope: new_binding.scope.join(" "),
            id_token,
            user_name: new_binding.username.clone(),
            // v5-N2 Phase 2：登录用户租户（写入登录日志用，不参与响应序列化）
            tenant_id: new_binding.tid,
            // 台账 F-8：登录用户主键（写入登录日志做不可变强关联，不参与响应序列化）
            user_id: new_binding.user_id,
            refresh_token,
            refresh_expires_in,
        })
    }

    /// v5-D3：RFC 7009 令牌吊销（token/revoke 端点内部实现）。
    /// 吊销成功、token 无效、已吊销一律返回 Ok（规范 §2.2：防 token 枚举）；
    /// 客户端认证失败由调用方映射 401。
    pub async fn revoke_token(
        &self,
        params: &TokenParams,
        store: &Arc<dyn SharedStore>,
    ) -> Result<(), OidcError> {
        // 客户端认证（失败 → invalid_client 401，由 handler 映射）
        self.verify_token_client(params).await?;
        let Some(token) = params.token.as_deref().filter(|s| !s.is_empty()) else {
            // 缺 token 参数：按规范返回 200（不泄漏存在性）
            return Ok(());
        };
        let token_hash = crate::utils::crypto::token_hash(token);

        // AT 吊销：读绑定拿 user_id → 删绑定 + 在线会话 + 用户集合成员
        let at_key = format!("{}{}", AT_KEY_PREFIX, token_hash);
        let at_json: Option<String> = store
            .get(&at_key)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.common.cache_failed")))?;
        if let Some(json) = at_json {
            let user_id = serde_json::from_str::<AccessBinding>(&json)
                .map(|b| b.user_id)
                .unwrap_or(0);
            let _: Result<u64, _> = store.del(&[at_key, format!("online:{}", token_hash)]).await;
            if user_id > 0 {
                let _: Result<(), _> = store
                    .set_rem(&format!("{}{}", USER_AT_KEY_PREFIX, user_id), &token_hash)
                    .await;
            }
            return Ok(());
        }

        // RT 吊销：删绑定 + 用户集合成员（轮换链终止）
        let rt_key = format!("{}{}", RT_KEY_PREFIX, token_hash);
        let rt_json: Option<String> = store
            .get(&rt_key)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.common.cache_failed")))?;
        if let Some(json) = rt_json {
            let user_id = serde_json::from_str::<RefreshBinding>(&json)
                .map(|b| b.user_id)
                .unwrap_or(0);
            let _: Result<u64, _> = store.del(&[rt_key]).await;
            if user_id > 0 {
                let _: Result<(), _> = store
                    .set_rem(&format!("{}{}", USER_RT_KEY_PREFIX, user_id), &token_hash)
                    .await;
            }
        }
        Ok(())
    }

    /// **RFC 7662 令牌内省**（批次 4，`[sso].introspection_enabled`）。
    ///
    /// 语义与安全要点：
    /// - 先做**客户端认证**（`verify_token_client`，失败 → `invalid_client` 401），
    ///   避免匿名探测；
    /// - 未知 / 已过期 / 非本客户端签发的令牌一律返回 `{"active": false}`——
    ///   **不区分原因**（RFC 7662 §2.2：不泄漏令牌是否存在，防枚举）；
    /// - 命中时按 **AT 绑定**（`sso:at:{sha256}`）返回声明，`exp` 取绑定自带的绝对过期
    ///   时刻 `exp_at`（签发时写入 now + at_ttl）
    ///   （`/sso/revoke` 是物理 DEL ⇒ 吊销即时反映为 `active: false`，与"停用即断链"一致）；
    /// - 只报告 **access_token**：`refresh_token` 传进来恒 `active: false`（不暴露 RT 链）。
    pub async fn introspect(
        &self,
        params: &TokenParams,
        store: &Arc<dyn SharedStore>,
        config: &SsoConfig,
        issuer: &str,
    ) -> Result<serde_json::Value, OidcError> {
        let client = self.verify_token_client(params).await?;
        let inactive = serde_json::json!({ "active": false });

        if !config.introspection_enabled {
            // 端点未启用（handler 已按 404 拦截，此处为纵深防御）
            return Ok(inactive);
        }
        let Some(token) = params.token.as_deref().filter(|s| !s.is_empty()) else {
            return Ok(inactive);
        };

        let token_hash = crate::utils::crypto::token_hash(token);
        let at_key = format!("{}{}", AT_KEY_PREFIX, token_hash);
        let at_json: Option<String> = store
            .get(&at_key)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.common.cache_failed")))?;
        let Some(at_json) = at_json else {
            return Ok(inactive);
        };
        let Ok(binding) = serde_json::from_str::<AccessBinding>(&at_json) else {
            return Ok(inactive);
        };
        // 只能内省**自己**的令牌：他客户端查询恒 inactive（否则任意已认证客户端都能窥探
        // 别家令牌的 subject/scope）
        if binding.client_id != client.client_id {
            tracing::warn!(
                asked_by = %client.client_id,
                issued_to = %binding.client_id,
                "内省请求的令牌并非本客户端签发，按 inactive 返回"
            );
            return Ok(inactive);
        }
        // exp 计算不再读 TTL（trait 无 TTL 语义）：绑定 JSON 携带绝对过期时刻 exp_at
        // （issue_access_token 写入 now + at_ttl，与原 `exp = now + 剩余 TTL` 恒等）。
        // exp_at 缺失（迁移期存量绑定）按 fail-safe 返回 inactive 并 WARN——RFC 7662
        // 允许对不确定令牌保守不报告；存量 AT 最长一个 TTL 周期（默认 1h）后自然消亡。
        let Some(exp_at) = binding.exp_at else {
            tracing::warn!(
                token_hash = %token_hash,
                "内省绑定缺 exp_at（迁移期存量），按 inactive 返回（fail-safe）"
            );
            return Ok(inactive);
        };
        let now = chrono::Utc::now().timestamp();
        if exp_at <= now {
            // 绑定存在但已到期（无过期键 / 已过期）⇒ 视为失效，不报告剩余寿命
            return Ok(inactive);
        }
        Ok(serde_json::json!({
            "active": true,
            "scope": binding.scope.join(" "),
            "client_id": binding.client_id,
            "username": binding.username,
            "token_type": "Bearer",
            "exp": exp_at,
            "iat": binding.auth_time,
            "sub": binding.user_id.to_string(),
            "aud": binding.client_id,
            "iss": issuer.trim_end_matches('/'),
            "tenant_id": binding.tid,
        }))
    }

    /// 解析同意页 `logo_uri` 的**代理源**（批次 4，`[sso].proxy_logo_uri`）。
    ///
    /// 返回 `Some(url)` 的前提：客户端存在且启用、`logo_uri` 非空、且通过 SSRF 校验
    /// （协议/主机解析）。任何一步不满足一律 `None`（宁可不显示 logo，也不去拉不可信地址）。
    pub async fn client_logo_source(&self, client_id: &str) -> Option<String> {
        // b71 吞错治理：档位语义保持不变（logo 是装饰性元素，任何不满足一律不外链），
        // 但**数据库故障**必须与"客户端不存在/未启用"可区分——原 `.ok()??` 把读库失败
        // 折叠成"无 logo"，故障期间运维在日志里看不到任何信号。
        let client = match self.client_repo.find_by_client_id(client_id).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    client_id,
                    error = %e,
                    "同意页 logo 代理：读取 SSO 客户端失败（本次不外链 logo，非配置问题）"
                );
                return None;
            }
        }?;
        if client.enabled != "1" {
            return None;
        }
        let logo = client.logo_uri.trim();
        if logo.is_empty() {
            return None;
        }
        let parsed = crate::common::ssrf::validate_url(logo).ok()?;
        let host = parsed.host_str()?.to_string();
        let port = parsed.port_or_known_default()?;
        if crate::common::ssrf::validate_host_resolution(&host, port)
            .await
            .is_err()
        {
            tracing::warn!(logo_uri = %logo, "同意页 logo 代理：目标地址未通过 SSRF 校验，回落到不外链");
            return None;
        }
        Some(logo.to_string())
    }

    /// 原子读取并删除授权码（GETDEL 语义），命中返回 Some(JSON 字符串)
    async fn getdel_code(
        &self,
        key: &str,
        store: &Arc<dyn SharedStore>,
    ) -> Result<Option<String>, OidcError> {
        let val: Option<String> = store
            .consume(key)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.common.cache_failed")))?;
        Ok(val)
    }

    /// 构造 ID Token（HS256，per-client 密钥）
    ///
    /// `base_url` 为请求推导出的服务基址，与 discovery 端点同源，用于 `resolve_issuer`：
    /// 保证 **id_token 的 `iss` 与发现文档 `issuer` 恒等**（否则合规 RP 校验 iss 必然拒绝）。
    fn build_id_token(
        &self,
        client: &ClientModel,
        binding: &CodeBinding,
        config: &SsoConfig,
        base_url: &str,
    ) -> Result<String, ServiceError> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let now = chrono::Utc::now().timestamp();
        let exp = now + config.id_token_ttl_secs.max(1) as i64;
        // 与 discovery 共用 resolve_issuer：config.issuer 优先，回退请求 base_url（不再回退 jwt.issuer，
        // 否则发现文档 advertised issuer 与 id_token iss 会不一致）。
        let issuer = self.resolve_issuer(config, base_url);
        let mut claims = serde_json::Map::new();
        claims.insert("iss".into(), serde_json::json!(issuer));
        claims.insert("aud".into(), serde_json::json!(client.client_id));
        // v5-D5：pairwise 客户端呈现 per-client 稳定假名 sub
        claims.insert(
            "sub".into(),
            serde_json::json!(resolve_subject(client, binding.user_id)),
        );
        claims.insert("iat".into(), serde_json::json!(now));
        claims.insert("exp".into(), serde_json::json!(exp));
        claims.insert("auth_time".into(), serde_json::json!(binding.auth_time));
        if let Some(n) = &binding.nonce {
            claims.insert("nonce".into(), serde_json::json!(n));
        }
        // v4 §6：profile 声明（name 用昵称而非登录名，避免向 RP 泄漏工号/内部登录名）
        if binding.scope.iter().any(|s| s == "profile") {
            claims.insert(
                "preferred_username".into(),
                serde_json::json!(binding.username),
            );
            let display = if binding.nick_name.is_empty() {
                &binding.username
            } else {
                &binding.nick_name
            };
            claims.insert("name".into(), serde_json::json!(display));
        }
        // v4 §6：email 声明（数据链路：issue_code_redirect 时查 sys_user 写入绑定）。
        // 本系统无邮箱验证流程，email_verified 恒 false（规范要求 claim 存在时必须携带）。
        if binding.scope.iter().any(|s| s == "email") {
            claims.insert("email".into(), serde_json::json!(binding.email));
            claims.insert("email_verified".into(), serde_json::json!(false));
        }
        // v4 C7：at_hash = base64url(SHA256(access_token) 左半 128bit)。
        // access_token 与 ID Token 同时返回时建议携带，防令牌替换攻击。
        {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(binding.access_token_hash.as_bytes());
            let digest = hasher.finalize();
            let at_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&digest[..digest.len() / 2]);
            claims.insert("at_hash".into(), serde_json::json!(at_hash));
        }
        // v5-E5：认证强度声明（RFC 8176 acr / OIDC amr）——authorize 时点快照
        // 用户 TOTP 启用状态：启用 → acr="mfa"、amr=["pwd","totp"]；否则 acr="pwd"、
        // amr=["pwd"]。RP 据此判断认证强度（如要求 mfa 才放行敏感操作）。
        if binding.totp_enabled {
            claims.insert("acr".into(), serde_json::json!("mfa"));
            claims.insert("amr".into(), serde_json::json!(["pwd", "totp"]));
        } else {
            claims.insert("acr".into(), serde_json::json!("pwd"));
            claims.insert("amr".into(), serde_json::json!(["pwd"]));
        }
        // v5-N2 Phase 1：租户 ID（tid）——多租户立项后 RP 可按租户区分用户主体
        claims.insert("tid".into(), serde_json::json!(binding.tid));
        let payload = serde_json::Value::Object(claims);
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());
        // v3-P1'-4：id_token_secret 以 enc2: 信封加密存储，签名前解密（明文兼容迁移期旧数据）
        let secret = self.decrypt_client_secret(&client.id_token_secret);
        // v5-D2：按客户端声明的算法签发——RS256（默认）用信封加密的 RSA 私钥（PKCS#8 PEM），
        // header.kid = client_id（JWKS 端点聚合公钥的键）；存量无 RSA 私钥的客户端回落 HS256。
        let token = if client.id_token_alg == "RS256" {
            let Some(pem_enc) = &client.rsa_private_key else {
                tracing::error!(
                    "RS256 客户端 {} 缺少 RSA 私钥，回落 HS256",
                    client.client_id
                );
                return self.sign_hs256(&payload, &secret, &client.client_id);
            };
            let pem = crate::utils::crypto::unseal_sensitive_value(pem_enc, &self.enc_key);
            header.alg = Algorithm::RS256;
            header.kid = Some(client.client_id.clone());
            let key = EncodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))?;
            encode(&header, &payload, &key)
                .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))?
        } else {
            self.sign_hs256(&payload, &secret, &client.client_id)?
        };
        Ok(token)
    }

    /// HS256 签发（per-client 对称密钥；v5-D2 前 RS256 客户端的回落路径）
    fn sign_hs256(
        &self,
        payload: &serde_json::Value,
        secret: &str,
        _client_id: &str,
    ) -> Result<String, ServiceError> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());
        encode(
            &header,
            payload,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))
    }

    /// v5-D2：JWKS 文档——聚合全部启用客户端的 RS256 公钥（kid = client_id）。
    /// HS256 客户端不发布公钥（对称密钥经注册通道分发），本端点仅含 RS256 条目；
    /// 全部为 HS256 时返回空 keys（与 jwks_uri OPTIONAL 语义一致，不影响 RP）。
    ///
    /// b71 吞错治理：原实现 `if let Ok(clients) = …await` 把**数据库故障**折叠成"无客户端"，
    /// 于是故障期间对外发布 `{"keys":[]}` 这份**语法合法但内容错误**的 JWKS——RP 会用它
    /// 校验 RS256 id_token 并全部拒签（且因文档合法而可能缓存一段时间），比直接 5xx 让 RP
    /// 沿用缓存更危险。现改为错误上抛（5xx ⇒ RP 保留上一份 JWKS）。
    pub async fn jwks(&self) -> Result<serde_json::Value, ServiceError> {
        let mut keys: Vec<serde_json::Value> = Vec::new();
        let clients = self.client_repo.find_all_enabled().await.map_err(|e| {
            tracing::warn!("JWKS 聚合读取客户端失败: {e}");
            ServiceError::internal(&crate::tr!("error.sso.jwks_unavailable"))
        })?;
        for c in clients {
            if c.id_token_alg != "RS256" {
                continue;
            }
            let Some(pem_enc) = &c.rsa_private_key else {
                continue;
            };
            let pem = crate::utils::crypto::unseal_sensitive_value(pem_enc, &self.enc_key);
            // D9：kid 优先取登记密钥指纹，为空回退 client_id（存量行为不变）
            let kid = c
                .key_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(c.client_id.as_str());
            // b71：单个客户端密钥解析失败只跳过该 kid（不因一处脏数据让整份 JWKS 5xx），
            // 但必须留痕——静默跳过会让 RP 拿到缺 kid 的文档，排障时无从下手。
            match rsa_public_jwk(&pem, kid) {
                Ok(jwk) => keys.push(jwk),
                Err(e) => {
                    tracing::warn!(client_id = %c.client_id, kid = %kid, error = %e, "JWKS 跳过无法解析的客户端公钥")
                }
            }
        }
        Ok(serde_json::json!({ "keys": keys }))
    }

    // -------------------- userinfo --------------------

    /// 处理 GET|POST /sso/userinfo（Bearer access_token → 按 scope 返回身份声明）
    ///
    /// v4-P0-A：access_token 为不透明令牌——校验方式改为「SHA-256 → GET `sso:at:{hash}` 绑定」，
    /// 不再做任何 JWT 解码（平台 JWT 在此也无效：无绑定即 401）。绑定缺失/删除即吊销，天然即时生效。
    /// v3-K3：同时校验 client 仍存在且启用——禁用/删除客户端后旧令牌立即失效，不再放行到 TTL 过期。
    pub async fn userinfo(
        &self,
        bearer: &str,
        store: &Arc<dyn SharedStore>,
        config: &SsoConfig,
    ) -> Result<serde_json::Value, OidcError> {
        if !config.enabled {
            return Err(OidcError::new(
                "invalid_request",
                crate::tr!("error.sso.disabled"),
            ));
        }
        let invalid = || {
            OidcError::new(
                "invalid_token",
                crate::tr!("error.sso.access_token_invalid"),
            )
        };
        // 不透明令牌：哈希命中绑定才有效
        let at_key = format!(
            "{}{}",
            AT_KEY_PREFIX,
            crate::utils::crypto::token_hash(bearer)
        );
        let raw: Option<String> = store
            .get(&at_key)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.common.cache_failed")))?;
        let raw = raw.ok_or_else(invalid)?;
        let binding: AccessBinding = serde_json::from_str(&raw).map_err(|_| invalid())?;
        // v3-K3：client 存在且启用（软删/停用后即时失效）
        let client = self
            .client_repo
            .find_by_client_id(&binding.client_id)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.common.cache_failed")))?
            .ok_or_else(invalid)?;
        if client.enabled != "1" {
            return Err(invalid());
        }

        // 按 scope 最小化下发（v2-I8/§6：profile→preferred_username/name；email→email/email_verified）
        let mut claims = serde_json::Map::new();
        // v5-D5：pairwise 客户端 sub 与 id_token 一致（per-client 稳定假名）
        claims.insert(
            "sub".into(),
            serde_json::json!(resolve_subject(&client, binding.user_id)),
        );
        if binding.scope.iter().any(|s| s == "profile") {
            claims.insert(
                "preferred_username".into(),
                serde_json::json!(binding.username),
            );
            claims.insert("name".into(), serde_json::json!(binding.nick_name));
        }
        if binding.scope.iter().any(|s| s == "email") {
            claims.insert("email".into(), serde_json::json!(binding.email));
            // 本系统无邮箱验证流程：规范要求 claim 存在时必须带 email_verified，恒 false
            claims.insert("email_verified".into(), serde_json::json!(false));
        }
        Ok(serde_json::Value::Object(claims))
    }

    // -------------------- 会话解析 --------------------

    /// 解析浏览器 Cookie 中的 JWT → 身份；无效 / 已登出（黑名单）→ None
    async fn resolve_session(
        &self,
        session_token: Option<&str>,
        store: &Arc<dyn SharedStore>,
        jwt: &JwtConfig,
    ) -> Result<Option<SessionIdentity>, ServiceError> {
        let Some(token) = session_token.filter(|t| !t.is_empty()) else {
            return Ok(None);
        };
        // PAT 前缀令牌不作为登录会话
        let claims = match JwtUtils::verify_token(token, jwt) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };
        let user_id: i64 = match claims.sub.parse() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        // 黑名单校验：已登出的会话不再视为有效（best-effort：查询失败按未拉黑处理，与原一致）
        let token_hash = crate::utils::crypto::token_hash(token);
        let blacklist_key = format!("blacklist:{}", token_hash);
        let blacklisted: Option<String> = store.get(&blacklist_key).await.unwrap_or(None);
        if blacklisted.is_some() {
            return Ok(None);
        }
        // v3-P0-B：登记登录会话索引（`sso:sess:{uid}` = hash 集合），
        // end_session 可按用户跨端拉黑全部 IdP 会话；TTL = JWT 剩余寿命。
        let remaining = (claims.exp as i64)
            .saturating_sub(chrono::Utc::now().timestamp())
            .max(60);
        let sess_key = format!("{}{}", SESS_KEY_PREFIX, user_id);
        // SADD + EXPIRE 合并走 trait 集合方法；best-effort（原两段式命令亦忽略失败）
        let _: Result<(), _> = store
            .set_add(&sess_key, &token_hash, remaining as u64)
            .await;
        Ok(Some(SessionIdentity {
            user_id,
            username: claims.username,
            // v3 P1'-1：登录 JWT 的 iat 即用户认证时刻（claims.rs:123 签发时写入）
            auth_time: claims.iat as i64,
            // v5-N2 Phase 1：租户 ID 随会话携带
            tid: claims.tid,
        }))
    }

    // -------------------- 客户端 CRUD --------------------

    /// 查询某客户端登记的回调地址白名单（供 RP-initiated logout 校验 post_logout_redirect_uri）
    pub async fn client_redirect_uris(&self, client_id: &str) -> Result<Vec<String>, ServiceError> {
        let Some(c) = self.client_repo.find_by_client_id(client_id).await? else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_str(&c.redirect_uris).unwrap_or_default())
    }

    // -------------------- 自助授权管理（v4-R8） --------------------

    /// 当前用户"已授权应用"列表（client_name 用同意时快照，v4-R6）
    pub async fn list_user_grants(&self, user_id: i64) -> Result<Vec<SsoGrantVo>, ServiceError> {
        let rows = self.consent_repo.find_by_user(user_id).await?;
        Ok(rows
            .into_iter()
            .map(|m| SsoGrantVo {
                client_id: m.client_id,
                client_name: m.client_name_snapshot,
                scopes: serde_json::from_str(&m.scopes).unwrap_or_default(),
                consented_at: m
                    .consented_at
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()),
            })
            .collect())
    }

    /// 用户撤销对某 client 的授权：软删同意记录 + 级联吊销该客户端名下的 SSO access_token。
    /// 返回是否确实存在有效授权（不存在时幂等成功，前端提示已撤销）。
    pub async fn revoke_user_grant(
        &self,
        user_id: i64,
        client_id: &str,
        store: &Arc<dyn SharedStore>,
    ) -> Result<bool, ServiceError> {
        let revoked = self.consent_repo.revoke(user_id, client_id).await?;
        if revoked {
            self.revoke_user_client_tokens(store, user_id, client_id)
                .await;
        }
        Ok(revoked)
    }

    pub async fn get_client_page(
        &self,
        q: SsoClientQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<SsoClientVo>, u64), ServiceError> {
        let page_num = q.page_num.unwrap_or(1).max(1);
        let page_size = q.page_size.unwrap_or(10).clamp(1, 100);
        let offset = crate::common::page::offset_of(page_num, page_size);
        let (rows, total) = self
            .client_repo
            .find_page_filtered(
                offset,
                page_size,
                q.client_name.as_deref(),
                q.client_id.as_deref(),
                q.enabled.as_deref(),
                // v5-N2 Phase 2：租户过滤（平台管理员 tid=0 全量；租户用户本租户隔离）
                crate::common::tenant::tenant_scope(operator_tid),
            )
            .await?;
        Ok((rows.into_iter().map(client_to_vo).collect(), total))
    }

    pub async fn get_client_by_pk(
        &self,
        pk: i64,
        operator_tid: i64,
    ) -> Result<SsoClientVo, ServiceError> {
        let m =
            self.client_repo.find_by_pk(pk).await?.ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.sso.client_not_found"))
            })?;
        // v5-N2 Phase 2：读归属校验（跨租户资源按 404 语义隐藏存在性）
        if !crate::common::tenant::tenant_allowed(operator_tid, m.tenant_id) {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.sso.client_not_found"
            )));
        }
        Ok(client_to_vo(m))
    }

    pub async fn add_client(
        &self,
        dto: SsoClientUpsertDto,
        create_by: &str,
        operator_tid: i64,
    ) -> Result<SsoClientCreateResult, ServiceError> {
        validate_client_name(&dto.client_name)?;
        let redirect_uris = validate_redirect_uris(&dto.redirect_uris)?;
        let scopes = validate_scopes(&dto.scopes)?;
        let grant_types = normalize_grant_types(dto.grant_types.as_deref());
        // v3 P1'-3：logo_uri 同意页渲染前必须服务端校验
        let logo_uri = validate_logo_uri(&dto.logo_uri)?;

        // client_id：留空自动生成，否则校验格式 + 唯一
        let client_id = match dto.client_id.as_deref().map(str::trim) {
            Some(cid) if !cid.is_empty() => {
                if !is_valid_client_id(cid) {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.sso.client_id_required"
                    )));
                }
                if self.client_repo.exists_by_client_id(cid).await? {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.sso.client_id_exists"
                    )));
                }
                // v4 §1.3：保留字双校验——静态通用表 + 动态配置值（jwt.audience/issuer 等），
                // 防止 client_id 与平台自身命名空间/受众标识撞名造成令牌语义混淆。
                if RESERVED_CLIENT_IDS.contains(&cid) || self.reserved_ids.iter().any(|r| r == cid)
                {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.sso.client_id_reserved"
                    )));
                }
                cid.to_string()
            }
            _ => loop {
                let cid = format!("app_{}", random_urlsafe(12));
                if !self.client_repo.exists_by_client_id(&cid).await? {
                    break cid;
                }
            },
        };

        // 密钥：明文 client_secret 返回一次；id_token_secret 仅服务端持有。
        // v3-P1'-4：主密钥已配置时必须加密成功才落库（fail-closed，拒绝明文入库）；
        // 主密钥未配置（迁移期 fail-open 策略）才允许明文。
        let client_secret = random_urlsafe(32);
        let client_secret_hash = crate::utils::crypto::token_hash(&client_secret);
        let id_token_secret = random_urlsafe(32);
        let id_token_secret_stored = if self.enc_key.is_empty() {
            tracing::warn!("CONFIG_ENC_KEY 未配置：id_token_secret 以明文落库（迁移期 fail-open）");
            id_token_secret
        } else {
            crate::utils::crypto::encrypt_config_value(&id_token_secret, &self.enc_key).map_err(
                |e| {
                    tracing::error!(
                        "id_token_secret 加密失败，拒绝创建客户端（fail-closed）: {}",
                        e
                    );
                    ServiceError::internal(&crate::tr!("error.sso.secret_encrypt_failed"))
                },
            )?
        };

        // v5-D2：RS256 私钥（PKCS#8 PEM）——新增客户端默认 RS256 签名；
        // 私钥信封加密落库（key 未配置时明文，迁移期策略），公钥经 /sso/jwks 发布。
        // keygen 为 CPU 密集大栈操作：spawn_blocking 避免阻塞 tokio worker
        //（v5-D2 修正：真实运行发现 tokio 栈上 keygen stack overflow 硬崩）
        let rsa_private_pem = tokio::task::spawn_blocking(generate_rsa_private_pem)
            .await
            .map_err(|e| ServiceError::internal(&format!("RSA keygen 任务失败: {e}")))?
            .map_err(|e| ServiceError::internal(&format!("RSA 密钥生成失败: {e}")))?;
        // D9：登记密钥指纹（kid）——必须在私钥被信封加密/移出前由明文 PEM 计算
        let key_id = rsa_key_thumbprint(&rsa_private_pem)
            .map_err(|e| ServiceError::internal(&format!("RSA thumbprint 计算失败: {e}")))?;
        let rsa_private_stored = if self.enc_key.is_empty() {
            tracing::warn!("CONFIG_ENC_KEY 未配置：rsa_private_key 以明文落库（迁移期 fail-open）");
            rsa_private_pem
        } else {
            crate::utils::crypto::encrypt_config_value(&rsa_private_pem, &self.enc_key).map_err(
                |e| {
                    tracing::error!("RSA 私钥加密失败，拒绝创建客户端（fail-closed）: {}", e);
                    ServiceError::internal(&crate::tr!("error.sso.secret_encrypt_failed"))
                },
            )?
        };

        let now = datetime::now_naive();
        let am = ClientActiveModel {
            client_id: Set(client_id.clone()),
            client_secret_hash: Set(client_secret_hash),
            id_token_secret: Set(id_token_secret_stored),
            id_token_alg: Set(normalize_id_token_alg(dto.id_token_alg.as_deref())),
            rsa_private_key: Set(Some(rsa_private_stored)),
            key_id: Set(Some(key_id)),
            subject_type: Set(normalize_subject_type(dto.subject_type.as_deref())),
            sector_identifier_uri: Set(validate_sector_identifier(
                dto.sector_identifier_uri.as_deref(),
            )?),
            client_name: Set(dto.client_name.trim().to_string()),
            logo_uri: Set(logo_uri),
            redirect_uris: Set(to_json_array(&redirect_uris)),
            scopes: Set(to_json_array(&scopes)),
            grant_types: Set(to_json_array(&grant_types)),
            consent_required: Set(normalize_flag(dto.consent_required.as_deref(), "1")),
            enabled: Set(normalize_flag(dto.enabled.as_deref(), "1")),
            remark: Set(dto.remark),
            // v5-N2 Phase 2：归属写入（平台管理员 tid=0 → 平台资源；租户管理员 → 本租户）
            tenant_id: Set(operator_tid),
            create_by: Set(create_by.to_string()),
            update_by: Set(create_by.to_string()),
            create_time: Set(Some(now)),
            update_time: Set(Some(now)),
            ..Default::default()
        };
        let saved = self.client_repo.insert(am).await?;
        Ok(SsoClientCreateResult {
            client_id,
            client_secret,
            client: client_to_vo(saved),
        })
    }

    pub async fn edit_client(
        &self,
        dto: SsoClientUpsertDto,
        update_by: &str,
        operator_tid: i64,
    ) -> Result<SsoClientVo, ServiceError> {
        if dto.sso_client_id <= 0 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.batch_id_invalid"
            )));
        }
        validate_client_name(&dto.client_name)?;
        let redirect_uris = validate_redirect_uris(&dto.redirect_uris)?;
        let scopes = validate_scopes(&dto.scopes)?;
        let grant_types = normalize_grant_types(dto.grant_types.as_deref());
        // v3 P1'-3：logo_uri 同意页渲染前必须服务端校验
        let logo_uri = validate_logo_uri(&dto.logo_uri)?;

        let m = self
            .client_repo
            .find_by_pk(dto.sso_client_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.sso.client_not_found")))?;
        // v5-N2 Phase 2：写归属校验（跨租户资源按 404 语义拒绝）
        if !crate::common::tenant::tenant_allowed(operator_tid, m.tenant_id) {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.sso.client_not_found"
            )));
        }

        // 未回传时保留原值（consent_required / enabled 可选）
        let consent_required = normalize_flag(dto.consent_required.as_deref(), &m.consent_required);
        let enabled = normalize_flag(dto.enabled.as_deref(), &m.enabled);
        // v5-D2/D5：算法与 subject 类型可选更新（未回传保留原值）。
        // 注意：pairwise 切换会使已发令牌的 sub 变化（RP 视为新用户），前端承担确认提示；
        // HS256 切换不删除 RSA 私钥（切回 RS256 立即恢复非对称签名）。
        let id_token_alg = normalize_id_token_alg(dto.id_token_alg.as_deref());
        let subject_type = normalize_subject_type(dto.subject_type.as_deref());

        // v5-D2 修正：显式切到 RS256 且当前无 RSA 私钥时**当场生成**——启动 ensure
        // 只覆盖"启动时点已声明 RS256"的客户端，存量 HS256 客户端中途切换会留下
        // key NULL 窗口（签发回落 HS256，与 RP 预期的 JWKS 验签不符）。生成后信封
        // 加密落库（同 add_client；CONFIG_ENC_KEY 未配置时明文，迁移期策略）。
        let mut new_rsa_key: Option<String> = None;
        let mut new_key_id: Option<String> = None;
        if id_token_alg == "RS256" && dto.id_token_alg.is_some() && m.rsa_private_key.is_none() {
            let pem = tokio::task::spawn_blocking(generate_rsa_private_pem)
                .await
                .map_err(|e| ServiceError::internal(&format!("RSA keygen 任务失败: {e}")))?
                .map_err(|e| ServiceError::internal(&format!("RSA 密钥生成失败: {e}")))?;
            // D9：同步登记新密钥指纹（kid），保证 JWKS 与库内私钥重新对齐
            new_key_id =
                Some(rsa_key_thumbprint(&pem).map_err(|e| {
                    ServiceError::internal(&format!("RSA thumbprint 计算失败: {e}"))
                })?);
            let sealed = if self.enc_key.is_empty() {
                tracing::warn!(
                    "CONFIG_ENC_KEY 未配置：rsa_private_key 以明文落库（迁移期 fail-open）"
                );
                pem
            } else {
                crate::utils::crypto::encrypt_config_value(&pem, &self.enc_key).map_err(|e| {
                    tracing::error!("RSA 私钥加密失败（fail-closed）: {}", e);
                    ServiceError::internal(&crate::tr!("error.sso.secret_encrypt_failed"))
                })?
            };
            new_rsa_key = Some(sealed);
        }

        // 关键：仅将可编辑列标记为 Set 才能被 ActiveModelTrait::update 真实写入；
        // Model.into() 会产生 Unchanged 值并被 update 跳过。client_id /
        // client_secret_hash / id_token_secret / create_* 保持 Unchanged，杜绝密钥篡改。
        let mut am: ClientActiveModel = m.into();
        am.client_name = Set(dto.client_name.trim().to_string());
        am.logo_uri = Set(logo_uri);
        am.redirect_uris = Set(to_json_array(&redirect_uris));
        am.scopes = Set(to_json_array(&scopes));
        am.grant_types = Set(to_json_array(&grant_types));
        am.id_token_alg = Set(id_token_alg);
        if let Some(sealed) = new_rsa_key {
            am.rsa_private_key = Set(Some(sealed));
        }
        if let Some(kid) = new_key_id {
            am.key_id = Set(Some(kid));
        }
        am.subject_type = Set(subject_type);
        am.sector_identifier_uri = Set(validate_sector_identifier(
            dto.sector_identifier_uri.as_deref(),
        )?);
        am.consent_required = Set(consent_required);
        am.enabled = Set(enabled);
        am.remark = Set(dto.remark);
        am.update_by = Set(update_by.to_string());

        // 经 ActiveModelBehavior::before_save 刷新 update_time
        let saved = self.client_repo.update(am).await?;
        Ok(client_to_vo(saved))
    }

    /// 批量删除客户端（v4-R9：**软删** + 级联清理）。
    ///
    /// 级联顺序（先吊销令牌再软删，避免竞态窗口内已删客户端仍可用旧令牌换身份）：
    /// 1. 逐个取有效客户端 → client_id；
    /// 2. 对每个 client 查出已授权用户 → 全量吊销其 SSO access_token（sso:at:* + online:*）；
    /// 3. 删除该 client 的全部同意记录；
    /// 4. 软删客户端（del_flag='2'，client_id 唯一约束不释放，防重建撞名，v2-K4）。
    pub async fn delete_clients(
        &self,
        ids: Vec<i64>,
        store: &Arc<dyn SharedStore>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.batch_id_invalid"
            )));
        }

        // B-1：ORM 步骤（归属校验 / 取待吊销用户集 / 物理删同意记录 / 软删客户端）
        // 全部收敛进**单个事务**——中途失败不得留下"同意记录已清但客户端仍在"的
        // 半成品（原实现无事务，物理删同意记录后 soft_delete 失败即产生该不一致）。
        //
        // store（Redis/DB 共享态）侧的令牌吊销**不可回滚**，故必须推迟到事务提交
        // 之后执行：若事务失败则 store 不动（安全）；若提交后吊销失败，最坏是令牌
        // 多活至 TTL（可重试、可接受），绝不会出现"数据已回滚但令牌已被吊销"的镜像
        // 不一致。这里用事务内收集 + 提交后执行两阶段表达该顺序。
        let client_repo = self.client_repo.clone();
        let consent_repo = self.consent_repo.clone();

        // 事务提交后待吊销的 (user_id, client_id) 集合
        let mut pending_revocations: Vec<(i64, String)> = Vec::new();
        {
            let txn = client_repo
                .base()
                .db()
                .begin()
                .await
                .map_err(|e| ServiceError::internal(&format!("开启事务失败: {e}")))?;

            for id in &ids {
                let Some(m) = client_repo.find_by_pk_conn(&txn, *id).await? else {
                    // 不存在按幂等跳过（与批量删除语义一致：不存在的 id 不报错）
                    continue;
                };
                // v5-N2 Phase 2：写归属校验（跨租户资源按 404 语义拒绝）
                if !crate::common::tenant::tenant_allowed(operator_tid, m.tenant_id) {
                    // txn 未提交，Drop 时自动回滚
                    return Err(ServiceError::not_found(&crate::tr!(
                        "error.sso.client_not_found"
                    )));
                }
                // 2. 事务内取该客户端全部已授权用户（与随后删除的记录集严格一致，
                //    避免原实现"先读后删"跨调用竞态导致的错位）
                let user_ids = consent_repo
                    .user_ids_by_client_conn(&txn, &m.client_id)
                    .await?;
                // 3. 事务内物理删同意记录（历史审计可走操作日志）
                consent_repo
                    .delete_by_client_conn(&txn, &m.client_id)
                    .await?;
                // 记录待吊销项（提交后执行）
                for uid in user_ids {
                    pending_revocations.push((uid, m.client_id.clone()));
                }
            }

            // 4. 事务内软删（del_flag='2'，client_id 唯一约束不释放，防重建撞名，v2-K4）
            client_repo
                .soft_delete_by_ids_conn(&txn, ids.clone())
                .await?;

            txn.commit()
                .await
                .map_err(|e| ServiceError::internal(&format!("提交事务失败: {e}")))?;
        }

        // ===== 事务已提交，以下为不可回滚的 store 侧级联吊销（best-effort 由实现内部保证）=====
        // v5 第九轮修正：原误用 revoke_user_sso_tokens（**全量**吊销该用户所有客户端的
        // AT）——删客户端 A 不应波及用户对客户端 B 的有效会话；
        // 现按 client 粒度（仅删 client_id 匹配的绑定与 online）。
        for (uid, client_id) in pending_revocations {
            self.revoke_user_client_tokens(store, uid, &client_id).await;
        }

        Ok(())
    }

    /// 启停客户端（v5-S6：**停用即吊销**该 client 名下全部用户的 SSO AT——
    /// 否则重新启用后 TTL 内存量绑定复活；启用方向无需副作用）。
    /// 停用期间 userinfo 的 client.enabled 校验本就拒绝旧令牌，本步把语义做实。
    pub async fn toggle_client(
        &self,
        pk: i64,
        enabled: &str,
        store: &Arc<dyn SharedStore>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let m =
            self.client_repo.find_by_pk(pk).await?.ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.sso.client_not_found"))
            })?;
        // v5-N2 Phase 2：写归属校验（跨租户资源按 404 语义拒绝）
        if !crate::common::tenant::tenant_allowed(operator_tid, m.tenant_id) {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.sso.client_not_found"
            )));
        }
        let client_id = m.client_id.clone();
        // 仅将 enabled 标记为 Set 才会被 update 写入（before_save 刷新 update_time）
        let mut am: ClientActiveModel = m.into();
        am.enabled = Set(if enabled == "1" {
            "1".to_string()
        } else {
            "0".to_string()
        });
        self.client_repo.update(am).await?;
        // v5-S6：停用 → 按 client 粒度吊销该客户端名下全部用户的 AT
        if enabled != "1" {
            let user_ids = self.consent_repo.user_ids_by_client(&client_id).await?;
            for uid in user_ids {
                self.revoke_user_client_tokens(store, uid, &client_id).await;
            }
        }
        Ok(())
    }

    /// **SSO D9：轮换 `client_secret`（零停机「双密钥读取期」）**。
    ///
    /// 语义（与 JWT 多密钥轮换同构）：
    /// 1. 生成新 secret，明文**仅本次响应返回一次**（落库只存 SHA-256 摘要）；
    /// 2. 轮换前的摘要移入 `previous_client_secret_hash` ⇒ 过渡期内**新旧两把都能鉴权**
    ///    （RP 换配期间不断服）；旧密钥命中时打 WARN 便于运维收口；
    /// 3. RP 换配完成后调用 [`Self::clear_previous_client_secret`] 结束过渡期 ⇒ 旧密钥立即失效。
    ///
    /// 归属：非本租户客户端按 404 语义拒绝。返回 [`SsoClientRotateResult`]（含一次性明文）。
    pub async fn rotate_client_secret(
        &self,
        pk: i64,
        update_by: &str,
        operator_tid: i64,
    ) -> Result<SsoClientRotateResult, ServiceError> {
        let m =
            self.client_repo.find_by_pk(pk).await?.ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.sso.client_not_found"))
            })?;
        if !crate::common::tenant::tenant_allowed(operator_tid, m.tenant_id) {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.sso.client_not_found"
            )));
        }
        let client_id = m.client_id.clone();
        let previous_hash = m.client_secret_hash.clone();
        let new_secret = random_urlsafe(32);
        let new_hash = crate::utils::crypto::token_hash(&new_secret);
        let mut am: ClientActiveModel = m.into();
        // 读取期最多保留"一把"旧密钥：用旧摘要覆盖（而非追加），避免无界堆积。
        am.previous_client_secret_hash = Set(Some(previous_hash));
        am.client_secret_hash = Set(new_hash);
        am.update_by = Set(update_by.to_string());
        self.client_repo.update(am).await?;
        Ok(SsoClientRotateResult {
            client_id,
            client_secret: new_secret,
        })
    }

    /// **SSO D9：结束双密钥读取期**（清空 `previous_client_secret_hash`）。
    ///
    /// 幂等：本无过渡期时同样返回成功（清空 = 现状）。本调用起旧 `client_secret` 立即失效。
    pub async fn clear_previous_client_secret(
        &self,
        pk: i64,
        update_by: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let m =
            self.client_repo.find_by_pk(pk).await?.ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.sso.client_not_found"))
            })?;
        if !crate::common::tenant::tenant_allowed(operator_tid, m.tenant_id) {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.sso.client_not_found"
            )));
        }
        let mut am: ClientActiveModel = m.into();
        am.previous_client_secret_hash = Set(None);
        am.update_by = Set(update_by.to_string());
        self.client_repo.update(am).await?;
        Ok(())
    }

    // -------------------- 令牌吊销（v4-F2 / P0-B） --------------------

    /// 全量吊销某用户的全部 SSO access_token + refresh_token（登出 / 强退 / 改密 /
    /// 停用/删除用户）：AT/RT 索引遍历、悬空自愈、online 同删等语义已封进
    /// [`SharedStore::revoke_all_for_user`] 实现（redis 档原样等价、local 档同库事务承载）。
    /// （v5 第九轮：客户端级联场景改用 revoke_user_client_tokens 按 client 粒度，
    /// 不再波及用户在其它客户端的有效会话。）
    pub async fn revoke_user_sso_tokens(&self, store: &Arc<dyn SharedStore>, user_id: i64) {
        // 失败仅记日志（原各 Redis 命令亦 best-effort，登出主流程不被阻断）
        if let Err(e) = store.revoke_all_for_user(&user_id.to_string()).await {
            tracing::error!("用户 SSO 令牌全量吊销失败 user_id={}: {}", user_id, e);
        }
    }

    /// 按客户端粒度吊销某用户的 SSO access_token（v4-R8 自助撤销授权的级联动作）：
    /// 读取每个 AT 的绑定 JSON，仅删除 `client_id` 匹配的令牌及其在线会话。
    pub async fn revoke_user_client_tokens(
        &self,
        store: &Arc<dyn SharedStore>,
        user_id: i64,
        client_id: &str,
    ) {
        let user_at_key = format!("{}{}", USER_AT_KEY_PREFIX, user_id);
        // 读索引失败按空集继续（best-effort，与原 SMEMBERS unwrap_or_default 等价）
        let hashes: Vec<String> = store.set_members(&user_at_key).await.unwrap_or_default();
        for h in &hashes {
            let at_key = format!("{}{}", AT_KEY_PREFIX, h);
            let matched = store
                .get(&at_key)
                .await
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str::<AccessBinding>(&j).ok())
                .map(|b| b.client_id == client_id)
                .unwrap_or(false);
            if matched {
                let _: Result<u64, _> = store.del(&[at_key, format!("online:{}", h)]).await;
                let _: Result<(), _> = store.set_rem(&user_at_key, h).await;
            }
        }
        // v5-D3 修正：按 client 粒度同步吊销 refresh_token（RT 轮换链终止）——
        // 否则撤权/删客户端/停用后 RT 仍可换出新 AT，级联吊销被架空
        let user_rt_key = format!("{}{}", USER_RT_KEY_PREFIX, user_id);
        let rt_hashes: Vec<String> = store.set_members(&user_rt_key).await.unwrap_or_default();
        for h in &rt_hashes {
            let rt_key = format!("{}{}", RT_KEY_PREFIX, h);
            let matched = store
                .get(&rt_key)
                .await
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str::<RefreshBinding>(&j).ok())
                .map(|b| b.client_id == client_id)
                .unwrap_or(false);
            if matched {
                let _: Result<u64, _> = store.del(&[rt_key]).await;
                let _: Result<(), _> = store.set_rem(&user_rt_key, h).await;
            }
        }
    }

    /// v4-P0-B：end_session 真实登出（RP-initiated Single Logout）。
    ///
    /// 身份来源（二选一，均需通过验证才产生副作用）：
    /// - `id_token_hint`：用对应客户端的 id_token_secret 验签（HS256），`aud` 必须等于
    ///   该 client_id → `sub` 即目标用户；
    /// - 浏览器 `session_token`（Admin-Token Cookie）：平台 JWT 验签通过即本人会话。
    ///
    /// 副作用：① 全量吊销目标用户 SSO access_token；② 黑名单该浏览器会话 JWT（剩余寿命 TTL，
    /// 仅当 hint 用户与 Cookie 用户一致或无 hint 时）。
    ///
    /// 返回 `Some(redirect_uri)`：`post_logout_redirect_uri` 精确命中该客户端登记白名单且
    /// 身份验证通过时回跳；hint 无效时 fail-closed 不回跳（OIDC 安全 BCP）。
    /// `allow_cookie_logout`：CSRF 防护（v4-R5）——无 hint 时仅允许同源/同站发起的登出
    /// （Sec-Fetch-Site ∈ same-origin/same-site/none）；跨站且无 hint 一律不产生副作用。
    pub async fn end_session(
        &self,
        client_id: Option<&str>,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        session_token: Option<&str>,
        allow_cookie_logout: bool,
        store: &Arc<dyn SharedStore>,
        jwt: &JwtConfig,
    ) -> Result<Option<String>, ServiceError> {
        // 1. 身份判定
        let mut hint_user: Option<i64> = None;
        let mut hint_client_id: Option<String> = None;
        if let Some(hint) = id_token_hint.filter(|h| !h.is_empty()) {
            match self.verify_id_token_hint(hint).await? {
                Some((cid, uid)) => {
                    hint_client_id = Some(cid);
                    hint_user = Some(uid);
                }
                // hint 携带但验签失败：fail-closed，不产生任何副作用、不回跳
                None => {
                    tracing::warn!("end_session：id_token_hint 验签失败，拒绝登出与回跳");
                    return Ok(None);
                }
            }
        }

        // 2. 副作用：吊销 SSO 令牌 + 跨端拉黑 IdP 登录会话
        if let Some(uid) = hint_user {
            self.revoke_user_sso_tokens(store, uid).await;
            self.blacklist_user_sessions(store, uid).await;
        }

        // 3. 黑名单浏览器会话（仅无 hint 或 hint 用户与 Cookie 用户一致时）
        if let Some(token) = session_token.filter(|t| !t.is_empty())
            && let Ok(claims) = JwtUtils::verify_token(token, jwt)
        {
            let cookie_user: Option<i64> = claims.sub.parse().ok();
            let hint_allows = hint_user.is_none() || hint_user == cookie_user;
            if hint_allows && (hint_user.is_some() || allow_cookie_logout) {
                let token_hash = crate::utils::crypto::token_hash(token);
                let ttl = (claims.exp as i64)
                    .saturating_sub(chrono::Utc::now().timestamp())
                    .max(60);
                let _: Result<(), _> = store
                    .set_ex(&format!("blacklist:{}", token_hash), "1", ttl as u64)
                    .await;
                if let Some(uid) = cookie_user {
                    self.revoke_user_sso_tokens(store, uid).await;
                }
            }
        }

        // 4. 回跳判定：post_logout_redirect_uri 必须精确命中客户端白名单（防开放重定向），
        //    且需通过身份验证（有效 hint 或同源 Cookie 登出），fail-closed
        let target_client = hint_client_id.or_else(|| client_id.map(str::to_string));
        if let (Some(cid), Some(ru)) = (target_client.as_deref(), post_logout_redirect_uri)
            && (hint_user.is_some() || allow_cookie_logout)
            && self
                .client_redirect_uris(cid)
                .await?
                .iter()
                .any(|w| w == ru)
        {
            return Ok(Some(ru.to_string()));
        }
        Ok(None)
    }

    /// 按用户拉黑其全部 IdP 登录会话（`sso:sess:{uid}` 索引 → 逐 hash 写 blacklist），
    /// 供 end_session 跨端登出；拉黑后清空索引。
    async fn blacklist_user_sessions(&self, store: &Arc<dyn SharedStore>, user_id: i64) {
        let sess_key = format!("{}{}", SESS_KEY_PREFIX, user_id);
        // 读索引失败按空集继续（best-effort，与原 SMEMBERS unwrap_or_default 等价）
        let hashes: Vec<String> = store.set_members(&sess_key).await.unwrap_or_default();
        for h in &hashes {
            // 会话剩余寿命未知（索引与 JWT 同 TTL），拉黑 24h 足以覆盖任何在途会话
            let _: Result<(), _> = store.set_ex(&format!("blacklist:{}", h), "1", 86_400).await;
        }
        if !hashes.is_empty() {
            let _: Result<u64, _> = store.del(&[sess_key]).await;
            tracing::info!(
                "已拉黑用户 IdP 会话 user_id={} count={}",
                user_id,
                hashes.len()
            );
        }
    }

    /// 验签 id_token_hint：
    /// 先**手动 base64url 解码** payload 取出 aud 定位客户端（不验签的 peek 仅用于路由，
    /// 随后立即用该客户端密钥完整验签，不信任 peek 结果），再完整验签。
    /// v5-D2：签名算法按客户端声明分支——RS256 用公钥组件验签（私钥推导公钥），
    /// HS256 用 id_token_secret；alg 缺省按 HS256 兼容旧客户端。
    /// 返回 `Some((client_id, sub))`；定位/验签任一失败返回 `None`。
    async fn verify_id_token_hint(
        &self,
        hint: &str,
    ) -> Result<Option<(String, i64)>, ServiceError> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};
        let aud = peek_jwt_claims(hint).and_then(|claims| match claims.get("aud") {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(serde_json::Value::Array(arr)) => {
                arr.first().and_then(|v| v.as_str()).map(str::to_string)
            }
            _ => None,
        });
        let Some(aud) = aud else {
            return Ok(None);
        };
        let Some(client) = self.client_repo.find_by_client_id(&aud).await? else {
            return Ok(None);
        };
        // v5-D2：按客户端声明算法构造验签密钥（RS256 公钥组件 / HS256 对称密钥）
        use base64::Engine as _;
        use rsa::traits::PublicKeyParts;
        let (alg, key) = match client.id_token_alg.as_str() {
            "RS256" => {
                use rsa::pkcs8::DecodePrivateKey;
                let Some(pem_enc) = &client.rsa_private_key else {
                    tracing::warn!(
                        "id_token_hint：RS256 客户端 {} 缺少私钥，验签失败",
                        client.client_id
                    );
                    return Ok(None);
                };
                let pem = crate::utils::crypto::unseal_sensitive_value(pem_enc, &self.enc_key);
                let private = rsa::RsaPrivateKey::from_pkcs8_pem(&pem).map_err(|e| {
                    tracing::error!("RSA 私钥解析失败 client_id={}: {}", aud, e);
                    ServiceError::internal(&crate::tr!("error.sso.client_auth_failed"))
                })?;
                let b64url = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
                let key = DecodingKey::from_rsa_components(
                    &b64url(&private.n().to_bytes_be()),
                    &b64url(&private.e().to_bytes_be()),
                )
                .map_err(|e| {
                    tracing::error!("RSA 公钥组件构造失败 client_id={}: {}", aud, e);
                    ServiceError::internal(&crate::tr!("error.sso.client_auth_failed"))
                })?;
                (Algorithm::RS256, key)
            }
            _ => (
                Algorithm::HS256,
                DecodingKey::from_secret(
                    self.decrypt_client_secret(&client.id_token_secret)
                        .as_bytes(),
                ),
            ),
        };
        let mut validation = Validation::new(alg);
        validation.set_audience(&[&aud]);
        validation.validate_exp = true;
        match jsonwebtoken::decode::<serde_json::Value>(hint, &key, &validation) {
            Ok(data) => {
                let sub = data
                    .claims
                    .get("sub")
                    .and_then(|s| s.as_str())
                    .and_then(|s| s.parse::<i64>().ok());
                Ok(sub.map(|uid| (aud, uid)))
            }
            Err(e) => {
                tracing::warn!("id_token_hint 验签失败 client_id={}: {}", aud, e);
                Ok(None)
            }
        }
    }

    // -------------------- 内部：redirect_uri --------------------

    /// 解析回调地址：给定则精确匹配白名单；未给定且白名单唯一则用之；否则 None
    fn resolve_redirect_uri(
        &self,
        requested: Option<&str>,
        whitelist: &[String],
    ) -> Option<String> {
        resolve_redirect_uri(requested, whitelist)
    }
}

/// 解析授权请求携带的 redirect_uri：
/// - 显式给出则必须精确命中白名单；
/// - 缺省时仅当白名单唯一才回填（多值时不可猜测，判为非法）。
fn resolve_redirect_uri(requested: Option<&str>, whitelist: &[String]) -> Option<String> {
    match requested.map(str::trim).filter(|s| !s.is_empty()) {
        Some(ru) => {
            if whitelist.iter().any(|w| w == ru) {
                Some(ru.to_string())
            } else {
                None
            }
        }
        None => {
            if whitelist.len() == 1 {
                whitelist.first().cloned()
            } else {
                None
            }
        }
    }
}

struct SessionIdentity {
    user_id: i64,
    username: String,
    /// 用户认证时刻（UTC 秒，v3 P1'-1：登录 JWT 的 iat——ID Token 的 auth_time 语义应为
    /// "用户实际完成认证的时刻"，而非"授权发生时刻"，否则 RP 的 max_age 判断永久失效）
    auth_time: i64,
    /// v5-N2 Phase 1：租户 ID（登录 JWT tid；旧 token 缺省 0）
    tid: i64,
}

/// 手动解码 JWT payload（base64url，**不验签**）。
/// 仅用于 id_token_hint 的 aud 路由（先定位客户端再用其密钥完整验签），
/// 结果绝不作为信任依据。格式非法返回 None。
fn peek_jwt_claims(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('=').as_bytes())
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

// ==================== 纯函数辅助（可单测） ====================

/// v5-D4：prompt 参数是否包含指定指令（空格分隔，OIDC Core §3.1.2.1）
fn prompt_contains(params: &AuthorizeParams, directive: &str) -> bool {
    params
        .prompt
        .as_deref()
        .map(|p| p.split_whitespace().any(|w| w == directive))
        .unwrap_or(false)
}

/// v5-D5：pairwise subject 派生——`SHA-256("{sector}:{user_id}")` hex 截断 32 字符。
/// 同一用户对不同 sector 呈现不同的稳定假名 sub，防 RP 间串联画像；同 sector 内
/// 恒定（可关联登录）。salt 取 client.sector_identifier_uri（未声明时 fallback
/// client_id——既有行为，回归不变）。
fn pairwise_subject(salt: &str, user_id: i64) -> String {
    let digest = crate::utils::crypto::token_hash(&format!("{salt}:{user_id}"));
    digest[..32].to_string()
}

/// subject 解析：public → user_id 字符串；pairwise → per-sector 稳定假名
///（sector_identifier_uri 声明优先，未声明 fallback client_id）
fn resolve_subject(client: &ClientModel, user_id: i64) -> String {
    if client.subject_type == "pairwise" {
        let salt = client
            .sector_identifier_uri
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&client.client_id);
        pairwise_subject(salt.trim(), user_id)
    } else {
        user_id.to_string()
    }
}

/// v5-D2：生成 RSA-2048 私钥并输出 PKCS#8 PEM（client 级 RS256 签名密钥）。
///
/// v5-D2 修正（真实运行验证发现）：rsa 0.9 的 keygen 素性测试需要较大线程栈，
/// 在 tokio worker（默认 2MB 栈）上直接调用会 stack overflow（0xC0000005 硬崩、
/// 连接重置且无任何日志）。故固定在 **16MB 独立栈线程**同步执行——调用方处于
/// async 上下文时应配合 `tokio::task::spawn_blocking` 使用。
pub(crate) fn generate_rsa_private_pem() -> anyhow::Result<String> {
    use rsa::pkcs8::EncodePrivateKey;
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let mut rng = rand::thread_rng();
            let private = rsa::RsaPrivateKey::new(&mut rng, 2048)?;
            let pem = private.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
            Ok(pem.to_string())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("RSA keygen 线程异常终止"))?
}

/// v5-D2：从 RS256 私钥 PEM 构造该客户端的 JWK（公钥组件 n/e，base64url 无填充）。
/// kid = client_id（JWKS 聚合键）。私钥解析失败返回 Err（跳过该客户端，不影响整体）。
fn rsa_public_jwk(private_pem: &str, kid: &str) -> anyhow::Result<serde_json::Value> {
    use base64::Engine as _;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(private_pem)?;
    let n = private.n().to_bytes_be();
    let e = private.e().to_bytes_be();
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    Ok(serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": b64(&n),
        "e": b64(&e),
    }))
}

/// D9：计算 RS256 私钥的 JWK Thumbprint（RFC 7638 §3）——规范化 JSON 成员顺序严格为
/// `e,kty,n`（无空白）→ SHA-256 → base64url 无填充。对同一 PEM 恒定、不同密钥互异，
/// 作为客户端密钥指纹登记于 `sys_oauth_client.key_id`（供 JWKS `kid` 使用）。
fn rsa_key_thumbprint(private_pem: &str) -> anyhow::Result<String> {
    use base64::Engine as _;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use sha2::{Digest, Sha256};
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(private_pem)?;
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let canon = format!(
        "{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}",
        b64(&private.e().to_bytes_be()),
        b64(&private.n().to_bytes_be())
    );
    let digest = Sha256::digest(canon.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

/// PKCE：S256(code_verifier) == code_challenge（base64url 无填充）
pub fn pkce_verify(code_verifier: &str, code_challenge: &str) -> bool {
    use base64::Engine;
    if code_verifier.is_empty() || code_challenge.is_empty() {
        return false;
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let digest = hasher.finalize();
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    computed == code_challenge
}

/// 请求 scope 是否为客户端允许 scope 的子集
pub fn scopes_subset(requested: &[String], allowed: &[String]) -> bool {
    requested.iter().all(|r| allowed.iter().any(|a| a == r))
}

/// 拆分空格分隔的 scope 字符串
pub fn split_scope(s: &str) -> Vec<String> {
    s.split_whitespace().map(|x| x.to_string()).collect()
}

/// client_id 格式：1~64 位字母数字下划线连字符
pub fn is_valid_client_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// redirect_uri 校验：必须 http(s) 绝对地址；返回去空白后的列表（拒绝空/重复）
fn validate_redirect_uris(list: &[String]) -> Result<Vec<String>, ServiceError> {
    let mut out: Vec<String> = Vec::with_capacity(list.len());
    for raw in list {
        let u = raw.trim();
        if u.is_empty() {
            continue;
        }
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.redirect_uri_invalid"
            )));
        }
        if out.iter().any(|e| e == u) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.redirect_uri_dup"
            )));
        }
        out.push(u.to_string());
    }
    if out.is_empty() {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.sso.redirect_uris_empty"
        )));
    }
    Ok(out)
}

fn validate_scopes(list: &[String]) -> Result<Vec<String>, ServiceError> {
    let mut out: Vec<String> = Vec::with_capacity(list.len());
    for raw in list {
        let s = raw.trim();
        if s.is_empty() {
            continue;
        }
        if !out.iter().any(|e| e == s) {
            out.push(s.to_string());
        }
    }
    // OIDC：客户端允许范围至少包含 openid
    if !out.iter().any(|s| s == "openid") {
        out.insert(0, "openid".to_string());
    }
    Ok(out)
}

fn validate_client_name(name: &str) -> Result<(), ServiceError> {
    let t = name.trim();
    if t.is_empty() || t.chars().count() > 128 {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.sso.client_name_required"
        )));
    }
    Ok(())
}

/// v3 P1'-3：`logo_uri` 服务端校验——同意页会直接渲染该 URL，不校验即允许管理员填入
/// 任意第三方地址（追踪像素泄漏用户 IP/行为）或超长字符串（DB 列宽溢出）。
/// 规则：空值合法（无 logo）；非空必须为 http(s) 绝对地址、host 非空、总长 ≤ 500。
fn validate_logo_uri(logo_uri: &Option<String>) -> Result<String, ServiceError> {
    let Some(raw) = logo_uri.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(String::new());
    };
    if raw.chars().count() > 500 {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.sso.logo_uri_invalid"
        )));
    }
    if !(raw.starts_with("http://") || raw.starts_with("https://")) {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.sso.logo_uri_invalid"
        )));
    }
    let host_ok = url::Url::parse(raw)
        .ok()
        .map(|u| !u.host_str().unwrap_or_default().is_empty())
        .unwrap_or(false);
    if !host_ok {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.sso.logo_uri_invalid"
        )));
    }
    Ok(raw.to_string())
}

fn normalize_grant_types(input: Option<&[String]>) -> Vec<String> {
    match input {
        None => vec!["authorization_code".to_string()],
        Some(list) => {
            let mut out: Vec<String> = list
                .iter()
                .map(|s| s.trim())
                .filter(|s| *s == "authorization_code" || *s == "refresh_token")
                .map(|s| s.to_string())
                .collect();
            if !out.iter().any(|s| s == "authorization_code") {
                out.insert(0, "authorization_code".to_string());
            }
            out.sort();
            out.dedup();
            out
        }
    }
}

/// v5-D2：ID Token 签名算法归一化（白名单 RS256/HS256，非法值回退 RS256）
fn normalize_id_token_alg(input: Option<&str>) -> String {
    match input.map(str::trim) {
        Some("HS256") => "HS256".to_string(),
        _ => "RS256".to_string(),
    }
}

/// v5-D5：subject 标识类型归一化（白名单 public/pairwise，非法值回退 public）
fn normalize_subject_type(input: Option<&str>) -> String {
    match input.map(str::trim) {
        Some("pairwise") => "pairwise".to_string(),
        _ => "public".to_string(),
    }
}

/// v5-D5：sector_identifier_uri 归一化（空 → None；非空必须 https URL，非法拒绝）
fn validate_sector_identifier(input: Option<&str>) -> Result<Option<String>, ServiceError> {
    match input.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => {
            if s.len() > 255 {
                return Err(ServiceError::bad_request(
                    "sector_identifier_uri 长度须 ≤255",
                ));
            }
            if !s.starts_with("https://") {
                return Err(ServiceError::bad_request(
                    "sector_identifier_uri 必须为 https URL（OIDC 规范要求）",
                ));
            }
            Ok(Some(s.to_string()))
        }
    }
}

fn normalize_flag(input: Option<&str>, default: &str) -> String {
    match input.map(str::trim) {
        Some("0") => "0".to_string(),
        Some("1") => "1".to_string(),
        _ => {
            if default == "0" || default == "1" {
                default.to_string()
            } else {
                "1".to_string()
            }
        }
    }
}

fn to_json_array(list: &[String]) -> String {
    serde_json::to_string(list).unwrap_or_else(|_| "[]".to_string())
}

fn client_to_vo(m: ClientModel) -> SsoClientVo {
    SsoClientVo {
        sso_client_id: m.sso_client_id,
        client_id: m.client_id,
        client_name: m.client_name,
        logo_uri: m.logo_uri,
        redirect_uris: serde_json::from_str(&m.redirect_uris).unwrap_or_default(),
        scopes: serde_json::from_str(&m.scopes).unwrap_or_default(),
        grant_types: serde_json::from_str(&m.grant_types).unwrap_or_default(),
        id_token_alg: m.id_token_alg,
        subject_type: m.subject_type,
        sector_identifier_uri: m.sector_identifier_uri,
        consent_required: m.consent_required,
        enabled: m.enabled,
        remark: m.remark,
        create_time: m
            .create_time
            .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()),
    }
}

/// 常量时间风格比较（避免凭据校验时序侧信道）
fn secret_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// URL 查询参数编码
fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// 构造回跳错误 URL：redirect_uri 为 None 时返回空串（由上层处理硬错误）
fn redirect_error_url(
    redirect_uri: Option<&str>,
    state: &Option<String>,
    error: &str,
    description: &str,
) -> String {
    let Some(ru) = redirect_uri.filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let sep = if ru.contains('?') { "&" } else { "?" };
    let mut url = format!(
        "{}{}error={}&error_description={}",
        ru,
        sep,
        url_encode(error),
        url_encode(description)
    );
    if let Some(st) = state
        && !st.is_empty()
    {
        url.push_str(&format!("&state={}", url_encode(st)));
    }
    url
}

/// 生成 URL-safe 随机串（base64url 无填充）
/// v5-D12：公开随机串生成（SCIM provision 随机密码用）
pub(crate) fn random_urlsafe_pub(bytes_len: usize) -> String {
    random_urlsafe(bytes_len)
}

fn random_urlsafe(bytes_len: usize) -> String {
    use base64::Engine;
    let mut buf = vec![0u8; bytes_len];
    {
        {
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut buf);
        }
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_known_vector() {
        // RFC 7636 附录 B 测试向量
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_verify(verifier, challenge));
        assert!(!pkce_verify("wrong-verifier", challenge));
        assert!(!pkce_verify("", challenge));
    }

    #[test]
    fn scopes_subset_logic() {
        let allowed = vec!["openid".to_string(), "profile".to_string()];
        assert!(scopes_subset(&["openid".to_string()], &allowed));
        assert!(scopes_subset(
            &["openid".to_string(), "profile".to_string()],
            &allowed
        ));
        assert!(!scopes_subset(
            &["openid".to_string(), "email".to_string()],
            &allowed
        ));
    }

    #[test]
    fn split_scope_handles_spaces() {
        assert_eq!(
            split_scope("openid profile  email"),
            vec!["openid", "profile", "email"]
        );
        assert!(split_scope("").is_empty());
    }

    /// v5-D9：同意票逐字比对——**一致即通过**、**任何实质差异即拒绝**（可证伪）。
    #[test]
    fn consent_ticket_accepts_exact_match_only() {
        let ticket = ConsentTicket {
            user_id: 42,
            client_id: "app_x".to_string(),
            redirect_uri: "https://app.test/cb".to_string(),
            scope: "openid profile".to_string(),
            state: Some("st_1".to_string()),
            nonce: Some("n_1".to_string()),
            code_challenge: "CH".to_string(),
            code_challenge_method: "S256".to_string(),
        };
        // 基线：完全一致 ⇒ 通过
        assert!(consent_ticket_matches(
            &ticket,
            42,
            "app_x",
            "https://app.test/cb",
            "openid profile",
            Some("st_1"),
            Some("n_1"),
            "CH",
            "S256"
        ));
        // 逐项篡改 ⇒ 全部必须失败（少一项都可能放过中间人篡改）
        let cases: [(&str, bool); 8] = [
            (
                "改 scope",
                consent_ticket_matches(
                    &ticket,
                    42,
                    "app_x",
                    "https://app.test/cb",
                    "openid profile email",
                    Some("st_1"),
                    Some("n_1"),
                    "CH",
                    "S256",
                ),
            ),
            (
                "改 redirect_uri",
                consent_ticket_matches(
                    &ticket,
                    42,
                    "app_x",
                    "https://evil.test/cb",
                    "openid profile",
                    Some("st_1"),
                    Some("n_1"),
                    "CH",
                    "S256",
                ),
            ),
            (
                "改 state",
                consent_ticket_matches(
                    &ticket,
                    42,
                    "app_x",
                    "https://app.test/cb",
                    "openid profile",
                    Some("st_2"),
                    Some("n_1"),
                    "CH",
                    "S256",
                ),
            ),
            (
                "改 nonce",
                consent_ticket_matches(
                    &ticket,
                    42,
                    "app_x",
                    "https://app.test/cb",
                    "openid profile",
                    Some("st_1"),
                    Some("n_2"),
                    "CH",
                    "S256",
                ),
            ),
            (
                "改 code_challenge",
                consent_ticket_matches(
                    &ticket,
                    42,
                    "app_x",
                    "https://app.test/cb",
                    "openid profile",
                    Some("st_1"),
                    Some("n_1"),
                    "OTHER",
                    "S256",
                ),
            ),
            (
                "改 code_challenge_method",
                consent_ticket_matches(
                    &ticket,
                    42,
                    "app_x",
                    "https://app.test/cb",
                    "openid profile",
                    Some("st_1"),
                    Some("n_1"),
                    "CH",
                    "plain",
                ),
            ),
            (
                "改 client_id",
                consent_ticket_matches(
                    &ticket,
                    42,
                    "app_y",
                    "https://app.test/cb",
                    "openid profile",
                    Some("st_1"),
                    Some("n_1"),
                    "CH",
                    "S256",
                ),
            ),
            (
                "他人用户（拿别人的票）",
                consent_ticket_matches(
                    &ticket,
                    43,
                    "app_x",
                    "https://app.test/cb",
                    "openid profile",
                    Some("st_1"),
                    Some("n_1"),
                    "CH",
                    "S256",
                ),
            ),
        ];
        for (name, matched) in cases {
            assert!(!matched, "{name} 必须被拒绝（票面与提交值逐字比对）");
        }
    }

    /// v5-D9：`None` 与空串**等价**（前端 `q()` 缺失 query 时返回空串/undefined），
    /// 但"空 vs 非空"仍属实质差异（不得被归一放过）。
    #[test]
    fn consent_ticket_none_and_empty_are_equivalent() {
        let mut ticket = ConsentTicket {
            user_id: 7,
            client_id: "app_x".to_string(),
            redirect_uri: "https://app.test/cb".to_string(),
            scope: "openid".to_string(),
            state: None,
            nonce: Some(String::new()),
            code_challenge: "CH".to_string(),
            code_challenge_method: "S256".to_string(),
        };
        // None（票面） vs 空串（提交） ⇒ 通过
        assert!(consent_ticket_matches(
            &ticket,
            7,
            "app_x",
            "https://app.test/cb",
            "openid",
            Some(""),
            None,
            "CH",
            "S256"
        ));
        // 票面为空、提交非空 ⇒ 拒绝
        ticket.state = Some(String::new());
        assert!(!consent_ticket_matches(
            &ticket,
            7,
            "app_x",
            "https://app.test/cb",
            "openid",
            Some("st"),
            None,
            "CH",
            "S256"
        ));
    }

    #[test]
    fn prompt_contains_directives() {
        let base = |prompt: Option<&str>| AuthorizeParams {
            client_id: "app_x".to_string(),
            redirect_uri: None,
            response_type: "code".to_string(),
            scope: "openid".to_string(),
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            prompt: prompt.map(str::to_string),
            max_age: None,
            acr_values: None,
        };
        assert!(prompt_contains(&base(Some("none")), "none"));
        assert!(prompt_contains(&base(Some("login none")), "none"));
        assert!(prompt_contains(&base(Some("login none")), "login"));
        assert!(!prompt_contains(&base(Some("login")), "none"));
        assert!(!prompt_contains(&base(None), "none"));
        assert!(!prompt_contains(&base(Some("nonexistent")), "none"));
    }

    #[test]
    fn pairwise_subject_stable_and_distinct() {
        // 同 RP 同用户恒定；不同 RP 假名互异；异用户假名互异
        let a1 = pairwise_subject("app_a", 1);
        assert_eq!(a1, pairwise_subject("app_a", 1), "同 RP 同用户应恒定");
        assert_ne!(a1, pairwise_subject("app_b", 1), "不同 RP 假名应互异");
        assert_ne!(a1, pairwise_subject("app_a", 2), "不同用户假名应互异");
        assert_eq!(a1.len(), 32, "假名应截断为 32 hex 字符");
        // sub 与 user_id 不应可逆关联（假名 ≠ user_id 字符串）
        assert_ne!(a1, "1");
    }

    #[test]
    fn pairwise_sector_aggregation() {
        // v5-D5：同 sector 的两个 RP → 相同 sub（组织内账号关联）
        let rp1 = pairwise_subject("https://corp.example/sector", 7);
        let rp2 = pairwise_subject("https://corp.example/sector", 7);
        assert_eq!(rp1, rp2, "同 sector 不同 RP 应同 sub");
        // 不同 sector → 互异
        assert_ne!(
            rp1,
            pairwise_subject("https://other.example/sector", 7),
            "不同 sector 假名应互异"
        );
        // sector 模式与 fallback（client_id 模式）互异
        assert_ne!(
            rp1,
            pairwise_subject("app_a", 7),
            "sector 与 client_id 盐应互异"
        );
    }

    #[test]
    fn sector_identifier_validation() {
        // https 合法；http/空超长非法
        assert!(
            validate_sector_identifier(Some("https://corp.example/sector"))
                .unwrap()
                .is_some()
        );
        assert!(validate_sector_identifier(Some("")).unwrap().is_none());
        assert!(validate_sector_identifier(None).unwrap().is_none());
        assert!(validate_sector_identifier(Some("http://corp.example")).is_err());
        assert!(validate_sector_identifier(Some(&"x".repeat(256))).is_err());
    }

    #[test]
    fn client_id_format() {
        assert!(is_valid_client_id("app_abc123"));
        assert!(is_valid_client_id("my-client"));
        assert!(!is_valid_client_id(""));
        assert!(!is_valid_client_id("bad id"));
        assert!(!is_valid_client_id(&"x".repeat(65)));
    }

    #[test]
    fn validate_redirect_uris_rules() {
        // 合法
        assert!(validate_redirect_uris(&["https://app.example.com/cb".to_string()]).is_ok());
        // 非 http(s)
        assert!(validate_redirect_uris(&["ftp://x".to_string()]).is_err());
        // 空列表
        assert!(validate_redirect_uris(&[]).is_err());
        // 重复
        assert!(
            validate_redirect_uris(&["https://a/cb".to_string(), "https://a/cb".to_string()])
                .is_err()
        );
    }

    #[test]
    fn validate_scopes_forces_openid() {
        let s = validate_scopes(&["profile".to_string()]).unwrap();
        assert_eq!(s[0], "openid");
        assert!(s.contains(&"profile".to_string()));
    }

    #[test]
    fn normalize_grant_types_always_has_code() {
        let g = normalize_grant_types(Some(&["refresh_token".to_string()]));
        assert!(g.contains(&"authorization_code".to_string()));
        assert!(g.contains(&"refresh_token".to_string()));
    }

    #[test]
    fn secret_eq_constant_time() {
        assert!(secret_eq("abcdef", "abcdef"));
        assert!(!secret_eq("abcdef", "abcdeg"));
        assert!(!secret_eq("abc", "abcdef"));
    }

    #[test]
    fn redirect_error_url_builds() {
        let u = redirect_error_url(
            Some("https://app/cb"),
            &Some("xyz".into()),
            "access_denied",
            "no",
        );
        assert!(u.starts_with("https://app/cb?error=access_denied"));
        assert!(u.contains("&state=xyz"));
        // 无 redirect_uri → 空串
        assert!(redirect_error_url(None, &None, "x", "y").is_empty());
    }

    #[test]
    fn resolve_redirect_uri_exact_match() {
        let wl = ["https://app/cb".to_string()];
        // 显式给出且命中 → 原样返回
        assert_eq!(
            resolve_redirect_uri(Some("https://app/cb"), &wl).as_deref(),
            Some("https://app/cb")
        );
        // 显式给出但未命中 → None（防开放重定向）
        assert_eq!(resolve_redirect_uri(Some("https://evil/cb"), &wl), None);
        // 未给出且白名单唯一 → 回填唯一值
        assert_eq!(
            resolve_redirect_uri(None, &wl).as_deref(),
            Some("https://app/cb")
        );
        // 未给出且白名单多值 → 不可猜测，None
        let multi = ["https://a/cb".to_string(), "https://b/cb".to_string()];
        assert_eq!(resolve_redirect_uri(None, &multi), None);
    }

    /// D9：RFC 7638 §3 JWK Thumbprint——字符集 / 长度 / 同 PEM 恒定 / 异密钥互异。
    #[test]
    fn rsa_key_thumbprint_rfc7638_properties() {
        let pem1 = generate_rsa_private_pem().expect("生成 PEM1 失败");
        let t1 = rsa_key_thumbprint(&pem1).expect("计算 thumbprint 失败");
        assert!(
            t1.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "thumbprint 应仅含 base64url 无填充字符集，实际: {t1}"
        );
        // SHA-256(32B) → base64url = 43 字符（容 43±1）
        assert!(
            (43usize).abs_diff(t1.len()) <= 1,
            "thumbprint 长度应 43±1，实际 {}",
            t1.len()
        );
        // 同 PEM 恒定（确定性）
        assert_eq!(t1, rsa_key_thumbprint(&pem1).unwrap(), "同 PEM 应恒定");
        // 两次独立生成互不相等
        let pem2 = generate_rsa_private_pem().expect("生成 PEM2 失败");
        assert_ne!(
            t1,
            rsa_key_thumbprint(&pem2).unwrap(),
            "不同密钥 thumbprint 应互异"
        );
    }

    /// 校验 error.sso.* 全部键在 zh-CN（默认）与 en-US 双语均存在真实翻译
    ///（rust-i18n 命中失败时回退返回键本身，故用 `!= 键` 判定缺失）。
    #[test]
    fn sso_error_keys_resolved_in_both_locales() {
        macro_rules! chk {
            ($($k:literal),+ $(,)?) => {
                $({
                    let s = crate::tr!($k);
                    assert_ne!(s, $k, "缺少翻译: {}", $k);
                    assert!(!s.is_empty(), "翻译为空: {}", $k);
                })+
            };
        }
        // zh-CN 为默认 locale
        chk!(
            "error.sso.disabled",
            "error.sso.client_not_found",
            "error.sso.client_disabled",
            "error.sso.client_id_required",
            "error.sso.client_id_exists",
            "error.sso.client_name_required",
            "error.sso.redirect_uris_empty",
            "error.sso.redirect_uri_invalid",
            "error.sso.redirect_uri_not_allowed",
            "error.sso.scope_invalid",
            "error.sso.response_type_unsupported",
            "error.sso.pkce_required",
            "error.sso.pkce_method_unsupported",
            "error.sso.openid_scope_required",
            "error.sso.not_login",
            "error.sso.code_invalid",
            "error.sso.client_auth_failed",
            "error.sso.grant_type_unsupported",
            "error.sso.pkce_verify_failed",
            "error.sso.token_failed",
            "error.sso.access_token_invalid",
            "error.sso.batch_id_invalid",
            "error.sso.redirect_uri_dup",
            "error.sso.client_id_reserved",
            "error.sso.secret_encrypt_failed",
        );
        // en-US 显式切换 locale
        crate::common::i18n::with_locale_sync("en-US", || {
            chk!(
                "error.sso.disabled",
                "error.sso.client_not_found",
                "error.sso.client_disabled",
                "error.sso.client_id_required",
                "error.sso.client_id_exists",
                "error.sso.client_name_required",
                "error.sso.redirect_uris_empty",
                "error.sso.redirect_uri_invalid",
                "error.sso.redirect_uri_not_allowed",
                "error.sso.scope_invalid",
                "error.sso.response_type_unsupported",
                "error.sso.pkce_required",
                "error.sso.pkce_method_unsupported",
                "error.sso.openid_scope_required",
                "error.sso.not_login",
                "error.sso.code_invalid",
                "error.sso.client_auth_failed",
                "error.sso.grant_type_unsupported",
                "error.sso.pkce_verify_failed",
                "error.sso.token_failed",
                "error.sso.access_token_invalid",
                "error.sso.batch_id_invalid",
                "error.sso.redirect_uri_dup",
                "error.sso.client_id_reserved",
                "error.sso.secret_encrypt_failed",
            );
        });
    }
}
