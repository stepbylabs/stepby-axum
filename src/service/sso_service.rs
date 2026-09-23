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
//! - 授权码一次性（Redis 原子 GETDEL + 短 TTL），绑定 client_id + redirect_uri + code_challenge；
//! - PKCE 强制 S256（拒绝 plain / 缺失）；redirect_uri **精确匹配**白名单（防开放重定向）；
//! - token / userinfo 错误按 RFC 6749/7591 返回 `{"error","error_description"}`（bare JSON，非信封）。
//!
//! 分层约束：不依赖 axum/tower；Redis / JwtConfig / SsoConfig 由调用方注入。

use base64::Engine as _;
use redis::aio::ConnectionManager;
use sea_orm::DatabaseConnection;
use sea_orm::Set;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;
use crate::common::error::ServiceError;
use crate::config::{JwtConfig, SsoConfig};
use crate::entity::sys_oauth_client::{ActiveModel as ClientActiveModel, Model as ClientModel};
use crate::jwt::claims::JwtUtils;
use crate::repository::sys_oauth_client::SysOauthClientRepository;
use crate::repository::sys_oauth_consent::SysOauthConsentRepository;

/// 授权码 Redis key 前缀
const CODE_KEY_PREFIX: &str = "sso:code:";
/// access_token（不透明令牌，v4-P0-A）Redis key 前缀：key = `sso:at:{sha256(token)}`
const AT_KEY_PREFIX: &str = "sso:at:";
/// 用户 → 已签发 SSO access_token 集合（v4-F2）：登出/强退/改密时按用户全量吊销
const USER_AT_KEY_PREFIX: &str = "sso:user_at:";
/// 登录会话索引（v3-P0-B）：`sso:sess:{uid}` = Set(token_hash)，end_session 时定位该用户全部登录会话
const SESS_KEY_PREFIX: &str = "sso:sess:";
/// client_id 保留字（v4 §1.3）：禁止与协议自身命名空间/常见系统字冲突。
/// 注意：与平台 jwt.audience / jwt.issuer 的碰撞校验是**动态比对配置**（见 add_client），
/// 静态表只兜底通用保留字，不兜底可配置值。
const RESERVED_CLIENT_IDS: &[&str] = &[
    "sso", "oidc", "oauth", "oauth2", "admin", "system", "api", "internal", "yebot",
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
    pub consent_required: String,
    pub enabled: String,
    pub remark: Option<String>,
    pub create_time: Option<String>,
}

/// 客户端分页查询条件
#[derive(Debug, Clone, Deserialize, ToSchema, TS)]
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
}

/// /sso/token 请求参数 —— **OAuth2/OIDC 协议面**（外部 RP 用标准客户端库调用），
/// 参数名由 RFC 6749 强制固定为 snake_case，不参与 camelCase / ts-rs 转换。
#[derive(Debug, Clone, Deserialize, Default)]
pub struct TokenParams {
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
}

/// /sso/token 成功响应（bare JSON）—— **协议面**，字段名由 OIDC 规范固定为 snake_case。
#[derive(Debug, Clone, Serialize)]
pub struct TokenResult {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
    pub id_token: String,
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
    pub fn discovery(&self, issuer: &str, _config: &SsoConfig) -> serde_json::Value {
        let issuer = issuer.trim_end_matches('/');
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}/sso/authorize", issuer),
            "token_endpoint": format!("{}/sso/token", issuer),
            "userinfo_endpoint": format!("{}/sso/userinfo", issuer),
            "end_session_endpoint": format!("{}/sso/logout", issuer),
            // v4 §5：OIDC Discovery 规定 jwks_uri 为 REQUIRED。HS256 不发布公钥，
            // 返回空 keys 集合（合规 RP 不会从对称密钥验证方拉取 JWKS）。
            "jwks_uri": format!("{}/sso/jwks", issuer),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256"],
            "scopes_supported": ["openid", "profile", "email"],
            // v3-P1-7：同时声明 client_secret_basic（大量 RP 客户端库默认 Basic）
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
            // v4 §6：claims_supported 与 scopes_supported 自洽（email scope 有对应 claim）
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
                "preferred_username", "name", "email", "email_verified"
            ],
        })
    }

    /// JWKS 端点响应（v4 §5）：HS256 对称签名不发布公钥，返回空 keys 集合以满足
    /// OIDC Discovery 对 jwks_uri REQUIRED 的要求；升级 RS256 后此处返回真实公钥集。
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({ "keys": [] })
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
        redis: &mut ConnectionManager,
        jwt: &JwtConfig,
        config: &SsoConfig,
    ) -> Result<AuthorizeOutcome, ServiceError> {
        if !config.enabled {
            return Err(ServiceError::bad_request(&crate::tr!("error.sso.disabled")));
        }

        // 1. 解析会话（JWT 校验 + 黑名单）；未登录 → 引导登录
        let identity = match self.resolve_session(session_token, redis, jwt).await? {
            Some(id) => id,
            None => return Ok(AuthorizeOutcome::NeedLogin),
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
                return Ok(AuthorizeOutcome::NeedConsent(Box::new(ConsentEcho {
                    client_id: client.client_id.clone(),
                    client_name: client.client_name.clone(),
                    logo_uri: client.logo_uri.clone(),
                    scopes: requested.clone(),
                    redirect_uri,
                    state: params.state.clone(),
                    nonce: params.nonce.clone(),
                    code_challenge,
                })));
            }
        }

        // 6. 直接签发授权码并回跳（auth_time 取登录会话的认证时刻，v3 P1'-1）
        let url = self
            .issue_code_redirect(
                identity.auth_time,
                identity.user_id,
                &identity.username,
                &client.client_id,
                &redirect_uri,
                &requested,
                &code_challenge,
                params.nonce.as_deref(),
                params.state.as_deref(),
                redis,
                config,
            )
            .await?;
        Ok(AuthorizeOutcome::Redirect(url))
    }

    /// 同意页批准 / 拒绝（受保护接口，用户身份来自登录态 Operator）
    pub async fn consent(
        &self,
        user_id: i64,
        username: &str,
        dto: ConsentDto,
        redis: &mut ConnectionManager,
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
                &client.client_id,
                &client.client_name,
                &serde_json::to_string(&requested)
                    .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))?,
                now,
            )
            .await?;

        // auth_time：同意页批准路径的身份来自登录态 Operator，其认证时刻由 handler 从
        // Claims.iat 传入（v3 P1'-1）
        self.issue_code_redirect(
            dto.auth_time
                .unwrap_or_else(|| chrono::Utc::now().timestamp()),
            user_id,
            username,
            &client.client_id,
            &redirect_uri,
            &requested,
            &code_challenge,
            dto.nonce.as_deref(),
            dto.state.as_deref(),
            redis,
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
        client_id: &str,
        redirect_uri: &str,
        scope: &[String],
        code_challenge: &str,
        nonce: Option<&str>,
        state: Option<&str>,
        redis: &mut ConnectionManager,
        config: &SsoConfig,
    ) -> Result<String, ServiceError> {
        let code = random_urlsafe(32);
        // v4 §6：查一次用户资料填充 email/nick_name（email scope 的真实数据链路；
        // 绑定随码缓存，token 兑换与 userinfo 无需再查库）
        let (nick_name, email) = self.lookup_user_profile(user_id).await;
        let binding = CodeBinding {
            client_id: client_id.to_string(),
            user_id,
            username: username.to_string(),
            nick_name,
            email,
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
        redis::cmd("SET")
            .arg(&key)
            .arg(&json)
            .arg("EX")
            .arg(config.code_ttl_secs.max(1))
            .query_async::<()>(redis)
            .await
            .map_err(|e| {
                tracing::error!("SSO 授权码写入 Redis 失败: {}", e);
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

    /// 处理 POST /sso/token（authorization_code 交换）
    ///
    /// v4-P0-A：`jwt` 参数已移除——access_token 不再是平台 JWT，无需平台签名密钥。
    pub async fn token(
        &self,
        params: TokenParams,
        redis: &mut ConnectionManager,
        config: &SsoConfig,
        base_url: &str,
    ) -> Result<TokenResult, OidcError> {
        if !config.enabled {
            return Err(OidcError::new(
                "invalid_request",
                crate::tr!("error.sso.disabled"),
            ));
        }
        if params.grant_type != "authorization_code" {
            return Err(OidcError::new(
                "unsupported_grant_type",
                crate::tr!("error.sso.grant_type_unsupported"),
            ));
        }
        let code = params
            .code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| {
                OidcError::new("invalid_request", crate::tr!("error.sso.code_invalid"))
            })?;

        // 客户端凭据校验（client_id/secret 可来自表单或 Basic 头，handler 已合并；
        // 缺失按 RFC 6749 §5.2 返回 invalid_client，handler 据此映射 401 + WWW-Authenticate）
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
                OidcError::new("invalid_grant", crate::tr!("error.sso.client_auth_failed"))
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
        if !secret_eq(&expected_hash, &client.client_secret_hash) {
            return Err(OidcError::new(
                "invalid_client",
                crate::tr!("error.sso.client_auth_failed"),
            ));
        }

        // 一次性取码（原子 GETDEL，防重放）
        let key = format!("{}{}", CODE_KEY_PREFIX, code);
        let binding_json = self
            .getdel_code(&key, redis)
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
        let now_secs = chrono::Utc::now().timestamp();
        let at_ttl = config.access_token_ttl_secs.max(1);
        let at_hash = crate::utils::crypto::token_hash(&access_token);
        binding.access_token_hash = at_hash.clone();
        let at_binding = AccessBinding {
            client_id: client.client_id.clone(),
            user_id: binding.user_id,
            username: binding.username.clone(),
            nick_name: binding.nick_name.clone(),
            email: binding.email.clone(),
            scope: binding.scope.clone(),
            auth_time: binding.auth_time,
        };
        let at_json = serde_json::to_string(&at_binding)
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;
        let at_key = format!("{}{}", AT_KEY_PREFIX, at_hash);
        let _: () = redis::cmd("SET")
            .arg(&at_key)
            .arg(&at_json)
            .arg("EX")
            .arg(at_ttl)
            .query_async(redis)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;
        // v4-F2：登记「用户 → 已签发 SSO AT」集合（登出/强退/改密全量吊销用）+ 在线可见。
        // 读路径有 EXISTS 悬空自愈（见 revoke_user_sso_tokens），集合 TTL 稍大于 AT TTL。
        let user_at_key = format!("{}{}", USER_AT_KEY_PREFIX, binding.user_id);
        let _: () = redis::cmd("SADD")
            .arg(&user_at_key)
            .arg(&at_hash)
            .query_async(redis)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;
        let _: () = redis::cmd("EXPIRE")
            .arg(&user_at_key)
            .arg(at_ttl + 60)
            .query_async(redis)
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
            exp: now_secs + at_ttl as i64,
            source: "sso".to_string(),
        };
        if let Ok(json) = serde_json::to_string(&online) {
            let online_key = format!("online:{}", at_hash);
            let _: () = redis::cmd("SETEX")
                .arg(&online_key)
                .arg(at_ttl)
                .arg(&json)
                .query_async(redis)
                .await
                .map_err(|_| {
                    OidcError::new("server_error", crate::tr!("error.sso.token_failed"))
                })?;
        }

        // 签发 id_token（HS256 + 每客户端密钥）
        let id_token = self
            .build_id_token(&client, &binding, config, base_url)
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;

        Ok(TokenResult {
            access_token,
            token_type: "Bearer",
            // v4-P0-A：expires_in 必须等于 access_token 的真实生命周期
            //（旧实现错用 id_token_ttl_secs，而 JWT exp 由 jwt.expire_hours 决定，两者严重不一致）
            expires_in: at_ttl,
            scope: binding.scope.join(" "),
            id_token,
        })
    }

    /// 原子读取并删除授权码（Redis GETDEL），命中返回 Some(JSON 字符串)
    async fn getdel_code(
        &self,
        key: &str,
        redis: &mut ConnectionManager,
    ) -> Result<Option<String>, OidcError> {
        let val: Option<String> = redis::cmd("GETDEL")
            .arg(key)
            .query_async(redis)
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
        claims.insert("sub".into(), serde_json::json!(binding.user_id.to_string()));
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
        let payload = serde_json::Value::Object(claims);
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());
        // v3-P1'-4：id_token_secret 以 enc2: 信封加密存储，签名前解密（明文兼容迁移期旧数据）
        let secret = self.decrypt_client_secret(&client.id_token_secret);
        let token = encode(
            &header,
            &payload,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))?;
        Ok(token)
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
        redis: &mut ConnectionManager,
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
        let raw: Option<String> = redis::cmd("GET")
            .arg(&at_key)
            .query_async(redis)
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
        claims.insert("sub".into(), serde_json::json!(binding.user_id.to_string()));
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
        redis: &mut ConnectionManager,
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
        // 黑名单校验：已登出的会话不再视为有效
        let token_hash = crate::utils::crypto::token_hash(token);
        let blacklist_key = format!("blacklist:{}", token_hash);
        let blacklisted: Option<String> = redis::cmd("GET")
            .arg(&blacklist_key)
            .query_async(redis)
            .await
            .unwrap_or(None);
        if blacklisted.is_some() {
            return Ok(None);
        }
        // v3-P0-B：登记登录会话索引（`sso:sess:{uid}` = hash 集合），
        // end_session 可按用户跨端拉黑全部 IdP 会话；TTL = JWT 剩余寿命。
        let remaining = (claims.exp as i64)
            .saturating_sub(chrono::Utc::now().timestamp())
            .max(60);
        let sess_key = format!("{}{}", SESS_KEY_PREFIX, user_id);
        let _: Result<i64, _> = redis::cmd("SADD")
            .arg(&sess_key)
            .arg(&token_hash)
            .query_async(redis)
            .await;
        let _: Result<i64, _> = redis::cmd("EXPIRE")
            .arg(&sess_key)
            .arg(remaining)
            .query_async(redis)
            .await;
        Ok(Some(SessionIdentity {
            user_id,
            username: claims.username,
            // v3 P1'-1：登录 JWT 的 iat 即用户认证时刻（claims.rs:123 签发时写入）
            auth_time: claims.iat as i64,
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
        redis: &mut ConnectionManager,
    ) -> Result<bool, ServiceError> {
        let revoked = self.consent_repo.revoke(user_id, client_id).await?;
        if revoked {
            self.revoke_user_client_tokens(redis, user_id, client_id)
                .await;
        }
        Ok(revoked)
    }

    pub async fn get_client_page(
        &self,
        q: SsoClientQueryDto,
    ) -> Result<(Vec<SsoClientVo>, u64), ServiceError> {
        let page_num = q.page_num.unwrap_or(1).max(1);
        let page_size = q.page_size.unwrap_or(10).clamp(1, 100);
        let offset = (page_num - 1) * page_size;
        let (rows, total) = self
            .client_repo
            .find_page_filtered(
                offset,
                page_size,
                q.client_name.as_deref(),
                q.client_id.as_deref(),
                q.enabled.as_deref(),
            )
            .await?;
        Ok((rows.into_iter().map(client_to_vo).collect(), total))
    }

    pub async fn get_client_by_pk(&self, pk: i64) -> Result<SsoClientVo, ServiceError> {
        let m =
            self.client_repo.find_by_pk(pk).await?.ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.sso.client_not_found"))
            })?;
        Ok(client_to_vo(m))
    }

    pub async fn add_client(
        &self,
        dto: SsoClientUpsertDto,
        create_by: &str,
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

        let now = datetime::now_naive();
        let am = ClientActiveModel {
            client_id: Set(client_id.clone()),
            client_secret_hash: Set(client_secret_hash),
            id_token_secret: Set(id_token_secret_stored),
            client_name: Set(dto.client_name.trim().to_string()),
            logo_uri: Set(logo_uri),
            redirect_uris: Set(to_json_array(&redirect_uris)),
            scopes: Set(to_json_array(&scopes)),
            grant_types: Set(to_json_array(&grant_types)),
            consent_required: Set(normalize_flag(dto.consent_required.as_deref(), "1")),
            enabled: Set(normalize_flag(dto.enabled.as_deref(), "1")),
            remark: Set(dto.remark),
            tenant_id: Set(0),
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

        // 未回传时保留原值（consent_required / enabled 可选）
        let consent_required = normalize_flag(dto.consent_required.as_deref(), &m.consent_required);
        let enabled = normalize_flag(dto.enabled.as_deref(), &m.enabled);

        // 关键：仅将可编辑列标记为 Set 才能被 ActiveModelTrait::update 真实写入；
        // Model.into() 会产生 Unchanged 值并被 update 跳过。client_id /
        // client_secret_hash / id_token_secret / create_* 保持 Unchanged，杜绝密钥篡改。
        let mut am: ClientActiveModel = m.into();
        am.client_name = Set(dto.client_name.trim().to_string());
        am.logo_uri = Set(logo_uri);
        am.redirect_uris = Set(to_json_array(&redirect_uris));
        am.scopes = Set(to_json_array(&scopes));
        am.grant_types = Set(to_json_array(&grant_types));
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
        redis: &mut ConnectionManager,
    ) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.batch_id_invalid"
            )));
        }
        for id in &ids {
            if let Some(m) = self.client_repo.find_by_pk(*id).await? {
                // 2. 级联吊销该客户端全部已授权用户的 SSO 令牌
                let user_ids = self.consent_repo.user_ids_by_client(&m.client_id).await?;
                for uid in user_ids {
                    self.revoke_user_sso_tokens(redis, uid).await;
                }
                // 3. 清理同意记录（物理删，历史审计可走操作日志）
                self.consent_repo.delete_by_client(&m.client_id).await?;
            }
        }
        // 4. 软删
        self.client_repo.soft_delete_by_ids(ids).await?;
        Ok(())
    }

    pub async fn toggle_client(&self, pk: i64, enabled: &str) -> Result<(), ServiceError> {
        let m =
            self.client_repo.find_by_pk(pk).await?.ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.sso.client_not_found"))
            })?;
        // 仅将 enabled 标记为 Set 才会被 update 写入（before_save 刷新 update_time）
        let mut am: ClientActiveModel = m.into();
        am.enabled = Set(if enabled == "1" {
            "1".to_string()
        } else {
            "0".to_string()
        });
        self.client_repo.update(am).await?;
        Ok(())
    }

    // -------------------- 令牌吊销（v4-F2 / P0-B） --------------------

    /// 全量吊销某用户的全部 SSO access_token（登出 / 强退 / 改密 / 删客户端级联）：
    /// 遍历 `sso:user_at:{uid}` 索引，逐个 DEL `sso:at:{hash}` 与 `online:{hash}`，
    /// 最后清空索引。集合中已自然过期的 hash 删不到任何 key，悬空自愈、无害。
    pub async fn revoke_user_sso_tokens(&self, redis: &mut ConnectionManager, user_id: i64) {
        let user_at_key = format!("{}{}", USER_AT_KEY_PREFIX, user_id);
        let hashes: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&user_at_key)
            .query_async(redis)
            .await
            .unwrap_or_else(|e| {
                tracing::error!("读取用户 SSO 令牌索引失败 user_id={}: {}", user_id, e);
                Vec::new()
            });
        for h in &hashes {
            let _: Result<i64, _> = redis::cmd("DEL")
                .arg(format!("{}{}", AT_KEY_PREFIX, h))
                .query_async(redis)
                .await;
            let _: Result<i64, _> = redis::cmd("DEL")
                .arg(format!("online:{}", h))
                .query_async(redis)
                .await;
        }
        let _: Result<i64, _> = redis::cmd("DEL").arg(&user_at_key).query_async(redis).await;
        if !hashes.is_empty() {
            tracing::info!(
                "已全量吊销用户 SSO access_token user_id={} count={}",
                user_id,
                hashes.len()
            );
        }
    }

    /// 按客户端粒度吊销某用户的 SSO access_token（v4-R8 自助撤销授权的级联动作）：
    /// 读取每个 AT 的绑定 JSON，仅删除 `client_id` 匹配的令牌及其在线会话。
    pub async fn revoke_user_client_tokens(
        &self,
        redis: &mut ConnectionManager,
        user_id: i64,
        client_id: &str,
    ) {
        let user_at_key = format!("{}{}", USER_AT_KEY_PREFIX, user_id);
        let hashes: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&user_at_key)
            .query_async(redis)
            .await
            .unwrap_or_default();
        for h in &hashes {
            let at_key = format!("{}{}", AT_KEY_PREFIX, h);
            let binding_json: Option<String> = redis::cmd("GET")
                .arg(&at_key)
                .query_async(redis)
                .await
                .unwrap_or(None);
            let matched = binding_json
                .as_deref()
                .and_then(|j| serde_json::from_str::<AccessBinding>(j).ok())
                .map(|b| b.client_id == client_id)
                .unwrap_or(false);
            if matched {
                let _: Result<i64, _> = redis::cmd("DEL").arg(&at_key).query_async(redis).await;
                let _: Result<i64, _> = redis::cmd("DEL")
                    .arg(format!("online:{}", h))
                    .query_async(redis)
                    .await;
                let _: Result<i64, _> = redis::cmd("SREM")
                    .arg(&user_at_key)
                    .arg(h)
                    .query_async(redis)
                    .await;
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
        redis: &mut ConnectionManager,
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
            self.revoke_user_sso_tokens(redis, uid).await;
            self.blacklist_user_sessions(redis, uid).await;
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
                let _: Result<(), _> = redis::cmd("SETEX")
                    .arg(format!("blacklist:{}", token_hash))
                    .arg(ttl)
                    .arg("1")
                    .query_async(redis)
                    .await;
                if let Some(uid) = cookie_user {
                    self.revoke_user_sso_tokens(redis, uid).await;
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
    async fn blacklist_user_sessions(&self, redis: &mut ConnectionManager, user_id: i64) {
        let sess_key = format!("{}{}", SESS_KEY_PREFIX, user_id);
        let hashes: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&sess_key)
            .query_async(redis)
            .await
            .unwrap_or_default();
        for h in &hashes {
            // 会话剩余寿命未知（索引与 JWT 同 TTL），拉黑 24h 足以覆盖任何在途会话
            let _: Result<(), _> = redis::cmd("SETEX")
                .arg(format!("blacklist:{}", h))
                .arg(86_400i64)
                .arg("1")
                .query_async(redis)
                .await;
        }
        if !hashes.is_empty() {
            let _: Result<i64, _> = redis::cmd("DEL").arg(&sess_key).query_async(redis).await;
            tracing::info!(
                "已拉黑用户 IdP 会话 user_id={} count={}",
                user_id,
                hashes.len()
            );
        }
    }

    /// 验签 id_token_hint（HS256 + 每客户端 id_token_secret）：
    /// 先**手动 base64url 解码** payload 取出 aud 定位客户端（不验签的 peek 仅用于路由，
    /// 随后立即用该客户端密钥完整验签，不信任 peek 结果），再完整验签。
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
        let secret = self.decrypt_client_secret(&client.id_token_secret);
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[&aud]);
        validation.validate_exp = true;
        match jsonwebtoken::decode::<serde_json::Value>(
            hint,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        ) {
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
fn validate_logo_uri(
    logo_uri: &Option<String>,
) -> Result<String, ServiceError> {
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
fn random_urlsafe(bytes_len: usize) -> String {
    use base64::Engine;
    let mut buf = vec![0u8; bytes_len];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
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
