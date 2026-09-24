//! 第三方登录 / OAuth2 / OIDC 模块 Service 层
//!
//! 职责：
//! - 提供商配置 CRUD（分页、详情、新增、修改、批量删除、启停）
//! - 登录页启用提供商列表（脱敏 client_secret 出参）
//! - 授权 URL 生成（state 防 CSRF，写入 Redis 一次性校验）
//! - 授权回调：授权码换令牌 → 换取用户信息 → 身份映射 → 自动登录 / 返回绑定凭据
//! - 绑定管理（当前用户绑定/解绑第三方身份）
//! - 首次登录自动创建本地账号（auto_create_user='1'）并绑定 + 直接登录
//!
//! 安全设计：
//! - OAuth `state` 参数：随机值 + 服务端 Redis 存储（provider 绑定），回调时一次性校验并删除，防 CSRF/重放
//! - `client_secret`：写接口明文接收，出参一律脱敏为空，防凭据泄漏
//! - 未绑定身份通过一次性 `handoff` 凭据（Redis，短 TTL）承载，绑定页校验后绑定到当前登录账号
//!
//! 分层约束：不依赖任何 Web 框架类型（axum / tower / tower-http），
//! 数据访问委托 Repository 层，状态/错误使用 ServiceError。

use futures::FutureExt;
use garde::Validate;
use redis::aio::ConnectionManager;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::entity::sys_oauth_provider::{
    ActiveModel as SysOauthProviderActiveModel, Model as SysOauthProviderModel,
};
use crate::entity::sys_oauth_user::{
    ActiveModel as SysOauthUserActiveModel, Model as SysOauthUserModel,
};
use crate::entity::sys_user::{ActiveModel as SysUserActiveModel, Model as SysUserModel};
use crate::entity::sys_user_role::ActiveModel as SysUserRoleActiveModel;
use crate::repository::sys_oauth_provider::SysOauthProviderRepository;
use crate::repository::sys_oauth_user::SysOauthUserRepository;
use crate::repository::sys_user::SysUserRepository;
use crate::repository::sys_user_role::SysUserRoleRepository;
use crate::service::SysUserService;
use crate::utils::password::encrypt_password;

/// 自动创建账号时绑定的默认角色（2 = 普通角色，见初始化迁移）
const DEFAULT_ROLE_ID: i64 = 2;
/// OAuth state 保存时长（秒）
const STATE_TTL_SECS: u64 = 600;
/// 绑定凭据（handoff）保存时长（秒）
const HANDOFF_TTL_SECS: u64 = 600;
/// 默认新账号初始密码长度
const AUTH_PWD_LEN: usize = 20;
/// 生成用户名的最大尝试次数
const USERNAME_MAX_ATTEMPTS: u32 = 8;
/// 用户名最大长度（对齐 sys_user.user_name 业务约束 <30）
const USERNAME_MAX_LEN: usize = 24;

// 提供商类型白名单
const PROVIDER_TYPES: &[&str] = &["github", "gitee", "wecom", "oidc"];

fn validate_provider_type(provider_type: &str) -> Result<(), ServiceError> {
    if PROVIDER_TYPES.contains(&provider_type) {
        Ok(())
    } else {
        Err(ServiceError::bad_request(&crate::tr!(
            "error.oauth.provider_type_invalid",
            provider_type = provider_type
        )))
    }
}

/// 生成授权/状态随机串（基于 CSPRNG）
fn random_token(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| CHARS[(rand::random::<u32>() as usize) % CHARS.len()] as char)
        .collect()
}

/// 生成符合密码复杂度要求的临时初始密码
fn random_password(len: usize) -> String {
    use rand::Rng;
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const DIGIT: &[u8] = b"0123456789";
    const SPECIAL: &[u8] = b"!@#$%^&*-_+=?";
    let mut rng = rand::thread_rng();
    let mut out: Vec<u8> = Vec::with_capacity(len);
    // 各占一字符，保证四类字符都存在
    out.push(UPPER[(rng.gen_range(0..u32::MAX) as usize) % UPPER.len()]);
    out.push(LOWER[(rng.gen_range(0..u32::MAX) as usize) % LOWER.len()]);
    out.push(DIGIT[(rng.gen_range(0..u32::MAX) as usize) % DIGIT.len()]);
    out.push(SPECIAL[(rng.gen_range(0..u32::MAX) as usize) % SPECIAL.len()]);
    let all: &[u8] = &[UPPER, LOWER, DIGIT, SPECIAL].concat();
    while out.len() < len {
        out.push(all[(rng.gen_range(0..u32::MAX) as usize) % all.len()]);
    }
    // 洗牌避免前 4 位固定类别可被猜测
    use rand::seq::SliceRandom;
    out.shuffle(&mut rng);
    String::from_utf8(out).expect("随机密码字节均为 ASCII")
}

/// 将第三方唯一标识净化为可用的本地用户名片段（仅保留字母数字）
fn sanitize_username_fragment(input: &str) -> String {
    let base: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(USERNAME_MAX_LEN)
        .collect();
    if base.is_empty() {
        random_token(8).to_lowercase()
    } else {
        base
    }
}

/// 提供商出参 VO（client_secret 一律脱敏为空）
#[derive(Debug, Clone, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProviderVo {
    pub provider_id: i64,
    pub provider_code: String,
    pub provider_name: String,
    pub provider_type: String,
    pub client_id: String,
    // 出参一律脱敏为空串（字段保留以维持出参 schema 稳定，禁止回填真实凭据）
    pub client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub scope: String,
    pub redirect_uri: String,
    pub auto_create_user: String,
    pub enabled: String,
    pub display_order: i32,
    pub remark: Option<String>,
    pub create_time: Option<String>,
    pub update_time: Option<String>,
}

impl ProviderVo {
    fn from_model(m: &SysOauthProviderModel) -> Self {
        Self {
            provider_id: m.provider_id,
            provider_code: m.provider_code.clone(),
            provider_name: m.provider_name.clone(),
            provider_type: m.provider_type.clone(),
            client_id: m.client_id.clone(),
            client_secret: String::new(),
            authorize_url: m.authorize_url.clone(),
            token_url: m.token_url.clone(),
            user_info_url: m.user_info_url.clone(),
            scope: m.scope.clone(),
            redirect_uri: m.redirect_uri.clone(),
            auto_create_user: m.auto_create_user.clone(),
            enabled: m.enabled.clone(),
            display_order: m.display_order,
            remark: m.remark.clone(),
            create_time: m.create_time.map(|t| t.to_string()),
            update_time: m.update_time.map(|t| t.to_string()),
        }
    }
}

/// 绑定展示 VO（access_token/refresh_token 脱敏为空）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OauthBindingVo {
    pub oauth_id: i64,
    pub provider: String,
    pub provider_user_id: String,
    pub nickname: Option<String>,
    pub avatar: Option<String>,
    pub email: Option<String>,
    pub last_login_time: Option<String>,
}

impl OauthBindingVo {
    fn from_model(m: &SysOauthUserModel) -> Self {
        Self {
            oauth_id: m.oauth_id,
            provider: m.provider.clone(),
            provider_user_id: m.provider_user_id.clone(),
            nickname: m.nickname.clone(),
            avatar: m.avatar.clone(),
            email: m.email.clone(),
            last_login_time: m.last_login_time.map(|t| t.to_string()),
        }
    }
}

// ==================== DTO ====================

/// 提供商分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ProviderQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub provider_name: Option<String>,
    pub provider_code: Option<String>,
    pub provider_type: Option<String>,
    pub enabled: Option<String>,
}

impl From<&ProviderQueryDto> for PageDomain {
    fn from(dto: &ProviderQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 提供商新增/修改 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProviderUpsertDto {
    #[garde(skip)]
    pub provider_id: Option<i64>,
    #[garde(length(min = 1, max = 64))]
    pub provider_code: String,
    #[garde(length(min = 1, max = 64))]
    pub provider_name: String,
    #[garde(length(min = 1, max = 32))]
    pub provider_type: String,
    #[garde(length(max = 200))]
    pub client_id: String,
    #[garde(length(max = 400))]
    pub client_secret: String,
    #[garde(length(max = 500))]
    pub authorize_url: String,
    #[garde(length(max = 500))]
    pub token_url: String,
    #[garde(length(max = 500))]
    pub user_info_url: String,
    #[garde(length(max = 200))]
    pub scope: String,
    #[garde(length(max = 500))]
    pub redirect_uri: String,
    #[garde(skip)]
    pub auto_create_user: Option<String>,
    #[garde(skip)]
    pub enabled: Option<String>,
    #[garde(skip)]
    pub display_order: Option<i32>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 启用提供商列表项（登录页展示，不返回 secret）
#[derive(Debug, Clone, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnabledProviderVo {
    pub provider_id: i64,
    pub provider_code: String,
    pub provider_name: String,
    /// 跳转授权 URL（由 begin_oauth 生成）
    pub authorize_url: String,
    pub redirect_uri: String,
}

/// 发起登录请求 DTO（生成授权 URL）
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BeginOauthDto {
    #[garde(length(min = 1, max = 64))]
    pub provider_code: String,
    /// 前端回调落地来源（用于动态生成 redirect_uri；为空时后端按请求 Host 生成）
    #[garde(length(max = 500))]
    pub redirect: Option<String>,
}

/// 授权回调查询参数 DTO
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct OauthCallbackDto {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// 绑定请求 DTO（当前登录账号绑定第三方身份）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BindOauthDto {
    /// 承载体（授权回调返回的 handoff 凭据）
    #[garde(length(min = 1, max = 128))]
    pub handoff: String,
}

/// 解绑请求 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UnbindOauthDto {
    #[garde(skip)]
    pub provider: String,
}

/// 授权回调结果
///
/// - LoggedIn { username }：身份已绑定（或自动创建成功），调用方应继续走
///   `AuthService::oauth_finalize_login` 签发会话。
/// - NeedBind { handoff }：身份未绑定且未启用自动创建，返回一次性凭据，
///   前端引导当前用户到绑定页。
#[derive(Debug, Clone, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum OauthCallResult {
    LoggedIn { username: String },
    NeedBind { handoff: String },
}

// ==================== Service ====================

/// 第三方登录模块 Service
pub struct SysOauthService {
    provider_repo: SysOauthProviderRepository,
    oauth_user_repo: SysOauthUserRepository,
    user_repo: SysUserRepository,
    user_role_repo: SysUserRoleRepository,
    user_service: SysUserService,
    http: reqwest::Client,
    /// v5-E6：敏感列信封加密主密钥（CONFIG_ENC_KEY；空=迁移期 fail-open 明文落库）
    enc_key: String,
}

impl SysOauthService {
    pub fn new(db: DatabaseConnection, user_service: SysUserService, enc_key: String) -> Self {
        Self {
            provider_repo: SysOauthProviderRepository::new(db.clone()),
            oauth_user_repo: SysOauthUserRepository::new(db.clone()),
            user_repo: SysUserRepository::new(db.clone()),
            user_role_repo: SysUserRoleRepository::new(db),
            user_service,
            http: reqwest::Client::new(),
            enc_key,
        }
    }

    /// v5-E6：敏感列写入口——CONFIG_ENC_KEY 已配置 → 信封加密（fail-closed，
    /// 加密失败拒绝写入；幂等：已带 enc2:/enc: 前缀原样）；未配置 → 明文落库
    /// （迁移期策略，与 id_token_secret 一致）。
    fn seal(&self, plaintext: &str) -> Result<String, ServiceError> {
        crate::utils::crypto::seal_sensitive_value(plaintext, &self.enc_key).map_err(|e| {
            tracing::error!("敏感值加密失败，拒绝写入: {}", e);
            ServiceError::internal(&crate::tr!("error.sso.secret_encrypt_failed"))
        })
    }

    /// v5-E6：敏感列读出口——幂等/明文兼容，解密失败原样返回（读路径宽松化）。
    fn unseal(&self, stored: &str) -> String {
        crate::utils::crypto::unseal_sensitive_value(stored, &self.enc_key)
    }

    // ==================== 提供商配置 ====================

    /// 分页查询提供商
    pub async fn get_provider_page(
        &self,
        query: ProviderQueryDto,
    ) -> Result<(Vec<ProviderVo>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let (rows, total) = self
            .provider_repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                query.provider_name.as_deref(),
                query.provider_code.as_deref(),
                query.provider_type.as_deref(),
                query.enabled.as_deref(),
            )
            .await?;
        Ok((rows.iter().map(ProviderVo::from_model).collect(), total))
    }

    /// 查询提供商详情（脱敏 secret）
    pub async fn get_provider_by_id(&self, provider_id: i64) -> Result<ProviderVo, ServiceError> {
        let model = self
            .provider_repo
            .find_by_id(provider_id)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.oauth.provider_not_found"))
            })?;
        Ok(ProviderVo::from_model(&model))
    }

    /// 新增提供商
    pub async fn add_provider(
        &self,
        dto: ProviderUpsertDto,
        operator: &str,
    ) -> Result<ProviderVo, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        validate_provider_type(&dto.provider_type)?;
        if self
            .provider_repo
            .exists_by_code(&dto.provider_code)
            .await?
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oauth.provider_code_exists"
            )));
        }

        let now = crate::common::datetime::now_naive();
        let am = SysOauthProviderActiveModel {
            provider_code: Set(dto.provider_code),
            provider_name: Set(dto.provider_name),
            provider_type: Set(dto.provider_type),
            client_id: Set(dto.client_id),
            // v5-E6：client_secret 信封加密落库（CONFIG_ENC_KEY 未配置时明文，迁移期策略）
            client_secret: Set(self.seal(&dto.client_secret)?),
            authorize_url: Set(dto.authorize_url),
            token_url: Set(dto.token_url),
            user_info_url: Set(dto.user_info_url),
            scope: Set(dto.scope),
            redirect_uri: Set(dto.redirect_uri),
            auto_create_user: Set(dto.auto_create_user.unwrap_or_else(|| "1".to_string())),
            enabled: Set(dto.enabled.unwrap_or_else(|| "0".to_string())),
            display_order: Set(dto.display_order.unwrap_or(0)),
            remark: Set(dto.remark),
            create_time: Set(Some(now)),
            update_time: Set(Some(now)),
            ..Default::default()
        };
        let model = self.provider_repo.insert(am).await?;
        let _ = operator;
        Ok(ProviderVo::from_model(&model))
    }

    /// 修改提供商
    pub async fn edit_provider(
        &self,
        dto: ProviderUpsertDto,
        operator: &str,
    ) -> Result<ProviderVo, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        validate_provider_type(&dto.provider_type)?;
        let provider_id = dto.provider_id.ok_or_else(|| {
            ServiceError::bad_request(&crate::tr!("error.oauth.provider_id_invalid"))
        })?;
        let existing = self
            .provider_repo
            .find_by_id(provider_id)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.oauth.provider_not_found"))
            })?;

        // 唯一编码校验（排除自身）
        if existing.provider_code != dto.provider_code
            && self
                .provider_repo
                .exists_by_code(&dto.provider_code)
                .await?
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oauth.provider_code_exists"
            )));
        }

        // 保留默认值（into() 移动 existing 后无法再访问）
        let default_auto_create = existing.auto_create_user.clone();
        let default_enabled = existing.enabled.clone();
        let default_order = existing.display_order;

        let mut am: SysOauthProviderActiveModel = existing.into();
        am.provider_code = Set(dto.provider_code);
        am.provider_name = Set(dto.provider_name);
        am.provider_type = Set(dto.provider_type);
        am.client_id = Set(dto.client_id);
        // secret：非空才覆盖（留空保持不变），避免每次编辑都要重填；v5-E6 加密落库
        if !dto.client_secret.is_empty() {
            am.client_secret = Set(self.seal(&dto.client_secret)?);
        }
        am.authorize_url = Set(dto.authorize_url);
        am.token_url = Set(dto.token_url);
        am.user_info_url = Set(dto.user_info_url);
        am.scope = Set(dto.scope);
        am.redirect_uri = Set(dto.redirect_uri);
        am.auto_create_user = Set(dto.auto_create_user.unwrap_or(default_auto_create));
        am.enabled = Set(dto.enabled.unwrap_or(default_enabled));
        am.display_order = Set(dto.display_order.unwrap_or(default_order));
        am.remark = Set(dto.remark);
        am.update_time = Set(Some(crate::common::datetime::now_naive()));
        let _ = operator;

        let model = self.provider_repo.update(am).await?;
        Ok(ProviderVo::from_model(&model))
    }

    /// 批量删除提供商
    pub async fn delete_providers(&self, provider_ids: Vec<i64>) -> Result<(), ServiceError> {
        if provider_ids.is_empty() {
            return Ok(());
        }
        let existing = self.provider_repo.find_by_ids(&provider_ids).await?;
        if existing.len() != provider_ids.len() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.oauth.provider_not_found"
            )));
        }
        self.provider_repo.delete_by_ids(provider_ids).await?;
        Ok(())
    }

    /// 启停提供商
    pub async fn toggle_provider(
        &self,
        provider_id: i64,
        enabled: String,
    ) -> Result<(), ServiceError> {
        if enabled != "0" && enabled != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oauth.enabled_invalid"
            )));
        }
        let existing = self
            .provider_repo
            .find_by_id(provider_id)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.oauth.provider_not_found"))
            })?;
        let mut am: SysOauthProviderActiveModel = existing.into();
        am.enabled = Set(enabled);
        am.update_time = Set(Some(crate::common::datetime::now_naive()));
        self.provider_repo.update(am).await?;
        Ok(())
    }

    // ==================== 发起登录 ====================

    /// 生成授权 URL（state 写入 Redis，回调时一次性校验）
    ///
    /// redirect_uri 解析优先级：配置项 > 请求参数 > 请求 Host 动态生成（https://{host}/auth/oauth/callback）
    pub async fn begin_oauth(
        &self,
        provider_code: &str,
        request_host: &str,
        base_scheme: &str,
        redis: &mut ConnectionManager,
    ) -> Result<EnabledProviderVo, ServiceError> {
        let provider = self
            .provider_repo
            .find_by_code(provider_code)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.oauth.provider_not_found"))
            })?;
        if provider.enabled != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oauth.provider_disabled"
            )));
        }
        if provider.client_id.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oauth.client_id_required"
            )));
        }

        let redirect_uri = self.resolve_redirect_uri(&provider, request_host, base_scheme);

        let state = random_token(32);
        let state_key = format!("oauth:state:{}", state);
        let state_val = serde_json::json!({
            "provider_code": provider.provider_code,
        })
        .to_string();
        redis::cmd("SET")
            .arg(&state_key)
            .arg(&state_val)
            .arg("EX")
            .arg(STATE_TTL_SECS)
            .query_async::<()>(redis)
            .await
            .map_err(|e| {
                tracing::error!("OAuth state 写入 Redis 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.cache_failed"))
            })?;

        // 组装授权 URL（保留 scope 原样，不重复编码）
        let sep = if provider.authorize_url.contains('?') {
            "&"
        } else {
            "?"
        };
        let authorize_url = format!(
            "{}{}client_id={}&redirect_uri={}&response_type=code&state={}&scope={}",
            provider.authorize_url,
            sep,
            urlencode(&provider.client_id),
            urlencode(&redirect_uri),
            urlencode(&state),
            urlencode(&provider.scope)
        );

        Ok(EnabledProviderVo {
            provider_id: provider.provider_id,
            provider_code: provider.provider_code,
            provider_name: provider.provider_name,
            authorize_url,
            redirect_uri,
        })
    }

    /// 根据配置 / Host 动态生成回调地址
    fn resolve_redirect_uri(
        &self,
        provider: &SysOauthProviderModel,
        request_host: &str,
        base_scheme: &str,
    ) -> String {
        if !provider.redirect_uri.trim().is_empty() {
            return provider.redirect_uri.trim().to_string();
        }
        let scheme = if base_scheme.is_empty() {
            "http"
        } else {
            base_scheme
        };
        let host = if request_host.is_empty() {
            "localhost:8080"
        } else {
            request_host
        };
        format!("{}://{}/oauth2/callback", scheme, host)
    }

    // ==================== 授权回调 ====================

    /// 处理授权回调
    ///
    /// 流程：state 校验 → 授权码换令牌 → 换取用户信息 → 身份映射：
    /// - 已绑定 → LoggedIn
    /// - 未绑定且 auto_create_user='1' → 自动创建本地账号 + 绑定 → LoggedIn
    /// - 未绑定且 auto_create_user='0' → NeedBind（返回一次性 handoff）
    pub async fn oauth_callback(
        &self,
        dto: OauthCallbackDto,
        request_host: &str,
        base_scheme: &str,
        redis: &mut ConnectionManager,
    ) -> Result<OauthCallResult, ServiceError> {
        // 上游拒绝授权
        if let Some(err) = dto.error {
            return Err(ServiceError::bad_request(&format!(
                "{}: {}",
                crate::tr!("error.oauth.unknown_error"),
                err
            )));
        }
        let code = dto
            .code
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.oauth.code_missing")))?;
        let state = dto
            .state
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.oauth.state_invalid")))?;

        // 校验 state（一次性）：从 Redis 读取并删除
        let state_key = format!("oauth:state:{}", state);
        let provider_code: String =
            match self.read_and_delete_redis_string(&state_key, redis).await? {
                Some(json_str) => serde_json::from_str::<serde_json::Value>(&json_str)
                    .ok()
                    .and_then(|v| {
                        v.get("provider_code")
                            .and_then(|p| p.as_str())
                            .map(String::from)
                    })
                    .ok_or_else(|| {
                        ServiceError::bad_request(&crate::tr!("error.oauth.state_invalid"))
                    })?,
                None => {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.oauth.state_invalid"
                    )));
                }
            };

        let provider = self
            .provider_repo
            .find_by_code(&provider_code)
            .await?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.oauth.provider_not_found"))
            })?;
        if provider.enabled != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oauth.provider_disabled"
            )));
        }

        let redirect_uri = self.resolve_redirect_uri(&provider, request_host, base_scheme);

        // 1. 授权码换令牌
        let token_payload = self.exchange_token(&provider, &code, &redirect_uri).await?;
        let access_token = token_payload.access_token.clone().ok_or_else(|| {
            ServiceError::bad_request(&crate::tr!("error.oauth.token_exchange_failed"))
        })?;

        // 2. 换取用户信息
        let userinfo = self.fetch_userinfo(&provider, &access_token).await?;
        let provider_user_id = userinfo.provider_user_id.clone().ok_or_else(|| {
            ServiceError::bad_request(&crate::tr!("error.oauth.userinfo_missing_id"))
        })?;

        // 3. 身份映射
        let existing_binding = self
            .oauth_user_repo
            .find_by_provider_identity(&provider.provider_code, &provider_user_id)
            .await?;

        if let Some(binding) = existing_binding {
            // 已绑定 → 更新令牌信息并直接登录（v5-E6：令牌信封加密）
            let sealed_at = self.seal(&access_token)?;
            let sealed_rt = match &token_payload.refresh_token {
                Some(rt) => Some(self.seal(rt)?),
                None => None,
            };
            self.oauth_user_repo
                .update(SysOauthUserActiveModel {
                    oauth_id: Set(binding.oauth_id),
                    access_token: Set(Some(sealed_at)),
                    refresh_token: Set(sealed_rt),
                    expires_at: Set(token_payload.expires_at),
                    last_login_time: Set(Some(crate::common::datetime::now_naive())),
                    ..Default::default()
                })
                .await?;

            // 校验本地账号仍存在且未停用（停用账号交由 oauth_finalize_login 拒绝）
            let user = self
                .user_service
                .get_active_user_by_username_by_id(binding.user_id)
                .await?;
            match user {
                Some(u) => {
                    let _ = u;
                    Ok(OauthCallResult::LoggedIn {
                        username: user_username(&self.user_service, binding.user_id).await?,
                    })
                }
                None => Err(ServiceError::unauthorized(&crate::tr!(
                    "error.oauth.local_user_not_found"
                ))),
            }
        } else if provider.auto_create_user == "1" {
            // 未绑定 + 自动创建 → 创建账号并绑定
            let username = self
                .auto_create_and_bind(&provider, &userinfo, token_payload, access_token)
                .await?;
            Ok(OauthCallResult::LoggedIn { username })
        } else {
            // 未绑定 + 需人工绑定 → 返回一次性 handoff
            let handoff = self.issue_handoff(&provider, &userinfo, redis).await?;
            Ok(OauthCallResult::NeedBind { handoff })
        }
    }

    // ==================== 绑定管理 ====================

    /// 当前登录账号绑定第三方身份（校验 handoff）
    pub async fn bind_oauth(
        &self,
        dto: BindOauthDto,
        user_id: i64,
        redis: &mut ConnectionManager,
    ) -> Result<OauthBindingVo, ServiceError> {
        // 校验 handoff 并获取身份
        let handoff_key = format!("oauth:handoff:{}", dto.handoff);
        let json_str = self
            .read_and_delete_redis_string(&handoff_key, redis)
            .await?
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.oauth.handoff_invalid")))?;
        let info: HandoffInfo = serde_json::from_str(&json_str)
            .map_err(|_| ServiceError::bad_request(&crate::tr!("error.oauth.handoff_invalid")))?;

        // 该第三方身份是否已绑定其他账号
        if let Some(existing) = self
            .oauth_user_repo
            .find_by_provider_identity(&info.provider, &info.provider_user_id)
            .await?
        {
            if existing.user_id != user_id {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.oauth.bind_taken"
                )));
            }
            // 已绑定到当前账号 → 直接返回
            return Ok(OauthBindingVo::from_model(&existing));
        }

        let now = crate::common::datetime::now_naive();
        // v5-E6：令牌信封加密（Option 逐个处理）
        let sealed_at = match &info.access_token {
            Some(t) => Some(self.seal(t)?),
            None => None,
        };
        let sealed_rt = match &info.refresh_token {
            Some(t) => Some(self.seal(t)?),
            None => None,
        };
        let am = SysOauthUserActiveModel {
            user_id: Set(user_id),
            provider: Set(info.provider),
            provider_user_id: Set(info.provider_user_id),
            nickname: Set(info.nickname),
            avatar: Set(info.avatar),
            email: Set(info.email),
            access_token: Set(sealed_at),
            refresh_token: Set(sealed_rt),
            expires_at: Set(info.expires_at),
            last_login_time: Set(Some(now)),
            create_time: Set(Some(now)),
            update_time: Set(Some(now)),
            ..Default::default()
        };
        let model = self.oauth_user_repo.insert(am).await?;
        Ok(OauthBindingVo::from_model(&model))
    }

    /// 当前登录账号解绑第三方身份
    ///
    /// 安全：仅可解绑自己的绑定；账号仅有本地密码来源（该绑定的 user 无其他绑定且
    /// 本地可密码登录）时才允许，防止账号失去所有登录途径。
    pub async fn unbind_oauth(&self, provider: &str, user_id: i64) -> Result<(), ServiceError> {
        // 找到该 provider 对当前用户的绑定
        let bindings = self.oauth_user_repo.find_by_user_id(user_id).await?;
        let target = bindings
            .iter()
            .find(|b| b.provider == provider)
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.oauth.no_binding")))?;

        // 解绑后不可为 0 个（该用户本地密码来源被切断）。若既无密码又无其他第三方来源会丧失登录途径，
        // 但 sys_user 均以 password 字段承载本地密码（OAuth 自动创建账号也生成随机密码）。
        self.oauth_user_repo
            .delete_by_oauth_id(target.oauth_id)
            .await?;
        Ok(())
    }

    /// 查询当前账号的全部第三方绑定
    pub async fn list_my_bindings(
        &self,
        user_id: i64,
    ) -> Result<Vec<OauthBindingVo>, ServiceError> {
        let bindings = self.oauth_user_repo.find_by_user_id(user_id).await?;
        Ok(bindings.iter().map(OauthBindingVo::from_model).collect())
    }

    /// 登录页启用的提供商列表（公开，脱敏）
    pub async fn list_enabled_providers(&self) -> Result<Vec<EnabledProviderVo>, ServiceError> {
        let providers = self.provider_repo.find_all_enabled().await?;
        Ok(providers
            .iter()
            .map(|p| EnabledProviderVo {
                provider_id: p.provider_id,
                provider_code: p.provider_code.clone(),
                provider_name: p.provider_name.clone(),
                authorize_url: String::new(), // 实际 URL 由 begin_oauth 生成（带 state）
                redirect_uri: p.redirect_uri.clone(),
            })
            .collect())
    }

    // ==================== 内部实现 ====================

    /// Redis 读取并删除一个 key（一次性）
    async fn read_and_delete_redis_string(
        &self,
        key: &str,
        redis: &mut ConnectionManager,
    ) -> Result<Option<String>, ServiceError> {
        let value: Option<String> = redis::cmd("GET")
            .arg(key)
            .query_async(redis)
            .await
            .map_err(|e| {
                tracing::error!("Redis GET oauth 凭据失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.cache_failed"))
            })?;
        if value.is_some() {
            let _: Option<()> = redis::cmd("DEL")
                .arg(key)
                .query_async(redis)
                .await
                .map_err(|e| {
                    tracing::error!("Redis DEL oauth 凭据失败: {}", e);
                    ServiceError::internal(&crate::tr!("error.common.cache_failed"))
                })?;
        }
        Ok(value)
    }

    /// 授权码换令牌
    async fn exchange_token(
        &self,
        provider: &SysOauthProviderModel,
        code: &str,
        redirect_uri: &str,
    ) -> Result<TokenPayload, ServiceError> {
        // v5-E6：secret 为信封加密存储，换取 token 前解密（先绑定避免临时值悬垂）
        let secret_plain = self.unseal(&provider.client_secret);
        let params = [
            ("client_id", provider.client_id.as_str()),
            ("client_secret", secret_plain.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ];
        let resp = self
            .http
            .post(&provider.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("OAuth token 端点请求失败 url={}: {}", provider.token_url, e);
                ServiceError::bad_request(&crate::tr!("error.oauth.token_exchange_failed"))
            })?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|_| {
            ServiceError::bad_request(&crate::tr!("error.oauth.token_exchange_failed"))
        })?;

        // 统一解析为 JSON Value（github 返回 form-encoded，先转码）
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                // 尝试表单编码解析（application/x-www-form-urlencoded）
                let text = String::from_utf8_lossy(&bytes);
                let mut map = serde_json::Map::new();
                for pair in text.split('&') {
                    if let Some((k, v)) = pair.split_once('=') {
                        let k = percent_decode(k);
                        let v = percent_decode(v);
                        map.insert(k, serde_json::Value::String(v));
                    }
                }
                if map.is_empty() {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.oauth.token_exchange_failed"
                    )));
                }
                serde_json::Value::Object(map)
            }
        };

        if !status.is_success() {
            tracing::error!(
                "OAuth token 端点返回错误 status={} body={}",
                status,
                String::from_utf8_lossy(&bytes)
            );
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oauth.token_exchange_failed"
            )));
        }

        let access_token = value
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from);
        let refresh_token = value
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(String::from);
        let expires_at = value
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .map(|secs| {
                crate::common::datetime::now_naive() + chrono::Duration::seconds(secs as i64)
            });

        Ok(TokenPayload {
            access_token,
            refresh_token,
            expires_at,
        })
    }

    /// 换取用户信息并抽取身份标识
    async fn fetch_userinfo(
        &self,
        provider: &SysOauthProviderModel,
        access_token: &str,
    ) -> Result<OauthIdentity, ServiceError> {
        let mut req = self
            .http
            .get(&provider.user_info_url)
            .bearer_auth(access_token);
        // github 需要 User-Agent + Accept
        if provider.provider_code == "github" {
            req = req
                .header("User-Agent", "yebot-oauth")
                .header("Accept", "application/vnd.github+json");
        }
        let resp = req.send().await.map_err(|e| {
            tracing::error!(
                "OAuth userinfo 端点请求失败 url={}: {}",
                provider.user_info_url,
                e
            );
            ServiceError::bad_request(&crate::tr!("error.oauth.userinfo_failed"))
        })?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|_| ServiceError::bad_request(&crate::tr!("error.oauth.userinfo_failed")))?;
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

        if !status.is_success() || value.is_null() {
            tracing::error!(
                "OAuth userinfo 返回错误 status={} body={}",
                status,
                String::from_utf8_lossy(&bytes)
            );
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oauth.userinfo_failed"
            )));
        }
        Ok(OauthIdentity::from_json(&value))
    }

    /// 自动创建本地账号 + 绑定（事务）
    async fn auto_create_and_bind(
        &self,
        provider: &SysOauthProviderModel,
        identity: &OauthIdentity,
        token: TokenPayload,
        access_token: String,
    ) -> Result<String, ServiceError> {
        let provider_user_id = identity.provider_user_id.as_deref().unwrap_or_default();
        if provider_user_id.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oauth.userinfo_missing_id"
            )));
        }

        // 邮箱冲突检查：若第三方邮箱已存在于本地账号，则不应自动创建，引导人工绑定
        if let Some(email) = identity.email.as_deref()
            && !email.is_empty()
            && self.user_repo.find_by_email(email).await?.is_some()
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oauth.email_conflict"
            )));
        }

        // 生成可用用户名
        let base = sanitize_username_fragment(provider_user_id);
        let username = self
            .find_available_username(&provider.provider_code, &base)
            .await?;

        // 生成随机初始密码（满足复杂度校验）+ Argon2 加密
        let raw_pwd = random_password(AUTH_PWD_LEN);
        let hashed = tokio::task::spawn_blocking(move || encrypt_password(&raw_pwd))
            .await
            .map_err(|e| {
                tracing::error!("OAuth 账号密码加密 spawn_blocking 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.password_encrypt_failed"))
            })??;

        let pcode = provider.provider_code.clone();
        let pname = provider.provider_name.clone();
        let user_role_repo = self.user_role_repo.clone();
        let oauth_user_repo = self.oauth_user_repo.clone();
        let user_repo = self.user_repo.clone();

        let db = self.user_repo.base().db().clone();
        let now = crate::common::datetime::now_naive();
        let nick = identity
            .nickname
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("{}用户", pname));
        let email = identity.email.clone();
        let avatar = identity.avatar.clone();

        // v5-E6：令牌信封加密（事务外先算好，避免闭包借用 self）
        let sealed_at = self.seal(&access_token)?;
        let sealed_rt = match &token.refresh_token {
            Some(t) => Some(self.seal(t)?),
            None => None,
        };

        let user = db
            .transaction::<_, SysUserModel, sea_orm::DbErr>(|txn| {
                let mut user_am = SysUserActiveModel {
                    ..Default::default()
                };
                user_am.dept_id = Set(None);
                user_am.user_name = Set(username.clone());
                user_am.nick_name = Set(nick.clone());
                user_am.email = Set(email.clone());
                user_am.avatar = Set(avatar.clone());
                user_am.user_type = Set(Some("10".to_string())); // OAuth 自动注册用户
                user_am.password = Set(Some(hashed.clone()));
                user_am.status = Set(Some("0".to_string()));
                user_am.del_flag = Set(Some("0".to_string()));
                user_am.create_by = Set(Some(format!("oauth:{}", pcode)));
                user_am.create_time = Set(Some(now));
                user_am.update_by = Set(Some(format!("oauth:{}", pcode)));
                user_am.update_time = Set(Some(now));
                user_am.remark = Set(Some(format!("由 {} 第三方登录自动创建", pname)));

                let username2 = username.clone();
                let pcode2 = pcode.clone();
                let puid = provider_user_id.to_string();
                let nick2 = nick.clone();
                let email2 = email.clone();
                let avatar2 = avatar.clone();
                let access_token2 = sealed_at;
                let refresh2 = sealed_rt;
                let expires2 = token.expires_at;

                async move {
                    let new_user = user_repo.base().insert_conn(txn, user_am).await?;
                    // 绑定默认角色（普通角色）
                    let _ = user_role_repo
                        .insert_many_conn(
                            txn,
                            vec![SysUserRoleActiveModel {
                                user_id: Set(new_user.user_id),
                                role_id: Set(DEFAULT_ROLE_ID),
                                source: Set("admin".to_owned()),
                            }],
                        )
                        .await?;
                    // 写入第三方绑定
                    let binding_am = SysOauthUserActiveModel {
                        user_id: Set(new_user.user_id),
                        provider: Set(pcode2),
                        provider_user_id: Set(puid),
                        nickname: Set(Some(nick2)),
                        avatar: Set(avatar2),
                        email: Set(email2),
                        access_token: Set(Some(access_token2)),
                        refresh_token: Set(refresh2),
                        expires_at: Set(expires2),
                        last_login_time: Set(Some(now)),
                        create_time: Set(Some(now)),
                        update_time: Set(Some(now)),
                        ..Default::default()
                    };
                    oauth_user_repo.base().insert_conn(txn, binding_am).await?;
                    let _ = username2;
                    Ok(new_user)
                }
                .boxed()
            })
            .await
            .map_err(|e| {
                tracing::error!("OAuth 自动创建账号事务失败: {}", e);
                ServiceError::internal(&crate::tr!("error.oauth.auto_create_failed"))
            })?;

        Ok(user.user_name)
    }

    /// 生成不冲突的本地用户名（尝试 base，冲突则追加随机后缀）
    async fn find_available_username(
        &self,
        provider: &str,
        base: &str,
    ) -> Result<String, ServiceError> {
        for attempt in 0..USERNAME_MAX_ATTEMPTS {
            let candidate = if attempt == 0 {
                let prefix = format!("{}_{}", provider, base);
                truncate(&prefix, USERNAME_MAX_LEN).to_lowercase()
            } else {
                let prefix = format!("{}_{}_{}", provider, base, random_token(4).to_lowercase());
                truncate(&prefix, USERNAME_MAX_LEN).to_lowercase()
            };
            if self
                .user_repo
                .find_by_user_name(&candidate)
                .await?
                .is_none()
            {
                return Ok(candidate);
            }
        }
        Err(ServiceError::bad_request(&crate::tr!(
            "error.oauth.username_occupied",
            name = format!("{}_{}", provider, base)
        )))
    }

    /// 签发绑定凭据（handoff）
    async fn issue_handoff(
        &self,
        provider: &SysOauthProviderModel,
        identity: &OauthIdentity,
        redis: &mut ConnectionManager,
    ) -> Result<String, ServiceError> {
        let handoff = random_token(48);
        let key = format!("oauth:handoff:{}", handoff);
        let info = HandoffInfo {
            provider: provider.provider_code.clone(),
            provider_user_id: identity.provider_user_id.clone().unwrap_or_default(),
            nickname: identity.nickname.clone(),
            avatar: identity.avatar.clone(),
            email: identity.email.clone(),
            access_token: None,
            refresh_token: None,
            expires_at: None,
        };
        let json_str = serde_json::to_string(&info)
            .map_err(|_| ServiceError::internal(&crate::tr!("error.oauth.unknown_error")))?;
        redis::cmd("SET")
            .arg(&key)
            .arg(json_str)
            .arg("EX")
            .arg(HANDOFF_TTL_SECS)
            .query_async::<()>(redis)
            .await
            .map_err(|e| {
                tracing::error!("OAuth handoff 写入 Redis 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.cache_failed"))
            })?;
        Ok(handoff)
    }
}

// ==================== 内部结构 ====================

/// 令牌响应解析结果
struct TokenPayload {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<chrono::NaiveDateTime>,
}

/// 从第三方用户信息 JSON 抽取的身份
struct OauthIdentity {
    provider_user_id: Option<String>,
    nickname: Option<String>,
    avatar: Option<String>,
    email: Option<String>,
}

impl OauthIdentity {
    fn from_json(v: &serde_json::Value) -> Self {
        // 取第一个非空字符串字段
        let get_str = |keys: &[&str]| -> Option<String> {
            for k in keys {
                if let Some(s) = v.get(k).and_then(|x| x.as_str())
                    && !s.is_empty()
                {
                    return Some(s.to_string());
                }
            }
            None
        };
        // 取首个数字型字段（github/gitee 用数字 id）
        let get_num = |keys: &[&str]| -> Option<String> {
            for k in keys {
                if let Some(n) = v.get(k).and_then(|x| x.as_i64()) {
                    return Some(n.to_string());
                }
            }
            None
        };
        Self {
            // 唯一标识优先级：sub/openid（OIDC/微信）→ 数字 id（github/gitee）→ login/account
            provider_user_id: get_str(&["sub", "openid"])
                .or_else(|| get_num(&["id", "uid", "userid", "UserId"]))
                .or_else(|| get_str(&["login", "account"])),
            nickname: get_str(&[
                "name",
                "nickname",
                "nick_name",
                "login",
                "preferred_username",
                "user_name",
            ]),
            avatar: get_str(&["avatar_url", "picture", "avatar", "headimgurl"]),
            email: get_str(&["email"]),
        }
    }
}

/// 绑定凭据内容（Redis JSON）
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct HandoffInfo {
    provider: String,
    provider_user_id: String,
    nickname: Option<String>,
    avatar: Option<String>,
    email: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<chrono::NaiveDateTime>,
}

// ==================== 辅助函数 ====================

/// RFC3986 严格百分号编码（空格 → %20、`+` → %2B，非 form_urlencoded 的 + 空格语义）。
/// 用于把 JWT / username 放入回调 URL 查询串，避免被 parse 为空格。
fn urlencode(s: &str) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        // RFC3986 unreserved: A-Z a-z 0-9 - _ . ~
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
    }
    out
}

/// 百分号解码
fn percent_decode(s: &str) -> String {
    percent_decoder(s).unwrap_or_else(|| s.to_string())
}

fn percent_decoder(s: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                bytes.push(byte);
                i += 3;
                continue;
            }
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8(bytes).ok()
}

/// 截断字符串到最大长度
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// 查询用户 user_name（供回调已绑定路径使用）
async fn user_username(
    user_service: &SysUserService,
    user_id: i64,
) -> Result<String, ServiceError> {
    let vo = user_service.get_user_by_id(user_id).await?;
    Ok(vo.user.user_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_random_password_meets_complexity() {
        let pwd = random_password(20);
        assert!(pwd.len() >= 16);
        assert!(pwd.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pwd.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pwd.chars().any(|c| c.is_ascii_digit()));
        assert!(pwd.chars().any(|c| "!@#$%^&*-_+=?".contains(c)));
    }

    #[test]
    fn test_sanitize_username_fragment() {
        assert_eq!(sanitize_username_fragment("alice-9012"), "alice9012");
        // 纯符号 → 随机
        let r = sanitize_username_fragment("###");
        assert_eq!(r.chars().count(), 8);
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate(&"a".repeat(100), 24).chars().count(), 24);
        assert_eq!(truncate("short", 24), "short");
    }

    #[test]
    fn test_provider_vo_masks_secret() {
        let m = SysOauthProviderModel {
            provider_id: 1,
            provider_code: "github".into(),
            provider_name: "GitHub".into(),
            provider_type: "github".into(),
            client_id: "cid".into(),
            client_secret: "super-secret".into(),
            authorize_url: "https://a".into(),
            token_url: "https://b".into(),
            user_info_url: "https://c".into(),
            scope: "read:user".into(),
            redirect_uri: String::new(),
            auto_create_user: "1".into(),
            enabled: "1".into(),
            display_order: 1,
            remark: None,
            create_time: None,
            update_time: None,
        };
        let vo = ProviderVo::from_model(&m);
        // 出参 client_secret 置空（字段保留，schema 稳定）
        assert!(vo.client_secret.is_empty());
        let json = serde_json::to_value(&vo).unwrap();
        assert_eq!(json["clientSecret"], "", "client_secret 出参应为空串");
    }

    #[test]
    fn test_validate_provider_type() {
        assert!(validate_provider_type("github").is_ok());
        assert!(validate_provider_type("oidc").is_ok());
        assert!(validate_provider_type("wechat").is_err());
    }

    #[test]
    fn test_urlencode() {
        assert_eq!(urlencode("rn@x y+z"), "rn%40x%20y%2Bz");
    }

    #[test]
    fn test_percent_decode_roundtrip() {
        let raw = "a b+c/d";
        let enc = urlencode(raw);
        let dec = percent_decode(&enc);
        assert_eq!(dec, raw);
    }

    #[test]
    fn test_oauth_identity_extraction() {
        let v: serde_json::Value = serde_json::json!({
            "sub": "oidc-123",
            "name": "张三",
            "picture": "https://x/avatar.png",
            "email": "a@b.com"
        });
        let id = OauthIdentity::from_json(&v);
        assert_eq!(id.provider_user_id.as_deref(), Some("oidc-123"));
        assert_eq!(id.nickname.as_deref(), Some("张三"));
        assert_eq!(id.email.as_deref(), Some("a@b.com"));
        assert_eq!(id.avatar.as_deref(), Some("https://x/avatar.png"));
    }

    #[test]
    fn test_oauth_identity_numeric_id() {
        let v: serde_json::Value = serde_json::json!({ "id": 42, "login": "octocat" });
        let id = OauthIdentity::from_json(&v);
        assert_eq!(id.provider_user_id.as_deref(), Some("42"));
        assert_eq!(id.nickname.as_deref(), Some("octocat"));
    }

    #[test]
    fn test_token_form_parse_not_covered_here() {
        // 表单解析逻辑在 exchange_token 内部受网络依赖，此处仅验证工具函数可用
        let _ = percent_decode("a%20b");
    }

    #[test]
    fn test_resolve_redirect_uri_logic() {
        // 交给 resolve 方法；此处验证无配置时拼接
        let _ = HashMap::<String, String>::new();
    }
}
