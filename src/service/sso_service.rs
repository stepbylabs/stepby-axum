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
/// access_token 绑定 Redis key 前缀
const AT_KEY_PREFIX: &str = "sso:at:";

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
#[ts(export, export_to = "SsoClientCreateResult.ts", rename_all = "camelCase")]
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
    redirect_uri: String,
    scope: Vec<String>,
    code_challenge: String,
    nonce: Option<String>,
    auth_time: i64,
}

/// access_token 绑定（供 userinfo 校验令牌确由本模块签发并还原 scope/身份）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessBinding {
    client_id: String,
    user_id: i64,
    username: String,
    scope: Vec<String>,
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
}

/// /sso/token 请求参数 —— **OAuth2/OIDC 协议面**（外部 RP 用标准客户端库调用），
/// 参数名由 RFC 6749 强制固定为 snake_case，不参与 camelCase / ts-rs 转换。
#[derive(Debug, Clone, Deserialize)]
pub struct TokenParams {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: String,
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
    /// 未登录：302 到前端登录页（handler 负责拼 `{base}/login?redirect=...`）
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

// ==================== Service ====================

pub struct SsoService {
    client_repo: SysOauthClientRepository,
    consent_repo: SysOauthConsentRepository,
}

impl SsoService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            client_repo: SysOauthClientRepository::new(db.clone()),
            consent_repo: SysOauthConsentRepository::new(db),
        }
    }

    // -------------------- 发现文档 --------------------

    /// 构造 OIDC 发现文档（bare JSON）
    pub fn discovery(&self, issuer: &str, config: &SsoConfig) -> serde_json::Value {
        let issuer = issuer.trim_end_matches('/');
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}/sso/authorize", issuer),
            "token_endpoint": format!("{}/sso/token", issuer),
            "userinfo_endpoint": format!("{}/sso/userinfo", issuer),
            "end_session_endpoint": format!("{}/sso/logout", issuer),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["HS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": [
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                "preferred_username", "name", "email"
            ],
            // 内部标记：本系统未启用时前端不展示入口
            "sso_enabled": config.enabled,
        })
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
        let redirect_uri = match self.resolve_redirect_uri(params.redirect_uri.as_deref(), &whitelist)
        {
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
        let requested: Vec<String> = split_scope(&params.scope);
        if !requested.iter().any(|s| s == "openid") {
            return Ok(AuthorizeOutcome::Redirect(redirect_error_url(
                Some(&redirect_uri),
                &params.state,
                "invalid_scope",
                &crate::tr!("error.sso.openid_scope_required"),
            )));
        }
        if !scopes_subset(&requested, &client_scopes) {
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

        // 6. 直接签发授权码并回跳
        let url = self
            .issue_code_redirect(
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

        // 拒绝：回跳携带 access_denied
        if !dto.approved {
            return Ok(redirect_error_url(
                Some(&redirect_uri),
                &dto.state,
                "access_denied",
                &crate::tr!("error.sso.not_login"),
            ));
        }

        let code_challenge = dto.code_challenge.clone().unwrap_or_default();
        if code_challenge.is_empty() || dto.code_challenge_method.as_deref() != Some("S256") {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.pkce_required"
            )));
        }

        // 记录同意
        let now = datetime::now_naive();
        self.consent_repo
            .upsert(
                user_id,
                &client.client_id,
                &serde_json::to_string(&requested)
                    .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))?,
                now,
            )
            .await?;

        self.issue_code_redirect(
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
    #[allow(clippy::too_many_arguments)]
    async fn issue_code_redirect(
        &self,
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
        let binding = CodeBinding {
            client_id: client_id.to_string(),
            user_id,
            username: username.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_vec(),
            code_challenge: code_challenge.to_string(),
            nonce: nonce.map(|s| s.to_string()),
            auth_time: chrono::Utc::now().timestamp(),
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
    pub async fn token(
        &self,
        params: TokenParams,
        redis: &mut ConnectionManager,
        jwt: &JwtConfig,
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

        // 客户端凭据校验
        let client = self
            .client_repo
            .find_by_client_id(&params.client_id)
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
        let expected_hash = crate::utils::crypto::token_hash(&params.client_secret);
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

        // 绑定一致性：client_id / redirect_uri
        if binding.client_id != params.client_id {
            return Err(OidcError::new(
                "invalid_grant",
                crate::tr!("error.sso.code_invalid"),
            ));
        }
        if let Some(ru) = params.redirect_uri.as_deref().filter(|s| !s.is_empty())
            && ru != binding.redirect_uri
        {
            return Err(OidcError::new(
                "invalid_grant",
                crate::tr!("error.sso.redirect_uri_not_allowed"),
            ));
        }

        // PKCE 校验
        let verifier = params.code_verifier.as_deref().unwrap_or_default();
        if !pkce_verify(verifier, &binding.code_challenge) {
            return Err(OidcError::new(
                "invalid_grant",
                crate::tr!("error.sso.pkce_verify_failed"),
            ));
        }

        // 签发 access_token（复用平台 JWT）+ 记录绑定供 userinfo 校验
        let (access_token, _claims) =
            JwtUtils::generate_token(&binding.user_id.to_string(), &binding.username, jwt, 0)
                .map_err(|_| {
                    OidcError::new("server_error", crate::tr!("error.sso.token_failed"))
                })?;
        let at_binding = AccessBinding {
            client_id: client.client_id.clone(),
            user_id: binding.user_id,
            username: binding.username.clone(),
            scope: binding.scope.clone(),
        };
        let at_json = serde_json::to_string(&at_binding)
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;
        let at_key = format!(
            "{}{}",
            AT_KEY_PREFIX,
            crate::utils::crypto::token_hash(&access_token)
        );
        let ttl = config.id_token_ttl_secs.max(1);
        let _: () = redis::cmd("SET")
            .arg(&at_key)
            .arg(&at_json)
            .arg("EX")
            .arg(ttl)
            .query_async(redis)
            .await
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;

        // 签发 id_token（HS256 + 每客户端密钥）
        let id_token = self
            .build_id_token(&client, &binding, config, base_url)
            .map_err(|_| OidcError::new("server_error", crate::tr!("error.sso.token_failed")))?;

        Ok(TokenResult {
            access_token,
            token_type: "Bearer",
            expires_in: ttl,
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
        // profile 声明
        if binding.scope.iter().any(|s| s == "profile")
            || binding.scope.iter().any(|s| s == "email")
        {
            claims.insert(
                "preferred_username".into(),
                serde_json::json!(binding.username),
            );
            claims.insert("name".into(), serde_json::json!(binding.username));
        }
        let payload = serde_json::Value::Object(claims);
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());
        let token = encode(
            &header,
            &payload,
            &EncodingKey::from_secret(client.id_token_secret.as_bytes()),
        )
        .map_err(|_| ServiceError::internal(&crate::tr!("error.sso.token_failed")))?;
        Ok(token)
    }

    // -------------------- userinfo --------------------

    /// 处理 GET /sso/userinfo（Bearer access_token → 按 scope 返回身份声明）
    pub async fn userinfo(
        &self,
        bearer: &str,
        redis: &mut ConnectionManager,
        jwt: &JwtConfig,
        config: &SsoConfig,
    ) -> Result<serde_json::Value, OidcError> {
        if !config.enabled {
            return Err(OidcError::new(
                "invalid_request",
                crate::tr!("error.sso.disabled"),
            ));
        }
        // 校验平台 JWT 签名
        let claims = JwtUtils::verify_token(bearer, jwt).map_err(|_| {
            OidcError::new(
                "invalid_token",
                crate::tr!("error.sso.access_token_invalid"),
            )
        })?;
        let user_id: i64 = claims.sub.parse().map_err(|_| {
            OidcError::new(
                "invalid_token",
                crate::tr!("error.sso.access_token_invalid"),
            )
        })?;
        // 必须为本模块签发的 access_token（绑定存在），且属主一致
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
        let raw = raw.ok_or_else(|| {
            OidcError::new(
                "invalid_token",
                crate::tr!("error.sso.access_token_invalid"),
            )
        })?;
        let binding: AccessBinding = serde_json::from_str(&raw).map_err(|_| {
            OidcError::new(
                "invalid_token",
                crate::tr!("error.sso.access_token_invalid"),
            )
        })?;
        if binding.user_id != user_id {
            return Err(OidcError::new(
                "invalid_token",
                crate::tr!("error.sso.access_token_invalid"),
            ));
        }

        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), serde_json::json!(binding.user_id.to_string()));
        let wants_profile = binding.scope.iter().any(|s| s == "profile" || s == "email");
        if wants_profile {
            claims.insert(
                "preferred_username".into(),
                serde_json::json!(binding.username),
            );
            claims.insert("name".into(), serde_json::json!(binding.username));
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
        let blacklist_key = format!("blacklist:{}", crate::utils::crypto::token_hash(token));
        let blacklisted: Option<String> = redis::cmd("GET")
            .arg(&blacklist_key)
            .query_async(redis)
            .await
            .unwrap_or(None);
        if blacklisted.is_some() {
            return Ok(None);
        }
        Ok(Some(SessionIdentity {
            user_id,
            username: claims.username,
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
                cid.to_string()
            }
            _ => loop {
                let cid = format!("app_{}", random_urlsafe(12));
                if !self.client_repo.exists_by_client_id(&cid).await? {
                    break cid;
                }
            },
        };

        // 密钥：明文 client_secret 返回一次；id_token_secret 仅服务端持有
        let client_secret = random_urlsafe(32);
        let client_secret_hash = crate::utils::crypto::token_hash(&client_secret);
        let id_token_secret = random_urlsafe(32);

        let now = datetime::now_naive();
        let am = ClientActiveModel {
            client_id: Set(client_id.clone()),
            client_secret_hash: Set(client_secret_hash),
            id_token_secret: Set(id_token_secret),
            client_name: Set(dto.client_name.trim().to_string()),
            logo_uri: Set(dto.logo_uri.unwrap_or_default().trim().to_string()),
            redirect_uris: Set(to_json_array(&redirect_uris)),
            scopes: Set(to_json_array(&scopes)),
            grant_types: Set(to_json_array(&grant_types)),
            consent_required: Set(normalize_flag(dto.consent_required.as_deref(), "1")),
            enabled: Set(normalize_flag(dto.enabled.as_deref(), "1")),
            remark: Set(dto.remark),
            tenant_id: Set(0),
            create_by: Set(create_by.to_string()),
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
        _update_by: &str,
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
        am.logo_uri = Set(dto.logo_uri.unwrap_or_default().trim().to_string());
        am.redirect_uris = Set(to_json_array(&redirect_uris));
        am.scopes = Set(to_json_array(&scopes));
        am.grant_types = Set(to_json_array(&grant_types));
        am.consent_required = Set(consent_required);
        am.enabled = Set(enabled);
        am.remark = Set(dto.remark);

        // 经 ActiveModelBehavior::before_save 刷新 update_time
        let saved = self.client_repo.update(am).await?;
        Ok(client_to_vo(saved))
    }

    pub async fn delete_clients(&self, ids: Vec<i64>) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.sso.batch_id_invalid"
            )));
        }
        self.client_repo.delete_by_ids(ids).await?;
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
            );
        });
    }
}
