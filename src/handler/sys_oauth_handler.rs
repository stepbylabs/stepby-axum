//! 第三方登录 / OAuth2 / OIDC Handler（Axum 原生实现）
//!
//! 接口路径（公开 + 受保护两层）：
//!
//! 公开（免鉴权）：
//! - GET  /oauth2/providers                登录页启用提供商列表
//! - GET  /oauth2/authorize?provider_code  生成授权 URL（前端据此跳转第三方）
//! - GET  /oauth2/callback                 授权回调（state 校验 → 换令牌 → 取身份 → 登录/绑定）。
//!   成功：LoggedIn → 302 到前端 /oauth-login?token=&username=；
//!   需绑定：NeedBind → 302 到前端 /oauth-login?handoff=
//!
//! 受保护（需 auth_middleware）：
//! - GET    /system/oauth/provider/list        提供商分页
//! - GET    /system/oauth/provider/{id}        提供商详情
//! - POST   /system/oauth/provider             新增提供商
//! - PUT    /system/oauth/provider             修改提供商
//! - DELETE /system/oauth/provider/{ids}       批量删除提供商
//! - PUT    /system/oauth/provider/{id}/status 启停提供商
//! - GET    /oauth2/my-bindings                当前账号第三方绑定列表
//! - POST   /oauth2/bind                       当前账号绑定第三方身份（handoff + 登录态）
//! - DELETE /oauth2/unbind                     当前账号解绑第三方身份
//!
//! 安全设计：
//! - 回调为浏览器重定向流程，state 一次性校验防 CSRF/重放（Redis）
//! - 回调成功后 token 以查询参数交给前端 /oauth-login 落地，前端存储后立即清理 URL
//! - provider 出参一概脱敏 client_secret；绑定出参脱敏第三方令牌
//! - 绑定接口要求登录态（Operator），仅能绑定/解绑自己的账号

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Redirect;
use serde::Deserialize;
use serde::Serialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{AjaxResult, AppError, TableDataInfo, ValidatedJson};
use crate::middleware::Operator;
use crate::middleware::tenant_host::HostTenant;
use crate::service::auth_service::LoginVo;
use crate::service::sys_oauth_service::{
    BindOauthDto, EnabledProviderVo, OauthCallResult, ProviderQueryDto, ProviderUpsertDto,
    ProviderVo,
};
use crate::state::AppState;
use crate::utils::ip::extract_client_ip;

/// 合作方回调成功后，浏览器落地到前端 /oauth-login 页面（Vue 路由读取 token/handoff）
const OAUTH_LOGIN_PAGE: &str = "oauth-login";

// ==================== DTO / VO ====================

/// 发起授权的查询参数
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeQuery {
    pub provider_code: String,
}

/// 启停状态查询参数
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ToggleQuery {
    pub enabled: String,
}

/// 解绑查询参数
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct UnbindQuery {
    pub provider: String,
}

/// 登录入口响应（authorizeUrl 由 begin 生成）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeResult {
    pub authorize_url: String,
}

/// 已绑定第三方身份列表项（含 provider 名称，前端展示）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MyBindingVo {
    pub provider: String,
    pub provider_name: String,
    pub provider_user_id: String,
    pub nickname: Option<String>,
    pub avatar: Option<String>,
    pub email: Option<String>,
    pub last_login_time: Option<String>,
}

crate::impl_into_response!(AuthorizeResult);

// ==================== 公开 Handler ====================

/// GET /oauth2/providers — 登录页启用提供商列表（公开，脱敏）
///
/// 多租户（台账 P1-2）：按请求 host 解析出的租户（`HostTenant`，由 tenant_host
/// 中间件在可信反代环境下注入）取可见集——本租户域名下可见「平台级 + 本租户自建」，
/// 无 host 上下文（平台 host / 未绑定域名 / 来源不可信）时仅平台级。
#[utoipa::path(
    get,
    path = "/oauth2/providers",
    responses(
        (status = 200, description = "登录页启用的第三方提供商列表（已脱敏）", body = AjaxResult<Vec<EnabledProviderVo>>),
    ),
    security(()),
    tag = "oauth"
)]
pub async fn list_providers(
    State(state): State<Arc<AppState>>,
    host_tenant: HostTenant,
) -> Result<AjaxResult<Vec<EnabledProviderVo>>, AppError> {
    let list = state
        .oauth_service
        .list_enabled_providers(host_tenant.tid())
        .await?;
    Ok(AjaxResult::success(list))
}

/// GET /oauth2/authorize?provider_code=xxx — 生成授权 URL
///
/// 前端拿到 authorize_url 后 `window.location.href = authorizeUrl` 跳转第三方。
/// state 已由 service 写入 Redis（一次性，防 CSRF/重放）。
#[utoipa::path(
    get,
    path = "/oauth2/authorize",
    params(AuthorizeQuery),
    responses(
        (status = 200, description = "第三方授权 URL", body = AuthorizeResult),
        (status = 400, description = "provider_code 无效或未启用"),
    ),
    security(()),
    tag = "oauth"
)]
pub async fn begin_oauth(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
    host_tenant: HostTenant,
) -> Result<AuthorizeResult, AppError> {
    let (host, scheme) = base_host_scheme(&headers, peer_addr);
    // P1-2：host 归属租户随 state 落 Redis，回调侧复现同一 provider 可见范围
    let authorize_url = state
        .oauth_service
        .begin_oauth(
            &query.provider_code,
            &host,
            &scheme,
            host_tenant.tid(),
            &state.store,
        )
        .await?;
    Ok(AuthorizeResult {
        authorize_url: authorize_url.authorize_url,
    })
}

/// GET /oauth2/callback?code=&state= — 授权回调（浏览器重定向流程，公开）
///
/// 成功：
/// - LoggedIn{username} → 复用 AuthService::oauth_finalize_login 签发会话 → 302 到前端
///   /oauth-login?token=xxx&username=xxx
/// - NeedBind{handoff} → 302 到前端 /oauth-login?handoff=xxx（未启用自动创建，需人工绑定）
///
/// 失败：302 到前端 /oauth-login?error=xxx（由前端展示，避免回调页裸报错）
#[utoipa::path(
    get,
    path = "/oauth2/callback",
    params(crate::service::sys_oauth_service::OauthCallbackDto),
    responses(
        (status = 302, description = "重定向到前端 /oauth-login（携带 token / handoff / error）"),
    ),
    security(()),
    tag = "oauth"
)]
pub async fn callback(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(dto): Query<crate::service::sys_oauth_service::OauthCallbackDto>,
) -> Result<Redirect, AppError> {
    let (host, scheme) = base_host_scheme(&headers, peer_addr);
    let base = format!("{}://{}", scheme, host);
    let login_ip = extract_client_ip(
        &headers,
        peer_addr.ip(),
        &state.config.server.trusted_proxies,
    );
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let result = state
        .oauth_service
        .oauth_callback(dto, &host, &scheme, &state.store)
        .await;

    let redirect = match result {
        Ok(OauthCallResult::LoggedIn { username }) => {
            // 复用密码登录链路：JWT 签发 + 登录日志 + 在线映射 + 旧会话清理
            let vo: LoginVo = state
                .auth_service
                .oauth_finalize_login(
                    &username,
                    &login_ip,
                    user_agent,
                    &state.store,
                    &state.config.jwt,
                    &state.ip_locator,
                )
                .await?;
            // URL 编码 username，避免昵称含特殊字符破坏查询参数
            let bump = url_encode(&username);
            format!(
                "{base}/{}?token={}&username={}",
                OAUTH_LOGIN_PAGE, vo.token, bump
            )
        }
        Ok(OauthCallResult::NeedBind { handoff }) => {
            format!("{base}/{OAUTH_LOGIN_PAGE}?handoff={handoff}")
        }
        Err(e) => {
            let msg = url_encode(&e.message);
            format!("{base}/{OAUTH_LOGIN_PAGE}?error={msg}")
        }
    };

    // 安全：仅 302，且 target 恒为本站相对路径拼出的同源地址
    Ok(Redirect::temporary(&redirect))
}

// ==================== 提供商管理 Handler ====================

/// GET /system/oauth/provider/list — 提供商分页（租户过滤）
#[utoipa::path(
    get,
    path = "/system/oauth/provider/list",
    params(ProviderQueryDto),
    responses(
        (status = 200, description = "提供商分页列表", body = TableDataInfo<ProviderVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "oauth"
)]
pub async fn provider_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<ProviderQueryDto>,
) -> Result<TableDataInfo<ProviderVo>, AppError> {
    let (rows, total) = state
        .oauth_service
        .get_provider_page(
            query,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/oauth/provider/{providerId} — 提供商详情
#[utoipa::path(
    get,
    path = "/system/oauth/provider/{providerId}",
    params(("providerId" = i64, Path, description = "提供商 ID")),
    responses(
        (status = 200, description = "提供商详情（已脱敏）", body = AjaxResult<ProviderVo>),
        (status = 404, description = "提供商不存在"),
    ),
    tag = "oauth"
)]
pub async fn provider_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(provider_id): Path<i64>,
) -> Result<AjaxResult<ProviderVo>, AppError> {
    let vo = state
        .oauth_service
        .get_provider_by_id(provider_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/oauth/provider — 新增提供商
#[utoipa::path(
    post,
    path = "/system/oauth/provider",
    request_body = ProviderUpsertDto,
    responses(
        (status = 200, description = "新增成功（已脱敏）", body = AjaxResult<ProviderVo>),
        (status = 400, description = "参数错误或 provider_code 重复"),
    ),
    tag = "oauth"
)]
pub async fn provider_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<ProviderUpsertDto>,
) -> Result<AjaxResult<ProviderVo>, AppError> {
    let vo = state
        .oauth_service
        .add_provider(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /system/oauth/provider — 修改提供商
#[utoipa::path(
    put,
    path = "/system/oauth/provider",
    request_body = ProviderUpsertDto,
    responses(
        (status = 200, description = "修改成功（已脱敏）", body = AjaxResult<ProviderVo>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "提供商不存在"),
    ),
    tag = "oauth"
)]
pub async fn provider_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<ProviderUpsertDto>,
) -> Result<AjaxResult<ProviderVo>, AppError> {
    let vo = state
        .oauth_service
        .edit_provider(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// DELETE /system/oauth/provider/{providerIds} — 批量删除提供商
#[utoipa::path(
    delete,
    path = "/system/oauth/provider/{providerIds}",
    params(("providerIds" = String, Path, description = "提供商 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "ID 不合法或超过批量上限"),
    ),
    tag = "oauth"
)]
pub async fn provider_delete(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids = crate::utils::parse_id_list::<i64>(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.oauth.provider_id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .oauth_service
        .delete_providers(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// PUT /system/oauth/provider/{providerId}/status — 启停提供商
#[utoipa::path(
    put,
    path = "/system/oauth/provider/{providerId}/status",
    params(
        ("providerId" = i64, Path, description = "提供商 ID"),
        ToggleQuery,
    ),
    responses(
        (status = 200, description = "启停成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "enabled 取值非法"),
        (status = 404, description = "提供商不存在"),
    ),
    tag = "oauth"
)]
pub async fn provider_toggle(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(provider_id): Path<i64>,
    Query(query): Query<ToggleQuery>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .oauth_service
        .toggle_provider(provider_id, query.enabled, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

// ==================== 绑定管理 Handler ====================

/// GET /oauth2/my-bindings — 当前账号第三方绑定列表（含 provider 名称）
#[utoipa::path(
    get,
    path = "/oauth2/my-bindings",
    responses(
        (status = 200, description = "当前账号第三方绑定列表", body = AjaxResult<Vec<MyBindingVo>>),
        (status = 401, description = "未授权"),
    ),
    tag = "oauth"
)]
pub async fn my_bindings(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<MyBindingVo>>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let bindings = state.oauth_service.list_my_bindings(user_id).await?;
    // 名称映射按操作者所属租户取可见集（平台操作者 tid=0 ⇒ 仅平台级 provider）
    let enabled = state
        .oauth_service
        .list_enabled_providers(Some(operator.tenant_id()))
        .await?;
    // provider_code → provider_name 映射（未启用的提供商也尝试用 code 兜底）
    let mut name_map: std::collections::HashMap<String, String> = enabled
        .iter()
        .map(|p| (p.provider_code.clone(), p.provider_name.clone()))
        .collect();
    let vos = bindings
        .into_iter()
        .map(|b| {
            let name = name_map
                .remove(&b.provider)
                .unwrap_or_else(|| b.provider.clone());
            MyBindingVo {
                provider: b.provider,
                provider_name: name,
                provider_user_id: b.provider_user_id,
                nickname: b.nickname,
                avatar: b.avatar,
                email: b.email,
                last_login_time: b.last_login_time,
            }
        })
        .collect();
    Ok(AjaxResult::success(vos))
}

/// POST /oauth2/bind — 当前登录账号绑定第三方身份（命中 handoff）
#[utoipa::path(
    post,
    path = "/oauth2/bind",
    request_body = BindOauthDto,
    responses(
        (status = 200, description = "绑定成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "handoff 无效或已过期"),
        (status = 401, description = "未授权"),
    ),
    tag = "oauth"
)]
pub async fn bind_oauth(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    // `ValidatedJson` 而非裸 `Json`：否则 `BindOauthDto.handoff` 的长度规则永不执行（见该字段注释）
    ValidatedJson(dto): ValidatedJson<BindOauthDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let binding = state
        .oauth_service
        .bind_oauth(dto, user_id, &state.store, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(serde_json::json!({
        "provider": binding.provider,
        "nickname": binding.nickname,
    })))
}

/// DELETE /oauth2/unbind?provider=xxx — 当前账号解绑第三方身份
#[utoipa::path(
    delete,
    path = "/oauth2/unbind",
    params(UnbindQuery),
    responses(
        (status = 200, description = "解绑成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "provider 参数缺失或无法反序列化"),
        (status = 404, description = "该 provider 未绑定到当前账号（error.oauth.no_binding）"),
        (status = 401, description = "未授权"),
    ),
    tag = "oauth"
)]
pub async fn unbind_oauth(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<UnbindQuery>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    state
        .oauth_service
        .unbind_oauth(&query.provider, user_id)
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

// ==================== 辅助函数 ====================

/// 解析 Operator 中携带的 user_id（sub claim，字符串）为 i64
fn parse_user_id(sub: &str) -> Result<i64, AppError> {
    sub.parse::<i64>()
        .map_err(|_| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))
}

/// 计算回调 host 与 scheme（优先 X-Forwarded-*，兼容反向代理部署）
///
/// - scheme：X-Forwarded-Proto 首个值；回退 http
/// - host：Host 头；回退 peer socket
fn base_host_scheme(headers: &HeaderMap, peer_addr: SocketAddr) -> (String, String) {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "http".to_string());
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| peer_addr.to_string());
    (host, scheme)
}

/// 简单 URL 编码（查询参数落库用，避免特殊字符破坏跳转地址）
fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
