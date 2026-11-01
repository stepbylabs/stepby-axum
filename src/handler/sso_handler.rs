//! 单点登录 / OIDC Provider Handler（Axum 原生实现）
//!
//! 公开端点（免鉴权，供外部应用接入）：
//! - GET  /.well-known/openid-configuration  OIDC 发现文档（bare JSON）
//! - GET  /sso/authorize                     授权端点（解析浏览器会话 Cookie）
//! - POST /sso/token                         令牌端点（授权码 + PKCE 交换，bare JSON）
//! - GET  /sso/userinfo                      用户信息端点（Bearer access_token，bare JSON）
//! - GET|POST /sso/logout                    RP-initiated end-session（best-effort 回跳）
//!
//! 受保护端点：
//! - POST /sso/consent                       同意页批准 / 拒绝（需登录态）
//! - GET    /system/oauth/client/list        客户端分页
//! - GET    /system/oauth/client/{id}        客户端详情
//! - POST   /system/oauth/client             新增客户端（返回一次性明文 secret）
//! - PUT    /system/oauth/client             修改客户端
//! - DELETE /system/oauth/client/{ids}       批量删除
//! - PUT    /system/oauth/client/{id}/status 启停
//!
//! 说明：OIDC 端点必须返回规范约定的裸 JSON / 302 跳转，不使用系统统一响应信封，
//! 因此这些 handler 直接返回 `axum::response::Response`。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use utoipa::IntoParams;

use crate::common::AppError;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{AjaxResult, TableDataInfo};
use crate::middleware::Operator;
use crate::service::sso_service::{
    AuthorizeOutcome, AuthorizeParams, ConsentDto, OidcError, SsoClientQueryDto,
    SsoClientUpsertDto, SsoClientVo, TokenParams,
};
use crate::state::AppState;

/// 会话 Cookie 名（前端 js-cookie 以 SameSite=Lax 写入，顶层导航可携带）
const SESSION_COOKIE: &str = "Admin-Token";

// ==================== Query DTO ====================

/// OIDC/OAuth2 授权端点查询参数。此端点是**面向外部 RP 的标准协议面**（非「后端→我方前端」），
/// 参数名由 RFC 6749 / OIDC Core 强制固定为 snake_case（`client_id` / `redirect_uri` /
/// `code_challenge` / `code_challenge_method` …），标准 OIDC 客户端库只发送这些名字。
/// 因此**不做 camelCase 重命名、也不经 ts-rs 导出**（前端从不以类型化对象消费它，仅靠浏览器 302 跳转）。
#[derive(Debug, Deserialize, IntoParams)]
pub struct AuthorizeQuery {
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub response_type: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    /// v5-D4：OIDC Core §3.1.2.1 认证请求参数（空格分隔：login/none/consent/select_account）
    #[serde(default)]
    pub prompt: Option<String>,
    /// v5-D4：重认证阈值（秒）——auth_time 距今超过该值须重新认证
    #[serde(default)]
    pub max_age: Option<i64>,
    /// v5-D4：期望认证强度（宽松语义：mfa 满足度以 id_token.acr 真实声明为准，v5-E5）
    #[serde(default)]
    pub acr_values: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct LogoutQuery {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub id_token_hint: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ToggleQuery {
    pub enabled: String,
}

// ==================== 公开端点 ====================

/// GET /.well-known/openid-configuration
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    responses(
        (status = 200, description = "OIDC 发现文档（bare JSON）", body = serde_json::Value),
        (status = 404, description = "SSO 未启用"),
    ),
    security(()),
    tag = "sso"
)]
pub async fn discovery(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    // v4-R3：SSO 关闭时发现文档一并 404（不暴露协议元数据，也避免 RP 误接半可用端点）
    if !state.config.sso.enabled {
        return oidc_error_response(
            StatusCode::NOT_FOUND,
            &OidcError::new("not_found", crate::tr!("error.sso.disabled")),
        );
    }
    let base = base_url(&headers, peer, &state.config.server.trusted_proxies);
    let issuer = state.sso_service.resolve_issuer(&state.config.sso, &base);
    let doc = state.sso_service.discovery(&issuer, &state.config.sso);
    with_no_store((StatusCode::OK, Json(doc)).into_response())
}

/// GET /sso/jwks（v5-D2：聚合全部启用 RS256 客户端的公钥，kid=client_id；
/// HS256 客户端不发布公钥。无 RS256 客户端时返回空 keys——jwks_uri 为 OPTIONAL）
#[utoipa::path(
    get,
    path = "/sso/jwks",
    responses(
        (status = 200, description = "JWKS（聚合启用 RS256 客户端公钥）", body = serde_json::Value),
        (status = 404, description = "SSO 未启用"),
        (status = 500, description = "客户端列表读取失败（b71：不再降级发布空 keys，见 sso_service::jwks）"),
    ),
    security(()),
    tag = "sso"
)]
pub async fn jwks(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    if !state.config.sso.enabled {
        return Ok(oidc_error_response(
            StatusCode::NOT_FOUND,
            &OidcError::new("not_found", crate::tr!("error.sso.disabled")),
        ));
    }
    let doc = state.sso_service.jwks().await?;
    Ok(with_no_store((StatusCode::OK, Json(doc)).into_response()))
}

/// GET /sso/authorize
#[utoipa::path(
    get,
    path = "/sso/authorize",
    params(AuthorizeQuery),
    responses(
        (status = 302, description = "重定向到前端登录页 / 同意页 / RP 回调（携带 code 或 error）"),
        (status = 400, description = "invalid_request（协议参数非法）"),
    ),
    security(()),
    tag = "sso"
)]
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Result<Response, AppError> {
    let token = cookie_value(&headers, SESSION_COOKIE);
    let params = AuthorizeParams {
        client_id: q.client_id,
        redirect_uri: q.redirect_uri,
        response_type: q.response_type,
        scope: q.scope,
        state: q.state,
        nonce: q.nonce,
        code_challenge: q.code_challenge,
        code_challenge_method: q.code_challenge_method,
        prompt: q.prompt,
        max_age: q.max_age,
        acr_values: q.acr_values,
    };
    // 批次 4（`[sso].audit_authorize_get`）：审计快照需在 params 被消费前取（默认关时不取）
    let audit_enabled = state.config.sso.audit_authorize_get;
    let audit_snapshot = audit_enabled.then(|| {
        format!(
            "client_id={}; redirect_uri={}; scope={}",
            params.client_id,
            params.redirect_uri.as_deref().unwrap_or(""),
            params.scope
        )
    });
    // 未登录回跳目标预先构造（params 稍后会被 authorize 消费）。
    // redirect 挂**同源相对路径**而非 `{base}` 绝对 URL：前端登录页对 redirect 参数做
    // 开放重定向守卫（isSafeRedirect 只接受单 `/` 开头的路径），绝对 URL 会被拒绝并
    // 回落到首页，登出态的 RP 授权链路就此断裂；相对路径还避免把 Host 推导结果回显到 URL。
    let login_target = login_redirect_target(&params);

    let outcome = state
        .sso_service
        .authorize(
            params,
            token.as_deref(),
            &state.store,
            &state.config.jwt,
            &state.config.sso,
        )
        .await?;

    // 批次 4（`[sso].audit_authorize_get`，默认关 = 改造前行为）：为授权端点写一条操作日志。
    // best-effort：失败只打 WARN，不影响授权跳转（审计是旁路，不是闸门）。
    if let Some(snapshot) = audit_snapshot {
        let ip = crate::utils::ip::extract_client_ip(
            &headers,
            peer.ip(),
            &state.config.server.trusted_proxies,
        );
        use crate::service::sys_oper_log_service::OperLogRecord;
        state
            .oper_log_service
            .record_oper_log(OperLogRecord {
                title: "SSO 授权请求".to_string(),
                business_type: 0,
                method: "GET".to_string(),
                request_method: "GET".to_string(),
                operator_type: 0,
                oper_name: "anonymous".to_string(),
                dept_name: String::new(),
                oper_url: "/sso/authorize".to_string(),
                oper_ip: ip,
                oper_location: String::new(),
                oper_param: snapshot,
                oper_before: String::new(),
                oper_diff: String::new(),
                json_result: String::new(),
                status: "0".to_string(),
                error_msg: String::new(),
                cost_time: 0,
                tenant_id: 0,
                target_tenant_id: None,
            })
            .await;
    }

    Ok(match outcome {
        AuthorizeOutcome::NeedLogin => {
            // 引导至前端登录页，登录后按 redirect 回到 authorize（相对路径，同源）
            // v5-D7：授权端点事件计数
            crate::observability::metrics::MetricsRegistry::global()
                .record_sso_event("authorize", "login");
            redirect_found(&login_target)
        }
        AuthorizeOutcome::NeedConsent(echo) => {
            crate::observability::metrics::MetricsRegistry::global()
                .record_sso_event("authorize", "consent");
            let target = format!(
                "/sso-consent?{}",
                encode_consent_query(&echo, state.config.sso.proxy_logo_uri)
            );
            redirect_found(&target)
        }
        AuthorizeOutcome::Redirect(url) => {
            // v5-D7：带 code 的成功签发与带 error 的拒绝（prompt=none/max_age 等）分开计
            let outcome = if url.contains("error=") {
                "rejected"
            } else {
                "ok"
            };
            crate::observability::metrics::MetricsRegistry::global()
                .record_sso_event("authorize", outcome);
            redirect_found(&url)
        }
        AuthorizeOutcome::HardError(err) => {
            crate::observability::metrics::MetricsRegistry::global()
                .record_sso_event("authorize", "invalid_request");
            oidc_error_response(
                StatusCode::BAD_REQUEST,
                &OidcError {
                    code: "invalid_request",
                    description: err.message,
                },
            )
        }
    })
}

/// POST /sso/token（application/x-www-form-urlencoded，另支持 Authorization: Basic 客户端认证）
#[utoipa::path(
    post,
    path = "/sso/token",
    request_body(content = TokenParams, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "令牌响应（RFC 6749 §5.1，Cache-Control: no-store）", body = serde_json::Value),
        (status = 400, description = "invalid_grant 等协议错误"),
        (status = 401, description = "invalid_client（带 WWW-Authenticate: Basic）"),
        (status = 500, description = "server_error"),
    ),
    security(()),
    tag = "sso"
)]
pub async fn token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    // Form rejection（缺字段/编码错）统一为 OIDC 标准错误体，而非 axum 默认纯文本（v3 P1'-5）
    form: Result<axum::Form<TokenParams>, axum::extract::rejection::FormRejection>,
) -> Response {
    // 与 discovery 端点同源推导 issuer：保证 id_token 的 iss 恒等于发现文档 advertised issuer
    let base = base_url(&headers, peer, &state.config.server.trusted_proxies);
    let mut params = match form {
        Ok(f) => f.0,
        Err(_) => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                &OidcError::new("invalid_request", "malformed token request".to_string()),
            );
        }
    };
    // v3 P1'-5：client_secret_basic（RFC 6749 §2.3.1）——主流客户端库默认 Basic 认证；
    // Basic 与表单同时出现时表单字段优先（规范未定义，取保守合并：缺哪个补哪个）
    if let Some((cid, csec)) = parse_basic_auth(&headers) {
        if params.client_id.is_none() {
            params.client_id = Some(cid);
        }
        if params.client_secret.is_none() {
            params.client_secret = Some(csec);
        }
    }
    // v5-E2：SSO 令牌签发事件写入登录日志（best-effort：spawn 异步写，不阻塞响应、
    // 失败不影响 token 发放）。审计链与本地登录对齐：登录日志可按 user_name 溯源
    // "该用户在何时为哪个 RP 兑换过令牌"。
    // v5-D7：协议事件指标（event 按 grant_type；outcome=ok 或错误码）
    let m_event = if params.grant_type == "refresh_token" {
        "token_refreshed"
    } else {
        "token_issued"
    };
    match state
        .sso_service
        .token(params.clone(), &state.store, &state.config.sso, &base)
        .await
    {
        Ok(result) => {
            crate::observability::metrics::MetricsRegistry::global()
                .record_sso_event(m_event, "ok");
            let ip = crate::utils::ip::extract_client_ip(
                &headers,
                peer.ip(),
                &state.config.server.trusted_proxies,
            );
            let state = state.clone();
            let user_name = result.user_name.clone();
            // v5-N2 Phase 2：登录日志归属被登录用户的租户（tid 随授权用户带入）
            let tenant_id = result.tenant_id;
            // 台账 F-8：登录日志以不可变主键强关联用户
            let user_id = result.user_id;
            let cid = params.client_id.clone().unwrap_or_default();
            crate::common::background::spawn_tracked(
                "sso_issue_login_log",
                crate::common::background::LIGHT_DB_BUDGET,
                Some(crate::observability::metrics::MetricsRegistry::global()),
                async move {
                    // B-2：ORM 写入下沉至 SysLogininforService（handler 不再直接构造 ActiveModel）
                    if let Err(e) = state
                        .logininfor_service
                        .write_sso_issue_log(tenant_id, user_id, user_name, ip, cid)
                        .await
                    {
                        tracing::warn!("SSO 令牌签发日志写入失败（best-effort）: {}", e);
                    }
                },
            );
            // RFC 6749 §5.1：token 响应必须携带 Cache-Control: no-store
            // 批六十六：序列化失败必须走统一错误契约——handler 内 panic 会中断整条连接
            //（无状态码、无留痕），故转为 500 并 error 日志。
            with_no_store(match serde_json::to_value(&result) {
                Ok(v) => (StatusCode::OK, Json(v)).into_response(),
                Err(e) => {
                    tracing::error!("SSO token 响应序列化失败: {}", e);
                    AppError::internal(&crate::tr!("error.common.internal")).into_response()
                }
            })
        }
        // RFC 6749 §5.2：invalid_client → 401 + WWW-Authenticate: Basic（v2-C2）；
        // server_error（DB 故障等）→ 500；其余协议错误保持 400
        Err(e) => {
            // v5-D7：失败也计数（outcome=OIDC 错误码）
            crate::observability::metrics::MetricsRegistry::global()
                .record_sso_event(m_event, e.code);
            let status = if e.code == "invalid_client" {
                StatusCode::UNAUTHORIZED
            } else if e.code == "server_error" {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            };
            let mut resp = oidc_error_response(status, &e);
            if status == StatusCode::UNAUTHORIZED {
                resp.headers_mut().insert(
                    axum::http::header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_static(
                        "Basic realm=\"stepby-sso\", charset=\"UTF-8\"",
                    ),
                );
            }
            resp
        }
    }
}

/// POST /sso/revoke（v5-D3，RFC 7009：令牌吊销——AT/RT 均可；
/// 吊销成功与 token 无效/已吊销均返回 200 空体，防枚举；客户端认证失败 401）
#[utoipa::path(
    post,
    path = "/sso/revoke",
    request_body(content = TokenParams, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "吊销完成（RFC 7009，恒 200 空体，防枚举）"),
        (status = 400, description = "协议参数错误"),
        (status = 401, description = "invalid_client（带 WWW-Authenticate: Basic）"),
        (status = 500, description = "server_error"),
    ),
    security(()),
    tag = "sso"
)]
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    form: Result<axum::Form<TokenParams>, axum::extract::rejection::FormRejection>,
) -> Response {
    let mut params = match form {
        Ok(f) => f.0,
        Err(_) => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                &OidcError::new(
                    "invalid_request",
                    "malformed revocation request".to_string(),
                ),
            );
        }
    };
    if let Some((cid, csec)) = parse_basic_auth(&headers) {
        if params.client_id.is_none() {
            params.client_id = Some(cid);
        }
        if params.client_secret.is_none() {
            params.client_secret = Some(csec);
        }
    }
    match state.sso_service.revoke_token(&params, &state.store).await {
        // RFC 7009 §2.2：恒 200 空体（含 token 无效/已吊销），防枚举
        Ok(()) => {
            // v5-D7：吊销事件计数（无效 token 也计为 ok——防枚举语义，不区分）
            crate::observability::metrics::MetricsRegistry::global()
                .record_sso_event("token_revoked", "ok");
            with_no_store((StatusCode::OK, Json(serde_json::json!({}))).into_response())
        }
        Err(e) => {
            crate::observability::metrics::MetricsRegistry::global()
                .record_sso_event("token_revoked", e.code);
            let status = if e.code == "invalid_client" {
                StatusCode::UNAUTHORIZED
            } else if e.code == "server_error" {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            };
            let mut resp = oidc_error_response(status, &e);
            if status == StatusCode::UNAUTHORIZED {
                resp.headers_mut().insert(
                    axum::http::header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_static(
                        "Basic realm=\"stepby-sso\", charset=\"UTF-8\"",
                    ),
                );
            }
            resp
        }
    }
}

/// POST /sso/introspect（批次 4，RFC 7662；`[sso].introspection_enabled` 默认 **关** ⇒ 404，
/// 与"端点不存在"的改造前行为等价）。
///
/// 客户端认证：`client_secret_basic` / `client_secret_post`（与 token/revoke 同口径）。
/// 无论令牌有效与否，**已认证**的请求一律 200（`active: true/false`）——RFC 7662 §2.2
/// 要求不得借错误码泄漏令牌存在性；只有客户端认证失败才 401。
#[utoipa::path(
    post,
    path = "/sso/introspect",
    request_body(content = TokenParams, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "令牌内省结果（RFC 7662，active: true/false）", body = serde_json::Value),
        (status = 400, description = "协议参数错误"),
        (status = 401, description = "invalid_client（带 WWW-Authenticate: Basic）"),
        (status = 404, description = "内省未启用（introspection_enabled=false）"),
        (status = 500, description = "server_error"),
    ),
    security(()),
    tag = "sso"
)]
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    form: Result<axum::Form<TokenParams>, axum::extract::rejection::FormRejection>,
) -> Response {
    // 关闭态 ⇒ 404（端点不存在），不暴露"存在但被关掉"的差异
    if !state.config.sso.enabled || !state.config.sso.introspection_enabled {
        return oidc_error_response(
            StatusCode::NOT_FOUND,
            &OidcError::new("not_found", crate::tr!("error.sso.disabled")),
        );
    }
    let mut params = match form {
        Ok(f) => f.0,
        Err(_) => {
            return oidc_error_response(
                StatusCode::BAD_REQUEST,
                &OidcError::new(
                    "invalid_request",
                    "malformed introspection request".to_string(),
                ),
            );
        }
    };
    if let Some((cid, csec)) = parse_basic_auth(&headers) {
        if params.client_id.is_none() {
            params.client_id = Some(cid);
        }
        if params.client_secret.is_none() {
            params.client_secret = Some(csec);
        }
    }
    let base = base_url(&headers, peer, &state.config.server.trusted_proxies);
    let issuer = state.sso_service.resolve_issuer(&state.config.sso, &base);
    match state
        .sso_service
        .introspect(&params, &state.store, &state.config.sso, &issuer)
        .await
    {
        // RFC 7662 §4：内省响应不得被缓存
        Ok(body) => with_no_store((StatusCode::OK, Json(body)).into_response()),
        Err(e) => {
            let status = if e.code == "invalid_client" {
                StatusCode::UNAUTHORIZED
            } else if e.code == "server_error" {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            };
            let mut resp = oidc_error_response(status, &e);
            if status == StatusCode::UNAUTHORIZED {
                resp.headers_mut().insert(
                    axum::http::header::WWW_AUTHENTICATE,
                    axum::http::HeaderValue::from_static(
                        "Basic realm=\"stepby-sso\", charset=\"UTF-8\"",
                    ),
                );
            }
            resp
        }
    }
}

/// GET /sso/client-logo/{clientId}（批次 4，`[sso].proxy_logo_uri` 默认 **关** ⇒ 404）
///
/// 同意页的原生行为是直接 `<img src={logo_uri}>` 外链第三方主机——那会把用户 IP / Referer
/// 泄漏给该主机。开启本开关后同意页改走同源本端点：服务端带 **SSRF 校验** 拉取（协议 +
/// 主机解析双重检查）、限制体积与超时、只放行 `image/*`，并按客户端 id 短缓存。
#[utoipa::path(
    get,
    path = "/sso/client-logo/{clientId}",
    params(("clientId" = String, Path, description = "OIDC 客户端 ID")),
    responses(
        (status = 200, description = "同源代理的客户端 logo 图片", content_type = "image/*"),
        (status = 404, description = "未开启代理 / 无 logo / 校验失败"),
        (status = 500, description = "HTTP 客户端构建失败"),
    ),
    security(()),
    tag = "sso"
)]
pub async fn client_logo(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
) -> Response {
    if !state.config.sso.enabled || !state.config.sso.proxy_logo_uri {
        return oidc_error_response(
            StatusCode::NOT_FOUND,
            &OidcError::new("not_found", crate::tr!("error.sso.disabled")),
        );
    }
    // 缓存的是**已通过 SSRF 校验的目标 URL**（不是图片字节：避免二进制进共享态需 base64 膨胀）。
    // 客户端改了 logo_uri 时靠 TTL 自然过期（1 小时）。
    // best-effort：读失败视为未命中、写失败仅影响下次命中，均与原 Redis 裸调用等价。
    let cache_key = format!("sso:logo:{}", client_id);
    let cached_url: Option<String> = state.store.get(&cache_key).await.unwrap_or(None);
    let url = match cached_url.filter(|u| !u.is_empty()) {
        Some(u) => u,
        None => {
            let Some(url) = state.sso_service.client_logo_source(&client_id).await else {
                // 无 logo / 未通过 SSRF 校验：404 让前端回落到首字母头像（不显示空白）
                // C.8：状态码不变，body 不再是空体——与同函数"未开启代理"分支同形状
                return oidc_error_response(
                    StatusCode::NOT_FOUND,
                    &OidcError::new("not_found", crate::tr!("error.sso.logo_unavailable")),
                );
            };
            let _: Result<(), _> = state
                .store
                .set_ex(&cache_key, &url, LOGO_CACHE_TTL_SECS)
                .await;
            url
        }
    };

    // b144：走 `outbound_client::build_with`（内嵌根证书回落），"不跟随重定向"这条保持不变——
    // 重定向可能把请求引到 SSRF 白名单之外的地址。
    let client = match crate::common::outbound_client::build_with("sso", |b| {
        b.timeout(std::time::Duration::from_secs(5))
            // 不跟随重定向：重定向可能把请求引到 SSRF 白名单之外的地址
            .redirect(reqwest::redirect::Policy::none())
    }) {
        Ok(c) => c,
        Err(_) => {
            return oidc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &OidcError::new("server_error", crate::tr!("error.sso.logo_proxy_failed")),
            );
        }
    };
    // b74（AGENTS B.4）：logo 代理是免鉴权端点上的**真实出网**，其健康度必须独立成桶
    // （故障面与 oauth_token/oauth_userinfo 不同：那是 IdP 的 API，这是客户端自配的图片地址）。
    // 本函数出口 5 条 ⇒ 用 RAII 守卫，不手写计数。
    let mut outbound = crate::observability::metrics::OutboundGuard::start("sso_logo");
    let resp = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => {
            return oidc_error_response(
                StatusCode::NOT_FOUND,
                &OidcError::new("not_found", crate::tr!("error.sso.logo_unavailable")),
            );
        }
    };
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    // 只放行图片类型：防止把本端点当通用内容代理
    if !content_type.starts_with("image/") {
        tracing::warn!(url = %url, content_type = %content_type, "同意页 logo 代理：响应非 image/*，拒绝");
        return oidc_error_response(
            StatusCode::NOT_FOUND,
            &OidcError::new("not_found", crate::tr!("error.sso.logo_unavailable")),
        );
    }
    let bytes = match resp.bytes().await {
        Ok(b) if b.len() <= MAX_LOGO_BYTES => b,
        Ok(_) => {
            tracing::warn!(url = %url, "同意页 logo 代理：体积超限，拒绝");
            return oidc_error_response(
                StatusCode::NOT_FOUND,
                &OidcError::new("not_found", crate::tr!("error.sso.logo_unavailable")),
            );
        }
        Err(_) => {
            return oidc_error_response(
                StatusCode::NOT_FOUND,
                &OidcError::new("not_found", crate::tr!("error.sso.logo_unavailable")),
            );
        }
    };
    outbound.succeeded();
    let mut out = bytes.into_response();
    if let Ok(ct) = HeaderValue::from_str(&content_type) {
        out.headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, ct);
    }
    out.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("public, max-age=3600"),
    );
    out
}

/// logo 体积上限（256 KiB）：超限即拒绝，避免把本端点当大文件代理
const MAX_LOGO_BYTES: usize = 256 * 1024;
/// logo 目标 URL 缓存 TTL（秒）
const LOGO_CACHE_TTL_SECS: u64 = 3600;

/// GET /sso/userinfo（Authorization: Bearer）
#[utoipa::path(
    get,
    path = "/sso/userinfo",
    responses(
        (status = 200, description = "用户信息 claims（RFC 6750，Cache-Control: no-store）", body = serde_json::Value),
        (status = 401, description = "invalid_token（带 WWW-Authenticate: Bearer）"),
    ),
    security(()),
    tag = "sso"
)]
pub async fn userinfo(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let bearer = match bearer_token(&headers) {
        Some(b) => b,
        None => {
            return oidc_error_response(
                StatusCode::UNAUTHORIZED,
                &OidcError::new("invalid_token", "missing bearer token".to_string()),
            );
        }
    };
    // v5-D11（本轮按准则⑥改判为默认关的开关）：响应**服务端**短 TTL 缓存。
    // 默认 0 = 不缓存 = 改造前行为；> 0 时按 AT 哈希缓存，TTL 硬上限 300s
    // （开启即接受"最多 300s 的吊销延迟"，由部署方权衡性能与即时性）。
    // 注意：这是**服务端**缓存，与 RFC 6750 的 `Cache-Control: no-store` 不冲突——
    // 后者约束的是浏览器/中间代理，下面命中缓存时同样带 no-store 返回。
    let ttl = state
        .config
        .sso
        .userinfo_cache_ttl_secs
        .min(crate::config::settings::USERINFO_CACHE_MAX_SECS);
    let cache_key = if ttl > 0 {
        let mut hasher = Sha256::new();
        hasher.update(bearer.as_bytes());
        Some(format!("sso:userinfo:{}", hex::encode(hasher.finalize())))
    } else {
        None
    };
    if let Some(key) = cache_key.as_deref() {
        // best-effort：读失败视为未命中（与原 Redis GET unwrap_or(None) 等价）
        let hit: Option<String> = state.store.get(key).await.unwrap_or(None);
        if let Some(raw) = hit
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw)
        {
            return with_no_store((StatusCode::OK, Json(v)).into_response());
        }
    }
    match state
        .sso_service
        .userinfo(bearer, &state.store, &state.config.sso)
        .await
    {
        // RFC 6750：userinfo 响应不得被缓存
        Ok(claims) => {
            if let Some(key) = cache_key.as_deref()
                && let Ok(raw) = serde_json::to_string(&claims)
            {
                // best-effort 写入：失败只影响"下次是否命中缓存"，不影响本次响应
                let _: Result<(), _> = state.store.set_ex(key, &raw, ttl).await;
            }
            with_no_store((StatusCode::OK, Json(claims)).into_response())
        }
        Err(e) => {
            // userinfo 错误按 RFC 6750 返回 401 + WWW-Authenticate
            let mut resp = oidc_error_response(StatusCode::UNAUTHORIZED, &e);
            if let Ok(v) = axum::http::HeaderValue::from_str(&format!(
                "Bearer error=\"{}\", error_description=\"{}\"",
                e.code, e.description
            )) {
                resp.headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, v);
            }
            resp
        }
    }
}

/// GET|POST /sso/logout（RP-initiated end-session，v4-P0-B 真实登出）
///
/// 副作用（需通过身份验证，防登出 CSRF）：
/// - `id_token_hint` 验签通过（对应客户端 HS256 密钥 + aud=client_id）→ 吊销该用户全部
///   SSO access_token、跨端拉黑 IdP 登录会话；
/// - 无 hint 时仅同源/同站请求（Sec-Fetch-Site ∈ same-origin/same-site/none）允许按
///   浏览器 Cookie 登出；跨站且无 hint 的一律无副作用（防 `<img src="/sso/logout">` 登出 CSRF）。
///
/// 回跳：`post_logout_redirect_uri` 精确命中该客户端登记白名单才 302（防开放重定向）；
/// hint 无效时 fail-closed 不回跳。
///
/// 注：路由同时注册 GET 与 POST（`/sso/logout`），此处按 GET 记录。
#[utoipa::path(
    get,
    path = "/sso/logout",
    params(LogoutQuery),
    responses(
        (status = 200, description = "登出完成（无 post_logout_redirect_uri 时返回 JSON 状态）", body = serde_json::Value),
        (status = 302, description = "重定向到 post_logout_redirect_uri（命中白名单时）"),
    ),
    security(()),
    tag = "sso"
)]
pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<LogoutQuery>,
) -> Result<Response, AppError> {
    // CSRF（v4-R5）：Sec-Fetch-Site 由浏览器强制、JS 不可伪造。
    // 老浏览器无该头 → 保守放行（副作用仍受 hint/白名单约束）。
    let sec_fetch_site = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let allow_cookie_logout = matches!(sec_fetch_site, "" | "none" | "same-origin" | "same-site");
    let session_token = cookie_value(&headers, SESSION_COOKIE);
    let redirect = state
        .sso_service
        .end_session(
            q.client_id.as_deref(),
            q.id_token_hint.as_deref(),
            q.post_logout_redirect_uri.as_deref(),
            session_token.as_deref(),
            allow_cookie_logout,
            &state.store,
            &state.config.jwt,
        )
        .await?;
    // v5-D7：登出事件计数
    crate::observability::metrics::MetricsRegistry::global().record_sso_event("logout", "ok");
    Ok(match redirect {
        Some(ru) => redirect_found(&ru),
        None => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "logged_out" })),
        )
            .into_response(),
    })
}

// ==================== 同意端点（受保护） ====================

/// POST /sso/consent —— 返回 { redirect } 供前端跳转
#[utoipa::path(
    post,
    path = "/sso/consent",
    request_body = ConsentDto,
    responses(
        (status = 200, description = "同意/拒绝结果（返回跳转地址）", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "同意参数非法或同意票校验失败"),
        (status = 401, description = "未授权"),
    ),
    tag = "sso"
)]
pub async fn consent(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<ConsentDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))?;
    // auth_time 权威来源：服务端登录 JWT 的 iat（v3 P1'-1）。
    // 前端不传或传错均以服务端为准，避免"认证时刻"被客户端伪造。
    let mut dto = dto;
    dto.auth_time = Some(operator.iat() as i64);
    let redirect = state
        .sso_service
        .consent(
            user_id,
            operator.username(),
            operator.tenant_id(),
            dto,
            &state.store,
            &state.config.sso,
        )
        .await?;
    Ok(AjaxResult::success(
        serde_json::json!({ "redirect": redirect }),
    ))
}

// ==================== 客户端管理（受保护） ====================

/// GET /system/oauth/client/list
#[utoipa::path(
    get,
    path = "/system/oauth/client/list",
    params(SsoClientQueryDto),
    responses(
        (status = 200, description = "OIDC 客户端分页列表", body = TableDataInfo<SsoClientVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "sso"
)]
pub async fn client_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(q): Query<SsoClientQueryDto>,
) -> Result<TableDataInfo<SsoClientVo>, AppError> {
    let (rows, total) = state
        .sso_service
        .get_client_page(q, operator.tenant_id())
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/oauth/client/{id}
#[utoipa::path(
    get,
    path = "/system/oauth/client/{id}",
    params(("id" = i64, Path, description = "客户端主键 ID")),
    responses(
        (status = 200, description = "客户端详情", body = AjaxResult<SsoClientVo>),
        (status = 404, description = "客户端不存在"),
    ),
    tag = "sso"
)]
pub async fn client_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
) -> Result<AjaxResult<SsoClientVo>, AppError> {
    let vo = state
        .sso_service
        .get_client_by_pk(id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/oauth/client —— 新增（一次性返回明文 secret）
#[utoipa::path(
    post,
    path = "/system/oauth/client",
    request_body = SsoClientUpsertDto,
    responses(
        (status = 200, description = "新增成功（clientSecret 为一次性明文）", body = AjaxResult<crate::service::sso_service::SsoClientCreateResult>),
        (status = 400, description = "参数错误或 client_id 重复"),
    ),
    tag = "sso"
)]
pub async fn client_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<SsoClientUpsertDto>,
) -> Result<AjaxResult<crate::service::sso_service::SsoClientCreateResult>, AppError> {
    let res = state
        .sso_service
        .add_client(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(res))
}

/// PUT /system/oauth/client —— 修改
#[utoipa::path(
    put,
    path = "/system/oauth/client",
    request_body = SsoClientUpsertDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<SsoClientVo>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "客户端不存在"),
    ),
    tag = "sso"
)]
pub async fn client_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<SsoClientUpsertDto>,
) -> Result<AjaxResult<SsoClientVo>, AppError> {
    let vo = state
        .sso_service
        .edit_client(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// DELETE /system/oauth/client/{ids}
#[utoipa::path(
    delete,
    path = "/system/oauth/client/{ids}",
    params(("ids" = String, Path, description = "客户端 ID 列表（逗号分隔）")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "ID 不合法或超过批量上限"),
    ),
    tag = "sso"
)]
pub async fn client_delete(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids = crate::utils::parse_id_list::<i64>(&ids)?;
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.sso.batch_id_invalid"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .sso_service
        .delete_clients(ids, &state.store, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// PUT /system/oauth/client/{id}/status
#[utoipa::path(
    put,
    path = "/system/oauth/client/{id}/status",
    params(
        ("id" = i64, Path, description = "客户端主键 ID"),
        ToggleQuery,
    ),
    responses(
        (status = 200, description = "启停成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "enabled 取值非法"),
        (status = 404, description = "客户端不存在"),
    ),
    tag = "sso"
)]
pub async fn client_toggle(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
    Query(q): Query<ToggleQuery>,
) -> Result<AjaxResult<()>, AppError> {
    // v5-S6：停用时按 client 粒度吊销该客户端名下全部用户的 SSO AT
    state
        .sso_service
        .toggle_client(id, &q.enabled, &state.store, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// POST /system/oauth/client/{id}/rotate-secret —— SSO D9：轮换 `client_secret`。
///
/// 零停机语义：新密钥立即生效，旧密钥进入"双密钥读取期"（RP 换配期间不断服）；
/// 响应中的 `clientSecret` 为**一次性明文**，请立即写入 RP 配置。
#[utoipa::path(
    post,
    path = "/system/oauth/client/{id}/rotate-secret",
    params(("id" = i64, Path, description = "客户端主键 ID")),
    responses(
        (status = 200, description = "轮换成功（clientSecret 为一次性明文）", body = AjaxResult<crate::service::sso_service::SsoClientRotateResult>),
        (status = 404, description = "客户端不存在"),
    ),
    tag = "sso"
)]
pub async fn client_rotate_secret(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
) -> Result<AjaxResult<crate::service::sso_service::SsoClientRotateResult>, AppError> {
    let res = state
        .sso_service
        .rotate_client_secret(id, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(res))
}

/// DELETE /system/oauth/client/{id}/rotate-secret —— SSO D9：结束双密钥读取期。
///
/// 清空旧密钥摘要 ⇒ 旧 `client_secret` 立即失效；幂等（本无过渡期时同样成功）。
#[utoipa::path(
    delete,
    path = "/system/oauth/client/{id}/rotate-secret",
    params(("id" = i64, Path, description = "客户端主键 ID")),
    responses(
        (status = 200, description = "已结束双密钥读取期（幂等）", body = AjaxResult<serde_json::Value>),
        (status = 404, description = "客户端不存在"),
    ),
    tag = "sso"
)]
pub async fn client_clear_previous_secret(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
) -> Result<AjaxResult<()>, AppError> {
    state
        .sso_service
        .clear_previous_client_secret(id, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

// ==================== 自助授权管理（v4-R8：仅登录，无需管理权限） ====================

/// GET /system/user/profile/sso-grants —— 当前用户"已授权应用"列表
#[utoipa::path(
    get,
    path = "/system/user/profile/sso-grants",
    responses(
        (status = 200, description = "当前用户已授权应用列表", body = AjaxResult<Vec<crate::service::sso_service::SsoGrantVo>>),
        (status = 401, description = "未授权"),
    ),
    tag = "sso"
)]
pub async fn grant_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<crate::service::sso_service::SsoGrantVo>>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))?;
    let grants = state.sso_service.list_user_grants(user_id).await?;
    Ok(AjaxResult::success(grants))
}

/// DELETE /system/user/profile/sso-grants/{clientId} —— 撤销对某应用的授权（级联吊销其名下 SSO AT）
#[utoipa::path(
    delete,
    path = "/system/user/profile/sso-grants/{clientId}",
    params(("clientId" = String, Path, description = "OIDC 客户端 ID")),
    responses(
        (status = 200, description = "撤销成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "clientId 为空"),
        (status = 401, description = "未授权"),
    ),
    tag = "sso"
)]
pub async fn grant_revoke(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(client_id): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))?;
    let client_id = client_id.trim().to_string();
    if client_id.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.sso.client_id_required"
        )));
    }
    state
        .sso_service
        .revoke_user_grant(user_id, &client_id, &state.store)
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

// ==================== 内部辅助 ====================

/// 构造 HTTP 302 Found 重定向（携带 Location）。
/// OAuth2/OIDC 授权回跳规范要求 302；axum 0.8 的 `Redirect` 仅提供 307/308，故手动组装。
/// 同时携带 `Cache-Control: no-store`（v4-R1：授权码/会话流转 URL 不得被中间层缓存）。
fn redirect_found(url: &str) -> Response {
    match HeaderValue::from_str(url) {
        Ok(v) => {
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::FOUND;
            resp.headers_mut().insert(axum::http::header::LOCATION, v);
            resp.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            resp
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "invalid redirect uri").into_response(),
    }
}

/// 为响应追加 `Cache-Control: no-store`（token / userinfo / discovery 协议面通用，RFC 6749 §5.1）
fn with_no_store(mut resp: Response) -> Response {
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    resp
}

fn oidc_error_response(status: StatusCode, err: &OidcError) -> Response {
    let mut resp = (
        status,
        Json(serde_json::json!({
            "error": err.code,
            "error_description": err.description,
        })),
    )
        .into_response();
    // v5 核查（F3 补全）：协议面错误响应同样不得被缓存（error_description 含
    // 客户端/回调线索，与成功响应同标准：no-store）
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    resp
}

/// 计算 base URL（scheme://host）
///
/// v3 P1'-2：`X-Forwarded-Proto` 仅在 TCP 对端位于 `server.trusted_proxies` 白名单时才采信
/// （复用 utils::ip 的可信代理范式）；不可信来源伪造该头会把 issuer 误标为 https。
/// Host 头为 HTTP 语义必需（HTTP/1.1），直连与反代场景均以其为准。
fn base_url(headers: &HeaderMap, peer: SocketAddr, trusted_proxies: &[String]) -> String {
    let scheme = if crate::utils::ip::is_trusted_proxy(&peer.ip(), trusted_proxies) {
        headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("http")
            .to_string()
    } else {
        "http".to_string()
    };
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| peer.to_string());
    format!("{}://{}", scheme, host)
}

/// 解析 `Authorization: Basic` 头为 (client_id, client_secret)（RFC 6749 §2.3.1）。
///
/// Basic 凭据 = base64(`urlencoded(client_id):urlencoded(client_secret)`)，需对两段做
/// percent-decode（含 `+`→空格，form-urlencoded 语义）。auth-scheme 按 RFC 7235
/// 大小写不敏感匹配。解析失败返回 None（按表单凭据处理）。
fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine as _;
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, encoded) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let joined = String::from_utf8(decoded).ok()?;
    let (cid, csec) = joined.split_once(':')?;
    Some((form_urldecode(cid)?, form_urldecode(csec)?))
}

/// form-urlencoded 解码：`+` → 空格，`%XX` → 字节；非法转义返回 None（fail-closed）
fn form_urldecode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hex = bytes.get(i + 1..i + 3)?;
                let hi = (hex[0] as char).to_digit(16)?;
                let lo = (hex[1] as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// 从 Cookie 头解析指定 cookie 值
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=')
            && k.trim() == name
        {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// 从 Authorization 头提取 Bearer 令牌
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// 供**我方前端 SPA** 消费的查询值编码：把空格编码为 `%20`（而非表单式的 `+`）。
///
/// 原因：Vue Router 按 RFC 3986 解析 `location.query`，**不会**把 `+` 还原成空格，
/// 于是 `scope=openid+profile` 会被前端读成字面量 `"openid+profile"`，按空格切分后拿不到
/// `openid`，导致同意页误判「授权请求无效」。而 `form_urlencoded` 里真正的 `+` 字符会被编码成
/// `%2B`，故把其输出中的 `+` 一律替换为 `%20` 是精确无损的（仅影响空格）。
/// RP 面向的 authorize/token 协议参数仍用 `urlencode`（`+`），由 RP 的表单解析正确还原。
fn urlencode_spa(s: &str) -> String {
    urlencode(s).replace('+', "%20")
}

/// 未登录时的登录页跳转目标：`/login?redirect=<urlencode(同源相对 authorize 路径)>`。
/// redirect 必须是相对路径（非 `{base}` 绝对 URL），否则前端开放重定向守卫会拒绝它。
fn login_redirect_target(p: &AuthorizeParams) -> String {
    let authorize_path = format!("/sso/authorize?{}", encode_authorize_query(p));
    format!("/login?redirect={}", urlencode(&authorize_path))
}

/// 拼回原始 authorize 查询（用于未登录回跳）
fn encode_authorize_query(p: &AuthorizeParams) -> String {
    let mut parts: Vec<String> = vec![
        format!("client_id={}", urlencode(&p.client_id)),
        format!("response_type={}", urlencode(&p.response_type)),
    ];
    if let Some(v) = &p.redirect_uri {
        parts.push(format!("redirect_uri={}", urlencode(v)));
    }
    if !p.scope.is_empty() {
        parts.push(format!("scope={}", urlencode(&p.scope)));
    }
    if let Some(v) = &p.state {
        parts.push(format!("state={}", urlencode(v)));
    }
    if let Some(v) = &p.nonce {
        parts.push(format!("nonce={}", urlencode(v)));
    }
    if let Some(v) = &p.code_challenge {
        parts.push(format!("code_challenge={}", urlencode(v)));
    }
    if let Some(v) = &p.code_challenge_method {
        parts.push(format!("code_challenge_method={}", urlencode(v)));
    }
    parts.join("&")
}

/// 拼同意页查询（回显至前端 /sso-consent）。
/// 该跳转的接收方是**我方前端页面**（非外部 RP），故按「应用私有 API」约定使用 camelCase，
/// 与前端 ts-rs 生成类型一致；而 RP 面向的 authorize/token 协议参数保持 snake_case（见 AuthorizeQuery）。
fn encode_consent_query(e: &crate::service::sso_service::ConsentEcho, proxy_logo: bool) -> String {
    // 全部值经 urlencode_spa：空格→%20，确保 Vue Router 逐字段解析（尤其 scope/clientName）正确。
    let mut parts: Vec<String> = vec![
        format!("clientId={}", urlencode_spa(&e.client_id)),
        format!("clientName={}", urlencode_spa(&e.client_name)),
        format!("scope={}", urlencode_spa(&e.scopes.join(" "))),
        format!("redirectUri={}", urlencode_spa(&e.redirect_uri)),
        "responseType=code".to_string(),
        "codeChallengeMethod=S256".to_string(),
        format!("codeChallenge={}", urlencode_spa(&e.code_challenge)),
    ];
    // 批次 4（`[sso].proxy_logo_uri`）：同意页改用同源 `/sso/client-logo/{clientId}`，
    // 不再直接外链第三方主机（避免把用户 IP/Referer 泄漏给该主机）。
    if proxy_logo {
        parts.push("logoProxy=1".to_string());
    }
    if !e.logo_uri.is_empty() {
        parts.push(format!("logoUri={}", urlencode_spa(&e.logo_uri)));
    }
    if let Some(v) = &e.state {
        parts.push(format!("state={}", urlencode_spa(v)));
    }
    if let Some(v) = &e.nonce {
        parts.push(format!("nonce={}", urlencode_spa(v)));
    }
    // v5-D9：同意票（仅 `[sso].consent_ticket = required` 时下发）——
    // 前端原样回传至 POST /sso/consent，服务端据此判定"同意参数未被篡改"。
    // `off` 档 `ticket` 恒 None ⇒ 本段不追加任何参数（关闭态查询串逐字不变）。
    if let Some(v) = &e.ticket {
        parts.push(format!("ticket={}", urlencode_spa(v)));
    }
    parts.join("&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Basic 认证凭据的 form-urlencoded 解码（RFC 6749 §2.3.1）：
    /// `+`→空格、`%XX`→字节、非法转义 fail-closed 返回 None
    #[test]
    fn form_urldecode_decodes_percent_and_plus() {
        assert_eq!(form_urldecode("app_x"), Some("app_x".to_string()));
        assert_eq!(form_urldecode("a+b"), Some("a b".to_string()));
        assert_eq!(form_urldecode("%2Fx"), Some("/x".to_string()));
        assert_eq!(form_urldecode("a%20b"), Some("a b".to_string()));
        // 非法：截断的 %XX
        assert_eq!(form_urldecode("a%2"), None);
        // 非法：非 hex 转义
        assert_eq!(form_urldecode("%zz"), None);
    }

    /// parse_basic_auth：标准 base64 头解析 + 解码失败返回 None
    #[test]
    fn parse_basic_auth_roundtrip() {
        let mut headers = HeaderMap::new();
        let raw = base64::engine::general_purpose::STANDARD.encode(b"app_x:secret-1");
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Basic {raw}")).unwrap(),
        );
        assert_eq!(
            parse_basic_auth(&headers),
            Some(("app_x".to_string(), "secret-1".to_string()))
        );
        // 非 Basic 头 → None
        let mut headers2 = HeaderMap::new();
        headers2.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(parse_basic_auth(&headers2), None);
        // base64 无效 → None
        let mut headers3 = HeaderMap::new();
        headers3.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Basic !!!!"),
        );
        assert_eq!(parse_basic_auth(&headers3), None);
    }

    /// base_url：X-Forwarded-Proto 仅在可信代理时采信（v3 P1'-2）
    #[test]
    fn base_url_ignores_forwarded_proto_from_untrusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("host", axum::http::HeaderValue::from_static("sso.corp.com"));
        headers.insert(
            "x-forwarded-proto",
            axum::http::HeaderValue::from_static("https"),
        );
        let peer: std::net::SocketAddr = "9.9.9.9:1234".parse().unwrap();
        // 不可信对端伪造 proto → 回退 http
        assert_eq!(base_url(&headers, peer, &[]), "http://sso.corp.com");
        // 对端是可信代理 → 采信 https
        assert_eq!(
            base_url(&headers, peer, &["9.9.9.9".to_string()]),
            "https://sso.corp.com"
        );
    }

    /// 同意页 echo 查询必须把空格编码为 %20（Vue Router 不把 `+` 还原为空格，否则 scope 解析出错）；
    /// 而真正的 `+` 字符应保留为 %2B（form 编码本就如此），替换只影响空格。
    #[test]
    fn consent_space_encodes_as_pct20_not_plus() {
        assert_eq!(
            urlencode_spa("openid profile email"),
            "openid%20profile%20email"
        );
        assert_eq!(
            urlencode_spa("SSO 客户端"),
            "SSO%20%E5%AE%A2%E6%88%B7%E7%AB%AF"
        );
        assert_eq!(urlencode_spa("a+b"), "a%2Bb");
        assert_eq!(urlencode_spa("plain"), "plain");
        // 反证：RP 面向的 urlencode 仍用 +（保持协议面原样，不改）
        assert_eq!(urlencode("openid profile"), "openid+profile");
    }

    /// 登出态登录回跳的 redirect 参数必须是**同源相对路径**（真实 E2E 审计发现的回归锁定）：
    /// 绝对 URL（`http://host/sso/authorize?...`）会被前端 isSafeRedirect 开放重定向守卫拒绝，
    /// 登录成功后回落到首页而非回到 authorize，整条 RP 授权链路断裂。
    #[test]
    fn login_redirect_carries_relative_authorize_path() {
        let p = AuthorizeParams {
            client_id: "app_x".to_string(),
            redirect_uri: Some("http://rp.local/cb".to_string()),
            response_type: "code".to_string(),
            scope: "openid profile".to_string(),
            state: Some("s 1".to_string()),
            nonce: None,
            code_challenge: Some("chal".to_string()),
            code_challenge_method: Some("S256".to_string()),
            prompt: None,
            max_age: None,
            acr_values: None,
        };
        let target = login_redirect_target(&p);
        // /login?redirect= 后紧跟 %2F（即 /sso/authorize 相对路径），绝不出现 %3A%2F%2F（://）
        assert!(
            target.starts_with("/login?redirect=%2Fsso%2Fauthorize%3Fclient_id%3Dapp_x"),
            "target={target}"
        );
        assert!(
            !target.contains("%3A%2F%2F"),
            "redirect 内不应混入绝对 URL: {target}"
        );
        // 内层 authorize 查询的空格先被表单编码为 +，整体再编码时 + 转义为 %2B
        assert!(target.contains("%26scope%3Dopenid%2Bprofile"));
        assert!(target.contains("%26state%3Ds%2B1"));
    }
}
