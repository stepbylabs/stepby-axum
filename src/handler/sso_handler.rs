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
#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct LogoutQuery {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub id_token_hint: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToggleQuery {
    pub enabled: String,
}

// ==================== 公开端点 ====================

/// GET /.well-known/openid-configuration
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
pub async fn jwks(State(state): State<Arc<AppState>>) -> Response {
    if !state.config.sso.enabled {
        return oidc_error_response(
            StatusCode::NOT_FOUND,
            &OidcError::new("not_found", crate::tr!("error.sso.disabled")),
        );
    }
    with_no_store((StatusCode::OK, Json(state.sso_service.jwks().await)).into_response())
}

/// GET /sso/authorize
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
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
            &mut state.redis.clone(),
            &state.config.jwt,
            &state.config.sso,
        )
        .await?;

    Ok(match outcome {
        AuthorizeOutcome::NeedLogin => {
            // 引导至前端登录页，登录后按 redirect 回到 authorize（相对路径，同源）
            redirect_found(&login_target)
        }
        AuthorizeOutcome::NeedConsent(echo) => {
            let target = format!("/sso-consent?{}", encode_consent_query(&echo));
            redirect_found(&target)
        }
        AuthorizeOutcome::Redirect(url) => redirect_found(&url),
        AuthorizeOutcome::HardError(err) => oidc_error_response(
            StatusCode::BAD_REQUEST,
            &OidcError {
                code: "invalid_request",
                description: err.message,
            },
        ),
    })
}

/// POST /sso/token（application/x-www-form-urlencoded，另支持 Authorization: Basic 客户端认证）
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
    match state
        .sso_service
        .token(
            params.clone(),
            &mut state.redis.clone(),
            &state.config.sso,
            &base,
        )
        .await
    {
        Ok(result) => {
            let ip = crate::utils::ip::extract_client_ip(
                &headers,
                peer.ip(),
                &state.config.server.trusted_proxies,
            );
            let db = state.db.clone();
            let user_name = result.user_name.clone();
            let cid = params.client_id.clone().unwrap_or_default();
            tokio::spawn(async move {
                let now = crate::common::datetime::now_naive();
                use sea_orm::{ActiveModelTrait, Set};
                let am = crate::entity::sys_logininfor::ActiveModel {
                    user_name: Set(Some(user_name)),
                    ipaddr: Set(Some(ip)),
                    login_location: Set(None),
                    browser: Set(Some("SSO".to_string())),
                    os: Set(Some("-".to_string())),
                    status: Set(Some("0".to_string())),
                    msg: Set(Some(format!("SSO 令牌签发: {cid}"))),
                    login_time: Set(Some(now)),
                    ..Default::default()
                };
                if let Err(e) = am.insert(&db).await {
                    tracing::warn!("SSO 令牌签发日志写入失败（best-effort）: {}", e);
                }
            });
            // RFC 6749 §5.1：token 响应必须携带 Cache-Control: no-store
            with_no_store(
                (StatusCode::OK, Json(serde_json::to_value(result).unwrap())).into_response(),
            )
        }
        // RFC 6749 §5.2：invalid_client → 401 + WWW-Authenticate: Basic（v2-C2）；
        // server_error（DB 故障等）→ 500；其余协议错误保持 400
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
                        "Basic realm=\"yebot-sso\", charset=\"UTF-8\"",
                    ),
                );
            }
            resp
        }
    }
}

/// POST /sso/revoke（v5-D3，RFC 7009：令牌吊销——AT/RT 均可；
/// 吊销成功与 token 无效/已吊销均返回 200 空体，防枚举；客户端认证失败 401）
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
    match state
        .sso_service
        .revoke_token(&params, &mut state.redis.clone())
        .await
    {
        // RFC 7009 §2.2：恒 200 空体（含 token 无效/已吊销），防枚举
        Ok(()) => with_no_store((StatusCode::OK, Json(serde_json::json!({}))).into_response()),
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
                        "Basic realm=\"yebot-sso\", charset=\"UTF-8\"",
                    ),
                );
            }
            resp
        }
    }
}

/// GET /sso/userinfo（Authorization: Bearer）
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
    match state
        .sso_service
        .userinfo(bearer, &mut state.redis.clone(), &state.config.sso)
        .await
    {
        // RFC 6750：userinfo 响应不得被缓存
        Ok(claims) => with_no_store((StatusCode::OK, Json(claims)).into_response()),
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
            &mut state.redis.clone(),
            &state.config.jwt,
        )
        .await?;
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
            &mut state.redis.clone(),
            &state.config.sso,
        )
        .await?;
    Ok(AjaxResult::success(
        serde_json::json!({ "redirect": redirect }),
    ))
}

// ==================== 客户端管理（受保护） ====================

/// GET /system/oauth/client/list
pub async fn client_list(
    State(state): State<Arc<AppState>>,
    Query(q): Query<SsoClientQueryDto>,
) -> Result<TableDataInfo<SsoClientVo>, AppError> {
    let (rows, total) = state.sso_service.get_client_page(q).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/oauth/client/{id}
pub async fn client_info(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<AjaxResult<SsoClientVo>, AppError> {
    let vo = state.sso_service.get_client_by_pk(id).await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/oauth/client —— 新增（一次性返回明文 secret）
pub async fn client_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<SsoClientUpsertDto>,
) -> Result<AjaxResult<crate::service::sso_service::SsoClientCreateResult>, AppError> {
    let res = state
        .sso_service
        .add_client(dto, operator.username())
        .await?;
    Ok(AjaxResult::success(res))
}

/// PUT /system/oauth/client —— 修改
pub async fn client_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<SsoClientUpsertDto>,
) -> Result<AjaxResult<SsoClientVo>, AppError> {
    let vo = state
        .sso_service
        .edit_client(dto, operator.username())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// DELETE /system/oauth/client/{ids}
pub async fn client_delete(
    State(state): State<Arc<AppState>>,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids = crate::utils::parse_id_list::<i64>(&ids);
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
        .delete_clients(ids, &mut state.redis.clone())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// PUT /system/oauth/client/{id}/status
pub async fn client_toggle(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(q): Query<ToggleQuery>,
) -> Result<AjaxResult<()>, AppError> {
    // v5-S6：停用时按 client 粒度吊销该客户端名下全部用户的 SSO AT
    state
        .sso_service
        .toggle_client(id, &q.enabled, &mut state.redis.clone())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

// ==================== 自助授权管理（v4-R8：仅登录，无需管理权限） ====================

/// GET /system/user/profile/sso-grants —— 当前用户"已授权应用"列表
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
        .revoke_user_grant(user_id, &client_id, &mut state.redis.clone())
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
fn encode_consent_query(e: &crate::service::sso_service::ConsentEcho) -> String {
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
    if !e.logo_uri.is_empty() {
        parts.push(format!("logoUri={}", urlencode_spa(&e.logo_uri)));
    }
    if let Some(v) = &e.state {
        parts.push(format!("state={}", urlencode_spa(v)));
    }
    if let Some(v) = &e.nonce {
        parts.push(format!("nonce={}", urlencode_spa(v)));
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
