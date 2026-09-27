//! WebAuthn / Passkey Handler（能力位 `auth.webauthn`，默认 off ⇒ 端点 404）。
//!
//! 分两组端点：
//! - **自助**（受保护 + 仅登录，见 `middleware/permission.rs::is_login_only_path`）：
//!   `register/start` / `register/finish` / `credentials`(list) / `credentials/{credId}`(delete)，
//!   操作对象恒为**当前登录用户本人**（归属校验在 service 层）；
//! - **公开**（免鉴权 + 限流，见 `router/webauthn_router.rs::public_webauthn_routes`）：
//!   `/login/webauthn/start` / `/login/webauthn/finish`，登录成功**复用既有登录完成链路**
//!   （`AuthService::finalize_webauthn_login`）签发令牌。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::HeaderMap;
use axum::http::request::Parts;

use crate::common::{AjaxResult, AppError};
use crate::handler::auth_handler::LoginResult;
use crate::middleware::Operator;
use crate::service::webauthn_service::{
    WebauthnCredentialVo, WebauthnLoginFinishDto, WebauthnLoginStartDto, WebauthnRegisterFinishDto,
};
use crate::state::AppState;
use crate::utils::ip::extract_client_ip;

/// 能力位门禁提取器：**在请求体解析之前**执行能力位判定。
///
/// 必须早于 `Json<T>`：否则"能力位关闭 + 非法 JSON"会先因反序列化失败返回 422，
/// 破坏"关闭态统一 404（不暴露端点存在性）"的口径。作为 FromRequestParts，它按参数声明
/// 顺序先于末尾的 FromRequest（Json）运行，任一不满足即以 404 短路。服务层另有同名守卫
/// （纵深防御，防止绕过 HTTP 层直接调用）。
pub struct WebauthnEnabled;

impl FromRequestParts<Arc<AppState>> for WebauthnEnabled {
    type Rejection = AppError;

    async fn from_request_parts(
        _parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        state.webauthn_service.ensure_enabled()?;
        Ok(WebauthnEnabled)
    }
}

/// 解析当前登录用户 ID（Operator.user_id 为字符串）
fn operator_user_id(operator: &Operator) -> Result<i64, AppError> {
    operator
        .user_id()
        .parse::<i64>()
        .map_err(|_| AppError::unauthorized(&crate::tr!("error.webauthn.user_id_invalid")))
}

// ==================== 自助：注册 / 凭据管理 ====================

/// POST /system/user/webauthn/register/start
///
/// 开始绑定 passkey：返回发送给 `navigator.credentials.create` 的 options（`data` 即 options）。
#[utoipa::path(
    post,
    path = "/system/user/webauthn/register/start",
    responses(
        (status = 200, description = "创建选项（WebAuthn PublicKeyCredentialCreationOptions）", body = AjaxResult<serde_json::Value>),
        (status = 404, description = "能力位未开启"),
        (status = 503, description = "rp_id/origin 未配置"),
    ),
    tag = "system-user"
)]
pub async fn register_start(
    State(state): State<Arc<AppState>>,
    _enabled: WebauthnEnabled,
    operator: Operator,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let user_id = operator_user_id(&operator)?;
    let options = state.webauthn_service.register_start(user_id).await?;
    Ok(AjaxResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        data: Some(options),
    })
}

/// POST /system/user/webauthn/register/finish
///
/// 完成绑定：校验证明对象并落库（同凭据 / 同名重复注册 ⇒ 400）。
#[utoipa::path(
    post,
    path = "/system/user/webauthn/register/finish",
    request_body = WebauthnRegisterFinishDto,
    responses(
        (status = 200, description = "绑定成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "响应无效或重复注册"),
        (status = 404, description = "能力位未开启"),
    ),
    tag = "system-user"
)]
pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    _enabled: WebauthnEnabled,
    operator: Operator,
    Json(dto): Json<WebauthnRegisterFinishDto>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id = operator_user_id(&operator)?;
    state.webauthn_service.register_finish(user_id, dto).await?;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.webauthn_registered"
    )))
}

/// GET /system/user/webauthn/credentials
///
/// 列出本人全部 passkey 凭据（仅本人）。
#[utoipa::path(
    get,
    path = "/system/user/webauthn/credentials",
    responses(
        (status = 200, description = "本人凭据列表", body = AjaxResult<Vec<WebauthnCredentialVo>>),
        (status = 404, description = "能力位未开启"),
    ),
    tag = "system-user"
)]
pub async fn list_credentials(
    State(state): State<Arc<AppState>>,
    _enabled: WebauthnEnabled,
    operator: Operator,
) -> Result<AjaxResult<Vec<WebauthnCredentialVo>>, AppError> {
    let user_id = operator_user_id(&operator)?;
    // 并列传入操作者租户：仓储层据此 `tenant_id` 收窄（纵深防御，审计器 R1 口径）
    let list = state
        .webauthn_service
        .list_credentials(user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(list))
}

/// DELETE /system/user/webauthn/credentials/{credId}
///
/// 删除本人凭据（越权 / 不存在 ⇒ 404，不区分）。
#[utoipa::path(
    delete,
    path = "/system/user/webauthn/credentials/{credId}",
    params(("credId" = i64, Path, description = "凭据 ID")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 404, description = "能力位未开启 / 凭据不存在或不属于本人"),
    ),
    tag = "system-user"
)]
pub async fn delete_credential(
    State(state): State<Arc<AppState>>,
    _enabled: WebauthnEnabled,
    operator: Operator,
    Path(cred_id): Path<i64>,
) -> Result<AjaxResult<()>, AppError> {
    let user_id = operator_user_id(&operator)?;
    state
        .webauthn_service
        .delete_credential(user_id, cred_id)
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.webauthn_deleted"
    )))
}

// ==================== 公开：passkey 登录 ====================

/// POST /login/webauthn/start
///
/// 开始 passkey 登录：返回发送给 `navigator.credentials.get` 的 options（`data` 即 options）。
/// **反枚举**：用户不存在 / 停用 / 租户停用 / 无凭据一律返回与密码登录失败同形的 401。
#[utoipa::path(
    post,
    path = "/login/webauthn/start",
    request_body = WebauthnLoginStartDto,
    responses(
        (status = 200, description = "请求选项（WebAuthn PublicKeyCredentialRequestOptions）", body = AjaxResult<serde_json::Value>),
        (status = 401, description = "登录失败（与密码登录同形，防用户名枚举）"),
        (status = 404, description = "能力位未开启"),
    ),
    security(()),
    tag = "auth"
)]
pub async fn login_start(
    State(state): State<Arc<AppState>>,
    _enabled: WebauthnEnabled,
    Json(dto): Json<WebauthnLoginStartDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let options = state.webauthn_service.login_start(&dto.username).await?;
    Ok(AjaxResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        data: Some(options),
    })
}

/// POST /login/webauthn/finish
///
/// 完成 passkey 登录：校验断言 → **复用既有登录完成链路**签发令牌（JWT + 在线会话 + 登录日志）。
#[utoipa::path(
    post,
    path = "/login/webauthn/finish",
    request_body = WebauthnLoginFinishDto,
    responses(
        (status = 200, description = "登录成功", body = LoginResult),
        (status = 401, description = "登录失败（与密码登录同形）"),
        (status = 404, description = "能力位未开启"),
    ),
    security(()),
    tag = "auth"
)]
pub async fn login_finish(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    _enabled: WebauthnEnabled,
    Json(dto): Json<WebauthnLoginFinishDto>,
) -> Result<LoginResult, AppError> {
    let login_ip = extract_client_ip(
        &headers,
        peer_addr.ip(),
        &state.config.server.trusted_proxies,
    );
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let username = dto.username.clone();

    // 1. 断言校验 + 归属校验（失败统一 401），返回已认证用户
    let user = state.webauthn_service.login_finish(&username, dto).await?;

    // 2. 复用既有登录完成链路签发令牌（不另写令牌逻辑）
    let mut redis = state.redis.clone();
    let vo = state
        .auth_service
        .finalize_webauthn_login(
            &user,
            &login_ip,
            user_agent,
            &mut redis,
            &state.config.jwt,
            &state.ip_locator,
        )
        .await;

    // 3. WebHook 事件分发（与密码登录同源），失败含原因供外部风控
    match &vo {
        Ok(v) => {
            state.web_hook_service.dispatch_event(
                crate::service::sys_web_hook_service::EVENT_LOGIN_SUCCESS,
                serde_json::json!({
                    "username": username,
                    "ip": login_ip,
                    "method": "webauthn",
                    "time": crate::common::datetime::now_naive().to_string(),
                }),
                v.tenant_id,
            );
        }
        Err(err) => {
            state.web_hook_service.dispatch_event(
                crate::service::sys_web_hook_service::EVENT_LOGIN_FAILURE,
                serde_json::json!({
                    "username": username,
                    "ip": login_ip,
                    "method": "webauthn",
                    "reason": err.to_string(),
                    "time": crate::common::datetime::now_naive().to_string(),
                }),
                user.tenant_id,
            );
        }
    }

    let vo = vo?;
    Ok(LoginResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        token: vo.token,
    })
}
