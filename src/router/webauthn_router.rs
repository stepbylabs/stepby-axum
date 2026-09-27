//! WebAuthn / Passkey 路由注册（能力位 `auth.webauthn`，默认 off ⇒ 端点 404）。
//!
//! - 自助（受保护 + 仅登录）：绑定 passkey、查看/删除本人凭据；
//! - 公开（免鉴权 + 限流）：passkey 登录两阶段，挂在 `public` 子树（不进入权限中间件鉴权面）。

use axum::Router;
use axum::routing::{delete, get, post};
use std::sync::Arc;

use crate::handler::webauthn_handler;
use crate::middleware::rate_limit::rate_limit_middleware;
use crate::state::AppState;

/// 自助路由（需 auth_middleware；无需 RBAC，按 `is_login_only_path` 白名单仅登录）
pub fn webauthn_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/system/user/webauthn/register/start",
            post(webauthn_handler::register_start),
        )
        .route(
            "/system/user/webauthn/register/finish",
            post(webauthn_handler::register_finish),
        )
        .route(
            "/system/user/webauthn/credentials",
            get(webauthn_handler::list_credentials),
        )
        .route(
            "/system/user/webauthn/credentials/{credId}",
            delete(webauthn_handler::delete_credential),
        )
}

/// 公开路由（免鉴权；挂限流中间件防暴力探测，参照 `/sso/*` 与 `/login`）
pub fn public_webauthn_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/login/webauthn/start", post(webauthn_handler::login_start))
        .route(
            "/login/webauthn/finish",
            post(webauthn_handler::login_finish),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state,
            rate_limit_middleware,
        ))
}
