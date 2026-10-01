// stepby-axum/src/router/sys_user_pref_router.rs
//! 用户消息偏好 / 免打扰路由注册
//!
//! 受保护路由（需 auth_middleware + permission_middleware，但按 is_login_only_path
//! 白名单放行哪种操作都仅针对当前登录用户本人，无需 RBAC）：
//! - GET  /system/profile/pref   查询当前用户消息偏好
//! - PUT  /system/profile/pref   更新当前用户消息偏好 / 免打扰

use axum::Router;
use axum::routing::get;
use std::sync::Arc;

use crate::handler::sys_user_pref_handler;
use crate::state::AppState;

/// 用户消息偏好路由（需挂在鉴权中间件下）
pub fn user_pref_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET 查询 / PUT 更新当前用户消息偏好
        .route(
            "/system/profile/pref",
            get(sys_user_pref_handler::get_pref).put(sys_user_pref_handler::update_pref),
        )
}
