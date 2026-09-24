// axum-backend/src/router/scim_router.rs
//! v5-D12：SCIM 2.0 路由（挂公开段——handler 内自校验独立 Bearer Token，
//! 不走平台 JWT 认证中间件：IdP 为服务器对服务器调用，凭据体系不同）。

use crate::handler::scim_handler;
use crate::state::AppState;
use axum::Router;
use axum::routing::get;
use std::sync::Arc;

/// /scim/v2/Users 路由组（Bearer 自校验）
pub fn public_scim_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/scim/v2/Users",
            get(scim_handler::list_users).post(scim_handler::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(scim_handler::get_user)
                .put(scim_handler::put_user)
                .patch(scim_handler::patch_user)
                .delete(scim_handler::delete_user),
        )
        // v5-D12：Groups 显式协议边界（501 + 语义说明；映射拍板后替换实现）
        .route(
            "/scim/v2/Groups",
            get(scim_handler::groups_not_implemented).post(scim_handler::groups_not_implemented),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(scim_handler::groups_not_implemented)
                .put(scim_handler::groups_not_implemented)
                .patch(scim_handler::groups_not_implemented)
                .delete(scim_handler::groups_not_implemented),
        )
        .with_state(state)
}
