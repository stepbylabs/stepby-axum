// stepby-axum/src/router/scim_router.rs
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
        // v5-D12 Group：Groups 真实现（RFC 7644 §4.2——组→角色集合 / 组→兼职部门
        // 双映射联动，替换原 501 显式边界）
        .route(
            "/scim/v2/Groups",
            get(scim_handler::list_groups).post(scim_handler::create_group),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(scim_handler::get_group)
                .put(scim_handler::put_group)
                .patch(scim_handler::patch_group)
                .delete(scim_handler::delete_group),
        )
        .with_state(state)
}
