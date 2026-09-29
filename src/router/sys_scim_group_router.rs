// backend-axum/src/router/sys_scim_group_router.rs
//! v5-D12 Group：SCIM 组管理端路由（JWT 鉴权中间件下）

use axum::Router;
use axum::routing::get;
use std::sync::Arc;

use crate::handler::sys_scim_group_handler;
use crate::state::AppState;

/// SCIM 组管理路由（需挂在鉴权中间件下）
pub fn scim_group_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET /system/scimGroup/list 分页查询
        .route("/system/scimGroup/list", get(sys_scim_group_handler::list))
        // GET /system/scimGroup/{id} 详情
        .route(
            "/system/scimGroup/{id}",
            get(sys_scim_group_handler::get_info)
                .put(sys_scim_group_handler::edit)
                .delete(sys_scim_group_handler::remove),
        )
}
