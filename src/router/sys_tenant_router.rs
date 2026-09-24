// axum-backend/src/router/sys_tenant_router.rs
//! 租户管理模块路由注册（多租户 Phase 2 立项实施）
//!
//! 权限要求（通过 permission_middleware 集中配置，详见 middleware/permission.rs）：
//! - GET    /system/tenant/list         system:tenant:list
//! - GET    /system/tenant/{deptId}     system:tenant:query
//! - POST   /system/tenant              system:tenant:add
//! - PUT    /system/tenant              system:tenant:edit
//! - PUT    /system/tenant/changeStatus system:tenant:edit
//! - DELETE /system/tenant/{deptId}     system:tenant:remove

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_tenant_handler;
use crate::state::AppState;

/// 租户模块路由（需挂在鉴权中间件下）
pub fn tenant_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/system/tenant/list", get(sys_tenant_handler::list))
        .route("/system/tenant", post(sys_tenant_handler::add))
        .route("/system/tenant", put(sys_tenant_handler::edit))
        .route(
            "/system/tenant/changeStatus",
            put(sys_tenant_handler::change_status),
        )
        .route(
            "/system/tenant/{deptId}",
            delete(sys_tenant_handler::remove),
        )
        .route("/system/tenant/{deptId}", get(sys_tenant_handler::get_info))
}
