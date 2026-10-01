// stepby-axum/src/router/sys_tenant_domain_router.rs
//! 租户域名管理模块路由注册（多租户 Phase 3 域名链路）
//!
//! 权限要求（通过 permission_middleware 集中配置，详见 middleware/permission.rs）：
//! - GET    /system/tenant/domain/list                 system:tenant:domain:list
//! - POST   /system/tenant/domain                      system:tenant:domain:add
//! - POST   /system/tenant/domain/verify/{domainId}    system:tenant:domain:verify
//! - PUT    /system/tenant/domain/primary              system:tenant:domain:edit
//! - PUT    /system/tenant/domain/changeStatus         system:tenant:domain:edit
//! - DELETE /system/tenant/domain/{domainId}           system:tenant:domain:remove
//!
//! 注：服务层另行强制「写操作仅平台操作者」，权限标识是 RBAC 之外的第二道闸门。

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_tenant_domain_handler;
use crate::state::AppState;

/// 租户域名模块路由（需挂在鉴权中间件下）
pub fn tenant_domain_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/system/tenant/domain/list",
            get(sys_tenant_domain_handler::list),
        )
        .route(
            "/system/tenant/domain",
            post(sys_tenant_domain_handler::add),
        )
        .route(
            "/system/tenant/domain/verify/{domainId}",
            post(sys_tenant_domain_handler::verify),
        )
        .route(
            "/system/tenant/domain/primary",
            put(sys_tenant_domain_handler::set_primary),
        )
        .route(
            "/system/tenant/domain/changeStatus",
            put(sys_tenant_domain_handler::change_status),
        )
        .route(
            "/system/tenant/domain/{domainId}",
            delete(sys_tenant_domain_handler::remove),
        )
}
