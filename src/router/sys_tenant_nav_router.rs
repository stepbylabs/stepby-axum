// axum-backend/src/router/sys_tenant_nav_router.rs
//! 租户自建导航 L3 模块路由注册（批次 3 / MT-1）
//!
//! 权限要求（通过 permission_middleware 集中配置，详见 middleware/permission.rs）：
//! - GET    /system/tenant/menu/list      system:tenantMenu:list
//! - GET    /system/tenant/menu/options   system:tenantMenu:list
//! - POST   /system/tenant/menu           system:tenantMenu:add
//! - PUT    /system/tenant/menu           system:tenantMenu:edit
//! - DELETE /system/tenant/menu/{l3Id}    system:tenantMenu:remove
//!
//! 注：`system:tenantMenu:` 属平台专属前缀（默认不得授予租户角色），仅由能力位
//! `nav.l3` 按档位逐条解锁（注册表 `governance::Item::unlocked`）；服务层再按 `NavScope`
//! 做能力位分档守卫与行级租户收窄——RBAC 之外的第二、三道闸门。

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_tenant_nav_handler;
use crate::state::AppState;

/// 租户自建导航模块路由（需挂在鉴权中间件下）
pub fn tenant_nav_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/system/tenant/menu/list",
            get(sys_tenant_nav_handler::list),
        )
        .route(
            "/system/tenant/menu/options",
            get(sys_tenant_nav_handler::options),
        )
        .route("/system/tenant/menu", post(sys_tenant_nav_handler::add))
        .route("/system/tenant/menu", put(sys_tenant_nav_handler::edit))
        .route(
            "/system/tenant/menu/{l3Id}",
            delete(sys_tenant_nav_handler::remove),
        )
}
