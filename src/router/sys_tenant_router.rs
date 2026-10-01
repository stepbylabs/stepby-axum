// stepby-axum/src/router/sys_tenant_router.rs
//! 租户管理模块路由注册（多租户 Phase 3：主键 = `tenant_id`，事实源 = sys_tenant）
//!
//! 权限要求（通过 permission_middleware 集中配置，详见 middleware/permission.rs）：
//! - GET    /system/tenant/list                 system:tenant:list
//! - GET    /system/tenant/package/options      system:tenant:list（服务层再校验仅平台）
//! - GET    /system/tenant/package/{id}/features system:tenant:list（服务层再校验仅平台）
//! - PUT    /system/tenant/package/features     system:tenant:edit（服务层再校验仅平台）
//! - GET    /system/tenant/{tenantId}           system:tenant:query
//! - POST   /system/tenant                      system:tenant:add
//! - PUT    /system/tenant                      system:tenant:edit
//! - PUT    /system/tenant/changeStatus         system:tenant:edit
//! - DELETE /system/tenant/{tenantId}           system:tenant:remove
//! - PUT    /system/tenant/restore/{tenantId}   system:tenant:edit

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_tenant_handler;
use crate::state::AppState;

/// 租户模块路由（需挂在鉴权中间件下）
pub fn tenant_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/system/tenant/list", get(sys_tenant_handler::list))
        // 注：`/package/options` 两段路径不会与单段 `{tenantId}` 冲突；静态段注册在前更直观
        .route(
            "/system/tenant/package/options",
            get(sys_tenant_handler::package_options),
        )
        // 套餐能力位（三层开关的中间层；仅平台可配，服务层再校验）
        // 注：静态段 `package/features` 与 `package/{packageId}/features` 段数不同，不冲突
        .route(
            "/system/tenant/package/features",
            put(sys_tenant_handler::set_package_features),
        )
        .route(
            "/system/tenant/package/{packageId}/features",
            get(sys_tenant_handler::package_features),
        )
        .route("/system/tenant", post(sys_tenant_handler::add))
        .route("/system/tenant", put(sys_tenant_handler::edit))
        .route(
            "/system/tenant/changeStatus",
            put(sys_tenant_handler::change_status),
        )
        .route(
            "/system/tenant/restore/{tenantId}",
            put(sys_tenant_handler::restore),
        )
        .route(
            "/system/tenant/{tenantId}",
            delete(sys_tenant_handler::remove),
        )
        .route(
            "/system/tenant/{tenantId}",
            get(sys_tenant_handler::get_info),
        )
}
