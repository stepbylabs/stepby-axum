// stepby-axum/src/audit/router.rs
//! 审计变更留痕路由注册（审计合规域独立路由，模块挂载见报告说明）
//!
//! 路由结构：
//! - /system/audit-change/* — 变更留痕（3 个接口）
//!
//! 集成说明：本路由器需在 `src/router/mod.rs` 的 `protected` 路由组内 merge
//! （挂载片段见任务报告），因 router/mod.rs 属本任务的禁改公共注册文件。

use axum::Router;
use axum::routing::get;
use std::sync::Arc;

use crate::audit::handler;
use crate::state::AppState;

/// 审计变更留痕路由
pub fn audit_change_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/system/audit-change/list",
            get(handler::list),
        )
        .route(
            "/system/audit-change/export",
            get(handler::export),
        )
        .route(
            "/system/audit-change/{id}",
            get(handler::get_info),
        )
}
