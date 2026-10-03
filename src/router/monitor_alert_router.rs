// stepby-axum/src/router/monitor_alert_router.rs
//! 告警规则模块路由注册
//!
//! 路由结构：
//! - /monitor/alert/list                分页查询（monitor:alert:list）
//! - /monitor/alert/export              导出 Excel（monitor:alert:list）
//! - /monitor/alert/changeEnabled       启停切换（monitor:alert:edit）
//! - /monitor/alert                     新增/修改（monitor:alert:add / monitor:alert:edit）
//! - /monitor/alert/{id}                详情（GET，monitor:alert:query）
//! - /monitor/alert/{id}/evaluate       手动评估（POST，monitor:alert:edit）
//! - /monitor/alert/{id}                批量删除（DELETE，monitor:alert:remove）
//!
//! 注意：静态路由（list、export、changeEnabled）需在动态路由 {id} 之前注册，
//! axum 0.8 优先匹配静态段；`/monitor/alert/{id}/evaluate` 为两段动态路径，
//! 与 `/monitor/alert/{id}` 不冲突。
//!
//! 多租户安全：告警规则为平台运维面（sys_alert_rule 无 tenant_id 列，指标为
//! 全局口径），整组 `/monitor/alert/*` 挂 [`platform_only_guard`]
//! （租户操作者一律 403），与 `/monitor/*` 其余平台监控面同口径。

use axum::Router;
use axum::routing::{get, post, put};
use std::sync::Arc;

use crate::handler::monitor_alert_handler;
use crate::middleware::platform_guard::platform_only_guard;
use crate::state::AppState;

/// 告警规则模块路由（平台专属，租户操作者 403）
pub fn monitor_alert_routes() -> Router<Arc<AppState>> {
    Router::new()
        // 静态路由优先注册
        .route("/monitor/alert/list", get(monitor_alert_handler::list))
        .route(
            "/monitor/alert/export",
            post(monitor_alert_handler::export),
        )
        .route(
            "/monitor/alert/changeEnabled",
            put(monitor_alert_handler::change_enabled),
        )
        // 集合资源
        .route("/monitor/alert", post(monitor_alert_handler::add))
        .route("/monitor/alert", put(monitor_alert_handler::edit))
        // 动态路由最后注册：GET（详情）/ DELETE（删除）共用 {id}；
        // POST {id}/evaluate 为独立子资源路径
        .route(
            "/monitor/alert/{id}",
            get(monitor_alert_handler::get_info).delete(monitor_alert_handler::remove),
        )
        .route(
            "/monitor/alert/{id}/evaluate",
            post(monitor_alert_handler::evaluate),
        )
        .route_layer(axum::middleware::from_fn(platform_only_guard))
}
