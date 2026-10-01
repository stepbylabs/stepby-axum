//! 操作日志路由注册
//!
//! 路由结构：
//! - /monitor/operlog/* — 操作日志（4 个接口）

use axum::Router;
use axum::routing::{delete, get, post};
use std::sync::Arc;

use crate::handler::sys_oper_log_handler;
use crate::state::AppState;

/// 操作日志路由
pub fn oper_log_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/monitor/operlog/list", get(sys_oper_log_handler::list))
        .route("/monitor/operlog/stats", get(sys_oper_log_handler::stats))
        .route(
            "/monitor/operlog/stats-by-type",
            get(sys_oper_log_handler::stats_by_type),
        )
        .route(
            "/monitor/operlog/alarm-status",
            get(sys_oper_log_handler::alarm_status),
        )
        .route(
            "/monitor/operlog/compliance-report",
            get(sys_oper_log_handler::compliance_report),
        )
        .route(
            "/monitor/operlog/{operIds}",
            delete(sys_oper_log_handler::remove),
        )
        .route(
            "/monitor/operlog/clean",
            delete(sys_oper_log_handler::clean),
        )
        .route(
            "/monitor/operlog/export",
            post(sys_oper_log_handler::export),
        )
}
