//! 可观测性监控路由注册
//!
//! 路由结构（与 middleware::permission 权限映射一致）：
//! - /monitor/slow-sql/list                — GET    慢请求列表（分页）
//! - /monitor/slow-sql/stats               — GET    慢请求聚合统计
//! - /monitor/slow-sql/clear               — DELETE 清空慢请求缓冲
//! - /monitor/error-log/list               — GET    错误日志列表（过滤 + 分页）
//! - /monitor/error-log/stats              — GET    错误聚合统计
//! - /monitor/error-log/clear              — DELETE 清空错误缓冲
//! - /monitor/redis/stats                  — GET    Redis 运行指标

use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get};

use crate::handler::monitor_observability_handler;
use crate::state::AppState;

/// 可观测性监控路由
pub fn observability_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/monitor/slow-sql/list",
            get(monitor_observability_handler::slow_sql_list),
        )
        .route(
            "/monitor/slow-sql/stats",
            get(monitor_observability_handler::slow_sql_stats),
        )
        .route(
            "/monitor/slow-sql/clear",
            delete(monitor_observability_handler::slow_sql_clear),
        )
        .route(
            "/monitor/error-log/list",
            get(monitor_observability_handler::error_log_list),
        )
        .route(
            "/monitor/error-log/stats",
            get(monitor_observability_handler::error_log_stats),
        )
        .route(
            "/monitor/error-log/clear",
            delete(monitor_observability_handler::error_log_clear),
        )
        .route(
            "/monitor/redis/stats",
            get(monitor_observability_handler::redis_stats),
        )
}
