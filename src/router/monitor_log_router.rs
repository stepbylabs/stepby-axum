//! 实时系统日志监控路由注册
//!
//! 路由结构：
//! - /monitor/log/files — GET 列出日志目录下的应用日志文件
//! - /monitor/log/tail   — GET 读取指定日志文件尾部并过滤（级别/关键字）
//!
//! 多租户安全（§27.13.4 / 原则 B）：宿主应用日志为**平台专属**（含全平台请求/SQL 日志），
//! 挂 [`platform_only_guard`] 请求层守卫，租户操作者一律 403。

use std::sync::Arc;

use axum::Router;
use axum::routing::get;

use crate::handler::monitor_log_handler;
use crate::middleware::platform_guard::platform_only_guard;
use crate::state::AppState;

/// 实时日志监控路由（平台专属）
pub fn log_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/monitor/log/files", get(monitor_log_handler::files))
        .route("/monitor/log/tail", get(monitor_log_handler::tail))
        .route_layer(axum::middleware::from_fn(platform_only_guard))
}
