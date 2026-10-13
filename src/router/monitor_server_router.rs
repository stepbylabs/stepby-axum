//! 服务器监控路由注册
//!
//! 路由结构：
//! - /monitor/server  — GET 获取服务器信息
//! - /monitor/db-pool — GET 获取数据库连接池统计（方言/池连接数/繁忙数/最大连接数）
//!
//! 多租户安全（§27.13.4 / 原则 B）：主机指标（CPU/内存/磁盘/JVM）无租户语义且
//! 属平台运维面，挂 [`platform_only_guard`] 请求层守卫，租户操作者一律 403。
//! 数据库连接池统计同属平台运维面（池状态无租户语义），沿用同一守卫。

use std::sync::Arc;

use axum::Router;
use axum::routing::get;

use crate::handler::monitor_server_handler;
use crate::middleware::platform_guard::platform_only_guard;
use crate::state::AppState;

/// 服务器监控路由（平台专属）
pub fn server_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/monitor/server", get(monitor_server_handler::get_server))
        .route("/monitor/db-pool", get(monitor_server_handler::get_db_pool))
        .route_layer(axum::middleware::from_fn(platform_only_guard))
}
