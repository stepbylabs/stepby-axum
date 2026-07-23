//! 服务器监控路由注册
//!
//! 路由结构：
//! - /monitor/server — GET 获取服务器信息

use std::sync::Arc;

use axum::Router;
use axum::routing::get;

use crate::handler::monitor_server_handler;
use crate::state::AppState;

/// 服务器监控路由
pub fn server_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/monitor/server", get(monitor_server_handler::get_server))
}
