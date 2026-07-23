//! 在线用户监控路由注册
//!
//! 路由结构：
//! - /monitor/online/list            — GET    查询在线用户列表
//! - /monitor/online/{tokenHash}     — DELETE 强退用户（P1-19：参数从 tokenId 改为 tokenHash）

use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get};

use crate::handler::monitor_online_handler;
use crate::state::AppState;

/// 在线用户监控路由
pub fn online_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/monitor/online/list", get(monitor_online_handler::list))
        .route(
            "/monitor/online/{tokenHash}",
            delete(monitor_online_handler::force_logout),
        )
}
