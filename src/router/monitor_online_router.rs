//! 在线用户监控路由注册
//!
//! 路由结构：
//! - /monitor/online/list            — GET    查询在线用户列表（管理员）
//! - /monitor/online/{tokenHash}     — DELETE 强退用户（P1-19：参数从 tokenId 改为 tokenHash）
//! - /monitor/my-session/list        — GET    自助会话列表（v5-N5：仅登录，强制按当前用户过滤）
//! - /monitor/my-session/{tokenHash} — DELETE 自助注销本人会话（v5-N5：仅登录 + 属主校验）

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
        // v5-N5：普通用户自助「会话管理」（MySessionPanel 专用，仅登录白名单）
        .route(
            "/monitor/my-session/list",
            get(monitor_online_handler::my_session_list),
        )
        .route(
            "/monitor/my-session/{tokenHash}",
            delete(monitor_online_handler::my_session_logout),
        )
}
