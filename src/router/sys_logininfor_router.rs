//! 登录日志路由注册
//!
//! 路由结构：
//! - /monitor/logininfor/* — 登录日志（5 个接口）

use std::sync::Arc;
use axum::Router;
use axum::routing::{delete, get, post};

use crate::handler::sys_logininfor_handler;
use crate::state::AppState;

/// 登录日志路由
pub fn logininfor_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/monitor/logininfor/list", get(sys_logininfor_handler::list))
        .route("/monitor/logininfor/stats", get(sys_logininfor_handler::stats))
        .route("/monitor/logininfor/unlock/{userName}", post(sys_logininfor_handler::unlock))
        .route("/monitor/logininfor/{infoIds}", delete(sys_logininfor_handler::remove))
        .route("/monitor/logininfor/clean", delete(sys_logininfor_handler::clean))
        .route("/monitor/logininfor/export", post(sys_logininfor_handler::export))
}
