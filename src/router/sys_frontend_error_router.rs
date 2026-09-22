//! 前端异常与性能监控路由注册
//!
//! 路由结构：
//! - /monitor/frontendError/* — 前端异常（report / list / 详情 / 删除 / 清空 / 统计）

use axum::Router;
use axum::routing::{delete, get, post};
use std::sync::Arc;

use crate::handler::sys_frontend_error_handler;
use crate::state::AppState;

/// 前端异常路由
pub fn frontend_error_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/monitor/frontendError/report",
            post(sys_frontend_error_handler::report),
        )
        .route(
            "/monitor/frontendError/list",
            get(sys_frontend_error_handler::list),
        )
        .route(
            "/monitor/frontendError/stats",
            get(sys_frontend_error_handler::stats),
        )
        .route(
            "/monitor/frontendError/clean",
            delete(sys_frontend_error_handler::clean),
        )
        .route(
            "/monitor/frontendError/{id}",
            get(sys_frontend_error_handler::info).delete(sys_frontend_error_handler::remove),
        )
}
