// backend-axum/src/router/sys_job_router.rs
//! 定时任务路由注册
//!
//! 路由结构：
//! - /monitor/job/* — 任务管理（8 个接口）
//! - /monitor/jobLog/* — 任务日志（4 个接口）

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::{sys_job_handler, sys_job_log_handler};
use crate::state::AppState;

/// 定时任务 + 任务日志路由
pub fn job_routes() -> Router<Arc<AppState>> {
    Router::new()
        // ===== 任务管理 =====
        .route("/monitor/job/list", get(sys_job_handler::list))
        .route("/monitor/job/{jobId}", get(sys_job_handler::get_info_by_id))
        .route("/monitor/job", post(sys_job_handler::add))
        .route("/monitor/job", put(sys_job_handler::edit))
        .route("/monitor/job/{jobId}", delete(sys_job_handler::remove))
        .route(
            "/monitor/job/changeStatus",
            put(sys_job_handler::change_status),
        )
        .route("/monitor/job/run", put(sys_job_handler::run))
        .route("/monitor/job/export", post(sys_job_handler::export))
        // ===== 任务日志 =====
        .route("/monitor/jobLog/list", get(sys_job_log_handler::list))
        .route(
            "/monitor/jobLog/{jobLogIds}",
            delete(sys_job_log_handler::remove),
        )
        .route("/monitor/jobLog/clean", delete(sys_job_log_handler::clean))
        .route("/monitor/jobLog/export", post(sys_job_log_handler::export))
}
