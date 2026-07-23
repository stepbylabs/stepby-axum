//! 任务进度中心路由注册
//!
//! 路由结构：
//! - /system/task/* — 任务进度（3 个接口）

use std::sync::Arc;
use axum::Router;
use axum::routing::get;

use crate::handler::sys_task_handler;
use crate::state::AppState;

/// 任务进度路由
pub fn task_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/system/task/list", get(sys_task_handler::list))
        .route("/system/task/{taskId}", get(sys_task_handler::get_info).delete(sys_task_handler::remove))
}
