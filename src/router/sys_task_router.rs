//! 任务进度中心路由注册
//!
//! 路由结构：
//! - /system/task/* — 任务进度（3 个接口）

use axum::Router;
use axum::routing::get;
use std::sync::Arc;

use crate::handler::sys_task_handler;
use crate::state::AppState;

/// 任务进度路由
pub fn task_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/system/task/list", get(sys_task_handler::list))
        // b71 契约审计：GET 详情零前端调用（同路径 DELETE 在用），保留 REST 完整性 → router/mod.rs 清单 ①
        .route(
            "/system/task/{taskId}",
            get(sys_task_handler::get_info).delete(sys_task_handler::remove),
        )
}
