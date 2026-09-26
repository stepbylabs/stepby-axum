// axum-backend/src/router/flow_router.rs
//! 审批工作流路由（方案 B′）
//!
//! 挂载到 protected 子树。权限登记三处同步（V6-E2）：
//! 1. `PERM_ROUTE_TABLE`（management 视图 system:flow:list）
//! 2. `is_login_only_path`（个人数据接口）
//! 3. `PROTECTED_ROUTES` 测试清单（漏登记 = 测试假绿，运行时 403）

use axum::Router;
use axum::routing::{get, post};
use std::sync::Arc;

use crate::handler::flow_handler;
use crate::state::AppState;

pub fn flow_routes() -> Router<Arc<AppState>> {
    Router::new()
        // 个人数据（仅登录；归属校验在 service 层）
        .route("/system/flow/todo", get(flow_handler::todo))
        .route("/system/flow/mine", get(flow_handler::mine))
        .route("/system/flow/done", get(flow_handler::done))
        .route(
            "/system/flow/pending-count",
            get(flow_handler::pending_count),
        )
        .route("/system/flow/task/{taskId}", get(flow_handler::task_detail))
        .route("/system/flow/demo/submit", post(flow_handler::submit_demo))
        .route(
            "/system/flow/demo/{docId}/resubmit",
            post(flow_handler::resubmit_demo),
        )
        .route(
            "/system/flow/demo/{docId}/withdraw",
            post(flow_handler::withdraw_demo),
        )
        .route("/system/flow/task/{taskId}/action", post(flow_handler::act))
        // 加签：在当前节点追加会签审批人（W-3）
        .route(
            "/system/flow/task/{taskId}/countersign-add",
            post(flow_handler::countersign_add),
        )
        // 管理视图（权限键 system:flow:list）
        .route("/system/flow/list", get(flow_handler::list))
        // 导出（W-11）：与列表同权限键、同可见范围
        .route("/system/flow/export", post(flow_handler::export))
}
