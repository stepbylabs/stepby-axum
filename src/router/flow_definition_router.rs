// stepby-axum/src/router/flow_definition_router.rs
//! 流程定义模块路由（G-02 M1；需挂在鉴权中间件下）

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::flow_definition_handler;
use crate::state::AppState;

pub fn flow_definition_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/system/flow/definition/list",
            get(flow_definition_handler::definition_list),
        )
        .route(
            "/system/flow/definition/publish/{flowId}",
            post(flow_definition_handler::definition_publish),
        )
        .route(
            // 删除段按 GET 段命名（{flowId}）避免 axum 0.8 同位置不同参数名构建期冲突
            "/system/flow/definition/{flowId}",
            delete(flow_definition_handler::definition_remove),
        )
        .route(
            "/system/flow/definition/{flowId}",
            get(flow_definition_handler::definition_info),
        )
        .route(
            "/system/flow/definition",
            post(flow_definition_handler::definition_add),
        )
        .route(
            "/system/flow/definition",
            put(flow_definition_handler::definition_edit),
        )
}
