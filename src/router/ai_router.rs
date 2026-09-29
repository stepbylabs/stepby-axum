//! AI 助手路由（NL2SQL v4.1）
//!
//! - POST /ai/chat   自然语言问数据（ai:chat，能力位 ai.copilot + [ai].enabled 双门控）
//! - GET  /ai/tables  可查询的白名单表 schema（ai:chat）
//!
//! 权限映射见 `middleware/permission.rs`（`("/POST", "/ai/chat", "ai:chat")`），
//! fail-closed 中间件强制校验；能力位与平台开关在 handler 内三重校验。
//! handler 位于 `src/ai/handler.rs`（与 service 同模块，便于共享类型）。

use crate::ai::handler;
use axum::Router;
use axum::routing::{get, post};
use std::sync::Arc;

use crate::state::AppState;

pub fn ai_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ai/chat", post(handler::chat))
        .route("/ai/tables", get(handler::tables))
}
