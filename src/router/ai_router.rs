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
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::state::AppState;

pub fn ai_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ai/chat", post(handler::chat))
        .route("/ai/tables", get(handler::tables))
        // AI-01：运行时配置管理（平台专属，handler 内 tenant_id==0 门控）
        .route("/system/aiConfig", get(handler::get_config))
        .route("/system/aiConfig", put(handler::update_config))
        .route("/system/aiConfig/test", post(handler::test_config))
        // AI-02：查询历史（本人=ai:chat 自查；管理视图=monitor:aiHistory:list）
        .route("/system/ai/history", get(handler::list_my_history))
        .route("/system/ai/history/admin", get(handler::list_admin_history))
        .route("/system/ai/history/{id}", delete(handler::remove_my_history))
        // AI-02 决策 2：重放本人历史（SQL 重新过守卫）
        .route("/ai/replay", post(handler::replay))
}
