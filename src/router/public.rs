// axum-backend/src/router/public.rs

use crate::handler;
use crate::handler::ws_handler;
use crate::router::auth_router;
use crate::state::AppState;
use axum::Router;
use axum::routing::get;
use std::sync::Arc;

/// 构建公开路由（免鉴权）
/// 含：/health、/metrics、/captchaImage、/login、/ws（WebSocket，query 参数鉴权）
pub fn public_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(handler::health))
        .route("/metrics", get(handler::metrics))
        // WebSocket 升级握手：通过 query 参数 token 鉴权（WS 无法使用 layer 中间件）
        .route("/ws", get(ws_handler::ws_handler))
        .merge(auth_router::public_auth_routes(state.clone()))
        .merge(crate::router::sys_oauth_router::public_oauth_routes(state))
}
