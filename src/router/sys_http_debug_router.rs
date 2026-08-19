//! 在线 HTTP 调试器路由注册
//!
//! 受保护路由（需 auth_middleware + permission_middleware）：
//! - POST /tool/http-debug/execute  服务端转发请求并返回调试结果（权限 tool:httpDebug:list）

use axum::Router;
use axum::routing::post;
use std::sync::Arc;

use crate::handler::sys_http_debug_handler;
use crate::state::AppState;

pub fn http_debug_routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/tool/http-debug/execute",
        post(sys_http_debug_handler::execute),
    )
}
