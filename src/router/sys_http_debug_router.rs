//! 在线 HTTP 调试器路由注册
//!
//! 受保护路由（需 auth_middleware + permission_middleware）：
//! - POST /tool/http-debug/execute  服务端转发请求并返回调试结果（权限 tool:httpDebug:list）
//!
//! 多租户安全（§27.13.4 / 原则 B）：该接口由服务端代理发起任意请求（SSRF 面），
//! 属**平台专属**能力，挂 [`platform_only_guard`] 请求层守卫，租户操作者一律 403。

use axum::Router;
use axum::routing::post;
use std::sync::Arc;

use crate::handler::sys_http_debug_handler;
use crate::middleware::platform_guard::platform_only_guard;
use crate::state::AppState;

pub fn http_debug_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/tool/http-debug/execute",
            post(sys_http_debug_handler::execute),
        )
        .route_layer(axum::middleware::from_fn(platform_only_guard))
}
