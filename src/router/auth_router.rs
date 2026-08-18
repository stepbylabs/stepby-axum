// axum-backend/src/router/auth_router.rs
//! 认证路由（公开 + 受保护两层）
//!
//! 公开路由（免鉴权）：
//! - GET  /captchaImage
//! - GET  /login（嵌入模式下返回 SPA index.html，由前端 router 处理 /login 页面）
//! - POST /login（登录 API）
//! - GET  /register（嵌入模式下返回 SPA index.html）
//! - POST /register（注册 API）
//!
//! 受保护路由（需 auth_middleware）：
//! - POST /logout
//! - GET  /getInfo
//! - GET  /getRouters
//! - POST /unlockscreen
//!
//! 注意：auth_middleware 由 router/mod.rs 统一挂载到 protected 分组，
//! 此处仅返回 Router<Arc<AppState>>，不挂载中间件。
//!
//! 设计说明（嵌入式部署 SPA 路由冲突修复）：
//! - 前端 SPA 路由 /login 和 /register 与后端 POST API 路径冲突
//! - Axum 0.8 在路径匹配但 method 不匹配时返回 405，不走 fallback
//! - 解决方案：为这两个路径同时注册 GET handler 返回 index.html
//! - 非嵌入模式下，GET /login 和 /register 也会返回 index.html（无害，开发模式下前端独立部署时不走这里）

use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};

use crate::embedded_assets;
use crate::handler::auth_handler;
use crate::middleware::rate_limit::rate_limit_middleware;
use crate::state::AppState;

/// 公开认证路由（免鉴权，挂载限流中间件防止暴力破解 P0-59）
pub fn public_auth_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    // 嵌入模式下，/login 和 /register 同时注册 GET（返回 SPA index.html）和 POST（API）
    // 非嵌入模式下，仅注册 POST（保留原行为，开发模式前端独立部署时不走这里）
    let embedded = embedded_assets::is_embedded_mode();

    let login_method = if embedded {
        get(embedded_assets::serve_index).post(auth_handler::login)
    } else {
        post(auth_handler::login)
    };

    let register_method = if embedded {
        get(embedded_assets::serve_index).post(auth_handler::register)
    } else {
        post(auth_handler::register)
    };

    Router::new()
        .route("/captchaImage", get(auth_handler::captcha))
        .route("/login", login_method)
        .route("/register", register_method)
        // 限流中间件：per-IP 令牌桶（100 突发 / 10/s 补充），防止暴力登录与注册刷接口
        // 使用 from_fn_with_state 注入 state，复用 auth_handler 的可信代理白名单逻辑提取真实 IP
        .route_layer(from_fn_with_state(state, rate_limit_middleware))
}

/// 受保护认证路由（需 auth_middleware）
pub fn protected_auth_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/logout", post(auth_handler::logout))
        .route("/getInfo", get(auth_handler::get_info))
        .route("/getRouters", get(auth_handler::get_routers))
        .route("/unlockscreen", post(auth_handler::unlock_screen))
}
