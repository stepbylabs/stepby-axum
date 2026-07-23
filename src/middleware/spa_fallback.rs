// axum-backend/src/middleware/spa_fallback.rs
//! SPA fallback 中间件
//!
//! 解决问题：部分前端 Vue Router 路径与后端 API 路径完全重叠
//! （例如 GET /monitor/cache、GET /monitor/server 既有 API handler 又是 SPA 页面路径）。
//! 当浏览器直接访问这些路径时（地址栏输入、刷新、外链跳转），axum 会匹配到 API handler，
//! auth_middleware 返回 401 JSON，前端 SPA 无法加载。
//!
//! 解决方案：检测浏览器导航请求（Sec-Fetch-Mode: navigate）且未携带 token 时，
//! 直接返回 SPA HTML（开发模式从文件系统读取，生产模式从嵌入资源读取），
//! 由前端路由接管。这样：
//! - 浏览器导航 GET /monitor/cache → 返回 SPA HTML（前端路由渲染页面）
//! - API 请求 GET /monitor/cache（fetch/XHR，Sec-Fetch-Mode: cors，带 Authorization）→ 走 auth_middleware
//!
//! 安全性：Sec-Fetch-Mode 由浏览器自动设置，无法在 JavaScript 中伪造（Fetch Metadata Request Headers），
//! 攻击者无法通过伪造此 header 绕过鉴权获取 API JSON 响应（此中间件仅返回 SPA HTML，不返回 API 数据）。
//!
//! 双模式支持：此中间件在开发模式（ServeDir）和生产模式（rust-embed）下均生效，
//! 通过 `embedded_assets::serve_spa()` 统一入口自动切换。

use axum::extract::Request;
use axum::http::header::{ACCEPT, AUTHORIZATION};
use axum::http::HeaderName;
use axum::middleware::Next;
use axum::response::Response;

use crate::embedded_assets;

/// Sec-Fetch-Mode header name（http crate 未内置常量，需手动声明）
///
/// Fetch Metadata Request Headers 规范：https://developer.mozilla.org/en-US/docs/Glossary/Fetch_metadata_request_header
/// 浏览器自动设置，JavaScript 无法伪造。
const SEC_FETCH_MODE: HeaderName = HeaderName::from_static("sec-fetch-mode");

/// 判断是否为浏览器导航请求
///
/// 浏览器地址栏输入、刷新、外链跳转等导航请求会携带 `Sec-Fetch-Mode: navigate`。
/// 此 header 由浏览器自动设置，JavaScript 无法伪造（Fetch Metadata API）。
fn is_browser_navigation(req: &Request) -> bool {
    // 1. Sec-Fetch-Mode: navigate（最可靠标识）
    let sec_fetch_mode = req
        .headers()
        .get(&SEC_FETCH_MODE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if sec_fetch_mode.eq_ignore_ascii_case("navigate") {
        return true;
    }

    // 2. 兜底：Accept 包含 text/html 且不含 application/json
    //    用于不支持 Sec-Fetch-Mode 的老浏览器（IE 等）
    let accept = req
        .headers()
        .get(&ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    accept.contains("text/html") && !accept.contains("application/json")
}

/// SPA fallback 中间件
///
/// 仅在以下条件全部满足时介入：
/// 1. 请求未携带 Authorization header（已登录的浏览器导航请求走正常鉴权）
/// 2. 请求为浏览器导航（Sec-Fetch-Mode: navigate 或 Accept: text/html）
///
/// 满足条件时直接返回 SPA HTML，不调用 next。
/// 否则放行让后续中间件（auth_middleware）处理。
///
/// 注意：此中间件在开发模式（ServeDir）和生产模式（rust-embed）下均生效，
/// 通过 `serve_spa()` 统一入口自动切换读取源。
pub async fn spa_fallback_middleware(req: Request, next: Next) -> Response {
    // 已携带 Authorization header 的请求走正常鉴权（API 请求或已登录的 SPA 资源请求）
    if req.headers().get(&AUTHORIZATION).is_some() {
        return next.run(req).await;
    }

    // 检测浏览器导航请求
    if is_browser_navigation(&req) {
        let path = req.uri().path().to_string();
        tracing::debug!(path = %path, "spa_fallback_middleware 拦截浏览器导航请求，返回 SPA HTML");
        // 返回 SPA HTML，前端路由接管（serve_spa 自动根据编译模式切换读取源）
        return embedded_assets::serve_spa(req).await;
    }

    // 非浏览器导航请求（API、静态资源等）走正常流程
    next.run(req).await
}
