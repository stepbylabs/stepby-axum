// stepby-axum/src/integration_tests/http_contract.rs
//! 边界层错误契约（b143）：提取器拒绝 + 路由兜底。
//!
//! 立项缺陷（真机取证）：
//! - `GET /system/user/list?pageNum=abc`、`GET /system/user/abc`、畸形 JSON、
//!   缺 Content-Type、multipart 缺 boundary —— axum 提取器拒绝一律回 `text/plain`
//!   英文内部措辞，绕过 C.8（`body.code` + `body.msg` + HTTP 状态映射 + `trace_id`）；
//! - 同源嵌入部署下根挂载点的兜底是**无条件** `serve_spa`：`GET /system/__nope__`
//!   与 `PATCH /system/user/list` 都回 `index.html` + 200 —— API/XHR 消费者拿到的
//!   是一张 HTML 冒充的成功响应（前端 `data.code` 读出 undefined ⇒ 按空数据渲染）。
//!
//! 本文件钉三件事，缺一即"修了但没接线"：
//! 1. 分离模式的兜底（404/405）已是 JSON 契约；
//! 2. 嵌入模式的兜底按"是否浏览器导航"三分派：导航 → SPA HTML（深链能力不回归）、
//!    真实静态资源 → 照发、其余 → JSON 404/405；
//! 3. 提取器拒绝经全局中间件改写成同一契约，且 `trace_id` 与响应头 `X-Request-Id` 同源同值。
//!
//! 覆盖口径说明：413（请求体超限）由 `middleware::extractor_contract::tests` 的迷你
//! 路由用 `DefaultBodyLimit::max(8)` 覆盖 —— 真机上要发 10MB 体才触发，而那一条记录的
//! 只是同一中间件对 `PAYLOAD_TOO_LARGE` 的分支，与真实路由的差别仅在阈值数值。
//!
//! 环境前提：嵌入模式的导航/静态资源两支需要 `frontend-dist/` 存在 —— 这与
//! `middleware::spa_fallback` 既有单测同一条假设（本仓工作区常态成立）。

use super::TestContext;
use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use std::net::SocketAddr;
use tower::ServiceExt;

/// 固定入站追踪号：断言响应体 `trace_id` 与响应头 `X-Request-Id` 都等于它
/// （`request_id_middleware` 复用合法入站头）。
const TRACE_ID: &str = "b143-it-trace";

fn build(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-request-id", TRACE_ID)
        .header("authorization", format!("Bearer {}", ctx.token));
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let mut req = b.body(Body::from(body.to_vec())).expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.expect("请求执行失败");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取响应体失败");
    (status, headers, body.to_vec())
}

fn header(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn is_json(headers: &HeaderMap) -> bool {
    header(headers, "content-type").starts_with("application/json")
}

/// 统一契约断言：HTTP 状态 == `body.code`、`msg` 是本地化文案且与预期一致、
/// `trace_id` 与响应头同源同值、边界层拒绝不带 `data`。
fn assert_contract(
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    expected_msg: &str,
) -> serde_json::Value {
    assert!(
        is_json(headers),
        "边界层拒绝必须是 JSON，实际 content-type={:?}，body={}",
        header(headers, "content-type"),
        String::from_utf8_lossy(body)
    );
    assert_eq!(
        header(headers, "x-request-id"),
        TRACE_ID,
        "响应头应回写入站追踪号"
    );
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_else(|e| {
        panic!(
            "响应体应是 JSON: {e}\nbody={}",
            String::from_utf8_lossy(body)
        )
    });
    assert_eq!(
        v["code"],
        status.as_u16() as i64,
        "body.code 必须等于 HTTP 状态（C.8）；实际 status={status}, body={v}"
    );
    assert_eq!(v["msg"], expected_msg, "文案必须是 i18n 本地化结果");
    assert_eq!(
        v["trace_id"], TRACE_ID,
        "错误体 trace_id 必须与响应头同源同值（b124 口径）"
    );
    assert!(v.get("data").is_none(), "边界层拒绝不应带 data 载荷：{v}");
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_extractor_rejections_follow_the_json_contract() {
    let ctx = TestContext::new().await;
    let app = ctx.app.clone();
    let parse_failed = crate::tr!("error.common.parse_failed");
    let media_type = crate::tr!("error.common.unsupported_media_type");

    // ① 查询串类型不匹配（真实受保护端点）
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::GET,
            "/system/user/list?pageNum=abc",
            &[("accept", "application/json")],
            b"",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "查询串类型错误应为 400");
    assert_contract(s, &h, &b, &parse_failed);

    // ② 路径段类型不匹配
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::GET,
            "/system/user/abc",
            &[("accept", "application/json")],
            b"",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "路径段类型错误应为 400");
    assert_contract(s, &h, &b, &parse_failed);

    // ③ 畸形 JSON（公开端点，证明中间件不依赖鉴权链）
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::POST,
            "/login",
            &[("content-type", "application/json")],
            br#"{"username":"#,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "畸形 JSON 应为 400");
    assert_contract(s, &h, &b, &parse_failed);

    // ④ 缺 Content-Type（axum 默认 415 + text/plain）
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::POST,
            "/login",
            &[("content-type", "text/plain")],
            b"x",
        ),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "内容类型不符应为 415"
    );
    assert_contract(s, &h, &b, &media_type);

    // ⑤ multipart 缺 boundary（multer::Error::NoBoundary → 400）
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::POST,
            "/common/upload",
            &[("content-type", "multipart/form-data")],
            b"",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "multipart 缺 boundary 应为 400");
    assert_contract(s, &h, &b, &parse_failed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_split_mode_fallbacks_follow_the_json_contract() {
    let ctx = TestContext::new().await;
    // 显式取分离模式：本仓 `.env` 里 `EMBEDDED_FRONTEND=true`，`build_app` 在本进程
    // 组装出的默认 app 走的是嵌入分支 ⇒ 不显式传 false 的话，这一条会与下一条测同一档，
    // 分离模式的 404/405 分支就没人看着（判据自欺的常见形态）。
    let app = crate::router::build_app_with_embedded_mode(ctx.state.clone(), false);

    // 未知路径
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::GET,
            "/system/__b143_nope__",
            &[("accept", "application/json")],
            b"",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_contract(s, &h, &b, &crate::tr!("error.common.route_not_found"));

    // 路径命中、方法不匹配（分离模式此前是 axum 默认 text/plain 405）
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::PATCH,
            "/system/user/list",
            &[("accept", "application/json")],
            b"",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
    assert_contract(s, &h, &b, &crate::tr!("error.common.method_not_allowed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_embedded_fallback_separates_navigation_from_api() {
    let ctx = TestContext::new().await;
    // 同一份 build_app 代码，仅显式传入嵌入模式（debug 测试进程默认是分离模式）
    let app = crate::router::build_app_with_embedded_mode(ctx.state.clone(), true);
    let route_not_found = crate::tr!("error.common.route_not_found");
    let method_not_allowed = crate::tr!("error.common.method_not_allowed");

    // ① 未知路径 + XHR：Accept 同时含 text/html 也**不算导航**（XHR 兜底场景），必须 JSON 404
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::GET,
            "/system/__b143_nope__",
            &[("accept", "text/html,application/json")],
            b"",
        ),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "XHR 请求未知路径不得再拿到 HTML 200（改造前的缺陷形态）"
    );
    assert_contract(s, &h, &b, &route_not_found);

    // ② 未知路径 + 浏览器导航：深链能力不得回归，仍回 SPA HTML
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::GET,
            "/system/__b143_nope__",
            &[("sec-fetch-mode", "navigate")],
            b"",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "浏览器导航未匹配路径应回 SPA 页面");
    assert!(
        header(&h, "content-type").starts_with("text/html"),
        "导航应命中 index.html，实际 content-type={}",
        header(&h, "content-type")
    );
    let html = String::from_utf8_lossy(&b).to_lowercase();
    assert!(
        html.contains("<html") && html.contains("id=\"app\""),
        "导航应回前端入口页（含 <html> 与 #app 挂载点），实际前 200 字符={}",
        String::from_utf8_lossy(&b[..b.len().min(200)])
    );

    // ③ 方法不匹配 + XHR：JSON 405（改造前是兜底 serve_spa 的 HTML 200）
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::PATCH,
            "/system/user/list",
            &[("accept", "application/json")],
            b"",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::METHOD_NOT_ALLOWED);
    assert_contract(s, &h, &b, &method_not_allowed);

    // ④ 方法不匹配 + 浏览器导航：仍回 SPA（用户直接访问 POST-only 页面路径的前端路由）
    let (s, h, _b) = call(
        &app,
        build(
            &ctx,
            Method::PATCH,
            "/system/user/list",
            &[("sec-fetch-mode", "navigate")],
            b"",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        header(&h, "content-type").starts_with("text/html"),
        "导航应命中 index.html，实际 content-type={}",
        header(&h, "content-type")
    );

    // ⑤ 真实静态资源（非导航）由兜底照发：不得被"未知路径"逻辑误伤
    let (s, h, b) = call(
        &app,
        build(
            &ctx,
            Method::GET,
            "/favicon.ico",
            &[("accept", "image/*")],
            b"",
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "真实静态资源不得被判成未匹配路径");
    assert!(
        header(&h, "content-type").starts_with("image/"),
        "favicon 应带图片 MIME，实际 content-type={}",
        header(&h, "content-type")
    );
    assert!(!b.is_empty(), "favicon 应有内容");
}
