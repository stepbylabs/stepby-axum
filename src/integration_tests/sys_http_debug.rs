//! 在线 HTTP 调试器（/tool/http-debug/execute）集成测试：
//! 覆盖确定性分支（不依赖外网可达性的稳定路径）：
//! - 不支持的方法（TRACE）→ 400
//! - 非法/缺主机名 URL → 400
//! - SSRF 阻断目标（127.0.0.1 / localhost / 保留地址）→ 400
//! - 合法但不可路由的外部目标 → HTTP 200 + `error` 字段（传输层失败）
//!
//! 注意：execute 的出站成功需要可达的外部 HTTP 服务（CI 不可靠），故仅覆盖上述确定性分支。

use super::TestContext;
use axum::http::{Method, StatusCode};

/// 不支持的方法（TRACE 不在白名单）→ HTTP 400。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_http_debug_rejects_unsupported_method() {
    let ctx = TestContext::new().await;
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/tool/http-debug/execute",
            Some(serde_json::json!({
                "method": "TRACE",
                "url": "https://example.com/"
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "TRACE 方法应返回 400，实际: HTTP {status} body={v}"
    );
    assert_ne!(v["code"], 200, "业务码不应为 200，实际: {v}");
}

/// 非法 URL（无 scheme）与缺主机名 URL（http://）→ HTTP 400。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_http_debug_rejects_invalid_url() {
    let ctx = TestContext::new().await;

    // 无 scheme 的相对文本，url::Url::parse 直接失败
    let bad_inputs = [
        serde_json::json!({"method": "GET", "url": "notaurl"}),
        serde_json::json!({"method": "GET", "url": "http://"}),
        serde_json::json!({"method": "GET", "url": ""}),
    ];
    for body in bad_inputs {
        let (status, v) = ctx
            .send_raw(ctx.request(Method::POST, "/tool/http-debug/execute", Some(body)))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "非法 URL 应返回 400，实际: HTTP {status} body={v}"
        );
        assert_ne!(v["code"], 200, "业务码不应为 200，实际: {v}");
    }
}

/// SSRF 阻断目标，静态层直接拒绝 → HTTP 400：
/// 127.0.0.1（环回 IP）、localhost（保留主机名）、198.18.0.1（基准测试段）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_http_debug_rejects_ssrf_targets() {
    let ctx = TestContext::new().await;

    let targets = [
        "http://127.0.0.1:1/",
        "http://localhost/",
        "http://10.0.0.1/",
        "http://169.254.169.254/",
        "http://198.18.0.1/",
    ];
    for url in targets {
        let (status, v) = ctx
            .send_raw(ctx.request(
                Method::POST,
                "/tool/http-debug/execute",
                Some(serde_json::json!({
                    "method": "GET",
                    "url": url,
                })),
            ))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "SSRF 目标 {url} 应返回 400，实际: HTTP {status} body={v}"
        );
        assert_ne!(v["code"], 200, "SSRF 目标业务码不应为 200，实际: {v}");
    }
}

/// 合法但不可路由的外部目标（8.8.8.8:1 端口 1 无可监听、出站被拒/超时）：
/// SSRF 静态+动态层放行后连接失败，Service 以 200 + `error` 字段返回（status=0）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_http_debug_external_transport_failure_returns_200_with_error() {
    let ctx = TestContext::new().await;
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/tool/http-debug/execute",
            Some(serde_json::json!({
                "method": "GET",
                "url": "http://8.8.8.8:1/",
                "timeoutSecs": 2
            })),
        ))
        .await;
    // 传输层失败不产生 HTTP 4xx/5xx，而是 200 携带 error 字段
    assert_eq!(
        status,
        StatusCode::OK,
        "传输层失败应返回 HTTP 200，实际: HTTP {status} body={v}"
    );
    assert_eq!(v["code"], 200, "业务码应为 200，实际: {v}");
    let data = &v["data"];
    assert_eq!(data["status"], 0, "传输层失败 status 应为 0，实际: {data}");
    assert!(
        data["error"].is_string(),
        "传输层失败应携带 error 字符串字段，实际: {data}"
    );
}
