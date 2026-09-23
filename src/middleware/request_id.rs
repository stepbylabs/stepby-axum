// axum-backend/src/middleware/request_id.rs

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

/// 请求 ID（注入到 request extensions，供 handler 提取）
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// 请求 ID 中间件：为每个请求生成 UUID 并写入响应头 X-Request-Id
///
/// 优先复用入站 X-Request-Id 头（用于多服务链路追踪），缺失时生成新 UUID。
/// 同时将 request_id 注入 tracing span，使后续 handler/中间件的日志自动携带 request_id 字段（P2-10），
/// 便于通过日志关联同一请求的所有处理步骤。
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    // 优先复用入站 X-Request-Id（用于多服务链路追踪）
    // 校验长度（≤128）和字符集（字母/数字/连字符），防止日志注入和响应头注入
    let request_id = req
        .headers()
        .get("X-Request-Id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 128
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    req.extensions_mut().insert(RequestId(request_id.clone()));

    // 将 request_id 注入 tracing span，使后续 handler/中间件的日志自动携带 request_id 字段（P2-10）
    let span = tracing::info_span!("request", request_id = %request_id);
    let mut response = next.run(req).instrument(span).await;

    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("X-Request-Id", val);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use tower::ServiceExt;

    // 覆盖意图：
    // - RequestId 生成（缺失/非法入站头时回退 UUID）
    // - 合法入站头原样复用（链路追踪）
    // - 非法入站头（超长/含非法字符/空）被丢弃并生成新 ID
    // - 响应头 X-Request-Id 回写与 request extensions 传播（handler 可提取）

    fn app() -> Router {
        async fn handler(req: Request<Body>) -> (axum::http::HeaderMap, String) {
            let ext = req
                .extensions()
                .get::<RequestId>()
                .map(|r| r.0.clone())
                .unwrap_or_default();
            (axum::http::HeaderMap::new(), ext)
        }
        Router::new()
            .route("/", get(handler))
            .layer(axum::middleware::from_fn(request_id_middleware))
    }

    /// 发起请求并返回 (响应头, 响应体字符串)
    async fn call(req: Request<Body>) -> (axum::http::response::Parts, String) {
        let res = app().oneshot(req).await.unwrap();
        let (parts, body) = res.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        (parts, text)
    }

    fn valid_uuid(id: &str) -> bool {
        id.len() == 36 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }

    #[tokio::test]
    async fn test_generates_uuid_when_no_inbound_header() {
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let (parts, body) = call(req).await;
        assert_eq!(parts.status, StatusCode::OK);
        // 响应头已回写
        let rid = parts
            .headers
            .get("X-Request-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        assert!(valid_uuid(&rid), "应生成 UUID: {rid}");
        // extensions 与响应头一致（handler 从 extensions 读取到的值）
        assert_eq!(body, rid);
    }

    #[tokio::test]
    async fn test_reuses_valid_inbound_header() {
        let inbound = "trace-abc-123";
        let req = Request::builder()
            .uri("/")
            .header("X-Request-Id", inbound)
            .body(Body::empty())
            .unwrap();
        let (parts, body) = call(req).await;
        let rid = parts
            .headers
            .get("X-Request-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        assert_eq!(rid, inbound, "合法入站头应原样复用");
        assert_eq!(body, inbound);
    }

    #[tokio::test]
    async fn test_reuses_valid_inbound_header_with_digits_and_dash() {
        let inbound = "req-20260718-001";
        let req = Request::builder()
            .uri("/")
            .header("X-Request-Id", inbound)
            .body(Body::empty())
            .unwrap();
        let (parts, _body) = call(req).await;
        assert_eq!(
            parts.headers.get("X-Request-Id").unwrap().to_str().unwrap(),
            inbound
        );
    }

    #[tokio::test]
    async fn test_rejects_too_long_inbound_header() {
        let inbound = "x".repeat(129);
        let req = Request::builder()
            .uri("/")
            .header("X-Request-Id", &inbound)
            .body(Body::empty())
            .unwrap();
        let (parts, body) = call(req).await;
        let rid = parts
            .headers
            .get("X-Request-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        assert_ne!(rid, inbound, "超长入站头应被丢弃");
        assert!(valid_uuid(&rid), "应生成新 UUID");
        assert_eq!(body, rid);
    }

    #[tokio::test]
    async fn test_rejects_invalid_chars_inbound_header() {
        for bad in ["with space", "with\tspace", "with/unicode-中"] {
            let req = Request::builder()
                .uri("/")
                .header("X-Request-Id", bad)
                .body(Body::empty())
                .unwrap();
            let (parts, body) = call(req).await;
            let rid = parts
                .headers
                .get("X-Request-Id")
                .and_then(|v| v.to_str().ok())
                .unwrap()
                .to_string();
            assert_ne!(rid, bad, "含非法字符的入站头应被丢弃: {bad:?}");
            assert!(valid_uuid(&rid));
            assert_eq!(body, rid);
        }
    }

    #[tokio::test]
    async fn test_rejects_empty_inbound_header() {
        let req = Request::builder()
            .uri("/")
            .header("X-Request-Id", "")
            .body(Body::empty())
            .unwrap();
        let (parts, _body) = call(req).await;
        let rid = parts
            .headers
            .get("X-Request-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        assert!(valid_uuid(&rid), "空入站头应生成新 UUID");
    }

    #[tokio::test]
    async fn test_response_header_set_for_all_requests() {
        // 任何请求都应带 X-Request-Id 响应头
        let req = Request::builder()
            .uri("/")
            .header(header::ACCEPT, "application/json")
            .body(Body::empty())
            .unwrap();
        let (parts, _) = call(req).await;
        assert!(parts.headers.contains_key("X-Request-Id"));
    }
}
