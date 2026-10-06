// stepby-axum/src/middleware/request_id.rs

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

/// 请求 ID（注入到 request extensions，供 handler 提取）
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

// G-13a：当前请求的 request_id（task-local 传播）
//
// 背景：错误响应出口 [`crate::common::error::AppError::into_response`] 拿不到
// request 上下文（Extensions 在那里已不可达），无法把 request_id 填进
// `body.trace_id`。axum/tower 中间件链与 handler 在同一 tokio task 上逐层
// await，故用 `task_local` 作用域传播是零依赖且语义精确的通道：
// - handler 正常/错误返回路径都在 scope 内，读取恒成功；
// - 脱离请求上下文（后台任务/定时器）读取失败 → `try_with` 返回 Err，
//   调用方按"无 trace_id"处理（skip 序列化），不会误填。
tokio::task_local! {
    pub static CURRENT_REQUEST_ID: String;
}

/// 请求 ID 中间件：为每个请求生成 UUID 并写入响应头 X-Request-Id
///
/// 优先复用入站 X-Request-Id 头（用于多服务链路追踪），缺失时生成新 UUID。
/// 同时将 request_id 注入 tracing span，使后续 handler/中间件的日志自动携带 request_id 字段（P2-10），
/// 便于通过日志关联同一请求的所有处理步骤。
/// G-13a：并注入 task-local 作用域，供错误响应出口读取（`body.trace_id`）。
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
    // G-13a：task-local scope 与 tracing instrument 同一 future 叠加，
    // handler 及其内部（含 AppError::into_response）均可读取当前 request_id
    let mut response = CURRENT_REQUEST_ID
        .scope(request_id.clone(), next.run(req).instrument(span))
        .await;

    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("X-Request-Id", val);
    }
    response
}

/// 读取当前请求的 request_id（G-13a）
///
/// 返回 `None` 表示当前不在请求作用域内（后台任务/测试直调等场景），
/// 调用方应跳过 trace_id 填充（而非编造值）。
pub fn current_request_id() -> Option<String> {
    CURRENT_REQUEST_ID
        .try_with(|id| id.clone())
        .ok()
        .filter(|s| !s.is_empty())
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

    /// G-13a：错误响应 body 必须携带与响应头同源的 trace_id
    /// （task-local 传播 → AppError::into_response 填充），报障即可凭该 ID grep 日志。
    #[tokio::test]
    async fn test_error_body_carries_trace_id_matching_header() {
        use crate::common::{AjaxResult, AppError};

        async fn failing_handler() -> Result<AjaxResult<()>, AppError> {
            Err(AppError::internal("boom"))
        }
        let app = Router::new()
            .route("/fail", get(failing_handler))
            .layer(axum::middleware::from_fn(request_id_middleware));

        let res = app
            .oneshot(Request::builder().uri("/fail").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = res.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let header_id = parts
            .headers
            .get("X-Request-Id")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        assert_eq!(
            json.get("trace_id").and_then(|v| v.as_str()),
            Some(header_id.as_str()),
            "body.trace_id 必须与响应头 X-Request-Id 同值"
        );
        assert_eq!(json.get("code").and_then(|v| v.as_i64()), Some(500));
    }

    /// G-13a：成功响应**不得**输出 trace_id 字段（skip_serializing_if 兼容口径）
    #[tokio::test]
    async fn test_success_body_omits_trace_id() {
        use crate::common::{AjaxResult, AppError};

        async fn ok_handler() -> Result<AjaxResult<&'static str>, AppError> {
            Ok(AjaxResult::success("ok"))
        }
        let app = Router::new()
            .route("/ok", get(ok_handler))
            .layer(axum::middleware::from_fn(request_id_middleware));

        let res = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.get("trace_id").is_none(), "成功响应不应输出 trace_id");
    }

    /// G-13a：非请求作用域内（后台任务）读取 request_id 必须返回 None，不得编造值
    #[tokio::test]
    async fn test_current_request_id_none_outside_scope() {
        assert!(current_request_id().is_none());
        CURRENT_REQUEST_ID
            .scope("scoped-id".to_string(), async {
                assert_eq!(current_request_id().as_deref(), Some("scoped-id"));
            })
            .await;
    }
}
