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
