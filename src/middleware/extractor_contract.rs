//! 提取器拒绝的统一错误契约（b143）
//!
//! 立案事实（HEAD 实测）：axum 的 `Query` / `Path` / `Json` / `Form` / `Multipart`
//! 拒绝默认回 `text/plain` + 英文内部措辞，例如
//! - `Failed to deserialize query string: pageNum: invalid digit found in string`
//! - `Invalid URL: Cannot parse \`abc\` to a \`i64\``
//! - `Failed to parse the request body as JSON: key must be a string at line 1 column 2`
//!
//! 而缺 `Content-Type` 的 415 与超限的 413 同样如此。这些响应违反 C.8
//! （`body.code` + `body.msg` + 状态码映射），并把 serde/axum 的内部措辞、
//! 解析位置直接交给客户端。`ValidatedJson` / `ValidatedQuery` 早已各自映射成 JSON
//! 契约，但那只覆盖"带 garde 的 DTO"；SSO 的 `token` 端点也单独包了
//! `Result<Form<...>, FormRejection>`。本中间件把这件事收成**边界层唯一实现**：
//! 任何 400/413/415/422 的 `text/plain` 响应都在出口改写为统一契约，
//! 未来新增提取器自动获得同一语义。
//!
//! 刻意**不**改写 404/405：静态资源缺失（`text/plain` 404，如 `.map` 拒绝）
//! 是资产语义，不是 API 契约范畴；路由级 404/405 已由 router 的兜底分派产出 JSON。

use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

/// 被丢弃的原拒绝体上限——它只应含一行英文说明，超出部分不再读。
const DISCARDED_REJECTION_BODY_LIMIT: usize = 8 * 1024;

/// 把提取器拒绝改写成统一 JSON 契约（`body.code` = 真实 HTTP 状态 + 本地化 msg + trace_id）。
pub async fn extractor_contract_middleware(req: Request, next: Next) -> Response {
    let res = next.run(req).await;
    let status = res.status();
    if !matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
            | StatusCode::UNPROCESSABLE_ENTITY
    ) {
        return res;
    }
    let is_plain = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().to_ascii_lowercase().starts_with("text/plain"));
    if !is_plain {
        return res;
    }
    let msg = match status {
        StatusCode::PAYLOAD_TOO_LARGE => crate::tr!("error.common.payload_too_large"),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => crate::tr!("error.common.unsupported_media_type"),
        _ => crate::tr!("error.common.parse_failed"),
    };
    tracing::debug!(status = %status, "提取器拒绝已改写为统一 JSON 契约");
    // 原体是提取器内部措辞（含字段名与解析位置），不对外、也不进日志；
    // 有界读完丢弃，避免留下未消费的响应流。读失败只影响"丢弃"这个动作本身，
    // 但仍要留痕——静默吞掉会让"改写时响应流异常"从观测面消失。
    let (_parts, body) = res.into_parts();
    if let Err(e) = axum::body::to_bytes(body, DISCARDED_REJECTION_BODY_LIMIT).await {
        tracing::debug!(error = %e, "提取器拒绝体读取失败（已丢弃，不影响契约改写）");
    }
    crate::common::response::status_error(status, msg)
}

#[cfg(test)]
mod tests {
    //! 覆盖意图：五个提取器（Query / Path / Json 语法错 / Json 数据错 / 缺 Content-Type）
    //! 的拒绝全部变成 `body.code` == HTTP 状态 + 本地化 msg + `trace_id`；
    //! 而 200 text/plain 与 404 text/plain（静态资源语义）必须原样放行。
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::{DefaultBodyLimit, Path, Query};
    use axum::http::{HeaderMap, Request, header};
    use axum::middleware::from_fn;
    use axum::routing::{get, post};
    use serde::Deserialize;
    use tower::ServiceExt;

    #[derive(Debug, Deserialize)]
    struct StrictQuery {
        n: u64,
    }

    #[derive(Debug, Deserialize)]
    struct StrictBody {
        n: u64,
    }

    fn contract_app() -> Router {
        Router::new()
            .route(
                "/query",
                get(|Query(q): Query<StrictQuery>| async move { format!("query {}", q.n) }),
            )
            .route(
                "/path/{id}",
                get(|Path(id): Path<i64>| async move { format!("path {id}") }),
            )
            .route(
                "/json",
                post(
                    |axum::Json(b): axum::Json<StrictBody>| async move { format!("json {}", b.n) },
                ),
            )
            .route(
                "/small",
                post(
                    |axum::Json(b): axum::Json<StrictBody>| async move { format!("small {}", b.n) },
                )
                .layer(DefaultBodyLimit::max(8)),
            )
            .route("/plain-ok", get(|| async { (StatusCode::OK, "plain ok") }))
            .route(
                "/plain-404",
                get(|| async { (StatusCode::NOT_FOUND, "Not Found") }),
            )
            .layer(from_fn(extractor_contract_middleware))
            .layer(from_fn(crate::middleware::request_id_middleware))
    }

    async fn send(req: Request<Body>) -> (StatusCode, HeaderMap, serde_json::Value) {
        let resp = contract_app().oneshot(req).await.expect("请求执行失败");
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("读取响应体失败");
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, headers, json)
    }

    fn req(method: &str, uri: &str, content_type: Option<&str>, body: &str) -> Request<Body> {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-request-id", "b143trace");
        if let Some(ct) = content_type {
            b = b.header(header::CONTENT_TYPE, ct);
        }
        b.body(Body::from(body.to_string())).expect("构造请求失败")
    }

    fn assert_contract(
        status: StatusCode,
        headers: &HeaderMap,
        body: &serde_json::Value,
        expect_msg: &str,
    ) {
        assert_eq!(
            body["code"],
            status.as_u16() as i64,
            "body.code 必须等于 HTTP 状态"
        );
        assert_eq!(body["msg"], expect_msg);
        assert_eq!(
            body["trace_id"], "b143trace",
            "改写后的错误体必须带 trace_id（与响应头同源）"
        );
        assert_eq!(
            headers.get("x-request-id").and_then(|v| v.to_str().ok()),
            Some("b143trace")
        );
        let ct = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.starts_with("application/json"),
            "改写后的响应必须是 JSON，实际: {ct}"
        );
    }

    #[tokio::test]
    async fn query_rejection_is_rewritten() {
        let (status, headers, body) = send(req("GET", "/query?n=abc", None, "")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_contract(
            status,
            &headers,
            &body,
            &crate::tr!("error.common.parse_failed"),
        );
    }

    #[tokio::test]
    async fn path_rejection_is_rewritten() {
        let (status, headers, body) = send(req("GET", "/path/abc", None, "")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_contract(
            status,
            &headers,
            &body,
            &crate::tr!("error.common.parse_failed"),
        );
    }

    #[tokio::test]
    async fn malformed_json_is_rewritten() {
        let (status, headers, body) =
            send(req("POST", "/json", Some("application/json"), "{bad")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_contract(
            status,
            &headers,
            &body,
            &crate::tr!("error.common.parse_failed"),
        );
    }

    #[tokio::test]
    async fn json_data_error_keeps_422_with_contract_body() {
        let (status, headers, body) = send(req(
            "POST",
            "/json",
            Some("application/json"),
            r#"{"n":"x"}"#,
        ))
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_contract(
            status,
            &headers,
            &body,
            &crate::tr!("error.common.parse_failed"),
        );
    }

    #[tokio::test]
    async fn missing_content_type_is_rewritten_as_415() {
        let (status, headers, body) = send(req("POST", "/json", None, r#"{"n":1}"#)).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_contract(
            status,
            &headers,
            &body,
            &crate::tr!("error.common.unsupported_media_type"),
        );
    }

    #[tokio::test]
    async fn oversized_body_is_rewritten_as_413() {
        let (status, headers, body) = send(req(
            "POST",
            "/small",
            Some("application/json"),
            r#"{"n":123456789}"#,
        ))
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_contract(
            status,
            &headers,
            &body,
            &crate::tr!("error.common.payload_too_large"),
        );
    }

    #[tokio::test]
    async fn success_and_asset_404_are_left_untouched() {
        let (status, headers, body) = send(req("GET", "/plain-ok", None, "")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8"),
            "200 text/plain 不属于提取器拒绝，必须原样放行"
        );
        assert!(body.is_null(), "放行的响应体不应被改写为 JSON");

        let (status, headers, _) = send(req("GET", "/plain-404", None, "")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8"),
            "静态资源 404（text/plain）不是 API 契约，必须原样放行"
        );
    }

    /// 反脆弱：判据不是"凡是 text/plain 都改"——门只开在 400/413/415/422。
    #[tokio::test]
    async fn non_rejection_plain_responses_are_not_rewritten() {
        for path in ["/plain-ok", "/plain-404"] {
            let (_, headers, _) = send(req("GET", path, None, "")).await;
            let ct = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert!(
                ct.starts_with("text/plain"),
                "{path} 不得被改写，实际: {ct}"
            );
        }
    }
}
