// stepby-axum/src/middleware/op_recording.rs
//! 操作录制采集中间件（`X-Record-Into: <recordingId>`）。
//!
//! ## 挂载位置（顺序即判据）
//!
//! 本中间件是 `route_layer` 链的**最内层**（即最先注册的那一条），因此它跑在
//! auth / permission / oper_log 之后、handler 之前。两个理由：
//! 1. 需要 `Claims`（租户、用户）——排在最外层时扩展里还是空的，只能自己再验一次令牌；
//! 2. 需要 `tool:recording:record` 的授权结论——自己查一遍权限表会与中间件形成两把尺。
//!
//! ## 默认零成本
//!
//! 没有 `X-Record-Into` 头时只做一次 header 查找就 `next.run(req)`，**不进 body 读取路径**。
//! 这一点是硬要求：本中间件挂在所有受保护路由上，任何"每个请求都读一遍 body"的实现都会
//! 让全站吞吐减半。
//!
//! ## 为什么要缓冲 body 再放回
//!
//! axum 的 `Json<T>` 提取器会 `into_parts` 消费 body。采集必须在 handler 之前把字节读出来，
//! 再把同一份字节塞回新请求里；不缓冲就只能录到空 body（回放发出空请求，等于录了个寂寞）。
//! 读取上限 [`MAX_CAPTURED_BODY_BYTES`]（与存储上限同源），超限**不录取**并计入
//! `outcome=body_too_large`——把 20 MB 的上传体读进内存换一条录不进去的步骤，不划算。
//!
//! ## 采集是异步的，且失败不外溢
//!
//! DB 写在 `spawn_tracked` 里做：采集失败不能让**用户这次操作**失败（他本来只是在正常
//! 干活，录不上是我们的问题）。失败留 WARN + `outcome=error` 计数，可归因、不静默。

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::common::error::AppError;
use crate::service::op_recording::{
    CaptureDecision, MAX_CAPTURED_BODY_BYTES, MAX_CAPTURED_QUERY_BYTES, decide_capture,
    filter_headers, redact_json_like, redact_query, truncate_body, truncate_bytes,
};
use crate::state::AppState;

/// 采集开关请求头（大小写无关）
pub const RECORD_HEADER: &str = "x-record-into";

/// 采集所需权限（与迁移里 `BTN_RECORD_ID` 的 perms 一致）
pub const RECORD_PERM: &str = "tool:recording:record";

/// 需要读取 body 的方法（其余方法即便带了开关也不采集，见 `decide_capture`）
fn method_has_body(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

/// 内容类型是否可采集（二进制内容存进文本列既无意义也不可回放）
fn content_type_capturable(ct: Option<&str>) -> bool {
    let Some(ct) = ct else {
        return true; // 无 Content-Type 的表单体（传统 x-www-form-urlencoded 常省略）
    };
    let lower = ct.to_ascii_lowercase();
    // multipart 一定带 boundary，二进制段无法按文本回放；octet-stream 同理
    !(lower.starts_with("multipart/") || lower.starts_with("application/octet-stream"))
}

pub async fn op_recording_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let raw = req
        .headers()
        .get(RECORD_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty());

    let Some(raw) = raw else {
        return next.run(req).await;
    };

    // 开关写错必须显式失败：静默不录 = 用户以为录上了，回放时才发现缺步
    let recording_id: i64 = match raw.parse() {
        Ok(v) if v > 0 => v,
        _ => {
            metrics().record_recording("capture", "bad_recording_id");
            return AppError::bad_request("X-Record-Into 必须是正整数录制 ID").into_response();
        }
    };

    let Some(claims) = req.extensions().get::<crate::jwt::Claims>().cloned() else {
        // 理论上不可达（auth 在更外层）；按 401 处理而不是放行
        metrics().record_recording("capture", "unauthenticated");
        return AppError::unauthorized("未认证的录制请求").into_response();
    };
    let tenant_id = claims.tid;
    let user_id = match claims.sub.parse::<i64>() {
        Ok(v) => v,
        Err(_) => {
            metrics().record_recording("capture", "malformed_subject");
            return AppError::unauthorized("令牌用户标识非法").into_response();
        }
    };

    // 授权：与路由权限表同源（工作台读取的是同一份权限集合）
    match state.menu_service.get_permissions_by_user_id(user_id).await {
        Ok(perms) => {
            let is_super = perms.iter().any(|p| p == "*:*:*");
            if !is_super && !perms.iter().any(|p| p == RECORD_PERM) {
                metrics().record_recording("capture", "forbidden");
                return AppError::forbidden("缺少操作录制采集权限（tool:recording:record）")
                    .into_response();
            }
        }
        Err(e) => {
            // fail-closed：查不出权限就不采集，但**不影响业务请求**（录制是旁路）
            tracing::warn!(error = %e, "录制采集：权限查询失败，本次不采集");
            metrics().record_recording("capture", "perm_unavailable");
            return next.run(req).await;
        }
    }

    let method = req.method().as_str().to_ascii_uppercase();
    let path = crate::middleware::normalize_api_prefix(req.uri().path()).to_string();
    let query = req
        .uri()
        .query()
        .map(|q| truncate_bytes(&redact_query(q), MAX_CAPTURED_QUERY_BYTES).0);

    // 先取抬头（需要 step_count 判定是否已满，也需要校验租户归属）
    let recording = match state
        .op_recording_service
        .repo()
        .find_by_id(recording_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            metrics().record_recording("capture", "recording_not_found");
            return AppError::not_found("录制不存在").into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, recording_id, "录制采集：读取录制失败");
            metrics().record_recording("capture", "error");
            return next.run(req).await;
        }
    };
    if recording.tenant_id != tenant_id {
        // 跨租户写入必须显式拒绝（不是"静默不录"——那会让攻击者以为成功）
        metrics().record_recording("capture", "cross_tenant");
        return AppError::forbidden("不能把操作录进其它租户的录制").into_response();
    }

    let decision = decide_capture(&method, &path, recording.step_count);
    if decision != CaptureDecision::Capture {
        metrics().record_recording("capture", decision.outcome());
        return next.run(req).await;
    }
    if recording.status == "archived" {
        metrics().record_recording("capture", "archived");
        return AppError::bad_request("已归档的录制不再接收新步骤").into_response();
    }

    // 只有需要 body 的方法才去读（GET 已经被 decide_capture 判掉，这里是双保险）
    if !method_has_body(&method) {
        metrics().record_recording("capture", "not_mutating");
        return next.run(req).await;
    }

    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if !content_type_capturable(content_type.as_deref()) {
        metrics().record_recording("capture", "binary_body");
        return next.run(req).await;
    }

    let headers_json = {
        let map = filter_headers(
            req.headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string())),
        );
        if map.is_empty() {
            None
        } else {
            serde_json::to_string(&map).ok()
        }
    };

    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_CAPTURED_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            // 超过上限或读取失败：**不录取**，但请求本身要能继续。
            // 这里无法把已消费的 body 还原，因此宁可让这次请求失败也不静默吞掉——
            // 走 413 让调用方看到"体太大且你开了录制"，而不是收到一个空 body 的 200。
            metrics().record_recording("capture", "body_too_large");
            return AppError::new(
                413,
                "请求体超过录制采集上限（64 KiB），请关闭 X-Record-Into 后重试",
            )
            .into_response();
        }
    };
    let req = Request::from_parts(parts, axum::body::Body::from(bytes.clone()));

    // 采集：异步写库，不影响本次响应时延
    {
        let body_text = String::from_utf8_lossy(&bytes).to_string();
        let (stored, _truncated) = truncate_body(&redact_json_like(&body_text));
        let capture = CapturePayload {
            recording_id,
            tenant_id,
            method: method.clone(),
            path: path.clone(),
            query_string: query.clone(),
            content_type: content_type.clone(),
            body: if stored.trim().is_empty() {
                None
            } else {
                Some(stored)
            },
            headers_json,
        };
        let state_bg = state.clone();
        crate::common::background::spawn_tracked(
            "op_recording_capture",
            crate::common::background::LIGHT_DB_BUDGET,
            Some(crate::observability::metrics::MetricsRegistry::global()),
            async move {
                match state_bg
                    .op_recording_service
                    .capture_step(
                        capture.recording_id,
                        capture.tenant_id,
                        &capture.method,
                        &capture.path,
                        capture.query_string,
                        capture.content_type,
                        capture.body,
                        capture.headers_json,
                        crate::common::datetime::now_naive(),
                    )
                    .await
                {
                    Ok(step) => {
                        metrics().record_recording("capture", "recorded");
                        tracing::debug!(
                            recording_id = capture.recording_id,
                            seq = step.seq,
                            path = %capture.path,
                            "操作已录进录制"
                        );
                    }
                    Err(e) => {
                        metrics().record_recording("capture", "error");
                        tracing::warn!(
                            recording_id = capture.recording_id,
                            error = %e,
                            "录制采集写库失败（业务请求不受影响）"
                        );
                    }
                }
            },
        );
    }

    next.run(req).await
}

/// 采集载荷（分离出来是为了让后台闭包只捕获必要字段）
struct CapturePayload {
    recording_id: i64,
    tenant_id: i64,
    method: String,
    path: String,
    query_string: Option<String>,
    content_type: Option<String>,
    body: Option<String>,
    headers_json: Option<String>,
}

fn metrics() -> Arc<crate::observability::metrics::MetricsRegistry> {
    crate::observability::metrics::MetricsRegistry::global()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_content_types_are_not_captured() {
        assert!(!content_type_capturable(Some(
            "multipart/form-data; boundary=x"
        )));
        assert!(!content_type_capturable(Some("application/octet-stream")));
        assert!(content_type_capturable(Some("application/json")));
        assert!(content_type_capturable(Some(
            "application/x-www-form-urlencoded"
        )));
        assert!(
            content_type_capturable(None),
            "无 Content-Type 的表单体必须可采集（否则传统表单流程整段录不上）"
        );
    }

    #[test]
    fn body_methods_are_exactly_the_mutating_four() {
        for m in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(method_has_body(m), "{m} 需要读取 body");
        }
        for m in ["GET", "HEAD", "OPTIONS"] {
            assert!(!method_has_body(m), "{m} 不得进入 body 读取路径");
        }
    }
}
