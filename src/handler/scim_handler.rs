// axum-backend/src/handler/scim_handler.rs
//! v5-D12：SCIM 2.0 端点（/scim/v2/Users，RFC 7644 最小可用子集）。
//!
//! 鉴权：独立 Bearer Token（`scim.bearer_token`，IdP 服务器对服务器凭据，
//! 与用户 JWT 无关）。constant-time 比较 token 哈希防时序侧信道。
//! 禁用（scim.enabled=false）时全部端点 404（不暴露存在性）。
//!
//! 错误模型：SCIM 使用 RFC 7644 自有错误 JSON（status/detail），**不走全局 AppError**——
//! 所有失败都直接构造为 HTTP Response 返回，因此 handler 返回 `Response` 而非
//! `Result<Response, AppError>`（编译修复：Response 无法 Into<AppError>）。

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;

use crate::service::scim_service::ScimError;
use crate::state::AppState;

/// Bearer 校验 + 禁用短路。返回 Ok(()) 表示通过；Err 为已构造好的 SCIM 错误 Response。
/// （clippy result_large_err：Err 携带完整 Response 属有意设计——SCIM 错误体自成协议，不经 AppError）
#[allow(clippy::result_large_err)]
fn check_access(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if !state.config.scim.enabled {
        return Err((StatusCode::NOT_FOUND, Json(json!({}))).into_response());
    }
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    let expected_hash = crate::utils::crypto::token_hash(state.config.scim.bearer_token.trim());
    let presented_hash = crate::utils::crypto::token_hash(presented);
    if presented.is_empty()
        || state.config.scim.bearer_token.trim().is_empty()
        || !constant_time_eq(&presented_hash, &expected_hash)
    {
        return Err(scim_error_response(
            401,
            ScimError::new(401, "无效的 SCIM 凭据"),
        ));
    }
    Ok(())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn scim_error_response(status: u16, e: ScimError) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (code, Json(serde_json::to_value(e).unwrap())).into_response()
}

/// 尊重 ScimError 自带的 HTTP status（字符串形式，解析失败回退 500）
fn scim_error_response_for_app(e: ScimError) -> Response {
    let status = e.status.parse::<u16>().unwrap_or(500);
    scim_error_response(status, e)
}

fn base_url_of(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| format!("http://{h}"))
        .unwrap_or_default()
}

/// GET /scim/v2/Users?startIndex=&count=&filter=
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    let base = base_url_of(&headers);
    let start_index = q
        .get("startIndex")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let count = q.get("count").and_then(|v| v.parse().ok()).unwrap_or(100);
    let filter = q.get("filter").map(String::as_str);
    match state
        .scim_service
        .list_users(start_index, count, filter, &base)
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => scim_error_response_for_app(e),
    }
}

/// GET /scim/v2/Users/{id}
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    let base = base_url_of(&headers);
    match state.scim_service.get_user(id, &base).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => scim_error_response_for_app(e),
    }
}

/// POST /scim/v2/Users
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    let base = base_url_of(&headers);
    match state.scim_service.create_user(&body, &base).await {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(resp).unwrap()),
        )
            .into_response(),
        Err(e) => scim_error_response_for_app(e),
    }
}

/// PUT /scim/v2/Users/{id}
pub async fn put_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    let base = base_url_of(&headers);
    match state.scim_service.put_user(id, &body, &base).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => scim_error_response_for_app(e),
    }
}

/// PATCH /scim/v2/Users/{id}
pub async fn patch_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    let base = base_url_of(&headers);
    match state.scim_service.patch_user(id, &body, &base).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => scim_error_response_for_app(e),
    }
}

/// DELETE /scim/v2/Users/{id}（deprovision = 停用，204）
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    match state.scim_service.delete_user(id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => scim_error_response_for_app(e),
    }
}
