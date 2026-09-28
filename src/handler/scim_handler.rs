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
#[utoipa::path(
    get,
    path = "/scim/v2/Users",
    responses(
        (status = 200, description = "SCIM ListResponse（用户列表）", body = serde_json::Value),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用"),
    ),
    security(()),
    tag = "scim"
)]
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
#[utoipa::path(
    get,
    path = "/scim/v2/Users/{id}",
    params(("id" = i64, Path, description = "用户 ID")),
    responses(
        (status = 200, description = "SCIM 用户资源", body = serde_json::Value),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用或用户不存在"),
    ),
    security(()),
    tag = "scim"
)]
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
#[utoipa::path(
    post,
    path = "/scim/v2/Users",
    request_body = serde_json::Value,
    responses(
        (status = 201, description = "创建成功（SCIM 用户资源）", body = serde_json::Value),
        (status = 400, description = "SCIM 请求体非法"),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用"),
    ),
    security(()),
    tag = "scim"
)]
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
        Ok(resp) => {
            // v5-D12：provision 事件（火后即忘；无订阅时无副作用）
            state.web_hook_service.dispatch_event(
                crate::service::sys_web_hook_service::EVENT_SCIM_USER_PROVISIONED,
                serde_json::json!({
                    "id": resp.id,
                    "userName": resp.user_name,
                    "externalId": resp.external_id,
                    "displayName": resp.name.display_name,
                }),
                state.config.scim.tenant_id,
            );
            (
                StatusCode::CREATED,
                Json(serde_json::to_value(resp).unwrap()),
            )
                .into_response()
        }
        Err(e) => scim_error_response_for_app(e),
    }
}

/// PUT /scim/v2/Users/{id}
#[utoipa::path(
    put,
    path = "/scim/v2/Users/{id}",
    params(("id" = i64, Path, description = "用户 ID")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "更新成功（SCIM 用户资源）", body = serde_json::Value),
        (status = 400, description = "SCIM 请求体非法"),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用或用户不存在"),
    ),
    security(()),
    tag = "scim"
)]
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
#[utoipa::path(
    patch,
    path = "/scim/v2/Users/{id}",
    params(("id" = i64, Path, description = "用户 ID")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "更新成功（SCIM 用户资源）", body = serde_json::Value),
        (status = 400, description = "SCIM 请求体非法"),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用或用户不存在"),
    ),
    security(()),
    tag = "scim"
)]
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
/// v5-D12 Group：deprovision 联动——清理组成员记录 + 撤 scim 来源授权/兼职
/// （admin 手授保留；见 scim_group_service::cleanup_user_membership）。
#[utoipa::path(
    delete,
    path = "/scim/v2/Users/{id}",
    params(("id" = i64, Path, description = "用户 ID")),
    responses(
        (status = 204, description = "停用成功（无响应体）"),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用或用户不存在"),
    ),
    security(()),
    tag = "scim"
)]
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    // deprovision 事件需要 userName——先读取（404 时直接返回错误响应）
    let base = base_url_of(&headers);
    let user = match state.scim_service.get_user(id, &base).await {
        Ok(u) => u,
        Err(e) => return scim_error_response_for_app(e),
    };
    match state.scim_service.delete_user(id).await {
        Ok(()) => {
            // v5-D12 Group：成员记录 + scim 来源授权联动清理（失败不阻断停用主流程）
            if let Err(e) = state.scim_group_service.cleanup_user_membership(id).await {
                tracing::warn!("SCIM deprovision 成员清理失败 user_id={id}: {}", e.detail);
            }
            // v5-D12：deprovision 事件（火后即忘）
            state.web_hook_service.dispatch_event(
                crate::service::sys_web_hook_service::EVENT_SCIM_USER_DEACTIVATED,
                serde_json::json!({
                    "id": user.id,
                    "userName": user.user_name,
                    "externalId": user.external_id,
                }),
                state.config.scim.tenant_id,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => scim_error_response_for_app(e),
    }
}

// ==================== Groups（v5-D12 Group：RFC 7644 §4.2 真实现） ====================

/// GET /scim/v2/Groups?startIndex=&count=&filter=
#[utoipa::path(
    get,
    path = "/scim/v2/Groups",
    responses(
        (status = 200, description = "SCIM ListResponse（组列表）", body = serde_json::Value),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用"),
    ),
    security(()),
    tag = "scim"
)]
pub async fn list_groups(
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
        .scim_group_service
        .list_groups(start_index, count, filter, &base)
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => scim_error_response_for_app(e),
    }
}

/// GET /scim/v2/Groups/{id}
#[utoipa::path(
    get,
    path = "/scim/v2/Groups/{id}",
    params(("id" = i64, Path, description = "组 ID")),
    responses(
        (status = 200, description = "SCIM 组资源", body = serde_json::Value),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用或组不存在"),
    ),
    security(()),
    tag = "scim"
)]
pub async fn get_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    let base = base_url_of(&headers);
    match state.scim_group_service.get_group(id, &base).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => scim_error_response_for_app(e),
    }
}

/// POST /scim/v2/Groups（provision：建组 + 成员 + role 组联动授权）
#[utoipa::path(
    post,
    path = "/scim/v2/Groups",
    request_body = serde_json::Value,
    responses(
        (status = 201, description = "创建成功（SCIM 组资源）", body = serde_json::Value),
        (status = 400, description = "SCIM 请求体非法"),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用"),
    ),
    security(()),
    tag = "scim"
)]
pub async fn create_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    let base = base_url_of(&headers);
    match state.scim_group_service.create_group(&body, &base).await {
        Ok(resp) => {
            state.web_hook_service.dispatch_event(
                crate::service::sys_web_hook_service::EVENT_SCIM_GROUP_PROVISIONED,
                serde_json::json!({
                    "id": resp.id,
                    "displayName": resp.display_name,
                    "externalId": resp.external_id,
                    "memberCount": resp.members.len(),
                }),
                state.config.scim.tenant_id,
            );
            (
                StatusCode::CREATED,
                Json(serde_json::to_value(resp).unwrap()),
            )
                .into_response()
        }
        Err(e) => scim_error_response_for_app(e),
    }
}

/// PUT /scim/v2/Groups/{id}（displayName + members 全量 diff，幂等）
#[utoipa::path(
    put,
    path = "/scim/v2/Groups/{id}",
    params(("id" = i64, Path, description = "组 ID")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "更新成功（SCIM 组资源）", body = serde_json::Value),
        (status = 400, description = "SCIM 请求体非法"),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用或组不存在"),
    ),
    security(()),
    tag = "scim"
)]
pub async fn put_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    let base = base_url_of(&headers);
    match state.scim_group_service.put_group(id, &body, &base).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => scim_error_response_for_app(e),
    }
}

/// PATCH /scim/v2/Groups/{id}（add/remove members、replace displayName/members）
#[utoipa::path(
    patch,
    path = "/scim/v2/Groups/{id}",
    params(("id" = i64, Path, description = "组 ID")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "更新成功（SCIM 组资源）", body = serde_json::Value),
        (status = 400, description = "SCIM 请求体非法"),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用或组不存在"),
    ),
    security(()),
    tag = "scim"
)]
pub async fn patch_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    let base = base_url_of(&headers);
    match state.scim_group_service.patch_group(id, &body, &base).await {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => scim_error_response_for_app(e),
    }
}

/// DELETE /scim/v2/Groups/{id}（软删 + 撤仅本组 source 的授权/兼职，204）
#[utoipa::path(
    delete,
    path = "/scim/v2/Groups/{id}",
    params(("id" = i64, Path, description = "组 ID")),
    responses(
        (status = 204, description = "删除成功（无响应体）"),
        (status = 401, description = "SCIM Bearer 凭据无效"),
        (status = 404, description = "SCIM 未启用或组不存在"),
    ),
    security(()),
    tag = "scim"
)]
pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(resp) = check_access(&state, &headers) {
        return resp;
    }
    let base = base_url_of(&headers);
    let group = match state.scim_group_service.get_group(id, &base).await {
        Ok(g) => g,
        Err(e) => return scim_error_response_for_app(e),
    };
    match state.scim_group_service.delete_group(id).await {
        Ok(()) => {
            state.web_hook_service.dispatch_event(
                crate::service::sys_web_hook_service::EVENT_SCIM_GROUP_DELETED,
                serde_json::json!({
                    "id": group.id,
                    "displayName": group.display_name,
                    "externalId": group.external_id,
                }),
                state.config.scim.tenant_id,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => scim_error_response_for_app(e),
    }
}
