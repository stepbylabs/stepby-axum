//! WebHook 事件目录 Handler（开放域，m20261003_000002_webhook_event）
//!
//! 接口路径对齐权限映射（PERM_ROUTE_TABLE）：
//! - GET  /system/webhook/event/list      事件目录分页（system:webhook:event:list）
//! - POST /system/webhook/{id}/test-send  按事件样例构造真实测试发送（system:webhook:test-send）
//!
//! 范式对齐 sys_web_hook_handler：Operator 取租户、AjaxResult/TableDataInfo 统一出参。

use std::sync::Arc;

use axum::extract::{Path, Query, State};

use crate::common::ValidatedJson;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::middleware::Operator;
use crate::service::sys_web_hook_service::{
    DeliveryResult, WebhookEventQueryDto, WebhookEventVo, WebhookTestSendDto,
};
use crate::state::AppState;

/// GET /system/webhook/event/list —— 事件目录分页查询
#[utoipa::path(
    get,
    path = "/system/webhook/event/list",
    params(WebhookEventQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<WebhookEventVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-webhook"
)]
pub async fn event_list(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Query(query): Query<WebhookEventQueryDto>,
) -> Result<TableDataInfo<WebhookEventVo>, AppError> {
    let (rows, total) = state.web_hook_service.list_events(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// POST /system/webhook/{id}/test-send —— 按事件目录构造真实测试发送
///
/// body `{ "eventKey": "user.created" }` → 以该事件的 payload_example 真实走出站投递
/// （含 HMAC 签名），返回投递结果并留痕 web_hook_log（source='test'）。
#[utoipa::path(
    post,
    path = "/system/webhook/{id}/test-send",
    params(("id" = i64, Path, description = "回调 ID")),
    request_body = WebhookTestSendDto,
    responses(
        (status = 200, description = "投递结果（含失败的真实结果）", body = AjaxResult<DeliveryResult>),
        (status = 400, description = "event_key 不在事件目录或参数错误"),
        (status = 404, description = "回调不存在"),
    ),
    tag = "monitor-webhook"
)]
pub async fn test_send(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(id): Path<i64>,
    ValidatedJson(dto): ValidatedJson<WebhookTestSendDto>,
) -> Result<AjaxResult<DeliveryResult>, AppError> {
    let result = state
        .web_hook_service
        .test_send(id, dto.event_key.trim(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(result))
}
