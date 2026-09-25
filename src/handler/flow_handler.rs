//! 审批工作流 Handler（Axum 原生实现）
//!
//! 接口路径（方案 B′，docs/optimization/topic-workflow-approval-final-2026-09-23.md）。
//!
//! 仅登录（个人数据，归属校验在 service 层）：
//!
//! - GET  /system/flow/todo — 我的待办
//! - GET  /system/flow/mine — 我发起的单据
//! - GET  /system/flow/pending-count — 待办数量（红点）
//! - GET  /system/flow/task/{taskId} — 任务详情 + 时间线
//! - POST /system/flow/demo/submit — 提交示例请假单并发起审批
//! - POST /system/flow/demo/{docId}/resubmit — 重新提交（round_no + 1）
//! - POST /system/flow/demo/{docId}/withdraw — 撤回（发起人，按单据维度）
//! - POST /system/flow/task/{taskId}/action — 审批动作（approve/reject/withdraw/transfer）
//!
//! 权限键（管理视图）：
//!
//! - GET /system/flow/list — 全部单据（system:flow:list）
//!
//! 安全：写动作一律拒绝 PAT 会话（V7-E1 方案 S）；归属校验在 service 层（V2-P0-4）。
//! 通知：service 返回待通知列表，由本 handler 执行 WS 定向 + 站内审计（分层约束，V7-E2）。

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::IntoResponse;

use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::entity::flow_demo_doc::Model as FlowDemoDocModel;
use crate::entity::sys_flow_task::Model as SysFlowTaskModel;
use crate::middleware::Operator;
use crate::service::sys_flow_service::{FlowActionDto, FlowPageQuery, FlowSubmitDto};
use crate::state::AppState;

/// 解析 Operator 携带的 user_id（JWT sub，字符串）为 i64
fn parse_user_id(sub: &str) -> Result<i64, AppError> {
    sub.parse::<i64>()
        .map_err(|_| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))
}

/// WS 定向推送"新待办"（严禁全局广播：待办含他人单据标题，V4-V4E5）
fn ws_notify_todo(state: &AppState, assignee_id: i64, title: &str) {
    state.broadcast_to_user(
        assignee_id,
        "flowTodo",
        serde_json::json!({
            "bizType": crate::service::sys_flow_service::BIZ_TYPE_DEMO,
            "title": title,
            "message": crate::tr!("msg.flow.todo_created"),
        }),
    );
}

/// WS 定向推送"已办结"给申请人
fn ws_notify_finished(state: &AppState, applicant_id: i64, status: &str) {
    state.broadcast_to_user(
        applicant_id,
        "flowFinished",
        serde_json::json!({
            "bizType": crate::service::sys_flow_service::BIZ_TYPE_DEMO,
            "status": status,
        }),
    );
}

/// 当前用户是否持有审批管理视图权限（system:flow:list 或超管）
async fn is_flow_manager(state: &AppState, user_id: i64) -> Result<bool, AppError> {
    let perms = state
        .menu_service
        .get_permissions_by_user_id(user_id)
        .await?;
    Ok(perms
        .iter()
        .any(|p| p == "*:*:*" || p == "system:flow:list"))
}

/// GET /system/flow/todo — 我的待办
pub async fn todo(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FlowPageQuery>,
) -> Result<TableDataInfo<SysFlowTaskModel>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let (rows, total) = state.flow_service.todo_page(user_id, query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/flow/pending-count — 待办数量（红点）
///
/// 响应带 `Cache-Control: no-store`：前端 SW 对 GET 走 NetworkFirst 缓存 1h（pwa.ts:53-66），
/// 弱网下红点可能读到旧缓存（V7-E4），计数接口必须绕缓存。
pub async fn pending_count(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<axum::response::Response, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let count = state.flow_service.pending_count(user_id).await?;
    let body = AjaxResult::success(count);
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    resp.headers_mut().insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}

/// GET /system/flow/mine — 我发起的单据
pub async fn mine(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FlowPageQuery>,
) -> Result<TableDataInfo<FlowDemoDocModel>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let (rows, total) = state.flow_service.mine_page(user_id, query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/flow/list — 全部单据（管理视图；权限键 system:flow:list）
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FlowPageQuery>,
) -> Result<TableDataInfo<FlowDemoDocModel>, AppError> {
    // 多租户：租户操作者仅见本租户单据；平台操作者全量（tenant_id=0 → None）
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    let (rows, total) = state.flow_service.all_page(query, tenant_scope).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/flow/task/{taskId} — 任务详情 + 时间线
pub async fn task_detail(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(task_id): Path<i64>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let is_manager = is_flow_manager(&state, user_id).await?;
    let detail = state
        .flow_service
        .task_detail(user_id, is_manager, task_id)
        .await?;
    Ok(AjaxResult::success(detail))
}

/// POST /system/flow/demo/submit — 提交示例请假单并发起审批
pub async fn submit_demo(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<FlowSubmitDto>,
) -> Result<AjaxResult<FlowDemoDocModel>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    crate::common::i18n::validate(&dto)?;
    let outcome = state
        .flow_service
        .submit_demo(user_id, operator.username(), dto)
        .await?;
    for uid in &outcome.notify_assignees {
        ws_notify_todo(&state, *uid, &outcome.doc.title);
        state
            .flow_service
            .send_flow_audit(*uid, "flow_todo", &outcome.doc.title)
            .await;
    }
    Ok(AjaxResult::success(outcome.doc))
}

/// POST /system/flow/demo/{docId}/resubmit — 重新提交（round_no + 1）
pub async fn resubmit_demo(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(doc_id): Path<i64>,
) -> Result<AjaxResult<FlowDemoDocModel>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let outcome = state
        .flow_service
        .resubmit_demo(user_id, operator.is_pat(), doc_id, None)
        .await?;
    for uid in &outcome.notify_assignees {
        ws_notify_todo(&state, *uid, &outcome.doc.title);
        state
            .flow_service
            .send_flow_audit(*uid, "flow_todo", &outcome.doc.title)
            .await;
    }
    Ok(AjaxResult::success(outcome.doc))
}

/// POST /system/flow/demo/{docId}/withdraw — 撤回（发起人，按单据维度）
pub async fn withdraw_demo(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(doc_id): Path<i64>,
) -> Result<AjaxResult<SysFlowTaskModel>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let outcome = state
        .flow_service
        .withdraw_by_doc(user_id, operator.is_pat(), doc_id, None)
        .await?;
    Ok(AjaxResult::success(outcome.task))
}

/// POST /system/flow/task/{taskId}/action — 审批动作
pub async fn act(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(task_id): Path<i64>,
    Json(dto): Json<FlowActionDto>,
) -> Result<AjaxResult<SysFlowTaskModel>, AppError> {
    let user_id = parse_user_id(operator.user_id())?;
    let outcome = state
        .flow_service
        .act(user_id, operator.is_pat(), task_id, dto)
        .await?;
    for uid in &outcome.notify_assignees {
        let title = outcome.task.title.clone().unwrap_or_default();
        ws_notify_todo(&state, *uid, &title);
        state
            .flow_service
            .send_flow_audit(*uid, "flow_todo", &title)
            .await;
    }
    if let Some((applicant_id, status)) = outcome.notify_finished {
        ws_notify_finished(&state, applicant_id, status);
        // 驳回是需要申请人采取行动的终态 → 站内通知（flow_reject 模板，1-8）；
        // approved 办结以 WS + 待办列表为准，不再重复站内打扰。
        if status == "rejected" {
            let title = outcome.task.title.clone().unwrap_or_default();
            state
                .flow_service
                .send_flow_audit(applicant_id, "flow_reject", &title)
                .await;
        }
    }
    Ok(AjaxResult::success(outcome.task))
}
