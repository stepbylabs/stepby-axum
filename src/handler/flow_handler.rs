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
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::IntoResponse;

use crate::common::{AjaxResult, AppError, TableDataInfo, ValidatedJson};
use crate::entity::flow_demo_doc::Model as FlowDemoDocModel;
use crate::entity::flow_graph_doc::Model as FlowGraphDocModel;
use crate::entity::sys_flow_task::Model as SysFlowTaskModel;
use crate::middleware::Operator;
use crate::service::sys_flow_service::{
    FlowActionDto, FlowCountersignDto, FlowDoneVo, FlowGraphSubmitDto, FlowPageQuery, FlowSubmitDto,
};
use crate::state::AppState;

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
#[utoipa::path(
    get,
    path = "/system/flow/todo",
    params(FlowPageQuery),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysFlowTaskModel>),
        (status = 401, description = "未登录"),
    ),
    tag = "system-flow"
)]
pub async fn todo(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FlowPageQuery>,
) -> Result<TableDataInfo<SysFlowTaskModel>, AppError> {
    let user_id = operator.user_id_i64()?;
    let (rows, total) = state.flow_service.todo_page(user_id, query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/flow/pending-count — 待办数量（红点）
///
/// 响应带 `Cache-Control: no-store`：前端 SW 对 GET 走 NetworkFirst 缓存 1h（pwa.ts:53-66），
/// 弱网下红点可能读到旧缓存（V7-E4），计数接口必须绕缓存。
#[utoipa::path(
    get,
    path = "/system/flow/pending-count",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<u64>),
        (status = 401, description = "未登录"),
    ),
    tag = "system-flow"
)]
pub async fn pending_count(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<axum::response::Response, AppError> {
    let user_id = operator.user_id_i64()?;
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
#[utoipa::path(
    get,
    path = "/system/flow/mine",
    params(FlowPageQuery),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<FlowDemoDocModel>),
        (status = 401, description = "未登录"),
    ),
    tag = "system-flow"
)]
pub async fn mine(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FlowPageQuery>,
) -> Result<TableDataInfo<FlowDemoDocModel>, AppError> {
    let user_id = operator.user_id_i64()?;
    let (rows, total) = state.flow_service.mine_page(user_id, query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/flow/done — 我审批过的（已办，W-8）
///
/// 口径：`operator_id = 本人` 且动作属裁决类（approve/reject）的流水；
/// 归属由查询条件本身保证（operator_id 取自已鉴权会话），无需额外权限键。
#[utoipa::path(
    get,
    path = "/system/flow/done",
    params(FlowPageQuery),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<FlowDoneVo>),
        (status = 401, description = "未登录"),
    ),
    tag = "system-flow"
)]
pub async fn done(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FlowPageQuery>,
) -> Result<TableDataInfo<FlowDoneVo>, AppError> {
    let user_id = operator.user_id_i64()?;
    let (rows, total) = state.flow_service.done_page(user_id, query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/flow/list — 全部单据（管理视图；权限键 system:flow:list）
#[utoipa::path(
    get,
    path = "/system/flow/list",
    params(FlowPageQuery),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<FlowDemoDocModel>),
        (status = 403, description = "缺少 system:flow:list 权限"),
    ),
    tag = "system-flow"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FlowPageQuery>,
) -> Result<TableDataInfo<FlowDemoDocModel>, AppError> {
    // 多租户：租户操作者仅见本租户单据；平台操作者全量（tenant_id=0 → None）
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    // 数据权限（W-5）：按操作者 data_scope 解析单据可见范围（部门树 + 本人；超管全量）
    let user_id = operator.user_id_i64()?;
    let doc_scope = state.flow_service.resolve_doc_scope(user_id).await?;
    let (rows, total) = state
        .flow_service
        .all_page(query, tenant_scope, &doc_scope)
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/flow/task/{taskId} — 任务详情 + 时间线
#[utoipa::path(
    get,
    path = "/system/flow/task/{taskId}",
    params(("taskId" = i64, Path, description = "任务 ID")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<serde_json::Value>),
        (status = 403, description = "非归属人且无管理权限"),
        (status = 404, description = "任务不存在"),
    ),
    tag = "system-flow"
)]
pub async fn task_detail(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(task_id): Path<i64>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let user_id = operator.user_id_i64()?;
    let is_manager = is_flow_manager(&state, user_id).await?;
    let detail = state
        .flow_service
        .task_detail(user_id, is_manager, task_id)
        .await?;
    Ok(AjaxResult::success(detail))
}

/// POST /system/flow/demo/submit — 提交示例请假单并发起审批
#[utoipa::path(
    post,
    path = "/system/flow/demo/submit",
    request_body = FlowSubmitDto,
    responses(
        (status = 200, description = "提交成功", body = AjaxResult<FlowDemoDocModel>),
        (status = 400, description = "参数校验失败 / 审批策略不可用"),
    ),
    tag = "system-flow"
)]
pub async fn submit_demo(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<FlowSubmitDto>,
) -> Result<AjaxResult<FlowDemoDocModel>, AppError> {
    let user_id = operator.user_id_i64()?;
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

/// POST /system/flow/graph/submit — 提交**图驱动**单据（批次十六：按图推进闭环）
///
/// 任一已发布流程定义（`is_latest='1'` + `status='1'`）都可驱动审批：
/// 提交时静态路由（条件边按 fields 求值，fail-closed），字段快照冻结进单据，
/// 推进时重放同路径。待办/动作/办结复用通用 task 端点。
#[utoipa::path(
    post,
    path = "/system/flow/graph/submit",
    request_body = FlowGraphSubmitDto,
    responses(
        (status = 200, description = "提交成功", body = AjaxResult<FlowGraphDocModel>),
        (status = 400, description = "图非法/条件求值失败/无审批节点"),
        (status = 404, description = "流程未发布或不存在"),
    ),
    tag = "system-flow"
)]
pub async fn submit_graph(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    // 批七十四 B2：服务层只对 `title` 做了非空判断，`flow_code`/`title` 的 garde 长度上限
    // 此前从未执行（超长串会原样进 `flow_code` 等值查询与单据标题落库）。
    ValidatedJson(dto): ValidatedJson<FlowGraphSubmitDto>,
) -> Result<AjaxResult<FlowGraphDocModel>, AppError> {
    let user_id = operator.user_id_i64()?;
    let outcome = state
        .flow_service
        .submit_graph(user_id, operator.username(), dto)
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
#[utoipa::path(
    post,
    path = "/system/flow/demo/{docId}/resubmit",
    params(("docId" = i64, Path, description = "单据 ID")),
    responses(
        (status = 200, description = "重新提交成功", body = AjaxResult<FlowDemoDocModel>),
        (status = 400, description = "PAT 会话 / 单据仍为 pending"),
        (status = 403, description = "非单据提交人"),
    ),
    tag = "system-flow"
)]
pub async fn resubmit_demo(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(doc_id): Path<i64>,
) -> Result<AjaxResult<FlowDemoDocModel>, AppError> {
    let user_id = operator.user_id_i64()?;
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
#[utoipa::path(
    post,
    path = "/system/flow/demo/{docId}/withdraw",
    params(("docId" = i64, Path, description = "单据 ID")),
    responses(
        (status = 200, description = "撤回成功", body = AjaxResult<SysFlowTaskModel>),
        (status = 400, description = "PAT 会话 / 单据无 pending 待办"),
        (status = 403, description = "非单据提交人"),
    ),
    tag = "system-flow"
)]
pub async fn withdraw_demo(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(doc_id): Path<i64>,
) -> Result<AjaxResult<SysFlowTaskModel>, AppError> {
    let user_id = operator.user_id_i64()?;
    let outcome = state
        .flow_service
        .withdraw_by_doc(user_id, operator.is_pat(), doc_id, None)
        .await?;
    Ok(AjaxResult::success(outcome.task))
}

/// POST /system/flow/export — 审批单据 Excel 导出（管理视图，W-11）
///
/// **权限口径（本轮分析结论）**：复用 `system:flow:list`（不新增 `system:flow:export`）。
/// 理由：①导出是列表能力的延伸，二者**可见范围必须完全一致**（同样叠加租户 + `data_scope`），
/// 否则导出即成为数据泄露旁路；②新增独立权限键需要「`PERM_ROUTE_TABLE` + `PROTECTED_ROUTES`
/// + `sys_menu` 种子 + 契约测试 + 迁移」五处同步，且需额外评估租户可授性，收益不足。
#[utoipa::path(
    post,
    path = "/system/flow/export",
    request_body(content = FlowExportDto, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "导出成功（xlsx 字节流）", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 403, description = "缺少 system:flow:list 权限"),
    ),
    tag = "system-flow"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Form(dto): Form<FlowExportDto>,
) -> Result<axum::response::Response, AppError> {
    use crate::common::excel::{CellValue, ExcelColumn, export_to_excel_with_fields};

    let user_id = operator.user_id_i64()?;
    let doc_scope = state.flow_service.resolve_doc_scope(user_id).await?;
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    let query = FlowPageQuery {
        page_num: None,
        page_size: None,
        status: dto.status.clone(),
    };
    let (rows, truncated) = state
        .flow_service
        .export_docs(query, tenant_scope, &doc_scope)
        .await?;

    let fields: Option<Vec<String>> =
        dto.fields
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                s.split(',')
                    .map(|f| f.trim().to_string())
                    .filter(|f| !f.is_empty())
                    .collect()
            });

    let columns = [
        ExcelColumn {
            key: "docId",
            header: ("单据编号", "Document ID"),
            getter: |r: &FlowDemoDocModel| CellValue::Number(r.doc_id as f64),
        },
        ExcelColumn {
            key: "title",
            header: ("单据标题", "Title"),
            getter: |r: &FlowDemoDocModel| CellValue::Text(r.title.clone().into()),
        },
        ExcelColumn {
            key: "applicantName",
            header: ("提交人", "Applicant"),
            getter: |r: &FlowDemoDocModel| {
                CellValue::Text(r.applicant_name.clone().unwrap_or_default().into())
            },
        },
        ExcelColumn {
            key: "leaveType",
            header: ("请假类型", "Leave Type"),
            getter: |r: &FlowDemoDocModel| CellValue::Text(r.leave_type.clone().into()),
        },
        ExcelColumn {
            key: "days",
            header: ("请假天数", "Days"),
            getter: |r: &FlowDemoDocModel| CellValue::Number(r.days as f64),
        },
        ExcelColumn {
            key: "flowMode",
            header: ("审批模式", "Flow Mode"),
            getter: |r: &FlowDemoDocModel| CellValue::Text(r.flow_mode.clone().into()),
        },
        ExcelColumn {
            key: "status",
            header: ("单据状态", "Status"),
            getter: |r: &FlowDemoDocModel| CellValue::Text(r.status.clone().into()),
        },
        ExcelColumn {
            key: "currentRound",
            header: ("当前轮次", "Round"),
            getter: |r: &FlowDemoDocModel| CellValue::Number(r.current_round as f64),
        },
        ExcelColumn {
            key: "submittedAt",
            header: ("提交时间", "Submitted At"),
            getter: |r: &FlowDemoDocModel| CellValue::from_opt_datetime(r.submitted_at),
        },
        ExcelColumn {
            key: "finishedAt",
            header: ("办结时间", "Finished At"),
            getter: |r: &FlowDemoDocModel| CellValue::from_opt_datetime(r.finished_at),
        },
    ];

    export_to_excel_with_fields(
        &crate::tr!("excel.sheet.flow_doc"),
        "flow_doc",
        &columns,
        &rows,
        fields.as_deref(),
        truncated,
    )
    .await
}

/// 审批导出 DTO（表单编码：状态筛选 + 可选字段选择）
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FlowExportDto {
    pub status: Option<String>,
    /// 导出字段 key（逗号分隔），为空时导出全部字段
    pub fields: Option<String>,
}

/// POST /system/flow/task/{taskId}/countersign-add — 加签（在当前节点追加会签审批人，W-3）
#[utoipa::path(
    post,
    path = "/system/flow/task/{taskId}/countersign-add",
    params(("taskId" = i64, Path, description = "任务 ID")),
    request_body = FlowCountersignDto,
    responses(
        (status = 200, description = "加签成功", body = AjaxResult<SysFlowTaskModel>),
        (status = 400, description = "PAT 会话 / 目标已在当前节点 / 目标用户不可用"),
        (status = 403, description = "非当前审批人"),
    ),
    tag = "system-flow"
)]
pub async fn countersign_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(task_id): Path<i64>,
    Json(dto): Json<FlowCountersignDto>,
) -> Result<AjaxResult<SysFlowTaskModel>, AppError> {
    let user_id = operator.user_id_i64()?;
    crate::common::i18n::validate(&dto)?;
    let outcome = state
        .flow_service
        .countersign_add(user_id, operator.is_pat(), task_id, dto.to_user_id)
        .await?;
    for uid in &outcome.notify_assignees {
        let title = outcome.task.title.clone().unwrap_or_default();
        ws_notify_todo(&state, *uid, &title);
        state
            .flow_service
            .send_flow_audit(*uid, "flow_todo", &title)
            .await;
    }
    Ok(AjaxResult::success(outcome.task))
}

/// POST /system/flow/task/{taskId}/countersign-del — 减签（从当前节点移除一名会签审批人，G-02 M2）
#[utoipa::path(
    post,
    path = "/system/flow/task/{taskId}/countersign-del",
    params(("taskId" = i64, Path, description = "任务 ID")),
    request_body = FlowCountersignDto,
    responses(
        (status = 200, description = "减签成功", body = AjaxResult<SysFlowTaskModel>),
        (status = 400, description = "PAT 会话 / 目标不在当前节点 / 移除后节点无有效审批人"),
        (status = 403, description = "非当前审批人"),
    ),
    tag = "system-flow"
)]
pub async fn countersign_del(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(task_id): Path<i64>,
    Json(dto): Json<FlowCountersignDto>,
) -> Result<AjaxResult<SysFlowTaskModel>, AppError> {
    let user_id = operator.user_id_i64()?;
    crate::common::i18n::validate(&dto)?;
    let outcome = state
        .flow_service
        .countersign_del(user_id, operator.is_pat(), task_id, dto.to_user_id, None)
        .await?;
    Ok(AjaxResult::success(outcome.task))
}

/// POST /system/flow/task/{taskId}/action — 审批动作
#[utoipa::path(
    post,
    path = "/system/flow/task/{taskId}/action",
    params(("taskId" = i64, Path, description = "任务 ID")),
    request_body = FlowActionDto,
    responses(
        (status = 200, description = "操作成功", body = AjaxResult<SysFlowTaskModel>),
        (status = 400, description = "PAT 会话 / 动作非法 / 任务已处理"),
        (status = 403, description = "非当前审批人"),
    ),
    tag = "system-flow"
)]
pub async fn act(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(task_id): Path<i64>,
    Json(dto): Json<FlowActionDto>,
) -> Result<AjaxResult<SysFlowTaskModel>, AppError> {
    let user_id = operator.user_id_i64()?;
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
