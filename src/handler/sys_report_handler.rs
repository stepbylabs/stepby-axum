//! 报表中心 + 定时订阅推送模块 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范（前缀 /system/report）：
//! - GET    /system/report/list                      分页查询报表定义
//! - GET    /system/report/{reportId}                查询报表详情
//! - POST   /system/report                           新增报表定义
//! - PUT    /system/report                           修改报表定义
//! - DELETE /system/report/{reportIds}               批量删除报表定义（级联逻辑删除其下订阅）
//! - PUT    /system/report/{reportId}/status         报表启停
//! - POST   /system/report/{reportId}/preview        手动预览报表快照（不落库、不推送）
//! - GET    /system/report/sub/list                  分页查询报表订阅
//! - GET    /system/report/sub/{subId}               查询订阅详情
//! - POST   /system/report/sub                       新增报表订阅
//! - PUT    /system/report/sub                       修改报表订阅
//! - DELETE /system/report/sub/{subIds}              批量删除报表订阅
//! - PUT    /system/report/sub/{subId}/status        订阅启停
//! - POST   /system/report/sub/{subId}/run           手动触发订阅推送
//!
//! 权限映射（permission_middleware）：
//! - system:report:list/query/add/edit/remove/status/preview
//! - system:report:sub:list/query/add/edit/remove/status/run

use axum::extract::{Path, Query, State};
use std::sync::Arc;

use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{AjaxResult, AppError, TableDataInfo, ValidatedJson};
use crate::entity::sys_report::Model as SysReportModel;
use crate::entity::sys_report_sub::Model as SysReportSubModel;
use crate::middleware::Operator;
use crate::service::sys_report_service::{
    PushSummaryVo, ReportAddDto, ReportEditDto, ReportQueryDto, ReportSnapshotVo, ReportStatusDto,
    SubAddDto, SubEditDto, SubQueryDto, SubStatusDto,
};
use crate::state::AppState;

// ==================== 报表定义 ====================

/// GET /system/report/list
/// 分页查询报表定义
#[utoipa::path(
    get,
    path = "/system/report/list",
    params(ReportQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysReportModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-report"
)]
pub async fn report_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<ReportQueryDto>,
) -> Result<TableDataInfo<SysReportModel>, AppError> {
    let (rows, total) = state
        .report_service
        .get_report_page(query, operator.tenant_id())
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/report/{reportId}
/// 查询报表详情
#[utoipa::path(
    get,
    path = "/system/report/{reportId}",
    params(("reportId" = i64, Path, description = "报表 ID")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysReportModel>),
        (status = 404, description = "报表不存在"),
    ),
    tag = "system-report"
)]
pub async fn report_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(report_id): Path<i64>,
) -> Result<AjaxResult<SysReportModel>, AppError> {
    let vo = state
        .report_service
        .get_report_by_id(report_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/report
/// 新增报表定义
#[utoipa::path(
    post,
    path = "/system/report",
    request_body = ReportAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<SysReportModel>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-report"
)]
pub async fn report_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::Json(dto): axum::Json<ReportAddDto>,
) -> Result<AjaxResult<SysReportModel>, AppError> {
    let vo = state
        .report_service
        .add_report(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /system/report
/// 修改报表定义
#[utoipa::path(
    put,
    path = "/system/report",
    request_body = ReportEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<SysReportModel>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-report"
)]
pub async fn report_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::Json(dto): axum::Json<ReportEditDto>,
) -> Result<AjaxResult<SysReportModel>, AppError> {
    let vo = state
        .report_service
        .edit_report(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// DELETE /system/report/{reportIds}
/// 批量删除报表定义
#[utoipa::path(
    delete,
    path = "/system/report/{reportIds}",
    params(("reportIds" = String, Path, description = "报表 ID 集合，逗号分隔")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
    ),
    tag = "system-report"
)]
pub async fn report_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids = crate::utils::parse_id_list::<i64>(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.report.id_empty")));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .report_service
        .delete_report(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// PUT /system/report/{reportId}/status
/// 报表启停
#[utoipa::path(
    put,
    path = "/system/report/{reportId}/status",
    request_body = ReportStatusDto,
    responses(
        (status = 200, description = "启停成功", body = AjaxResult<serde_json::Value>),
    ),
    tag = "system-report"
)]
pub async fn report_status(
    State(state): State<Arc<AppState>>,
    Path(report_id): Path<i64>,
    operator: Operator,
    // 批七十四 B2：裸 `Json` 使 `status` 的 `length(1,1)` 永不执行——服务层直接把入参
    // 写进 `sys_report.status`（无二次校验），空串/任意长串都会落库。
    ValidatedJson(mut dto): ValidatedJson<ReportStatusDto>,
) -> Result<AjaxResult<()>, AppError> {
    dto.report_id = report_id;
    state
        .report_service
        .change_report_status(dto, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// POST /system/report/{reportId}/preview
/// 手动预览报表快照（不落库、不推送）
#[utoipa::path(
    post,
    path = "/system/report/{reportId}/preview",
    params(("reportId" = i64, Path, description = "报表 ID")),
    responses(
        (status = 200, description = "预览成功", body = AjaxResult<ReportSnapshotVo>),
    ),
    tag = "system-report"
)]
pub async fn report_preview(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(report_id): Path<i64>,
) -> Result<AjaxResult<ReportSnapshotVo>, AppError> {
    let vo = state
        .report_service
        .preview_report(report_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

// ==================== 报表订阅 ====================

/// GET /system/report/sub/list
/// 分页查询报表订阅
#[utoipa::path(
    get,
    path = "/system/report/sub/list",
    params(SubQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysReportSubModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-report"
)]
pub async fn sub_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<SubQueryDto>,
) -> Result<TableDataInfo<SysReportSubModel>, AppError> {
    let (rows, total) = state
        .report_service
        .get_sub_page(query, operator.tenant_id())
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/report/sub/{subId}
/// 查询订阅详情
#[utoipa::path(
    get,
    path = "/system/report/sub/{subId}",
    params(("subId" = i64, Path, description = "订阅 ID")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysReportSubModel>),
        (status = 404, description = "订阅不存在"),
    ),
    tag = "system-report"
)]
pub async fn sub_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(sub_id): Path<i64>,
) -> Result<AjaxResult<SysReportSubModel>, AppError> {
    let vo = state
        .report_service
        .get_sub_by_id(sub_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/report/sub
/// 新增报表订阅
#[utoipa::path(
    post,
    path = "/system/report/sub",
    request_body = SubAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<SysReportSubModel>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-report"
)]
pub async fn sub_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::Json(dto): axum::Json<SubAddDto>,
) -> Result<AjaxResult<SysReportSubModel>, AppError> {
    let vo = state
        .report_service
        .add_sub(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /system/report/sub
/// 修改报表订阅
#[utoipa::path(
    put,
    path = "/system/report/sub",
    request_body = SubEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<SysReportSubModel>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-report"
)]
pub async fn sub_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::Json(dto): axum::Json<SubEditDto>,
) -> Result<AjaxResult<SysReportSubModel>, AppError> {
    let vo = state
        .report_service
        .edit_sub(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// DELETE /system/report/sub/{subIds}
/// 批量删除报表订阅
#[utoipa::path(
    delete,
    path = "/system/report/sub/{subIds}",
    params(("subIds" = String, Path, description = "订阅 ID 集合，逗号分隔")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
    ),
    tag = "system-report"
)]
pub async fn sub_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(ids): Path<String>,
) -> Result<AjaxResult<()>, AppError> {
    let ids = crate::utils::parse_id_list::<i64>(&ids);
    if ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!(
            "error.report_sub.id_empty"
        )));
    }
    if ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }
    state
        .report_service
        .delete_sub(ids, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// PUT /system/report/sub/{subId}/status
/// 订阅启停
#[utoipa::path(
    put,
    path = "/system/report/sub/{subId}/status",
    request_body = SubStatusDto,
    responses(
        (status = 200, description = "启停成功", body = AjaxResult<serde_json::Value>),
    ),
    tag = "system-report"
)]
pub async fn sub_status(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<i64>,
    operator: Operator,
    // 与 `report_status` 同理：裸 `Json` 会让 `status` 长度规则形同虚设
    ValidatedJson(mut dto): ValidatedJson<SubStatusDto>,
) -> Result<AjaxResult<()>, AppError> {
    dto.sub_id = sub_id;
    state
        .report_service
        .change_sub_status(dto, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.default")))
}

/// POST /system/report/sub/{subId}/run
/// 手动触发订阅推送（立即生成快照并投递）
#[utoipa::path(
    post,
    path = "/system/report/sub/{subId}/run",
    params(("subId" = i64, Path, description = "订阅 ID")),
    responses(
        (status = 200, description = "推送成功", body = AjaxResult<PushSummaryVo>),
    ),
    tag = "system-report"
)]
pub async fn sub_run(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(sub_id): Path<i64>,
) -> Result<AjaxResult<PushSummaryVo>, AppError> {
    let vo = state
        .report_service
        .run_sub_now(sub_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}
