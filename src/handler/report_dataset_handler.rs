//! 报表数据集与大屏 Handler（G-01 M1）
//!
//! - GET/POST/PUT/DELETE /report/dataset（+/{id}）
//! - POST /report/dataset/preview                    试跑（LIMIT 100 + Semaphore）
//! - GET/POST/PUT/DELETE /report/dashboard（+/{id}）

use axum::extract::{Path, State};
use serde_json::json;
use std::sync::Arc;

use crate::common::ValidatedJson;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::middleware::Operator;
use crate::service::report_dataset_service::{
    DashboardUpsertDto, DatasetPreviewDto, DatasetUpsertDto,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

/// GET /report/dataset/list
#[utoipa::path(
    get,
    path = "/report/dataset/list",
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<crate::service::report_dataset_service::DatasetVo>),
    ),
    tag = "report"
)]
pub async fn dataset_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<TableDataInfo<crate::service::report_dataset_service::DatasetVo>, AppError> {
    let (rows, total) = state
        .report_dataset_service
        .get_dataset_page(0, 200, operator.tenant_id())
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /report/dataset/{datasetId}
#[utoipa::path(
    get,
    path = "/report/dataset/{datasetId}",
    params(("datasetId" = i64, Path, description = "数据集 ID")),
    responses((status = 200, description = "查询成功")),
    tag = "report"
)]
pub async fn dataset_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dataset_id): Path<i64>,
) -> Result<AjaxResult<crate::service::report_dataset_service::DatasetVo>, AppError> {
    let vo = state
        .report_dataset_service
        .get_dataset_by_id(dataset_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /report/dataset
#[utoipa::path(
    post,
    path = "/report/dataset",
    request_body = DatasetUpsertDto,
    responses((status = 200, description = "新增成功"), (status = 400, description = "SQL 白名单校验失败")),
    tag = "report"
)]
pub async fn dataset_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<DatasetUpsertDto>,
) -> Result<AjaxResult<crate::service::report_dataset_service::DatasetVo>, AppError> {
    let vo = state
        .report_dataset_service
        .add_dataset(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /report/dataset
#[utoipa::path(
    put,
    path = "/report/dataset",
    request_body = DatasetUpsertDto,
    responses((status = 200, description = "修改成功"), (status = 400, description = "SQL 白名单校验失败")),
    tag = "report"
)]
pub async fn dataset_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<DatasetUpsertDto>,
) -> Result<AjaxResult<crate::service::report_dataset_service::DatasetVo>, AppError> {
    let vo = state
        .report_dataset_service
        .edit_dataset(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// DELETE /report/dataset/{datasetIds}
#[utoipa::path(
    delete,
    path = "/report/dataset/{datasetIds}",
    params(("datasetIds" = String, Path, description = "数据集 ID 列表（逗号分隔）")),
    responses((status = 200, description = "删除成功")),
    tag = "report"
)]
pub async fn dataset_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dataset_ids): Path<String>,
) -> Result<AjaxResult<&'static str>, AppError> {
    let ids: Vec<i64> = parse_id_list(&dataset_ids)?;
    state
        .report_dataset_service
        .remove_dataset(ids, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success("删除成功"))
}

/// POST /report/dataset/preview
#[utoipa::path(
    post,
    path = "/report/dataset/preview",
    request_body = DatasetPreviewDto,
    responses(
        (status = 200, description = "试跑成功（≤100 行）"),
        (status = 400, description = "参数缺失 / SQL 校验失败"),
        (status = 500, description = "并发满 / 查询超时"),
    ),
    tag = "report"
)]
pub async fn dataset_preview(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<DatasetPreviewDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let vo = state
        .report_dataset_service
        .preview_dataset(dto, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(json!({
        "columns": vo.columns,
        "rows": vo.rows,
        "truncated": vo.truncated
    })))
}

/// GET /report/dashboard/list
#[utoipa::path(
    get,
    path = "/report/dashboard/list",
    responses((status = 200, description = "查询成功")),
    tag = "report"
)]
pub async fn dashboard_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<TableDataInfo<crate::service::report_dataset_service::DashboardVo>, AppError> {
    let (rows, total) = state
        .report_dataset_service
        .get_dashboard_page(0, 200, operator.tenant_id())
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// POST /report/dataset/{datasetId}/sql — 取 SQL 模板明文（编辑回填）
///
/// 为何独立端点而非 info 出参：list/info 走 `report:dataset:list`（普通可见），
/// 明文仅 `report:dataset:edit` 持有者可见——权限差异在**路由键**层表达，
/// fail-closed 中间件天然拦截无 edit 权限者（VO 恒不含明文，零泄漏面）。
#[utoipa::path(
    post,
    path = "/report/dataset/{datasetId}/sql",
    params(("datasetId" = i64, Path, description = "数据集 ID")),
    responses(
        (status = 200, description = "返回 SQL 明文", body = AjaxResult<String>),
        (status = 403, description = "无 report:dataset:edit 权限"),
    ),
    tag = "report"
)]
pub async fn dataset_sql(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dataset_id): Path<i64>,
) -> Result<AjaxResult<String>, AppError> {
    let sql = state
        .report_dataset_service
        .get_dataset_sql(dataset_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(sql))
}

/// GET /report/dashboard/{dashboardId}
#[utoipa::path(
    get,
    path = "/report/dashboard/{dashboardId}",
    params(("dashboardId" = i64, Path, description = "大屏 ID")),
    responses((status = 200, description = "查询成功")),
    tag = "report"
)]
pub async fn dashboard_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dashboard_id): Path<i64>,
) -> Result<AjaxResult<crate::service::report_dataset_service::DashboardVo>, AppError> {
    let vo = state
        .report_dataset_service
        .get_dashboard_by_id(dashboard_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /report/dashboard（save：新增或更新，dashboardId 缺省=新增）
#[utoipa::path(
    post,
    path = "/report/dashboard",
    request_body = DashboardUpsertDto,
    responses((status = 200, description = "保存成功"), (status = 400, description = "layout_json 校验失败")),
    tag = "report"
)]
pub async fn dashboard_save(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<DashboardUpsertDto>,
) -> Result<AjaxResult<crate::service::report_dataset_service::DashboardVo>, AppError> {
    let vo = state
        .report_dataset_service
        .save_dashboard(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// DELETE /report/dashboard/{dashboardIds}
#[utoipa::path(
    delete,
    path = "/report/dashboard/{dashboardIds}",
    params(("dashboardIds" = String, Path, description = "大屏 ID 列表（逗号分隔）")),
    responses((status = 200, description = "删除成功")),
    tag = "report"
)]
pub async fn dashboard_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dashboard_ids): Path<String>,
) -> Result<AjaxResult<&'static str>, AppError> {
    let ids: Vec<i64> = parse_id_list(&dashboard_ids)?;
    state
        .report_dataset_service
        .remove_dashboard(ids, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success("删除成功"))
}
