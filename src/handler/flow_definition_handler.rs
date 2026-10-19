//! 流程定义 Handler（G-02 M1：可视化流程定义 CRUD + 版本发布）
//!
//! - GET    /system/flow/definition/list            分页（租户过滤）
//! - GET    /system/flow/definition/{flowId}        详情
//! - POST   /system/flow/definition                 新增（草稿，graph_json 复验）
//! - PUT    /system/flow/definition                 修改（已发布版本不可改图）
//! - POST   /system/flow/definition/publish/{id}    发布（version+1 新行，is_latest 切换）
//! - DELETE /system/flow/definition/{flowIds}       软删

use axum::extract::{Path, Query, State};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::IntoParams;

use crate::common::ValidatedJson;
use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::middleware::Operator;
use crate::service::flow_definition_service::{FlowDefUpsertDto, FlowDefVo};
use crate::state::AppState;

#[derive(Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct FlowDefQuery {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    #[serde(default)]
    pub flow_code: Option<String>,
}

fn default_page_num() -> u64 {
    1
}
fn default_page_size() -> u64 {
    10
}

/// GET /system/flow/definition/list
#[utoipa::path(
    get,
    path = "/system/flow/definition/list",
    params(FlowDefQuery),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<FlowDefVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-flow"
)]
pub async fn definition_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<FlowDefQuery>,
) -> Result<TableDataInfo<FlowDefVo>, AppError> {
    let (offset, limit) = crate::common::page::page_args(query.page_num, query.page_size);
    let (rows, total) = state
        .flow_definition_service
        .get_page(
            offset,
            limit,
            query.flow_code.as_deref(),
            operator.tenant_id(),
        )
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/flow/definition/{flowId}
#[utoipa::path(
    get,
    path = "/system/flow/definition/{flowId}",
    params(("flowId" = i64, Path, description = "流程定义 ID")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<FlowDefVo>),
        (status = 404, description = "流程定义不存在"),
    ),
    tag = "system-flow"
)]
pub async fn definition_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(flow_id): Path<i64>,
) -> Result<AjaxResult<FlowDefVo>, AppError> {
    let vo = state
        .flow_definition_service
        .get_by_id(flow_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/flow/definition
#[utoipa::path(
    post,
    path = "/system/flow/definition",
    request_body = FlowDefUpsertDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<FlowDefVo>),
        (status = 400, description = "graph_json 校验失败或编码重复"),
    ),
    tag = "system-flow"
)]
pub async fn definition_add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<FlowDefUpsertDto>,
) -> Result<AjaxResult<FlowDefVo>, AppError> {
    let vo = state
        .flow_definition_service
        .add(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /system/flow/definition
#[utoipa::path(
    put,
    path = "/system/flow/definition",
    request_body = FlowDefUpsertDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<FlowDefVo>),
        (status = 400, description = "已发布版本不可改图 / graph_json 校验失败"),
        (status = 404, description = "流程定义不存在"),
    ),
    tag = "system-flow"
)]
pub async fn definition_edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<FlowDefUpsertDto>,
) -> Result<AjaxResult<FlowDefVo>, AppError> {
    let vo = state
        .flow_definition_service
        .edit(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/flow/definition/publish/{flowId}
#[utoipa::path(
    post,
    path = "/system/flow/definition/publish/{flowId}",
    params(("flowId" = i64, Path, description = "流程定义 ID")),
    responses(
        (status = 200, description = "发布成功（返回新版本号）"),
        (status = 400, description = "graph_json 校验失败"),
    ),
    tag = "system-flow"
)]
pub async fn definition_publish(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(flow_id): Path<i64>,
) -> Result<AjaxResult<crate::service::flow_definition_service::FlowDefPublishVo>, AppError> {
    let vo = state
        .flow_definition_service
        .publish(flow_id, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// DELETE /system/flow/definition/{flowIds}
#[utoipa::path(
    delete,
    path = "/system/flow/definition/{flowIds}",
    params(("flowIds" = String, Path, description = "流程定义 ID 列表（逗号分隔）")),
    responses((status = 200, description = "删除成功")),
    tag = "system-flow"
)]
pub async fn definition_remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(flow_ids): Path<String>,
) -> Result<AjaxResult<&'static str>, AppError> {
    let ids: Vec<i64> = flow_ids
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    state
        .flow_definition_service
        .remove(ids, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success("删除成功"))
}
