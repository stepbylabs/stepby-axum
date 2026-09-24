// axum-backend/src/handler/sys_scim_group_handler.rs
//! v5-D12 Group：SCIM 组管理端接口（JWT 鉴权，管理界面用）。
//!
//! 职责边界：组权威在 IdP——管理端**不提供建组**（经 SCIM POST /Groups 创建），
//! 仅提供：列表 / 详情（成员只读）/ 绑定与映射类型编辑（全成员联动 diff）/ 删除。
//! ScimError → AppError 按 status 映射（400/404/409/500）。

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

use crate::common::{AjaxResult, AppError, TableDataInfo};
use crate::service::scim_group_service::{ScimGroupAdminDetail, ScimGroupAdminRow};
use crate::service::scim_service::ScimError;
use crate::state::AppState;

/// ScimError → AppError（管理端走全局 AppError 体系）
fn scim_to_app(e: ScimError) -> AppError {
    let status = e.status.parse::<u16>().unwrap_or(500);
    match status {
        400 => AppError::bad_request(&e.detail),
        404 => AppError::not_found(&e.detail),
        409 => AppError::new(409, &e.detail),
        _ => AppError::internal(&e.detail),
    }
}

/// 列表查询参数
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ScimGroupQueryDto {
    pub page_num: Option<u64>,
    pub page_size: Option<u64>,
    pub display_name: Option<String>,
    pub mapping_type: Option<String>,
}

/// GET /system/scimGroup/list
#[utoipa::path(
    get,
    path = "/system/scimGroup/list",
    params(ScimGroupQueryDto),
    responses(
        (status = 200, description = "SCIM 组分页列表", body = TableDataInfo<ScimGroupAdminRow>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-scim-group"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ScimGroupQueryDto>,
) -> Result<TableDataInfo<ScimGroupAdminRow>, AppError> {
    let page = q.page_num.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(10).clamp(1, 100);
    let (rows, total) = state
        .scim_group_service
        .admin_list(
            page,
            page_size,
            q.display_name.as_deref(),
            q.mapping_type.as_deref(),
        )
        .await
        .map_err(scim_to_app)?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/scimGroup/{id}
#[utoipa::path(
    get,
    path = "/system/scimGroup/{id}",
    responses(
        (status = 200, description = "SCIM 组详情（成员只读 + 绑定）", body = AjaxResult<ScimGroupAdminDetail>),
        (status = 404, description = "组不存在"),
    ),
    tag = "system-scim-group"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<AjaxResult<ScimGroupAdminDetail>, AppError> {
    let detail = state
        .scim_group_service
        .admin_detail(id)
        .await
        .map_err(scim_to_app)?;
    Ok(AjaxResult::success(detail))
}

/// PUT /system/scimGroup/{id} 请求体：映射类型与/或绑定集合（全量替换）
#[derive(Debug, Deserialize, utoipa::ToSchema, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "ScimGroupAdminUpsertDto.ts", rename_all = "camelCase")]
#[schema(as = ScimGroupAdminUpsertDto)]
pub struct ScimGroupAdminUpsertDto {
    /// 映射类型（role/dept）；变更前置：当前绑定必须为空
    pub mapping_type: Option<String>,
    /// 绑定目标 id 全量集合（role→role_id / dept→dept_id）；None = 不动绑定
    pub binding_target_ids: Option<Vec<i64>>,
}

/// PUT /system/scimGroup/{id}
#[utoipa::path(
    put,
    path = "/system/scimGroup/{id}",
    request_body = ScimGroupAdminUpsertDto,
    responses(
        (status = 200, description = "更新后详情（绑定变更已联动全成员授权）", body = AjaxResult<ScimGroupAdminDetail>),
        (status = 400, description = "mappingType 非法 / 变更前置不满足 / 绑定目标不存在"),
    ),
    tag = "system-scim-group"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<ScimGroupAdminUpsertDto>,
) -> Result<AjaxResult<ScimGroupAdminDetail>, AppError> {
    let detail = state
        .scim_group_service
        .admin_update(id, body.mapping_type, body.binding_target_ids)
        .await
        .map_err(scim_to_app)?;
    Ok(AjaxResult::success(detail))
}

/// DELETE /system/scimGroup/{id}（= SCIM DELETE 同语义：软删 + 撤仅 scim 来源授权）
#[utoipa::path(
    delete,
    path = "/system/scimGroup/{id}",
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 404, description = "组不存在"),
    ),
    tag = "system-scim-group"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state
        .scim_group_service
        .admin_delete(id)
        .await
        .map_err(scim_to_app)?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}
