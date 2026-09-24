// axum-backend/src/handler/sys_tenant_handler.rs
//! 租户管理 Handler（多租户 Phase 2 立项实施）
//!
//! 接口路径与返回格式对齐 yebot-ui 前端调用规范：
//! - GET    /system/tenant/list            租户列表（parent_id=0 顶层部门，排除平台根）
//! - GET    /system/tenant/{deptId}        租户详情
//! - POST   /system/tenant                 新建租户
//! - PUT    /system/tenant                 修改租户
//! - PUT    /system/tenant/changeStatus    租户启停（停用后该租户用户无法登录）
//! - DELETE /system/tenant/{deptId}        删除租户（租户内仍有用户时拒绝）

use axum::Json;
use axum::extract::{Path, Query, State};
use std::sync::Arc;

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::service::sys_tenant_service::{
    SysTenantService, TenantAddDto, TenantEditDto, TenantQueryDto, TenantStatusDto, TenantVo,
};
use crate::state::AppState;

/// GET /system/tenant/list — 租户列表
#[utoipa::path(
    get,
    path = "/system/tenant/list",
    params(TenantQueryDto),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<TenantVo>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-tenant"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Query(query): Query<TenantQueryDto>,
) -> Result<AjaxResult<Vec<TenantVo>>, AppError> {
    let list = state.tenant_service.list(query).await?;
    Ok(AjaxResult::success(list))
}

/// GET /system/tenant/{deptId} — 租户详情
#[utoipa::path(
    get,
    path = "/system/tenant/{deptId}",
    params(("deptId" = i64, Path, description = "租户 ID（根部门 ID）")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<TenantVo>),
        (status = 404, description = "租户不存在"),
    ),
    tag = "system-tenant"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(dept_id): Path<i64>,
) -> Result<AjaxResult<TenantVo>, AppError> {
    let vo = state.tenant_service.get_info(dept_id).await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/tenant — 新建租户
#[utoipa::path(
    post,
    path = "/system/tenant",
    request_body = TenantAddDto,
    responses(
        (status = 200, description = "创建成功", body = AjaxResult<TenantVo>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-tenant"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<TenantAddDto>,
) -> Result<AjaxResult<TenantVo>, AppError> {
    let vo = state
        .tenant_service
        .add(dto, operator.username())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /system/tenant — 修改租户
#[utoipa::path(
    put,
    path = "/system/tenant",
    request_body = TenantEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<TenantVo>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-tenant"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<TenantEditDto>,
) -> Result<AjaxResult<TenantVo>, AppError> {
    let vo = state
        .tenant_service
        .edit(dto, operator.username())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /system/tenant/changeStatus — 租户启停
#[utoipa::path(
    put,
    path = "/system/tenant/changeStatus",
    request_body = TenantStatusDto,
    responses(
        (status = 200, description = "操作成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-tenant"
)]
pub async fn change_status(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<TenantStatusDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state
        .tenant_service
        .change_status(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/tenant/{deptId} — 删除租户
#[utoipa::path(
    delete,
    path = "/system/tenant/{deptId}",
    params(("deptId" = i64, Path, description = "租户 ID（根部门 ID）")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "租户内仍有用户"),
    ),
    tag = "system-tenant"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dept_id): Path<i64>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state
        .tenant_service
        .remove(dept_id, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// 供 router 挂载的类型自检（避免 unused import 告警）
#[allow(dead_code)]
fn _type_assert(_s: &SysTenantService) {}
