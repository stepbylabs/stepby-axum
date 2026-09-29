// backend-axum/src/handler/sys_tenant_nav_handler.rs
//! 租户自建导航 L3 Handler（批次 3 / MT-1）
//!
//! 接口路径与权限（权限映射见 middleware/permission.rs）：
//! - GET    /system/tenant/menu/list          system:tenantMenu:list
//! - GET    /system/tenant/menu/options       system:tenantMenu:list
//! - POST   /system/tenant/menu               system:tenantMenu:add
//! - PUT    /system/tenant/menu               system:tenantMenu:edit
//! - DELETE /system/tenant/menu/{l3Id}        system:tenantMenu:remove
//!
//! 准入判据（能力位 `nav.l3`）与行级租户收窄在 service 层，**不在 handler**：
//! RBAC 是外层闸门，能力位与租户归属是服务层守卫（`NavScope`），二者缺一不可。

use axum::Json;
use axum::extract::{Path, Query, State};
use std::sync::Arc;

use crate::common::{AjaxResult, AppError};
use crate::middleware::{Operator, TargetTenant};
use crate::service::sys_tenant_nav_service::{
    SysTenantMenuVo, SysTenantNavService, TenantNavAddDto, TenantNavEditDto, TenantNavMenuOptionVo,
    TenantNavQueryDto,
};
use crate::state::AppState;

/// GET /system/tenant/menu/list — 本租户（或指定租户，平台操作者）的导航配置列表
#[utoipa::path(
    get,
    path = "/system/tenant/menu/list",
    params(TenantNavQueryDto),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<SysTenantMenuVo>>),
        (status = 403, description = "能力位 nav.l3 未开启或无权限"),
    ),
    tag = "system-tenant-nav"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<TenantNavQueryDto>,
) -> Result<AjaxResult<Vec<SysTenantMenuVo>>, AppError> {
    let list = state
        .tenant_nav_service
        .list(query.tenant_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(list))
}

/// GET /system/tenant/menu/options — 可选菜单池（M/C 展平，带 selected 标记）
#[utoipa::path(
    get,
    path = "/system/tenant/menu/options",
    params(TenantNavQueryDto),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<TenantNavMenuOptionVo>>),
        (status = 403, description = "能力位 nav.l3 未开启或无权限"),
    ),
    tag = "system-tenant-nav"
)]
pub async fn options(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<TenantNavQueryDto>,
) -> Result<AjaxResult<Vec<TenantNavMenuOptionVo>>, AppError> {
    let user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.auth.user_id_parse_failed")))?;
    let list = state
        .tenant_nav_service
        .options(query.tenant_id, user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(list))
}

/// POST /system/tenant/menu — 新增导航行
#[utoipa::path(
    post,
    path = "/system/tenant/menu",
    request_body = TenantNavAddDto,
    responses(
        (status = 200, description = "创建成功", body = AjaxResult<SysTenantMenuVo>),
        (status = 400, description = "引用菜单非法 / 重复挂载 / 父级非法"),
        (status = 403, description = "能力位未开启、只读档、或跨租户"),
    ),
    tag = "system-tenant-nav"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Json(dto): Json<TenantNavAddDto>,
) -> Result<AjaxResult<SysTenantMenuVo>, AppError> {
    // 审计 target_tenant_id：新增即确知归属租户
    if let Some(tid) = dto.tenant_id {
        target_tenant.set(tid);
    }
    let vo = state
        .tenant_nav_service
        .add(dto, operator.username(), operator.tenant_id())
        .await?;
    target_tenant.set(vo.tenant_id);
    Ok(AjaxResult::success(vo))
}

/// PUT /system/tenant/menu — 修改导航行（父级 / 排序 / 显隐 / 启停）
#[utoipa::path(
    put,
    path = "/system/tenant/menu",
    request_body = TenantNavEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<SysTenantMenuVo>),
        (status = 400, description = "父级非法 / 状态值非法"),
        (status = 403, description = "能力位未开启、只读档、或跨租户"),
        (status = 404, description = "导航行不存在"),
    ),
    tag = "system-tenant-nav"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Json(dto): Json<TenantNavEditDto>,
) -> Result<AjaxResult<SysTenantMenuVo>, AppError> {
    let vo = state
        .tenant_nav_service
        .edit(dto, operator.username(), operator.tenant_id())
        .await?;
    target_tenant.set(vo.tenant_id);
    Ok(AjaxResult::success(vo))
}

/// DELETE /system/tenant/menu/{l3Id} — 删除导航行（软删；有子节点时拒绝）
#[utoipa::path(
    delete,
    path = "/system/tenant/menu/{l3Id}",
    params(("l3Id" = i64, Path, description = "L3 导航行 ID")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "存在子节点，无法删除"),
        (status = 403, description = "能力位未开启、只读档、或跨租户"),
        (status = 404, description = "导航行不存在"),
    ),
    tag = "system-tenant-nav"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Path(l3_id): Path<i64>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let tid = state
        .tenant_nav_service
        .remove(l3_id, operator.username(), operator.tenant_id())
        .await?;
    target_tenant.set(tid);
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// 供 router 挂载的类型自检（避免 unused import 告警）
#[allow(dead_code)]
fn _type_assert(_s: &SysTenantNavService) {}
