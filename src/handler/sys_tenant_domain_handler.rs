// backend-axum/src/handler/sys_tenant_domain_handler.rs
//! 租户域名管理 Handler（多租户 Phase 3 域名链路，文档 §27.7 / §29.6）
//!
//! 接口路径与权限（权限映射见 middleware/permission.rs）：
//! - GET    /system/tenant/domain/list                system:tenant:domain:list
//! - POST   /system/tenant/domain                     system:tenant:domain:add
//! - POST   /system/tenant/domain/verify/{domainId}   system:tenant:domain:verify
//! - PUT    /system/tenant/domain/primary             system:tenant:domain:edit
//! - PUT    /system/tenant/domain/changeStatus        system:tenant:domain:edit
//! - DELETE /system/tenant/domain/{domainId}          system:tenant:domain:remove
//!
//! 安全：域名管理（增/删/改/验证/设主）**仅平台操作者**（`operator_tid == 0`）可执行；
//! 租户操作者仅可只读本租户域名（service 层强制 tenant_scope + 隐藏 verify_token）。

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;

use crate::common::{AjaxResult, AppError};
use crate::middleware::{Operator, TargetTenant};
use crate::service::sys_tenant_domain_service::{
    SysTenantDomainService, TenantDomainAddDto, TenantDomainIdDto, TenantDomainStatusDto,
    TenantDomainVerifyVo, TenantDomainVo,
};
use crate::state::AppState;

/// 域名列表查询参数
#[derive(Debug, Clone, Deserialize, ToSchema, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(parameter_in = Query)]
#[schema(as = TenantDomainQueryDto)]
pub struct TenantDomainQueryDto {
    /// 归属租户过滤（仅平台操作者可用；租户操作者调用本接口一律 403）
    #[serde(default)]
    pub tenant_id: Option<i64>,
}

/// GET /system/tenant/domain/list — 域名列表
#[utoipa::path(
    get,
    path = "/system/tenant/domain/list",
    params(TenantDomainQueryDto),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<TenantDomainVo>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-tenant-domain"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<TenantDomainQueryDto>,
) -> Result<AjaxResult<Vec<TenantDomainVo>>, AppError> {
    let list = state
        .tenant_domain_service
        .list(query.tenant_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(list))
}

/// POST /system/tenant/domain — 新增域名绑定（仅平台管理员）
#[utoipa::path(
    post,
    path = "/system/tenant/domain",
    request_body = TenantDomainAddDto,
    responses(
        (status = 200, description = "创建成功", body = AjaxResult<TenantDomainVo>),
        (status = 400, description = "参数错误 / 域名冲突 / 主域名冲突"),
        (status = 403, description = "仅平台管理员可管理域名"),
    ),
    tag = "system-tenant-domain"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Json(dto): Json<TenantDomainAddDto>,
) -> Result<AjaxResult<TenantDomainVo>, AppError> {
    // 审计 target_tenant_id：新增即确知归属租户
    target_tenant.set(dto.tenant_id);
    let vo = state
        .tenant_domain_service
        .add(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/tenant/domain/verify/{domainId} — DNS TXT 验证（仅平台管理员）
#[utoipa::path(
    post,
    path = "/system/tenant/domain/verify/{domainId}",
    params(("domainId" = i64, Path, description = "域名绑定 ID")),
    responses(
        (status = 200, description = "验证结果（verified 标识是否通过）", body = AjaxResult<TenantDomainVerifyVo>),
        (status = 400, description = "DNS TXT 查询失败 / 域名不可验证"),
        (status = 403, description = "仅平台管理员可管理域名"),
        (status = 404, description = "域名不存在"),
    ),
    tag = "system-tenant-domain"
)]
pub async fn verify(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Path(domain_id): Path<i64>,
) -> Result<AjaxResult<TenantDomainVerifyVo>, AppError> {
    let vo = state
        .tenant_domain_service
        .verify(domain_id, operator.username(), operator.tenant_id())
        .await?;
    // 审计 target_tenant_id：由域名归属租户回填
    target_tenant.set(vo.tenant_id);
    Ok(AjaxResult::success(vo))
}

/// PUT /system/tenant/domain/primary — 设为主域名（仅平台管理员）
#[utoipa::path(
    put,
    path = "/system/tenant/domain/primary",
    request_body = TenantDomainIdDto,
    responses(
        (status = 200, description = "设置成功", body = AjaxResult<TenantDomainVo>),
        (status = 400, description = "域名未验证，不能设为主域名"),
        (status = 403, description = "仅平台管理员可管理域名"),
        (status = 404, description = "域名不存在"),
    ),
    tag = "system-tenant-domain"
)]
pub async fn set_primary(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Json(dto): Json<TenantDomainIdDto>,
) -> Result<AjaxResult<TenantDomainVo>, AppError> {
    let vo = state
        .tenant_domain_service
        .set_primary(dto, operator.username(), operator.tenant_id())
        .await?;
    target_tenant.set(vo.tenant_id);
    Ok(AjaxResult::success(vo))
}

/// PUT /system/tenant/domain/changeStatus — 域名启停（仅平台管理员）
#[utoipa::path(
    put,
    path = "/system/tenant/domain/changeStatus",
    request_body = TenantDomainStatusDto,
    responses(
        (status = 200, description = "操作成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 403, description = "仅平台管理员可管理域名"),
        (status = 404, description = "域名不存在"),
    ),
    tag = "system-tenant-domain"
)]
pub async fn change_status(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Json(dto): Json<TenantDomainStatusDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let tid = state
        .tenant_domain_service
        .change_status(dto, operator.username(), operator.tenant_id())
        .await?;
    target_tenant.set(tid);
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/tenant/domain/{domainId} — 删除域名绑定（仅平台管理员）
#[utoipa::path(
    delete,
    path = "/system/tenant/domain/{domainId}",
    params(("domainId" = i64, Path, description = "域名绑定 ID")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 403, description = "仅平台管理员可管理域名"),
        (status = 404, description = "域名不存在"),
    ),
    tag = "system-tenant-domain"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Path(domain_id): Path<i64>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let tid = state
        .tenant_domain_service
        .remove(domain_id, operator.username(), operator.tenant_id())
        .await?;
    target_tenant.set(tid);
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// 供 router 挂载的类型自检（避免 unused import 告警）
#[allow(dead_code)]
fn _type_assert(_s: &SysTenantDomainService) {}
