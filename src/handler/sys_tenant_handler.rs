// stepby-axum/src/handler/sys_tenant_handler.rs
//! 租户管理 Handler（多租户 Phase 3：事实源 = `sys_tenant`，主键为 `tenant_id`）
//!
//! 接口路径与返回格式对齐 stepby-vue 前端调用规范：
//! - GET    /system/tenant/list            租户列表（平台全量；租户操作者仅本租户）
//! - GET    /system/tenant/{tenantId}      租户详情
//! - POST   /system/tenant                 新建租户（含根部门/默认角色/管理员初始化，仅平台）
//! - PUT    /system/tenant                 修改租户（平台可改全部；租户仅名称/联系人/备注）
//! - PUT    /system/tenant/changeStatus    租户启停（停用立即吊销该租户全部会话，仅平台）
//! - DELETE /system/tenant/{tenantId}      删除租户（软删回收站；租户内仍有用户时拒绝，仅平台）
//! - PUT    /system/tenant/restore/{tenantId}  恢复租户（回收站 → 停用态，仅平台）

use axum::Json;
use axum::extract::{Path, Query, State};
use std::sync::Arc;

use crate::common::{AjaxResult, AppError};
use crate::middleware::{Operator, TargetTenant};
use crate::service::event_outbox_service as outbox;
use crate::service::sys_tenant_service::{
    PackageFeaturesUpdateDto, PackageFeaturesVo, SysTenantService, TenantAddDto, TenantEditDto,
    TenantPackageOptionVo, TenantQueryDto, TenantStatusDto, TenantVo,
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
    operator: Operator,
    Query(query): Query<TenantQueryDto>,
) -> Result<AjaxResult<Vec<TenantVo>>, AppError> {
    let list = state
        .tenant_service
        .list(
            query,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(list))
}

/// GET /system/tenant/{tenantId} — 租户详情
#[utoipa::path(
    get,
    path = "/system/tenant/{tenantId}",
    params(("tenantId" = i64, Path, description = "租户 ID（独立 id 空间）")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<TenantVo>),
        (status = 404, description = "租户不存在"),
        (status = 403, description = "跨租户访问被拒绝"),
    ),
    tag = "system-tenant"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(tenant_id): Path<i64>,
) -> Result<AjaxResult<TenantVo>, AppError> {
    let vo = state
        .tenant_service
        .get_info(tenant_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/tenant — 新建租户（仅平台管理员）
#[utoipa::path(
    post,
    path = "/system/tenant",
    request_body = TenantAddDto,
    responses(
        (status = 200, description = "创建成功（含一次性返回的租户管理员初始密码）", body = AjaxResult<TenantVo>),
        (status = 400, description = "参数错误"),
        (status = 403, description = "仅平台管理员可新建租户"),
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
        .add(dto, operator.username(), operator.tenant_id())
        .await?;
    // 出站领域事件（`[events].outbound`，默认 `off` = 一个字节都不发）：
    // fire-and-forget，推送失败不影响创建结果
    outbox::spawn_emit(
        state.config.events.clone(),
        outbox::EVENT_TENANT_CREATED,
        serde_json::json!({
            "tenantId": vo.tenant_id,
            "tenantCode": vo.tenant_code,
            "tenantName": vo.tenant_name,
            "operator": operator.username(),
        }),
    );
    // Webhook 事件目录（开放域）：创建事务已提交，派发 tenant.created（subscribed_events 过滤口径）
    crate::service::sys_web_hook_service::emit_event(
        &state,
        "tenant.created",
        serde_json::json!({
            "tenantId": vo.tenant_id,
            "tenantCode": vo.tenant_code,
            "tenantName": vo.tenant_name,
            "operator": operator.username(),
        }),
    )
    .await;
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
        (status = 403, description = "租户越权修改平台分配项（套餐/配额/到期）"),
    ),
    tag = "system-tenant"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Json(dto): Json<TenantEditDto>,
) -> Result<AjaxResult<TenantVo>, AppError> {
    // 多租户 Phase 3：记录被操作租户，供审计 target_tenant_id（平台代管场景）
    target_tenant.set(dto.tenant_id);
    let vo = state
        .tenant_service
        .edit(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /system/tenant/changeStatus — 租户启停（仅平台管理员）
#[utoipa::path(
    put,
    path = "/system/tenant/changeStatus",
    request_body = TenantStatusDto,
    responses(
        (status = 200, description = "操作成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 403, description = "仅平台管理员可启停租户"),
    ),
    tag = "system-tenant"
)]
pub async fn change_status(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Json(dto): Json<TenantStatusDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // 多租户 Phase 3：记录被操作租户，供审计 target_tenant_id
    target_tenant.set(dto.tenant_id);
    // 事件载荷需在 dto 被消费前取出
    let (event_tenant_id, event_status) = (dto.tenant_id, dto.status.clone());
    state
        .tenant_service
        .change_status(dto, operator.username(), operator.tenant_id())
        .await?;
    // 出站领域事件（默认 off = 不发）：租户启停（停用同时会触发全链断链，见 P0-1）
    outbox::spawn_emit(
        state.config.events.clone(),
        outbox::EVENT_TENANT_STATUS_CHANGED,
        serde_json::json!({
            "tenantId": event_tenant_id,
            "status": event_status,
            "operator": operator.username(),
        }),
    );
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/tenant/{tenantId} — 删除租户（仅平台管理员）
#[utoipa::path(
    delete,
    path = "/system/tenant/{tenantId}",
    params(("tenantId" = i64, Path, description = "租户 ID（独立 id 空间）")),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "租户内仍有用户"),
        (status = 403, description = "仅平台管理员可删除租户"),
    ),
    tag = "system-tenant"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Path(tenant_id): Path<i64>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // 多租户 Phase 3：记录被删租户，供审计 target_tenant_id
    target_tenant.set(tenant_id);
    state
        .tenant_service
        .remove(tenant_id, operator.username(), operator.tenant_id())
        .await?;
    // 出站领域事件（默认 off = 不发）：租户删除（软删进入回收站）
    outbox::spawn_emit(
        state.config.events.clone(),
        outbox::EVENT_TENANT_DELETED,
        serde_json::json!({ "tenantId": tenant_id, "operator": operator.username() }),
    );
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// PUT /system/tenant/restore/{tenantId} — 恢复租户（仅平台管理员）
#[utoipa::path(
    put,
    path = "/system/tenant/restore/{tenantId}",
    params(("tenantId" = i64, Path, description = "租户 ID（独立 id 空间）")),
    responses(
        (status = 200, description = "恢复成功（恢复为停用态，需显式启用）", body = AjaxResult<TenantVo>),
        (status = 400, description = "租户不在回收站"),
        (status = 403, description = "仅平台管理员可恢复租户"),
    ),
    tag = "system-tenant"
)]
pub async fn restore(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Path(tenant_id): Path<i64>,
) -> Result<AjaxResult<TenantVo>, AppError> {
    // 多租户 Phase 3：记录被恢复租户，供审计 target_tenant_id
    target_tenant.set(tenant_id);
    let vo = state
        .tenant_service
        .restore(tenant_id, operator.username(), operator.tenant_id())
        .await?;
    // 出站领域事件（默认 off = 不发）：租户从回收站恢复
    outbox::spawn_emit(
        state.config.events.clone(),
        outbox::EVENT_TENANT_RESTORED,
        serde_json::json!({ "tenantId": vo.tenant_id, "operator": operator.username() }),
    );
    Ok(AjaxResult::success(vo))
}

/// GET /system/tenant/package/options — 套餐下拉（仅平台管理员）
#[utoipa::path(
    get,
    path = "/system/tenant/package/options",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<TenantPackageOptionVo>>),
        (status = 403, description = "仅平台管理员可查询套餐名录"),
    ),
    tag = "system-tenant"
)]
pub async fn package_options(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<TenantPackageOptionVo>>, AppError> {
    let list = state
        .tenant_service
        .package_options(operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(list))
}

/// GET /system/tenant/package/{packageId}/features — 套餐能力位配置（仅平台管理员）
#[utoipa::path(
    get,
    path = "/system/tenant/package/{packageId}/features",
    params(("packageId" = i64, Path, description = "套餐 ID")),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<PackageFeaturesVo>),
        (status = 403, description = "仅平台管理员可查询套餐能力位"),
        (status = 404, description = "套餐不存在"),
    ),
    tag = "system-tenant"
)]
pub async fn package_features(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(package_id): Path<i64>,
) -> Result<AjaxResult<PackageFeaturesVo>, AppError> {
    let vo = state
        .tenant_service
        .package_features(package_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// PUT /system/tenant/package/features — 设置套餐能力位（仅平台管理员）
///
/// 写入后立即收敛该套餐下全部租户的角色菜单授权（关闭能力位需回收菜单，避免假入口）。
#[utoipa::path(
    put,
    path = "/system/tenant/package/features",
    request_body = PackageFeaturesUpdateDto,
    responses(
        (status = 200, description = "保存成功（返回保存后的完整配置）", body = AjaxResult<PackageFeaturesVo>),
        (status = 400, description = "能力位键未登记 / 模式非法 / 平台未开启该项"),
        (status = 403, description = "仅平台管理员可配置套餐能力位"),
        (status = 404, description = "套餐不存在"),
    ),
    tag = "system-tenant"
)]
pub async fn set_package_features(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<PackageFeaturesUpdateDto>,
) -> Result<AjaxResult<PackageFeaturesVo>, AppError> {
    let vo = state
        .tenant_service
        .set_package_features(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// 供 router 挂载的类型自检（避免 unused import 告警）
#[allow(dead_code)]
fn _type_assert(_s: &SysTenantService) {}
