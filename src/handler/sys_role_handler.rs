// stepby-axum/src/handler/sys_role_handler.rs
//! 角色模块 Handler（Axum 原生实现）
//!
//! 接口路径与返回格式对齐 stepby-vue 前端调用规范：
//! - GET    /system/role/list                       分页查询角色
//! - POST   /system/role                            新增角色
//! - PUT    /system/role                            修改角色
//! - DELETE /system/role/{id}                       删除角色（支持批量逗号分隔）
//! - GET    /system/role/{id}                       查询角色详情
//! - PUT    /system/role/changeStatus               启停角色
//! - PUT    /system/role/dataScope                  修改数据权限
//! - GET    /system/role/authUser/allocatedList     查询已授权用户列表
//! - GET    /system/role/authUser/unallocatedList   查询未授权用户列表
//! - PUT    /system/role/authUser/cancel            取消单个用户授权
//! - PUT    /system/role/authUser/cancelAll         批量取消用户授权
//! - PUT    /system/role/authUser/selectAll         批量授权用户选择
//! - GET    /system/role/deptTree/{roleId}          查询角色部门树

use axum::Json;
use axum::extract::{Form, Path, Query, State};
use axum::response::Response;
use garde::Validate;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::common::ValidatedJson;
use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::{
    AjaxResult, AppError, TableDataInfo, TreeSelectVo,
    excel::{CellValue, ExcelColumn, export_to_excel},
};
use crate::entity::sys_role::Model as SysRoleModel;
use crate::entity::sys_user::Model as SysUserModel;
use crate::middleware::{Operator, TargetTenant};
use crate::service::sys_role_service::{
    AuthUserQueryDto, AuthUserSelectDto, CancelAuthUserDto, DataScopeDto, RoleAddDto, RoleEditDto,
    RoleQueryDto, RoleVo,
};
use crate::state::AppState;
use crate::utils::parse_id_list;

// ==================== 辅助 DTO ====================

/// 启停角色请求体
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleStatusDto {
    #[garde(skip)]
    pub role_id: i64,
    #[garde(length(min = 1, max = 1))]
    pub status: String,
}

// ==================== Handler 实现 ====================

/// GET /system/role/list
/// 分页查询角色
#[utoipa::path(
    get,
    path = "/system/role/list",
    params(RoleQueryDto),
    responses(
        (status = 200, description = "查询成功", body = TableDataInfo<SysRoleModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-role"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<RoleQueryDto>,
) -> Result<TableDataInfo<SysRoleModel>, AppError> {
    // 数据权限（P0-R81-004）：传入 operator_user_id 进行 data_scope 过滤
    // P1 修复: fail-closed — JWT sub 解析失败时拒绝访问，防止绕过数据权限过滤
    let operator_user_id: i64 = operator.user_id().parse::<i64>().map_err(|_| {
        tracing::warn!(sub = %operator.user_id(), "角色列表: JWT sub 解析失败，拒绝访问");
        AppError::unauthorized(&crate::tr!("error.common.session_invalid"))
    })?;
    let (rows, total) = state
        .role_service
        .get_role_page(
            query,
            Some(operator_user_id),
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// POST /system/role/export
/// 导出角色列表为 Excel
///
/// 前端 download() 发送 application/x-www-form-urlencoded，使用 Form 提取器
#[utoipa::path(
    post,
    path = "/system/role/export",
    params(RoleQueryDto),
    responses(
        (status = 200, description = "导出成功", content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-role"
)]
pub async fn export(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Form(query): Form<RoleQueryDto>,
) -> Result<Response, AppError> {
    // 数据权限（P0-R81-004）：导出需应用与 list 相同的 data_scope 过滤，防止越权导出
    // P1 修复: fail-closed — JWT sub 解析失败时拒绝访问
    let operator_user_id: i64 = operator.user_id().parse::<i64>().map_err(|_| {
        tracing::warn!(sub = %operator.user_id(), "角色导出: JWT sub 解析失败，拒绝访问");
        AppError::unauthorized(&crate::tr!("error.common.session_invalid"))
    })?;
    let rows = state
        .role_service
        .export_roles(
            query,
            Some(operator_user_id),
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;

    let columns = [
        ExcelColumn {
            key: "roleId",
            header: ("角色编号", "Role ID"),
            getter: |r: &SysRoleModel| CellValue::Text(r.role_id.to_string().into()),
        },
        ExcelColumn {
            key: "roleName",
            header: ("角色名称", "Role Name"),
            getter: |r: &SysRoleModel| CellValue::Text(r.role_name.clone().into()),
        },
        ExcelColumn {
            key: "roleKey",
            header: ("权限字符", "Permission Key"),
            getter: |r: &SysRoleModel| CellValue::Text(r.role_key.clone().into()),
        },
        ExcelColumn {
            key: "roleSort",
            header: ("显示顺序", "Sort"),
            getter: |r: &SysRoleModel| CellValue::Number(r.role_sort as f64),
        },
        ExcelColumn {
            key: "status",
            header: ("状态", "Status"),
            getter: |r: &SysRoleModel| {
                CellValue::Text(
                    if r.status == "0" {
                        crate::tr!("common.status.normal")
                    } else {
                        crate::tr!("common.status.disabled")
                    }
                    .into(),
                )
            },
        },
        ExcelColumn {
            key: "createTime",
            header: ("创建时间", "Create Time"),
            getter: |r: &SysRoleModel| CellValue::from_opt_datetime(r.create_time),
        },
        ExcelColumn {
            key: "remark",
            header: ("备注", "Remark"),
            getter: |r: &SysRoleModel| CellValue::Text(r.remark.clone().unwrap_or_default().into()),
        },
    ];

    export_to_excel(&crate::tr!("excel.sheet.role"), "role", &columns, &rows).await
}

/// GET /system/role/{id}
/// 查询角色详情（含 menu_ids）
#[utoipa::path(
    get,
    path = "/system/role/{id}",
    params(
        ("id" = i64, Path, description = "角色 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<RoleVo>),
        (status = 404, description = "角色不存在"),
    ),
    tag = "system-role"
)]
pub async fn get_info_by_id(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(role_id): Path<i64>,
) -> Result<AjaxResult<RoleVo>, AppError> {
    // P0-6：传入 operator_user_id 校验角色在数据范围内（此前可读取任意角色详情含 menu_ids）
    // b95：再按操作者租户校验归属——数据范围与租户边界是两道不同的闸
    let operator_user_id: Option<i64> = operator.user_id().parse().ok();
    let vo = state
        .role_service
        .get_role_by_id_scoped(role_id, operator_user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success(vo))
}

/// POST /system/role
/// 新增角色
#[utoipa::path(
    post,
    path = "/system/role",
    request_body = RoleAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或角色权限字符重复"),
    ),
    tag = "system-role"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<RoleAddDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let role = state
        .role_service
        .add_role(dto, operator.username(), operator.tenant_id())
        .await?;
    // Webhook 事件目录（开放域）：新增事务已提交，派发 role.created
    // P0 跨租户修复：tenant_id 取事件主体（新角色）租户（与 payload tenantId 同源）
    crate::service::sys_web_hook_service::emit_event(
        &state,
        "role.created",
        serde_json::json!({
            "roleId": role.role_id,
            "roleName": role.role_name,
            "roleKey": role.role_key,
            "tenantId": role.tenant_id,
            "operator": operator.username(),
        }),
        role.tenant_id,
    )
    .await;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.add_role",
        name = role.role_name
    )))
}

/// PUT /system/role
/// 修改角色
#[utoipa::path(
    put,
    path = "/system/role",
    request_body = RoleEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "角色不存在"),
    ),
    tag = "system-role"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Json(dto): Json<RoleEditDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // 多租户 Phase 3：记录被操作角色所属租户，供审计 target_tenant_id（平台代管场景）
    // b71 吞错治理：归属预读失败必须留痕，不得静默回落到操作者租户。
    match state.role_service.get_role_by_id(dto.role_id, None).await {
        Ok(vo) => target_tenant.set(vo.role.tenant_id),
        Err(e) => {
            tracing::warn!(role_id = dto.role_id, error = %e, "审计归属预读失败，target_tenant_id 回落操作者租户")
        }
    }
    // 提前取出目标角色 ID（dto 将被 edit_role 按值消费）
    let target_role_id = dto.role_id;
    state
        .role_service
        .edit_role(dto, operator.username(), operator.tenant_id())
        .await?;
    // Webhook 事件目录（开放域）：编辑事务已提交，派发 role.updated
    // P0 跨租户修复：tenant_id 取操作者租户（与 payload tenantId 同源），事件仅投递给同租户回调
    crate::service::sys_web_hook_service::emit_event(
        &state,
        "role.updated",
        serde_json::json!({
            "roleId": target_role_id,
            "tenantId": operator.tenant_id(),
            "operator": operator.username(),
        }),
        operator.tenant_id(),
    )
    .await;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/role/{ids}
/// 删除角色（支持批量逗号分隔的 String Path）
#[utoipa::path(
    delete,
    path = "/system/role/{ids}",
    params(
        ("ids" = String, Path, description = "角色 ID 列表（逗号分隔）")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "角色 ID 不合法或不允许删除超管角色"),
    ),
    tag = "system-role"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Path(ids): Path<String>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // 支持逗号分隔的批量删除
    let role_ids: Vec<i64> = parse_id_list::<i64>(&ids)?;

    if role_ids.is_empty() {
        return Err(AppError::bad_request(&crate::tr!("error.role.id_empty")));
    }

    if role_ids.len() > MAX_BATCH_DELETE_SIZE {
        return Err(AppError::bad_request(&crate::tr!(
            "error.common.batch_size_exceeded",
            max = MAX_BATCH_DELETE_SIZE
        )));
    }

    // R8-API-008：调用批量原子事务方法，保证部分失败时回滚
    // 多租户 Phase 3：解析被删角色所属租户，全部可解析且唯一时记录审计 target_tenant_id
    // （跨多个租户或存在解析失败时保持 NULL，避免误标归属）
    //
    // b71 N+1 治理：与用户批量删除同族——原先逐 ID 调 `get_role_by_id`（每次附带菜单/权限
    // 装配）只为读 tenant_id；改走 service 的批量口径单条 `is_in` 查询。
    {
        let tid_map = state.role_service.tenant_ids_by_role_ids(&role_ids).await?;
        let distinct_ids: std::collections::HashSet<i64> = role_ids.iter().copied().collect();
        let all_resolved = distinct_ids.iter().all(|id| tid_map.contains_key(id));
        let mut resolved: Vec<i64> = distinct_ids
            .iter()
            .filter_map(|id| tid_map.get(id).copied())
            .collect();
        resolved.sort_unstable();
        resolved.dedup();
        if all_resolved && resolved.len() == 1 {
            target_tenant.set(resolved[0]);
        }
    }

    // 克隆一份用于事件派发（delete_roles 按值消费原列表）
    let deleted_role_ids = role_ids.clone();
    state
        .role_service
        .delete_roles(role_ids, operator.tenant_id())
        .await?;
    // Webhook 事件目录（开放域）：删除事务已提交，派发 role.deleted（含批量 ID 列表）
    // P0 跨租户修复：tenant_id 取操作者租户（与 payload tenantId 同源），事件仅投递给同租户回调
    crate::service::sys_web_hook_service::emit_event(
        &state,
        "role.deleted",
        serde_json::json!({
            "roleIds": deleted_role_ids,
            "tenantId": operator.tenant_id(),
            "operator": operator.username(),
        }),
        operator.tenant_id(),
    )
    .await;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

/// PUT /system/role/changeStatus
/// 启停角色
#[utoipa::path(
    put,
    path = "/system/role/changeStatus",
    request_body = RoleStatusDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或不允许停用超管角色"),
    ),
    tag = "system-role"
)]
pub async fn change_status(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<RoleStatusDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state
        .role_service
        .update_role_status(
            dto.role_id,
            &dto.status,
            operator.username(),
            operator.tenant_id(),
        )
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// PUT /system/role/dataScope
/// 修改角色数据权限
#[utoipa::path(
    put,
    path = "/system/role/dataScope",
    request_body = DataScopeDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "角色不存在"),
    ),
    tag = "system-role"
)]
pub async fn data_scope(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<DataScopeDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state
        .role_service
        .update_data_scope(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// GET /system/role/authUser/allocatedList
/// 查询角色已授权用户列表
#[utoipa::path(
    get,
    path = "/system/role/authUser/allocatedList",
    params(AuthUserQueryDto),
    responses(
        (status = 200, description = "已授权用户分页列表", body = TableDataInfo<SysUserModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-role"
)]
pub async fn allocated_user_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<AuthUserQueryDto>,
) -> Result<TableDataInfo<SysUserModel>, AppError> {
    // P0-6：传入 operator_user_id 应用数据范围过滤（此前可枚举全部已授权用户）
    let operator_user_id: Option<i64> = operator.user_id().parse().ok();
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    let (rows, total) = state
        .role_service
        .get_allocated_users(query, operator_user_id, tenant_scope)
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/role/authUser/unallocatedList
/// 查询角色未授权用户列表
#[utoipa::path(
    get,
    path = "/system/role/authUser/unallocatedList",
    params(AuthUserQueryDto),
    responses(
        (status = 200, description = "未授权用户分页列表", body = TableDataInfo<SysUserModel>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-role"
)]
pub async fn unallocated_user_list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<AuthUserQueryDto>,
) -> Result<TableDataInfo<SysUserModel>, AppError> {
    // P0-6：传入 operator_user_id 应用数据范围过滤（此前可枚举全部用户）
    let operator_user_id: Option<i64> = operator.user_id().parse().ok();
    let tenant_scope = crate::common::tenant::tenant_scope(operator.tenant_id());
    let (rows, total) = state
        .role_service
        .get_unallocated_users(query, operator_user_id, tenant_scope)
        .await?;
    Ok(TableDataInfo::new(total, rows))
}

/// PUT /system/role/authUser/cancel
/// 取消单个用户授权
#[utoipa::path(
    put,
    path = "/system/role/authUser/cancel",
    request_body = CancelAuthUserDto,
    responses(
        (status = 200, description = "取消授权成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-role"
)]
pub async fn auth_user_cancel(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<CancelAuthUserDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;
    state
        .role_service
        .cancel_auth_user(dto, operator_user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.cancel_auth"
    )))
}

/// PUT /system/role/authUser/cancelAll
/// 批量取消用户授权（通过 URL query 传递 roleId + userIds）
#[utoipa::path(
    put,
    path = "/system/role/authUser/cancelAll",
    params(AuthUserSelectDto),
    responses(
        (status = 200, description = "批量取消授权成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-role"
)]
pub async fn auth_user_cancel_all(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(dto): Query<AuthUserSelectDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;
    state
        .role_service
        .cancel_all_auth_users(dto, operator_user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.cancel_auth"
    )))
}

/// PUT /system/role/authUser/selectAll
/// 批量授权用户选择（通过 URL query 传递 roleId + userIds）
#[utoipa::path(
    put,
    path = "/system/role/authUser/selectAll",
    params(AuthUserSelectDto),
    responses(
        (status = 200, description = "批量授权成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-role"
)]
pub async fn auth_user_select_all(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(dto): Query<AuthUserSelectDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let operator_user_id: i64 = operator
        .user_id()
        .parse()
        .map_err(|_| AppError::internal(&crate::tr!("error.user.operator_id_parse_failed")))?;
    state
        .role_service
        .select_all_auth_users(dto, operator_user_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.auth")))
}

/// GET /system/role/deptTree/{roleId}
/// 查询角色部门树（含已勾选部门 ID）
///
/// 返回结构对齐前端 RoleDeptTreeResult extends AjaxResult：
/// `{ code, msg, checkedKeys, depts }`（字段在顶层，非 data 字段内）
#[utoipa::path(
    get,
    path = "/system/role/deptTree/{roleId}",
    params(
        ("roleId" = i64, Path, description = "角色 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = RoleDeptTreeResult),
        (status = 404, description = "角色不存在"),
    ),
    tag = "system-role"
)]
pub async fn dept_tree_select(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(role_id): Path<i64>,
) -> Result<RoleDeptTreeResult, AppError> {
    let vo = state
        .role_service
        .get_dept_tree(role_id, operator.tenant_id())
        .await?;
    Ok(RoleDeptTreeResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        checked_keys: vo.checked_keys,
        depts: vo.depts,
    })
}

// ==================== 顶层响应类型 ====================

/// 角色部门树响应（对齐前端 RoleDeptTreeResult extends AjaxResult）
///
/// checkedKeys 和 depts 字段直接挂在响应根对象上。
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleDeptTreeResult {
    pub code: i32,
    pub msg: String,
    pub checked_keys: Vec<i64>,
    pub depts: Vec<TreeSelectVo>,
}

crate::impl_into_response!(RoleDeptTreeResult);

/// GET /system/role/optionselect
/// 角色下拉选项（启用角色，租户行级过滤；数据权限规则页等场景）
#[utoipa::path(
    get,
    path = "/system/role/optionselect",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<crate::service::sys_role_service::RoleOptionVo>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-role"
)]
pub async fn optionselect(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<crate::service::sys_role_service::RoleOptionVo>>, AppError> {
    let rows = state
        .role_service
        .list_role_options(crate::common::tenant::tenant_scope(operator.tenant_id()))
        .await?;
    Ok(AjaxResult::success(rows))
}
