// axum-backend/src/handler/sys_role_handler.rs
//! 角色模块 Handler（Axum 原生实现）
//!
//! 接口路径与返回格式对齐 ref-salvo-admin / ruoyi-vue3-ts：
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

use std::sync::Arc;
use axum::extract::{Form, Path, Query, State};
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use garde::Validate;

use crate::common::constants::MAX_BATCH_DELETE_SIZE;
use crate::common::ValidatedJson;
use crate::common::{excel::{export_to_excel, CellValue, ExcelColumn}, AjaxResult, AppError, TableDataInfo, TreeSelectVo};
use crate::entity::sys_role::Model as SysRoleModel;
use crate::entity::sys_user::Model as SysUserModel;
use crate::middleware::Operator;
use crate::service::sys_role_service::{
    AuthUserQueryDto, AuthUserSelectDto, CancelAuthUserDto, DataScopeDto, RoleAddDto,
    RoleEditDto, RoleQueryDto, RoleVo,
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
    let operator_user_id: i64 = operator
        .user_id()
        .parse::<i64>()
        .map_err(|_| {
            tracing::warn!(sub = %operator.user_id(), "角色列表: JWT sub 解析失败，拒绝访问");
            AppError::unauthorized(&crate::tr!("error.common.session_invalid"))
        })?;
    let (rows, total) = state
        .role_service
        .get_role_page(query, Some(operator_user_id))
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
    let operator_user_id: i64 = operator
        .user_id()
        .parse::<i64>()
        .map_err(|_| {
            tracing::warn!(sub = %operator.user_id(), "角色导出: JWT sub 解析失败，拒绝访问");
            AppError::unauthorized(&crate::tr!("error.common.session_invalid"))
        })?;
    let rows = state.role_service.export_roles(query, Some(operator_user_id)).await?;

    let columns = [
        ExcelColumn { key: "roleId", header: ("角色编号", "Role ID"), getter: |r: &SysRoleModel| CellValue::Text(r.role_id.to_string().into()) },
        ExcelColumn { key: "roleName", header: ("角色名称", "Role Name"), getter: |r: &SysRoleModel| CellValue::Text(r.role_name.clone().into()) },
        ExcelColumn { key: "roleKey", header: ("权限字符", "Permission Key"), getter: |r: &SysRoleModel| CellValue::Text(r.role_key.clone().into()) },
        ExcelColumn { key: "roleSort", header: ("显示顺序", "Sort"), getter: |r: &SysRoleModel| CellValue::Text(r.role_sort.to_string().into()) },
        ExcelColumn { key: "status", header: ("状态", "Status"), getter: |r: &SysRoleModel| CellValue::Text(if r.status == "0" { crate::tr!("common.status.normal") } else { crate::tr!("common.status.disabled") }.into()) },
        ExcelColumn { key: "createTime", header: ("创建时间", "Create Time"), getter: |r: &SysRoleModel| CellValue::Text({
                r.create_time
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default()
                    .into()
            }) },
        ExcelColumn { key: "remark", header: ("备注", "Remark"), getter: |r: &SysRoleModel| CellValue::Text(r.remark.clone().unwrap_or_default().into()) },
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
    Path(role_id): Path<i64>,
) -> Result<AjaxResult<RoleVo>, AppError> {
    let vo = state.role_service.get_role_by_id(role_id).await?;
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
    let role = state.role_service.add_role(dto, operator.username()).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.add_role", name = role.role_name)))
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
    Json(dto): Json<RoleEditDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state.role_service.edit_role(dto, operator.username()).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/role/{ids}
/// 删除角色（支持批量逗号分隔，对齐 ref-salvo-admin 的 String Path）
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
    Path(ids): Path<String>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // 支持逗号分隔的批量删除
    let role_ids: Vec<i64> = parse_id_list::<i64>(&ids);

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
    state.role_service.delete_roles(role_ids).await?;
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
        .update_role_status(dto.role_id, &dto.status, operator.username())
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
        .update_data_scope(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// GET /system/role/authUser/allocatedList
/// 查询角色已授权用户列表
pub async fn allocated_user_list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthUserQueryDto>,
) -> Result<TableDataInfo<SysUserModel>, AppError> {
    let (rows, total) = state.role_service.get_allocated_users(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// GET /system/role/authUser/unallocatedList
/// 查询角色未授权用户列表
pub async fn unallocated_user_list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthUserQueryDto>,
) -> Result<TableDataInfo<SysUserModel>, AppError> {
    let (rows, total) = state.role_service.get_unallocated_users(query).await?;
    Ok(TableDataInfo::new(total, rows))
}

/// PUT /system/role/authUser/cancel
/// 取消单个用户授权
pub async fn auth_user_cancel(
    State(state): State<Arc<AppState>>,
    Json(dto): Json<CancelAuthUserDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state.role_service.cancel_auth_user(dto).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.cancel_auth")))
}

/// PUT /system/role/authUser/cancelAll
/// 批量取消用户授权（通过 URL query 传递 roleId + userIds）
pub async fn auth_user_cancel_all(
    State(state): State<Arc<AppState>>,
    Query(dto): Query<AuthUserSelectDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state.role_service.cancel_all_auth_users(dto).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.cancel_auth")))
}

/// PUT /system/role/authUser/selectAll
/// 批量授权用户选择（通过 URL query 传递 roleId + userIds）
pub async fn auth_user_select_all(
    State(state): State<Arc<AppState>>,
    Query(dto): Query<AuthUserSelectDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state.role_service.select_all_auth_users(dto).await?;
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
    Path(role_id): Path<i64>,
) -> Result<RoleDeptTreeResult, AppError> {
    let vo = state.role_service.get_dept_tree(role_id).await?;
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
