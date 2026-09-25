// axum-backend/src/handler/sys_dept_handler.rs
//! 部门模块 Handler（Axum 原生实现）
//!
//! 接口路径与返回格式对齐 yebot-ui 前端调用规范：
//! - GET    /system/dept/list                  部门列表（扁平，前端组装树）
//! - GET    /system/dept/list/exclude/{deptId} 排除指定节点的部门列表（修改父部门选择用）
//! - GET    /system/dept/treeselect            部门下拉树（返回 TreeSelect 格式）
//! - GET    /system/dept/{deptId}              查询部门详情
//! - POST   /system/dept                       新增部门
//! - PUT    /system/dept                       修改部门
//! - DELETE /system/dept/{deptId}              删除部门

use axum::Json;
use axum::extract::{Path, Query, State};
use std::sync::Arc;

use crate::common::{AjaxResult, AppError, TreeSelectVo};
use crate::entity::sys_dept::Model as SysDeptModel;
use crate::middleware::{Operator, TargetTenant};
use crate::service::sys_dept_service::{DeptAddDto, DeptEditDto, DeptQueryDto, DeptSortDto};
use crate::state::AppState;

// ==================== Handler 实现 ====================

/// GET /system/dept/list
/// 部门列表（扁平，前端自行组装树）
#[utoipa::path(
    get,
    path = "/system/dept/list",
    params(DeptQueryDto),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<SysDeptModel>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-dept"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Query(query): Query<DeptQueryDto>,
) -> Result<AjaxResult<Vec<SysDeptModel>>, AppError> {
    // 数据权限（P0-R81-004）：传入 operator_user_id 进行 data_scope 过滤
    // P1 修复: fail-closed — JWT sub 解析失败时拒绝访问，防止绕过数据权限过滤
    // P2 修复: 错误消息改用 i18n key，避免硬编码中文
    let operator_user_id: i64 = operator.user_id().parse::<i64>().map_err(|_| {
        tracing::warn!(sub = %operator.user_id(), "部门列表: JWT sub 解析失败，拒绝访问");
        AppError::unauthorized(&crate::tr!("error.common.session_invalid"))
    })?;
    let list = state
        .dept_service
        .list_depts(
            query,
            Some(operator_user_id),
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(list))
}

/// PUT /system/dept/updateSort
/// 保存部门排序（对齐前端 DeptSortParams：deptIds/orderNums 逗号分隔字符串）
#[utoipa::path(
    put,
    path = "/system/dept/updateSort",
    request_body = DeptSortDto,
    responses(
        (status = 200, description = "排序成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-dept"
)]
pub async fn update_sort(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<DeptSortDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state
        .dept_service
        .update_dept_sort(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.sort")))
}

/// GET /system/dept/list/exclude/{deptId}
/// 排除指定节点及其子部门的部门列表（修改部门时选择父部门用）
#[utoipa::path(
    get,
    path = "/system/dept/list/exclude/{deptId}",
    params(
        ("deptId" = i64, Path, description = "部门 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<SysDeptModel>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-dept"
)]
pub async fn list_exclude(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dept_id): Path<i64>,
) -> Result<AjaxResult<Vec<SysDeptModel>>, AppError> {
    // P0-6：传入 operator_user_id 应用 data_scope 过滤（此前未过滤可枚举全部部门）
    let operator_user_id: Option<i64> = operator.user_id().parse().ok();
    let list = state
        .dept_service
        .list_exclude(
            dept_id,
            operator_user_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(list))
}

/// GET /system/dept/treeselect
/// 部门下拉树（对齐前端 treeselect，返回 AjaxResult<TreeSelect[]>）
///
/// 返回 TreeSelect 格式 `{ id, label, disabled, children }`，非完整 SysDeptModel。
#[utoipa::path(
    get,
    path = "/system/dept/treeselect",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<TreeSelectVo>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-dept"
)]
pub async fn treeselect(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<Vec<TreeSelectVo>>, AppError> {
    // P0-6：传入 operator_user_id 应用 data_scope 过滤（此前未过滤可枚举全部部门树）
    let operator_user_id: Option<i64> = operator.user_id().parse().ok();
    let tree = state
        .dept_service
        .build_dept_tree_select(
            operator_user_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(tree))
}

/// GET /system/dept/{deptId}
/// 查询部门详情
#[utoipa::path(
    get,
    path = "/system/dept/{deptId}",
    params(
        ("deptId" = i64, Path, description = "部门 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysDeptModel>),
        (status = 404, description = "部门不存在"),
    ),
    tag = "system-dept"
)]
pub async fn get_info(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(dept_id): Path<i64>,
) -> Result<AjaxResult<SysDeptModel>, AppError> {
    // P0-6：传入 operator_user_id 校验部门在数据范围内（不在则 404）
    let operator_user_id: Option<i64> = operator.user_id().parse().ok();
    let dept = state
        .dept_service
        .get_dept_by_id(
            dept_id,
            operator_user_id,
            crate::common::tenant::tenant_scope(operator.tenant_id()),
        )
        .await?;
    Ok(AjaxResult::success(dept))
}

/// POST /system/dept
/// 新增部门
#[utoipa::path(
    post,
    path = "/system/dept",
    request_body = DeptAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误或部门名称重复"),
    ),
    tag = "system-dept"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<DeptAddDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let dept = state
        .dept_service
        .add_dept(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.add_dept",
        name = dept.dept_name
    )))
}

/// PUT /system/dept
/// 修改部门
#[utoipa::path(
    put,
    path = "/system/dept",
    request_body = DeptEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "部门不存在"),
    ),
    tag = "system-dept"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Json(dto): Json<DeptEditDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // 多租户 Phase 3：记录被操作部门所属租户，供审计 target_tenant_id（平台代管场景）
    if let Ok(dept) = state
        .dept_service
        .get_dept_by_id(dto.dept_id, None, None)
        .await
    {
        target_tenant.set(dept.tenant_id);
    }
    state
        .dept_service
        .edit_dept(dto, operator.username(), operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// DELETE /system/dept/{deptId}
/// 删除部门
#[utoipa::path(
    delete,
    path = "/system/dept/{deptId}",
    params(
        ("deptId" = i64, Path, description = "部门 ID")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "存在子部门不允许删除"),
    ),
    tag = "system-dept"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    target_tenant: TargetTenant,
    Path(dept_id): Path<i64>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    // 多租户 Phase 3：记录被删部门所属租户，供审计 target_tenant_id（平台代管场景）
    if let Ok(dept) = state
        .dept_service
        .get_dept_by_id(dept_id, None, None)
        .await
    {
        target_tenant.set(dept.tenant_id);
    }
    state
        .dept_service
        .delete_dept(dept_id, operator.tenant_id())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}
