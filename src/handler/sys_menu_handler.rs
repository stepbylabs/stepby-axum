// backend-axum/src/handler/sys_menu_handler.rs
//! 菜单模块 Handler（Axum 原生实现）
//!
//! 接口路径与返回格式对齐 frontend-vue 前端调用规范：
//! - GET    /system/menu/list                        菜单列表（扁平）
//! - POST   /system/menu                             新增菜单
//! - PUT    /system/menu                             修改菜单
//! - PUT    /system/menu/updateSort                  保存菜单排序
//! - DELETE /system/menu/{id}                        删除菜单
//! - GET    /system/menu/{id}                        查询菜单详情
//! - GET    /system/menu/treeselect                  菜单下拉树（返回 TreeSelect 格式）
//! - GET    /system/menu/roleMenuTreeselect/{roleId} 角色菜单下拉树（menus/checkedKeys 在顶层）

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

use crate::common::{AjaxResult, AppError, TreeSelectVo};
use crate::entity::sys_menu::Model as SysMenuModel;
use crate::middleware::Operator;
use crate::service::sys_menu_service::{MenuAddDto, MenuEditDto, MenuQueryDto, MenuSortDto};
use crate::state::AppState;

// ==================== Handler 实现 ====================

/// GET /system/menu/list
/// 菜单列表（扁平，前端自行组装树）
#[utoipa::path(
    get,
    path = "/system/menu/list",
    params(MenuQueryDto),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<SysMenuModel>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-menu"
)]
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<MenuQueryDto>,
) -> Result<AjaxResult<Vec<SysMenuModel>>, AppError> {
    let list = state.menu_service.get_menu_list(query).await?;
    Ok(AjaxResult::success(list))
}

/// GET /system/menu/treeselect
/// 菜单下拉树（对齐前端 treeselect，返回 AjaxResult<TreeSelect[]>）
///
/// 返回 TreeSelect 格式 `{ id, label, disabled, children }`，非完整 SysMenuModel。
#[utoipa::path(
    get,
    path = "/system/menu/treeselect",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<Vec<TreeSelectVo>>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-menu"
)]
pub async fn treeselect(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<Vec<TreeSelectVo>>, AppError> {
    let tree = state.menu_service.get_menu_tree_select().await?;
    Ok(AjaxResult::success(tree))
}

/// GET /system/menu/roleMenuTreeselect/{roleId}
/// 角色菜单下拉树（对齐前端 RoleMenuTreeselectResult extends AjaxResult）
///
/// 返回结构：`{ code, msg, checkedKeys, menus }`（menus/checkedKeys 在顶层，非 data 字段内）。
/// menus 为 TreeSelect 格式。
#[utoipa::path(
    get,
    path = "/system/menu/roleMenuTreeselect/{roleId}",
    params(
        ("roleId" = i64, Path, description = "角色 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = RoleMenuTreeResult),
        (status = 404, description = "角色不存在"),
    ),
    tag = "system-menu"
)]
pub async fn role_menu_treeselect(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Path(role_id): Path<i64>,
) -> Result<RoleMenuTreeResult, AppError> {
    // P0-6：传入 operator_user_id 校验角色在数据范围内（与 role get_info 一致）
    let operator_user_id: Option<i64> = operator.user_id().parse().ok();
    let role_vo = state
        .role_service
        .get_role_by_id(role_id, operator_user_id)
        .await?;
    let menus = state.menu_service.get_menu_tree_select().await?;
    Ok(RoleMenuTreeResult {
        code: 200,
        msg: crate::tr!("msg.success.default"),
        checked_keys: role_vo.menu_ids,
        menus,
    })
}

/// GET /system/menu/{id}
/// 查询菜单详情
#[utoipa::path(
    get,
    path = "/system/menu/{id}",
    params(
        ("id" = i64, Path, description = "菜单 ID")
    ),
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<SysMenuModel>),
        (status = 404, description = "菜单不存在"),
    ),
    tag = "system-menu"
)]
pub async fn get_info_by_id(
    State(state): State<Arc<AppState>>,
    Path(menu_id): Path<i64>,
) -> Result<AjaxResult<SysMenuModel>, AppError> {
    let menu = state.menu_service.get_menu_by_id(menu_id).await?;
    Ok(AjaxResult::success(menu))
}

/// POST /system/menu
/// 新增菜单
#[utoipa::path(
    post,
    path = "/system/menu",
    request_body = MenuAddDto,
    responses(
        (status = 200, description = "新增成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-menu"
)]
pub async fn add(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<MenuAddDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    let menu = state
        .menu_service
        .add_menu(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!(
        "msg.success.add_menu",
        name = menu.menu_name
    )))
}

/// PUT /system/menu
/// 修改菜单
#[utoipa::path(
    put,
    path = "/system/menu",
    request_body = MenuEditDto,
    responses(
        (status = 200, description = "修改成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 404, description = "菜单不存在"),
    ),
    tag = "system-menu"
)]
pub async fn edit(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<MenuEditDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state
        .menu_service
        .edit_menu(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.edit")))
}

/// PUT /system/menu/updateSort
/// 保存菜单排序（对齐前端 MenuSortParams：menuIds/orderNums 逗号分隔字符串）
#[utoipa::path(
    put,
    path = "/system/menu/updateSort",
    request_body = MenuSortDto,
    responses(
        (status = 200, description = "排序成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
    ),
    tag = "system-menu"
)]
pub async fn update_sort(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<MenuSortDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state
        .menu_service
        .update_menu_sort(dto, operator.username())
        .await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.sort")))
}

/// DELETE /system/menu/{id}
/// 删除菜单
#[utoipa::path(
    delete,
    path = "/system/menu/{id}",
    params(
        ("id" = i64, Path, description = "菜单 ID")
    ),
    responses(
        (status = 200, description = "删除成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "菜单不存在子菜单不允许删除"),
    ),
    tag = "system-menu"
)]
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(menu_id): Path<i64>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    state.menu_service.delete_menu(menu_id).await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.delete")))
}

// ==================== 顶层响应类型 ====================

/// 角色菜单树响应（对齐前端 RoleMenuTreeselectResult extends AjaxResult）
///
/// checkedKeys 和 menus 字段直接挂在响应根对象上。
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleMenuTreeResult {
    pub code: i32,
    pub msg: String,
    pub checked_keys: Vec<i64>,
    pub menus: Vec<TreeSelectVo>,
}

crate::impl_into_response!(RoleMenuTreeResult);
