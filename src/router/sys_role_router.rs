// stepby-axum/src/router/sys_role_router.rs
//! 角色模块路由注册

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_role_handler;
use crate::state::AppState;

/// 角色模块路由（需挂在鉴权中间件下）
pub fn role_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET /system/role/list 分页查询角色
        .route("/system/role/list", get(sys_role_handler::list))
        // POST /system/role 新增角色
        .route("/system/role", post(sys_role_handler::add))
        // PUT /system/role 修改角色
        .route("/system/role", put(sys_role_handler::edit))
        // PUT /system/role/changeStatus 启停角色
        .route(
            "/system/role/changeStatus",
            put(sys_role_handler::change_status),
        )
        // PUT /system/role/dataScope 修改数据权限
        .route("/system/role/dataScope", put(sys_role_handler::data_scope))
        // GET /system/role/authUser/allocatedList 查询已授权用户列表
        .route(
            "/system/role/authUser/allocatedList",
            get(sys_role_handler::allocated_user_list),
        )
        // GET /system/role/authUser/unallocatedList 查询未授权用户列表
        .route(
            "/system/role/authUser/unallocatedList",
            get(sys_role_handler::unallocated_user_list),
        )
        // PUT /system/role/authUser/cancel 取消单个用户授权
        .route(
            "/system/role/authUser/cancel",
            put(sys_role_handler::auth_user_cancel),
        )
        // PUT /system/role/authUser/cancelAll 批量取消用户授权
        .route(
            "/system/role/authUser/cancelAll",
            put(sys_role_handler::auth_user_cancel_all),
        )
        // PUT /system/role/authUser/selectAll 批量授权用户选择
        .route(
            "/system/role/authUser/selectAll",
            put(sys_role_handler::auth_user_select_all),
        )
        // DELETE /system/role/{id} 删除角色（支持批量逗号分隔）
        .route("/system/role/{id}", delete(sys_role_handler::remove))
        // POST /system/role/export 导出角色列表
        .route("/system/role/export", post(sys_role_handler::export))
        // GET /system/role/{id} 查询角色详情
        .route("/system/role/{id}", get(sys_role_handler::get_info_by_id))
        // GET /system/role/deptTree/{roleId} 查询角色部门树
        .route(
            "/system/role/deptTree/{roleId}",
            get(sys_role_handler::dept_tree_select),
        )
}
