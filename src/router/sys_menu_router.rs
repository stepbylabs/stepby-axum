// backend-axum/src/router/sys_menu_router.rs
//! 菜单模块路由注册

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_menu_handler;
use crate::state::AppState;

/// 菜单模块路由（需挂在鉴权中间件下）
pub fn menu_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET /system/menu/list 菜单列表
        .route("/system/menu/list", get(sys_menu_handler::list))
        // GET /system/menu/treeselect 菜单下拉树
        .route("/system/menu/treeselect", get(sys_menu_handler::treeselect))
        // POST /system/menu 新增菜单
        .route("/system/menu", post(sys_menu_handler::add))
        // PUT /system/menu 修改菜单
        .route("/system/menu", put(sys_menu_handler::edit))
        // PUT /system/menu/updateSort 保存菜单排序
        .route(
            "/system/menu/updateSort",
            put(sys_menu_handler::update_sort),
        )
        // DELETE /system/menu/{id} 删除菜单
        .route("/system/menu/{id}", delete(sys_menu_handler::remove))
        // GET /system/menu/{id} 查询菜单详情
        .route("/system/menu/{id}", get(sys_menu_handler::get_info_by_id))
        // GET /system/menu/roleMenuTreeselect/{roleId} 角色菜单下拉树
        .route(
            "/system/menu/roleMenuTreeselect/{roleId}",
            get(sys_menu_handler::role_menu_treeselect),
        )
}
