// stepby-axum/src/router/sys_menu_router.rs
//! 菜单模块路由注册

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_menu_handler;
use crate::middleware::platform_guard::platform_only_guard;
use crate::state::AppState;

/// 菜单模块路由（需挂在鉴权中间件下）
///
/// 拆分口径（b95）：
/// - **菜单定义面**（列表 / 详情 / 新增 / 修改 / 排序 / 删除）是平台专属：`sys_menu`
///   是全局表（无 tenant_id），租户一旦可写就能改 perms 或把平台专属菜单挂进自己的
///   授权面，故整组挂 [`platform_only_guard`]，租户操作者一律 403。
/// - **角色授权用的只读菜单树**（`treeselect` / `roleMenuTreeselect`）**不挂**平台守卫：
///   租户管理员给本租角色分配菜单时必须读它。把它们一起圈掉会让角色页的菜单树静默
///   变空（前端 catch 成空数组），保存时把角色授权整体清掉——这不是"更安全"，是
///   静默的数据破坏。租户可见面由服务层按**可授予权限**过滤（与保存前门禁同一把尺），
///   所以"看得见"与"存得下"不会分家。
pub fn menu_routes() -> Router<Arc<AppState>> {
    menu_definition_routes().merge(menu_role_tree_routes())
}

/// 平台专属的菜单定义面。
fn menu_definition_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET /system/menu/list 菜单列表
        .route("/system/menu/list", get(sys_menu_handler::list))
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
        .route_layer(axum::middleware::from_fn(platform_only_guard))
}

/// 角色授权用的只读菜单树（平台与租户都可达，服务层按租户过滤可授予面）。
fn menu_role_tree_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET /system/menu/treeselect 菜单下拉树
        .route("/system/menu/treeselect", get(sys_menu_handler::treeselect))
        // GET /system/menu/roleMenuTreeselect/{roleId} 角色菜单下拉树
        .route(
            "/system/menu/roleMenuTreeselect/{roleId}",
            get(sys_menu_handler::role_menu_treeselect),
        )
}
