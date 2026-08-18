// axum-backend/src/router/sys_dept_router.rs
//! 部门模块路由注册
//!
//! 权限要求（通过 permission_middleware 集中配置，详见 middleware/permission.rs）：
//! - GET    /system/dept/list                  system:dept:list
//! - GET    /system/dept/list/exclude/{deptId} system:dept:list
//! - GET    /system/dept/treeselect            仅需登录（无细粒度权限）
//! - GET    /system/dept/{deptId}              system:dept:query
//! - POST   /system/dept                       system:dept:add
//! - PUT    /system/dept                       system:dept:edit
//! - DELETE /system/dept/{deptId}              system:dept:remove

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_dept_handler;
use crate::state::AppState;

/// 部门模块路由（需挂在鉴权中间件下）
pub fn dept_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET /system/dept/list 部门列表
        .route("/system/dept/list", get(sys_dept_handler::list))
        // GET /system/dept/list/exclude/{deptId} 排除节点的部门列表
        .route(
            "/system/dept/list/exclude/{deptId}",
            get(sys_dept_handler::list_exclude),
        )
        // GET /system/dept/treeselect 部门下拉树
        .route("/system/dept/treeselect", get(sys_dept_handler::treeselect))
        // POST /system/dept 新增部门
        .route("/system/dept", post(sys_dept_handler::add))
        // PUT /system/dept 修改部门
        .route("/system/dept", put(sys_dept_handler::edit))
        // PUT /system/dept/updateSort 保存部门排序
        .route(
            "/system/dept/updateSort",
            put(sys_dept_handler::update_sort),
        )
        // DELETE /system/dept/{deptId} 删除部门
        .route("/system/dept/{deptId}", delete(sys_dept_handler::remove))
        // GET /system/dept/{deptId} 查询部门详情
        .route("/system/dept/{deptId}", get(sys_dept_handler::get_info))
}
