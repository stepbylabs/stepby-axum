// axum-backend/src/router/sys_user_router.rs
//! 用户模块路由注册

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_user_handler;
use crate::state::AppState;

/// 用户模块路由（需挂在鉴权中间件下）
pub fn user_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET /system/user/list 分页查询用户
        .route("/system/user/list", get(sys_user_handler::list))
        // POST /system/user/export 导出用户列表
        .route("/system/user/export", post(sys_user_handler::export))
        // POST /system/user/importTemplate 下载导入模板
        .route(
            "/system/user/importTemplate",
            post(sys_user_handler::import_template),
        )
        // POST /system/user/importData 批量导入用户
        .route(
            "/system/user/importData",
            post(sys_user_handler::import_data),
        )
        // POST /system/user 新增用户
        .route("/system/user", post(sys_user_handler::add))
        // PUT /system/user 修改用户
        .route("/system/user", put(sys_user_handler::edit))
        // PUT /system/user/changeStatus 启停用户
        .route(
            "/system/user/changeStatus",
            put(sys_user_handler::change_status),
        )
        // PUT /system/user/resetPwd 重置密码
        .route("/system/user/resetPwd", put(sys_user_handler::reset_pwd))
        // PUT /system/user/profile/updatePwd 个人改密
        .route(
            "/system/user/profile/updatePwd",
            put(sys_user_handler::update_profile_pwd),
        )
        // GET /system/user/profile 个人信息
        // PUT /system/user/profile 修改个人信息
        .route(
            "/system/user/profile",
            get(sys_user_handler::get_profile).put(sys_user_handler::update_profile),
        )
        // POST /system/user/profile/avatar 头像上传（multipart）
        .route(
            "/system/user/profile/avatar",
            post(sys_user_handler::avatar_upload),
        )
        // GET /system/user/deptTree 部门下拉树
        .route(
            "/system/user/deptTree",
            get(sys_user_handler::dept_tree_select),
        )
        // GET /system/user/ 获取角色列表（用户表单下拉用）
        .route(
            "/system/user/",
            get(sys_user_handler::get_roles_for_user_form),
        )
        // PUT /system/user/authRole 分配用户角色
        .route("/system/user/authRole", put(sys_user_handler::auth_role))
        // GET /system/user/authRole/{userId} 查询用户授权角色
        .route(
            "/system/user/authRole/{userId}",
            get(sys_user_handler::auth_role_get),
        )
        // GET /system/user/{userId}/anonymize/precheck GDPR 用户匿名化预检（dry-run）
        .route(
            "/system/user/{userId}/anonymize/precheck",
            get(sys_user_handler::anonymize_precheck),
        )
        // POST /system/user/{userId}/anonymize GDPR 用户匿名化执行（不可逆）
        .route(
            "/system/user/{userId}/anonymize",
            post(sys_user_handler::anonymize_user),
        )
        // DELETE /system/user/{id} 删除用户
        .route("/system/user/{id}", delete(sys_user_handler::remove))
        // GET /system/user/{id} 查询用户详情
        .route("/system/user/{id}", get(sys_user_handler::get_info_by_id))
}
