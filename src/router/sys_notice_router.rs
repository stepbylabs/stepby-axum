//! 通知公告模块路由注册
//!
//! 路由结构：
//! - /system/notice/list            GET     分页查询通知公告
//! - /system/notice/listTop         GET     首页顶部公告列表
//! - /system/notice/readUsers/list  GET     查询公告已读用户列表
//! - /system/notice/{noticeId}      GET     查询通知公告详情
//! - /system/notice                 POST    新增通知公告
//! - /system/notice/markRead        POST    标记公告已读
//! - /system/notice/markReadAll     POST    批量标记公告已读（指定 IDs）
//! - /system/notice/markAllUnreadRead POST   标记当前用户所有未读为已读（跨页全部已读）
//! - /system/notice                 PUT     修改通知公告
//! - /system/notice/{noticeIds}     DELETE  批量删除通知公告
//!
//! 权限由 permission_middleware 中间件按 (method, path) 映射执行：
//! - system:notice:list / query / add / edit / remove

use axum::Router;
use axum::routing::{delete, get, post, put};
use std::sync::Arc;

use crate::handler::sys_notice_handler;
use crate::state::AppState;

/// 通知公告模块路由
pub fn notice_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET /system/notice/list 分页查询通知公告
        .route("/system/notice/list", get(sys_notice_handler::list))
        // GET /system/notice/listTop 首页顶部公告列表（静态路由优先于动态路由）
        .route("/system/notice/listTop", get(sys_notice_handler::list_top))
        // GET /system/notice/readUsers/list 查询公告已读用户列表（静态路由优先于动态路由）
        .route(
            "/system/notice/readUsers/list",
            get(sys_notice_handler::list_read_users),
        )
        // GET /system/notice/{noticeId} 查询通知公告详情
        .route(
            "/system/notice/{noticeId}",
            get(sys_notice_handler::get_info),
        )
        // POST /system/notice 新增通知公告
        .route("/system/notice", post(sys_notice_handler::add))
        // POST /system/notice/markRead 标记公告已读
        .route(
            "/system/notice/markRead",
            post(sys_notice_handler::mark_read),
        )
        // POST /system/notice/markReadAll 批量标记公告已读（指定 IDs）
        .route(
            "/system/notice/markReadAll",
            post(sys_notice_handler::mark_read_all),
        )
        // POST /system/notice/markAllUnreadRead 标记当前用户所有未读为已读（跨页"全部已读"）
        .route(
            "/system/notice/markAllUnreadRead",
            post(sys_notice_handler::mark_all_unread_read),
        )
        // PUT /system/notice 修改通知公告
        .route("/system/notice", put(sys_notice_handler::edit))
        // DELETE /system/notice/{noticeIds} 批量删除通知公告
        .route(
            "/system/notice/{noticeId}",
            delete(sys_notice_handler::remove),
        )
}
