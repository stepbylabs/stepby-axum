//! 岗位模块路由注册
//!
//! 路由结构：
//! - /system/post/list            GET    分页查询岗位
//! - /system/post/optionselect    GET    查询全部岗位（下拉用）
//! - /system/post/export          POST   导出岗位列表
//! - /system/post                 POST   新增岗位
//! - /system/post                 PUT    修改岗位
//! - /system/post/{postId}        GET    查询岗位详情
//! - /system/post/{postIds}       DELETE 批量删除岗位

use std::sync::Arc;
use axum::Router;
use axum::routing::{delete, get, post, put};

use crate::handler::sys_post_handler;
use crate::state::AppState;

/// 岗位模块路由
pub fn post_routes() -> Router<Arc<AppState>> {
    Router::new()
        // GET /system/post/list 分页查询岗位
        .route("/system/post/list", get(sys_post_handler::list))
        // GET /system/post/optionselect 查询全部岗位（下拉用，仅需登录）
        .route("/system/post/optionselect", get(sys_post_handler::optionselect))
        // POST /system/post/export 导出岗位列表
        .route("/system/post/export", post(sys_post_handler::export))
        // POST /system/post 新增岗位
        .route("/system/post", post(sys_post_handler::add))
        // PUT /system/post 修改岗位
        .route("/system/post", put(sys_post_handler::edit))
        // GET /system/post/{postId} 查询岗位详情
        .route("/system/post/{postId}", get(sys_post_handler::get_info))
        // DELETE /system/post/{postIds} 批量删除岗位
        .route("/system/post/{postId}", delete(sys_post_handler::remove))
}
