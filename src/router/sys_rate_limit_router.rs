//! API 限流配置模块路由注册
//!
//! 路由结构：
//! - /system/rateLimit/list         分页查询（system:rateLimit:list）
//! - /system/rateLimit/export       导出（system:rateLimit:export）
//! - /system/rateLimit              新增/修改（system:rateLimit:add / system:rateLimit:edit）
//! - /system/rateLimit/{id}         详情（GET，system:rateLimit:query）
//! - /system/rateLimit/{id}         批量删除（DELETE，id 支持逗号分隔多个，system:rateLimit:remove）
//!
//! 注意：静态路由（list、export）需在动态路由 {id} 之前注册，
//! axum 0.8 优先匹配静态段。GET 和 DELETE 可共用同一动态路径，不冲突。

use axum::Router;
use axum::routing::{get, post, put};
use std::sync::Arc;

use crate::handler::sys_rate_limit_handler;
use crate::state::AppState;

/// API 限流配置模块路由
pub fn rate_limit_routes() -> Router<Arc<AppState>> {
    Router::new()
        // 静态路由优先注册
        .route("/system/rateLimit/list", get(sys_rate_limit_handler::list))
        .route(
            "/system/rateLimit/export",
            post(sys_rate_limit_handler::export),
        )
        // 集合资源
        .route("/system/rateLimit", post(sys_rate_limit_handler::add))
        .route("/system/rateLimit", put(sys_rate_limit_handler::edit))
        // 动态路由最后注册：GET（详情）和 DELETE（删除，id 支持逗号分隔）共用同一动态路径
        .route(
            "/system/rateLimit/{id}",
            get(sys_rate_limit_handler::get_info).delete(sys_rate_limit_handler::remove),
        )
}
