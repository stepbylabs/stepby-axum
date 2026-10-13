//! 通用模块路由注册
//!
//! 路由结构：
//! - POST /common/upload             通用文件上传
//! - GET  /common/download           通用文件下载
//! - GET  /common/download/resource  通用资源下载
//! - GET  /common/global-search      全局搜索（跨白名单实体，逐域权限过滤）
//! - GET  /dashboard/stats           仪表盘聚合统计（U5：含 8 字段 + 最近操作日志）
//! - GET  /dashboard/user-stats      用户统计（U14：用户分布 + 30 天创建趋势）
//!
//! 注意：POST /common/upload 会被 oper_log_middleware 记录写操作日志。

use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, post};

use crate::handler::{common_handler, common_search_handler, upload_chunk_handler};
use crate::state::AppState;

/// 通用模块路由（需挂在鉴权中间件下）
pub fn common_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/common/upload", post(common_handler::upload))
        // G-10：分片上传/断点续传（init/part/complete 均受 protected 链同款中间件保护）
        .route(
            "/common/upload/chunk/init",
            post(upload_chunk_handler::chunk_init),
        )
        .route(
            "/common/upload/chunk/part",
            post(upload_chunk_handler::chunk_part),
        )
        .route(
            "/common/upload/chunk/session/{sessionId}",
            get(upload_chunk_handler::chunk_session),
        )
        .route(
            "/common/upload/chunk/complete",
            post(upload_chunk_handler::chunk_complete),
        )
        .route(
            "/common/upload/chunk/{sessionId}",
            delete(upload_chunk_handler::chunk_abort),
        )
        .route("/common/download", get(common_handler::download))
        .route(
            "/common/download/resource",
            get(common_handler::download_resource),
        )
        .route(
            "/common/global-search",
            get(common_search_handler::global_search),
        )
        .route("/dashboard/stats", get(common_handler::dashboard_stats))
        .route("/dashboard/user-stats", get(common_handler::user_stats))
}
