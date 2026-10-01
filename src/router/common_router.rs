//! 通用模块路由注册
//!
//! 路由结构：
//! - POST /common/upload             通用文件上传
//! - GET  /common/download           通用文件下载
//! - GET  /common/download/resource  通用资源下载
//! - GET  /dashboard/stats           仪表盘聚合统计（U5：含 8 字段 + 最近操作日志）
//! - GET  /dashboard/user-stats      用户统计（U14：用户分布 + 30 天创建趋势）
//!
//! 注意：POST /common/upload 会被 oper_log_middleware 记录写操作日志。

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::handler::common_handler;
use crate::state::AppState;

/// 通用模块路由（需挂在鉴权中间件下）
pub fn common_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/common/upload", post(common_handler::upload))
        .route("/common/download", get(common_handler::download))
        .route(
            "/common/download/resource",
            get(common_handler::download_resource),
        )
        .route("/dashboard/stats", get(common_handler::dashboard_stats))
        .route("/dashboard/user-stats", get(common_handler::user_stats))
}
