//! 数据备份/恢复路由注册
//!
//! 路由结构：
//! - /system/backup/* — 备份日志（6 个接口）

use std::sync::Arc;
use axum::Router;
use axum::routing::{get, post};

use crate::handler::sys_backup_handler;
use crate::state::AppState;

/// 备份管理路由
pub fn backup_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/system/backup/list", get(sys_backup_handler::list))
        .route("/system/backup/{backupId}", get(sys_backup_handler::get_info).delete(sys_backup_handler::remove))
        .route("/system/backup", post(sys_backup_handler::create))
        .route("/system/backup/restore/{backupId}", post(sys_backup_handler::restore))
        .route("/system/backup/download/{backupId}", get(sys_backup_handler::download))
}
