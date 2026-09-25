//! 数据备份/恢复路由注册
//!
//! 路由结构：
//! - /system/backup/* — 备份日志（6 个接口）
//!
//! 多租户安全（§27.13.4 / 原则 B）：整组 `/system/backup/*` 为**平台专属**能力
//! （备份为整库 pg_dump/mysqldump，下载面即全库数据；恢复会覆盖现库），
//! 挂 [`platform_only_guard`] 请求层守卫：租户操作者（含租户管理员）一律 403，
//! 作为 permission 层（`system:backup:*` 已移出租户可授集合）的第二道防线。

use axum::Router;
use axum::routing::{get, post};
use std::sync::Arc;

use crate::handler::sys_backup_handler;
use crate::middleware::platform_guard::platform_only_guard;
use crate::state::AppState;

/// 备份管理路由（平台专属，租户操作者 403）
pub fn backup_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/system/backup/list", get(sys_backup_handler::list))
        .route(
            "/system/backup/{backupId}",
            get(sys_backup_handler::get_info).delete(sys_backup_handler::remove),
        )
        .route("/system/backup", post(sys_backup_handler::create))
        .route(
            "/system/backup/restore/{backupId}",
            post(sys_backup_handler::restore),
        )
        .route(
            "/system/backup/download/{backupId}",
            get(sys_backup_handler::download),
        )
        // 租户数据包导出（F-2 定案）：平台为指定租户导出 JSON 数据包，
        // 落盘后成为一条 tenant_export 备份日志，沿用上方下载/删除链路
        .route(
            "/system/backup/tenant-export/{tenantId}",
            post(sys_backup_handler::export_tenant),
        )
        .route_layer(axum::middleware::from_fn(platform_only_guard))
}
