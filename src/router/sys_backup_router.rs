//! 数据备份/恢复路由注册
//!
//! 路由结构：
//! - /system/backup/* — 备份日志（6 个接口）
//!
//! 多租户安全（§27.13.4 / 原则 B）：整组 `/system/backup/*` 为**平台专属**能力
//! （备份为整库 pg_dump/mysqldump，下载面即全库数据；恢复会覆盖现库），
//! 挂 [`platform_only_guard`] 请求层守卫：租户操作者（含租户管理员）一律 403，
//! 作为 permission 层（`system:backup:*` 已移出租户可授集合）的第二道防线。
//!
//! **批次 2 例外（能力位感知）**：`platform_only_guard` 对**登记在册**的少数路径
//! 按平台层能力位放行租户操作者——
//! - `GET /system/backup/list`、`GET /system/backup/{backupId}`
//!   ⇒ 需 `backup.visibility` 达 `view_only` 档；
//! - `GET /system/backup/download/{backupId}`
//!   ⇒ 需 `backup.visibility` 达 `full` 档（下载即拿到文件本体，只读档不放行）；
//! - `POST /system/backup/self-export` ⇒ 需 `backup.tenant_self_export`。
//!
//! 放行后仍有**两道**收窄：permission 层（需租户角色持有对应 perms，而该 perms 只有在
//! **套餐**也开启同键能力位时才可授予）与**服务层行级收窄**（`sys_backup_service`
//! 把租户可见范围强制收窄为 `backup_type = 'tenant_export' AND tenant_id = 自己`，
//! 因此租户既看不到也下载不了整库备份）。默认（能力位全关）下与改造前逐条等价。

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
        // b71 契约审计：GET 详情零前端调用（同路径 DELETE 在用），保留 REST 完整性 → router/mod.rs 清单 ①
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
        // 租户**自助**导出（批次 2）：无租户参数，服务端强制取操作者所属租户
        .route(
            "/system/backup/self-export",
            post(sys_backup_handler::self_export),
        )
        .route_layer(axum::middleware::from_fn(platform_only_guard))
}
