// axum-backend/migration/src/m20260926_000012_backup_permission_granularity.rs
//! 批次 2（MT-7）：备份权限**粒度化**——新增两个按钮 perms。
//!
//! ## 缺陷（本轮取证）
//!
//! `permission.rs` 原把 `GET /system/backup/download/{backupId}`（整库文件下载）与
//! `POST /system/backup/tenant-export/{tenantId}`（数据包导出）都映射到
//! `system:backup:query` ⇒ **授予 query 等于授予整库下载**。而能力位
//! `backup.readonly_visible` 想下放的正是"只读子集"，两者混在同一条 perms 上
//! 无法安全拆分。
//!
//! ## 口径
//!
//! - `GET /system/backup/download/{backupId}` ⇒ `system:backup:download`（本迁移 3625）
//! - `POST /system/backup/tenant-export/{tenantId}` ⇒ `system:backup:export`（本迁移 3626）
//! - `POST /system/backup/self-export`（租户自助导出）⇒ 复用 `system:backup:export`
//!
//! 段位：`menu-id-registry.md` §下一个可用段位「新增 C/F 页面按钮（小模块）**3625 起**」
//! （1200–1213 备份段已被 m20260721–24 占满）。
//!
//! ## 授予约定
//!
//! **不授予任何角色**（保守起步）：两个 perms 均属平台专属前缀 `system:backup:`，
//! 默认整面不下放。能力位开启后由 `initialize::ensure_tenant_role_menu_governance`
//! 的 ①' 按 **perms 粒度**回填给平台普通角色（role_id=2）：
//! - `backup.readonly_visible` ⇒ 回填 `system:backup:list` / `:query` / `:download` 对应菜单；
//! - `backup.tenant_self_export` ⇒ 回填 `system:backup:export` 对应菜单。
//!
//! 注意 `system:backup:edit`（恢复，覆盖现库）与 `:add` / `:remove` **不在**解锁白名单内，
//! 因此即使能力位开启，也不会被回填 — 这正是 perms 粒度相对前缀粒度的关键差别。
//!
//! 与 `initialize::ensure_backup_permission_menus` **双写保持一致**（存量库不跑
//! Migrator::up，两处清单必须双写；R4 为回归门禁）。

use sea_orm_migration::prelude::*;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite
    )
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        format!("'{}'", now)
    } else {
        "NOW()".to_string()
    }
}

/// 幂等 INSERT
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        format!("INSERT OR IGNORE INTO {}", body)
    } else if is_postgres(manager) {
        format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
    } else {
        format!("INSERT IGNORE INTO {}", body)
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

/// 菜单段位（`menu-id-registry.md`「新增 C/F 页面按钮（小模块）3625 起」）
pub const MENU_ID_DOWNLOAD: i64 = 3625;
/// 数据包导出（平台代导出 + 租户自助导出共用 perms）
pub const MENU_ID_EXPORT: i64 = 3626;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000012_backup_permission_granularity"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);
        let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";

        // F 按钮：备份下载（从 system:backup:query 中独立出来）
        let download_sql = format!(
            "{menu_cols} VALUES \
            (3625, '备份下载', 118, 5, '', '', '', '', '1', '0', 'F', '0', '0', 'system:backup:download', '#', 'admin', {now}, '整库备份文件下载（批次 2 从 query 独立）', '0', NULL)"
        );
        execute_idempotent_insert(manager, &download_sql).await?;

        // F 按钮：数据包导出（平台代导出 /system/backup/tenant-export/{tenantId}
        // 与租户自助导出 /system/backup/self-export 共用）
        let export_sql = format!(
            "{menu_cols} VALUES \
            (3626, '数据包导出', 118, 6, '', '', '', '', '1', '0', 'F', '0', '0', 'system:backup:export', '#', 'admin', {now}, '租户数据包导出（平台代导出 + 租户自助导出）', '0', NULL)"
        );
        execute_idempotent_insert(manager, &export_sql).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id IN (3625, 3626)")
            .await?;
        conn.execute_unprepared("DELETE FROM sys_menu WHERE menu_id IN (3625, 3626)")
            .await?;
        Ok(())
    }
}
