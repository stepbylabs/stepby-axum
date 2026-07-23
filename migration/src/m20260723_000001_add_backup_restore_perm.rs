// axum-backend/migration/src/m20260723_000001_add_backup_restore_perm.rs
//! 第八次迁移：补充备份恢复接口的权限标识
//!
//! 背景：
//! - 前端 backup/index.vue 的"恢复"按钮使用 v-hasPermi="['system:backup:edit']"
//! - 后端 permission.rs 中间件将 POST /system/backup/restore/{backupId} 映射到 system:backup:edit
//! - 但 m20260721_000003_add_new_menus 仅注册了 query/add/remove 三个 F 类型按钮，
//!   未注册 edit，导致非超管用户看不到"恢复"按钮且 API 调用被拦截（403）。
//!
//! 本迁移：
//! 1. 向 sys_menu 插入 menu_id=1211 的 F 类型按钮权限 system:backup:edit
//! 2. 为普通角色 role_id=2 关联 sys_role_menu (2, 1211)
//!
//! 超管通过 *:*:* 通配符访问，无需显式关联。

use sea_orm_migration::prelude::*;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(backend, sea_orm_migration::sea_orm::DatabaseBackend::Sqlite)
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(backend, sea_orm_migration::sea_orm::DatabaseBackend::Postgres)
}

/// 当前时间表达式（跨数据库兼容）
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

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260723_000001_add_backup_restore_perm"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);

        // 1 个 F 类型按钮权限：备份恢复
        let button_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (1211, '备份恢复', 118, 4, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:backup:edit', '#', 'admin', {now}, '数据备份恢复操作权限', '0')"
        );
        execute_idempotent_insert(manager, &button_sql).await?;

        // 为普通角色 role_id=2 关联
        let role_menu_sql = "sys_role_menu (role_id, menu_id) VALUES (2, 1211)";
        execute_idempotent_insert(manager, role_menu_sql).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_role_menu WHERE menu_id = 1211",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_menu WHERE menu_id = 1211",
            )
            .await?;
        Ok(())
    }
}
