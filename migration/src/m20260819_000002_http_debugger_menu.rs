// stepby-axum/migration/src/m20260819_000002_http_debugger_menu.rs
//! 在线 HTTP 调试器 模块迁移
//!
//! 本模块为无状态工具（服务端转发，无独立数据表），因此仅注册菜单元数据：
//!   - C 页面「HTTP 调试器」(menu_id=3410, parent_id=3 系统工具目录,
//!     path=http-debugger, component=tool/http-debugger/index, perms=tool:httpDebug:list)
//!   - role_menu 关联 role_id=2
//!
//! 幂等：全部走 execute_idempotent_insert（INSERT OR IGNORE / ON CONFLICT DO NOTHING）。

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
    matches!(
        backend,
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
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
        "m20260819_000002_http_debugger_menu"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 菜单常量（避开已用菜单 ID：工具页面起 116，oauth 按钮 3261-3264，本模块独立取 3410）
        const PAGE_MENU_ID: i64 = 3410;
        const PARENT_DIR_ID: i64 = 3; // 系统工具目录

        let now = now_expr(manager);
        let page_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            ({PAGE_MENU_ID}, 'HTTP 调试器', {PARENT_DIR_ID}, 9, 'http-debugger', 'tool/http-debugger/index', '', '', '1', '0', 'C', '0', '0', 'tool:httpDebug:list', 'send', 'admin', {now}, '在线 HTTP 转发调试（服务端代理 + SSRF 防护）', '0')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;
        execute_idempotent_insert(
            manager,
            &format!("sys_role_menu (role_id, menu_id) VALUES (2, {PAGE_MENU_ID})"),
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        const PAGE_MENU_ID: i64 = 3410;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_role_menu WHERE menu_id = {PAGE_MENU_ID}"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_menu WHERE menu_id = {PAGE_MENU_ID}"
            ))
            .await?;
        Ok(())
    }
}
