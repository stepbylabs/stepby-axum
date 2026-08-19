// axum-backend/migration/src/m20260819_000006_observability_menu.rs
//! 可观测性（运行监控）模块迁移
//!
//! 本模块为无状态工具（进程内可观测性缓冲，无独立数据表），因此仅注册菜单元数据：
//!   - C 页面「运行监控」(menu_id=3550, parent_id=2 系统监控目录,
//!     path=observability, component=monitor/observability/index,
//!     perms=monitor:slowSql:list —— 两个视图（慢请求/错误聚合）共享该查看权限)
//!   - F 按钮「清空」修改（menu_id=3551, perms=monitor:slowSql:list）
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
        "m20260819_000006_observability_menu"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 菜单常量（避开已用菜单 ID：本模块独立取 3550/3551）
        const PAGE_MENU_ID: i64 = 3550;
        const BTN_MENU_ID: i64 = 3551;
        const PARENT_DIR_ID: i64 = 2; // 系统监控目录

        let now = now_expr(manager);

        // 1. C 类型菜单（页面）：运行监控
        //    perms=monitor:slowSql:list（permission.rs 中可观测性接口均映射到此权限）
        let page_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            ({PAGE_MENU_ID}, '运行监控', {PARENT_DIR_ID}, 10, 'observability', 'monitor/observability/index', '', '', '1', '0', 'C', '0', '0', 'monitor:slowSql:list', 'monitor', 'admin', {now}, '可观测性：慢请求 / 错误聚合 / Redis 指标', '0')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;
        execute_idempotent_insert(
            manager,
            &format!("sys_role_menu (role_id, menu_id) VALUES (2, {PAGE_MENU_ID})"),
        )
        .await?;

        // 2. F 类型按钮：清空（页面动作，权限沿用视图权限）
        let btn_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            ({BTN_MENU_ID}, '清空', {PAGE_MENU_ID}, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'monitor:slowSql:list', 'delete', 'admin', {now}, '清空慢请求 / 错误日志缓冲', '0')"
        );
        execute_idempotent_insert(manager, &btn_sql).await?;
        execute_idempotent_insert(
            manager,
            &format!("sys_role_menu (role_id, menu_id) VALUES (2, {BTN_MENU_ID})"),
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        const BTN_MENU_ID: i64 = 3551;
        const PAGE_MENU_ID: i64 = 3550;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_role_menu WHERE menu_id IN ({PAGE_MENU_ID}, {BTN_MENU_ID})"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_menu WHERE menu_id IN ({PAGE_MENU_ID}, {BTN_MENU_ID})"
            ))
            .await?;
        Ok(())
    }
}
