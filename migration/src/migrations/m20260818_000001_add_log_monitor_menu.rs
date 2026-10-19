// stepby-axum/migration/src/migrations/m20260818_000001_add_log_monitor_menu.rs
//! 新增「实时日志」监控菜单（menu_id=135）
//!
//! 背景：
//! - 后端已实现实时系统日志查看能力（handler/monitor_log_handler.rs）：
//!   - GET /monitor/log/files 列出日志目录下的应用日志文件（app.log.YYYY-MM-DD）
//!   - GET /monitor/log/tail   读取指定日志文件尾部并过滤（级别/关键字）
//! - 功能定位：运维无需登入服务器即可在线查看应用实时日志（top 后台管理系统常见模块）
//!
//! 本迁移：
//! - 在「系统监控」(parent_id=2) 目录下新增 C 类型页面菜单 menu_id=135
//!   order_num=9（排在登录日志 order_num=8 之后）
//!   perms=monitor:log:list（permission.rs 中两个 GET 接口均映射到此权限）
//! - 为普通角色 role_id=2 关联该菜单
//! - 使用幂等 INSERT，保证可重复执行

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

/// 种子时间表达式（批七十四 B1：归口到 `crate::seed_now_expr`，三方言统一 UTC 字面量）。
/// 本函数只是委托，**不得**在此另拼时间 ⇒ 换库/换时区不再换口径。
fn now_expr(_manager: &SchemaManager<'_>) -> String {
    crate::seed_now_expr()
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
        "m20260818_000001_add_log_monitor_menu"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);

        // 1. C 类型菜单（页面）：实时日志
        //    parent_id=2（系统监控目录），order_num=9（登录日志之后）
        //    path=logtail，component=monitor/logtail/index
        //    perms=monitor:log:list（permission.rs 中 GET 接口映射到此权限）
        let menu_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (135, '实时日志', 2, 9, 'logtail', 'monitor/logtail/index', '', '', '1', '0', 'C', '0', '0', 'monitor:log:list', 'log', 'admin', {now}, '在线查看应用实时日志（自动刷新，支持级别/关键字过滤）', '0')"
        );
        execute_idempotent_insert(manager, &menu_sql).await?;

        // 2. 为普通角色 role_id=2 关联新菜单
        let role_menu_sql = "sys_role_menu (role_id, menu_id) VALUES (2, 135)";
        execute_idempotent_insert(manager, role_menu_sql).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除 role_menu 关联
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 135")
            .await?;

        // 删除菜单
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id = 135")
            .await?;

        Ok(())
    }
}
