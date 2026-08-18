//! 注册"数据看板"菜单：dashboard/index.vue 仪表板页面
//!
//! 背景：
//!   - views/dashboard/index.vue 是完整的管理员仪表板（用户/角色/登录/操作统计）
//!   - 但该页面之前未在菜单中注册，完全无法访问（孤儿页面）
//!   - 与 workbench/index.vue（个人工作台）互补：
//!     * dashboard = 管理员全局视图（统计图表、操作日志）
//!     * workbench = 个人视角（最近访问、收藏、个人通知）
//!
//! 操作：
//!   1. 在 sys_menu 中注册"数据看板"菜单（parent_id=1 系统管理，component=dashboard/index）
//!   2. 权限标识 monitor:dashboard:list（所有登录用户默认可访问）
//!   3. 为 role_id=2（普通角色）分配该菜单权限
//!
//! 注意：菜单 ID 在 init.rs 之后动态生成，使用幂等 INSERT 保证兼容性。
//! 若 menuId 已被占用，使用 SELECT MAX(menu_id)+1 动态获取。

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::Statement;

/// 判断是否 SQLite 后端
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite
    )
}

/// 判断是否 PostgreSQL 后端
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

/// 获取当前时间 SQL 表达式（数据库兼容）
fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        format!("'{}'", now)
    } else {
        "NOW()".to_string()
    }
}

/// 构建幂等 INSERT 语句的 SQL 前缀（数据库兼容）
///
/// - SQLite: `INSERT OR IGNORE INTO`
/// - MySQL: `INSERT IGNORE INTO`
/// - PostgreSQL: `INSERT INTO ... ON CONFLICT DO NOTHING`（需调用方配合）
fn idempotent_insert_prefix(manager: &SchemaManager<'_>) -> &'static str {
    if is_sqlite(manager) {
        "INSERT OR IGNORE INTO"
    } else {
        "INSERT IGNORE INTO"
    }
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let backend = manager.get_database_backend();

        // 1. 检查是否已存在（幂等性）
        let existing: Option<i64> = conn
            .query_one(Statement::from_sql_and_values(
                backend,
                "SELECT menu_id FROM sys_menu WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index' LIMIT 1",
                [],
            ))
            .await?
            .map(|row| row.try_get_by_index::<i64>(0).unwrap_or(0));

        if existing.is_some() {
            return Ok(()); // 已存在，跳过
        }

        // 2. 获取下一个 menu_id
        let next_id: i64 = conn
            .query_one(Statement::from_sql_and_values(
                backend,
                "SELECT COALESCE(MAX(menu_id), 0) + 1 FROM sys_menu",
                [],
            ))
            .await?
            .map(|row| row.try_get_by_index::<i64>(0).unwrap_or(2043))
            .unwrap_or(2043);

        // 3. 插入菜单（含 i18n_key='menu.dashboard'，确保语言切换时菜单名能正确翻译）
        // 多数据库兼容：SQLite 用预计算时间字符串，MySQL/PostgreSQL 用 NOW()
        let now = now_expr(manager);
        conn.execute(Statement::from_sql_and_values(
            backend,
            format!(
                "INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES ($1, '数据看板', 1, 0, 'dashboard', 'dashboard/index', '', '', '1', '0', 'C', '0', '0', 'monitor:dashboard:list', 'chart', 'admin', {}, '系统数据看板（用户/角色/登录/操作统计）', '0', 'menu.dashboard')",
                now
            ),
            [next_id.into()],
        ))
        .await?;

        // 4. 为 role_id=2（普通角色）分配该菜单权限（幂等）
        let role_menu_sql = if is_postgres(manager) {
            "INSERT INTO sys_role_menu (role_id, menu_id) VALUES (2, $1) ON CONFLICT DO NOTHING"
                .to_string()
        } else {
            format!(
                "{} sys_role_menu (role_id, menu_id) VALUES (2, $1)",
                idempotent_insert_prefix(manager)
            )
        };
        conn.execute(Statement::from_sql_and_values(
            backend,
            &role_menu_sql,
            [next_id.into()],
        ))
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id IN (SELECT menu_id FROM sys_menu WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index')")
            .await?;
        conn.execute_unprepared("DELETE FROM sys_menu WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index'")
            .await?;
        Ok(())
    }
}
