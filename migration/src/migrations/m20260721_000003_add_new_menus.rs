// stepby-axum/migration/src/migrations/m20260721_000003_add_new_menus.rs
//! 第七次迁移：新增 3 个菜单种子数据
//!
//! 新增菜单：
//! 1. menu_id=118 备份管理（系统管理目录下，parent_id=1）路径 system/backup
//! 2. menu_id=119 任务进度（系统管理目录下，parent_id=1）路径 system/task
//! 3. menu_id=120 审计大屏（系统监控目录下，parent_id=2）路径 monitor/audit-dashboard
//!
//! 同步新增按钮权限（F 类型）：
//! - 1200 备份查询 / 1201 备份新增 / 1202 备份删除
//! - 1203 任务查询 / 1204 任务删除
//! - 1205 审计查询
//!
//! 同时为超管角色（role_id=1）和普通角色（role_id=2）补全 sys_role_menu 关联。
//! 注：超管角色通过 `*:*:*` 权限通配符访问所有菜单，sys_role_menu 关联可缺省，
//! 但普通角色必须显式关联才能在动态路由中拿到这些菜单。

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
        "m20260721_000003_add_new_menus"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);

        // 3 个 C 类型菜单（页面）
        let menus_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (118, '备份管理', 1, 10, 'backup', 'system/backup/index', '', '', '1', '0', 'C', '0', '0', 'system:backup:list', 'backup', 'admin', {now}, '数据备份与恢复菜单', '0'), \
            (119, '任务进度', 1, 11, 'task', 'system/task/index', '', '', '1', '0', 'C', '0', '0', 'system:task:list', 'task', 'admin', {now}, '任务进度中心菜单', '0'), \
            (120, '审计大屏', 2, 7, 'audit-dashboard', 'monitor/audit-dashboard/index', '', '', '1', '0', 'C', '0', '0', 'monitor:audit:list', 'audit', 'admin', {now}, '审计日志可视化大屏菜单', '0')"
        );
        execute_idempotent_insert(manager, &menus_sql).await?;

        // 6 个 F 类型按钮权限
        let buttons_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (1200, '备份查询', 118, 1, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:backup:query', '#', 'admin', {now}, '', '0'), \
            (1201, '备份新增', 118, 2, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:backup:add', '#', 'admin', {now}, '', '0'), \
            (1202, '备份删除', 118, 3, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:backup:remove', '#', 'admin', {now}, '', '0'), \
            (1203, '任务查询', 119, 1, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:task:query', '#', 'admin', {now}, '', '0'), \
            (1204, '任务删除', 119, 2, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:task:remove', '#', 'admin', {now}, '', '0'), \
            (1205, '审计查询', 120, 1, '#', '', '', '', '1', '0', 'F', '0', '0', 'monitor:audit:query', '#', 'admin', {now}, '', '0')"
        );
        execute_idempotent_insert(manager, &buttons_sql).await?;

        // 为普通角色 role_id=2 关联新增的 9 个菜单（超管通过 *:*:* 通配符访问，无需显式关联）
        let role_menu_sql = "sys_role_menu (role_id, menu_id) VALUES \
            (2, 118), (2, 119), (2, 120), \
            (2, 1200), (2, 1201), (2, 1202), \
            (2, 1203), (2, 1204), (2, 1205)"
            .to_string();
        execute_idempotent_insert(manager, &role_menu_sql).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除 role_menu 关联
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_role_menu WHERE menu_id IN (118, 119, 120, 1200, 1201, 1202, 1203, 1204, 1205)",
            )
            .await?;
        // 删除菜单
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_menu WHERE menu_id IN (118, 119, 120, 1200, 1201, 1202, 1203, 1204, 1205)",
            )
            .await?;
        Ok(())
    }
}
