// stepby-axum/migration/src/migrations/m20260728_000001_add_changelog_menu.rs
//! 第十三次迁移：新增"更新日志"菜单（TierS-2 功能）
//!
//! 背景：
//! - 对比开源后台管理项目，更新日志页面是常见的高价值低成本功能
//! - 前端已创建独立页面 src/views/tool/changelog/index.vue
//! - 路由已在 router/index.ts 的 extraConstantRoutes 中注册（/tool/changelog）
//! - 本次迁移仅注册菜单项到 sys_menu，让用户能从侧边栏访问
//!
//! menu_id 规划：
//! - 131 更新日志（C 类型菜单，parent_id=3 系统工具目录，order_num=7）
//!   URL: /tool/changelog
//!   component: tool/changelog/index
//!   perms: tool:changelog:list（所有人可见）
//!
//! 权限设计：
//! - tool:changelog:list 所有人可见（role_id=2 显式关联，超管自动通配符）
//!
//! 注意：
//! - 路由已在 extraConstantRoutes 中静态注册，无需 get_routers 动态加载
//! - 菜单注册仅用于侧边栏显示和权限标识

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
        "m20260728_000001_add_changelog_menu"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);

        // C 类型菜单：更新日志
        // parent_id=3 (系统工具目录)
        // order_num=7（在 帮助中心 order_num=6 之后）
        // perms=tool:changelog:list
        let changelog_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (131, '更新日志', 3, 7, 'changelog', 'tool/changelog/index', '', '', '1', '0', 'C', '0', '0', 'tool:changelog:list', 'documentation', 'admin', {now}, '系统更新日志（版本时间线、搜索、高亮）', '0')"
        );
        execute_idempotent_insert(manager, &changelog_sql).await?;

        // 为普通角色 role_id=2 关联新菜单（让普通用户也能访问）
        let role_menu_sql = "sys_role_menu (role_id, menu_id) VALUES (2, 131)";
        execute_idempotent_insert(manager, role_menu_sql).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除 role_menu 关联
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 131")
            .await?;

        // 删除菜单
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id = 131")
            .await?;

        Ok(())
    }
}
