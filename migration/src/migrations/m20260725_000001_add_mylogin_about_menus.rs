// stepby-axum/migration/src/migrations/m20260725_000001_add_mylogin_about_menus.rs
//! 第十次迁移：新增"我的登录历史"和"关于系统"两个低成本高价值菜单
//!
//! 背景：
//! - 主流开源后台管理系统普遍提供"用户自查登录记录"和"系统信息总览"功能
//! - 复用现有 /monitor/logininfor 接口（按当前用户筛选），无需新增后端 API
//! - "关于系统"为纯静态页面，展示版本/技术栈/构建信息
//!
//! menu_id 规划：
//! - 123 我的登录历史（C 类型菜单，parent_id=2 系统监控目录）
//! - 124 关于系统（C 类型菜单，parent_id=3 系统工具目录）
//! - 1214 我的登录查询按钮（F 类型，parent_id=123，可选）
//!
//! 权限设计：
//! - monitor:mylogin:list 所有人可见（role_id=2 显式关联，超管自动通配符）
//! - tool:about:list 所有人可见（同上）
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
        "m20260725_000001_add_mylogin_about_menus"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);

        // 1. C 类型菜单：我的登录历史
        //    parent_id=2 (系统监控目录)
        //    order_num=9（在 IP 库管理 order_num=8 之后）
        //    perms=monitor:mylogin:list
        let my_login_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (123, '我的登录', 2, 9, 'my-login', 'monitor/my-login/index', '', '', '1', '0', 'C', '0', '0', 'monitor:mylogin:list', 'guide', 'admin', {now}, '用户自查最近登录历史（复用 logininfor 接口，按当前用户筛选）', '0')"
        );
        execute_idempotent_insert(manager, &my_login_sql).await?;

        // 2. C 类型菜单：关于系统
        //    parent_id=3 (系统工具目录)
        //    order_num=4（在系统接口 order_num=3 之后）
        //    perms=tool:about:list
        let about_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (124, '关于系统', 3, 4, 'about', 'tool/about/index', '', '', '1', '0', 'C', '0', '0', 'tool:about:list', 'info', 'admin', {now}, '系统版本/技术栈/构建信息/依赖列表', '0')"
        );
        execute_idempotent_insert(manager, &about_sql).await?;

        // 3. 为普通角色 role_id=2 关联新菜单（让普通用户也能访问）
        let role_menu_sql = "sys_role_menu (role_id, menu_id) VALUES (2, 123), (2, 124)";
        execute_idempotent_insert(manager, role_menu_sql).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除 role_menu 关联
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id IN (123, 124)")
            .await?;

        // 删除菜单
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id IN (123, 124)")
            .await?;

        Ok(())
    }
}
