// axum-backend/migration/src/m20260726_000001_add_notice_center_session_menus.rs
//! 第十一次迁移：新增"通知中心"和"会话管理"两个低成本高价值菜单
//!
//! 背景：
//! - 参考主流开源后台管理系统（RuoYi、Tabler、AdminLTE、vben-admin 等）
//! - 复用现有 /system/notice/list + /monitor/online/list 接口，按当前用户筛选
//! - "通知中心"聚合个人未读/全部通知，支持批量已读
//! - "会话管理"展示当前用户所有活跃会话，支持远程注销（区别于管理员视角的在线用户）
//!
//! menu_id 规划：
//! - 125 通知中心（C 类型菜单，parent_id=1 系统管理目录）
//! - 126 会话管理（C 类型菜单，parent_id=2 系统监控目录）
//!
//! 权限设计：
//! - system:notice:center 所有人可见（role_id=2 显式关联，超管自动通配符）
//! - monitor:session:list 所有人可见（同上）
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
        "m20260726_000001_add_notice_center_session_menus"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);

        // 1. C 类型菜单：通知中心
        //    parent_id=1 (系统管理目录)
        //    order_num=10（在 限流配置 order_num=9 之后）
        //    perms=system:notice:center
        let notice_center_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (125, '通知中心', 1, 10, 'notice-center', 'system/notice-center/index', '', '', '1', '0', 'C', '0', '0', 'system:notice:center', 'message', 'admin', {now}, '个人通知聚合页（未读/全部/批量已读，复用 notice 接口按当前用户筛选）', '0')"
        );
        execute_idempotent_insert(manager, &notice_center_sql).await?;

        // 2. C 类型菜单：会话管理
        //    parent_id=2 (系统监控目录)
        //    order_num=10（在 我的登录 order_num=9 之后）
        //    perms=monitor:session:list
        let my_session_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (126, '会话管理', 2, 10, 'my-session', 'monitor/my-session/index', '', '', '1', '0', 'C', '0', '0', 'monitor:session:list', 'monitor', 'admin', {now}, '当前用户活跃会话管理（复用 online 接口，支持远程注销自己的其他会话）', '0')"
        );
        execute_idempotent_insert(manager, &my_session_sql).await?;

        // 3. 为普通角色 role_id=2 关联新菜单（让普通用户也能访问）
        let role_menu_sql = "sys_role_menu (role_id, menu_id) VALUES (2, 125), (2, 126)";
        execute_idempotent_insert(manager, role_menu_sql).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除 role_menu 关联
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_role_menu WHERE menu_id IN (125, 126)",
            )
            .await?;

        // 删除菜单
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_menu WHERE menu_id IN (125, 126)",
            )
            .await?;

        Ok(())
    }
}
