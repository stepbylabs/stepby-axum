// stepby-axum/migration/src/m20260819_000003_report_module.rs
//! 报表中心 + 定时订阅推送模块迁移
//!
//! 新增两张表（跨 sqlite/postgres/mysql 兼容，参考 m20260818_000002_msg_module）：
//!   1. sys_report      报表定义表（report_type 支持 login_stats/user_stats/msg_stats/custom）
//!   2. sys_report_sub  报表订阅表（cron 周期推送，邮件 + 站内信）
//!
//! 然后插入菜单元数据（前置约定：系统管理目录 parent_id=1）：
//!   - M 目录「报表中心」(menu_id=151, path=report, component=ParentView)
//!   - C 页面「报表定义」(152) /「报表订阅」(153)
//!   - F 按钮权限（report: add/edit/remove/status/preview；sub: add/edit/remove/status/run）
//!   - role_menu 关联 role_id=2
//!
//! 幂等：全部走 execute_idempotent_insert（INSERT OR IGNORE / ON CONFLICT DO NOTHING）。

use crate::IndexDdlExt;
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
        "m20260819_000003_report_module"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表 ====================
        up_create_tables(manager).await?;

        // ==================== 2. 菜单元数据 ====================
        let now = now_expr(manager);

        // 2.1 M 目录「报表中心」（parent_id=1 系统管理）
        let dir_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (151, '报表中心', 1, 92, 'report', 'ParentView', '', '', '1', '0', 'M', '0', '0', '', 'chart', 'admin', {now}, '报表定义与定时订阅推送', '0')"
        );
        execute_idempotent_insert(manager, &dir_sql).await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 151)")
            .await?;

        // 2.2 C 页面菜单（报表定义 / 报表订阅）
        let page_rows: &[(&str, i64, i64, &str, &str, &str)] = &[
            // (name, menu_id, order_num, path, component, perms)
            (
                "报表定义",
                152,
                1,
                "index",
                "system/report/index",
                "system:report:list",
            ),
            (
                "报表订阅",
                153,
                2,
                "sub",
                "system/report/sub/index",
                "system:report:sub:list",
            ),
        ];
        for (name, menu_id, order_num, path, component, perms) in page_rows {
            let sql = format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                ({menu_id}, '{name}', 151, {order_num}, '{path}', '{component}', '', '', '1', '0', 'C', '0', '0', '{perms}', 'documentation', 'admin', {now}, '', '0')"
            );
            execute_idempotent_insert(manager, &sql).await?;
            execute_idempotent_insert(
                manager,
                &format!("sys_role_menu (role_id, menu_id) VALUES (2, {menu_id})"),
            )
            .await?;
        }

        // 2.3 F 按钮权限
        // 报表定义(152)：add/edit/remove/status/preview；报表订阅(153)：add/edit/remove/status/run
        let btn_rows: &[(i64, &str, i64, &str)] = &[
            (3431, "报表新增", 152, "system:report:add"),
            (3432, "报表修改", 152, "system:report:edit"),
            (3433, "报表删除", 152, "system:report:remove"),
            (3434, "报表启停", 152, "system:report:status"),
            (3435, "报表预览", 152, "system:report:preview"),
            (3441, "订阅新增", 153, "system:report:sub:add"),
            (3442, "订阅修改", 153, "system:report:sub:edit"),
            (3443, "订阅删除", 153, "system:report:sub:remove"),
            (3444, "订阅启停", 153, "system:report:sub:status"),
            (3445, "立即推送", 153, "system:report:sub:run"),
        ];
        for (menu_id, name, parent_id, perms) in btn_rows {
            let sql = format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                ({menu_id}, '{name}', {parent_id}, 1, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '#', 'admin', {now}, '', '0')"
            );
            execute_idempotent_insert(manager, &sql).await?;
            execute_idempotent_insert(
                manager,
                &format!("sys_role_menu (role_id, menu_id) VALUES (2, {menu_id})"),
            )
            .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除按钮权限与 role_menu、菜单
        let menu_ids = [
            151, 152, 153, 3431, 3432, 3433, 3434, 3435, 3441, 3442, 3443, 3444, 3445,
        ];
        for id in menu_ids {
            manager
                .get_connection()
                .execute_unprepared(&format!("DELETE FROM sys_role_menu WHERE menu_id = {}", id))
                .await?;
            manager
                .get_connection()
                .execute_unprepared(&format!("DELETE FROM sys_menu WHERE menu_id = {}", id))
                .await?;
        }

        // 删除两张表
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_report_sub")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_report")
            .await?;
        Ok(())
    }
}

/// 建两张表（跨库兼容）
async fn up_create_tables(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // -------- sys_report --------
    let report_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_report (
            report_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            report_code  VARCHAR(64) NOT NULL UNIQUE,
            report_name  VARCHAR(64) NOT NULL,
            report_type  VARCHAR(32) NOT NULL,
            config       TEXT NOT NULL,
            status       VARCHAR(2) DEFAULT '0',
            remark       VARCHAR(500),
            create_by    VARCHAR(64),
            create_time  DATETIME,
            update_time  DATETIME,
            del_flag     VARCHAR(1) DEFAULT '0'
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_report (
            report_id    BIGSERIAL PRIMARY KEY,
            report_code  VARCHAR(64) NOT NULL UNIQUE,
            report_name  VARCHAR(64) NOT NULL,
            report_type  VARCHAR(32) NOT NULL,
            config       TEXT NOT NULL,
            status       VARCHAR(2) DEFAULT '0',
            remark       VARCHAR(500),
            create_by    VARCHAR(64),
            create_time  TIMESTAMP,
            update_time  TIMESTAMP,
            del_flag     VARCHAR(1) DEFAULT '0'
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_report (
            report_id    BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            report_code  VARCHAR(64) NOT NULL UNIQUE,
            report_name  VARCHAR(64) NOT NULL,
            report_type  VARCHAR(32) NOT NULL,
            config       TEXT NOT NULL,
            status       VARCHAR(2) DEFAULT '0',
            remark       VARCHAR(500),
            create_by    VARCHAR(64),
            create_time  DATETIME,
            update_time  DATETIME,
            del_flag     VARCHAR(1) DEFAULT '0'
        )"#
    };
    manager
        .get_connection()
        .execute_unprepared(report_sql)
        .await?;

    // -------- sys_report_sub --------
    let sub_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_report_sub (
            sub_id            INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id         INTEGER NOT NULL,
            sub_name          VARCHAR(64) NOT NULL,
            cron              VARCHAR(64) NOT NULL,
            push_email        VARCHAR(2) DEFAULT '0',
            receive_email     VARCHAR(2000),
            push_sys_msg      VARCHAR(2) DEFAULT '0',
            receive_user_ids  VARCHAR(4000),
            status            VARCHAR(2) DEFAULT '0',
            last_run_time     DATETIME,
            remark            VARCHAR(500),
            create_by         VARCHAR(64),
            create_time       DATETIME,
            update_by         VARCHAR(64),
            update_time       DATETIME,
            del_flag          VARCHAR(1) DEFAULT '0'
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_report_sub (
            sub_id            BIGSERIAL PRIMARY KEY,
            report_id         BIGINT NOT NULL,
            sub_name          VARCHAR(64) NOT NULL,
            cron              VARCHAR(64) NOT NULL,
            push_email        VARCHAR(2) DEFAULT '0',
            receive_email     VARCHAR(2000),
            push_sys_msg      VARCHAR(2) DEFAULT '0',
            receive_user_ids  VARCHAR(4000),
            status            VARCHAR(2) DEFAULT '0',
            last_run_time     TIMESTAMP,
            remark            VARCHAR(500),
            create_by         VARCHAR(64),
            create_time       TIMESTAMP,
            update_by         VARCHAR(64),
            update_time       TIMESTAMP,
            del_flag          VARCHAR(1) DEFAULT '0'
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_report_sub (
            sub_id            BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            report_id         BIGINT NOT NULL,
            sub_name          VARCHAR(64) NOT NULL,
            cron              VARCHAR(64) NOT NULL,
            push_email        VARCHAR(2) DEFAULT '0',
            receive_email     VARCHAR(2000),
            push_sys_msg      VARCHAR(2) DEFAULT '0',
            receive_user_ids  VARCHAR(4000),
            status            VARCHAR(2) DEFAULT '0',
            last_run_time     DATETIME,
            remark            VARCHAR(500),
            create_by         VARCHAR(64),
            create_time       DATETIME,
            update_by         VARCHAR(64),
            update_time       DATETIME,
            del_flag          VARCHAR(1) DEFAULT '0'
        )"#
    };
    manager.get_connection().execute_unprepared(sub_sql).await?;

    // -------- 索引（report_id 用于级联查询/删除，状态用于订阅扫描） --------
    manager
        .get_connection()
        .execute_index_ddl_ic("CREATE INDEX idx_report_sub_report_id ON sys_report_sub (report_id)")
        .await?;
    manager
        .get_connection()
        .execute_index_ddl_ic("CREATE INDEX idx_report_sub_status ON sys_report_sub (status)")
        .await?;

    Ok(())
}
