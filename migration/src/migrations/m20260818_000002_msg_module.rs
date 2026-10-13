// stepby-axum/migration/src/m20260818_000002_msg_module.rs
//! 消息渠道与模板管理模块迁移
//!
//! 新增三张表（跨 sqlite/postgres/mysql 兼容，参考 m20260721_000002_sys_task）：
//!   1. sys_msg_channel   消息渠道（email/sms/site）
//!   2. sys_msg_template  消息模板（支持 {{var}} 变量）
//!   3. sys_msg_send_log  发送记录（含重试计数；status/channel_code/create_time 建索引）
//!
//! 然后插入菜单元数据（前置约定：系统管理目录 parent_id=1）：
//!   - M 目录「消息管理」(menu_id=140, path=msg, component=ParentView)
//!   - C 页面「消息渠道」(141) /「消息模板」(142) /「发送记录」(143)
//!   - F 按钮权限（add/edit/remove/test / add/edit/remove / remove/clean/retry）关联到各页面
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
        "m20260818_000002_msg_module"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表 ====================
        up_create_tables(manager).await?;

        // ==================== 2. 菜单元数据 ====================
        let now = now_expr(manager);

        // 2.1 M 目录「消息管理」（parent_id=1 系统管理）
        let dir_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (140, '消息管理', 1, 90, 'msg', 'ParentView', '', '', '1', '0', 'M', '0', '0', '', 'message', 'admin', {now}, '消息渠道与模板管理', '0')"
        );
        execute_idempotent_insert(manager, &dir_sql).await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 140)")
            .await?;

        // 2.2 C 页面菜单（消息渠道 / 消息模板 / 发送记录）
        let page_rows: &[(&str, i64, i64, &str, &str, &str)] = &[
            // (name, menu_id, order_num, path, component, perms)
            (
                "消息渠道",
                141,
                1,
                "channel",
                "system/message/channel/index",
                "system:msg:channel:list",
            ),
            (
                "消息模板",
                142,
                2,
                "template",
                "system/message/template/index",
                "system:msg:template:list",
            ),
            (
                "发送记录",
                143,
                3,
                "log",
                "system/message/log/index",
                "system:msg:log:list",
            ),
        ];
        for (name, menu_id, order_num, path, component, perms) in page_rows {
            let icon = match *menu_id {
                141 => "mail",
                142 => "documentation",
                _ => "log",
            };
            let sql = format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                ({menu_id}, '{name}', 140, {order_num}, '{path}', '{component}', '', '', '1', '0', 'C', '0', '0', '{perms}', '{icon}', 'admin', {now}, '', '0')"
            );
            execute_idempotent_insert(manager, &sql).await?;
            execute_idempotent_insert(
                manager,
                &format!("sys_role_menu (role_id, menu_id) VALUES (2, {menu_id})"),
            )
            .await?;
        }

        // 2.3 F 按钮权限（关联各页面菜单 parent_id）
        // 消息渠道(141)：add/edit/remove/test；消息模板(142)：add/edit/remove；发送记录(143)：remove/clean/retry
        let btn_rows: &[(i64, &str, i64, &str)] = &[
            (3101, "渠道新增", 141, "system:msg:channel:add"),
            (3102, "渠道修改", 141, "system:msg:channel:edit"),
            (3103, "渠道删除", 141, "system:msg:channel:remove"),
            (3104, "渠道测试", 141, "system:msg:channel:test"),
            (3111, "模板新增", 142, "system:msg:template:add"),
            (3112, "模板修改", 142, "system:msg:template:edit"),
            (3113, "模板删除", 142, "system:msg:template:remove"),
            (3121, "记录删除", 143, "system:msg:log:remove"),
            (3122, "记录清空", 143, "system:msg:log:clean"),
            (3123, "记录重试", 143, "system:msg:log:retry"),
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
            140, 141, 142, 143, 3101, 3102, 3103, 3104, 3111, 3112, 3113, 3121, 3122, 3123,
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

        // 删除三张表
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_msg_send_log")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_msg_template")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_msg_channel")
            .await?;
        Ok(())
    }
}

/// 建三张表（跨库兼容）
async fn up_create_tables(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // -------- sys_msg_channel --------
    let channel_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_msg_channel (
            channel_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_name VARCHAR(64) NOT NULL,
            channel_code VARCHAR(64) NOT NULL UNIQUE,
            channel_type VARCHAR(32) NOT NULL,
            config_json  TEXT,
            status       VARCHAR(2) DEFAULT '0',
            remark       VARCHAR(500),
            create_by    VARCHAR(64),
            create_time  DATETIME,
            update_by    VARCHAR(64),
            update_time  DATETIME,
            del_flag     VARCHAR(1) DEFAULT '0'
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_msg_channel (
            channel_id   BIGSERIAL PRIMARY KEY,
            channel_name VARCHAR(64) NOT NULL,
            channel_code VARCHAR(64) NOT NULL UNIQUE,
            channel_type VARCHAR(32) NOT NULL,
            config_json  TEXT,
            status       VARCHAR(2) DEFAULT '0',
            remark       VARCHAR(500),
            create_by    VARCHAR(64),
            create_time  TIMESTAMP,
            update_by    VARCHAR(64),
            update_time  TIMESTAMP,
            del_flag     VARCHAR(1) DEFAULT '0'
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_msg_channel (
            channel_id   BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            channel_name VARCHAR(64) NOT NULL,
            channel_code VARCHAR(64) NOT NULL UNIQUE,
            channel_type VARCHAR(32) NOT NULL,
            config_json  TEXT,
            status       VARCHAR(2) DEFAULT '0',
            remark       VARCHAR(500),
            create_by    VARCHAR(64),
            create_time  DATETIME,
            update_by    VARCHAR(64),
            update_time  DATETIME,
            del_flag     VARCHAR(1) DEFAULT '0'
        )"#
    };
    manager
        .get_connection()
        .execute_unprepared(channel_sql)
        .await?;

    // -------- sys_msg_template --------
    let template_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_msg_template (
            template_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            template_name    VARCHAR(64) NOT NULL,
            template_code    VARCHAR(64) NOT NULL UNIQUE,
            channel_code     VARCHAR(64) NOT NULL DEFAULT 'email',
            template_subject VARCHAR(200) NOT NULL,
            template_content TEXT NOT NULL,
            status           VARCHAR(2) DEFAULT '0',
            remark           VARCHAR(500),
            create_by        VARCHAR(64),
            create_time      DATETIME,
            update_by        VARCHAR(64),
            update_time      DATETIME,
            del_flag         VARCHAR(1) DEFAULT '0'
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_msg_template (
            template_id      BIGSERIAL PRIMARY KEY,
            template_name    VARCHAR(64) NOT NULL,
            template_code    VARCHAR(64) NOT NULL UNIQUE,
            channel_code     VARCHAR(64) NOT NULL DEFAULT 'email',
            template_subject VARCHAR(200) NOT NULL,
            template_content TEXT NOT NULL,
            status           VARCHAR(2) DEFAULT '0',
            remark           VARCHAR(500),
            create_by        VARCHAR(64),
            create_time      TIMESTAMP,
            update_by        VARCHAR(64),
            update_time      TIMESTAMP,
            del_flag         VARCHAR(1) DEFAULT '0'
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_msg_template (
            template_id      BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            template_name    VARCHAR(64) NOT NULL,
            template_code    VARCHAR(64) NOT NULL UNIQUE,
            channel_code     VARCHAR(64) NOT NULL DEFAULT 'email',
            template_subject VARCHAR(200) NOT NULL,
            template_content TEXT NOT NULL,
            status           VARCHAR(2) DEFAULT '0',
            remark           VARCHAR(500),
            create_by        VARCHAR(64),
            create_time      DATETIME,
            update_by        VARCHAR(64),
            update_time      DATETIME,
            del_flag         VARCHAR(1) DEFAULT '0'
        )"#
    };
    manager
        .get_connection()
        .execute_unprepared(template_sql)
        .await?;

    // -------- sys_msg_send_log --------
    let log_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_msg_send_log (
            log_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            template_code    VARCHAR(64),
            channel_code     VARCHAR(32),
            to_addr          VARCHAR(200) NOT NULL,
            subject          VARCHAR(200),
            content          TEXT,
            status           VARCHAR(2) DEFAULT '0',
            retry_count      INTEGER DEFAULT 0,
            max_retry_count  INTEGER DEFAULT 3,
            last_error       VARCHAR(1000),
            send_time        DATETIME,
            remark           VARCHAR(500),
            create_time      DATETIME
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_msg_send_log (
            log_id           BIGSERIAL PRIMARY KEY,
            template_code    VARCHAR(64),
            channel_code     VARCHAR(32),
            to_addr          VARCHAR(200) NOT NULL,
            subject          VARCHAR(200),
            content          TEXT,
            status           VARCHAR(2) DEFAULT '0',
            retry_count      INTEGER DEFAULT 0,
            max_retry_count  INTEGER DEFAULT 3,
            last_error       VARCHAR(1000),
            send_time        TIMESTAMP,
            remark           VARCHAR(500),
            create_time      TIMESTAMP
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_msg_send_log (
            log_id           BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            template_code    VARCHAR(64),
            channel_code     VARCHAR(32),
            to_addr          VARCHAR(200) NOT NULL,
            subject          VARCHAR(200),
            content          TEXT,
            status           VARCHAR(2) DEFAULT '0',
            retry_count      INTEGER DEFAULT 0,
            max_retry_count  INTEGER DEFAULT 3,
            last_error       VARCHAR(1000),
            send_time        DATETIME,
            remark           VARCHAR(500),
            create_time      DATETIME
        )"#
    };
    manager.get_connection().execute_unprepared(log_sql).await?;

    // -------- sys_msg_send_log 索引（status / channel_code / create_time） --------
    manager
        .get_connection()
        .execute_index_ddl_ic("CREATE INDEX idx_msg_send_log_status ON sys_msg_send_log (status)")
        .await?;
    manager
        .get_connection()
        .execute_index_ddl_ic(
            "CREATE INDEX idx_msg_send_log_channel_code ON sys_msg_send_log (channel_code)",
        )
        .await?;
    manager
        .get_connection()
        .execute_index_ddl_ic(
            "CREATE INDEX idx_msg_send_log_create_time ON sys_msg_send_log (create_time)",
        )
        .await?;

    Ok(())
}
