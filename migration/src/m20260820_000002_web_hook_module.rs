// axum-backend/migration/src/m20260820_000002_web_hook_module.rs
//! WebHook 事件订阅模块迁移（G5）
//!
//! 新增两张表（跨 sqlite/postgres/mysql 兼容，参考 m20260818_000002_msg_module）：
//!   1. sys_web_hook      回调配置表（订阅一个或多个事件类型，出站目标 URL + 签名密钥）
//!   2. sys_web_hook_log  推送记录表（每次出站投递留痕：事件、目标、状态、响应、耗时，审计兜底）
//!
//! 然后插入菜单元数据（前置约定：系统管理目录 parent_id=1）：
//!   - M 目录「WebHook 订阅」(menu_id=157, path=webHook, component=ParentView)
//!   - C 页面「回调配置」(158) /「推送记录」(159)
//!   - F 按钮权限（webHook: query/add/edit/remove/status/test；webHook:log: query/remove/clean/retry）
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
        "m20260820_000002_web_hook_module"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表 ====================
        up_create_tables(manager).await?;

        // ==================== 2. 菜单元数据 ====================
        let now = now_expr(manager);

        // 2.1 M 目录「WebHook 订阅」（parent_id=1 系统管理）
        let dir_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (157, 'WebHook 订阅', 1, 96, 'webHook', 'ParentView', '', '', '1', '0', 'M', '0', '0', '', 'connection', 'admin', {now}, '业务事件对外 HTTP 回调订阅', '0')"
        );
        execute_idempotent_insert(manager, &dir_sql).await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 157)")
            .await?;

        // 2.2 C 页面菜单（回调配置 / 推送记录）
        let page_rows: &[(&str, i64, i64, &str, &str, &str)] = &[
            (
                "回调配置",
                158,
                1,
                "index",
                "system/webHook/index",
                "system:webHook:list",
            ),
            (
                "推送记录",
                159,
                2,
                "log",
                "system/webHook/log/index",
                "system:webHook:log:list",
            ),
        ];
        for (name, menu_id, order_num, path, component, perms) in page_rows {
            let sql = format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                ({menu_id}, '{name}', 157, {order_num}, '{path}', '{component}', '', '', '1', '0', 'C', '0', '0', '{perms}', 'documentation', 'admin', {now}, '', '0')"
            );
            execute_idempotent_insert(manager, &sql).await?;
            execute_idempotent_insert(
                manager,
                &format!("sys_role_menu (role_id, menu_id) VALUES (2, {menu_id})"),
            )
            .await?;
        }

        // 2.3 F 按钮权限
        // 回调配置(158)：query/add/edit/remove/status/test；推送记录(159)：query/remove/clean/retry
        let btn_rows: &[(i64, &str, i64, &str)] = &[
            (3531, "回调查询", 158, "system:webHook:query"),
            (3532, "回调新增", 158, "system:webHook:add"),
            (3533, "回调修改", 158, "system:webHook:edit"),
            (3534, "回调删除", 158, "system:webHook:remove"),
            (3535, "回调启停", 158, "system:webHook:status"),
            (3536, "测试推送", 158, "system:webHook:test"),
            (3541, "记录查询", 159, "system:webHook:log:query"),
            (3542, "记录删除", 159, "system:webHook:log:remove"),
            (3543, "清空记录", 159, "system:webHook:log:clean"),
            (3544, "记录重试", 159, "system:webHook:log:retry"),
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
            157, 158, 159, 3531, 3532, 3533, 3534, 3535, 3536, 3541, 3542, 3543, 3544,
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
            .execute_unprepared("DROP TABLE IF EXISTS sys_web_hook_log")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_web_hook")
            .await?;
        Ok(())
    }
}

/// 建两张表（跨库兼容）
async fn up_create_tables(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // -------- sys_web_hook --------
    let hook_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_web_hook (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            hook_name     VARCHAR(100) NOT NULL,
            event_types   VARCHAR(2000) NOT NULL,
            target_url    VARCHAR(1000) NOT NULL,
            secret        VARCHAR(255),
            content_type  VARCHAR(16) DEFAULT 'json',
            timeout_secs  INTEGER DEFAULT 10,
            status        VARCHAR(2) DEFAULT '0',
            remark        VARCHAR(500),
            create_by     VARCHAR(64),
            create_time   DATETIME,
            update_by     VARCHAR(64),
            update_time   DATETIME,
            del_flag      VARCHAR(1) DEFAULT '0'
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_web_hook (
            id            BIGSERIAL PRIMARY KEY,
            hook_name     VARCHAR(100) NOT NULL,
            event_types   VARCHAR(2000) NOT NULL,
            target_url    VARCHAR(1000) NOT NULL,
            secret        VARCHAR(255),
            content_type  VARCHAR(16) DEFAULT 'json',
            timeout_secs  INTEGER DEFAULT 10,
            status        VARCHAR(2) DEFAULT '0',
            remark        VARCHAR(500),
            create_by     VARCHAR(64),
            create_time   TIMESTAMP,
            update_by     VARCHAR(64),
            update_time   TIMESTAMP,
            del_flag      VARCHAR(1) DEFAULT '0'
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_web_hook (
            id            BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            hook_name     VARCHAR(100) NOT NULL,
            event_types   VARCHAR(2000) NOT NULL,
            target_url    VARCHAR(1000) NOT NULL,
            secret        VARCHAR(255),
            content_type  VARCHAR(16) DEFAULT 'json',
            timeout_secs  INTEGER DEFAULT 10,
            status        VARCHAR(2) DEFAULT '0',
            remark        VARCHAR(500),
            create_by     VARCHAR(64),
            create_time   DATETIME,
            update_by     VARCHAR(64),
            update_time   DATETIME,
            del_flag      VARCHAR(1) DEFAULT '0'
        )"#
    };
    manager
        .get_connection()
        .execute_unprepared(hook_sql)
        .await?;

    // -------- sys_web_hook_log --------
    let log_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_web_hook_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            hook_id     INTEGER,
            hook_name   VARCHAR(100),
            event_type  VARCHAR(128) NOT NULL,
            target_url  VARCHAR(1000) NOT NULL,
            payload     TEXT,
            status      VARCHAR(2) DEFAULT '0',
            status_code INTEGER,
            response    TEXT,
            error_msg   VARCHAR(1000),
            cost_ms     INTEGER DEFAULT 0,
            create_time DATETIME
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_web_hook_log (
            id          BIGSERIAL PRIMARY KEY,
            hook_id     BIGINT,
            hook_name   VARCHAR(100),
            event_type  VARCHAR(128) NOT NULL,
            target_url  VARCHAR(1000) NOT NULL,
            payload     TEXT,
            status      VARCHAR(2) DEFAULT '0',
            status_code INTEGER,
            response    TEXT,
            error_msg   VARCHAR(1000),
            cost_ms     INTEGER DEFAULT 0,
            create_time TIMESTAMP
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_web_hook_log (
            id          BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            hook_id     BIGINT,
            hook_name   VARCHAR(100),
            event_type  VARCHAR(128) NOT NULL,
            target_url  VARCHAR(1000) NOT NULL,
            payload     TEXT,
            status      VARCHAR(2) DEFAULT '0',
            status_code INTEGER,
            response    TEXT,
            error_msg   VARCHAR(1000),
            cost_ms     INTEGER DEFAULT 0,
            create_time DATETIME
        )"#
    };
    manager.get_connection().execute_unprepared(log_sql).await?;

    // -------- 索引（hook_id 用于级联查询，状态用于筛选） --------
    manager
        .get_connection()
        .execute_unprepared("CREATE INDEX IF NOT EXISTS idx_web_hook_log_hook_id ON sys_web_hook_log (hook_id)")
        .await?;
    manager
        .get_connection()
        .execute_unprepared("CREATE INDEX IF NOT EXISTS idx_web_hook_log_created ON sys_web_hook_log (create_time)")
        .await?;

    Ok(())
}