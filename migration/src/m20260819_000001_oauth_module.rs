// axum-backend/migration/src/m20260819_000001_oauth_module.rs
//! 第三方登录 / OAuth2 / OIDC 模块迁移
//!
//! 新增两张表（跨 sqlite/postgres/mysql 兼容，参考 m20260818_000002_msg_module）：
//!   1. sys_oauth_provider  登录提供商配置（github/gitee/wecom 企业微信/oidc 通用 OIDC）
//!      client_id/client_secret 存库，生产建议经 sys_config 加密或仅填写非敏感字段；
//!      此处采用与消息渠道一致的明文配置模型，敏感凭据由管理员填录。
//!   2. sys_oauth_user      第三方身份与本地账号的绑定表（provider + provider_user_id 唯一）
//!
//! 然后插入菜单元数据（前置约定：系统管理目录 parent_id=1）：
//!   - M 目录「单点登录」(menu_id=145, path=oauth, component=ParentView)
//!   - C 页面「登录配置」(146)（路径 system/oauth/provider/index）
//!   - F 按钮权限（add/edit/remove/toggle 关联页面 146）
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
        "m20260819_000001_oauth_module"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表 ====================
        up_create_tables(manager).await?;

        // ==================== 2. 默认提供商种子数据 ====================
        let now = now_expr(manager);
        let providers: &[(&str, &str, &str, &str, &str, &str, i64)] = &[
            (
                "github",
                "GitHub",
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                "https://api.github.com/user",
                "read:user%20user:email",
                1,
            ),
            (
                "gitee",
                "Gitee",
                "https://gitee.com/oauth/authorize",
                "https://gitee.com/oauth/token",
                "https://gitee.com/api/v5/user",
                "user_info%20email",
                2,
            ),
            (
                "wecom",
                "企业微信",
                "https://login.work.weixin.qq.com/wwlogin/sso/login",
                "https://open.weixin.qq.com/connect/oauth2/access_token",
                "https://qyapi.weixin.qq.com/cgi-bin/getuserinfo",
                "snsapi_base",
                3,
            ),
            (
                "oidc",
                "通用 OIDC",
                "https://change-me.example.com/oauth/authorize",
                "https://change-me.example.com/oauth/token",
                "https://change-me.example.com/oauth/userinfo",
                "openid%20profile%20email",
                4,
            ),
        ];
        for (code, name, auth_url, token_url, user_url, scope, order) in providers {
            let sql = format!(
                "sys_oauth_provider (provider_code, provider_name, provider_type, client_id, client_secret, authorize_url, token_url, user_info_url, scope, redirect_uri, auto_create_user, enabled, display_order, remark, create_time) VALUES \
                ('{code}', '{name}', '{code}', '', '', '{auth_url}', '{token_url}', '{user_url}', '{scope}', '', '1', '0', {order}, '内置约定端点，填充凭据并启用后可用', {now})"
            );
            execute_idempotent_insert(manager, &sql).await?;
        }

        // ==================== 3. 菜单元数据 ====================
        // 3.1 M 目录「单点登录」（parent_id=1 系统管理）
        let dir_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (145, '单点登录', 1, 95, 'oauth', 'ParentView', '', '', '1', '0', 'M', '0', '0', '', 'connection', 'admin', {now}, '第三方登录/OAuth2/OIDC 配置', '0')"
        );
        execute_idempotent_insert(manager, &dir_sql).await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 145)")
            .await?;

        // 3.2 C 页面「登录配置」
        let page_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (146, '登录配置', 145, 1, 'provider', 'system/oauth/provider/index', '', '', '1', '0', 'C', '0', '0', 'system:oauth:provider:list', 'key', 'admin', {now}, 'OAuth2/OIDC 提供商配置', '0')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 146)")
            .await?;

        // 3.3 F 按钮权限（关联页面 146）
        let btn_rows: &[(i64, &str, i64, &str)] = &[
            (3261, "配置新增", 146, "system:oauth:provider:add"),
            (3262, "配置修改", 146, "system:oauth:provider:edit"),
            (3263, "配置删除", 146, "system:oauth:provider:remove"),
            (3264, "配置启停", 146, "system:oauth:provider:toggle"),
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
        let menu_ids = [145, 146, 3261, 3262, 3263, 3264];
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
            .execute_unprepared("DROP TABLE IF EXISTS sys_oauth_user")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_oauth_provider")
            .await?;
        Ok(())
    }
}

/// 建两张表（跨库兼容）
async fn up_create_tables(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // -------- sys_oauth_provider --------
    let provider_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_provider (
            provider_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_code  VARCHAR(64) NOT NULL UNIQUE,
            provider_name  VARCHAR(64) NOT NULL,
            provider_type  VARCHAR(32) NOT NULL,
            client_id      VARCHAR(200) NOT NULL DEFAULT '',
            client_secret  VARCHAR(200) NOT NULL DEFAULT '',
            authorize_url  VARCHAR(500) NOT NULL DEFAULT '',
            token_url      VARCHAR(500) NOT NULL DEFAULT '',
            user_info_url  VARCHAR(500) NOT NULL DEFAULT '',
            scope          VARCHAR(200) NOT NULL DEFAULT '',
            redirect_uri   VARCHAR(500) NOT NULL DEFAULT '',
            auto_create_user VARCHAR(1) NOT NULL DEFAULT '1',
            enabled        VARCHAR(1) NOT NULL DEFAULT '0',
            display_order  INTEGER NOT NULL DEFAULT 0,
            remark         VARCHAR(500),
            create_time    DATETIME,
            update_time    DATETIME
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_provider (
            provider_id    BIGSERIAL PRIMARY KEY,
            provider_code  VARCHAR(64) NOT NULL UNIQUE,
            provider_name  VARCHAR(64) NOT NULL,
            provider_type  VARCHAR(32) NOT NULL,
            client_id      VARCHAR(200) NOT NULL DEFAULT '',
            client_secret  VARCHAR(200) NOT NULL DEFAULT '',
            authorize_url  VARCHAR(500) NOT NULL DEFAULT '',
            token_url      VARCHAR(500) NOT NULL DEFAULT '',
            user_info_url  VARCHAR(500) NOT NULL DEFAULT '',
            scope          VARCHAR(200) NOT NULL DEFAULT '',
            redirect_uri   VARCHAR(500) NOT NULL DEFAULT '',
            auto_create_user VARCHAR(1) NOT NULL DEFAULT '1',
            enabled        VARCHAR(1) NOT NULL DEFAULT '0',
            display_order  INTEGER NOT NULL DEFAULT 0,
            remark         VARCHAR(500),
            create_time    TIMESTAMP,
            update_time    TIMESTAMP
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_provider (
            provider_id    BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            provider_code  VARCHAR(64) NOT NULL UNIQUE,
            provider_name  VARCHAR(64) NOT NULL,
            provider_type  VARCHAR(32) NOT NULL,
            client_id      VARCHAR(200) NOT NULL DEFAULT '',
            client_secret  VARCHAR(200) NOT NULL DEFAULT '',
            authorize_url  VARCHAR(500) NOT NULL DEFAULT '',
            token_url      VARCHAR(500) NOT NULL DEFAULT '',
            user_info_url  VARCHAR(500) NOT NULL DEFAULT '',
            scope          VARCHAR(200) NOT NULL DEFAULT '',
            redirect_uri   VARCHAR(500) NOT NULL DEFAULT '',
            auto_create_user VARCHAR(1) NOT NULL DEFAULT '1',
            enabled        VARCHAR(1) NOT NULL DEFAULT '0',
            display_order  INTEGER NOT NULL DEFAULT 0,
            remark         VARCHAR(500),
            create_time    DATETIME,
            update_time    DATETIME
        )"#
    };
    manager
        .get_connection()
        .execute_unprepared(provider_sql)
        .await?;

    // -------- sys_oauth_user --------
    // 第三方身份绑定表：provider + provider_user_id 唯一
    let oauth_user_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_user (
            oauth_id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id           BIGINT NOT NULL,
            provider          VARCHAR(32) NOT NULL,
            provider_user_id  VARCHAR(128) NOT NULL,
            nickname          VARCHAR(64),
            avatar            VARCHAR(500),
            email             VARCHAR(200),
            access_token      TEXT,
            refresh_token     TEXT,
            expires_at        DATETIME,
            last_login_time   DATETIME,
            create_time       DATETIME,
            update_time       DATETIME,
            UNIQUE(provider, provider_user_id)
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_user (
            oauth_id          BIGSERIAL PRIMARY KEY,
            user_id           BIGINT NOT NULL,
            provider          VARCHAR(32) NOT NULL,
            provider_user_id  VARCHAR(128) NOT NULL,
            nickname          VARCHAR(64),
            avatar            VARCHAR(500),
            email             VARCHAR(200),
            access_token      TEXT,
            refresh_token     TEXT,
            expires_at        TIMESTAMP,
            last_login_time   TIMESTAMP,
            create_time       TIMESTAMP,
            update_time       TIMESTAMP,
            UNIQUE(provider, provider_user_id)
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_user (
            oauth_id          BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id           BIGINT NOT NULL,
            provider          VARCHAR(32) NOT NULL,
            provider_user_id  VARCHAR(128) NOT NULL,
            nickname          VARCHAR(64),
            avatar            VARCHAR(500),
            email             VARCHAR(200),
            access_token      TEXT,
            refresh_token     TEXT,
            expires_at        DATETIME,
            last_login_time   DATETIME,
            create_time       DATETIME,
            update_time       DATETIME,
            UNIQUE KEY uk_oauth_provider_user (provider, provider_user_id)
        )"#
    };
    manager
        .get_connection()
        .execute_unprepared(oauth_user_sql)
        .await?;

    // sys_oauth_user 索引（user_id 关联查询）
    manager
        .get_connection()
        .execute_index_ddl_ic("CREATE INDEX idx_oauth_user_user_id ON sys_oauth_user (user_id)")
        .await?;

    Ok(())
}
