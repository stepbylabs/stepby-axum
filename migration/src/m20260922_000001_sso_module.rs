// stepby-axum/migration/src/m20260922_000001_sso_module.rs
//! 单点登录 / OIDC Provider（SSO server 角色）模块迁移
//!
//! 与 m20260819_000001_oauth_module（OAuth **客户端**：本系统作为第三方登录的消费方）
//! 互补：本模块让 Stepby 充当**授权服务器**，向企业内部其它应用签发令牌。
//!
//! 新增两张表（跨 sqlite/postgres/mysql 兼容，DCL 参考 m20260819_000001_oauth_module）：
//!   1. sys_oauth_client   已注册 OAuth2/OIDC 客户端（应用）配置
//!      - client_id        公开标识（应用侧使用，唯一）
//!      - client_secret_hash 明文密钥的 SHA-256（仅创建时返回一次明文，落库只存摘要）
//!      - id_token_secret  HS256 对称签名密钥（仅服务端签名使用，永不出现在出参）
//!      - redirect_uris / scopes / grant_types 为 JSON 数组字符串
//!      - consent_required '1' 首次授权需用户同意；'0' 直接签发授权码
//!      - tenant_id        多租户前向兼容预留（默认 0，本轮不回填存量、不参与过滤）
//!   2. sys_oauth_consent  用户对客户端的授权同意记录（user_id + client_id 唯一）
//!
//! 然后插入菜单元数据（前置约定：单点登录目录 menu_id=145，见 oauth_module）：
//!   - C 页面「SSO 客户端」(menu_id=147, path=client, component=system/oauth/client/index)
//!   - F 按钮权限（add/edit/remove/toggle 关联页面 147）
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
        "m20260922_000001_sso_module"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表 ====================
        up_create_tables(manager).await?;

        // ==================== 2. 菜单元数据 ====================
        let now = now_expr(manager);

        // 2.1 C 页面「SSO 客户端」（挂单点登录目录 145）
        let page_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (147, 'SSO 客户端', 145, 2, 'client', 'system/oauth/client/index', '', '', '1', '0', 'C', '0', '0', 'system:oauth:client:list', 'peoples', 'admin', {now}, 'OIDC Provider 已注册客户端管理', '0')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 147)")
            .await?;

        // 2.2 F 按钮权限（关联页面 147）
        let btn_rows: &[(i64, &str, i64, &str)] = &[
            (3265, "客户端新增", 147, "system:oauth:client:add"),
            (3266, "客户端修改", 147, "system:oauth:client:edit"),
            (3267, "客户端删除", 147, "system:oauth:client:remove"),
            (3268, "客户端启停", 147, "system:oauth:client:toggle"),
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
        let menu_ids = [147, 3265, 3266, 3267, 3268];
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

        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_oauth_consent")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_oauth_client")
            .await?;
        Ok(())
    }
}

/// 建两张表（跨库兼容）
async fn up_create_tables(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // -------- sys_oauth_client --------
    let client_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_client (
            sso_client_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id         VARCHAR(64) NOT NULL UNIQUE,
            client_secret_hash VARCHAR(64) NOT NULL DEFAULT '',
            id_token_secret   VARCHAR(128) NOT NULL DEFAULT '',
            client_name       VARCHAR(128) NOT NULL,
            logo_uri          VARCHAR(500) NOT NULL DEFAULT '',
            redirect_uris     TEXT NOT NULL,
            scopes            TEXT NOT NULL,
            grant_types       TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]',
            consent_required  VARCHAR(1) NOT NULL DEFAULT '1',
            enabled           VARCHAR(1) NOT NULL DEFAULT '1',
            remark            VARCHAR(500),
            tenant_id         INTEGER NOT NULL DEFAULT 0,
            create_by         VARCHAR(64) DEFAULT '',
            create_time       DATETIME,
            update_time       DATETIME
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_client (
            sso_client_id     BIGSERIAL PRIMARY KEY,
            client_id         VARCHAR(64) NOT NULL UNIQUE,
            client_secret_hash VARCHAR(64) NOT NULL DEFAULT '',
            id_token_secret   VARCHAR(128) NOT NULL DEFAULT '',
            client_name       VARCHAR(128) NOT NULL,
            logo_uri          VARCHAR(500) NOT NULL DEFAULT '',
            redirect_uris     TEXT NOT NULL,
            scopes            TEXT NOT NULL,
            grant_types       TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]',
            consent_required  VARCHAR(1) NOT NULL DEFAULT '1',
            enabled           VARCHAR(1) NOT NULL DEFAULT '1',
            remark            VARCHAR(500),
            tenant_id         BIGINT NOT NULL DEFAULT 0,
            create_by         VARCHAR(64) DEFAULT '',
            create_time       TIMESTAMP,
            update_time       TIMESTAMP
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_client (
            sso_client_id     BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            client_id         VARCHAR(64) NOT NULL UNIQUE,
            client_secret_hash VARCHAR(64) NOT NULL DEFAULT '',
            id_token_secret   VARCHAR(128) NOT NULL DEFAULT '',
            client_name       VARCHAR(128) NOT NULL,
            logo_uri          VARCHAR(500) NOT NULL DEFAULT '',
            redirect_uris     TEXT NOT NULL,
            scopes            TEXT NOT NULL,
            grant_types       VARCHAR(500) NOT NULL DEFAULT '["authorization_code","refresh_token"]',
            consent_required  VARCHAR(1) NOT NULL DEFAULT '1',
            enabled           VARCHAR(1) NOT NULL DEFAULT '1',
            remark            VARCHAR(500),
            tenant_id         BIGINT NOT NULL DEFAULT 0,
            create_by         VARCHAR(64) DEFAULT '',
            create_time       DATETIME,
            update_time       DATETIME
        )"#
    };
    manager
        .get_connection()
        .execute_unprepared(client_sql)
        .await?;

    // -------- sys_oauth_consent --------
    // 授权同意表：user_id + client_id 唯一，scopes 记录已授予范围
    let consent_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_consent (
            consent_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       BIGINT NOT NULL,
            client_id     VARCHAR(64) NOT NULL,
            scopes        TEXT NOT NULL,
            auth_time     DATETIME,
            create_time   DATETIME,
            update_time   DATETIME,
            UNIQUE(user_id, client_id)
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_consent (
            consent_id    BIGSERIAL PRIMARY KEY,
            user_id       BIGINT NOT NULL,
            client_id     VARCHAR(64) NOT NULL,
            scopes        TEXT NOT NULL,
            auth_time     TIMESTAMP,
            create_time   TIMESTAMP,
            update_time   TIMESTAMP,
            UNIQUE(user_id, client_id)
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_oauth_consent (
            consent_id    BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id       BIGINT NOT NULL,
            client_id     VARCHAR(64) NOT NULL,
            scopes        TEXT NOT NULL,
            auth_time     DATETIME,
            create_time   DATETIME,
            update_time   DATETIME,
            UNIQUE KEY uk_sso_consent_user_client (user_id, client_id)
        )"#
    };
    manager
        .get_connection()
        .execute_unprepared(consent_sql)
        .await?;

    // 索引：按用户查询已授权客户端
    manager
        .get_connection()
        .execute_index_ddl_ic("CREATE INDEX idx_sso_consent_user_id ON sys_oauth_consent (user_id)")
        .await?;

    Ok(())
}
