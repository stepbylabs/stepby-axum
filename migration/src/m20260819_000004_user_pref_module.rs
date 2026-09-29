// stepby-axum/migration/src/m20260819_000004_user_pref_module.rs
//! 个人中心：消息偏好 + 免打扰 模块迁移
//!
//! 新增单表（跨 sqlite/postgres/mysql 兼容，参考 m20260818_000002_msg_module）：
//!   sys_user_pref  用户消息偏好表（以 user_id 为主键，每用户至多一行）
//!     - email_notify    是否接收公告邮件（'1'=接收 默认，'0'=关闭）
//!     - sysmsg_notify   是否接收站内信通知（'1' 默认，'0'=关闭）
//!     - announce_notify 是否接收通知公告（'1' 默认，'0'=关闭）
//!     - dnd_enabled     是否启用免打扰（'0' 默认 关闭，'1'=启用）
//!     - dnd_start / dnd_end  免打扰时间段（HH:MM，支持跨天）
//!     - extra   扩展 JSON（预留，可为 NULL）
//!     - update_time
//!
//! 不插入任何菜单元数据（本功能挂在个人中心 Tab，非后台管理菜单）。
//!
//! 幂等：全部走 CREATE TABLE IF NOT EXISTS。

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

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260819_000004_user_pref_module"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let create_sql = if is_sqlite(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_user_pref (
                user_id         BIGINT PRIMARY KEY,
                email_notify    VARCHAR(1) NOT NULL DEFAULT '1',
                sysmsg_notify   VARCHAR(1) NOT NULL DEFAULT '1',
                announce_notify VARCHAR(1) NOT NULL DEFAULT '1',
                dnd_enabled     VARCHAR(1) NOT NULL DEFAULT '0',
                dnd_start       VARCHAR(5) NOT NULL DEFAULT '',
                dnd_end         VARCHAR(5) NOT NULL DEFAULT '',
                extra           TEXT,
                update_time     DATETIME
            )"#
        } else if is_postgres(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_user_pref (
                user_id         BIGINT PRIMARY KEY,
                email_notify    VARCHAR(1) NOT NULL DEFAULT '1',
                sysmsg_notify   VARCHAR(1) NOT NULL DEFAULT '1',
                announce_notify VARCHAR(1) NOT NULL DEFAULT '1',
                dnd_enabled     VARCHAR(1) NOT NULL DEFAULT '0',
                dnd_start       VARCHAR(5) NOT NULL DEFAULT '',
                dnd_end         VARCHAR(5) NOT NULL DEFAULT '',
                extra           TEXT,
                update_time     TIMESTAMP
            )"#
        } else {
            r#"CREATE TABLE IF NOT EXISTS sys_user_pref (
                user_id         BIGINT NOT NULL PRIMARY KEY,
                email_notify    VARCHAR(1) NOT NULL DEFAULT '1',
                sysmsg_notify   VARCHAR(1) NOT NULL DEFAULT '1',
                announce_notify VARCHAR(1) NOT NULL DEFAULT '1',
                dnd_enabled     VARCHAR(1) NOT NULL DEFAULT '0',
                dnd_start       VARCHAR(5) NOT NULL DEFAULT '',
                dnd_end         VARCHAR(5) NOT NULL DEFAULT '',
                extra           TEXT,
                update_time     DATETIME
            )"#
        };
        manager
            .get_connection()
            .execute_unprepared(create_sql)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_user_pref")
            .await?;
        Ok(())
    }
}
