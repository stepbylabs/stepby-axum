// axum-backend/migration/src/m20260721_000001_sys_backup_log.rs
//! 数据备份日志表迁移
//!
//! 新增表：sys_backup_log - 数据备份/恢复操作日志
//!
//! 字段说明：
//! - backup_id: 主键自增
//! - file_name: 备份文件名（含扩展名）
//! - file_path: 备份文件相对路径
//! - file_size: 文件字节数
//! - backup_type: manual=手动备份, auto=自动备份, restore=恢复
//! - status: success=成功, failed=失败
//! - error_msg: 失败原因（status=failed 时填充）
//! - create_by: 操作人
//! - create_time: 操作时间

use sea_orm_migration::prelude::*;
use crate::IndexDdlExt;

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

impl sea_orm_migration::MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260721_000001_sys_backup_log"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let sql = if is_sqlite(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_backup_log (
                backup_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name    VARCHAR(200) NOT NULL,
                file_path    VARCHAR(500) NOT NULL,
                file_size    BIGINT NOT NULL DEFAULT 0,
                backup_type  VARCHAR(20) NOT NULL,
                status       VARCHAR(20) NOT NULL,
                error_msg    VARCHAR(1000),
                create_by    VARCHAR(64),
                create_time  DATETIME
            )"#
            .to_string()
        } else if is_postgres(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_backup_log (
                backup_id    BIGSERIAL PRIMARY KEY,
                file_name    VARCHAR(200) NOT NULL,
                file_path    VARCHAR(500) NOT NULL,
                file_size    BIGINT NOT NULL DEFAULT 0,
                backup_type  VARCHAR(20) NOT NULL,
                status       VARCHAR(20) NOT NULL,
                error_msg    VARCHAR(1000),
                create_by    VARCHAR(64),
                create_time  TIMESTAMP
            )"#
            .to_string()
        } else {
            r#"CREATE TABLE IF NOT EXISTS sys_backup_log (
                backup_id    BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                file_name    VARCHAR(200) NOT NULL,
                file_path    VARCHAR(500) NOT NULL,
                file_size    BIGINT NOT NULL DEFAULT 0,
                backup_type  VARCHAR(20) NOT NULL,
                status       VARCHAR(20) NOT NULL,
                error_msg    VARCHAR(1000),
                create_by    VARCHAR(64),
                create_time  DATETIME
            )"#
            .to_string()
        };

        manager.get_connection().execute_unprepared(&sql).await?;

        // 普通索引：backup_type / create_time
        manager
            .get_connection()
            .execute_index_ddl_ic(
                "CREATE INDEX idx_sys_backup_log_type ON sys_backup_log (backup_type)",
            )
            .await?;
        manager
            .get_connection()
            .execute_index_ddl_ic(
                "CREATE INDEX idx_sys_backup_log_create_time ON sys_backup_log (create_time)",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_backup_log")
            .await?;
        Ok(())
    }
}
