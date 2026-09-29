// stepby-axum/migration/src/m20260721_000002_sys_task.rs
//! 任务进度中心表迁移
//!
//! 新增表：sys_task - 长任务进度跟踪（导出/导入/备份等）
//!
//! 字段说明：
//! - task_id: 主键自增
//! - task_type: export=导出, import=导入, backup=备份, other=其他
//! - task_name: 任务显示名称
//! - status: pending=等待, running=运行中, success=成功, failed=失败
//! - progress: 进度百分比 0-100
//! - total: 任务总量
//! - current: 当前完成量
//! - result_msg: 结果消息（含失败原因或文件下载 URL）
//! - operator: 操作人
//! - create_time / update_time: 时间戳

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

impl sea_orm_migration::MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260721_000002_sys_task"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let sql = if is_sqlite(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_task (
                task_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                task_type    VARCHAR(20) NOT NULL,
                task_name    VARCHAR(200) NOT NULL,
                status       VARCHAR(20) NOT NULL,
                progress     INTEGER NOT NULL DEFAULT 0,
                total        BIGINT NOT NULL DEFAULT 0,
                current      BIGINT NOT NULL DEFAULT 0,
                result_msg   VARCHAR(1000),
                operator     VARCHAR(64),
                create_time  DATETIME,
                update_time  DATETIME
            )"#
            .to_string()
        } else if is_postgres(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_task (
                task_id      BIGSERIAL PRIMARY KEY,
                task_type    VARCHAR(20) NOT NULL,
                task_name    VARCHAR(200) NOT NULL,
                status       VARCHAR(20) NOT NULL,
                progress     INTEGER NOT NULL DEFAULT 0,
                total        BIGINT NOT NULL DEFAULT 0,
                current      BIGINT NOT NULL DEFAULT 0,
                result_msg   VARCHAR(1000),
                operator     VARCHAR(64),
                create_time  TIMESTAMP,
                update_time  TIMESTAMP
            )"#
            .to_string()
        } else {
            r#"CREATE TABLE IF NOT EXISTS sys_task (
                task_id      BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                task_type    VARCHAR(20) NOT NULL,
                task_name    VARCHAR(200) NOT NULL,
                status       VARCHAR(20) NOT NULL,
                progress     INTEGER NOT NULL DEFAULT 0,
                total        BIGINT NOT NULL DEFAULT 0,
                current      BIGINT NOT NULL DEFAULT 0,
                result_msg   VARCHAR(1000),
                operator     VARCHAR(64),
                create_time  DATETIME,
                update_time  DATETIME
            )"#
            .to_string()
        };

        manager.get_connection().execute_unprepared(&sql).await?;

        manager
            .get_connection()
            .execute_index_ddl_ic("CREATE INDEX idx_sys_task_status ON sys_task (status)")
            .await?;
        manager
            .get_connection()
            .execute_index_ddl_ic("CREATE INDEX idx_sys_task_operator ON sys_task (operator)")
            .await?;
        manager
            .get_connection()
            .execute_index_ddl_ic("CREATE INDEX idx_sys_task_create_time ON sys_task (create_time)")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_task")
            .await?;
        Ok(())
    }
}
