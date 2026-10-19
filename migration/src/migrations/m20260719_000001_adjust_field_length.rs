// stepby-axum/migration/src/migrations/m20260719_000001_adjust_field_length.rs
//! 第五次迁移：调整字段长度（P2-30 + P2-31）
//!
//! 修改内容：
//! 1. P2-30: sys_job.cron_expression  VARCHAR(255) → VARCHAR(64)
//!    cron 表达式实际长度不会超过 64 字符，原 255 过宽，收缩以规范 schema。
//! 2. P2-31: sys_dept.ancestors       VARCHAR(50)  → VARCHAR(500)
//!    部门树层级较深时 ancestors 路径（如 0,100,200,300,...）可能超过 50 字符，
//!    扩展到 500 以容纳更深层级。
//!
//! 数据库兼容性说明：
//! - PostgreSQL：使用 `ALTER TABLE ... ALTER COLUMN ... TYPE VARCHAR(n)`，
//!   仅修改类型，保留原有 DEFAULT 与 NULL 属性。
//! - MySQL：使用 `ALTER TABLE ... MODIFY COLUMN ... VARCHAR(n) DEFAULT ''`。
//!   MySQL 的 MODIFY COLUMN 会重置列的全部属性，因此显式重新声明 `DEFAULT ''`
//!   （与建表语句 m20250711_000001 中 `.default("")` 一致）。
//! - SQLite：不强制 VARCHAR 长度（存储类型统一为 TEXT），字段长度修改无实际意义，
//!   且 SQLite 不支持 ALTER COLUMN TYPE / MODIFY COLUMN 语法，故跳过并输出 warn 日志。
//!
//! 注意：
//! - sys_job.cron_expression 收缩为 VARCHAR(64)，若已有数据超过 64 字符，
//!   MySQL/PG 的 ALTER 可能失败（数据超长）。执行前请确认现有数据长度。
//! - sys_dept.ancestors 扩展到 500 属于宽松化，不会因现有数据失败。
//! - down 方法将字段恢复为原始长度（255 / 50），回滚前同样需确认数据长度。
//!
//! 实现说明：
//! - 后端检测沿用本 crate 既有模式（见 m20250711_000001_init.rs）：
//!   `manager.get_connection().get_database_backend()` 返回
//!   `sea_orm_migration::sea_orm::DatabaseBackend`。
//! - 通过 `execute_unprepared` 执行原始 SQL，避免 sea-orm-migration 的
//!   `modify_column` 在 SQLite 上不兼容的问题。
//! - 本 migration crate 未引入 tracing 依赖（Cargo.toml 不可改动），
//!   故使用 `eprintln!` 输出 SQLite 跳过警告到 stderr。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260719_000001_adjust_field_length"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        match backend {
            sea_orm_migration::sea_orm::DatabaseBackend::MySql => {
                // MySQL: MODIFY COLUMN 需重新声明默认值（与建表 default("") 一致）
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_job MODIFY COLUMN cron_expression VARCHAR(64) DEFAULT ''",
                    )
                    .await?;
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_dept MODIFY COLUMN ancestors VARCHAR(500) DEFAULT ''",
                    )
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Postgres => {
                // PostgreSQL: ALTER COLUMN TYPE 保留默认值与 NULL 属性
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_job ALTER COLUMN cron_expression TYPE VARCHAR(64)",
                    )
                    .await?;
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_dept ALTER COLUMN ancestors TYPE VARCHAR(500)",
                    )
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
                // SQLite 不强制 VARCHAR 长度，跳过（避免不支持的 ALTER 语法）
                eprintln!(
                    "[migration][warn] m20260719_000001: SQLite 不强制 VARCHAR 长度，\
                     跳过 sys_job.cron_expression / sys_dept.ancestors 字段长度修改"
                );
            }
            _ => unreachable!("unknown backend"),
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        match backend {
            sea_orm_migration::sea_orm::DatabaseBackend::MySql => {
                // 反向恢复原始长度（255 / 50）
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_job MODIFY COLUMN cron_expression VARCHAR(255) DEFAULT ''",
                    )
                    .await?;
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_dept MODIFY COLUMN ancestors VARCHAR(50) DEFAULT ''",
                    )
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Postgres => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_job ALTER COLUMN cron_expression TYPE VARCHAR(255)",
                    )
                    .await?;
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_dept ALTER COLUMN ancestors TYPE VARCHAR(50)",
                    )
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
                eprintln!(
                    "[migration][warn] m20260719_000001: SQLite 不强制 VARCHAR 长度，\
                     跳过 sys_job.cron_expression / sys_dept.ancestors 字段长度回滚"
                );
            }
            _ => unreachable!("unknown backend"),
        }
        Ok(())
    }
}
