// axum-backend/migration/src/m20260722_000002_oper_log_before.rs
//! 操作日志变更前快照字段迁移
//!
//! 在 sys_oper_log 表新增 oper_before 列（TEXT 类型，可空），
//! 用于审计追踪：中间件对 PUT/DELETE 请求自动捕获变更前数据快照（JSON 字符串）。
//!
//! 字段位置：紧跟 oper_param 之后（MySQL 使用 AFTER 子句定位）。
//!
//! 数据库兼容性说明：
//! - MySQL：使用 `ALTER TABLE ... ADD COLUMN ... AFTER oper_param` 精确定位字段顺序
//! - PostgreSQL：使用 `ALTER TABLE ... ADD COLUMN ...`（PG 不支持 AFTER，按表尾追加）
//! - SQLite：使用 `ALTER TABLE ... ADD COLUMN ...`（SQLite 同样不支持 AFTER）

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260722_000002_oper_log_before"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        match backend {
            sea_orm_migration::sea_orm::DatabaseBackend::MySql => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_oper_log ADD COLUMN oper_before TEXT DEFAULT NULL AFTER oper_param",
                    )
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Postgres => {
                manager
                    .get_connection()
                    .execute_unprepared("ALTER TABLE sys_oper_log ADD COLUMN oper_before TEXT")
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
                manager
                    .get_connection()
                    .execute_unprepared("ALTER TABLE sys_oper_log ADD COLUMN oper_before TEXT")
                    .await?;
            }
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        match backend {
            sea_orm_migration::sea_orm::DatabaseBackend::MySql
            | sea_orm_migration::sea_orm::DatabaseBackend::Postgres => {
                manager
                    .get_connection()
                    .execute_unprepared("ALTER TABLE sys_oper_log DROP COLUMN oper_before")
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
                eprintln!(
                    "[migration][warn] m20260722_000002: SQLite 不支持 DROP COLUMN，跳过回滚"
                );
            }
        }
        Ok(())
    }
}
