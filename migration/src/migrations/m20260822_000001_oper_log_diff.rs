// stepby-axum/migration/src/m20260822_000001_oper_log_diff.rs
//! 操作日志字段级变更差异（Tier-S #2）迁移
//!
//! 在 sys_oper_log 表新增 oper_diff 列（TEXT 类型，可空）。
//! 中间件对成功执行的 PUT（修改）请求，比对"变更前快照"与"变更后重新读取的快照"，
//! 计算逐字段 before→after 差异（JSON 数组），供审计详情页精确展示"哪些字段、从什么改成了什么"。
//!
//! 字段位置：紧跟 oper_before 之后（MySQL 使用 AFTER 子句定位）。
//!
//! 数据库兼容性说明：
//! - MySQL：`ALTER TABLE ... ADD COLUMN ... AFTER oper_before` 精确定位字段顺序
//! - PostgreSQL / SQLite：不支持 AFTER，按表尾追加

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260822_000001_oper_log_diff"
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
                        "ALTER TABLE sys_oper_log ADD COLUMN oper_diff TEXT DEFAULT NULL AFTER oper_before",
                    )
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Postgres => {
                manager
                    .get_connection()
                    .execute_unprepared("ALTER TABLE sys_oper_log ADD COLUMN oper_diff TEXT")
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
                manager
                    .get_connection()
                    .execute_unprepared("ALTER TABLE sys_oper_log ADD COLUMN oper_diff TEXT")
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
                    .execute_unprepared("ALTER TABLE sys_oper_log DROP COLUMN oper_diff")
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
                eprintln!(
                    "[migration][warn] m20260822_000001: SQLite 不支持 DROP COLUMN，跳过回滚"
                );
            }
        }
        Ok(())
    }
}
