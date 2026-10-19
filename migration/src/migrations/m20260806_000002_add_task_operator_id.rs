// stepby-axum/migration/src/migrations/m20260806_000002_add_task_operator_id.rs
//! 迁移：sys_task 表增加 operator_id 列（P0-2 越权广播修复）
//!
//! 背景：taskProgress 消息原通过全局 WS 广播推送给所有在线客户端，存在跨用户
//! 信息泄漏。修复方案：task 记录增加 operator_id（任务创建者 user_id），
//! taskProgress 定向推送给创建者。本迁移为 sys_task 增加该列（可空，兼容历史数据）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260806_000002_add_task_operator_id"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_task"))
                    .add_column(
                        ColumnDef::new(Alias::new("operator_id"))
                            .big_integer()
                            .null()
                            .comment("操作人 user_id（P0-2：taskProgress 定向推送目标，None 为系统任务）"),
                    )
                    .to_owned(),
            )
            .await
    }

    /// 回滚：删掉本迁移新增的 `operator_id` 列（批七十六 R-10 补齐——此前本文件是全仓
    /// 121 条迁移里**唯一**没有 `down()` 的一条，`Migrator::down` 会直接返回
    /// `Migration("We Don't Do That Here")`，把整条回滚链打断在中间）。
    ///
    /// 方言口径与同族 `m20260822_000001` 的 DROP COLUMN 回滚一致：MySQL/PG 支持，
    /// SQLite（3.35 之前的 sea-query 生成路径不支持）跳过并告警，不谎报"已回滚"。
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        match backend {
            sea_orm_migration::sea_orm::DatabaseBackend::MySql
            | sea_orm_migration::sea_orm::DatabaseBackend::Postgres => {
                manager
                    .get_connection()
                    .execute_unprepared("ALTER TABLE sys_task DROP COLUMN operator_id")
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
                eprintln!(
                    "[migration][warn] m20260806_000002: SQLite 不支持 DROP COLUMN，跳过回滚"
                );
            }
            _ => unreachable!("unknown backend"),
        }
        Ok(())
    }
}
