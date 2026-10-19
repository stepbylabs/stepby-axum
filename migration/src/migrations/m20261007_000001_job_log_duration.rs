//! G-09 定时任务运行统计报表（P3 审计项，方案深审 2026-10-06）：
//! sys_job_log 追加 `duration_ms` 独立列。
//!
//! 背景：此前任务耗时以字符串拼进 `job_message`（`"... (elapsed 123ms)"`），
//! 报表聚合只能 LIKE 反析文本（脆弱且慢）或全量捞日志应用层正则——不可接受。
//! 本迁移落独立列后，成功率趋势 / 耗时分布 / 失败 TOP 均可直接 SQL/应用层聚合。
//!
//! - duration_ms BIGINT NULL（存量行无耗时数据，容忍 NULL）
//! - 存量库兜底：initialize 侧幂等 ALTER（SQLite 无 IF NOT EXISTS，按错误忽略）

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000001_job_log_duration"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 存量库兜底可能已补列而不登记版本 ⇒ 无守卫 ADD COLUMN 会 duplicate column 硬失败
        // （与本批 chain_hash / prompt_tokens / actions_json 同族，逐列 has_column 口径）。
        if manager.has_column("sys_job_log", "duration_ms").await? {
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_job_log"))
                    .add_column(
                        ColumnDef::new(Alias::new("duration_ms"))
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_column("sys_job_log", "duration_ms").await? {
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_job_log"))
                    .drop_column(Alias::new("duration_ms"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
