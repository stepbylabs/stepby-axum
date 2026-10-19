// stepby-axum/migration/src/migrations/m20261006_000003_ai_token_usage.rs
//! AI-02 token 用量观测（§5.57，P2 立项项）：
//! ai_chat_history 追加三列用量字段（OpenAI 兼容协议 usage 三值）。
//!
//! - prompt_tokens / completion_tokens / total_tokens BIGINT NULL
//! - provider 未返回 usage 时为 NULL（容忍）
//! - 存量库兜底：initialize 侧幂等 ALTER（SQLite 无 IF NOT EXISTS，按错误忽略）

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261006_000003_ai_token_usage"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 逐列 has_column 守卫：存量库不跑 Migrator::up，而兜底路径可能已按存在性补过列
        // ⇒ 版本号没登记时，无守卫的 ADD COLUMN 会以 `duplicate column name: prompt_tokens`
        // 硬失败（2026-10-18 存量库逐条前推实测）。口径同 m20261007_000006 / flow.rs 兜底。
        for col in ["prompt_tokens", "completion_tokens", "total_tokens"] {
            if manager.has_column("ai_chat_history", col).await? {
                continue;
            }
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("ai_chat_history"))
                        .add_column(ColumnDef::new(Alias::new(col)).big_integer().null())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for col in ["total_tokens", "completion_tokens", "prompt_tokens"] {
            if !manager.has_column("ai_chat_history", col).await? {
                continue;
            }
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("ai_chat_history"))
                        .drop_column(Alias::new(col))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
