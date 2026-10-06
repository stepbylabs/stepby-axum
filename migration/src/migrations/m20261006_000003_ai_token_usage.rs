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
        for col in ["prompt_tokens", "completion_tokens", "total_tokens"] {
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
