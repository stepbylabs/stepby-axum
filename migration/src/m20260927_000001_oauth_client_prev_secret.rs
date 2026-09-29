// stepby-axum/migration/src/m20260927_000001_oauth_client_prev_secret.rs
//! SSO D9（原「定案不做」→ 按准则⑥改为**默认关的过渡期机制**）：
//! `sys_oauth_client` 增 `previous_client_secret_hash` 列，支撑 `client_secret` **零停机轮换**。
//!
//! ## 为什么需要"双密钥读取期"
//!
//! RP（依赖方）用 `client_secret` 在令牌端点做客户端鉴权（RFC 6749 §2.3.1）。
//! 若只保留一把密钥，"改密钥"与"RP 换配置"之间的时间差会**直接造成鉴权失败**（断服）。
//! 标准做法（同 JWT 多密钥轮换）：
//!
//! 1. 轮换：新密钥立即生效，**旧密钥摘要**移入本列 ⇒ 过渡期内两把都能通过鉴权；
//! 2. RP 换配置（可观测：旧密钥命中时可告警）；
//! 3. 过渡期结束：清空本列 ⇒ 旧密钥立即失效。
//!
//! ## 语义与安全
//!
//! - `NULL` = **无过渡期**（默认；与改造前逐字节等价 ⇒ 存量行行为零变更）；
//! - 只存 SHA-256 摘要，明文仅在轮换响应中返回一次；
//! - 两把密钥的校验共用等时比较 `secret_eq`，不引入时序侧信道。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260927_000001_oauth_client_prev_secret"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_oauth_client"))
                    .add_column(
                        ColumnDef::new(Alias::new("previous_client_secret_hash"))
                            .string_len(64)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_oauth_client"))
                    .drop_column(Alias::new("previous_client_secret_hash"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
