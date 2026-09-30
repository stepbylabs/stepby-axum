// stepby-axum/migration/src/m20260926_000004_oauth_client_key_id.rs
//! 台账 D9（SSO 终稿 §4 低成本预备）：sys_oauth_client 增 `key_id` 密钥版本列。
//!
//! 背景：RS256 客户端签名私钥当前"单密钥"（`rsa_private_key` 信封加密落库），
//! 密钥轮换需要"版本标识"来区分新旧密钥（否则轮换即数据迁移）。本轮只补列并
//! 在密钥生成/导入时写入版本标识（RFC 7638 JWK thumbprint，base64url(SHA-256)），
//! **不实现轮换本身**（合规触发再上，见台账 §5.1 D9/D10）。
//!
//! 存量行留 NULL = 未登记版本（历史密钥）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000004_oauth_client_key_id"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_oauth_client"))
                    .add_column(ColumnDef::new(Alias::new("key_id")).string_len(64).null())
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
                    .drop_column(Alias::new("key_id"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
