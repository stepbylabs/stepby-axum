// axum-backend/migration/src/m20260924_000004_sso_subject_type.rs
//! v5-D5：客户端 subject 标识类型（OIDC Core §8）。
//!
//! - `public`（默认）：所有 RP 看到相同 sub（= user_id 字符串）；
//! - `pairwise`：每个 RP 看到不同的稳定假名 sub（SHA-256(client_id:user_id) 截断），
//!   防止 RP 间通过 sub 串联用户画像。切换类型会使已发令牌的 sub 变化——RP 侧视为新用户，
//!   运维需知悉（文档 §9 声明）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260924_000004_sso_subject_type"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE sys_oauth_client ADD COLUMN subject_type VARCHAR(8) NOT NULL DEFAULT 'public'",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_oauth_client DROP COLUMN subject_type")
            .await?;
        Ok(())
    }
}
