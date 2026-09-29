// stepby-axum/migration/src/m20260924_000007_sector_identifier.rs
//! v5-D5：sys_oauth_client 增 sector_identifier_uri 列。
//!
//! OIDC Core §8：pairwise subject 下，同一 sector（sector_identifier 指向的
//! 聚合）内的多个 RP 应获得**相同**的稳定假名 sub（便于同一组织内账号关联，
//! 同时保持与其它 sector 隔离）。NULL = 未声明 sector，pairwise 以 client_id
//! 为 salt（既有行为，回归不变）。幂等 ensure 由 AppInitializer 兜底。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260924_000007_sector_identifier"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE sys_oauth_client ADD COLUMN sector_identifier_uri VARCHAR(255)",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_oauth_client DROP COLUMN sector_identifier_uri")
            .await?;
        Ok(())
    }
}
