// axum-backend/migration/src/m20260924_000006_scim_external_id.rs
//! v5-D12：SCIM 用户目录同步——sys_user 增 scim_external_id 列。
//!
//! externalId 为 IdP 侧用户唯一标识（RFC 7644 §2.3），以 SCIM 写入后用于
//! IdP 与本系统的稳定关联；NULL = 非 SCIM provision 的本地用户。
//! 唯一索引防同 IdP 重复推送。幂等 ensure 由 AppInitializer 兜底
//!（存量库启动不跑 Migrator::up 的架构约定）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260924_000006_scim_external_id"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_user ADD COLUMN scim_external_id VARCHAR(255)")
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE UNIQUE INDEX idx_sys_user_scim_external_id ON sys_user (scim_external_id)",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS idx_sys_user_scim_external_id")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_user DROP COLUMN scim_external_id")
            .await?;
        Ok(())
    }
}
