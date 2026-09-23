// axum-backend/migration/src/m20260924_000005_user_tenant_id.rs
//! v5-N2 Phase 2（第一步）：sys_user 增 tenant_id 列，登录 JWT 的 tid 从恒 0
//! 升级为真实数据链路（登录查库带出）。
//!
//! 存量用户默认 0 = 平台单租户；多租户立项后由租户管理功能维护该值。
//! Repository 过滤层（按 tid 注入查询条件）仍属 Phase 2 后续（随立项）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260924_000005_user_tenant_id"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE sys_user ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 0",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_user DROP COLUMN tenant_id")
            .await?;
        Ok(())
    }
}
