// axum-backend/migration/src/m20260923_000001_sso_v4_hardening.rs
//! SSO v4 安全加固迁移（对应 docs/optimization/topic-sso-multitenant-v4-final-2026-09-23.md）
//!
//! 1. sys_oauth_client：
//!    - 新增 `update_by`（审计：最后修改人，v4-R7）
//!    - 新增 `del_flag`（v2-K7/P1-5：客户端**软删**，del_flag='2'；client_id 唯一约束
//!      不因软删释放，防"重建同名 client 继承旧授权"的静默授权风险）
//! 2. sys_oauth_consent：
//!    - `auth_time` 更名为 `consented_at`（v4-R4：同名字段语义修正——该列记录的是
//!      "同意/授权时刻"，与 ID Token 的 auth_time（认证时刻）是两个概念，不得混用）
//!    - 存量回填：`consented_at` 为 NULL 的旧记录用 `create_time` 补齐
//!    - 新增 `client_name_snapshot`（v4-R6：同意时的客户端名称快照——客户端事后改名
//!      不得追溯篡改用户"已授权应用"页展示的授权对象）
//!    - 新增 `del_flag`（v2-I7：用户撤销授权 = 软删，保留审计痕迹）
//!    - 存量回填：`client_name_snapshot` 为空时从 sys_oauth_client 取当前名称
//! 3. grant_types 修正：refresh_token 授权类型服务端从未实现（token 端点仅接受
//!    authorization_code），历史默认值误导接入方 → 存量含 refresh_token 的行统一改为
//!    ["authorization_code"]（v4 §1.2）
//!
//! 兼容性：ALTER TABLE ADD/RENAME COLUMN 与相关 UPDATE 均为 sqlite/postgres/mysql 8+ 通用语法。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260923_000001_sso_v4_hardening"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // ==================== 1. sys_oauth_client：update_by / del_flag ====================
        conn.execute_unprepared(
            "ALTER TABLE sys_oauth_client ADD COLUMN update_by VARCHAR(64) DEFAULT ''",
        )
        .await?;
        conn.execute_unprepared(
            "ALTER TABLE sys_oauth_client ADD COLUMN del_flag VARCHAR(1) NOT NULL DEFAULT '0'",
        )
        .await?;

        // ==================== 2. sys_oauth_consent：语义修正 + 快照 + 软删 ====================
        conn.execute_unprepared(
            "ALTER TABLE sys_oauth_consent RENAME COLUMN auth_time TO consented_at",
        )
        .await?;
        conn.execute_unprepared(
            "ALTER TABLE sys_oauth_consent ADD COLUMN client_name_snapshot VARCHAR(128) NOT NULL DEFAULT ''",
        )
        .await?;
        conn.execute_unprepared(
            "ALTER TABLE sys_oauth_consent ADD COLUMN del_flag VARCHAR(1) NOT NULL DEFAULT '0'",
        )
        .await?;
        // 存量回填：同意时刻缺省用创建时间；客户端名快照缺省取当前名称
        conn.execute_unprepared(
            "UPDATE sys_oauth_consent SET consented_at = create_time WHERE consented_at IS NULL",
        )
        .await?;
        conn.execute_unprepared(
            "UPDATE sys_oauth_consent SET client_name_snapshot = COALESCE(\
                (SELECT c.client_name FROM sys_oauth_client c WHERE c.client_id = sys_oauth_consent.client_id), '') \
             WHERE client_name_snapshot = ''",
        )
        .await?;

        // ==================== 3. grant_types 修正（refresh_token 未实现，去除误导） ====================
        conn.execute_unprepared(
            "UPDATE sys_oauth_client SET grant_types = '[\"authorization_code\"]' \
             WHERE grant_types LIKE '%refresh_token%'",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 反向：仅移除新增列/恢复列名；数据回填不可逆（历史语义无备份来源）
        conn.execute_unprepared(
            "UPDATE sys_oauth_client SET grant_types = '[\"authorization_code\",\"refresh_token\"]'",
        )
        .await?;
        conn.execute_unprepared("ALTER TABLE sys_oauth_consent DROP COLUMN del_flag")
            .await?;
        conn.execute_unprepared("ALTER TABLE sys_oauth_consent DROP COLUMN client_name_snapshot")
            .await?;
        conn.execute_unprepared(
            "ALTER TABLE sys_oauth_consent RENAME COLUMN consented_at TO auth_time",
        )
        .await?;
        conn.execute_unprepared("ALTER TABLE sys_oauth_client DROP COLUMN del_flag")
            .await?;
        conn.execute_unprepared("ALTER TABLE sys_oauth_client DROP COLUMN update_by")
            .await?;
        Ok(())
    }
}
