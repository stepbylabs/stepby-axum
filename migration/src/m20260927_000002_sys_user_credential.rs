// axum-backend/migration/src/m20260927_000002_sys_user_credential.rs
//! WebAuthn / Passkey 凭据表（sys_user_credential）迁移。
//!
//! 能力位 `auth.webauthn`（默认 off）的持久化载体：每个用户可绑定多个 passkey。
//!
//! - `cred_id`        自增主键（API 删除路径参数 `credId`）
//! - `user_id`        属主用户
//! - `tenant_id`      多租户归属（默认 0 = 平台租户）
//! - `credential_id`  认证器唯一凭据 ID（Base64url，**唯一索引**，登录查库键）
//! - `public_key`     Base64url 编码的 COSE 公钥
//! - `name`           人类可读凭据名
//! - `sign_count`     签名计数器（防克隆检测）
//! - `last_used_at`   最近一次成功认证时间（可空）
//! - `create_time`    创建时间
//! - `del_flag`       软删标记（默认 '0'；删除走物理删除，本列保留以复用全库过滤口径）
//!
//! 索引：`uk_sys_user_credential_credential_id`（唯一，认证热路径）、
//!       `idx_sys_user_credential_user_id`（列表）。
//!
//! ⚠️ 存量库（embedded）按架构约定**不跑 `Migrator::up`**，由 `initialize` 的
//! `ensure_sys_user_credential_table` 幂等兜底建表（两处字段必须一致）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260927_000002_sys_user_credential"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("sys_user_credential"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("cred_id"))
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("user_id"))
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("tenant_id"))
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Alias::new("credential_id"))
                            .string_len(512)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Alias::new("public_key")).text().not_null())
                    .col(
                        ColumnDef::new(Alias::new("name"))
                            .string_len(255)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("sign_count"))
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Alias::new("last_used_at"))
                            .date_time()
                            .null(),
                    )
                    .col(ColumnDef::new(Alias::new("create_time")).date_time().null())
                    .col(
                        ColumnDef::new(Alias::new("del_flag"))
                            .string_len(1)
                            .not_null()
                            .default("0"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("uk_sys_user_credential_credential_id")
                    .unique()
                    .table(Alias::new("sys_user_credential"))
                    .col(Alias::new("credential_id"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_user_credential_user_id")
                    .table(Alias::new("sys_user_credential"))
                    .col(Alias::new("user_id"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .if_exists()
                    .table(Alias::new("sys_user_credential"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
