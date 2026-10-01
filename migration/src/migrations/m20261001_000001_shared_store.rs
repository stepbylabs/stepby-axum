// stepby-axum/migration/src/migrations/m20261001_000001_shared_store.rs
//! 共享态存储（SharedStore）三表迁移。
//!
//! 定位：`[cache].mode = local | redis` 双档架构的 S1/S2 持久层（方案见
//! `docs/optimization/ZERO-DEPENDENCY-DEPLOYMENT-PLAN-2026-10-01.md` v5.1）。
//! - `sys_shared_kv`：S2 一次性/短期态（验证码、在线会话、user_sessions 互踢索引、
//!   SSO 授权码/RT/AT 绑定、幂等槽位、ws_conn 计数、登录失败计数、consent 票据、
//!   WebAuthn 挑战态等）——键值 + 可空过期时间戳（UTC 秒；NULL = 永不过期）。
//! - `sys_shared_lock`：调度锁（job 防重入 + 集群整轮互斥），单语句 CAS（token 比对）。
//! - `sys_token_revocation`：S1 吊销权威层（blacklist 与历史 JWT 型 SSO AT 阻断同表，
//!   `source` 区分）。**两档共用的权威层**：local 档读写此表；redis 档双写
//!   （Redis 当期安全 + DB 幂等落库）并在启动期回填 Redis（档位切换无缝）。
//!
//! `sys_user.password_version` 列由 `initialize::ensure_user_password_version_column`
//! 幂等兜底补齐（与 `ensure_user_tenant_id_column` 同范式：先查列存在再 ALTER，
//! 规避 MySQL 不支持 `ADD COLUMN IF NOT EXISTS` 的方言差异）。
//!
//! ⚠️ 存量库（embedded）按架构约定不跑 `Migrator::up`，由 `initialize` 的
//! `ensure_shared_store_tables` 幂等兜底建表（两处字段必须一致）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261001_000001_shared_store"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ── 1. sys_shared_kv：S2 一次性/短期态（键值 + UTC 秒过期）──
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("sys_shared_kv"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("kv_key"))
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Alias::new("kv_value")).text().not_null())
                    .col(ColumnDef::new(Alias::new("expire_at")).big_integer().null())
                    .to_owned(),
            )
            .await?;

        // 过期 GC 与 auth 无关（auth 走 PK 点查）；GC 任务按 expire_at 扫描
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_shared_kv_expire_at")
                    .table(Alias::new("sys_shared_kv"))
                    .col(Alias::new("expire_at"))
                    .to_owned(),
            )
            .await?;

        // ── 2. sys_shared_lock：调度锁（单语句 CAS）──
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("sys_shared_lock"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("lock_key"))
                            .string_len(255)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("lock_token"))
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("expire_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // ── 3. sys_token_revocation：S1 吊销权威层（blacklist + 历史 SSO AT 阻断）──
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("sys_token_revocation"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("token_hash"))
                            .string_len(128)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("expire_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("source"))
                            .string_len(32)
                            .not_null()
                            .default("logout"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_token_revocation_expire_at")
                    .table(Alias::new("sys_token_revocation"))
                    .col(Alias::new("expire_at"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for t in ["sys_token_revocation", "sys_shared_lock", "sys_shared_kv"] {
            manager
                .drop_table(Table::drop().if_exists().table(Alias::new(t)).to_owned())
                .await?;
        }
        Ok(())
    }
}
