// stepby-axum/migration/src/m20260924_000003_sso_rs256.rs
//! v5-D2：ID Token 签名升级支持 RS256（非对称）。
//!
//! - `id_token_alg`：该客户端 ID Token 的签名算法（RS256/HS256）。
//!   新增客户端默认 RS256（主流 RP 客户端库的原生算法，消除 HS256 互操作边界）；
//!   运维可改回 HS256（验签密钥=client_secret，经注册通道分发）。
//! - `rsa_private_key`：RS256 私钥（PKCS#8 PEM，信封加密落库，v5-E6 同款
//!   seal/unseal_sensitive_value）；公钥经 /sso/jwks 发布（聚合所有启用客户端）。
//!
//! 兼容性：存量客户端默认 RS256，`rsa_private_key` 为 NULL——启动时由
//! AppInitializer::ensure_sso_rs256_keys 为其懒生成（见 initialize/mod.rs），
//! 生成前签发请求回落 HS256（过渡窗口极短，且 HS256/RS256 均为合法声明算法）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260924_000003_sso_rs256"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE sys_oauth_client ADD COLUMN id_token_alg VARCHAR(8) NOT NULL DEFAULT 'RS256'",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_oauth_client ADD COLUMN rsa_private_key TEXT")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_oauth_client DROP COLUMN rsa_private_key")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_oauth_client DROP COLUMN id_token_alg")
            .await?;
        Ok(())
    }
}
