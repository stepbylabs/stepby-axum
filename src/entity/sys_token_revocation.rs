//! sys_token_revocation 实体定义（SharedStore S1 吊销权威层）
//!
//! **两档共用的权威持久层**（v5.1 方案）：
//! - local 档：读写本表（每请求 PK 点查，SQLite 本地微秒级）；
//! - redis 档：写路径双写（Redis 当期安全 + 本表幂等落库），读路径走 Redis
//!   （miss 回源本表），启动期从本表幂等回填 Redis → 档位切换无缝。
//!
//! 承载键族（`source` 区分）：
//! - `logout` / `kick`：登出/强退/租户踢线写入的 `blacklist:{token_hash}`
//! - `sso_legacy_at`：v4-F1 历史 JWT 型 SSO AT 转写阻断（原 `sso:at:{hash}` 的
//!   阻断用途；绑定 JSON 仍为 S2 短期态，不落本表）

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "sys_token_revocation")]
pub struct Model {
    /// 令牌 SHA-256 哈希（对应原 Redis `blacklist:{hash}` / `sso:at:{hash}` 的 hash 段）
    #[sea_orm(primary_key, auto_increment = false)]
    pub token_hash: String,
    /// 吊销失效时间（UTC 秒；与原 Redis TTL 对齐，过期后令牌本身也已自然过期）
    pub expire_at: i64,
    /// 吊销来源（logout / kick / sso_legacy_at）
    pub source: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}
