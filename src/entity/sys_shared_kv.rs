//! sys_shared_kv 实体定义（SharedStore S2 一次性/短期态承载表）
//!
//! 承载键族（TTL = expire_at UTC 秒，NULL = 永不过期）：
//! `captcha:{uuid}:{ip}`、`online:{hash}`、`user_sessions:{uid}:{ip}:{browser}`、
//! `sso:code:{code}`、`sso:rt:{hash}`、`sso:at:{hash}`、`sso:user_rt:{uid}`、
//! `sso:user_at:{uid}`、`idempotency:*`、`ws_conn:{uid}`、`login_fail:{u}`、
//! `totp:login_fail:{u}`、`totp:enabled:{uid}`、consent 票据、WebAuthn 挑战态等。
//!
//! 注意：本表是 local 档的 S2 承载；redis 档不使用本表（切换后遗留行由 GC 清理）。
//! 仅服务端内部使用，不暴露 API（无 TS/ToSchema 派生）。

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "sys_shared_kv")]
pub struct Model {
    /// 缓存键（对应原 Redis 键名，含冒号分层）
    #[sea_orm(primary_key, auto_increment = false)]
    pub kv_key: String,
    /// 值（原 Redis 值原样存储；SSO 绑定为 JSON 文本）
    pub kv_value: String,
    /// 过期时间（UTC 秒；NULL = 永不过期）；读时惰性判定 + GC 定时清理
    pub expire_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}
