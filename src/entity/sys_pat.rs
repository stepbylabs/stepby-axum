//! sys_pat 实体定义（个人访问令牌 Personal Access Token）
//!
//! 供第三方/脚本以 `Authorization: Bearer ybt_xxx` 长期访问受保护 API。
//! 安全设计：
//! - 仅存 `token_hash`（SHA-256 hex），明文只在创建接口返回一次，绝不落库；
//! - `token_prefix` 存展示用前缀（如 `ybt_ab12…`），用于列表辨识；
//! - `scopes` 为权限标识 JSON 数组（如 `["system:notice:list"]`），请求时按段通配匹配；
//! - `status`：'0' 有效 / '1' 已吊销，吊销即时生效（每请求查库）。
//!
//! 出参不直接序列化本 Model（含 `token_hash`），由 Service 层 `PatVo` 脱敏后返回。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::common::datetime;

#[derive(Clone, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_pat")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    /// 令牌 ID（应用生成的 uuid hex，非自增，跨方言可移植）
    #[sea_orm(primary_key, auto_increment = false)]
    pub pat_id: String,
    /// 属主用户 ID
    pub user_id: i64,
    /// 令牌名称（用户自定义备注）
    pub name: String,
    /// 令牌明文的 SHA-256 hex（唯一，用于鉴权查库）
    pub token_hash: String,
    /// 展示前缀（如 `ybt_ab12`）
    pub token_prefix: String,
    /// 权限范围 JSON 数组字符串
    pub scopes: String,
    /// 状态：'0' 有效，'1' 已吊销
    pub status: String,
    /// 过期时间（NULL 表示永不过期，实际受配置上限约束）
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub expires_at: Option<NaiveDateTime>,
    /// 最近使用时间（best-effort 更新）
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub last_used_at: Option<NaiveDateTime>,
    /// 创建人
    pub create_by: String,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub create_time: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub update_time: Option<NaiveDateTime>,
}

/// 手写 Debug：脱敏 token_hash（避免调试日志泄漏令牌摘要）
impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SysPat")
            .field("pat_id", &self.pat_id)
            .field("user_id", &self.user_id)
            .field("name", &self.name)
            .field("token_hash", &"<redacted>")
            .field("token_prefix", &self.token_prefix)
            .field("scopes", &self.scopes)
            .field("status", &self.status)
            .field("expires_at", &self.expires_at)
            .field("last_used_at", &self.last_used_at)
            .field("create_by", &self.create_by)
            .field("create_time", &self.create_time)
            .field("update_time", &self.update_time)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
