//! sys_oauth_client 实体定义（OIDC Provider：已注册客户端/应用配置表）
//!
//! 与 sys_oauth_provider（本系统作为第三方登录**消费方**）方向相反：
//! 本表登记**以 Yebot 为身份中心**的外部应用，本系统作为授权服务器为其签发令牌。
//!
//! 安全设计：
//! - `client_secret_hash` 存明文密钥的 SHA-256 hex（明文仅创建时返回一次，绝不落库）；
//! - `id_token_secret` 为 HS256 对称签名密钥，仅服务端签发 ID Token 使用，永不出现在出参；
//! - `redirect_uris` / `scopes` / `grant_types` 为 JSON 数组字符串；redirect_uri 采用精确匹配白名单；
//! - `tenant_id` 多租户前向兼容预留（默认 0，本轮不参与查询过滤）。
//!
//! 出参不直接序列化本 Model（含两处密钥），由 Service 层 `SsoClientVo` 脱敏后返回。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::common::datetime;

/// 注意：不 derive(Debug)，改用手动实现以脱敏 client_secret_hash / id_token_secret
#[derive(Clone, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_oauth_client")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    /// 内部自增主键（供后台 CRUD 定位；对外标识使用 client_id）
    #[sea_orm(primary_key)]
    pub sso_client_id: i64,
    /// 公开客户端标识（应用侧使用，唯一）
    pub client_id: String,
    /// client_secret 明文的 SHA-256 hex（鉴权校验用，脱敏出参）
    pub client_secret_hash: String,
    /// HS256 ID Token 签名密钥（仅服务端使用，脱敏出参）
    pub id_token_secret: String,
    /// 客户端名称（同意页 / 列表展示）
    pub client_name: String,
    /// Logo URI（同意页展示，可空）
    pub logo_uri: String,
    /// 回调地址白名单 JSON 数组字符串（精确匹配）
    pub redirect_uris: String,
    /// 允许 scope JSON 数组字符串
    pub scopes: String,
    /// 支持的授权类型 JSON 数组字符串
    pub grant_types: String,
    /// 是否需要用户同意（'1'=需要 '0'=直接签发）
    pub consent_required: String,
    /// 是否启用（'0'=停用 '1'=启用）
    pub enabled: String,
    pub remark: Option<String>,
    /// 多租户前向兼容预留字段（默认 0，本轮不参与过滤）
    pub tenant_id: i64,
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

/// 手动实现 Debug 以脱敏两处密钥，防止泄漏到日志
impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("sys_oauth_client::Model")
            .field("sso_client_id", &self.sso_client_id)
            .field("client_id", &self.client_id)
            .field("client_secret_hash", &"<redacted>")
            .field("id_token_secret", &"<redacted>")
            .field("client_name", &self.client_name)
            .field("logo_uri", &self.logo_uri)
            .field("redirect_uris", &self.redirect_uris)
            .field("scopes", &self.scopes)
            .field("grant_types", &self.grant_types)
            .field("consent_required", &self.consent_required)
            .field("enabled", &self.enabled)
            .field("remark", &self.remark)
            .field("tenant_id", &self.tenant_id)
            .field("create_by", &self.create_by)
            .field("create_time", &self.create_time)
            .field("update_time", &self.update_time)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
