//! sys_oauth_provider 实体定义（OAuth2/OIDC 登录提供商配置表）
//!
//! provider_type: github / gitee / wecom / oidc（通用 OIDC）
//! enabled:       "0"=停用（默认，填充凭据后启用） "1"=启用
//! auto_create_user: "1"=首次登录自动创建本地账号并绑定 "0"=仅允许绑定既有账号

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

/// 注意：不 derive(Debug)，改用手动实现以脱敏 client_secret 字段
#[derive(Clone, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_oauth_provider")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysOauthProvider",
    export_to = "SysOauthProvider.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysOauthProvider)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub provider_id: i64,
    /// 提供商编码（github/gitee/wecom/oidc，唯一）
    pub provider_code: String,
    /// 提供商名称
    pub provider_name: String,
    /// 提供商类型（github/gitee/wecom/oidc）
    pub provider_type: String,
    /// OAuth2 Client ID
    pub client_id: String,
    /// OAuth2 Client Secret（脱敏出参，写接口明文接收）
    pub client_secret: String,
    /// 授权端点
    pub authorize_url: String,
    /// 令牌端点
    pub token_url: String,
    /// 用户信息端点
    pub user_info_url: String,
    /// 请求 scope
    pub scope: String,
    /// 回调地址（为空时后端按请求 Host 动态生成）
    pub redirect_uri: String,
    /// 首次登录是否自动创建本地账号（1=是 0=否）
    pub auto_create_user: String,
    /// 是否启用（0=停用 1=启用）
    pub enabled: String,
    /// 展示顺序
    pub display_order: i32,
    pub remark: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub update_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

/// 手动实现 Debug 以脱敏 client_secret，防止 OAuth 客户端密钥泄漏到日志
impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("sys_oauth_provider::Model")
            .field("provider_id", &self.provider_id)
            .field("provider_code", &self.provider_code)
            .field("provider_name", &self.provider_name)
            .field("provider_type", &self.provider_type)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("authorize_url", &self.authorize_url)
            .field("token_url", &self.token_url)
            .field("user_info_url", &self.user_info_url)
            .field("scope", &self.scope)
            .field("redirect_uri", &self.redirect_uri)
            .field("auto_create_user", &self.auto_create_user)
            .field("enabled", &self.enabled)
            .field("display_order", &self.display_order)
            .field("remark", &self.remark)
            .field("create_time", &self.create_time)
            .field("update_time", &self.update_time)
            .finish()
    }
}

crate::impl_timestamped_active_model!();
