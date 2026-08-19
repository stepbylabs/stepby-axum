//! sys_oauth_user 实体定义（第三方身份与本地账号绑定表）
//!
//! 唯一约束 (provider, provider_user_id)：同一第三方身份只绑定一份。
//! user_id 指向 sys_user 主键，实现 OAuth 登录时映射到本地账号。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

/// 注意：不 derive(Debug)，改用手动实现以脱敏 access_token/refresh_token 字段
#[derive(Clone, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_oauth_user")]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SysOauthUser.ts", rename_all = "camelCase")]
#[schema(as = SysOauthUser)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub oauth_id: i64,
    /// 绑定的本地用户 ID
    pub user_id: i64,
    /// 提供商编码
    pub provider: String,
    /// 第三方用户唯一标识（sub / OAuth2 id）
    pub provider_user_id: String,
    pub nickname: Option<String>,
    pub avatar: Option<String>,
    pub email: Option<String>,
    /// 第三方 access_token（脱敏出参）
    pub access_token: Option<String>,
    /// 第三方 refresh_token（脱敏出参）
    pub refresh_token: Option<String>,
    /// 令牌过期时间
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub expires_at: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub last_login_time: Option<NaiveDateTime>,
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

/// 手动实现 Debug 以脱敏 access_token/refresh_token，防止第三方令牌泄漏到日志
impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("sys_oauth_user::Model")
            .field("oauth_id", &self.oauth_id)
            .field("user_id", &self.user_id)
            .field("provider", &self.provider)
            .field("provider_user_id", &self.provider_user_id)
            .field("nickname", &self.nickname)
            .field("avatar", &self.avatar)
            .field("email", &self.email)
            .field(
                "access_token",
                &self.access_token.as_deref().map(|_| "<redacted>"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_deref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("last_login_time", &self.last_login_time)
            .field("create_time", &self.create_time)
            .field("update_time", &self.update_time)
            .finish()
    }
}

crate::impl_timestamped_active_model!();
