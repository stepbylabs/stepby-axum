//! sys_user_pref 实体定义（用户消息偏好 + 免打扰表）
//!
//! 以 user_id 为主键，每用户至多一行；未配置时各字段取默认值（全量接收、免打扰关闭）。
//! - email_notify    '1'=接收公告邮件（默认） '0'=关闭
//! - sysmsg_notify   '1'=接收站内信通知（默认） '0'=关闭
//! - announce_notify '1'=接收通知公告（默认） '0'=关闭
//! - dnd_enabled     '0'=免打扰关闭（默认） '1'=启用
//! - dnd_start/end   免打扰时间段（HH:MM，支持跨天）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_user_pref")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysUserPref",
    export_to = "SysUserPref.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysUserPref)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub user_id: i64,
    /// 是否接收公告邮件（'1' 是，默认；'0' 否）
    pub email_notify: String,
    /// 是否接收站内信通知（'1' 是，默认；'0' 否）
    pub sysmsg_notify: String,
    /// 是否接收通知公告（'1' 是，默认；'0' 否）
    pub announce_notify: String,
    /// 是否启用免打扰（'0' 否，默认；'1' 是）
    pub dnd_enabled: String,
    /// 免打扰开始时间（HH:MM）
    pub dnd_start: String,
    /// 免打扰结束时间（HH:MM）
    pub dnd_end: String,
    /// 扩展 JSON（预留）
    pub extra: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub update_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
