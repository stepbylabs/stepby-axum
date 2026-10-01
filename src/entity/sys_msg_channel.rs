//! sys_msg_channel 实体定义（消息渠道表）
//!
//! channel_code: "email"/"sms"/"site"
//! channel_type: "email"/"sms"/"site"（白名单校验）
//! status:       "0"=正常, "1"=停用
//! config_json:  渠道配置 JSON（敏感字段如 SMTP 密码出入参脱敏，不入库明文展示）

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_msg_channel")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysMsgChannel",
    export_to = "SysMsgChannel.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysMsgChannel)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub channel_id: i64,
    /// 渠道名称
    pub channel_name: String,
    /// 渠道编码（email/sms/site）
    pub channel_code: String,
    /// 渠道类型（email/sms/site）
    pub channel_type: String,
    /// 渠道配置 JSON（敏感字段脱敏展示）
    pub config_json: Option<String>,
    /// 状态（0=正常 1=停用）
    pub status: Option<String>,
    pub create_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub update_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
    /// 删除标志（0=正常 1=已删）
    pub del_flag: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
