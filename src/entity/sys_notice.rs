//! sys_notice 实体定义（通知公告表）
//!
//! notice_type: "1"=通知, "2"=公告
//! status:      "0"=正常, "1"=关闭
//! 注：notice 表无 del_flag，使用物理删除

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_notice")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysNotice",
    export_to = "SysNotice.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysNotice)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub notice_id: i64,
    pub notice_title: String,
    /// 公告类型（1=通知 2=公告）
    pub notice_type: String,
    /// 公告内容（长文本）
    pub notice_content: Option<String>,
    /// 状态（0=正常 1=关闭）
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
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
