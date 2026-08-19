//! sys_report 实体定义（报表定义表）
//!
//! report_type: login_stats / user_stats / msg_stats / custom
//! status:       "0"=启用 "1"=停用
//! config:       报表配置 JSON（custom 类型可存任意聚合配置）

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_report")]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SysReport.ts", rename_all = "camelCase")]
#[schema(as = SysReport)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub report_id: i64,
    /// 报表编码（唯一）
    pub report_code: String,
    /// 报表名称
    pub report_name: String,
    /// 报表类型（login_stats/user_stats/msg_stats/custom）
    pub report_type: String,
    /// 报表配置 JSON
    pub config: String,
    /// 状态（0=启用 1=停用）
    pub status: String,
    pub remark: Option<String>,
    pub create_by: Option<String>,
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
    pub del_flag: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
