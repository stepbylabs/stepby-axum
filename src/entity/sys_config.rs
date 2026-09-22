//! sys_config 实体定义（参数配置表）
//!
//! 注意：config 表无 del_flag，使用物理删除
//! config_type: "Y"=内置, "N"=非内置

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_config")]
#[serde(rename_all = "camelCase")]
#[ts(export, rename = "SysConfig", export_to = "SysConfig.ts", rename_all = "camelCase")]
#[schema(as = SysConfig)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub config_id: i64,
    pub config_name: Option<String>,
    #[sea_orm(unique)]
    pub config_key: String,
    pub config_value: Option<String>,
    /// 系统内置：Y=是, N=否
    pub config_type: Option<String>,
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
