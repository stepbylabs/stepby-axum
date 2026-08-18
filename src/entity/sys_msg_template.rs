//! sys_msg_template 实体定义（消息模板表）
//!
//! template_subject / template_content 支持 {{var}} 变量替换（render_template 渲染）
//! status: "0"=正常, "1"=停用
//! channel_code: 该模板默认落地的渠道编码（默认 email）

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_msg_template")]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SysMsgTemplate.ts", rename_all = "camelCase")]
#[schema(as = SysMsgTemplate)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub template_id: i64,
    /// 模板名称
    pub template_name: String,
    /// 模板编码（唯一）
    pub template_code: String,
    /// 渠道编码（默认 email）
    pub channel_code: String,
    /// 模板主题（支持 {{var}} 变量）
    pub template_subject: String,
    /// 模板内容（支持 {{var}} 变量）
    pub template_content: String,
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
