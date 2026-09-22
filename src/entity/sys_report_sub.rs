//! sys_report_sub 实体定义（报表订阅表）
//!
//! 定时订阅推送配置：将某个报表（sys_report）的统计快照按 cron 周期
//! 通过 email（MailerService）和/或 站内信（sys_msg site 渠道）推送给目标受众。
//!
//! push_email / push_sys_msg: '1'=启用 '0'=关闭
//! receive_email: 逗号分隔的收件人邮箱地址（push_email 启用时使用）
//! receive_user_ids: 逗号分隔的目标用户 id（push_sys_msg 启用时使用）
//! status: '0'=启用 '1'=停用
//! cron: 6 字段 cron 表达式（tokio-cron-scheduler 要求含秒）

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_report_sub")]
#[serde(rename_all = "camelCase")]
#[ts(export, rename = "SysReportSub", export_to = "SysReportSub.ts", rename_all = "camelCase")]
#[schema(as = SysReportSub)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub sub_id: i64,
    /// 关联报表 id
    pub report_id: i64,
    /// 订阅名称
    pub sub_name: String,
    /// 周期 cron 表达式（6 字段）
    pub cron: String,
    /// 是否邮件推送（1=是 0=否）
    pub push_email: String,
    /// 收件邮箱（逗号分隔）
    pub receive_email: Option<String>,
    /// 是否站内信推送（1=是 0=否）
    pub push_sys_msg: String,
    /// 目标用户 id（逗号分隔）
    pub receive_user_ids: Option<String>,
    /// 状态（0=启用 1=停用）
    pub status: String,
    /// 上次成功执行时间
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub last_run_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
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
    pub del_flag: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
