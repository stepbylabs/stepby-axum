//! sys_msg_send_log 实体定义（消息发送记录表）
//!
//! status: "0"=成功, "1"=失败, "2"=待重试
//! retry_count: 已重试次数；max_retry_count: 最大重试次数（默认 3）
//! last_error: 最近一次失败原因
//! 本表仅 create_time（无 update_time），不使用时间戳自动维护宏。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_msg_send_log")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysMsgSendLog",
    export_to = "SysMsgSendLog.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysMsgSendLog)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub log_id: i64,
    /// 模板编码
    pub template_code: Option<String>,
    /// 渠道编码
    pub channel_code: Option<String>,
    /// 收件地址（邮箱/手机号/站内用户）
    pub to_addr: String,
    /// 主题
    pub subject: Option<String>,
    /// 内容
    pub content: Option<String>,
    /// 短信投递原始渲染参数 JSON 快照（云厂商重试还原用，G-07 扩展）
    pub sms_params: Option<String>,
    /// 状态（0=成功 1=失败 2=待重试）
    pub status: Option<String>,
    /// 已重试次数
    pub retry_count: Option<i32>,
    /// 最大重试次数
    pub max_retry_count: Option<i32>,
    /// 最近失败原因
    pub last_error: Option<String>,
    /// 发送时间
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub send_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
