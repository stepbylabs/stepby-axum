//! sys_webhook_event 实体定义（WebHook 事件目录表）
//!
//! 事件目录是 emit_event 派发与订阅过滤的"事件键事实源"：
//! - event_key：事件键（如 `user.created`），UNIQUE，业务派发与订阅均以它匹配；
//! - payload_example：真实字段样例（JSON 文本），test-send 直接用它构造真实出站投递；
//! - enabled：'1'=启用 '0'=停用（停用仅表示目录下架展示，不影响已派发中的事件）。
//!
//! 迁移：m20261003_000002_webhook_event（含 16 个种子事件）。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_webhook_event")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 事件键（如 `user.created`；唯一，派发与订阅过滤的事实源）
    pub event_key: String,
    /// 事件名称（展示用）
    pub name: String,
    /// 事件说明
    pub description: Option<String>,
    /// 负载样例（JSON 文本；test-send 构造真实投递的数据源）
    pub payload_example: Option<String>,
    /// 状态（'1'=启用 '0'=停用）
    pub enabled: String,
    #[serde(
        serialize_with = "crate::common::datetime::serialize_opt",
        deserialize_with = "crate::common::datetime::deserialize_opt"
    )]
    pub created_at: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "crate::common::datetime::serialize_opt",
        deserialize_with = "crate::common::datetime::deserialize_opt"
    )]
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
