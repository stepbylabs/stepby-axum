//! sys_web_hook_log 实体定义（WebHook 投递记录表）
//!
//! 每次出站投递留痕：事件类型、目标 URL、请求体、结果状态、响应/错误、耗时。
//! status:    "0"=成功 "1"=失败
//! status_code: HTTP 状态码（网络/超时错误为 NULL 或 0），供重试与审计。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_web_hook_log")]
#[serde(rename_all = "camelCase")]
#[ts(export, rename = "SysWebHookLog", export_to = "SysWebHookLog.ts", rename_all = "camelCase")]
#[schema(as = SysWebHookLog)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 关联回调 id（回调查删后可能为 NULL）
    pub hook_id: Option<i64>,
    /// 回调名称快照
    pub hook_name: Option<String>,
    /// 触发的事件类型
    pub event_type: String,
    /// 投递目标 URL
    pub target_url: String,
    /// 请求体（JSON 序列化）
    pub payload: Option<String>,
    /// 结果状态（0=成功 1=失败）
    pub status: String,
    /// HTTP 状态码
    pub status_code: Option<i32>,
    /// 响应体（截断存储）
    pub response: Option<String>,
    /// 错误信息
    pub error_msg: Option<String>,
    /// 耗时（毫秒）
    pub cost_ms: i32,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

/// 推送记录为只追加日志，仅 create_time，无 update_time。
/// 不能复用 impl_timestamped_active_model!（该宏会写 update_time），故自定义 ActiveModelBehavior。
#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        if insert {
            self.create_time = sea_orm::Set(Some(crate::common::datetime::now_naive()));
        }
        Ok(self)
    }
}