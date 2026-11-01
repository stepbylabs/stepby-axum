//! sys_op_recording_step 实体（录制步骤明细）
//!
//! 每一步 = 一次真实发生过的 HTTP 调用：方法 + 路径 + 查询串 + 内容类型 + 请求体 +
//! **允许回放的**请求头子集 + 期望状态码。
//!
//! 为什么 `(recording_id, seq)` 是唯一索引而不是普通列：回放顺序是判据。并发追加两步时
//! 若各自读到同一个 `max(seq)`，后写者覆盖前写者 ⇒ 一段录制静默丢一步，而列表上的
//! `step_count` 仍显示 2。唯一约束把这个竞态变成"可重试的失败"而不是"看不见的缺口"。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "sys_op_recording_step")]
#[serde(rename_all = "camelCase")]
#[schema(as = SysOpRecordingStep)]
pub struct Model {
    /// 多租户归属（与抬头同租户；回放时逐行比对，防跨租户取步）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub step_id: i64,
    /// 所属录制
    pub recording_id: i64,
    /// 顺序号（从 1 开始，段内唯一）
    pub seq: i32,
    /// HTTP 方法（大写）
    pub method: String,
    /// 请求路径（**只存 path，不存绝对 URL**——回放目标永远由服务端配置决定，见服务层注释）
    pub path: String,
    /// 查询串（不含 `?`）
    pub query_string: Option<String>,
    /// 请求内容类型
    pub content_type: Option<String>,
    /// 请求体（已脱敏；超限截断并留标记）
    pub body: Option<String>,
    /// 允许回放的请求头子集（JSON 对象；白名单字段）
    pub headers_json: Option<String>,
    /// 返回值抽取规则（JSON 对象：`{"变量名":"data.id"}`）。
    ///
    /// 这是"录一次 → 反复跑"能串起来的关键：新建类接口返回的 id 是每次不同的，
    /// 后续步骤若写死字面量，第二次回放必然落在旧对象上（或直接 404）。抽取规则让
    /// 下一步可以用 `{{变量名}}` 引用本次结果。
    pub extract_json: Option<String>,
    /// 期望状态码（None = 只要求 2xx/3xx）
    pub expect_status: Option<i32>,
    /// 备注（这一步在业务上做什么）
    pub note: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub create_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
