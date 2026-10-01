//! sys_oper_log 实体定义（操作日志表，日志表物理删除，时间由业务层设置）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_oper_log")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysOperLog",
    export_to = "SysOperLog.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysOperLog)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    /// 被操作资源的目标租户（多租户 Phase 3）。
    ///
    /// 仅当「操作者租户」与「被操作资源租户」不一致（平台代管他租户资源）时写入，
    /// 用于让资源所属租户也能在审计日志中看到涉及自身资源的代管操作；
    /// 两者一致或单租户场景为 `NULL`。
    pub target_tenant_id: Option<i64>,
    #[sea_orm(primary_key)]
    pub oper_id: i64,
    pub title: Option<String>,
    pub business_type: Option<i32>,
    pub method: Option<String>,
    pub request_method: Option<String>,
    pub operator_type: Option<i32>,
    pub oper_name: Option<String>,
    pub dept_name: Option<String>,
    pub oper_url: Option<String>,
    pub oper_ip: Option<String>,
    pub oper_location: Option<String>,
    pub oper_param: Option<String>,
    /// 变更前数据快照（JSON，仅 PUT/DELETE 记录）
    pub oper_before: Option<String>,
    /// 字段级变更差异（JSON 数组 [{field,old,new}]，仅 PUT 成功记录）
    pub oper_diff: Option<String>,
    pub json_result: Option<String>,
    pub status: Option<String>,
    pub error_msg: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub oper_time: Option<NaiveDateTime>,
    pub cost_time: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
