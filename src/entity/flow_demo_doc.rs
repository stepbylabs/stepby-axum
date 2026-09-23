//! flow_demo_doc 实体定义（示例业务单据：请假申请）
//!
//! 这是审批能力的真实业务宿主（此前 demo_seed 只有裸表、无 entity/service）。
//! status 为**派生投影**（事实源是 sys_flow_task/sys_flow_log）：
//!   draft → pending → approved | rejected | withdrawn
//! current_round / current_node_seq 亦为派生列（由 flow service 在同一事务内同步）。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "flow_demo_doc")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "FlowDemoDoc",
    export_to = "FlowDemoDoc.ts",
    rename_all = "camelCase"
)]
#[schema(as = FlowDemoDoc)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub doc_id: i64,
    /// 单据标题（同时快照进 sys_flow_task.title）
    pub title: String,
    /// 提交人 user_id
    pub applicant_id: i64,
    /// 提交人姓名
    pub applicant_name: Option<String>,
    /// 提交人部门
    pub dept_id: Option<i64>,
    /// 请假类型（annual/sick/personal，字典 sys_flow_leave_type）
    pub leave_type: String,
    /// 请假天数
    pub days: i32,
    /// 事由
    pub reason: Option<String>,
    /// 审批模式（single=两级单审 / countersign=一级会签）
    pub flow_mode: String,
    /// 状态（draft/pending/approved/rejected/withdrawn；派生投影）
    pub status: String,
    /// 当前轮次（派生）
    pub current_round: i32,
    /// 当前节点序号（派生）
    pub current_node_seq: Option<i32>,
    /// 提交时间
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub submitted_at: Option<NaiveDateTime>,
    /// 办结时间
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub finished_at: Option<NaiveDateTime>,
    /// 多租户前向兼容预留（默认 0，不参与过滤）
    pub tenant_id: i64,
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
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
