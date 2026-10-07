//! sys_flow_task 实体定义（审批待办：唯一事实源）
//!
//! status:  pending=待审批, approved=已通过, rejected=已驳回,
//!          cancelled=已取消(撤回/驳回终止), transferred=已转办
//! task_type: single=单审, countersign=会签
//!
//! 设计依据：docs/optimization/topic-workflow-approval-final-2026-09-23.md（方案 B′）
//! - 唯一索引 (biz_type, biz_id, round_no, node_seq, assignee_id)：同轮内幂等、新一轮放行（V4-E1）
//! - title/applicant 冗余：跨 biz_type 聚合列表免 N 次 join（V4-E2）
//! - due_at：SLA 超时扫描；last_reminded_at：提醒审计（Redis SETNX 去重的 DB 侧留痕）

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_flow_task")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysFlowTask",
    export_to = "SysFlowTask.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysFlowTask)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub task_id: i64,
    /// 业务类型（如 demo_doc）
    pub biz_type: String,
    /// 业务单据 ID
    pub biz_id: i64,
    /// 轮次（提交/重新提交/退回重开时 +1）
    pub round_no: i32,
    /// 节点序号（从 1 起）
    pub node_seq: i32,
    /// 节点名称
    pub node_name: Option<String>,
    /// 审批人 user_id（提交时按策略快照，不重算）
    pub assignee_id: i64,
    /// 任务类型（single=单审 / countersign=会签 / or_sign=或签 / weighted=加权票）
    pub task_type: String,
    /// 状态（pending/approved/rejected/cancelled/transferred/discarded）
    pub status: String,
    /// 单据标题（提交时快照，跨类型聚合列表展示用）
    pub title: Option<String>,
    /// 提交人 user_id（快照）
    pub applicant_id: i64,
    /// 提交人姓名（快照）
    pub applicant_name: Option<String>,
    /// 审批意见（acted 时填写）
    pub comment: Option<String>,
    /// 审批时间
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub acted_at: Option<NaiveDateTime>,
    /// SLA 截止时间（超时扫描依据）
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub due_at: Option<NaiveDateTime>,
    /// 最近一次超时提醒时间（审计）
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub last_reminded_at: Option<NaiveDateTime>,
    /// 审批人权重快照（weighted 行生效，提交时定格；其余类型恒 1，G-02 M2）
    pub weight: i64,
    /// 节点门槛快照（weighted 行：权重和 ≥ threshold 即节点通过；其余类型 NULL，G-02 M2）
    pub threshold: Option<i64>,
    /// 委派转出人（delegate 动作记录原审批人；处理完回不到 A，G-02 M2）
    pub delegate_from: Option<i64>,
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
