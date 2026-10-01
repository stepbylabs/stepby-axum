//! sys_flow_log 实体定义（审批流水：语义级动作时间线，业务凭证）
//!
//! action: submit=提交, approve=同意, reject=驳回, withdraw=撤回,
//!         transfer=转办, timeout_remind=超时提醒, auto_approve=自动通过
//! operator_id: NULL = 系统动作（对齐 sys_task.operator_id=None 语义，不伪造 user_id）
//!
//! 重要：本表是审批凭证，**永不纳入** `LOG_RETENTION_DAYS` 日志清理（cleanup_expired_logs
//! 只清 sys_oper_log / sys_logininfor，见 scheduler/mod.rs）。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_flow_log")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysFlowLog",
    export_to = "SysFlowLog.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysFlowLog)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub log_id: i64,
    /// 业务类型
    pub biz_type: String,
    /// 业务单据 ID
    pub biz_id: i64,
    /// 轮次
    pub round_no: i32,
    /// 节点序号（提交/撤回等单据级动作为 NULL）
    pub node_seq: Option<i32>,
    /// 动作（submit/approve/reject/withdraw/transfer/timeout_remind/auto_approve）
    pub action: String,
    /// 变更前状态
    pub from_status: Option<String>,
    /// 变更后状态
    pub to_status: Option<String>,
    /// 操作人（NULL=系统动作）
    pub operator_id: Option<i64>,
    /// 转办目标 user_id（仅 transfer）
    pub to_user_id: Option<i64>,
    /// 意见
    pub comment: Option<String>,
    /// 动作时间
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub acted_at: Option<NaiveDateTime>,
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
