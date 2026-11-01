//! sys_op_recording_run 实体（回放运行结论）
//!
//! 一次回放 = 一条运行记录 + 一条 `sys_task` 进度行（`task_id` 关联）。两者分工：
//! `sys_task` 回答"跑到第几步了"（前端浮层进度条），本表回答"每一步各自成没成、为什么"。
//!
//! `status`：`running` / `success` / `failed` / `partial`（有成功也有失败）。
//! `partial` 的存在是必要的：`stop_on_error=false` 时"停在第 3 步"与"跑完 5 步错了 2 步"
//! 是两种不同的结论，压成一个 `failed` 会让使用者以为后半段没执行。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "sys_op_recording_run")]
#[serde(rename_all = "camelCase")]
#[schema(as = SysOpRecordingRun)]
pub struct Model {
    /// 多租户归属
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub run_id: i64,
    /// 所属录制
    pub recording_id: i64,
    /// 关联的任务进度行（`sys_task.task_id`）
    pub task_id: Option<i64>,
    /// 运行结论（running/success/failed/partial）
    pub status: String,
    /// 计划步骤数
    pub total: i32,
    /// 成功步骤数
    pub succeeded: i32,
    /// 失败步骤数
    pub failed: i32,
    /// 跳过步骤数（变量缺失/显式跳过）
    pub skipped: i32,
    /// 逐步骤结局（JSON 数组，见服务层 `StepOutcome`）
    pub detail_json: Option<String>,
    /// 触发回放的操作人
    pub operator: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub started_at: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub finished_at: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
