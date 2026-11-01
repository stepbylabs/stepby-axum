//! sys_op_recording 实体（操作录制抬头）
//!
//! 一次录制 = 一段**按顺序回放**的 HTTP 调用序列。抬头只放"这段录制是什么"，
//! 步骤明细在 `sys_op_recording_step`（回放要按 `seq` 单步取、单步改，塞 JSON 列做不到）。
//!
//! - `source`：`ui` 中间件采集 / `api` 外部写入 / `import` 脚本导入
//! - `status`：`draft` 草稿（可继续追加）/ `ready` 可回放 / `archived` 归档（只读）
//! - `last_run_status`：`success` / `failed` / `partial`（与 `sys_op_recording_run.status` 同源取值）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "sys_op_recording")]
#[serde(rename_all = "camelCase")]
#[schema(as = SysOpRecording)]
pub struct Model {
    /// 多租户归属（写入取操作者租户；读侧经 `tenant_scope` 收敛）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub recording_id: i64,
    /// 录制名称
    pub name: String,
    /// 说明（这段流程是干什么的）
    pub description: Option<String>,
    /// 来源（ui/api/import）
    pub source: String,
    /// 状态（draft/ready/archived）
    pub status: String,
    /// 步骤数（由步骤表维护，仅供列表展示；**判据仍以步骤表实计数为准**）
    pub step_count: i32,
    /// 最近一次回放结论（success/failed/partial）
    pub last_run_status: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub last_run_time: Option<NaiveDateTime>,
    /// 录制人 user_id
    pub owner_id: Option<i64>,
    /// 录制人用户名（展示用）
    pub owner_name: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub create_time: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub update_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
