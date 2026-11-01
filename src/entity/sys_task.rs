//! sys_task 实体定义（任务进度中心表）
//!
//! 取值以 [`crate::service::sys_task_service::TASK_TYPES`] 为准（b148 起**写入侧强校验**）：
//! - task_type: `operlog_export`=操作日志导出 / `replay`=录制回放 / `other`=其他
//! - status:    `pending`=等待 / `running`=运行中 / `success`=成功 / `failed`=失败
//!
//! 为什么不在这里再列一遍类型：这张表的旧注释写的是 export/import/backup/other，
//! 与真实取值 operlog_export / replay **完全对不上**——注释漂了两年没人发现，因为
//! 没有任何判据拿它和代码对账。单一事实源放在 service 常量里，由写入侧白名单钉住。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "sys_task")]
#[serde(rename_all = "camelCase")]
#[schema(as = SysTask)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub task_id: i64,
    /// 任务类型（export/import/backup/other）
    pub task_type: String,
    /// 任务名称
    pub task_name: String,
    /// 状态（pending/running/success/failed）
    pub status: String,
    /// 进度 0-100
    pub progress: i32,
    /// 总数
    pub total: i64,
    /// 当前完成数
    pub current: i64,
    /// 结果消息
    pub result_msg: Option<String>,
    /// 操作人（展示用）
    pub operator: Option<String>,
    /// 操作人 user_id（P0-2：taskProgress 定向推送目标，None 表示系统任务/无归属用户，不推送 WS）
    pub operator_id: Option<i64>,
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
