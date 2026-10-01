//! sys_job_log 实体定义（定时任务调度日志表，日志表物理删除，时间由业务层设置）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_job_log")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysJobLog",
    export_to = "SysJobLog.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysJobLog)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub job_log_id: i64,
    pub job_name: String,
    pub job_group: String,
    pub invoke_target: String,
    pub job_message: Option<String>,
    pub status: Option<String>,
    pub exception_info: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
