//! report_dashboard 实体定义（G-01 M1：报表大屏画布配置）
//!
//! - layout_json：与前端 dashboardLayout 同 schema 家族的增量配置
//!   （[{widgetId, chartType, datasetId, x,y,w,h, option:{...}}]）；
//! - schema_version：layout 演进版本化（读取端版本化兼容函数 + 单测）。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "report_dashboard")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "ReportDashboard",
    export_to = "ReportDashboard.ts",
    rename_all = "camelCase"
)]
#[schema(as = ReportDashboard)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub dashboard_id: i64,
    pub tenant_id: i64,
    pub dashboard_code: String,
    pub dashboard_name: String,
    /// 画布布局 JSON（含 schemaVersion）
    pub layout_json: String,
    pub schema_version: i32,
    /// "0"=启用 "1"=停用
    pub status: String,
    pub remark: Option<String>,
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
    pub del_flag: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
