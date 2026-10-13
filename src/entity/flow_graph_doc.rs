//! flow_graph_doc 实体定义（批次十六：图驱动单据——任意已发布流程图的审批实例）
//!
//! - 提交时快照 `flow_id`（版本绑定：实例按提交时版本推进，后续发版不影响在途单据）；
//! - `fields_json` 冻结条件求值字段池（提交时写入 ⇒ 推进时重放同路径，确定性）；
//! - status/current_round/current_node_seq/finished_at 投影列契约与 flow_demo_doc 一致
//!   （`biz_type::sync_projection` 回写）。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "flow_graph_doc")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "FlowGraphDoc",
    export_to = "FlowGraphDoc.ts",
    rename_all = "camelCase"
)]
#[schema(as = FlowGraphDoc)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub doc_id: i64,
    /// 租户归属（0 = 平台级）
    pub tenant_id: i64,
    /// 提交人部门快照（`DeptLeader` 策略定位用，提交时冻结）
    pub dept_id: Option<i64>,
    /// 绑定的流程定义行（提交时 is_latest='1' 的那条；版本快照）
    pub flow_id: i64,
    /// 流程编码冗余（列表免 join）
    pub flow_code: String,
    /// 单据标题
    pub title: String,
    /// 字段快照 JSON（条件边求值池；提交时冻结 ⇒ 推进重放同路径）
    pub fields_json: String,
    /// pending / approved / rejected / withdrawn
    pub status: String,
    pub current_round: i32,
    pub current_node_seq: Option<i32>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub submitted_at: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub finished_at: Option<NaiveDateTime>,
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
