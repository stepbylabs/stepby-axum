//! flow_definition 实体定义（G-02 M1：可视化流程定义存储）
//!
//! - (tenant_id, flow_code, version) 唯一；is_latest='1' 每 code 至多一条；
//! - graph_json 结构由 `common/flow_graph.rs` 白名单校验器负责（保存前复验）；
//! - status: "0"=草稿/停用 "1"=已发布（实例绑定 version 后按 version 推进）。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "flow_definition")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "FlowDefinition",
    export_to = "FlowDefinition.ts",
    rename_all = "camelCase"
)]
#[schema(as = FlowDefinition)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub flow_id: i64,
    /// 租户归属（0 = 平台级）
    pub tenant_id: i64,
    /// 流程编码（唯一性 = tenant + code + version）
    pub flow_code: String,
    pub flow_name: String,
    /// BPMN-lite 图定义（nodes/edges JSON；common/flow_graph.rs 校验）
    pub graph_json: String,
    /// 版本号（同 code 递增；实例绑定 version）
    pub version: i32,
    /// 每 code 的最新已发布版标记（'1'/'0'）
    pub is_latest: String,
    /// "0"=草稿/停用 "1"=已发布
    pub status: String,
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
    pub remark: Option<String>,
    pub del_flag: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
