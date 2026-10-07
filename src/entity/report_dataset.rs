//! report_dataset 实体定义（G-01 M1：通用报表受控数据集）
//!
//! - sql_template 为管理员预注册的参数化 SELECT 模板（`common/dataset_sql.rs` 校验）；
//! - columns_meta：试跑采样的列元数据 JSON（设计器列选择）；
//! - 密文列无（SQL 模板非凭据）；密文列不可 LIKE/等值/排序的边界不适用。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "report_dataset")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "ReportDataset",
    export_to = "ReportDataset.ts",
    rename_all = "camelCase"
)]
#[schema(as = ReportDataset)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub dataset_id: i64,
    /// 租户归属（0 = 平台级）
    pub tenant_id: i64,
    pub dataset_code: String,
    pub dataset_name: String,
    /// 受控 SELECT 模板（`:param` 命名占位符；运行期参数绑定）
    pub sql_template: String,
    /// 参数 schema JSON（[{name,type,required}]）
    pub params_schema: Option<String>,
    /// 列元数据 JSON（[{name,type}]，试跑采样）
    pub columns_meta: Option<String>,
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
