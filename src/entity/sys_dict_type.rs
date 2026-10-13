//! sys_dict_type 实体定义（字典类型表）

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_dict_type")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysDictType",
    export_to = "SysDictType.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysDictType)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub dict_id: i64,
    pub dict_name: Option<String>,
    /// 字典类型标识。
    ///
    /// 唯一性已由迁移 `m20260925_000004` 的复合唯一索引
    /// `uk_sys_dict_type_tenant (tenant_id, dict_type)` 承担（同租户内唯一；平台与各租户
    /// 可自建同名类型——但服务层显式禁止租户与平台类型同名，见 `sys_dict_service`），
    /// 故此处不再标注单列 unique 属性；运行时查询由 SQL 显式构造，不受该属性影响。
    pub dict_type: Option<String>,
    pub status: Option<String>,
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
