//! sys_scim_group 实体定义（SCIM Group 组实体，v5-D12 Group）
//!
//! 组权威在 IdP（经 SCIM API 管理）；管理端仅可改 mapping_type / 绑定 / 删组，
//! 不可建组（无 IdP 场景的"独立用户组"语义已由"组→角色集合"变体取代，见方案 §22）。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_scim_group")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysScimGroup",
    export_to = "SysScimGroup.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysScimGroup)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub group_id: i64,
    /// 组显示名（IdP 同步；管理端只读）
    pub display_name: String,
    /// IdP 侧唯一标识（NULL = 非 IdP 场景；唯一索引 uk_scim_group_external_id）
    pub external_id: Option<String>,
    /// 映射类型：'role'（组→角色集合，默认）| 'dept'（组→兼职部门同步）。
    /// 变更时必须先清空绑定（服务层强制）。
    pub mapping_type: String,
    /// 软删标记：'0' 正常 / '2' 已删除（审计保留）
    pub del_flag: Option<String>,
    /// 多租户前向兼容预留（E3 约定：新表一律预留，当前恒 0 不参与过滤）
    pub tenant_id: i64,
    pub create_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub update_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
