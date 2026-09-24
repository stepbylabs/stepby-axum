//! sys_scim_group_binding 实体定义（组绑定目标，v5-D12 Group）
//!
//! target_id 语义由所属组的 mapping_type 决定：
//! - 'role' → sys_role.role_id（组→角色集合，成员联动 sys_user_role 授权）
//! - 'dept' → sys_dept.dept_id（组→兼职部门，成员联动 sys_user_dept 兼职记录）
//!
//! 唯一约束 (group_id, target_id) 防重复绑定。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_scim_group_binding")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysScimGroupBinding",
    export_to = "SysScimGroupBinding.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysScimGroupBinding)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub group_id: i64,
    /// 目标 id：mapping_type='role' → role_id；'dept' → dept_id
    pub target_id: i64,
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
