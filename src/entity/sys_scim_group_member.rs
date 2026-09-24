//! sys_scim_group_member 实体定义（组成员，复合主键，v5-D12 Group）
//!
//! 成员关系独立存表（不通过 sys_user_role(source) 反推）：管理员手授同角色
//! （source='admin'）与组成员身份是两个事实源，混用会把 admin 手授误判为组成员。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_scim_group_member")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysScimGroupMember",
    export_to = "SysScimGroupMember.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysScimGroupMember)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub group_id: i64,
    #[sea_orm(primary_key)]
    pub user_id: i64,
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
