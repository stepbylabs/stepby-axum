//! sys_user_dept 实体定义（用户兼职部门关联表，多部门任职最小侵入版）
//!
//! 设计（方案 §23 §4 更优解）：主部门唯一事实源 = sys_user.dept_id（本表不存
//! 主部门，避免 is_primary 双写漂移）；"全部归属" = dept_id ∪ 本表。
//! source：'admin'（人工配置）| 'scim:{group_id}'（组→兼职部门同步写入）。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_user_dept")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysUserDept",
    export_to = "SysUserDept.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysUserDept)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub user_id: i64,
    /// 兼职部门 id（≠ sys_user.dept_id 主部门；唯一约束 (user_id, dept_id)）
    pub dept_id: i64,
    /// 归属来源：'admin' | 'scim:{group_id}'
    pub source: String,
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
