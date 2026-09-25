//! sys_tenant_package 实体定义（租户套餐，多租户 Phase 3）
//!
//! 套餐 = **功能白名单上限**：`menu_ids` 为该套餐允许授权的 `sys_menu.menu_id`
//! 逗号分隔集合；空 / NULL = **不限制**（全量平台菜单）。
//!
//! 注意语义边界（文档 §27.1 决策 10）：套餐只定义"能授什么"，**账号配额**
//! 落在 `sys_tenant.account_count`，不与本表 `default_account_count` 混用
//! （后者仅在新建租户时作为默认值拷入租户行）。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_tenant_package")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysTenantPackage",
    export_to = "SysTenantPackage.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysTenantPackage)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub package_id: i64,
    #[sea_orm(unique)]
    pub package_name: String,
    /// 允许授权的菜单 ID 白名单（逗号分隔；空 / NULL = 不限制）
    pub menu_ids: Option<String>,
    /// 新建租户时的默认账号配额（拷贝到 sys_tenant.account_count）
    pub default_account_count: Option<i32>,
    /// '0' 正常 / '1' 停用
    pub status: Option<String>,
    pub del_flag: Option<String>,
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
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();