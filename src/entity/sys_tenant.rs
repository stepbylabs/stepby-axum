//! sys_tenant 实体定义（租户主表，多租户 Phase 3）
//!
//! 决策（文档 §27.1 / §29.7 P1）：**租户独立 id 空间**——`tenant_id` 不再复用
//! `sys_dept.dept_id`；`dept_id` 仅记录该租户的组织树挂载根部门（可为空）。
//! 归属单一来源：`sys_dept.tenant_id` / `sys_user.tenant_id` 等业务列均指向本表
//! `tenant_id`；`tenant_id = 0` 保留为平台租户（跨租户运营，不落本表行）。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_tenant")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysTenant",
    export_to = "SysTenant.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysTenant)]
pub struct Model {
    /// 租户 ID（独立 id 空间，不复用 dept_id；0 保留给平台租户，不落本表行）
    #[sea_orm(primary_key)]
    pub tenant_id: i64,
    /// 租户短码（域名/展示用；全局唯一，登录页与子域名均可体现）
    #[sea_orm(unique)]
    pub tenant_code: String,
    pub tenant_name: String,
    /// 组织树根部门（该租户的部门树挂载点；本表行的 tenant_id 与 dept_id 无相等关系）
    pub dept_id: Option<i64>,
    /// 套餐 ID（sys_tenant_package.package_id；NULL = 不限套餐）
    pub package_id: Option<i64>,
    pub contact_name: Option<String>,
    pub contact_phone: Option<String>,
    pub contact_email: Option<String>,
    /// 主域名（冗余自 sys_tenant_domain 中 is_primary='0' 的行，便于列表展示）
    pub domain: Option<String>,
    /// 到期时间（过期后拒登；NULL = 永不过期）
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub expire_time: Option<NaiveDateTime>,
    /// 账号数上限（配额上限；0 = 不限）
    pub account_count: Option<i32>,
    /// '0' 正常 / '1' 停用（停用后该租户用户无法登录；登录校验读本列）
    pub status: Option<String>,
    /// '0' 存在 / '2' 已删除
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
