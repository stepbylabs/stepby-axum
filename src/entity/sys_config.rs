//! sys_config 实体定义（参数配置表）
//!
//! 注意：config 表无 del_flag，使用物理删除
//! config_type: "Y"=内置, "N"=非内置

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_config")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysConfig",
    export_to = "SysConfig.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysConfig)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub config_id: i64,
    pub config_name: Option<String>,
    /// 参数键名。
    ///
    /// 注意：唯一性已由迁移 `m20260925_000004` 的复合唯一索引
    /// `uk_sys_config_tenant_key (tenant_id, config_key)` 承担（同一租户内键名唯一，
    /// 不同租户可各自持有同名覆盖行），故此处**不再**标注单列 unique 属性
    /// （该属性会与租户覆盖语义冲突并产生误导）。
    /// 该属性仅影响 SeaORM 建表/DDL 生成，运行时查询始终由 SQL 显式构造，不受影响。
    pub config_key: String,
    pub config_value: Option<String>,
    /// 系统内置：Y=是, N=否
    pub config_type: Option<String>,
    /// 治理域（多租户 Phase 3.5f，迁移 m20260925_000004，§27.8）：
    /// `platform_only`（平台锁定，租户不可见/不可改）/ `platform_default`（租户可见、可覆盖）/
    /// `tenant_private`（租户私有）。列默认 `platform_only`（fail-closed）。
    pub scope: Option<String>,
    /// 租户是否可覆盖（"1"=可，"0"=不可）。列默认 `'0'`（fail-closed）。
    pub tenant_editable: Option<String>,
    /// 租户是否可见（"1"=可见，"0"=不可见）。列默认 `'0'`（fail-closed）；
    /// 平台安全项（platform_only）恒为 "0"，由代码常量锁定。
    pub visible_to_tenant: Option<String>,
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
