//! sys_role 实体定义（角色信息表）

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_role")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysRole",
    export_to = "SysRole.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysRole)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub role_id: i64,
    pub role_name: String,
    /// 角色权限字符。
    ///
    /// 唯一性已由迁移 `m20260925_000004` 的复合唯一索引
    /// `uk_sys_role_tenant_key (tenant_id, role_key)` 承担（同租户内唯一，不同租户可同名），
    /// 故此处不再标注单列 unique 属性；运行时查询由 SQL 显式构造，不受该属性影响。
    pub role_key: String,
    pub role_sort: i32,
    pub data_scope: Option<String>,
    /// 自定义部门 SQL 过滤片段（data_scope="2" 时可选）。仅存原始字符串，
    /// 运行时由 common::custom_scope 白名单解析为参数化条件，绝不拼接裸 SQL。
    pub custom_sql: Option<String>,
    pub menu_check_strictly: Option<bool>,
    pub dept_check_strictly: Option<bool>,
    pub status: String,
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
