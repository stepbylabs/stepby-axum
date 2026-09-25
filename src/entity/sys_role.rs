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
    /// 系统角色标记（台账 P0-2：超管判定与可变 `role_key` 解耦）。
    ///
    /// 平台超级管理员 = `is_system && tenant_id == 0`（见 [`Model::is_platform_super_admin`]）。
    /// 仅由种子/迁移置位；业务侧新建角色一律为 `false`，且不可通过 DTO 修改。
    #[sea_orm(default_value = false)]
    pub is_system: bool,
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

impl Model {
    /// 是否平台超级管理员角色（台账 P0-2 定案口径）：
    /// 必须同时满足"系统标记"与"平台租户归属"两个条件——
    /// 租户侧即使自建 `role_key = 'admin'` 的角色（租户内唯一，见
    /// `uk_sys_role_tenant_key`），也因 `tenant_id != 0` 无法获得超管短路。
    pub fn is_platform_super_admin(&self) -> bool {
        self.is_system && self.tenant_id == 0
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
