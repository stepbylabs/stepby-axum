//! sys_data_rule 实体定义（DP-01 结构化数据权限规则——规则定义表）
//!
//! 规则挂角色生效（对齐 data_scope 三层收敛语义）：规则定义目标表/列/操作符/值类型，
//! `sys_role_data_rule` 关联角色。查询期由 `DataRuleService::build_conditions` 求值，
//! 以 sea-orm Condition 显式注入（值参数化零注入；表/列名录入正则白名单）。
//!
//! 值类型（value_type）：
//! - fixed：固定值（rule_value）
//! - current_user：当前用户 ID
//! - current_dept：当前用户部门 ID
//! - current_dept_children：当前用户部门及全部后代部门 ID（in 语义）
//! - current_tenant：当前租户 ID

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_data_rule")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub rule_id: i64,
    /// 规则名（展示用）
    pub rule_name: String,
    /// 目标表名（录入正则白名单 `^[a-z_][a-z0-9_]*$`）
    pub table_name: String,
    /// 目标列名（同上白名单）
    pub field_name: String,
    /// 操作符：eq / ne / like / gt / lt / ge / le / in
    pub op: String,
    /// 值类型：fixed / current_user / current_dept / current_dept_children / current_tenant
    pub value_type: String,
    /// fixed（或 in 的逗号分隔清单）时的值；动态值类型此列为空
    pub rule_value: Option<String>,
    /// 状态（0 正常 1 停用）
    pub status: String,
    /// 多租户归属（平台=0）
    pub tenant_id: i64,
    pub create_by: Option<String>,
    pub create_time: Option<chrono::NaiveDateTime>,
    pub update_by: Option<String>,
    pub update_time: Option<chrono::NaiveDateTime>,
    pub remark: Option<String>,
    pub del_flag: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}
