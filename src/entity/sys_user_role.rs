//! sys_user_role 实体定义（用户角色关联表，复合主键）

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_user_role")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub user_id: i64,
    #[sea_orm(primary_key)]
    pub role_id: i64,
    /// 授权来源：'admin'（管理员手授，默认/存量行）| 'scim:{group_id}'
    /// （SCIM 组→角色联动）。管理员编辑用户只 diff 'admin' 行，SCIM 联动只动
    /// 本组 source 行——两个事实源分离，消除回写抖动（v5-D12 Group）。
    #[sea_orm(default_value = "admin")]
    pub source: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
