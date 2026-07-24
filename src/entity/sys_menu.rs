//! sys_menu 实体定义（菜单权限表）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use sea_orm::Set;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;
use crate::utils::tree::TreeNode;

/// sys_menu 实体（菜单权限表）
///
/// `children` 是自引用递归字段，使用 `#[schema(no_recursion)]` 属性
/// 让 utoipa 生成 `$ref` 自引用，打破递归（utoipa 5.1.0+ 官方方案）。
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_menu")]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SysMenu.ts", rename_all = "camelCase")]
#[schema(as = SysMenu)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub menu_id: i64,
    pub menu_name: String,
    pub parent_id: Option<i64>,
    pub order_num: Option<i32>,
    pub path: Option<String>,
    pub component: Option<String>,
    pub query: Option<String>,
    pub route_name: Option<String>,
    pub is_frame: Option<String>,
    pub is_cache: Option<String>,
    pub menu_type: Option<String>,
    pub visible: Option<String>,
    pub status: Option<String>,
    pub perms: Option<String>,
    /// i18n 翻译 key（可选），用于前端按当前 locale 翻译菜单标题。
    /// 内置菜单由 migration 填充（如 "menu.user"）；自定义菜单留空，前端回退到 menu_name 原文。
    pub i18n_key: Option<String>,
    pub icon: Option<String>,
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
    pub del_flag: Option<String>,
    /// 子菜单列表（不入库，仅用于树形组装）
    #[sea_orm(ignore)]
    #[ts(skip)]
    #[schema(no_recursion)]
    pub children: Option<Vec<Model>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        let now = chrono::Local::now().naive_local();
        if insert {
            self.create_time = Set(Some(now));
        }
        self.update_time = Set(Some(now));
        Ok(self)
    }
}

/// 为 SysMenuModel 实现 TreeNode trait，支持 build_tree 组装树形结构
impl TreeNode for Model {
    type Id = i64;
    fn id(&self) -> i64 {
        self.menu_id
    }
    fn parent_id(&self) -> i64 {
        self.parent_id.unwrap_or(0)
    }
    fn children_mut(&mut self) -> &mut Option<Vec<Self>> {
        &mut self.children
    }
}
