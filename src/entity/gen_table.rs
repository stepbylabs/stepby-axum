//! gen_table 实体定义（代码生成业务表）
//!
//! 存储用户导入的数据库表元数据，用于代码生成。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "gen_table")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub table_id: i64,
    /// 表名称
    pub table_name: String,
    /// 表描述
    pub table_comment: Option<String>,
    /// 关联子表名
    pub sub_table_name: Option<String>,
    /// 子表关联外键名
    pub sub_table_fk_name: Option<String>,
    /// 实体类名称（首字母大写驼峰）
    pub class_name: Option<String>,
    /// 模板类型（crud/tree/sub）
    pub tpl_category: Option<String>,
    /// 前端模板类型（element-plus）
    pub tpl_web_type: Option<String>,
    /// 生成包路径（如 com.stepby.system）
    pub package_name: Option<String>,
    /// 生成模块名（如 system）
    pub module_name: Option<String>,
    /// 生成业务名（如 user）
    pub business_name: Option<String>,
    /// 生成功能名（如 用户管理）
    pub function_name: Option<String>,
    /// 生成功能作者
    pub function_author: Option<String>,
    /// 代码生成方式（0=zip 1=自定义路径）
    pub gen_type: Option<String>,
    /// 自定义生成路径
    pub gen_path: Option<String>,
    /// 其他生成选项（JSON 字符串）
    pub options: Option<String>,
    pub create_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub update_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::gen_table_column::Entity")]
    GenTableColumn,
}

impl Related<super::gen_table_column::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::GenTableColumn.def()
    }
}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}
