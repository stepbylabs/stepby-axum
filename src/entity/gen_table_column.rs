//! gen_table_column 实体定义（代码生成业务表字段）
//!
//! 存储数据库表字段的元数据及代码生成配置。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "gen_table_column")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub column_id: i64,
    /// 归属表编号
    pub table_id: i64,
    /// 列名称
    pub column_name: Option<String>,
    /// 列描述
    pub column_comment: Option<String>,
    /// 列类型（如 VARCHAR(100)、BIGINT）
    pub column_type: Option<String>,
    /// Rust 类型（如 String、i64）
    pub java_type: Option<String>,
    /// Rust 字段名（snake_case）
    pub java_field: Option<String>,
    /// 是否主键（1=是 0=否）
    pub is_pk: Option<String>,
    /// 是否自增（1=是 0=否）
    pub is_increment: Option<String>,
    /// 是否必填（1=是 0=否）
    pub is_required: Option<String>,
    /// 是否为插入字段（1=是 0=否）
    pub is_insert: Option<String>,
    /// 是否编辑字段（1=是 0=否）
    pub is_edit: Option<String>,
    /// 是否列表字段（1=是 0=否）
    pub is_list: Option<String>,
    /// 是否查询字段（1=是 0=否）
    pub is_query: Option<String>,
    /// 查询方式（EQ/NE/LIKE/BETWEEN 等）
    pub query_type: Option<String>,
    /// 显示类型（input/textarea/select/datetime/imageUpload 等）
    pub html_type: Option<String>,
    /// 字典类型（如 sys_user_sex）
    pub dict_type: Option<String>,
    /// 排序
    pub sort: Option<i32>,
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
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::gen_table::Entity",
        from = "Column::TableId",
        to = "super::gen_table::Column::TableId"
    )]
    GenTable,
}

impl Related<super::gen_table::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::GenTable.def()
    }
}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}
