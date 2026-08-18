//! sys_rate_limit 实体定义（API 限流配置表）
//!
//! 注意：rate_limit 表无 del_flag，使用物理删除
//! route_pattern: "*" 表示全局默认，其他为路由前缀（如 /system/user、/login）
//!
//! 中间件读取顺序：先精确匹配 route_pattern，未命中则使用 "*" 全局默认。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_rate_limit")]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SysRateLimit.ts", rename_all = "camelCase")]
#[schema(as = SysRateLimit)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 路由前缀（"*" 表示全局默认，其他为具体路由前缀如 /system/user、/login）
    #[sea_orm(unique)]
    pub route_pattern: String,
    /// 桶容量（突发请求上限）
    pub capacity: i32,
    /// 每秒补充令牌数
    pub refill_per_second: f64,
    /// 是否启用
    pub enabled: bool,
    /// 描述
    pub description: Option<String>,
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
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
