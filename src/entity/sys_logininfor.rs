//! sys_logininfor 实体定义（系统访问记录 / 登录日志表）
//! 注意：ipaddr 字段为全小写（对齐前端 TS 定义），不使用下划线分隔

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_logininfor")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysLogininfor",
    export_to = "SysLogininfor.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysLogininfor)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub info_id: i64,
    pub user_name: Option<String>,
    /// 登录 IP 地址（全小写，对齐前端 ipaddr 字段）
    pub ipaddr: Option<String>,
    pub login_location: Option<String>,
    pub browser: Option<String>,
    pub os: Option<String>,
    pub status: Option<String>,
    pub msg: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub login_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
