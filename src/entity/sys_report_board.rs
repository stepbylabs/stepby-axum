//! sys_report_board 实体定义（报表看板表，配置化只读报表 v1）
//!
//! - tenant_id：多租户归属（0=平台租户）
//! - user_id：属主（v1 仅本人可读写）
//! - name：看板名称（UNIQUE(user_id, name)）
//! - config：看板配置 JSON（卡片数组），服务层反序列化为强类型 ReportBoardConfig 校验，
//!   sourceKey 只允许命中数据源白名单（杜绝任意 URL/SQL 注入面）

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_report_board")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysReportBoard",
    export_to = "SysReportBoard.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysReportBoard)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 属主用户 ID（v1 仅本人可读写）
    pub user_id: i64,
    /// 看板名称（用户内唯一）
    pub name: String,
    /// 看板配置 JSON（卡片数组：id/title/chartType/sourceKey/size）
    pub config: String,
    /// 启用状态（'1'=启用 '0'=停用，v1 保留字段）
    pub enabled: String,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
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
