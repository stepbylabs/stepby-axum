//! sys_frontend_error 实体定义（前端异常与性能监控表，只追加日志）
//!
//! 统一承载两类可观测数据：
//! - 前端运行时异常：level=error/warning，source=vue/global/rejection/resource/api/other
//! - Web Vitals 性能指标：level=info，source=vital，value 存指标数值（秒/比例）
//!
//! 物理删除（日志表），仅 create_time（无 update_time），自定义 ActiveModelBehavior。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_frontend_error")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysFrontendError",
    export_to = "SysFrontendError.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysFrontendError)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 严重级别：error / warning / info（vitals 一般为 info）
    pub level: String,
    /// 来源：vue / global / rejection / resource / api / vital / other
    pub source: String,
    /// 错误名 / 指标名（如 "TypeError"、"LCP"）
    pub name: Option<String>,
    /// 错误信息 / 指标摘要
    pub message: Option<String>,
    /// 堆栈（errors）
    pub stack: Option<String>,
    /// 发生页面 URL
    pub page_url: Option<String>,
    /// User-Agent
    pub user_agent: Option<String>,
    /// 视口宽（px）
    pub view_width: Option<i32>,
    /// 视口高（px）
    pub view_height: Option<i32>,
    /// 性能指标数值（vitals，errors 为 NULL）
    pub value: Option<f64>,
    /// 上报用户名（登录态）
    pub user_name: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

/// 前端异常为只追加日志，仅 create_time，无 update_time。
/// 不能复用 impl_timestamped_active_model!（该宏会写 update_time），故自定义 ActiveModelBehavior。
#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        if insert {
            self.create_time = sea_orm::Set(Some(crate::common::datetime::now_naive()));
        }
        Ok(self)
    }
}
