//! sys_oper_log 实体定义（操作日志表，日志表物理删除，时间由业务层设置）

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_oper_log")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysOperLog",
    export_to = "SysOperLog.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysOperLog)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    /// 被操作资源的目标租户（多租户 Phase 3）。
    ///
    /// 仅当「操作者租户」与「被操作资源租户」不一致（平台代管他租户资源）时写入，
    /// 用于让资源所属租户也能在审计日志中看到涉及自身资源的代管操作；
    /// 两者一致或单租户场景为 `NULL`。
    pub target_tenant_id: Option<i64>,
    #[sea_orm(primary_key)]
    pub oper_id: i64,
    pub title: Option<String>,
    pub business_type: Option<i32>,
    pub method: Option<String>,
    pub request_method: Option<String>,
    pub operator_type: Option<i32>,
    pub oper_name: Option<String>,
    pub dept_name: Option<String>,
    pub oper_url: Option<String>,
    pub oper_ip: Option<String>,
    pub oper_location: Option<String>,
    pub oper_param: Option<String>,
    /// 变更前数据快照（JSON，仅 PUT/DELETE 记录）
    pub oper_before: Option<String>,
    /// 字段级变更差异（JSON 数组 [{field,old,new}]，仅 PUT 成功记录）
    pub oper_diff: Option<String>,
    pub json_result: Option<String>,
    pub status: Option<String>,
    pub error_msg: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub oper_time: Option<NaiveDateTime>,
    pub cost_time: Option<i64>,
    /// 操作日志防篡改链哈希（HMAC-SHA256，hex 64 字符）。
    ///
    /// 迁移 m20261003_000001 新增列。写入时在分布式锁内基于上一条非 NULL
    /// chain_hash 计算链接哈希；锁竞争超限/共享态后端异常时降级为 NULL，
    /// 校验端对称跳过 NULL 行，保证链在非 NULL 子序列上连续可验证。
    pub chain_hash: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
