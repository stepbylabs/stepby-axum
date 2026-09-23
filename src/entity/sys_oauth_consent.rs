//! sys_oauth_consent 实体定义（OIDC Provider：用户对客户端的授权同意记录）
//!
//! 记录某用户在某 client_id 上已授予的 scope 集合（user_id + client_id 唯一）。
//! authorize 流程据此判断是否需要跳转到同意页；用户批准时 upsert 本表。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_oauth_consent")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub consent_id: i64,
    pub user_id: i64,
    pub client_id: String,
    /// 已授予 scope JSON 数组字符串
    pub scopes: String,
    /// 客户端名称快照（v4-F4/R6：客户端被删除/改名后，用户仍能识别"曾授权给谁"）
    #[serde(default)]
    pub client_name_snapshot: String,
    /// 同意时刻（v4-R6：由 auth_time 改名——本表语义是"用户批准授权的时刻"，
    /// 与 ID Token 的 auth_time（用户认证时刻）同名不同义，改名防误用）
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub consented_at: Option<NaiveDateTime>,
    /// 软删除标记（'0'=有效 '2'=用户已撤销；v2-I7 用户自助撤销不物理删，保留审计）
    #[serde(default)]
    pub del_flag: String,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub create_time: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub update_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
