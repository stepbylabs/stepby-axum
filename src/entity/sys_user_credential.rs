//! sys_user_credential 实体定义（WebAuthn / Passkey 凭据表）
//!
//! 每个用户可绑定多个 passkey（凭据）。字段语义对齐 `passkey-server` 的
//! [`StoredPasskey`](https://docs.rs/passkey-server)：
//! - `credential_id`：认证器全局唯一凭据 ID（Base64url 文本，**唯一约束**，登录时据此查库）；
//! - `public_key`：Base64url 编码的 COSE 公钥（仅公钥，无秘密；私钥永不出认证器）；
//! - `sign_count`：签名计数器（防克隆检测，每次成功认证后更新）；
//! - `last_used_at`：最近一次成功认证时间（可空，仅审计/展示用）；
//! - `del_flag`：软删标记（默认 '0'）。删除凭据走**物理删除**（见 service 说明），
//!   本列保留以与全库口径一致，读取一律按 `del_flag = '0'` 过滤（纵深防御）。
//!
//! 注意：本实体**不使用** `impl_timestamped_active_model!`（该宏要求存在 `update_time` 列），
//! `create_time` 由 Repository 在插入时显式写入。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_user_credential")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    /// 凭据 ID（自增主键；API 中的删除路径参数 `credId` 即此值）
    #[sea_orm(primary_key)]
    pub cred_id: i64,
    /// 属主用户 ID
    pub user_id: i64,
    /// 多租户归属（0=平台租户）
    pub tenant_id: i64,
    /// 认证器唯一凭据 ID（Base64url；登录时据此定位凭据）
    #[sea_orm(unique)]
    pub credential_id: String,
    /// Base64url 编码的 COSE 公钥
    pub public_key: String,
    /// 人类可读的凭据名（用户自定义 / 认证器 AAGUID 派生）
    pub name: String,
    /// 签名计数器（防克隆检测）
    pub sign_count: i64,
    /// 最近一次成功认证时间（可空）
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub last_used_at: Option<NaiveDateTime>,
    /// 创建时间
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
    /// 软删标记（默认 '0'；删除走物理删除，本列保留以复用全库过滤口径）
    pub del_flag: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

/// 空行为实现（默认钩子）：`create_time` 由 Repository 显式写入，不做自动时间戳
/// （本表无 `update_time` 列，故不使用 `impl_timestamped_active_model!`）。
#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}
