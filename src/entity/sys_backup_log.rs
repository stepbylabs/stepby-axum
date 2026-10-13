//! sys_backup_log 实体定义（数据备份日志表）
//!
//! backup_type: "manual"=手动备份, "auto"=自动备份, "restore"=恢复
//! status:      "success"=成功, "failed"=失败

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "sys_backup_log")]
#[serde(rename_all = "camelCase")]
#[schema(as = SysBackupLog)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub backup_id: i64,
    /// 备份文件名
    pub file_name: String,
    /// 备份文件绝对/相对路径
    pub file_path: String,
    /// 备份文件大小（字节）
    pub file_size: i64,
    /// 备份类型（manual=手动备份, auto=自动备份, restore=恢复）
    pub backup_type: String,
    /// 状态（success=成功, failed=失败）
    pub status: String,
    /// 错误消息（失败时）
    pub error_msg: Option<String>,
    pub create_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub create_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
