//! sys_audit_change 实体定义（业务数据变更留痕表，审计合规域）
//!
//! 由业务写路径（sys_user / sys_role / sys_config / sys_web_hook 等）在
//! 同一事务内调用 `service::sys_audit_change_service::record_change` 写入，
//! 记录行级变更的前后 JSON 快照与字段级差异，供审计回溯与合规导出。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

/// 变更动作枚举值：新增
pub const ACTION_INSERT: &str = "INSERT";
/// 变更动作枚举值：更新
pub const ACTION_UPDATE: &str = "UPDATE";
/// 变更动作枚举值：删除
pub const ACTION_DELETE: &str = "DELETE";

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_audit_change")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysAuditChange",
    export_to = "SysAuditChange.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysAuditChange)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 多租户归属（0=平台；记录时从 before/after 快照的 tenant_id 字段提取，缺省落 DB 默认 0）
    pub tenant_id: i64,
    /// 被变更的表名（如 sys_user）
    pub table_name: String,
    /// 被变更行的主键值（字符串化，兼容非数值主键）
    pub row_pk: String,
    /// 变更动作：INSERT / UPDATE / DELETE
    pub action: String,
    /// 发生变化的字段名清单（JSON 数组，如 ["status","del_flag"]）
    pub changed_fields: String,
    /// 变更前快照（JSON 对象；INSERT 时为 NULL；敏感列值打码为 "***"）
    pub before_data: Option<String>,
    /// 变更后快照（JSON 对象；DELETE 时为 NULL；敏感列值打码为 "***"）
    pub after_data: Option<String>,
    /// 操作人用户 ID（事务内从 sys_user 回查补齐；回查失败为 NULL）
    pub operator_id: Option<i64>,
    /// 操作人用户名（回查失败为 NULL）
    pub operator_name: Option<String>,
    /// 变更发生时间（非可空，序列化为 RFC3339 UTC 字符串）
    #[serde(
        serialize_with = "datetime::serialize",
        deserialize_with = "datetime::deserialize"
    )]
    #[ts(as = "String")]
    pub operated_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
