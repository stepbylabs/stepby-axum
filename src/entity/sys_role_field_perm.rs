// stepby-axum/src/entity/sys_role_field_perm.rs
//! sys_role_field_perm 实体定义（角色字段级权限矩阵）
//!
//! 表由迁移 m20261003_000005_role_field_perm 创建（存量库由
//! `initialize/mod.rs::ensure_role_field_perm_tables` 幂等兜底，DDL 单一事实源在该迁移文件）。
//!
//! 字段语义（hidden 语义：该角色查看该业务表时隐藏这些字段）：
//! - `role_id`：角色 ID（sys_role.role_id）
//! - `table_key`：业务表标识，白名单见
//!   `service/sys_role_field_perm_service.rs::FIELD_PERM_TABLES`（首期仅 `sys_user`）
//! - `field_key`：字段标识（白名单同上，首期仅 `phonenumber` / `email`）
//! - 唯一约束 (role_id, table_key, field_key)：同角色同表同字段仅一行，
//!   是"全量覆盖式保存"幂等重放的基础（INSERT 冲突忽略）。
//! - 裁剪判定三层开关：平台 `sys.fieldPerm.enabled` → 租户能力位 `role.field_perm`
//!   → 本表角色行；任一层不满足即空集合（关闭态无行为变化，见服务层单测）。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use sea_orm::Set;
use serde::{Deserialize, Serialize};

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "sys_role_field_perm")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 角色 ID
    pub role_id: i64,
    /// 业务表标识（白名单见 FIELD_PERM_TABLES）
    pub table_key: String,
    /// 字段标识（白名单见 FIELD_PERM_TABLES 对应字段清单）
    pub field_key: String,
    /// 创建时间
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub create_time: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

/// 时间戳填充：insert 时写 create_time（本表无 update 语义，保存走全量覆盖重建）。
#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(
        self,
        _db: &C,
        insert: bool,
    ) -> Result<Self, DbErr>
    where
        C: sea_orm::ConnectionTrait,
    {
        let mut this = self;
        if insert {
            this.create_time = Set(Some(crate::common::datetime::now_naive()));
        }
        Ok(this)
    }
}
