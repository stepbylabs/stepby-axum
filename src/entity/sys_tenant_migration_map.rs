//! sys_tenant_migration_map 实体定义（tid remap 映射表，多租户 Phase 3）
//!
//! **唯一不可逆点**的配套保护（文档 §29.7 风险与回滚）：
//! P1 把旧 tid（= 原租户根部门 `dept_id`）remap 为独立 `sys_tenant.tenant_id`。
//! 映射表**与业务表同事务写入、禁止清理**——回滚路径只能依赖它反向 UPDATE。
//!
//! `old_tid` 唯一：一个旧 tid 只允许映射一次（重复 remap 会被唯一索引挡住，
//! 避免把已经 remap 过的数据二次映射成别的租户）。
//!
//! ⚠️ **状态：迁移回滚保护的预留表**（§5.34 实体链路盘点 E-02）——表由
//! initialize Phase 3 迁移创建，但当前**无任何 service/repository/router 消费**
//! （remap 为一次性历史操作，回滚路径依赖手工 SQL + 本表）。**请勿**在无
//! 功能设计的情况下新增业务读写；若实现租户迁移功能，应先补 repository +
//! 审计 + 权限三层。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS)]
#[sea_orm(table_name = "sys_tenant_migration_map")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysTenantMigrationMap",
    export_to = "SysTenantMigrationMap.ts",
    rename_all = "camelCase"
)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub map_id: i64,
    /// 旧 tid（= 原租户根部门 dept_id，remap 前在业务表中流通的值）
    #[sea_orm(unique)]
    pub old_tid: i64,
    /// 新 tenant_id（sys_tenant.tenant_id）
    pub new_tenant_id: i64,
    pub create_time: Option<NaiveDateTime>,
    pub remark: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

// 追加写审计表：不自动维护 create_time/update_time（无 update_time 列，
// 写入方显式赋值；remap 由 AppInitializer / 服务层显式 SET create_time）
impl ActiveModelBehavior for ActiveModel {}
