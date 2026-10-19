// stepby-axum/migration/src/migrations/m20260717_000001_add_indexes.rs
//! 第三次迁移：补充高频查询字段索引
//!
//! 新增索引：
//! 1. sys_oper_log.oper_name — 按操作人筛选审计日志（高频）
//! 2. sys_oper_log.oper_ip  — 按 IP 筛选审计日志
//! 3. sys_logininfor.ipaddr — 按 IP 筛选登录日志
//!
//! 修复 DB-07/DB-08：原迁移遗漏这些高频查询字段的索引。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260717_000001_add_indexes"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // sys_oper_log: 按操作人筛选（高频查询）
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_oper_log_oper_name")
                    .table(Alias::new("sys_oper_log"))
                    .col(Alias::new("oper_name"))
                    .to_owned(),
            )
            .await?;

        // sys_oper_log: 按 IP 筛选（安全审计场景）
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_oper_log_oper_ip")
                    .table(Alias::new("sys_oper_log"))
                    .col(Alias::new("oper_ip"))
                    .to_owned(),
            )
            .await?;

        // sys_logininfor: 按 IP 筛选（安全审计场景）
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_logininfor_ipaddr")
                    .table(Alias::new("sys_logininfor"))
                    .col(Alias::new("ipaddr"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_sys_logininfor_ipaddr")
                    .table(Alias::new("sys_logininfor"))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_sys_oper_log_oper_ip")
                    .table(Alias::new("sys_oper_log"))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_sys_oper_log_oper_name")
                    .table(Alias::new("sys_oper_log"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
