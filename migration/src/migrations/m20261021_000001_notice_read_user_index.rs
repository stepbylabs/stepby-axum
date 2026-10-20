// stepby-axum/migration/src/migrations/m20261021_000001_notice_read_user_index.rs
//! 通知已读半连接索引：`sys_notice_read (user_id, tenant_id, notice_id)`
//!
//! 背景（b81 / §10 N-9）：`/system/notice/list?isRead=0` 与 `listTop` 的未读/已读过滤
//! 使用子查询 `SELECT notice_id FROM sys_notice_read WHERE user_id = ? [AND tenant_id = ?]`。
//! 既有索引是 `(notice_id, user_id)` 与 `(tenant_id)`；前者首列不是 `user_id`，后者对
//! 平台操作者（tenant_id 不参与过滤）没有区分度 ⇒ 实测 SQLite 计划为
//! `SEARCH sys_notice_read USING INDEX idx_sys_notice_read_tid (tenant_id=?)`，
//! 每次列表查询都要扫描该租户的全部已读行。
//!
//! 新索引以 `user_id` 为前缀，平台与租户两种谓词都能走覆盖索引（仅回索引、不回表）。
//! 该索引随迁移在存量库补齐，并由 `integration_tests::tenant_index_plan` 的
//! `EXPLAIN QUERY PLAN` 判据钉住（含"删索引后判据必须转红"的变异控制组）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261021_000001_notice_read_user_index"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_notice_read_user_tenant_notice")
                    .table(Alias::new("sys_notice_read"))
                    .col(Alias::new("user_id"))
                    .col(Alias::new("tenant_id"))
                    .col(Alias::new("notice_id"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_sys_notice_read_user_tenant_notice")
                    .table(Alias::new("sys_notice_read"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
