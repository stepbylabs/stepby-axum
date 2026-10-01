// stepby-axum/migration/src/m20260928_000002_frontend_error_device_type.rs
//! FCP-011：`sys_frontend_error` 增加 `device_type` 列（Web Vitals 移动端分桶）。
//!
//! 前端上报器（frontendErrorReporter.ts）按 UA/视口推断设备类型
//! （mobile / tablet / desktop）随 vitals/异常一并上报；后端此前仅存
//! user_agent 原文，无法在查询侧直接按设备分桶聚合。
//!
//! 方言说明：`ADD COLUMN ... VARCHAR(16) NULL` 三库（PostgreSQL / MySQL / SQLite）
//! 语法一致，使用 sea-orm Table::alter 表达。存量库（启动不跑 Migrator::up）由
//! `src/initialize/mod.rs::ensure_frontend_error_device_type` 幂等兜底补列。
//!
//! down() 删列：日志表无外部依赖，删列安全（历史数据丢弃可接受）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260928_000002_frontend_error_device_type"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_frontend_error"))
                    .add_column_if_not_exists(
                        ColumnDef::new(Alias::new("device_type"))
                            .string_len(16)
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_frontend_error"))
                    .drop_column(Alias::new("device_type"))
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 可证伪：迁移名必须精确（存量库兜底与文档按名对齐）。
    #[test]
    fn migration_name_is_exact() {
        assert_eq!(
            Migration.name(),
            "m20260928_000002_frontend_error_device_type"
        );
    }
}
