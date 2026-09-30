// stepby-axum/migration/src/m20260722_000001_add_dict_label_en.rs
//! 字典数据国际化：新增 dict_label_en 字段
//!
//! sys_dict_data 原本只有 dict_label（中文标签），新增 dict_label_en（英文标签）
//! 用于前端 useDict Hook 根据当前 locale 自动选择对应语言的 label。
//!
//! 数据库兼容性说明：
//! - MySQL：使用 `ALTER TABLE ... ADD COLUMN ... AFTER dict_label` 将新字段
//!   紧邻 dict_label 之后，便于 DBA 巡检。
//! - PostgreSQL：使用 `ALTER TABLE ... ADD COLUMN ...`（PG 不支持 AFTER 子句，
//!   字段顺序由 PG 内部决定，应用层不依赖物理顺序）。
//! - SQLite：使用 TEXT 类型（SQLite 不强制 VARCHAR 长度）。
//!
//! 数据回填：
//! - 新字段允许为 NULL，但为避免前端在 en-US 下显示空 label，
//!   迁移完成后将 dict_label_en IS NULL 的行回填为 dict_label（中文标签）。
//!   后续可由管理员在前端逐条翻译为英文。
//!
//! 回滚说明：
//! - MySQL/PostgreSQL：直接 DROP COLUMN dict_label_en。
//! - SQLite：旧版本不支持 DROP COLUMN，跳过并输出 warn 日志。
//!
//! 实现说明：
//! - 后端检测沿用本 crate 既有模式（见 m20250711_000001_init.rs）：
//!   `manager.get_connection().get_database_backend()` 返回
//!   `sea_orm_migration::sea_orm::DatabaseBackend`。
//! - 通过 `execute_unprepared` 执行原始 SQL。
//! - 本 migration crate 未引入 tracing 依赖（Cargo.toml 不可改动），
//!   故使用 `eprintln!` 输出 SQLite 跳过警告到 stderr。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260722_000001_add_dict_label_en"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        match backend {
            sea_orm_migration::sea_orm::DatabaseBackend::MySql => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_dict_data ADD COLUMN dict_label_en VARCHAR(100) DEFAULT NULL AFTER dict_label",
                    )
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Postgres => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        "ALTER TABLE sys_dict_data ADD COLUMN dict_label_en VARCHAR(100)",
                    )
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
                manager
                    .get_connection()
                    .execute_unprepared("ALTER TABLE sys_dict_data ADD COLUMN dict_label_en TEXT")
                    .await?;
            }
        }
        // 为现有数据填充英文标签（默认与中文相同，便于后续翻译）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_dict_data SET dict_label_en = dict_label WHERE dict_label_en IS NULL",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        match backend {
            sea_orm_migration::sea_orm::DatabaseBackend::MySql
            | sea_orm_migration::sea_orm::DatabaseBackend::Postgres => {
                manager
                    .get_connection()
                    .execute_unprepared("ALTER TABLE sys_dict_data DROP COLUMN dict_label_en")
                    .await?;
            }
            sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
                // SQLite 旧版本不支持 DROP COLUMN，跳过
                eprintln!("[migration][warn] m20260722_000001: SQLite 不支持 DROP COLUMN，跳过");
            }
        }
        Ok(())
    }
}
