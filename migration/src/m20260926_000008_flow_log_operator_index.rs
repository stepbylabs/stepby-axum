// axum-backend/migration/src/m20260926_000008_flow_log_operator_index.rs
//! 台账 W-12：为「已办视图」（W-8）补索引 `idx_flow_log_operator (operator_id, acted_at)`。
//!
//! ## 背景
//!
//! `sys_flow_log` 的既有索引只有 `idx_flow_log_biz (biz_type, biz_id, round_no)`（时间线维度）。
//! 「我审批过的」视图（W-8）按 `operator_id = ?` 过滤并按 `acted_at` 倒序分页，
//! 既有索引完全不覆盖 ⇒ **全表扫描**。
//!
//! ## 口径
//!
//! 迁移只进不退：本文件为**新增**迁移（不改动 `m20260923_000002_flow_module.rs`）；
//! `initialize/mod.rs::ensure_flow_indexes` 同步补同款兜底语句，保证既有库/新库一致。
//! 幂等：`IF NOT EXISTS`（PG/SQLite）；MySQL 由 `seaql_migrations` 保证只执行一次。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000008_flow_log_operator_index"
    }
}

const INDEX_NAME: &str = "idx_flow_log_operator";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let ine = if is_sqlite(manager) || is_postgres(manager) {
            "IF NOT EXISTS "
        } else {
            ""
        };
        conn.execute_unprepared(&format!(
            "CREATE INDEX {ine}{INDEX_NAME} ON sys_flow_log (operator_id, acted_at)"
        ))
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // MySQL 的 DROP INDEX 需要 ON <table>，PG/SQLite 不需要
        let sql = if is_sqlite(manager) || is_postgres(manager) {
            format!("DROP INDEX IF EXISTS {INDEX_NAME}")
        } else {
            format!("DROP INDEX {INDEX_NAME} ON sys_flow_log")
        };
        conn.execute_unprepared(&sql).await?;
        Ok(())
    }
}

fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm::DatabaseBackend::Sqlite
    )
}

fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm::DatabaseBackend::Postgres
    )
}
