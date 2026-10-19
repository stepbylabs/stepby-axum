// stepby-axum/migration/src/migrations/m20260925_000005_tenant_unique_scope.rs
//! 多租户 Phase 3.5g：剩余唯一域租户化（flow_task 业务唯一、scim_group external_id）。
//!
//! 承接 `m20260925_000004_tenant_saas_governance`（该迁移租户化了 role/user-scim/
//! config/dict_type 四项唯一域），本迁移补齐审计 R5 报告剩余的两项**非平台全局语义**唯一域：
//!
//!   1. `sys_flow_task`：旧 `uk_flow_task_biz (biz_type, biz_id, round_no, node_seq,
//!      assignee_id)` → 新 `uk_flow_task_tenant_biz (tenant_id, biz_type, biz_id,
//!      round_no, node_seq, assignee_id)`。原因：不同租户可能使用相同的 biz_type/biz_id
//!      业务键，旧索引会导致跨租户业务键互相顶撞（第二个租户建单失败）。
//!   2. `sys_scim_group`：旧 `uk_scim_group_external_id (external_id)` → 新
//!      `uk_scim_group_tenant_external (tenant_id, external_id)`。原因：externalId 是
//!      **每个 IdP（每租户）内部**的唯一键，全局唯一会阻止不同租户使用相同 IdP 标识。
//!
//! **不包含** `sys_tenant.tenant_code` / `sys_tenant_domain.domain`：二者是平台全局语义
//! （租户短码、域名在全平台范围内必须唯一），保持单列唯一索引，属正确设计。
//!
//! 幂等：删索引用方言分支（sqlite/pg `DROP INDEX IF EXISTS`，mysql 先查
//! information_schema）；建索引复用 `execute_index_ddl_ic`。**唯一索引创建失败只告警
//! 不阻断**（存量数据可能存在同租户重复键，属数据问题，不应阻断启动/迁移）。
//!
//! 本迁移与 `src/initialize/mod.rs::ensure_tenant_unique_scope` 为**双写**关系
//! （存量库启动不跑 `Migrator::up`，由 AppInitializer 幂等兜底）——修改时必须两处同步。

use crate::IndexDdlExt;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::Statement;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite
    )
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

/// 幂等删索引（三方言）：sqlite/pg 直接 `DROP INDEX IF EXISTS`；
/// MySQL 无该从句，先查 information_schema.statistics 判存在再
/// `DROP INDEX <idx> ON <table>`。
async fn drop_index_idempotent(
    manager: &SchemaManager<'_>,
    table: &str,
    index: &str,
) -> Result<(), DbErr> {
    let conn = manager.get_connection();
    if is_sqlite(manager) || is_postgres(manager) {
        conn.execute_unprepared(&format!("DROP INDEX IF EXISTS {index}"))
            .await?;
        return Ok(());
    }
    let row = conn
        .query_one_raw(Statement::from_string(
            conn.get_database_backend(),
            format!(
                "SELECT COUNT(*) AS n FROM information_schema.statistics \
                 WHERE table_schema = DATABASE() AND table_name = '{table}' AND index_name = '{index}'"
            ),
        ))
        .await?;
    let exists = row
        .map(|r| {
            r.try_get::<i64>("", "n")
                .or_else(|_| r.try_get::<i32>("", "n").map(i64::from))
                .unwrap_or(0)
        })
        .unwrap_or(0)
        > 0;
    if exists {
        conn.execute_unprepared(&format!("DROP INDEX {index} ON {table}"))
            .await?;
    }
    Ok(())
}

/// 建唯一索引：失败只告警不阻断（存量数据同租户重复键属数据问题）。
async fn create_unique_index_tolerant(
    manager: &SchemaManager<'_>,
    table: &str,
    index: &str,
    columns: &str,
) -> Result<(), DbErr> {
    let sql = format!("CREATE UNIQUE INDEX {index} ON {table} ({columns})");
    if let Err(e) = manager.get_connection().execute_index_ddl_ic(&sql).await {
        eprintln!(
            "[migration m20260925_000005] 唯一索引 {index} 创建失败（存量数据可能存在同租户重复，已跳过不阻断启动）: {e}"
        );
    }
    Ok(())
}

/// 待租户化的唯一域：(表, 旧单列唯一索引, 旧索引列, 新复合唯一索引, 复合列)
const UNIQUE_SCOPES: &[(&str, &str, &str, &str, &str)] = &[
    (
        "sys_flow_task",
        "uk_flow_task_biz",
        "biz_type, biz_id, round_no, node_seq, assignee_id",
        "uk_flow_task_tenant_biz",
        "tenant_id, biz_type, biz_id, round_no, node_seq, assignee_id",
    ),
    (
        "sys_scim_group",
        "uk_scim_group_external_id",
        "external_id",
        "uk_scim_group_tenant_external",
        "tenant_id, external_id",
    ),
];

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260925_000005_tenant_unique_scope"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, old_index, _old_cols, new_index, new_cols) in UNIQUE_SCOPES {
            drop_index_idempotent(manager, table, old_index).await?;
            create_unique_index_tolerant(manager, table, new_index, new_cols).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, old_index, old_cols, new_index, _new_cols) in UNIQUE_SCOPES {
            drop_index_idempotent(manager, table, new_index).await?;
            create_unique_index_tolerant(manager, table, old_index, old_cols).await?;
        }
        Ok(())
    }
}
