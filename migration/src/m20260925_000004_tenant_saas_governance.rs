// axum-backend/migration/src/m20260925_000004_tenant_saas_governance.rs
//! 多租户 Phase 3.5f：SaaS 治理（config 治理列 + 唯一域租户化 + 审计目标租户）。
//!
//! 对应文档 §27.8（config 治理）/ §27.9（隔离缺口：审计目标租户）/ §29.7 P2
//! （config 治理列与两层缓存、审计 target_tenant_id）。**只做 DDL + 元数据 seed**：
//! 服务层的两层缓存与读写治理见 `src/service/sys_config_service.rs`。
//!
//! 内容：
//!   1. `sys_config` 增治理列 `scope` / `tenant_editable` / `visible_to_tenant`；
//!   2. `sys_oper_log` 增 `target_tenant_id`（平台代管时记录被操作资源租户，
//!      使租户可查"平台对我做过什么"；由审计写入链路负责赋值，本迁移只建列）；
//!   3. **唯一域租户化 4 项**（先删旧单列唯一索引，再建 `(tenant_id, <列>)` 复合唯一）：
//!      - `sys_role`：`uk_sys_role_key` → `uk_sys_role_tenant_key (tenant_id, role_key)`
//!      - `sys_user`：`idx_sys_user_scim_external_id` → `uk_sys_user_tenant_scim (tenant_id, scim_external_id)`
//!      - `sys_config`：`uk_sys_config_key` → `uk_sys_config_tenant_key (tenant_id, config_key)`
//!      - `sys_dict_type`：`uk_sys_dict_type` → `uk_sys_dict_type_tenant (tenant_id, dict_type)`
//!   4. config 治理元数据 seed（幂等 UPDATE，只改治理列，**不动 config_value**）：
//!      安全项 → `platform_only`；可下放项 → `platform_default`。
//!
//! 幂等：列存在性探测后 ALTER（sqlite pragma / pg·mysql information_schema）；
//! 删索引用方言分支（sqlite/pg `DROP INDEX IF EXISTS`，mysql 先查 information_schema）；
//! 建索引复用 `execute_index_ddl_ic`。**唯一索引创建失败只告警不阻断**
//! （存量数据可能存在同租户重复 key，属数据问题，不应阻断启动/迁移）。
//! `sys_oper_log.target_tenant_id` 由另一条代码链路写入，本迁移不碰实体。

use crate::IndexDdlExt;
use governance::{keys_with_coverage, Coverage};
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

/// 幂等加列：存在性探测后 `ALTER TABLE ADD COLUMN`（三方言）。
/// `column_def` 为列类型 + 约束，如 `VARCHAR(32) NOT NULL DEFAULT 'platform_only'`。
async fn ensure_column(
    manager: &SchemaManager<'_>,
    table: &str,
    column: &str,
    column_def: &str,
) -> Result<(), DbErr> {
    let conn = manager.get_connection();
    let exists_sql = if is_sqlite(manager) {
        format!("SELECT COUNT(*) AS n FROM pragma_table_info('{table}') WHERE name = '{column}'")
    } else if is_postgres(manager) {
        format!(
            "SELECT COUNT(*) AS n FROM information_schema.columns \
             WHERE table_name = '{table}' AND column_name = '{column}'"
        )
    } else {
        format!(
            "SELECT COUNT(*) AS n FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = '{table}' AND column_name = '{column}'"
        )
    };
    let row = conn
        .query_one(Statement::from_string(
            conn.get_database_backend(),
            exists_sql,
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
        return Ok(());
    }
    conn.execute_unprepared(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {column_def}"
    ))
    .await?;
    Ok(())
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
        .query_one(Statement::from_string(
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

/// 建唯一索引：失败只告警不阻断（存量数据同租户重复 key 属数据问题）。
async fn create_unique_index_tolerant(
    manager: &SchemaManager<'_>,
    table: &str,
    index: &str,
    columns: &str,
) -> Result<(), DbErr> {
    let sql = format!("CREATE UNIQUE INDEX {index} ON {table} ({columns})");
    if let Err(e) = manager.get_connection().execute_index_ddl_ic(&sql).await {
        eprintln!(
            "[migration m20260925_000004] 唯一索引 {index} 创建失败（存量数据可能存在同租户重复，已跳过不阻断启动）: {e}"
        );
    }
    Ok(())
}

/// 安全项 / 可下放项 config key：**一律取自共享注册表 crate `governance`**。
///
/// 抽离动机：本 crate 无法依赖 `axum-backend`（lib），此前只能保留同值本地副本并靠注释
/// 约束「修改时必须两处同步」。该形态已导致过治理静默失效事故，故上移为独立零依赖 crate，
/// 从物理上消除复制路径（启动兜底 `ensure_tenant_saas_governance` 引用同一份数据）。
/// 把键清单拼成 SQL 的 `'a', 'b'` 字面量列表。
fn quoted_list(keys: impl IntoIterator<Item = &'static str>) -> String {
    keys.into_iter()
        .map(|k| format!("'{k}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260925_000004_tenant_saas_governance"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // ---- 1. sys_config 治理列（列名/类型/默认值须与 AppInitializer 兜底逐列一致）----
        ensure_column(
            manager,
            "sys_config",
            "scope",
            "VARCHAR(32) NOT NULL DEFAULT 'platform_only'",
        )
        .await?;
        ensure_column(
            manager,
            "sys_config",
            "tenant_editable",
            "VARCHAR(1) NOT NULL DEFAULT '0'",
        )
        .await?;
        ensure_column(
            manager,
            "sys_config",
            "visible_to_tenant",
            "VARCHAR(1) NOT NULL DEFAULT '0'",
        )
        .await?;

        // ---- 2. sys_oper_log 目标租户列（§27.9 缺口 3）----
        ensure_column(manager, "sys_oper_log", "target_tenant_id", "BIGINT NULL").await?;

        // ---- 3. 唯一域租户化 4 项（先删旧单列唯一，再建复合唯一）----
        for (table, old_index, new_index, cols) in [
            (
                "sys_role",
                "uk_sys_role_key",
                "uk_sys_role_tenant_key",
                "tenant_id, role_key",
            ),
            (
                "sys_user",
                "idx_sys_user_scim_external_id",
                "uk_sys_user_tenant_scim",
                "tenant_id, scim_external_id",
            ),
            (
                "sys_config",
                "uk_sys_config_key",
                "uk_sys_config_tenant_key",
                "tenant_id, config_key",
            ),
            (
                "sys_dict_type",
                "uk_sys_dict_type",
                "uk_sys_dict_type_tenant",
                "tenant_id, dict_type",
            ),
        ] {
            drop_index_idempotent(manager, table, old_index).await?;
            create_unique_index_tolerant(manager, table, new_index, cols).await?;
        }

        // ---- 4. config 治理元数据 seed（幂等 UPDATE，只改治理列，不动 config_value）----
        // 语义由共享注册表的 `Coverage` 单一事实源给出（§27.8）：platform_only = 租户不可见 +
        // 不可改；platform_default = 租户可见 + 可覆盖。按覆盖策略分组，新增治理域无需改本迁移。
        for coverage in [
            Coverage::Locked,
            Coverage::Free,
            Coverage::Ceiling,
            Coverage::Private,
        ] {
            let list = quoted_list(keys_with_coverage(coverage));
            if list.is_empty() {
                continue;
            }
            conn.execute_unprepared(&format!(
                "UPDATE sys_config SET scope = '{}', tenant_editable = '{}', \
                 visible_to_tenant = '{}' WHERE config_key IN ({list})",
                coverage.scope(),
                coverage.tenant_editable(),
                coverage.visible_to_tenant()
            ))
            .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 恢复旧单列唯一索引 + 删除新复合唯一索引（失败只告警，回滚不阻断）
        for (table, old_index, new_index, old_col) in [
            (
                "sys_role",
                "uk_sys_role_key",
                "uk_sys_role_tenant_key",
                "role_key",
            ),
            (
                "sys_user",
                "idx_sys_user_scim_external_id",
                "uk_sys_user_tenant_scim",
                "scim_external_id",
            ),
            (
                "sys_config",
                "uk_sys_config_key",
                "uk_sys_config_tenant_key",
                "config_key",
            ),
            (
                "sys_dict_type",
                "uk_sys_dict_type",
                "uk_sys_dict_type_tenant",
                "dict_type",
            ),
        ] {
            drop_index_idempotent(manager, table, new_index).await?;
            let _ = conn
                .execute_index_ddl_ic(&format!(
                    "CREATE UNIQUE INDEX {old_index} ON {table} ({old_col})"
                ))
                .await;
        }
        for (table, column) in [
            ("sys_config", "visible_to_tenant"),
            ("sys_config", "tenant_editable"),
            ("sys_config", "scope"),
            ("sys_oper_log", "target_tenant_id"),
        ] {
            conn.execute_unprepared(&format!("ALTER TABLE {table} DROP COLUMN {column}"))
                .await?;
        }
        Ok(())
    }
}
