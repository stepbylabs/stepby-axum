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

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::Statement;
use crate::IndexDdlExt;

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
        .query_one(Statement::from_string(conn.get_database_backend(), exists_sql))
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
    conn.execute_unprepared(&format!("ALTER TABLE {table} ADD COLUMN {column} {column_def}"))
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

/// 安全项 config key（platform_only，平台锁定）。
///
/// 单一事实源为 `axum-backend/src/service/sys_config_service.rs::PLATFORM_LOCKED_KEYS`
/// （migration crate 无法依赖 lib，故此处保留同值本地副本，**修改时必须两处同步**）。
const PLATFORM_ONLY_KEYS: &[&str] = &[
    "sys.user.initPassword",
    "sys.account.captchaEnabled",
    "sys.account.registerUser",
    "sys.login.blackIPList",
    "ip_location.update_source",
    "ip_location.maxmind_account_id",
    "ip_location.maxmind_license_key",
    "ip_location.auto_update_enabled",
    "sys.audit.alarm.window_minutes",
    "sys.audit.alarm.fail_threshold",
    "sys.audit.alarm.fail_rate_threshold",
];

/// 可下放项 config key（platform_default，有平台默认值）。
///
/// 单一事实源为 `axum-backend/src/service/sys_config_service.rs::PLATFORM_DEFAULT_KEYS`
/// （migration crate 无法依赖 lib，故此处保留同值本地副本，**修改时必须两处同步**）。
const PLATFORM_DEFAULT_KEYS: &[&str] = &[
    "sys.index.skinName",
    "sys.index.sideTheme",
    "sys.login.background",
];

fn quoted_list(keys: &[&str]) -> String {
    keys.iter()
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
        // 语义（§27.8）：platform_only = 租户不可见 + 不可改；platform_default = 租户可见 + 可覆盖。
        conn.execute_unprepared(&format!(
            "UPDATE sys_config SET scope = 'platform_only', tenant_editable = '0', visible_to_tenant = '0' \
             WHERE config_key IN ({})",
            quoted_list(PLATFORM_ONLY_KEYS)
        ))
        .await?;
        conn.execute_unprepared(&format!(
            "UPDATE sys_config SET scope = 'platform_default', tenant_editable = '1', visible_to_tenant = '1' \
             WHERE config_key IN ({})",
            quoted_list(PLATFORM_DEFAULT_KEYS)
        ))
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 恢复旧单列唯一索引 + 删除新复合唯一索引（失败只告警，回滚不阻断）
        for (table, old_index, new_index, old_col) in [
            ("sys_role", "uk_sys_role_key", "uk_sys_role_tenant_key", "role_key"),
            (
                "sys_user",
                "idx_sys_user_scim_external_id",
                "uk_sys_user_tenant_scim",
                "scim_external_id",
            ),
            ("sys_config", "uk_sys_config_key", "uk_sys_config_tenant_key", "config_key"),
            ("sys_dict_type", "uk_sys_dict_type", "uk_sys_dict_type_tenant", "dict_type"),
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