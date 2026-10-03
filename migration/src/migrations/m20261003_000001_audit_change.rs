// stepby-axum/migration/src/migrations/m20261003_000001_audit_change.rs
//! 审计合规域迁移（数据变更留痕 + 操作日志防篡改链）：
//!
//! 1. 新表 `sys_audit_change`：业务表数据变更留痕（INSERT/UPDATE/DELETE 前后快照 +
//!    字段级 diff），由业务写路径在同一事务内调用 `record_change` 写入：
//!    - table_name + row_pk：被变更的表与行主键（VARCHAR，兼容非数值主键）
//!    - action：INSERT / UPDATE / DELETE
//!    - changed_fields：JSON 数组（发生变化的字段名清单）
//!    - before_data / after_data：JSON 快照（INSERT 时 before 为 NULL；DELETE 时 after 为 NULL；
//!      敏感列如 password/secret/token 的值打码为 "***"）
//!    - operator_id / operator_name：操作人（事务内从 sys_user 回查补齐）
//!    - operated_at：变更发生时间
//!
//! 2. `sys_oper_log` 加列 `chain_hash VARCHAR(64) NULL`：操作日志 HMAC-SHA256 防篡改链。
//!    NULL = 该行未入链（并发锁获取失败的降级行），校验接口跳过 NULL 行不误报。
//!
//! 3. 菜单元数据（挂在日志管理目录 parent_id=108，段位 4000 全新段）：
//!    - C 页面「变更留痕」(4000) perms=system:audit-change:list
//!    - F 按钮「变更查询」(4001) /「变更导出」(4002)
//!    - role_menu 关联 role_id=2（common 角色）
//!
//! ## 口径
//!
//! 与 m20261002_000001_perf_indexes 同款：迁移只进不退；存量库不跑 Migrator::up，
//! `initialize/mod.rs` 兜底函数同步补幂等语句（建表 IF NOT EXISTS + 加列前查列存在性）。
//! 索引幂等：`IF NOT EXISTS`（PG/SQLite）；MySQL 经 `IndexDdlExt` 容错"索引已存在"。

use crate::IndexDdlExt;
use sea_orm_migration::prelude::*;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(backend, sea_orm_migration::sea_orm::DatabaseBackend::Sqlite)
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

/// 当前时间表达式（跨数据库兼容）
fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        format!("'{}'", now)
    } else {
        "NOW()".to_string()
    }
}

/// 幂等 INSERT
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        format!("INSERT OR IGNORE INTO {}", body)
    } else if is_postgres(manager) {
        format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
    } else {
        format!("INSERT IGNORE INTO {}", body)
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261003_000001_audit_change"
    }
}

/// 审计索引目标（down 与 up 共用）
const AUDIT_INDEX_TARGETS: &[(&str, &str)] = &[
    ("idx_audit_change_row", "sys_audit_change (table_name, row_pk)"),
    ("idx_audit_change_time", "sys_audit_change (operated_at)"),
    ("idx_audit_change_tenant", "sys_audit_change (tenant_id)"),
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // ==================== 1. 建表 sys_audit_change ====================
        let sql = if is_sqlite(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_audit_change (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id       BIGINT NOT NULL DEFAULT 0,
                table_name      VARCHAR(64) NOT NULL,
                row_pk          VARCHAR(64) NOT NULL,
                action          VARCHAR(16) NOT NULL,
                changed_fields  TEXT NOT NULL,
                before_data     TEXT,
                after_data      TEXT,
                operator_id     BIGINT,
                operator_name   VARCHAR(64),
                operated_at     TIMESTAMP NOT NULL
            )"#
            .to_string()
        } else if is_postgres(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_audit_change (
                id              BIGSERIAL PRIMARY KEY,
                tenant_id       BIGINT NOT NULL DEFAULT 0,
                table_name      VARCHAR(64) NOT NULL,
                row_pk          VARCHAR(64) NOT NULL,
                action          VARCHAR(16) NOT NULL,
                changed_fields  TEXT NOT NULL,
                before_data     TEXT,
                after_data      TEXT,
                operator_id     BIGINT,
                operator_name   VARCHAR(64),
                operated_at     TIMESTAMP NOT NULL
            )"#
            .to_string()
        } else {
            r#"CREATE TABLE IF NOT EXISTS sys_audit_change (
                id              BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                tenant_id       BIGINT NOT NULL DEFAULT 0,
                table_name      VARCHAR(64) NOT NULL,
                row_pk          VARCHAR(64) NOT NULL,
                action          VARCHAR(16) NOT NULL,
                changed_fields  TEXT NOT NULL,
                before_data     TEXT,
                after_data      TEXT,
                operator_id     BIGINT,
                operator_name   VARCHAR(64),
                operated_at     DATETIME NOT NULL
            )"#
            .to_string()
        };
        conn.execute_unprepared(&sql).await?;

        // ==================== 2. 三个审计查询索引 ====================
        // MySQL 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属），留空交由
        // execute_index_ddl_ic 容错"索引已存在"实现幂等；PG/SQLite 直接 INE。
        let ine = match conn.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "",
            _ => "IF NOT EXISTS ",
        };
        for (idx_name, target) in AUDIT_INDEX_TARGETS {
            conn.execute_index_ddl_ic(&format!(
                "CREATE INDEX {ine}{idx_name} ON {target}"
            ))
            .await?;
        }

        // ==================== 3. sys_oper_log 加 chain_hash 列 ====================
        // sea-query 的 TableAlterStatement 跨三方言生成等价 DDL（ADD COLUMN 通用语法）。
        // 迁移幂等由 Migrator 版本机制保证（每库只执行一次）；
        // 存量库（不跑 Migrator::up）由 initialize/mod.rs 兜底函数按列存在性检查补列。
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_oper_log"))
                    .add_column(
                        ColumnDef::new(Alias::new("chain_hash"))
                            .string_len(64)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // ==================== 4. 菜单元数据（审计合规域，段位 4000） ====================
        let now = now_expr(manager);
        let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";

        // C 页面「变更留痕」（挂日志管理目录 108）
        let page_sql = format!(
            "{menu_cols} VALUES \
            (4000, '变更留痕', 108, 4, 'auditChange', 'system/auditChange/index', '', '', '1', '0', 'C', '0', '0', 'system:audit-change:list', 'log', 'admin', {now}, '业务数据变更留痕审计（前后快照 + 字段差异）', '0', 'menu.audit_change')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 4000)")
            .await?;

        // F 按钮（权限标识与后端 PERM_ROUTE_TABLE 对齐，menu_perm_contract 契约测试依赖）
        let btn_rows: &[(i64, &str, &str)] = &[
            (4001, "变更查询", "system:audit-change:query"),
            (4002, "变更导出", "system:audit-change:export"),
        ];
        for (menu_id, name, perms) in btn_rows {
            let sql = format!(
                "{menu_cols} VALUES \
                ({menu_id}, '{name}', 4000, 1, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '#', 'admin', {now}, '', '0', NULL)"
            );
            execute_idempotent_insert(manager, &sql).await?;
            execute_idempotent_insert(
                manager,
                &format!("sys_role_menu (role_id, menu_id) VALUES (2, {menu_id})"),
            )
            .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 索引：MySQL 的 DROP INDEX 需要 ON <table>，PG/SQLite 不需要
        for (idx_name, target) in AUDIT_INDEX_TARGETS {
            let sql = match conn.get_database_backend() {
                sea_orm::DatabaseBackend::MySql => {
                    let table = target.split(" (").next().unwrap_or(target);
                    format!("DROP INDEX {idx_name} ON {table}")
                }
                _ => format!("DROP INDEX IF EXISTS {idx_name}"),
            };
            conn.execute_unprepared(&sql).await?;
        }
        // 删菜单种子（幂等：IF EXISTS 仅 PG/SQLite 支持，MySQL 用 DELETE 影响行数容忍 0）
        let _ = conn
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id IN (4000, 4001, 4002)")
            .await;
        let _ = conn
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id IN (4000, 4001, 4002)")
            .await;
        // 删表（加列不回滚：SQLite 不支持 DROP COLUMN，保持"迁移只进不退"惯例）
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_audit_change")
            .await?;
        Ok(())
    }
}
