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
//! `initialize/mod.rs` 兜底函数引用本文件导出的单一事实源（建表 SQL / 索引清单 /
//! 加列 DDL / 菜单种子）同步补幂等语句（建表 IF NOT EXISTS + 加列前查列存在性）。
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

/// 种子时间表达式（批七十四 B1：归口到 `crate::seed_now_expr`，三方言统一 UTC 字面量）。
/// 本函数只是委托，**不得**在此另拼时间 ⇒ 换库/换时区不再换口径。
fn now_expr(_manager: &SchemaManager<'_>) -> String {
    crate::seed_now_expr()
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

// ==================== 单一事实源（迁移 up 与 initialize 兜底共用） ====================
//
// 存量库不跑 Migrator::up，`initialize/mod.rs::ensure_audit_change_tables` 每次启动
// 幂等兜底。建表 SQL / 索引清单 / 加列 DDL / 菜单种子全部抽为本文件的 pub 常量与函数，
// 两侧引用同一来源——漂移在物理上不可能。幂等前缀（INSERT OR IGNORE / ON CONFLICT /
// IGNORE）与列存在性检查是执行机制而非 SQL 内容，由两侧各自的执行器负责
// （迁移：execute_idempotent_insert；兜底：flow_insert / ensure_tenant_index）。

/// 审计查询索引（迁移 up/down 与兜底共用）
///
/// 元组：(索引名, 表名, 列清单)。迁移侧拼 `CREATE INDEX {ine}{name} ON {table} ({cols})`
/// （MySQL 经 `IndexDdlExt` 容错"索引已存在"）；兜底侧交 `ensure_tenant_index` 幂等执行。
pub const AUDIT_INDEXES: &[(&str, &str, &str)] = &[
    (
        "idx_audit_change_row",
        "sys_audit_change",
        "table_name, row_pk",
    ),
    ("idx_audit_change_time", "sys_audit_change", "operated_at"),
    ("idx_audit_change_tenant", "sys_audit_change", "tenant_id"),
];

/// `sys_oper_log.chain_hash` 加列 DDL 片段（迁移与兜底共用单一来源）
///
/// 列存在性检查（迁移侧由 Migrator 版本机制保证、兜底侧由 sso_has_column 负责）
/// 是幂等机制而非 SQL 内容，保持各侧自持。
pub const OPER_LOG_CHAIN_HASH_DDL: &str = "chain_hash VARCHAR(64) NULL";

/// 三方言建表 SQL（迁移 up 与 initialize 兜底共用单一来源）
///
/// `id` 自增主键与 `operated_at` 时间列按方言声明，其余列三方言一致。
pub fn create_table_sql(backend: sea_orm_migration::sea_orm::DatabaseBackend) -> String {
    use sea_orm_migration::sea_orm::DatabaseBackend;
    let (id_col, operated_at_type) = match backend {
        DatabaseBackend::Sqlite => ("id INTEGER PRIMARY KEY AUTOINCREMENT", "TIMESTAMP NOT NULL"),
        DatabaseBackend::Postgres => ("id BIGSERIAL PRIMARY KEY", "TIMESTAMP NOT NULL"),
        DatabaseBackend::MySql => (
            "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            "DATETIME NOT NULL",
        ),
        _ => unreachable!("unknown backend"),
    };
    format!(
        "CREATE TABLE IF NOT EXISTS sys_audit_change (
            {id_col},
            tenant_id       BIGINT NOT NULL DEFAULT 0,
            table_name      VARCHAR(64) NOT NULL,
            row_pk          VARCHAR(64) NOT NULL,
            action          VARCHAR(16) NOT NULL,
            changed_fields  TEXT NOT NULL,
            before_data     TEXT,
            after_data      TEXT,
            operator_id     BIGINT,
            operator_name   VARCHAR(64),
            operated_at     {operated_at_type}
        )"
    )
}

/// 审计菜单种子列清单（含 i18n_key，迁移与兜底共用）
pub const AUDIT_MENU_COLS: &str = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";

/// 菜单种子角色关联（role_id=2 common 角色；C 页面与 F 按钮均授予）
pub const AUDIT_MENU_ROLE_ID: i64 = 2;

/// 审计菜单种子行类型：(menu_id, menu_name, parent_id, order_num, path, component,
/// menu_type, perms, icon, remark, i18n_key)
pub type AuditMenuRow = (
    i64,
    &'static str,
    i64,
    i64,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
);

/// 审计菜单种子行（结构化元组，迁移与兜底共用）
///
/// F 按钮 remark 为空串、i18n_key 为 NULL；C 页面（4000）均有值。
pub const AUDIT_MENU_ROWS: &[AuditMenuRow] = &[
    (
        4000,
        "变更留痕",
        108,
        4,
        "auditChange",
        "system/auditChange/index",
        "C",
        "system:audit-change:list",
        "log",
        "业务数据变更留痕审计（前后快照 + 字段差异）",
        Some("menu.audit_change"),
    ),
    (
        4001,
        "变更查询",
        4000,
        1,
        "",
        "",
        "F",
        "system:audit-change:query",
        "#",
        "",
        None,
    ),
    (
        4002,
        "变更导出",
        4000,
        1,
        "",
        "",
        "F",
        "system:audit-change:export",
        "#",
        "",
        None,
    ),
];

/// 审计菜单种子 INSERT 语句体（不含幂等前缀——迁移 execute_idempotent_insert /
/// 兜底 flow_insert 各自拼接，语义等价）
///
/// 返回顺序与原迁移/兜底写库顺序一致：每行先 sys_menu 再 sys_role_menu
/// （4000 → role_menu(2,4000) → 4001 → role_menu → 4002 **无 role_menu**）。
///
/// b73 轮 15：`sys_role_menu` 行按 [`governance::common_role_may_grant`] 过滤——
/// 4002「变更留痕导出」是写/外泄面权限（`system:audit-change:export`），不再默认授予
/// common 角色（§8.2 只读姿态）。菜单行本身照常发放，perms 契约与授权页不受影响。
pub fn audit_menu_seed_bodies(now_expr: &str) -> Vec<String> {
    let mut bodies = Vec::with_capacity(AUDIT_MENU_ROWS.len() * 2);
    for (
        menu_id,
        name,
        parent_id,
        order_num,
        path,
        component,
        menu_type,
        perms,
        icon,
        remark,
        i18n_key,
    ) in AUDIT_MENU_ROWS
    {
        let i18n_sql = match i18n_key {
            Some(key) => format!("'{key}'"),
            None => "NULL".to_string(),
        };
        bodies.push(format!(
            "{AUDIT_MENU_COLS} VALUES \
            ({menu_id}, '{name}', {parent_id}, {order_num}, '{path}', '{component}', '', '', '1', '0', '{menu_type}', '0', '0', '{perms}', '{icon}', 'admin', {now_expr}, '{remark}', '0', {i18n_sql})"
        ));
        if governance::common_role_may_grant(*menu_id, menu_type, perms) {
            bodies.push(format!(
                "sys_role_menu (role_id, menu_id) VALUES ({AUDIT_MENU_ROLE_ID}, {menu_id})"
            ));
        }
    }
    bodies
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // ==================== 1. 建表 sys_audit_change（单一事实源） ====================
        let backend = conn.get_database_backend();
        conn.execute_unprepared(&create_table_sql(backend)).await?;

        // ==================== 2. 三个审计查询索引（单一事实源） ====================
        // MySQL 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属），留空交由
        // execute_index_ddl_ic 容错"索引已存在"实现幂等；PG/SQLite 直接 INE。
        let ine = match conn.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "",
            _ => "IF NOT EXISTS ",
        };
        for (idx_name, table, cols) in AUDIT_INDEXES {
            conn.execute_index_ddl_ic(&format!("CREATE INDEX {ine}{idx_name} ON {table} ({cols})"))
                .await?;
        }

        // ==================== 3. sys_oper_log 加 chain_hash 列（DDL 单一事实源） ====================
        // 三方言 ADD COLUMN 通用语法。**必须带列存在性守卫**：存量库启动时不跑 Migrator::up
        // （initialize/mod.rs:45），而审计兜底 ledger.rs 会"缺列才补"，于是存在
        // **列已补上、seaql_migrations 版本号却没登记**的库；这类库后来真跑 Migrator::up 时，
        // 无守卫的 ALTER 直接 `duplicate column name: chain_hash` 硬失败（2026-10-18 实测，
        // 存量库停在 88/121 处即挂）。口径与 m20261004_000003 等"先 has_column 再 ADD"一致。
        if !manager.has_column("sys_oper_log", "chain_hash").await? {
            conn.execute_unprepared(&format!(
                "ALTER TABLE sys_oper_log ADD COLUMN {OPER_LOG_CHAIN_HASH_DDL}"
            ))
            .await?;
        }

        // ==================== 4. 菜单元数据（单一事实源，段位 4000） ====================
        let now = now_expr(manager);
        for body in audit_menu_seed_bodies(&now) {
            execute_idempotent_insert(manager, &body).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 索引：MySQL 的 DROP INDEX 需要 ON <table>，PG/SQLite 不需要
        for (idx_name, table, _cols) in AUDIT_INDEXES {
            let sql = match conn.get_database_backend() {
                sea_orm::DatabaseBackend::MySql => format!("DROP INDEX {idx_name} ON {table}"),
                _ => format!("DROP INDEX IF EXISTS {idx_name}"),
            };
            conn.execute_unprepared(&sql).await?;
        }
        // 删菜单种子（幂等：IF EXISTS 仅 PG/SQLite 支持，MySQL 用 DELETE 影响行数容忍 0）
        let menu_ids = AUDIT_MENU_ROWS
            .iter()
            .map(|(id, ..)| id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = conn
            .execute_unprepared(&format!(
                "DELETE FROM sys_role_menu WHERE menu_id IN ({menu_ids})"
            ))
            .await;
        let _ = conn
            .execute_unprepared(&format!(
                "DELETE FROM sys_menu WHERE menu_id IN ({menu_ids})"
            ))
            .await;
        // 删表（加列不回滚：SQLite 不支持 DROP COLUMN，保持"迁移只进不退"惯例）
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_audit_change")
            .await?;
        Ok(())
    }
}
