// stepby-axum/migration/src/migrations/m20261003_000005_role_field_perm.rs
//! 字段级权限 M2 迁移：新建 `sys_role_field_perm` 表 + 角色管理按钮种子 + 平台开关种子。
//!
//! ## 表结构（三方言兼容，参考 m20261003_000003_alert_rule 写法）
//!
//! - `role_id`：角色 ID（sys_role.role_id）
//! - `table_key`：业务表标识（白名单见主 crate
//!   `service/sys_role_field_perm_service.rs::FIELD_PERM_TABLES`，首期仅 `sys_user`）
//! - `field_key`：字段标识（白名单同上，首期仅 `phonenumber` / `email`）
//! - `create_time`：创建时间
//! - UNIQUE (role_id, table_key, field_key)：同一角色同表同字段仅一行（覆盖式保存的幂等基础）
//! - 索引 idx(role_id)：按角色批量查询（hidden_fields 并集判定的高频路径）
//!
//! ## 菜单元数据
//!
//! 挂「角色管理」页面（menu_id=101）按钮段（既有 1007-1011，本迁移从 6 起续段）：
//! - F 按钮 4120「字段权限」 perms=system:role:fieldPerm（矩阵读）
//! - F 按钮 4121「字段权限保存」 perms=system:role:fieldPermSave（矩阵写）
//!
//! 两条均授予 role_id=1（超管角色；超管另有 `*:*:*` 通配，此处落 role_menu 行
//! 保证菜单树里按钮可见，与"能力全备、默认安全"一致——按钮可见不代表功能开启）。
//!
//! ## sys_config 种子
//!
//! 第一层平台开关 `sys.fieldPerm.enabled`（默认 'false' = 关闭态即安全态）。
//! 该键同步登记在 `governance::CONFIGS`（Coverage::Locked，平台锁定），启动期
//! 治理列收敛（ensure_tenant_saas_governance）会自动把行收敛到声明姿态。
//!
//! ## 口径
//!
//! 与 m20261003_000001_audit_change 同款：迁移只进不退；存量库不跑 Migrator::up，
//! `initialize/mod.rs` 兜底函数引用本文件导出的单一事实源（建表 SQL / 索引清单 /
//! 菜单种子 / config 种子）同步补幂等语句。

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
        "m20261003_000005_role_field_perm"
    }
}

// ==================== 单一事实源（迁移 up 与 initialize 兜底共用） ====================
//
// 存量库不跑 Migrator::up，`initialize/mod.rs::ensure_role_field_perm_tables` 每次启动
// 幂等兜底。建表 SQL / 索引清单 / 菜单种子 / config 种子全部抽为本文件的 pub 常量与函数，
// 两侧引用同一来源——漂移在物理上不可能。幂等前缀（INSERT OR IGNORE / ON CONFLICT /
// IGNORE）是执行机制而非 SQL 内容，由两侧各自的执行器负责
// （迁移：execute_idempotent_insert；兜底：flow_insert）。

/// 字段权限查询索引（迁移 up/down 与兜底共用）
///
/// 元组：(索引名, 表名, 列清单)。迁移侧拼 `CREATE INDEX {ine}{name} ON {table} ({cols})`
/// （MySQL 经 `IndexDdlExt` 容错"索引已存在"）；兜底侧交 `ensure_tenant_index` 幂等执行。
pub const ROLE_FIELD_PERM_INDEXES: &[(&str, &str, &str)] = &[(
    "idx_role_field_perm_role",
    "sys_role_field_perm",
    "role_id",
)];

/// 第一层平台开关的 `sys_config` 键（迁移与主 crate 服务层共用字符串）
pub const FIELD_PERM_ENABLED_CONFIG_KEY: &str = "sys.fieldPerm.enabled";

/// 三方言建表 SQL（迁移 up 与 initialize 兜底共用单一来源）
///
/// `id` 自增主键与 `create_time` 时间列按方言声明，其余列三方言一致；
/// UNIQUE 约束内联建表（三方言均支持表级 CONSTRAINT，兜底侧随 IF NOT EXISTS 建表幂等）。
pub fn create_table_sql(backend: sea_orm_migration::sea_orm::DatabaseBackend) -> String {
    use sea_orm_migration::sea_orm::DatabaseBackend;
    let (id_col, ts_type) = match backend {
        DatabaseBackend::Sqlite => ("id INTEGER PRIMARY KEY AUTOINCREMENT", "TIMESTAMP NOT NULL"),
        DatabaseBackend::Postgres => ("id BIGSERIAL PRIMARY KEY", "TIMESTAMP NOT NULL"),
        DatabaseBackend::MySql => (
            "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            "DATETIME NOT NULL",
        ),
        _ => unreachable!("unknown backend"),
    };
    format!(
        "CREATE TABLE IF NOT EXISTS sys_role_field_perm (
            {id_col},
            role_id     BIGINT NOT NULL,
            table_key   VARCHAR(64) NOT NULL,
            field_key   VARCHAR(64) NOT NULL,
            create_time {ts_type},
            CONSTRAINT uk_role_field_perm UNIQUE (role_id, table_key, field_key)
        )"
    )
}

/// 菜单种子列清单（与 m20261003_000003_alert_rule 同款，F 按钮不带 i18n_key）
pub const FIELD_PERM_MENU_COLS: &str = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag)";

/// 菜单种子角色关联（role_id=1 超管角色；读/写按钮均授予）
pub const FIELD_PERM_MENU_ROLE_ID: i64 = 1;

/// 菜单种子行类型：(menu_id, menu_name, parent_id, order_num, path, component,
/// menu_type, perms, icon, remark)
pub type FieldPermMenuRow = (
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
);

/// 菜单种子行（结构化元组，迁移与兜底共用）
///
/// F 按钮 4120/4121 挂「角色管理」页面（menu_id=101）按钮段（既有 1007-1011 从 6 续段）。
pub const FIELD_PERM_MENU_ROWS: &[FieldPermMenuRow] = &[
    (
        4120,
        "字段权限",
        101,
        6,
        "#",
        "",
        "F",
        "system:role:fieldPerm",
        "#",
        "角色字段级权限矩阵查看",
    ),
    (
        4121,
        "字段权限保存",
        101,
        7,
        "#",
        "",
        "F",
        "system:role:fieldPermSave",
        "#",
        "角色字段级权限矩阵保存（全量覆盖）",
    ),
];

/// 菜单种子 INSERT 语句体（不含幂等前缀——迁移 execute_idempotent_insert /
/// 兜底 flow_insert 各自拼接，语义等价）
///
/// 返回顺序与写库顺序一致：4120 → role_menu(1,4120) → 4121 → role_menu(1,4121)。
pub fn field_perm_menu_seed_bodies(now_expr: &str) -> Vec<String> {
    let mut bodies = Vec::with_capacity(FIELD_PERM_MENU_ROWS.len() * 2);
    for (menu_id, name, parent_id, order_num, path, component, menu_type, perms, icon, remark) in
        FIELD_PERM_MENU_ROWS
    {
        bodies.push(format!(
            "{FIELD_PERM_MENU_COLS} VALUES \
            ({menu_id}, '{name}', {parent_id}, {order_num}, '{path}', '{component}', '', '', '1', '0', '{menu_type}', '0', '0', '{perms}', '{icon}', 'admin', {now_expr}, '{remark}', '0')"
        ));
        bodies.push(format!(
            "sys_role_menu (role_id, menu_id) VALUES ({FIELD_PERM_MENU_ROLE_ID}, {menu_id})"
        ));
    }
    bodies
}

/// 平台开关 `sys.fieldPerm.enabled` 的 config 种子行 INSERT 语句体
/// （不含幂等前缀；唯一域 (tenant_id, config_key) 冲突时忽略 = 保留运维已改的值）
///
/// 默认 'false' = 关闭态即安全态：关闭态下 hidden_fields 恒空、矩阵接口拒绝，
/// 全系统零行为变化（可证伪单测锁死）。
pub fn field_perm_config_seed_body(now_expr: &str) -> String {
    format!(
        "sys_config (tenant_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
        (0, '字段级权限开关', '{FIELD_PERM_ENABLED_CONFIG_KEY}', 'false', 'Y', 'admin', {now_expr}, \
        '角色字段级权限总开关（平台锁定）；false=关闭，关闭态裁剪逻辑短路、矩阵接口拒绝')"
    )
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // ==================== 1. 建表 sys_role_field_perm（单一事实源） ====================
        let backend = conn.get_database_backend();
        conn.execute_unprepared(&create_table_sql(backend))
            .await?;

        // ==================== 2. 角色查询索引（单一事实源） ====================
        // MySQL 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属），留空交由
        // execute_index_ddl_ic 容错"索引已存在"实现幂等；PG/SQLite 直接 INE。
        let ine = match conn.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "",
            _ => "IF NOT EXISTS ",
        };
        for (idx_name, table, cols) in ROLE_FIELD_PERM_INDEXES {
            conn.execute_index_ddl_ic(&format!(
                "CREATE INDEX {ine}{idx_name} ON {table} ({cols})"
            ))
            .await?;
        }

        // ==================== 3. 菜单元数据（单一事实源，角色管理按钮段） ====================
        let now = now_expr(manager);
        for body in field_perm_menu_seed_bodies(&now) {
            execute_idempotent_insert(manager, &body).await?;
        }

        // ==================== 4. sys_config 平台开关种子（默认 false = 关闭） ====================
        execute_idempotent_insert(manager, &field_perm_config_seed_body(&now)).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 索引：MySQL 的 DROP INDEX 需要 ON <table>，PG/SQLite 不需要
        for (idx_name, table, _cols) in ROLE_FIELD_PERM_INDEXES {
            let sql = match conn.get_database_backend() {
                sea_orm::DatabaseBackend::MySql => format!("DROP INDEX {idx_name} ON {table}"),
                _ => format!("DROP INDEX IF EXISTS {idx_name}"),
            };
            conn.execute_unprepared(&sql).await?;
        }
        // 删菜单种子（幂等：IF EXISTS 仅 PG/SQLite 支持，MySQL 用 DELETE 影响行数容忍 0）
        let menu_ids = FIELD_PERM_MENU_ROWS
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
        // 删 config 种子（回滚仅清本迁移引入的开关行）
        let _ = conn
            .execute_unprepared(&format!(
                "DELETE FROM sys_config WHERE config_key = '{FIELD_PERM_ENABLED_CONFIG_KEY}'"
            ))
            .await;
        // 删表
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_role_field_perm")
            .await?;
        Ok(())
    }
}
