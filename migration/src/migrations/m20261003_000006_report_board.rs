// stepby-axum/migration/src/migrations/m20261003_000006_report_board.rs
//! 报表看板（配置化只读报表 v1）迁移：新建 `sys_report_board` 表 + 菜单种子。
//!
//! ## 表结构（三方言兼容，参考 m20261003_000005_role_field_perm 写法）
//!
//! - `tenant_id`：多租户归属（0=平台租户），行级隔离随 operator 租户
//! - `user_id`：属主（v1 仅本人可读写，无共享语义）
//! - `name`：看板名称（用户内唯一）
//! - `config`：看板配置 JSON（卡片数组：id/title/chartType/sourceKey/size），
//!   由主 crate 服务层反序列化为强类型 `ReportBoardConfig` 校验；
//!   `sourceKey` 只允许命中服务层数据源白名单（杜绝任意 URL/SQL 注入面）
//! - `enabled`：'1'=启用（'0'=停用，v1 保留字段）
//! - UNIQUE (user_id, name)：同一用户同名称唯一（覆盖式保存的幂等基础）
//! - 索引 idx(user_id)：按属主拉取看板清单的高频路径
//!
//! ## 菜单元数据
//!
//! 挂「系统工具」目录（menu_id=3，按钮段位对齐 4120/4121 式全新 4130 段）：
//! - C 页面 4130「报表看板」 path=reportBoard component=tool/reportBoard/index
//!   perms=tool:reportBoard:list
//! - F 按钮 4131「看板保存」 perms=tool:reportBoard:save（4121 式保存按钮）
//!
//! 两条均授予 role_id=2（common 角色；C 页面与 F 按钮均授予）。
//!
//! ## 口径
//!
//! 与 m20261003_000001_audit_change 同款：迁移只进不退；存量库不跑 Migrator::up，
//! `initialize/mod.rs` 兜底函数引用本文件导出的单一事实源（建表 SQL / 索引清单 /
//! 菜单种子）同步补幂等语句。

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
        "m20261003_000006_report_board"
    }
}

// ==================== 单一事实源（迁移 up 与 initialize 兜底共用） ====================
//
// 存量库不跑 Migrator::up，`initialize/mod.rs::ensure_report_board_tables` 每次启动
// 幂等兜底。建表 SQL / 索引清单 / 菜单种子全部抽为本文件的 pub 常量与函数，
// 两侧引用同一来源——漂移在物理上不可能。幂等前缀（INSERT OR IGNORE / ON CONFLICT /
// IGNORE）是执行机制而非 SQL 内容，由两侧各自的执行器负责
// （迁移：execute_idempotent_insert；兜底：flow_insert）。

/// 看板查询索引（迁移 up/down 与兜底共用）
///
/// 元组：(索引名, 表名, 列清单)。迁移侧拼 `CREATE INDEX {ine}{name} ON {table} ({cols})`
/// （MySQL 经 `IndexDdlExt` 容错"索引已存在"）；兜底侧交 `ensure_tenant_index` 幂等执行。
pub const REPORT_BOARD_INDEXES: &[(&str, &str, &str)] =
    &[("idx_report_board_user", "sys_report_board", "user_id")];

/// 三方言建表 SQL（迁移 up 与 initialize 兜底共用单一来源）
///
/// `id` 自增主键与时间列按方言声明，其余列三方言一致；
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
        "CREATE TABLE IF NOT EXISTS sys_report_board (
            {id_col},
            tenant_id   BIGINT NOT NULL DEFAULT 0,
            user_id     BIGINT NOT NULL,
            name        VARCHAR(64) NOT NULL,
            config      TEXT NOT NULL,
            enabled     CHAR(1) NOT NULL DEFAULT '1',
            create_time {ts_type},
            update_time {ts_type},
            CONSTRAINT uk_report_board_user_name UNIQUE (user_id, name)
        )"
    )
}

/// 菜单种子列清单（含 i18n_key，与 m20261003_000001_audit_change 同款；F 按钮不带 i18n_key）
pub const REPORT_BOARD_MENU_COLS: &str = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";

/// 菜单种子角色关联（role_id=2 common 角色；C 页面与 F 按钮均授予）
pub const REPORT_BOARD_MENU_ROLE_ID: i64 = 2;

/// 菜单种子行类型：(menu_id, menu_name, parent_id, order_num, path, component,
/// menu_type, perms, icon, remark, i18n_key)
pub type ReportBoardMenuRow = (
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

/// 菜单种子行（结构化元组，迁移与兜底共用）
///
/// C 页面 4130 + F 按钮 4131，挂「系统工具」目录（menu_id=3）4130 全新按钮段位。
pub const REPORT_BOARD_MENU_ROWS: &[ReportBoardMenuRow] = &[
    (
        4130,
        "报表看板",
        3,
        9,
        "reportBoard",
        "tool/reportBoard/index",
        "C",
        "tool:reportBoard:list",
        "chart",
        "配置化只读报表看板（数据源白名单，v1 仅本人可见）",
        Some("menu.reportBoard"),
    ),
    (
        4131,
        "看板保存",
        4130,
        1,
        "",
        "",
        "F",
        "tool:reportBoard:save",
        "#",
        "",
        None,
    ),
];

/// 菜单种子 INSERT 语句体（不含幂等前缀——迁移 execute_idempotent_insert /
/// 兜底 flow_insert 各自拼接，语义等价）
///
/// 返回顺序与写库顺序一致：4130 → role_menu(2,4130) → 4131 → role_menu(2,4131)。
pub fn report_board_menu_seed_bodies(now_expr: &str) -> Vec<String> {
    let mut bodies = Vec::with_capacity(REPORT_BOARD_MENU_ROWS.len() * 2);
    for (menu_id, name, parent_id, order_num, path, component, menu_type, perms, icon, remark, i18n_key) in
        REPORT_BOARD_MENU_ROWS
    {
        let i18n_sql = match i18n_key {
            Some(key) => format!("'{key}'"),
            None => "NULL".to_string(),
        };
        bodies.push(format!(
            "{REPORT_BOARD_MENU_COLS} VALUES \
            ({menu_id}, '{name}', {parent_id}, {order_num}, '{path}', '{component}', '', '', '1', '0', '{menu_type}', '0', '0', '{perms}', '{icon}', 'admin', {now_expr}, '{remark}', '0', {i18n_sql})"
        ));
        bodies.push(format!(
            "sys_role_menu (role_id, menu_id) VALUES ({REPORT_BOARD_MENU_ROLE_ID}, {menu_id})"
        ));
    }
    bodies
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // ==================== 1. 建表 sys_report_board（单一事实源） ====================
        let backend = conn.get_database_backend();
        conn.execute_unprepared(&create_table_sql(backend))
            .await?;

        // ==================== 2. 属主查询索引（单一事实源） ====================
        // MySQL 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属），留空交由
        // execute_index_ddl_ic 容错"索引已存在"实现幂等；PG/SQLite 直接 INE。
        let ine = match conn.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "",
            _ => "IF NOT EXISTS ",
        };
        for (idx_name, table, cols) in REPORT_BOARD_INDEXES {
            conn.execute_index_ddl_ic(&format!(
                "CREATE INDEX {ine}{idx_name} ON {table} ({cols})"
            ))
            .await?;
        }

        // ==================== 3. 菜单元数据（单一事实源，系统工具目录 4130 段） ====================
        let now = now_expr(manager);
        for body in report_board_menu_seed_bodies(&now) {
            execute_idempotent_insert(manager, &body).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 索引：MySQL 的 DROP INDEX 需要 ON <table>，PG/SQLite 不需要
        for (idx_name, table, _cols) in REPORT_BOARD_INDEXES {
            let sql = match conn.get_database_backend() {
                sea_orm::DatabaseBackend::MySql => format!("DROP INDEX {idx_name} ON {table}"),
                _ => format!("DROP INDEX IF EXISTS {idx_name}"),
            };
            conn.execute_unprepared(&sql).await?;
        }
        // 删菜单种子（幂等：IF EXISTS 仅 PG/SQLite 支持，MySQL 用 DELETE 影响行数容忍 0）
        let menu_ids = REPORT_BOARD_MENU_ROWS
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
        // 删表
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_report_board")
            .await?;
        Ok(())
    }
}
