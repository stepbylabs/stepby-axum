// stepby-axum/migration/src/migrations/m20261003_000003_alert_rule.rs
//! 告警规则引擎迁移：新建 `sys_alert_rule` 表 + 「告警规则」菜单种子。
//!
//! ## 表结构（三方言兼容，参考 m20260818_000002_msg_module 写法）
//!
//! - `name`：规则名称（展示用）
//! - `metric`：指标标识（白名单见主 crate `service/sys_alert_service.rs::VALID_METRICS`）
//! - `comparator`：比较器 gt/lt/ge/le
//! - `threshold`：阈值（DOUBLE / DOUBLE PRECISION）
//! - `silent_minutes`：静默期（分钟），触发后在该窗口内不重复通知
//! - `notify_channel_id` / `notify_template_id`：消息中心渠道 / 模板（可空；
//!   为空时评估命中仅记录 `last_fired_at` 与日志，不发送通知）
//! - `enabled`：'1' 启用 / '0' 停用
//! - `last_fired_at`：上次触发时间（NULL = 从未触发）
//!
//! ## 口径
//!
//! 迁移负责全新库；存量库由主 crate `initialize/mod.rs::ensure_alert_rule_tables`
//! 幂等兜底（启动不跑 Migrator::up），兜底直接引用本文件导出的单一事实源
//! （建表 SQL / 索引 / 菜单种子），漂移在物理上不可能。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261003_000003_alert_rule"
    }
}

// ==================== 单一事实源（迁移 up 与 initialize 兜底共用） ====================
//
// 幂等前缀（INSERT OR IGNORE / ON CONFLICT / IGNORE）与索引存在性容错是执行机制
// 而非 SQL 内容，由两侧各自的执行器负责（迁移：execute_idempotent_insert /
// 方言分支；兜底：flow_insert / ensure_tenant_index）。

/// 告警规则索引（迁移与兜底共用）
///
/// 元组：(索引名, 表名, 列清单, 是否唯一)。MySQL 不支持 CREATE INDEX IF NOT EXISTS：
/// 迁移侧新表场景直接建（失败上抛真实错误）；兜底侧经 ensure_tenant_index
/// 先查 information_schema 判存在。
pub const ALERT_INDEXES: &[(&str, &str, &str, bool)] =
    &[("idx_alert_rule_enabled", "sys_alert_rule", "enabled", false)];

/// 告警菜单种子列清单（迁移与兜底共用）
pub const ALERT_MENU_COLS: &str = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag)";

/// 告警菜单种子行类型：(menu_id, menu_name, parent_id, order_num, path, component,
/// menu_type, perms, icon, remark)
pub type AlertMenuRow = (
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

/// 告警菜单种子行（结构化元组，迁移与兜底共用）
///
/// C 页面 4110 挂「系统监控」目录（menu_id=2）；F 按钮 4111-4114 挂页面下。
pub const ALERT_MENU_ROWS: &[AlertMenuRow] = &[
    (
        4110,
        "告警规则",
        2,
        60,
        "alert",
        "monitor/alert/index",
        "C",
        "monitor:alert:list",
        "alert",
        "告警规则引擎菜单",
    ),
    (
        4111,
        "告警查询",
        4110,
        1,
        "#",
        "",
        "F",
        "monitor:alert:query",
        "#",
        "",
    ),
    (
        4112,
        "告警新增",
        4110,
        1,
        "#",
        "",
        "F",
        "monitor:alert:add",
        "#",
        "",
    ),
    (
        4113,
        "告警修改",
        4110,
        1,
        "#",
        "",
        "F",
        "monitor:alert:edit",
        "#",
        "",
    ),
    (
        4114,
        "告警删除",
        4110,
        1,
        "#",
        "",
        "F",
        "monitor:alert:remove",
        "#",
        "",
    ),
];

/// 页面角色关联（role_id=2 common 角色；仅 C 页面授予，F 按钮不授予——与迁移原行为一致）
pub const ALERT_MENU_ROLE_GRANTS: &[(i64, i64)] = &[(2, 4110)];

/// 三方言建表 SQL（迁移 up 与 initialize 兜底共用单一来源）
///
/// `id` 自增主键 / `threshold` 浮点 / 时间列按方言声明。
pub fn create_table_sql(backend: sea_orm_migration::sea_orm::DatabaseBackend) -> String {
    use sea_orm_migration::sea_orm::DatabaseBackend;
    let table_sql = match backend {
        DatabaseBackend::Sqlite => {
            r#"CREATE TABLE IF NOT EXISTS sys_alert_rule (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                name               VARCHAR(64) NOT NULL,
                metric             VARCHAR(64) NOT NULL,
                comparator         VARCHAR(2) NOT NULL,
                threshold          DOUBLE NOT NULL,
                silent_minutes     INT NOT NULL DEFAULT 30,
                notify_channel_id  BIGINT,
                notify_template_id BIGINT,
                enabled            CHAR(1) DEFAULT '1',
                last_fired_at      DATETIME,
                created_at         DATETIME,
                updated_at         DATETIME
            )"#
        }
        DatabaseBackend::Postgres => {
            r#"CREATE TABLE IF NOT EXISTS sys_alert_rule (
                id                 BIGSERIAL PRIMARY KEY,
                name               VARCHAR(64) NOT NULL,
                metric             VARCHAR(64) NOT NULL,
                comparator         VARCHAR(2) NOT NULL,
                threshold          DOUBLE PRECISION NOT NULL,
                silent_minutes     INT NOT NULL DEFAULT 30,
                notify_channel_id  BIGINT,
                notify_template_id BIGINT,
                enabled            CHAR(1) DEFAULT '1',
                last_fired_at      TIMESTAMP,
                created_at         TIMESTAMP,
                updated_at         TIMESTAMP
            )"#
        }
        DatabaseBackend::MySql => {
            r#"CREATE TABLE IF NOT EXISTS sys_alert_rule (
                id                 BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                name               VARCHAR(64) NOT NULL,
                metric             VARCHAR(64) NOT NULL,
                comparator         VARCHAR(2) NOT NULL,
                threshold          DOUBLE NOT NULL,
                silent_minutes     INT NOT NULL DEFAULT 30,
                notify_channel_id  BIGINT NULL,
                notify_template_id BIGINT NULL,
                enabled            CHAR(1) DEFAULT '1',
                last_fired_at      DATETIME NULL,
                created_at         DATETIME,
                updated_at         DATETIME
            )"#
        }
        _ => unreachable!("unknown backend"),
    };
    table_sql.to_string()
}

/// 告警菜单种子 INSERT 语句体（不含幂等前缀——迁移 execute_idempotent_insert /
/// 兜底 flow_insert 各自拼接，语义等价）
///
/// 返回顺序与原迁移/兜底写库顺序一致：页面 4110 → role_menu(2,4110) → 按钮 4111-4114。
pub fn alert_menu_seed_bodies(now_expr: &str) -> Vec<String> {
    let mut bodies = Vec::with_capacity(ALERT_MENU_ROWS.len() + ALERT_MENU_ROLE_GRANTS.len());
    for (menu_id, name, parent_id, order_num, path, component, menu_type, perms, icon, remark) in
        ALERT_MENU_ROWS
    {
        bodies.push(format!(
            "{ALERT_MENU_COLS} VALUES \
            ({menu_id}, '{name}', {parent_id}, {order_num}, '{path}', '{component}', '', '', '1', '0', '{menu_type}', '0', '0', '{perms}', '{icon}', 'admin', {now_expr}, '{remark}', '0')"
        ));
        // 页面行后紧跟角色关联（F 按钮不授予——与原迁移/兜底行为一致）
        if *menu_type == "C" {
            for (role_id, granted_menu_id) in ALERT_MENU_ROLE_GRANTS {
                if *granted_menu_id == *menu_id {
                    bodies.push(format!(
                        "sys_role_menu (role_id, menu_id) VALUES ({role_id}, {granted_menu_id})"
                    ));
                }
            }
        }
    }
    bodies
}

/// 判断当前数据库方言（建表 DDL 三分支复用）
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite
    )
}

fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

/// 当前时间表达式（跨数据库兼容；SQLite 无 NOW()，落库时取本地时间字面量）
fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
    } else {
        "NOW()".to_string()
    }
}

/// 幂等 INSERT（SQLite: INSERT OR IGNORE / PG: ON CONFLICT DO NOTHING / MySQL: INSERT IGNORE）
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        format!("INSERT OR IGNORE INTO {body}")
    } else if is_postgres(manager) {
        format!("INSERT INTO {body} ON CONFLICT DO NOTHING")
    } else {
        format!("INSERT IGNORE INTO {body}")
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表（单一事实源，三方言分支收敛于 create_table_sql） ====================
        let backend = manager.get_connection().get_database_backend();
        manager
            .get_connection()
            .execute_unprepared(&create_table_sql(backend))
            .await?;

        // ==================== 2. 索引（单一事实源） ====================
        // MySQL 不支持 CREATE INDEX IF NOT EXISTS：新表场景不可能已存在同名索引，
        // 且迁移仅对全新库执行一次，直接创建即可（失败上抛真实错误）。
        for (idx_name, table, cols, _unique) in ALERT_INDEXES {
            if is_postgres(manager) || is_sqlite(manager) {
                manager
                    .get_connection()
                    .execute_unprepared(&format!(
                        "CREATE INDEX IF NOT EXISTS {idx_name} ON {table} ({cols})"
                    ))
                    .await?;
            } else {
                manager
                    .get_connection()
                    .execute_unprepared(&format!("CREATE INDEX {idx_name} ON {table} ({cols})"))
                    .await?;
            }
        }

        // ==================== 3. 菜单元数据（单一事实源） ====================
        // 「系统监控」目录 menu_id=2（path='monitor'）下新增页面 + 按钮权限，
        // 页面对前端路由 /monitor/alert，按钮 perms 与后端 PERM_ROUTE_TABLE 对齐
        // （契约测试 integration_tests/menu_perm_contract.rs 保证二者不漂移）。
        let now = now_expr(manager);
        for body in alert_menu_seed_bodies(&now) {
            execute_idempotent_insert(manager, &body).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 菜单 id 从种子行单一事实源推导（4110-4114）
        let menu_ids = ALERT_MENU_ROWS
            .iter()
            .map(|(id, ..)| id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        // 先删菜单种子，再删角色关联（页面），最后删表
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_role_menu WHERE menu_id IN ({menu_ids})"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_menu WHERE menu_id IN ({menu_ids})"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_alert_rule")
            .await?;
        Ok(())
    }
}
