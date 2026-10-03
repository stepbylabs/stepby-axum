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
//! 迁移负责全新库；存量库由主 crate `service/sys_alert_service.rs::ensure_alert_rule_table`
//! 幂等兜底（启动不跑 Migrator::up），两处 DDL 语义一致。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261003_000003_alert_rule"
    }
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
        format!(
            "'{}'",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        )
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
    manager
        .get_connection()
        .execute_unprepared(&sql)
        .await?;
    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表（三方言分支） ====================
        let table_sql = if is_sqlite(manager) {
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
        } else if is_postgres(manager) {
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
        } else {
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
        };
        manager
            .get_connection()
            .execute_unprepared(table_sql)
            .await?;

        // ==================== 2. 索引（enabled 过滤评估轮询用） ====================
        // MySQL 不支持 CREATE INDEX IF NOT EXISTS：新表场景不可能已存在同名索引，
        // 且迁移仅对全新库执行一次，直接创建即可（失败上抛真实错误）。
        if is_postgres(manager) || is_sqlite(manager) {
            manager
                .get_connection()
                .execute_unprepared(
                    "CREATE INDEX IF NOT EXISTS idx_alert_rule_enabled ON sys_alert_rule (enabled)",
                )
                .await?;
        } else {
            manager
                .get_connection()
                .execute_unprepared(
                    "CREATE INDEX idx_alert_rule_enabled ON sys_alert_rule (enabled)",
                )
                .await?;
        }

        // ==================== 3. 菜单元数据 ====================
        // 「系统监控」目录 menu_id=2（path='monitor'）下新增页面 + 按钮权限，
        // 页面对前端路由 /monitor/alert，按钮 perms 与后端 PERM_ROUTE_TABLE 对齐
        // （契约测试 integration_tests/menu_perm_contract.rs 保证二者不漂移）。
        let now = now_expr(manager);

        // 3.1 C 页面「告警规则」menu_id=4110
        let page_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (4110, '告警规则', 2, 60, 'alert', 'monitor/alert/index', '', '', '1', '0', 'C', '0', '0', 'monitor:alert:list', 'alert', 'admin', {now}, '告警规则引擎菜单', '0')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;
        // 页面对通用角色 role_id=2 可见（与消息模块 140 同口径）
        execute_idempotent_insert(
            manager,
            "sys_role_menu (role_id, menu_id) VALUES (2, 4110)",
        )
        .await?;

        // 3.2 F 按钮权限（4111-4114：query/add/edit/remove）
        let buttons: &[(&str, i64, &str)] = &[
            ("告警查询", 4111, "monitor:alert:query"),
            ("告警新增", 4112, "monitor:alert:add"),
            ("告警修改", 4113, "monitor:alert:edit"),
            ("告警删除", 4114, "monitor:alert:remove"),
        ];
        for (name, menu_id, perms) in buttons {
            let sql = format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                ({menu_id}, '{name}', 4110, 1, '#', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '#', 'admin', {now}, '', '0')"
            );
            execute_idempotent_insert(manager, &sql).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 先删菜单种子（按钮依赖页面），再删页面，最后删表
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 4110")
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_menu WHERE menu_id BETWEEN 4110 AND 4114",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_alert_rule")
            .await?;
        Ok(())
    }
}
