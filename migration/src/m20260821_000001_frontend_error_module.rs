// axum-backend/migration/src/m20260821_000001_frontend_error_module.rs
//! 前端异常与性能监控模块迁移（Tier-S #1）
//!
//! 新增一张表 `sys_frontend_error`（跨 sqlite/postgres/mysql 兼容，参考 m20260820_000002_web_hook_module）：
//!   统一承载「前端运行时异常」（Vue 错误 / 全局错误 / 未捕获 Promise / 资源加载失败 / 接口异常）
//!   与「Web Vitals 性能指标」（LCP / CLS / INP / FCP / TTFB）两类可观测数据。
//!   - level：error / warning / info（vitals 一般为 info）
//!   - source：vue / global / rejection / resource / api / vital / other
//!   - value：性能指标数值（秒/像素等，errors 为 NULL）
//!
//! 然后插入菜单元数据（前置约定：系统监控目录 parent_id=2）：
//!   - C 页面「前端异常」(menu_id=160, path=frontendError, component=monitor/frontendError/index,
//!     perms=monitor:frontendError:list)
//!   - F 按钮「异常删除」(menu_id=1061, perms=monitor:frontendError:remove)，
//!     10xx 段沿用 operlog 家族按钮约定，远离 sys_menu 种子最大 ID 3551，
//!     避免与 E2E 用例动态创建的 `MAX+1` 测试菜单（3552+）发生主键冲突
//!   - role_menu 关联 role_id=2
//!
//! 幂等：全部走 execute_idempotent_insert（INSERT OR IGNORE / ON CONFLICT DO NOTHING）。

use sea_orm_migration::prelude::*;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(backend, sea_orm_migration::sea_orm::DatabaseBackend::Sqlite)
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(
        backend,
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
        "m20260821_000001_frontend_error_module"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表 ====================
        up_create_table(manager).await?;

        // ==================== 2. 菜单元数据 ====================
        let now = now_expr(manager);

        // 2.1 C 页面「前端异常」（parent_id=2 系统监控目录，order_num=11 排在运行监控之后）
        let page_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (160, '前端异常', 2, 11, 'frontendError', 'monitor/frontendError/index', '', '', '1', '0', 'C', '0', '0', 'monitor:frontendError:list', 'warning', 'admin', {now}, '前端运行时异常 + Web Vitals 性能监控', '0')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 160)")
            .await?;

        // 2.2 F 按钮「异常删除」（menu_id=1061，10xx 段远离种子最大 ID 与 E2E 动态菜单）
        let btn_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (1061, '异常删除', 160, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'monitor:frontendError:remove', '#', 'admin', {now}, '', '0')"
        );
        execute_idempotent_insert(manager, &btn_sql).await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 1061)")
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for id in [160, 1061] {
            manager
                .get_connection()
                .execute_unprepared(&format!("DELETE FROM sys_role_menu WHERE menu_id = {}", id))
                .await?;
            manager
                .get_connection()
                .execute_unprepared(&format!("DELETE FROM sys_menu WHERE menu_id = {}", id))
                .await?;
        }
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_frontend_error")
            .await?;
        Ok(())
    }
}

/// 建表（跨库兼容）
async fn up_create_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_frontend_error (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            level       VARCHAR(16) NOT NULL,
            source      VARCHAR(32) NOT NULL,
            name        VARCHAR(255),
            message     TEXT,
            stack       TEXT,
            page_url    VARCHAR(1000),
            user_agent  VARCHAR(512),
            view_width  INTEGER,
            view_height INTEGER,
            value       REAL,
            user_name   VARCHAR(64),
            create_time DATETIME
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_frontend_error (
            id          BIGSERIAL PRIMARY KEY,
            level       VARCHAR(16) NOT NULL,
            source      VARCHAR(32) NOT NULL,
            name        VARCHAR(255),
            message     TEXT,
            stack       TEXT,
            page_url    VARCHAR(1000),
            user_agent  VARCHAR(512),
            view_width  INTEGER,
            view_height INTEGER,
            value       DOUBLE PRECISION,
            user_name   VARCHAR(64),
            create_time TIMESTAMP
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_frontend_error (
            id          BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            level       VARCHAR(16) NOT NULL,
            source      VARCHAR(32) NOT NULL,
            name        VARCHAR(255),
            message     TEXT,
            stack       TEXT,
            page_url    VARCHAR(1000),
            user_agent  VARCHAR(512),
            view_width  INT,
            view_height INT,
            value       DOUBLE,
            user_name   VARCHAR(64),
            create_time DATETIME
        )"#
    };
    manager.get_connection().execute_unprepared(sql).await?;

    // 索引：按时间清理 / 列表倒序，按 level+source 聚合筛选
    manager
        .get_connection()
        .execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_fe_created ON sys_frontend_error (create_time)",
        )
        .await?;
    manager
        .get_connection()
        .execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_fe_level_source ON sys_frontend_error (level, source)",
        )
        .await?;

    Ok(())
}
