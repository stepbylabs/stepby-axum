// axum-backend/migration/src/m20260722_000003_sys_rate_limit.rs
//! API 限流配置表迁移
//!
//! 新增表：sys_rate_limit - 路由前缀限流配置
//!
//! 字段说明：
//! - id: 主键自增
//! - route_pattern: 路由前缀（"*" 表示全局默认，如 /system/user、/login）
//! - capacity: 桶容量（突发请求上限）
//! - refill_per_second: 每秒补充令牌数
//! - enabled: 是否启用（默认 true）
//! - description: 描述
//! - create_by / create_time / update_by / update_time: 审计字段
//!
//! 同时新增菜单：
//! - menu_id=121 限流配置（系统管理目录下，parent_id=1）路径 system/rateLimit
//! - 5 个按钮权限（query/add/edit/remove/export）
//!
//! 数据库兼容性说明：
//! - MySQL/PostgreSQL：使用 BOOLEAN 类型
//! - SQLite：BOOLEAN 类型实际存储为 INTEGER（0/1），SeaORM 自动转换

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

impl sea_orm_migration::MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260722_000003_sys_rate_limit"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let sql = if is_sqlite(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_rate_limit (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                route_pattern       VARCHAR(200) NOT NULL,
                capacity            INTEGER NOT NULL DEFAULT 100,
                refill_per_second   DOUBLE NOT NULL DEFAULT 10.0,
                enabled             BOOLEAN NOT NULL DEFAULT TRUE,
                description         VARCHAR(500),
                create_by           VARCHAR(64),
                create_time         DATETIME,
                update_by           VARCHAR(64),
                update_time         DATETIME
            )"#
            .to_string()
        } else if is_postgres(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_rate_limit (
                id                  BIGSERIAL PRIMARY KEY,
                route_pattern       VARCHAR(200) NOT NULL,
                capacity            INTEGER NOT NULL DEFAULT 100,
                refill_per_second   DOUBLE PRECISION NOT NULL DEFAULT 10.0,
                enabled             BOOLEAN NOT NULL DEFAULT TRUE,
                description         VARCHAR(500),
                create_by           VARCHAR(64),
                create_time         TIMESTAMP,
                update_by           VARCHAR(64),
                update_time         TIMESTAMP
            )"#
            .to_string()
        } else {
            r#"CREATE TABLE IF NOT EXISTS sys_rate_limit (
                id                  BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                route_pattern       VARCHAR(200) NOT NULL,
                capacity            INTEGER NOT NULL DEFAULT 100,
                refill_per_second   DOUBLE NOT NULL DEFAULT 10.0,
                enabled             BOOLEAN NOT NULL DEFAULT TRUE,
                description         VARCHAR(500),
                create_by           VARCHAR(64),
                create_time         DATETIME,
                update_by           VARCHAR(64),
                update_time         DATETIME
            )"#
            .to_string()
        };

        manager.get_connection().execute_unprepared(&sql).await?;

        // route_pattern 唯一索引
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_sys_rate_limit_route_pattern ON sys_rate_limit (route_pattern)",
            )
            .await?;
        // enabled 索引（中间件查询启用配置时使用）
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX IF NOT EXISTS idx_sys_rate_limit_enabled ON sys_rate_limit (enabled)",
            )
            .await?;

        let now = now_expr(manager);

        // 插入默认全局配置（route_pattern='*'）
        let default_sql = format!(
            "sys_rate_limit (route_pattern, capacity, refill_per_second, enabled, description, create_by, create_time, update_by, update_time) VALUES \
            ('*', 100, 10.0, TRUE, '全局默认', 'admin', {now}, 'admin', {now})"
        );
        execute_idempotent_insert(manager, &default_sql).await?;

        // 1 个 C 类型菜单（页面）
        let menus_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (121, '限流配置', 1, 12, 'rateLimit', 'system/rateLimit/index', '', '', '1', '0', 'C', '0', '0', 'system:rateLimit:list', 'guide', 'admin', {now}, 'API 限流配置菜单', '0')"
        );
        execute_idempotent_insert(manager, &menus_sql).await?;

        // 5 个 F 类型按钮权限
        let buttons_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (1206, '限流查询', 121, 1, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:rateLimit:query', '#', 'admin', {now}, '', '0'), \
            (1207, '限流新增', 121, 2, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:rateLimit:add', '#', 'admin', {now}, '', '0'), \
            (1208, '限流修改', 121, 3, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:rateLimit:edit', '#', 'admin', {now}, '', '0'), \
            (1209, '限流删除', 121, 4, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:rateLimit:remove', '#', 'admin', {now}, '', '0'), \
            (1210, '限流导出', 121, 5, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:rateLimit:export', '#', 'admin', {now}, '', '0')"
        );
        execute_idempotent_insert(manager, &buttons_sql).await?;

        // 为普通角色 role_id=2 关联新增的 6 个菜单（超管通过 *:*:* 通配符访问，无需显式关联）
        let role_menu_sql = "sys_role_menu (role_id, menu_id) VALUES \
            (2, 121), (2, 1206), (2, 1207), (2, 1208), (2, 1209), (2, 1210)"
            .to_string();
        execute_idempotent_insert(manager, &role_menu_sql).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除 role_menu 关联
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_role_menu WHERE menu_id IN (121, 1206, 1207, 1208, 1209, 1210)",
            )
            .await?;
        // 删除菜单
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_menu WHERE menu_id IN (121, 1206, 1207, 1208, 1209, 1210)",
            )
            .await?;
        // 删除限流配置表
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_rate_limit")
            .await?;
        Ok(())
    }
}
