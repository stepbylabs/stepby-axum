// stepby-axum/migration/src/m20260724_000001_ip_location_menus.rs
//! 第九次迁移：新增 IP 归属地库管理菜单和按钮权限
//!
//! 背景：
//! - 后端 ip_location_service + handler + router 已实现 IP 库管理功能
//! - 接口路径：/system/ipLocation/{status,config,update,reload}
//! - 权限标识：monitor:iplocation:{list,edit}
//! - 前端页面路径：monitor/ip-location/index
//!
//! menu_id 规划：
//! - 118-121 已被前序迁移占用（备份/任务/审计/限流）
//! - 1200-1211 已被前序迁移占用（按钮权限）
//! - 1212 已被本迁移的早期错误版本插入（parent_id 指向 121 限流配置，孤儿）
//!
//! 本迁移使用：
//! - menu_id=122 IP 库管理（C 类型菜单，parent_id=2 系统监控目录）
//! - menu_id=1213 IP 库更新（F 类型按钮，parent_id=122）
//!
//! 同时清理 1212 孤儿数据（如存在），保证幂等性。
//!
//! 超管通过 *:*:* 通配符访问，无需显式关联。

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
        "m20260724_000001_ip_location_menus"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);

        // 0. 清理早期错误版本残留的 menu_id=1212 孤儿数据（parent_id 误指向 121 限流配置）
        //    使用 DELETE 而非幂等 INSERT，确保结构正确
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_role_menu WHERE menu_id = 1212 AND menu_id NOT IN (SELECT menu_id FROM sys_menu WHERE menu_id = 1212 AND perms = 'monitor:iplocation:edit' AND parent_id = 122)",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id = 1212 AND parent_id != 122")
            .await?;

        // 1. C 类型菜单（页面）：IP 库管理
        //    parent_id=2 (系统监控目录)
        //    order_num=8（在审计大屏 order_num=7 之后）
        //    perms=monitor:iplocation:list（permission.rs 中 GET 接口映射到此权限）
        let menu_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (122, 'IP 库管理', 2, 8, 'ip-location', 'monitor/ip-location/index', '', '', '1', '0', 'C', '0', '0', 'monitor:iplocation:list', 'ip', 'admin', {now}, 'IP 归属地库管理菜单（下载/更新/热加载）', '0')"
        );
        execute_idempotent_insert(manager, &menu_sql).await?;

        // 2. F 类型按钮权限：IP 库更新/保存配置/热加载
        let button_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (1213, 'IP 库更新', 122, 1, '#', '', '', '', '1', '0', 'F', '0', '0', 'monitor:iplocation:edit', '#', 'admin', {now}, 'IP 库下载/更新/热加载操作权限', '0')"
        );
        execute_idempotent_insert(manager, &button_sql).await?;

        // 3. sys_config 预置 4 个 IP 库管理配置项（默认值）
        //    注：license_key 和 account_id 默认为空（用户在后台保存后才会写入加密值）
        let config_sql = format!(
            "sys_config (config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
            ('IP 库更新源', 'ip_location.update_source', 'p3terx', 'Y', 'admin', {now}, 'maxmind=官方(需凭据) / p3terx=GitHub镜像(免凭据)'), \
            ('MaxMind Account ID(加密)', 'ip_location.maxmind_account_id', '', 'Y', 'admin', {now}, 'MaxMind 官方账户 ID（AES-256-GCM 加密存储）'), \
            ('MaxMind License Key(加密)', 'ip_location.maxmind_license_key', '', 'Y', 'admin', {now}, 'MaxMind 官方 License Key（AES-256-GCM 加密存储）'), \
            ('IP 库自动更新开关', 'ip_location.auto_update_enabled', 'false', 'Y', 'admin', {now}, '是否启用定时自动更新（true/false）')"
        );
        execute_idempotent_insert(manager, &config_sql).await?;

        // 4. 为普通角色 role_id=2 关联新菜单和按钮
        let role_menu_sql = "sys_role_menu (role_id, menu_id) VALUES (2, 122), (2, 1213)";
        execute_idempotent_insert(manager, role_menu_sql).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除 role_menu 关联
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id IN (122, 1213)")
            .await?;

        // 删除菜单
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id IN (122, 1213)")
            .await?;

        // 删除 sys_config 预置配置项
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_config WHERE config_key IN \
                ('ip_location.update_source', \
                'ip_location.maxmind_account_id', \
                'ip_location.maxmind_license_key', \
                'ip_location.auto_update_enabled')",
            )
            .await?;

        Ok(())
    }
}
