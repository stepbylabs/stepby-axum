// axum-backend/migration/src/m20260925_000002_tenant_module.rs
//! 多租户 Phase 2（立项实施）——租户管理模块菜单。
//!
//! 菜单：3700 段全新号（见 menu-id-registry.md：新增大模块 3700 起步进 100）。
//!   - C 页面 3700「租户管理」（挂系统管理目录 1，i18n_key 必填）
//!   - F 按钮 3701 查询 / 3702 新增 / 3703 修改 / 3704 删除
//!
//! role_menu：C 页面与 query 按钮关联 role_id=2（common 只读白名单语义：
//! common 角色可见页面，但 add/edit/remove 不授予）。
//!
//! 数据模型：**dept 树根 = 租户**（立项定案第 2 条），不建独立 sys_tenant 表；
//! 租户管理端点操作 sys_dept 中 parent_id=0 的顶层部门（dept_id=100 为平台根）。

use sea_orm_migration::prelude::*;

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
        "m20260925_000002_tenant_module"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);
        let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";

        // C 页面「租户管理」（挂系统管理目录 1）
        let page_sql = format!(
            "{menu_cols} VALUES \
            (3700, '租户管理', 1, 8, 'tenant', 'system/tenant/index', '', '', '1', '0', 'C', '0', '0', 'system:tenant:list', 'peoples', 'admin', {now}, '多租户管理（dept 树根=租户）', '0', 'menu.tenant')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;
        // common（role_id=2）只读白名单：C 页面自动可见
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 3700)")
            .await?;

        // F 按钮权限（关联页面 3700）
        let btn_rows: &[(i64, &str, &str)] = &[
            (3701, "租户查询", "system:tenant:query"),
            (3702, "租户新增", "system:tenant:add"),
            (3703, "租户修改", "system:tenant:edit"),
            (3704, "租户删除", "system:tenant:remove"),
        ];
        for (menu_id, name, perms) in btn_rows {
            let sql = format!(
                "{menu_cols} VALUES \
                ({menu_id}, '{name}', 3700, 1, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '#', 'admin', {now}, '', '0', NULL)"
            );
            execute_idempotent_insert(manager, &sql).await?;
        }
        // 仅 query 按钮授予 role_id=2（add/edit/remove 不授，保持只读语义）
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 3701)")
            .await?;

        // ---- 域名绑定（多租户 Phase 3 域名链路，menu_id 段位 3800-3804，父 3700）----
        // 与 AppInitializer 的 `ensure_multitenant_phase2` 双写保持一致（存量库启动不跑
        // Migrator::up，两处清单必须双写；R4 为回归门禁）。
        // 授予约定：查看（list）与验证（verify）授予平台普通角色（role_id=2），
        // 新增/修改/删除仅平台操作者（operator_tid=0）可用，故不授予普通角色。
        let domain_rows: &[(i64, &str, i64, &str)] = &[
            (3800, "域名查询", 5, "system:tenant:domain:list"),
            (3801, "域名新增", 6, "system:tenant:domain:add"),
            (3802, "域名验证", 7, "system:tenant:domain:verify"),
            (3803, "域名修改", 8, "system:tenant:domain:edit"),
            (3804, "域名删除", 9, "system:tenant:domain:remove"),
        ];
        for (menu_id, name, order_num, perms) in domain_rows {
            let sql = format!(
                "{menu_cols} VALUES \
                ({menu_id}, '{name}', 3700, {order_num}, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '#', 'admin', {now}, '', '0', NULL)"
            );
            execute_idempotent_insert(manager, &sql).await?;
        }
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 3800)")
            .await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 3802)")
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for menu_id in [3700, 3701, 3702, 3703, 3704, 3800, 3801, 3802, 3803, 3804] {
            conn.execute_unprepared(&format!(
                "DELETE FROM sys_role_menu WHERE menu_id = {menu_id}"
            ))
            .await?;
            conn.execute_unprepared(&format!("DELETE FROM sys_menu WHERE menu_id = {menu_id}"))
                .await?;
        }
        Ok(())
    }
}
