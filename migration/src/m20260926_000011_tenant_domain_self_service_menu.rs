// axum-backend/migration/src/m20260926_000011_tenant_domain_self_service_menu.rs
//! 批次 1c：**租户自助域名管理**页面菜单（能力位 `tenant.domain_self_service` 的③层入口）。
//!
//! ## 为什么需要独立页面
//!
//! 现有的域名管理入口是**租户管理页（3700）里的抽屉**（`TenantDomainDrawer.vue`），
//! 3800-3804 五个按钮菜单挂在 3700 之下。租户管理员看不到 3700（租户列表是平台专属），
//! 因此能力位开启后**租户侧没有任何可达入口** ⇒ 只有后端权限而无页面 = 假功能。
//!
//! 故按 `menu-id-registry.md` 的「新增大模块 3900 起」段位新增一组自包含菜单：
//!   - C 页面 3900「我的域名」（顶层菜单，`system/tenant/domain/index`）
//!   - F 按钮 3901 新增 / 3902 验证 / 3903 修改 / 3904 删除
//!
//! ## 授予约定
//!
//! **默认不授予任何角色**（能力位默认 `off` = 现状）。平台开启能力位后，
//! `initialize::ensure_tenant_role_menu_governance` 的 ①' 回填步骤会把它们授予
//! **平台普通角色（role_id=2）**——role 2 是"新建租户默认管理员角色"的菜单模板，
//! 使新建租户自动获得租户自助页面；存量租户由管理员按需授予。
//!
//! 关闭能力位时，同一步骤的 ① 会把这些授权收回（关闭态即安全态）。
//!
//! 与 `initialize::ensure_domain_self_service_menu` **双写保持一致**（存量库不跑
//! Migrator::up，两处清单必须双写；R4 为回归门禁）。

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

/// 菜单段位（`menu-id-registry.md` §下一个可用段位「新增大模块 3900 起」）
pub const MENU_ID_PAGE: i64 = 3900;
/// 按钮段位：3901 新增 / 3902 验证 / 3903 修改 / 3904 删除
pub const MENU_ID_BUTTONS: [i64; 4] = [3901, 3902, 3903, 3904];

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000011_tenant_domain_self_service_menu"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);
        let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";

        // C 页面「我的域名」（顶层菜单：租户无需也不应持有平台目录节点的授权）
        let page_sql = format!(
            "{menu_cols} VALUES \
            (3900, '我的域名', 0, 90, 'my-domain', 'system/tenant/domain/index', '', '', '1', '0', 'C', '0', '0', 'system:tenant:domain:list', 'link', 'admin', {now}, '租户自助域名管理（需能力位 tenant.domain_self_service）', '0', 'menu.myDomain')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;

        // F 按钮权限（关联页面 3900）；**不授予任何角色**（能力位默认关闭）
        let btn_rows: &[(i64, &str, i64, &str)] = &[
            (3901, "域名新增", 1, "system:tenant:domain:add"),
            (3902, "域名验证", 2, "system:tenant:domain:verify"),
            (3903, "域名修改", 3, "system:tenant:domain:edit"),
            (3904, "域名删除", 4, "system:tenant:domain:remove"),
        ];
        for (menu_id, name, order_num, perms) in btn_rows {
            let sql = format!(
                "{menu_cols} VALUES \
                ({menu_id}, '{name}', 3900, {order_num}, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '#', 'admin', {now}, '', '0', NULL)"
            );
            execute_idempotent_insert(manager, &sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(&format!(
            "DELETE FROM sys_role_menu WHERE menu_id IN ({})",
            std::iter::once(MENU_ID_PAGE)
                .chain(MENU_ID_BUTTONS)
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .await?;
        conn.execute_unprepared(
            "DELETE FROM sys_menu WHERE menu_id IN (3900, 3901, 3902, 3903, 3904)",
        )
        .await?;
        Ok(())
    }
}
