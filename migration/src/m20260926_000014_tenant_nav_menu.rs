// stepby-axum/migration/src/m20260926_000014_tenant_nav_menu.rs
//! 批次 3（MT-1）：**租户自建导航 L3** 页面菜单（能力位 `nav.l3` 的③层入口）。
//!
//! ## 为什么需要独立页面
//!
//! L3 导航配置管理的是"本租户的导航结构"，入口必须落在租户可达的页面上（与批次 1c
//! 的「我的域名」同理）：平台侧租户管理页（3700）租户管理员看不到。
//!
//! 故按 `menu-id-registry.md` 的「新增 C/F 页面按钮（小模块）**3627 起**」段位新增：
//!   - C 页面 3627「导航设置」（顶层菜单，`system/tenant/nav/index`，perms `system:tenantMenu:list`）
//!   - F 按钮 3628 新增 / 3629 修改 / 3630 删除
//!
//! ## 授予约定
//!
//! **默认不授予任何角色**（能力位默认 `off` = 现状）。平台开启能力位后，
//! `initialize::ensure_tenant_role_menu_governance` 的 ①' 按 **perms 粒度**回填给
//! **平台普通角色（role_id=2）**：
//! - `view_only` ⇒ 只解锁 `system:tenantMenu:list` ⇒ 仅回填 3627（无写按钮，不造假入口）；
//! - `full` ⇒ 追加解锁 add/edit/remove ⇒ 一并回填 3628-3630。
//!
//! 关闭能力位时同一步骤的 ① 会把授权收回（关闭态即安全态）。
//!
//! 与 `initialize::ensure_tenant_nav_menu` **双写保持一致**（存量库不跑 Migrator::up，
//! 两处清单必须双写；R4 为回归门禁）。

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

/// 菜单段位（`menu-id-registry.md`「新增 C/F 页面按钮（小模块）3627 起」）
pub const MENU_ID_PAGE: i64 = 3627;
/// 按钮段位：3628 新增 / 3629 修改 / 3630 删除
pub const MENU_ID_BUTTONS: [i64; 3] = [3628, 3629, 3630];

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000014_tenant_nav_menu"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);
        let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";

        // C 页面「导航设置」（顶层菜单：租户无需也不应持有平台目录节点的授权）
        let page_sql = format!(
            "{menu_cols} VALUES \
            (3627, '导航设置', 0, 91, 'my-nav', 'system/tenant/nav/index', '', '', '1', '0', 'C', '0', '0', 'system:tenantMenu:list', 'tree-table', 'admin', {now}, '租户自建导航 L3 配置（需能力位 nav.l3）', '0', 'menu.myNav')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;

        // F 按钮权限（关联页面 3627）；**不授予任何角色**（能力位默认关闭）
        let btn_rows: &[(i64, &str, i64, &str)] = &[
            (3628, "导航新增", 1, "system:tenantMenu:add"),
            (3629, "导航修改", 2, "system:tenantMenu:edit"),
            (3630, "导航删除", 3, "system:tenantMenu:remove"),
        ];
        for (menu_id, name, order_num, perms) in btn_rows {
            let sql = format!(
                "{menu_cols} VALUES \
                ({menu_id}, '{name}', 3627, {order_num}, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '#', 'admin', {now}, '', '0', NULL)"
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
        conn.execute_unprepared("DELETE FROM sys_menu WHERE menu_id IN (3627, 3628, 3629, 3630)")
            .await?;
        Ok(())
    }
}
