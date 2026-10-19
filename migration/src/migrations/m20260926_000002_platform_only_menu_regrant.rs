// stepby-axum/migration/src/migrations/m20260926_000002_platform_only_menu_regrant.rs
//! 台账 F-4 / F-5（原则 B）：平台专属能力菜单退出租户与平台普通角色可授集合。
//!
//! 背景（`docs/optimization/multitenant-pending-items-ledger-2026-09-25.md` §1.2）：
//! - 菜单 116「代码生成」+ 1055「生成查询」被 `m20260924_000010` 的只读白名单保底授予
//!   平台普通角色（role_id=2）⇒ 租户管理员实得 `tool:gen:list/:query`，可
//!   `GET /tool/gen/db/list` **枚举全库表名**（跨租户信息泄漏）；
//! - 菜单 113/114/3021（`monitor:cache:list/:query`）同理 ⇒ 跨租户缓存可观测面。
//!
//! 目标状态（声明式）：平台专属 perms 前缀（`tool:gen:` / `monitor:cache:`）对应菜单
//! **不进租户可授集合**，也不默认授予平台普通角色：
//!   ① role_id=2（平台普通角色）剔除；
//!   ② 存量租户自建角色（sys_role.tenant_id <> 0）剔除——它们在初始化时复制了
//!      平台普通角色菜单，会残留"菜单可见但请求 403"的假入口。
//! 平台超管（role_id=1）不受影响；服务层另有平台守卫兜底（handler 层 tid≠0 → 403）。
//!
//! 存量库兜底：`initialize::ensure_tenant_role_menu_governance`（同一剔除逻辑已并入）。
//! 幂等：DELETE 天然幂等；重复执行结果一致。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000002_platform_only_menu_regrant"
    }
}

/// 平台专属菜单 ID（按 perms 语义取自 sys_menu，见 m20250711_000001_init 与
/// m20260802_000004_add_missing_button_perms）：
/// - 113/114 缓存监控页面与列表（monitor:cache:list）
/// - 3021/3022/3023 缓存查询与清理按钮（monitor:cache:query/clearName/clearKey）
/// - 116 代码生成页面（tool:gen:list）、1055 生成查询按钮（tool:gen:query）
const PLATFORM_ONLY_MENU_IDS: &[i64] = &[113, 114, 3021, 3022, 3023, 116, 1055];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let id_list = PLATFORM_ONLY_MENU_IDS
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // ① 平台普通角色（role_id=2）剔除
        conn.execute_unprepared(&format!(
            "DELETE FROM sys_role_menu WHERE role_id = 2 AND menu_id IN ({id_list})"
        ))
        .await?;

        // ② 存量租户自建角色剔除（按角色归属租户判定，不依赖 role_id 白名单）
        conn.execute_unprepared(&format!(
            r#"DELETE FROM sys_role_menu WHERE menu_id IN ({id_list})
               AND role_id IN (SELECT role_id FROM sys_role WHERE tenant_id <> 0)"#
        ))
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚 = 恢复"平台普通角色默认持有"的语义（仅重插 sys_menu 中仍存在的菜单项）
        let conn = manager.get_connection();
        let id_list = PLATFORM_ONLY_MENU_IDS
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute_unprepared(&format!(
            r#"INSERT INTO sys_role_menu (role_id, menu_id)
               SELECT 2, menu_id FROM sys_menu WHERE menu_id IN ({id_list})
                 AND del_flag = '0'
                 AND menu_id NOT IN (SELECT menu_id FROM sys_role_menu WHERE role_id = 2)"#
        ))
        .await?;
        Ok(())
    }
}
