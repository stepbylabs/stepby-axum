// stepby-axum/migration/src/m20260926_000007_platform_only_ratelimit.rs
//! 台账 2026-09-26 复核（原则 B）：**`system:rateLimit:` 收敛为平台专属**并按完整清单剔除。
//!
//! ## 缺陷
//!
//! `sys_rate_limit`（API 限流配置）**无 `tenant_id` 列**，且限流中间件在**租户解析之前**
//! 执行（`middleware/rate_limit.rs` 按 IP / 路由维度）⇒ 该配置**本质无租户维度**。
//! 但 `system:rateLimit:` 未列入平台专属前缀，且 `sys_rate_limit_router.rs` 未挂
//! `platform_only_guard` ⇒ **拥有该权限的租户操作者可改/删全平台限流规则**（含 `/login`
//! 登录爆破防护与 `*` 全局默认），并可通过导出面枚举全平台路由清单。
//!
//! ## 口径
//!
//! 与 `m20260926_000006` 同款**按完整前缀清单**剔除（避免 m000002/m000005 那种"只列本批
//! 新增项导致漏剔"的问题）。清单必须与 `src/common/tenant.rs::PLATFORM_ONLY_PERM_PREFIXES`
//! 逐项一致，由单测 `platform_only_prefixes_match_migration_lists` 编译期断言（指向**最新**
//! 全量迁移）。
//!
//! 幂等：DELETE 天然幂等（重复执行 0 行）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000007_platform_only_ratelimit"
    }
}

/// 与 `common::tenant::PLATFORM_ONLY_PERM_PREFIXES` **逐项一致**（9 项，含本批新增的
/// `system:rateLimit:`）。迁移 crate 无法引用 `src` 常量，故显式列出并由单测保双向一致。
const PLATFORM_ONLY_PERM_PREFIXES: &[&str] = &[
    "system:tenant:domain:",
    "tool:gen:",
    "tool:httpDebug:",
    "monitor:cache:",
    "monitor:log:",
    "monitor:slowSql:",
    "monitor:health:",
    "system:backup:",
    "system:rateLimit:",
];

/// 构造 `perms LIKE '<prefix>%' OR ...` 的条件片段（前缀均来自本文件常量，无注入面）
fn perms_like_clause() -> String {
    PLATFORM_ONLY_PERM_PREFIXES
        .iter()
        .map(|p| format!("perms LIKE '{p}%'"))
        .collect::<Vec<_>>()
        .join(" OR ")
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let clause = perms_like_clause();

        // ① 平台普通角色（role_id=2）剔除
        conn.execute_unprepared(&format!(
            "DELETE FROM sys_role_menu WHERE role_id = 2 AND menu_id IN \
             (SELECT menu_id FROM sys_menu WHERE del_flag = '0' AND ({clause}))"
        ))
        .await?;

        // ② 存量租户自建角色剔除（按角色归属租户判定，不依赖 role_id 白名单）
        conn.execute_unprepared(&format!(
            "DELETE FROM sys_role_menu WHERE menu_id IN \
             (SELECT menu_id FROM sys_menu WHERE del_flag = '0' AND ({clause})) \
             AND role_id IN (SELECT role_id FROM sys_role WHERE tenant_id <> 0)"
        ))
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚 = 恢复"平台普通角色默认持有"的语义（仅重插 sys_menu 中仍存在的菜单项；
        // 租户角色侧不回插——租户角色本不应持有平台专属能力）
        let conn = manager.get_connection();
        let clause = perms_like_clause();
        conn.execute_unprepared(&format!(
            "INSERT INTO sys_role_menu (role_id, menu_id) \
             SELECT 2, menu_id FROM sys_menu WHERE del_flag = '0' AND ({clause}) \
               AND menu_id NOT IN (SELECT menu_id FROM sys_role_menu WHERE role_id = 2)"
        ))
        .await?;
        Ok(())
    }
}
