// axum-backend/migration/src/m20260926_000006_platform_only_prefix_full.rs
//! 台账 §8.7-B / 2026-09-26 复核缺陷修复：**按完整平台专属前缀清单全量剔除菜单**。
//!
//! ## 缺陷（本轮复核实证）
//!
//! `m20260926_000002` 用**硬编码菜单 ID**（`[113,114,3021,3022,3023,116,1055]`）覆盖
//! `tool:gen:` / `monitor:cache:` 两类；`m20260926_000005` 按前缀动态匹配但数组只含
//! 本批新增的 5 项。两份清单**都不含 `system:tenant:domain:`**，而该前缀对应菜单
//! 3800（域名查询）/ 3802（域名验证）由 `m20260925_000002` 授予了平台普通角色
//! （`sys_role_menu (2, 3800)` / `(2, 3802)`）⇒ **新库（走 Migrator 的库）中平台普通
//! 角色仍持有域名管理菜单**，形成"菜单可见但请求一律 403"的假入口（违反原则 B）。
//!
//! 存量库反而无此问题——`initialize::ensure_tenant_role_menu_governance` 按
//! `PLATFORM_ONLY_PERM_PREFIXES` **动态** LIKE 剔除，天然覆盖全部 8 项。缺口仅在
//! "新库走迁移"这一条路径 ⇒ 本迁移补齐，使两条路径语义一致。
//!
//! ## 口径
//!
//! 本迁移的清单**必须**与 `src/common/tenant.rs::PLATFORM_ONLY_PERM_PREFIXES` 一致，
//! 由单元测试 `platform_only_prefixes_match_migration_lists`（`common/tenant.rs`）
//! 以 `include_str!` 编译期嵌入本源码做双向断言，防止再次只改一处。
//!
//! 幂等：DELETE 天然幂等（重复执行 0 行）；与 m000002 / m000005 叠加执行结果一致。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000006_platform_only_prefix_full"
    }
}

/// 与 `common::tenant::PLATFORM_ONLY_PERM_PREFIXES` **逐项一致**（8 项）。
///
/// 迁移 crate 无法引用 `src` 常量（独立 crate），故此处显式列出并由单测保双向一致。
/// 新增平台专属前缀时必须同时改三处：`common/tenant.rs` 常量、本数组、
/// `initialize::ensure_tenant_role_menu_governance`（该处按常量动态，无需改）。
const PLATFORM_ONLY_PERM_PREFIXES: &[&str] = &[
    "system:tenant:domain:",
    "tool:gen:",
    "tool:httpDebug:",
    "monitor:cache:",
    "monitor:log:",
    "monitor:slowSql:",
    "monitor:health:",
    "system:backup:",
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

        // ① 平台普通角色（role_id=2）剔除：补齐 m000002 未覆盖的 system:tenant:domain: 等
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
