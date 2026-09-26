// axum-backend/migration/src/m20260926_000013_platform_only_tenant_menu.rs
//! 批次 3（MT-1）：**`system:tenantMenu:` 纳入平台专属前缀**并按完整清单剔除。
//!
//! ## 为什么必须登记为"平台专属前缀"
//!
//! `system:tenantMenu:`（L3 租户自建导航管理）功能**面向租户**，但必须经能力位 `nav.l3`
//! 才可下放。若不登记在本清单中，能力位**关闭**时已授予的菜单不会被启动治理 ① 收回
//! ⇒ 租户侧残留"菜单可见但请求一律 403"的**假入口**（违反 §29 硬约束）。
//!
//! 登记后：① 剔除（命中前缀且不在解锁清单内）+ ①' 回填（在解锁清单内）形成对称治理，
//! 关闭态自动收回、开启态按档位回填给平台普通角色（role_id=2）。
//!
//! ## 口径
//!
//! 与 `m20260926_000007_platform_only_ratelimit` 同款**按完整前缀清单**剔除（避免
//! m000002/m000005 那种"只列本批新增项导致漏剔"的问题）。清单必须与
//! `src/common/tenant.rs::PLATFORM_ONLY_PERM_PREFIXES` 逐项一致，由单测
//! `platform_only_prefixes_match_migration_lists` 编译期断言（指向**最新**全量迁移）。
//!
//! 注意：本迁移**不做能力位感知**（迁移期无能力位上下文）——它只保证"默认整面不下放"，
//! 开启态的回填由启动治理 ①' 负责。这与 m000007 的语义一致。
//!
//! 幂等：DELETE 天然幂等（重复执行 0 行）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000013_platform_only_tenant_menu"
    }
}

/// 与 `common::tenant::PLATFORM_ONLY_PERM_PREFIXES` **逐项一致**（10 项，含本批新增的
/// `system:tenantMenu:`）。迁移 crate 无法引用 `src` 常量，故显式列出并由单测保双向一致。
const PLATFORM_ONLY_PERM_PREFIXES: &[&str] = &[
    "system:tenant:domain:",
    "system:tenantMenu:",
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
        // 租户角色侧不回插——租户角色本不应持有未开启能力位的平台面菜单）
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
