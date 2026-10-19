// stepby-axum/migration/src/migrations/m20260926_000005_platform_only_prefix_governance.rs
//! 台账 P2-4（原则 B）：**新增平台专属前缀**对应菜单退出租户与平台普通角色可授集合。
//!
//! 与 `m20260926_000002_platform_only_menu_regrant`（覆盖 `tool:gen:` / `monitor:cache:`）
//! 互补：本迁移按 `sys_menu.perms` **前缀动态匹配**，覆盖本批新纳入的平台专属能力：
//!
//! - `tool:httpDebug:`  HTTP 调试器（服务端代理发起任意请求，SSRF 面）
//! - `monitor:log:`     实时日志（宿主应用日志，含全平台请求/SQL 日志）
//! - `monitor:slowSql:` 可观测性（慢请求/错误聚合、Redis 指标，跨租户宿主级观测面）
//! - `monitor:health:`  健康检查（DB/Redis/磁盘等宿主依赖状态，无租户语义）
//! - `system:backup:`   备份管理（整库 pg_dump/mysqldump；下载即全库数据，恢复会覆盖现库）
//!
//! 声明式目标：这些 perms 对应菜单**不进租户可授集合**，也不默认授予平台普通角色：
//!   ① role_id=2（平台普通角色）剔除；
//!   ② 存量租户自建角色（`sys_role.tenant_id <> 0`）剔除
//!      （租户初始化时复制了平台普通角色菜单，会残留"菜单可见但请求 403"的假入口）。
//! 平台超管（role_id=1）不受影响；请求层另有 `middleware::platform_guard::platform_only_guard`
//! 兜底（`/system/backup/*`、`/monitor/log/*`、`/monitor/slow-sql|error-log|redis/*`、
//! `/monitor/server`、`/tool/http-debug/*` 对租户操作者一律 403）。
//!
//! 存量库兜底：`initialize::ensure_tenant_role_menu_governance`（按
//! `PLATFORM_ONLY_PERM_PREFIXES` 动态剔除，已并入本批新前缀）。
//! 幂等：DELETE 天然幂等；重复执行结果一致。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000005_platform_only_prefix_governance"
    }
}

/// 本批新增的平台专属 perms 前缀（与 `common::tenant::PLATFORM_ONLY_PERM_PREFIXES` 中
/// 本批新增项一致；迁移 crate 无法引用 src 常量，故此处显式列出，由单测/审计器保双向一致）。
const PLATFORM_ONLY_PERM_PREFIXES: &[&str] = &[
    "tool:httpDebug:",
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
