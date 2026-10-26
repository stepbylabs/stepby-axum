// stepby-axum/migration/src/migrations/m20261017_000002_platform_only_alert.rs
//! 批七十四 B3：**`monitor:alert:` 纳入平台专属前缀**并按完整清单剔除。
//!
//! ## 为什么必须登记为"平台专属前缀"（真缺陷，非预防性改造）
//!
//! `src/router/monitor_alert_router.rs` 早已给整组 `/monitor/alert/*` 挂
//! `platform_only_guard` ⇒ 租户操作者（`tenant_id <> 0`）访问一律 403
//! `error.tenant.platform_only`（守卫 fail-closed，Claims 缺失同样 403）。
//! 但 `PLATFORM_ONLY_PERM_PREFIXES` 的 12 项里**没有** `monitor:alert:`，于是：
//!
//! 1. `is_grantable_perm` 判该族 perms"可授予"（判定顺序 `common/features.rs`：
//!    解锁清单 → 平台专属 → tier2）；
//! 2. `m20261003_000003_alert_rule.rs` 的 `ALERT_MENU_ROLE_GRANTS = [(2, 4110)]`
//!    把告警页面菜单发给平台普通角色 `common`（role_id=2）；
//! 3. `common` 是**新建租户默认管理员角色的菜单模板源**
//!    （`sys_tenant_service::tenant_role_menu_ids` 复制 `common` 菜单 ∩ 可授予判定）
//!    ⇒ 新租户管理员**继承** 4110；
//! 4. `getRouters` 出口剪枝 `prune_capability_gated_menus` 与授权门禁**同源**用
//!    `is_grantable_perm_with_features` ⇒ 注册表未登记 ⇒ 菜单不被剪除。
//!
//! 净效果：租户操作者**看得见**"告警规则"菜单、点进去 `GET /monitor/alert/list`
//! **必然 403**——正是 AGENTS 落地准则 2 点名的假入口，且它同时绕开三层开关收敛
//! （授权层放行、请求层拒绝）。
//!
//! 归属定性：**平台专属**。指标面为 cpu/mem/disk/全局登录失败（非租户维度），
//! 真要下放须先做租户级指标采集，另立项。
//!
//! ## 口径
//!
//! 与 `m20260926_000013` / `m20261008_000001` 同款**按完整前缀清单**剔除（避免
//! m000002/m000005 那种"只列本批新增项导致漏剔"）。清单必须与
//! `src/common/tenant.rs::PLATFORM_ONLY_PERM_PREFIXES` 逐项一致，由单测
//! `platform_only_prefixes_match_migration_lists` 锁双向一致（b95 起 `LATEST_SRC`
//! 已推进到 `m20261026_000003_platform_only_menu_manage`，本迁移为历史清单）。
//!
//! 本迁移**不做能力位感知**（迁移期无能力位上下文）——只保证"默认整面不下放"；
//! 开启态回填由启动治理 ①' 负责。
//!
//! 幂等：DELETE 天然幂等（重复执行 0 行）。
//!
//! 多租户与权限（全局铁律第一问）：本迁移**就是**租户隔离收敛本身——剔除范围
//! ① role_id=2（租户管理员模板源）② `tenant_id <> 0` 的存量租户角色；平台侧
//! 超管（`*:*:*`）不受影响，`monitor:alert:` 面在平台视角继续可用（能力全备，
//! 默认安全，不砍功能）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261017_000002_platform_only_alert"
    }
}

/// 与 `common::tenant::PLATFORM_ONLY_PERM_PREFIXES` **逐项一致**（13 项，含本批新增的
/// `monitor:alert:`——告警规则，指标面为宿主资源与全局登录失败，非租户维度）。
/// 迁移 crate 无法引用 `src` 常量，故显式列出并由单测锁双向一致。
const PLATFORM_ONLY_PERM_PREFIXES: &[&str] = &[
    "system:tenant:domain:",
    "system:tenantMenu:",
    "tool:gen:",
    "tool:httpDebug:",
    "monitor:cache:",
    "monitor:log:",
    "monitor:slowSql:",
    "monitor:health:",
    "monitor:operlogArchive:",
    "monitor:alert:",
    "system:backup:",
    "system:rateLimit:",
    "system:aiConfig:",
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

        // ① 平台普通角色（role_id=2，新建租户管理员的菜单模板源）剔除
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
