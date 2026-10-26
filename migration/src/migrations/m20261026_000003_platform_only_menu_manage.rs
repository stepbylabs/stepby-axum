// stepby-axum/migration/src/migrations/m20261026_000003_platform_only_menu_manage.rs
//! 批九十五：**`system:menu:` 纳入平台专属前缀**并按完整清单剔除。
//!
//! ## 为什么必须登记为"平台专属前缀"（真缺陷，非预防性改造）
//!
//! `sys_menu` 是**全局定义表**（无 `tenant_id`）：租户一旦能写菜单，就能改 perms
//! （例如把自己角色的键写成 `*:*:*` 直接命中超管短路），或把平台专属菜单挂进自己的
//! 授权面，影响**所有租户**。因此菜单定义面与租户管理、缓存监控同属平台面。
//!
//! 但 `PLATFORM_ONLY_PERM_PREFIXES` 原先没有 `system:menu:`，于是：
//! 1. `is_grantable_perm_with_features` 判该族 perms"可授予"；
//! 2. 种子把 `system:menu:list/query` 发给平台普通角色 `common`（`role_id=2`）；
//! 3. `common` 是**新建租户默认管理员角色的菜单模板源**
//!    （`sys_tenant_service::tenant_role_menu_ids`）⇒ 新租户管理员继承该菜单；
//! 4. `getRouters` 出口剪枝与授权门禁同源 ⇒ 注册表未登记 ⇒ 菜单不被剪除。
//!
//! 净效果是租户看得见"菜单管理"、点进去请求 403（假入口），且租户能读到全局菜单定义。
//!
//! ## 口径
//!
//! 与 `m20261017_000002` 同款**按完整前缀清单**剔除（避免"只列本批新增项导致漏剔"）。
//! 清单必须与 `src/common/tenant.rs::PLATFORM_ONLY_PERM_PREFIXES` 逐项一致，
//! 由单测 `platform_only_prefixes_match_migration_lists` 编译期断言
//! （`LATEST_SRC` 指向本迁移）。
//!
//! 本迁移**不做能力位感知**（迁移期无能力位上下文）——只保证"默认整面不下放"；
//! 未来若要把菜单管理下放租户，必须先拆掉全局表语义，另立项。
//!
//! 幂等：DELETE 天然幂等（重复执行 0 行）。
//!
//! 多租户与权限（全局铁律第一问）：本迁移**就是**租户隔离收敛本身——剔除范围
//! ① role_id=2（租户管理员模板源）② `tenant_id <> 0` 的存量租户角色；平台侧
//! 超管（`*:*:*`）不受影响，菜单定义面在平台视角继续可用（能力全备，默认安全，
//! 不砍功能）。角色授权页用的**只读菜单树**仍在服务层按可授予面过滤后对租户开放
//! （见 `router/sys_menu_router.rs` 的拆分口径）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261026_000003_platform_only_menu_manage"
    }
}

/// 与 `common::tenant::PLATFORM_ONLY_PERM_PREFIXES` **逐项一致**（14 项，含本批新增的
/// `system:menu:`——菜单定义是全局表，租户可写即跨租户越权）。
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
    "system:menu:",
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
        // 租户角色侧不回插——租户角色本不应持有平台面菜单）
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
