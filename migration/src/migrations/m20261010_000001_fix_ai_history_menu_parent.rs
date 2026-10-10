// stepby-axum/migration/src/migrations/m20261010_000001_fix_ai_history_menu_parent.rs
//! 批次三十一：修复「AI 问数历史」菜单不可达（真实缺陷）
//!
//! 缺陷现象（e2e F100 实证）：访问 `/monitor/audit-dashboard/aiHistory`，
//! 渲染出的却是「审计大屏」页面，AI 问数历史表格永不出现。
//!
//! 根因：`m20261006_000001_ai_config_and_history` 把「AI 问数历史」(4116, menu_type='C',
//! component='monitor/aiHistory/index') 挂到菜单 120「审计大屏」之下，而 **120 自身
//! 也是 menu_type='C' 且带 component**（`monitor/audit-dashboard/index`）。
//!
//! 后端 `menu_to_router` 对 C 型菜单同时产出 component 与 children，前端据此注册
//! 嵌套路由；子路由的相对 path 需由父组件的 `<router-view>` 承接，而
//! `audit-dashboard/index.vue` 并无 `<router-view>` ⇒ 子页面永远无法渲染，
//! 命中父组件 = 显示审计大屏。Vue Router 的名称/路径解析规则使该结构**静默失效**
//! （不报错、不 404，仅渲染错误的页面——最危险的一类）。
//!
//! 同时「系统监控」(2) 目录下的全部同级菜单（在线会话/定时任务/缓存管理/健康检查…
//! 共 14 项）**一律为平级 C 页面，无嵌套结构**。4116 是唯一异类。
//!
//! 修复：把 4116 的 `parent_id` 由 120 改为 2，`path` 由相对 `aiHistory` 改为
//! `aiHistory`（顶级同级下 path 仍为单段，路由解析为 `/monitor/aiHistory`），
//! 与同域其它页面完全一致。120「审计大屏」保持原样（其自身页面仍可达）。
//!
//! 多租户与权限（全局铁律第一问）：
//! - 菜单可见性：120 与 2 均为平台/租户共有目录，改挂不改变可见范围；
//! - 权限键不变（`monitor:aiHistory:list` 已由 m20261006 种入 sys_menu.perms
//!   与 PERM_ROUTE_TABLE，本迁移只动父子关系与路径，**不触碰权限契约**）；
//! - 租户隔离：菜单为全局模板（tenant_id 概念不适用于 sys_menu 本身），
//!   各租户经 role_menu 授权获得，改挂后授权行不受影响。
//!
//! 存量库兜底：`initialize/mod.rs` 的 `ensure_ai_history_menu_parent`（幂等 UPDATE）。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 幂等：仅当 4116 仍挂在 120 下时修正（重复执行 / 新库已正确时为空操作）。
        // 用 UPDATE ... WHERE 天然幂等，无需 INSERT OR IGNORE 三方言分支。
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET parent_id = 2, path = 'aiHistory' \
                 WHERE menu_id = 4116 AND parent_id = 120",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET parent_id = 120, path = 'aiHistory' \
                 WHERE menu_id = 4116 AND parent_id = 2",
            )
            .await?;
        Ok(())
    }
}
