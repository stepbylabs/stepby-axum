// stepby-axum/migration/src/migrations/m20260928_000003_dedupe_dashboard_menu.rs
//! 数据看板菜单去重（用户实测缺陷：菜单树出现两个「数据看板」）。
//!
//! 根因：m20260729_000001 先在**顶级**（parent_id=0）注册了「数据看板」
//! （menu_id=132，path='dashboard'，component='dashboard/index'）；随后
//! m20260801_000002 又动态注册同一页面到「系统管理」（parent_id=1）下——其查重
//! 条件带 `AND parent_id = 1`，查不到顶级 132 ⇒ 存量库出现两条同 component 菜单，
//! 菜单树渲染两个入口（路由 hash 冲突，第二个入口行为不可预期）。
//!
//! 修复（本迁移）：删除 parent_id=1 的重复行（保留 132 顶级置顶入口——
//! m20260729 的设计意图，order_num=0 置顶 + chart 图标），连带清理 sys_role_menu
//! 引用。幂等：无重复行时为 no-op。
//!
//! 防重演：m20260801_000002 的查重条件已同步去掉 `AND parent_id = 1`
//! （全新库不会再插入第二条）。
//!
//! `down()` 有意为 no-op：重复菜单本属缺陷，回滚只会复现缺陷。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260928_000003_dedupe_dashboard_menu"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // 1. 清理重复行的角色引用
        conn.execute_unprepared(
            "DELETE FROM sys_role_menu WHERE menu_id IN (
                SELECT menu_id FROM sys_menu
                WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index'
            )",
        )
        .await?;

        // 2. 删除重复菜单行（保留顶级 132）
        conn.execute_unprepared(
            "DELETE FROM sys_menu WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index'",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_name_is_exact() {
        assert_eq!(Migration.name(), "m20260928_000003_dedupe_dashboard_menu");
    }
}
