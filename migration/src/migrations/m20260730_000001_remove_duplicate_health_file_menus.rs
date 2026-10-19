// stepby-axum/migration/src/migrations/m20260730_000001_remove_duplicate_health_file_menus.rs
//! 第十五次迁移：清理重复的 health/file 菜单记录
//!
//! 背景：
//! menu_id=2011（health, parent=2, name="????"）与 menu_id=133（健康检查）重复
//! menu_id=2012（file, parent=1, name="????"）与 menu_id=134（文件管理）重复
//! 这两条记录是 2026-07-19 手动测试时插入的残留数据，name 字段为 "????"，
//! 导致前端路由树中出现重复路由且侧边栏显示 "<?>???" 乱码菜单名。
//!
//! 修复：删除 menu_id=2011/2012 及其 sys_role_menu 关联

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260730_000001_remove_duplicate_health_file_menus"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除 sys_role_menu 中 menu_id=2011/2012 的关联
        for menu_id in [2011, 2012] {
            let sql = format!("DELETE FROM sys_role_menu WHERE menu_id = {}", menu_id);
            manager.get_connection().execute_unprepared(&sql).await?;
        }

        // 删除 sys_menu 中 menu_id=2011/2012 的记录
        for menu_id in [2011, 2012] {
            let sql = format!("DELETE FROM sys_menu WHERE menu_id = {}", menu_id);
            manager.get_connection().execute_unprepared(&sql).await?;
        }

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚无意义：这两条记录是错误数据，不需要恢复
        Ok(())
    }
}
