//! 清理无效菜单：彻底删除 menu_id=111（数据监控/druid）
//!
//! 背景：
//!   - menu_id=111 是 RuoYi 遗留的 Java Druid 监控菜单，component=monitor/druid/index
//!   - 前端 views/monitor/druid/ 目录已在 m20260720_000001_hide_druid_menu 中删除
//!   - 之前只做了 visible='1' 隐藏，但数据库记录和 sys_role_menu 关联仍残留
//!   - 用户点击仍会触发 loadView 兜底警告（组件不存在）
//!
//! 操作：
//!   1. 删除 sys_menu WHERE menu_id = 111
//!   2. 删除 sys_role_menu WHERE menu_id = 111（清理残留关联）
//!
//! down 方法：无法恢复（原数据在 m20250711_000001_init.rs 种子数据中可重建）

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. 清理 sys_role_menu 关联
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 111")
            .await?;

        // 2. 删除菜单记录
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id = 111")
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // 无法恢复：原种子数据在 m20250711_000001_init.rs 中，如需恢复请参考该文件
        Ok(())
    }
}
