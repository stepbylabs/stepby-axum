//! 合并菜单：缓存列表 → 缓存监控（P0-2）
//!
//! 背景：
//!   - menu_id=114（缓存列表）和 menu_id=113（缓存监控）共享 @/api/monitor/cache 模块
//!   - 两页面是同一资源的两个视角（宏观状态 vs 微观 key 操作）
//!   - 已合并为单页面 Tab 切换（cache/index.vue 含「概览」+「键管理」两个 Tab）
//!   - 此迁移删除 cacheList 菜单记录及其 sys_role_menu 关联
//!
//! 操作：
//!   1. 删除 sys_role_menu WHERE menu_id = 114
//!   2. 删除 sys_menu WHERE menu_id = 114
//!   3. 更新 menu_id=113（缓存监控）的 menu_name 为「缓存管理」匹配新的合并语义
//!
//! down 方法：无法恢复

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. 清理 sys_role_menu 关联
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 114")
            .await?;

        // 2. 删除缓存列表菜单记录
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id = 114")
            .await?;

        // 3. 更新缓存监控菜单名为「缓存管理」（涵盖概览+键管理两个 Tab）
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET menu_name = '缓存管理' WHERE menu_id = 113")
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // 无法恢复：原种子数据在 m20250711_000001_init.rs 中
        Ok(())
    }
}
