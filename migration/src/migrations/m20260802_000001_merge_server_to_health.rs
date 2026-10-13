//! 合并菜单：服务监控 → 健康检查（P0-1）
//!
//! 背景：
//!   - menu_id=112（服务监控）的页面 monitor/server/index.vue 与 monitor/health/index.vue 严重重叠
//!   - health 页面已调用 /monitor/server API 并展示 server 的 CPU/内存/磁盘字段，是 server 的超集
//!   - server 页面已删除，前端不再有 monitor/server 目录
//!   - 此迁移彻底删除 server 菜单记录及其 sys_role_menu 关联
//!
//! 操作：
//!   1. 删除 sys_role_menu WHERE menu_id = 112
//!   2. 删除 sys_menu WHERE menu_id = 112
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
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 112")
            .await?;

        // 2. 删除菜单记录
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id = 112")
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // 无法恢复：原种子数据在 m20250711_000001_init.rs 中，如需恢复请参考该文件
        Ok(())
    }
}
