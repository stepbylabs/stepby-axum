//! 修复 menu_id=118(备份管理)、119(任务进度)、121(限流配置) 的 parent_id
//!
//! 背景：
//!   - m20260721_000003_add_new_menus 插入 menu_id=118(备份管理) 和 119(任务进度)，
//!     指定 parent_id=1（系统管理目录 /system）
//!   - m20260722_000003_sys_rate_limit 插入 menu_id=121(限流配置)，
//!     指定 parent_id=1（系统管理目录 /system）
//!   - 但这三个菜单在功能上属于监控范畴（备份进度、任务进度、限流监控），
//!     应归属 /monitor 目录（parent_id=2），与审计大屏(120)、IP 库(122) 一致
//!   - 数据库中 parent_id 已通过菜单管理界面手动修改为 2，但缺少正式迁移记录，
//!     导致全新部署时菜单仍会在 /system 目录下
//!
//! 修复：
//!   使用 UPDATE（非 INSERT）强制修正 parent_id=2 及对应 order_num
//!   - 118: order_num=10（排在 IP 库 8 之后）
//!   - 119: order_num=11
//!   - 121: order_num=12
//!
//! 注意：
//!   - path 字段（backup/task/rateLimit）不变，仅 parent_id 变化
//!   - component 字段（system/backup/index 等）不变，前端视图文件位置未移动
//!   - perms 字段（system:backup:* / system:task:* / system:rateLimit:*）不变，
//!     权限标识前缀不改，避免前后端权限字符串大规模修改

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. 修正 parent_id: 1 → 2（系统管理 → 系统监控）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET parent_id = 2, order_num = 10 WHERE menu_id = 118 AND parent_id = 1",
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET parent_id = 2, order_num = 11 WHERE menu_id = 119 AND parent_id = 1",
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET parent_id = 2, order_num = 12 WHERE menu_id = 121 AND parent_id = 1",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚：恢复 parent_id=1（系统管理目录）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET parent_id = 1 WHERE menu_id IN (118, 119, 121)",
            )
            .await?;

        Ok(())
    }
}
