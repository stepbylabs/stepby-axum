//! 修复 menu_id=122 (IP 库管理) 的 parent_id 错误
//!
//! 背景：
//!   - m20260724_000001_ip_location_menus 使用 INSERT OR IGNORE 插入 menu 122，
//!     指定 parent_id=2（系统监控目录 /monitor）
//!   - 但数据库实际 parent_id=1（系统管理目录 /system），导致路由注册为
//!     /system/ip-location 而非预期的 /monitor/ip-location
//!   - 根因：INSERT OR IGNORE 在 menu_id=122 已存在时静默跳过，不更新 parent_id
//!   - 影响：访问 /monitor/ip-location 返回 404（catch-all 兜底）
//!
//! 修复：
//!   使用 UPDATE（非 INSERT）强制修正 parent_id=2、order_num=8
//!   同步修正 perms 字段从 system:iplocation:* 改为 monitor:iplocation:*，
//!   与父目录 /monitor 下的其他菜单（monitor:online、monitor:job 等）保持一致
//!
//! 注意：
//!   - perms 字段变更需同步前后端的权限标识，但前端使用 v-hasPermi="['monitor:iplocation:list']"
//!     已在 m20260724 迁移中设置（DB 中 perms 可能仍为 system:iplocation:* ）
//!   - 此迁移同时修正 perms 字段，确保前后端权限标识一致

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. 修正 parent_id: 1 → 2（系统管理 → 系统监控）
        //    order_num=8（在 /monitor 目录下排在 backup=6, task=7 之后）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET parent_id = 2, order_num = 8 WHERE menu_id = 122 AND parent_id = 1",
            )
            .await?;

        // 2. 修正 perms 前缀：system:iplocation:* → monitor:iplocation:*
        //    与父目录 /monitor 下的菜单权限命名规范一致
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET perms = 'monitor:iplocation:list' WHERE menu_id = 122 AND perms = 'system:iplocation:list'",
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET perms = 'monitor:iplocation:query' WHERE menu_id = 1221 AND perms = 'system:iplocation:query'",
            )
            .await?;

        // 按钮权限：热加载（edit）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET perms = 'monitor:iplocation:edit' WHERE menu_id = 1213 AND perms = 'system:iplocation:edit'",
            )
            .await?;

        // 3. 同步后端 permission.rs 中的权限映射（代码层已使用 monitor:iplocation:* ）
        //    此处仅修正 DB 数据，代码层无需改动（已验证 permission.rs 使用 monitor:iplocation: 前缀）

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚：恢复 parent_id=1（系统管理目录）
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET parent_id = 1 WHERE menu_id = 122")
            .await?;

        // 回滚 perms 前缀
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET perms = 'system:iplocation:list' WHERE menu_id = 122 AND perms = 'monitor:iplocation:list'",
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET perms = 'system:iplocation:query' WHERE menu_id = 1221 AND perms = 'monitor:iplocation:query'",
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET perms = 'system:iplocation:edit' WHERE menu_id = 1213 AND perms = 'monitor:iplocation:edit'",
            )
            .await?;

        Ok(())
    }
}
