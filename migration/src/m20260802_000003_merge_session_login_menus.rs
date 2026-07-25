//! 合并菜单：在线用户+会话管理 → 在线会话（P1-1），登录日志+我的登录 → 登录日志双视角（P1-2）
//!
//! P1-1 背景：
//!   - menu_id=109（在线用户）与 menu_id=126（会话管理/我的会话）共用 /monitor/online API
//!   - 109 为管理员视角（全部在线），126 为用户视角（我的会话）
//!   - 前端已将 my-session 合并到 online/index.vue 的 Tab 中（MySessionPanel 子组件）
//!   - 此迁移删除 126 菜单，更新 109 菜单名为「在线会话」，并为 common 角色授权 109
//!
//! P1-2 背景：
//!   - menu_id=501（登录日志）与 menu_id=123（我的登录）共用 /monitor/logininfor API
//!   - 501 为管理员视角（全部日志），123 为用户视角（我的登录）
//!   - 前端已将 my-login 合并到 logininfor/index.vue 的 Tab 中（MyLoginPanel 子组件）
//!   - 501 原在 parent_id=108（日志管理）下，普通用户无法访问
//!   - 123 原在 parent_id=2（系统监控）下，普通用户可访问
//!   - 此迁移删除 123 菜单，将 501 移至 parent_id=2（系统监控），并为 common 角色授权 501
//!
//! 操作：
//!   P1-1:
//!     1. 删除 sys_role_menu WHERE menu_id = 126
//!     2. 删除 sys_menu WHERE menu_id = 126
//!     3. 更新 sys_menu SET menu_name='在线会话' WHERE menu_id = 109
//!     4. INSERT sys_role_menu (role_id=2, menu_id=109) — common 角色授权
//!
//!   P1-2:
//!     5. 删除 sys_role_menu WHERE menu_id = 123
//!     6. 删除 sys_menu WHERE menu_id = 123
//!     7. 更新 sys_menu SET parent_id=2, order_num=11 WHERE menu_id = 501 — 移至系统监控
//!     8. INSERT sys_role_menu (role_id=2, menu_id=501) — common 角色授权

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ====== P1-1: 合并在线用户 + 会话管理 ======

        // 1. 清理 my-session 的 sys_role_menu 关联
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 126")
            .await?;

        // 2. 删除 my-session 菜单记录
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id = 126")
            .await?;

        // 3. 更新 online 菜单名为「在线会话」
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET menu_name = '在线会话' WHERE menu_id = 109")
            .await?;

        // 4. 为 common 角色授权 online 菜单（普通用户可见"我的会话"Tab）
        manager
            .get_connection()
            .execute_unprepared(
                "INSERT OR IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, 109)",
            )
            .await?;

        // ====== P1-2: 合并登录日志 + 我的登录 ======

        // 5. 清理 my-login 的 sys_role_menu 关联
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 123")
            .await?;

        // 6. 删除 my-login 菜单记录
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id = 123")
            .await?;

        // 7. 将 logininfor 从 日志管理(108) 移至 系统监控(2)，order_num=11（排在健康检查后）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET parent_id = 2, order_num = 11 WHERE menu_id = 501",
            )
            .await?;

        // 8. 为 common 角色授权 logininfor 菜单（普通用户可见"我的登录"Tab）
        manager
            .get_connection()
            .execute_unprepared(
                "INSERT OR IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, 501)",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // 无法恢复：原种子数据在 m20250711_000001_init.rs 和 m20260725_000001 中
        Ok(())
    }
}
