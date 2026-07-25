//! 补全缺失的按钮权限子菜单（menu_type='F'）
//!
//! 背景：
//!   - 12 个叶子菜单(menu_type='C')中，4 个有操作按钮但未注册按钮权限子菜单
//!   - 通知中心(file=125)、文件管理(134)、缓存管理(113)、表单构建(115)
//!   - 只读页面（数据看板/健康检查/工作台/关于/快捷键/帮助/更新日志/系统接口）无需补全
//!
//! 操作：
//!   1. 通知中心(125)补 4 个按钮权限：query/markRead/markBatchRead/markAllRead
//!   2. 文件管理(134)补 5 个按钮权限：query/upload/download/copy/remove
//!   3. 缓存管理(113)补 3 个按钮权限：query/clearName/clearKey
//!   4. 表单构建(115)补 3 个按钮权限：export/copy/clear
//!   5. 为 common 角色(role_id=2)授权所有新增按钮权限
//!
//! menu_id 分配：从 3000 起步（避开种子数据 1-999、1000-1999 保留段、2000-2099 测试数据段）

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 通知中心按钮权限（parent_id=125）
        let notice_center_perms = [
            (3001, "通知查询", "system:notice:center:query", 1),
            (3002, "通知标记已读", "system:notice:center:markRead", 2),
            (3003, "通知批量标记已读", "system:notice:center:markBatchRead", 3),
            (3004, "通知全部标记已读", "system:notice:center:markAllRead", 4),
        ];
        for (id, name, perms, order) in notice_center_perms {
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    "INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, menu_type, visible, status, perms, icon, create_by, create_time, del_flag) VALUES ({}, '{}', 125, {}, '', '', 'F', '0', '0', '{}', '#', 'system', datetime('now'), '0')",
                    id, name, order, perms
                ))
                .await?;
            // common 角色授权
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    "INSERT OR IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, {})",
                    id
                ))
                .await?;
        }

        // 文件管理按钮权限（parent_id=134）
        let file_perms = [
            (3011, "文件查询", "system:file:query", 1),
            (3012, "文件上传", "system:file:upload", 2),
            (3013, "文件下载", "system:file:download", 3),
            (3014, "文件复制链接", "system:file:copy", 4),
            (3015, "文件删除", "system:file:remove", 5),
        ];
        for (id, name, perms, order) in file_perms {
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    "INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, menu_type, visible, status, perms, icon, create_by, create_time, del_flag) VALUES ({}, '{}', 134, {}, '', '', 'F', '0', '0', '{}', '#', 'system', datetime('now'), '0')",
                    id, name, order, perms
                ))
                .await?;
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    "INSERT OR IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, {})",
                    id
                ))
                .await?;
        }

        // 缓存管理按钮权限（parent_id=113）
        let cache_perms = [
            (3021, "缓存查询", "monitor:cache:query", 1),
            (3022, "缓存名称清除", "monitor:cache:clearName", 2),
            (3023, "缓存键清除", "monitor:cache:clearKey", 3),
        ];
        for (id, name, perms, order) in cache_perms {
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    "INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, menu_type, visible, status, perms, icon, create_by, create_time, del_flag) VALUES ({}, '{}', 113, {}, '', '', 'F', '0', '0', '{}', '#', 'system', datetime('now'), '0')",
                    id, name, order, perms
                ))
                .await?;
            // 缓存管理按钮权限仅授权给 admin 角色（role_id=1），不给 common
            // 因缓存清除是高危操作，普通用户不应有权限
        }

        // 表单构建按钮权限（parent_id=115）
        let build_perms = [
            (3031, "表单构建导出", "tool:build:export", 1),
            (3032, "表单构建复制", "tool:build:copy", 2),
            (3033, "表单构建清空", "tool:build:clear", 3),
        ];
        for (id, name, perms, order) in build_perms {
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    "INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, menu_type, visible, status, perms, icon, create_by, create_time, del_flag) VALUES ({}, '{}', 115, {}, '', '', 'F', '0', '0', '{}', '#', 'system', datetime('now'), '0')",
                    id, name, order, perms
                ))
                .await?;
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    "INSERT OR IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, {})",
                    id
                ))
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let ids = [3001, 3002, 3003, 3004, 3011, 3012, 3013, 3014, 3015, 3021, 3022, 3023, 3031, 3032, 3033];
        for id in ids {
            manager
                .get_connection()
                .execute_unprepared(&format!("DELETE FROM sys_role_menu WHERE menu_id = {}", id))
                .await?;
            manager
                .get_connection()
                .execute_unprepared(&format!("DELETE FROM sys_menu WHERE menu_id = {}", id))
                .await?;
        }
        Ok(())
    }
}
