//! 修复缺失 i18n_key 的菜单：/help-center 与 /system/dashboard
//!
//! 背景：
//!   - m20260725_000002_add_menu_i18n_key 在新增 i18n_key 列时填充了内置菜单的 key
//!   - 但后续 m20260801_000002_register_dashboard_menu 注册的"数据看板"菜单未带 i18n_key
//!   - 通过菜单管理 UI 手工添加的 /help-center 顶级目录也未配置 i18n_key
//!   - 结果：语言切换时这两个菜单名仍显示中文（menu.dashboard / menu.helpCenter 翻译键已存在）
//!
//! 操作：
//!   1. UPDATE sys_menu SET i18n_key='menu.dashboard'
//!      WHERE path='dashboard' AND parent_id=1 AND component='dashboard/index'
//!   2. UPDATE sys_menu SET i18n_key='menu.helpCenter'
//!      WHERE path='help-center' AND parent_id=0 AND menu_type='M'
//!
//! 回滚：将对应行 i18n_key 重置为 NULL
//!
//! 注：menu.helpCenter 翻译键需要在前端语言包中新增（与 menu.help 区分，避免与
//! tool/help 子菜单冲突）。

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::Statement;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let backend = manager.get_database_backend();

        // 1. 修复 /system/dashboard 数据看板菜单的 i18n_key
        conn.execute(Statement::from_sql_and_values(
            backend,
            "UPDATE sys_menu SET i18n_key = $1 WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index' AND (i18n_key IS NULL OR i18n_key = '')",
            ["menu.dashboard".into()],
        ))
        .await?;

        // 2. 修复 /help-center 顶级目录的 i18n_key
        //    使用 menu.helpCenter 区别于 tool/help 子菜单（menu.help）
        conn.execute(Statement::from_sql_and_values(
            backend,
            "UPDATE sys_menu SET i18n_key = $1 WHERE path = 'help-center' AND parent_id = 0 AND menu_type = 'M' AND (i18n_key IS NULL OR i18n_key = '')",
            ["menu.helpCenter".into()],
        ))
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let backend = manager.get_database_backend();

        conn.execute(Statement::from_sql_and_values(
            backend,
            "UPDATE sys_menu SET i18n_key = NULL WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index' AND i18n_key = $1",
            ["menu.dashboard".into()],
        ))
        .await?;

        conn.execute(Statement::from_sql_and_values(
            backend,
            "UPDATE sys_menu SET i18n_key = NULL WHERE path = 'help-center' AND parent_id = 0 AND menu_type = 'M' AND i18n_key = $1",
            ["menu.helpCenter".into()],
        ))
        .await?;

        Ok(())
    }
}
