//! 第六次迁移：隐藏 Druid 监控菜单（menu_id=111）
//!
//! 背景：
//!   Druid 是阿里巴巴 Java 数据库连接池监控工具，当前 Java 系后台框架普遍集成。
//!   stepby 后端基于 Rust + Axum + SeaORM，从未集成 Druid，但 migration m20250711
//!   原样拷贝了参考 admin 项目的 sys_menu 种子数据，导致 menu_id=111（数据监控/druid）
//!   在前端动态菜单中显示，点击后进入占位页 `views/monitor/druid/index.vue`，
//!   该页面 `<script setup>` 为空，仅显示 "Druid 未配置" 提示。
//!
//! 处理方案：
//!   1. 将 menu_id=111 的 visible 改为 '1'（隐藏），不再在导航菜单中展示
//!   2. 保留 status='0'（正常），便于未来如实现真实 DB 监控可重新启用
//!   3. 前端删除 `views/monitor/druid/` 目录（占位页清理）
//!   4. 不删除菜单记录，避免影响已有 sys_role_menu 关联数据
//!
//! 回滚说明：
//!   down 方法将 visible 恢复为 '0'（显示），前端 druid 目录需从 git 历史恢复。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260720_000001_hide_druid_menu"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 三库统一的 UPDATE 语句（无方言差异）
        // visible='1' 表示隐藏菜单（约定：0=显示, 1=隐藏）
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET visible = '1' WHERE menu_id = 111")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚：恢复 visible='0'（显示）
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET visible = '0' WHERE menu_id = 111")
            .await?;
        Ok(())
    }
}
