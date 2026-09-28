// axum-backend/migration/src/m20260731_000001_fix_menu_order_and_icons.rs
//! 第十六次迁移：修复菜单 order_num 冲突 + 工作台置顶 + 4 组 icon 重复
//!
//! 背景：
//! - 后端 sys_menu 查询缺失 ORDER BY，order_num 字段完全失效（已在 repository 修复）
//! - 顶级菜单 order_num=3 存在冲突（1 系统管理 和 3 系统工具 都是 3）
//! - 用户要求工作台置顶（个人工作台 127 应在数据看板 132 之前）
//! - 4 组 icon 仍重复：
//!   1. chart：132 数据看板 + 120 审计大屏
//!   2. online：126 会话管理 + 109 在线用户
//!   3. component：130 工作台首页 + 124 关于系统
//!   4. monitor：133 健康检查 + 2 系统监控
//!
//! 修复内容：
//! 1. 顶级菜单 order_num 重排（无冲突，工作台置顶）：
//!    - 127 个人工作台 → 0（置顶，用户默认看到工作台）
//!    - 132 数据看板 → 1
//!    - 1 系统管理 → 2
//!    - 2 系统监控 → 3
//!    - 3 系统工具 → 4
//!    - 4 Stepby官网 → 5
//! 2. 4 组 icon 去重（保留语义更匹配的一方，替换另一方）：
//!    - 120 审计大屏 chart→eye-open（审计=监察/看守语义）
//!    - 126 会话管理 online→people（会话=用户群语义，与 109 在线用户区分）
//!    - 130 工作台首页 component→tab（工作台=标签页/工作区语义）
//!    - 133 健康检查 monitor→bug（健康检查=诊断/排错语义，与 2 系统监控区分）
//!
//! 关于工作台与数据看板的关系：
//! - /index（首页）：默认落地页，显示登录统计+系统介绍，affix 标签页，不在侧边栏
//! - /workbench/index（工作台首页）：个人工作区，快捷入口/待办/任务
//! - /dashboard（数据看板）：统计仪表盘，图表/趋势/指标
//!
//! 三者功能不重叠，保留各自入口

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260731_000001_fix_menu_order_and_icons"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ========== 1. 顶级菜单 order_num 重排 ==========
        // 127 个人工作台 → 0（置顶）
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 0 WHERE menu_id = 127")
            .await?;
        // 132 数据看板 → 1
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 1 WHERE menu_id = 132")
            .await?;
        // 1 系统管理 → 2
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 2 WHERE menu_id = 1")
            .await?;
        // 2 系统监控 → 3
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 3 WHERE menu_id = 2")
            .await?;
        // 3 系统工具 → 4
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 4 WHERE menu_id = 3")
            .await?;
        // 4 Stepby官网 → 5
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 5 WHERE menu_id = 4")
            .await?;

        // ========== 2. 4 组 icon 去重 ==========
        // 120 审计大屏 chart→eye-open（审计=监察语义，eye-open.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'eye-open' WHERE menu_id = 120 AND icon = 'chart'",
            )
            .await?;
        // 126 会话管理 online→people（会话=用户群语义，people.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'people' WHERE menu_id = 126 AND icon = 'online'",
            )
            .await?;
        // 130 工作台首页 component→tab（工作台=标签页语义，tab.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'tab' WHERE menu_id = 130 AND icon = 'component'",
            )
            .await?;
        // 133 健康检查 monitor→bug（健康检查=诊断语义，bug.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'bug' WHERE menu_id = 133 AND icon = 'monitor'",
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚 order_num
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 1 WHERE menu_id = 127")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 0 WHERE menu_id = 132")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 3 WHERE menu_id = 1")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 2 WHERE menu_id = 2")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 3 WHERE menu_id = 3")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 4 WHERE menu_id = 4")
            .await?;

        // 回滚 icon
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET icon = 'chart' WHERE menu_id = 120")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET icon = 'online' WHERE menu_id = 126")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET icon = 'component' WHERE menu_id = 130")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET icon = 'monitor' WHERE menu_id = 133")
            .await?;

        Ok(())
    }
}
