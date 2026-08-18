// axum-backend/migration/src/m20260727_000001_add_workbench_shortcuts_help_menus.rs
//! 第十二次迁移：新增"个人工作台"、"快捷键中心"、"帮助中心"三个低成本高价值菜单
//!
//! 背景：
//! - 对比前 10 开源后台管理项目（vue-element-admin、vue-pure-admin、vben-admin、
//!   naive-ui-admin、JeecgBoot、ant-design-pro、
//!   Vuestic Admin、AdminLTE）后筛选出的缺失功能
//! - 复用现有 API（/getInfo、/system/notice/listTop、/monitor/online/list、
//!   /monitor/logininfor/list、收藏夹、最近访问），无新增后端接口
//! - "个人工作台" 个性化 Dashboard（参考 vue-pure-admin、vben-admin 的 workbench）
//! - "快捷键中心" 把 ? 弹窗升级为正式菜单页面（参考 Linear、Notion）
//! - "帮助中心" 集中静态帮助文档（参考 JeecgBoot）
//!
//! menu_id 规划：
//! - 127 个人工作台（M 类型目录，parent_id=0 顶级菜单，order_num=0 排在最前）
//!   component='' → 后端 get_routers 自动转换为 "Layout"
//! - 130 工作台首页（C 类型菜单，parent_id=127，path=index，component=workbench/index）
//!   URL: /workbench/index
//! - 128 快捷键中心（C 类型菜单，parent_id=3 系统工具目录，order_num=5）
//! - 129 帮助中心（C 类型菜单，parent_id=3 系统工具目录，order_num=6）
//!
//! 权限设计：
//! - workbench:view 所有人可见（role_id=2 显式关联，超管自动通配符）
//! - tool:shortcuts:list 所有人可见
//! - tool:help:list 所有人可见
//!
//! 超管通过 *:*:* 通配符访问，无需显式关联。
//!
//! 设计说明：
//! - 个人工作台采用 M+C 两层结构（而非顶级 C），以符合路由约定：
//!   顶级菜单必须为 Layout 容器，实际页面作为子路由渲染。
//!   若顶级 C 菜单直接使用 component=workbench/index，会导致路由无 Layout 包裹，
//!   进而触发前端路由守卫 catch 块 → 自动登出（P0 级回归缺陷）。

use sea_orm_migration::prelude::*;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(backend, sea_orm_migration::sea_orm::DatabaseBackend::Sqlite)
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(
        backend,
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

/// 当前时间表达式（跨数据库兼容）
fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        format!("'{}'", now)
    } else {
        "NOW()".to_string()
    }
}

/// 幂等 INSERT
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        format!("INSERT OR IGNORE INTO {}", body)
    } else if is_postgres(manager) {
        format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
    } else {
        format!("INSERT IGNORE INTO {}", body)
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260727_000001_add_workbench_shortcuts_help_menus"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);

        // 1. M 类型目录：个人工作台
        //    parent_id=0 (顶级菜单，作为独立入口)
        //    order_num=0（排在最前，作为登录后首选入口）
        //    component='' → 后端 get_routers 转换为 "Layout"
        //    is_frame='1' → redirect=noRedirect（单子菜单时不自动重定向到其他菜单）
        let workbench_dir_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (127, '个人工作台', 0, 0, 'workbench', '', '', '', '1', '0', 'M', '0', '0', 'workbench:view', 'dashboard', 'admin', {now}, '个性化工作台目录（欢迎卡片、我的统计、最近访问、收藏、未读通知、快捷入口）', '0')"
        );
        execute_idempotent_insert(manager, &workbench_dir_sql).await?;

        // 2. C 类型子菜单：工作台首页
        //    parent_id=127 (个人工作台目录的子菜单)
        //    path=index → URL: /workbench/index
        //    component=workbench/index → 前端 loadView('workbench/index')
        let workbench_page_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (130, '工作台首页', 127, 1, 'index', 'workbench/index', '', '', '1', '0', 'C', '0', '0', 'workbench:view', 'dashboard', 'admin', {now}, '个人工作台首页（问候语、快捷入口、最近访问、收藏、未读通知）', '0')"
        );
        execute_idempotent_insert(manager, &workbench_page_sql).await?;

        // 3. C 类型菜单：快捷键中心
        //    parent_id=3 (系统工具目录)
        //    order_num=5（在 关于系统 order_num=4 之后）
        //    perms=tool:shortcuts:list
        let shortcuts_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (128, '快捷键中心', 3, 5, 'shortcuts', 'tool/shortcuts/index', '', '', '1', '0', 'C', '0', '0', 'tool:shortcuts:list', 'button', 'admin', {now}, '快捷键查询面板（全局快捷键、命令面板、可搜索）', '0')"
        );
        execute_idempotent_insert(manager, &shortcuts_sql).await?;

        // 4. C 类型菜单：帮助中心
        //    parent_id=3 (系统工具目录)
        //    order_num=6
        //    perms=tool:help:list
        let help_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (129, '帮助中心', 3, 6, 'help', 'tool/help/index', '', '', '1', '0', 'C', '0', '0', 'tool:help:list', 'question', 'admin', {now}, '系统帮助文档（快速上手、快捷键、FAQ、联系方式）', '0')"
        );
        execute_idempotent_insert(manager, &help_sql).await?;

        // 5. 为普通角色 role_id=2 关联新菜单（让普通用户也能访问）
        let role_menu_sql =
            "sys_role_menu (role_id, menu_id) VALUES (2, 127), (2, 128), (2, 129), (2, 130)";
        execute_idempotent_insert(manager, role_menu_sql).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 删除 role_menu 关联
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id IN (127, 128, 129, 130)")
            .await?;

        // 删除菜单
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id IN (127, 128, 129, 130)")
            .await?;

        Ok(())
    }
}
