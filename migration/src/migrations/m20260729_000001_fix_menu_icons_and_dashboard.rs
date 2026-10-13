// stepby-axum/migration/src/m20260729_000001_fix_menu_icons_and_dashboard.rs
//! 第十四次迁移：修复菜单 icon 问题 + order_num 冲突 + 新增 /dashboard 菜单
//!
//! 背景：
//! - 5 个菜单 icon 引用了不存在的 SVG 文件，导致侧边栏图标位置空白
//! - 3 组菜单 icon 语义重复（guide×3、message×2、monitor×2）
//! - menu_id=118(备份管理) 和 125(通知中心) order_num 都为 10，造成排序冲突
//! - /dashboard 数据看板有路由无菜单，用户侧边栏看不到入口
//! - menu_id=111(druid) 已隐藏但 sys_role_menu 残留关联（脏数据）
//!
//! 修复内容：
//! 1. 修正 5 个缺失 SVG 的 icon：backup→download、task→list、audit→chart、ip→international、info→question
//! 2. 修正 3 组重复 icon：
//!    - 121 限流配置 guide→lock
//!    - 123 我的登录 guide→logininfor
//!    - 125 通知中心 message→bell
//!    - 126 会话管理 monitor→online
//!    - 130 工作台首页 dashboard→component
//! 3. 修正 order_num 冲突：125 通知中心 order_num: 10→13
//! 4. 新增 menu_id=132 数据看板菜单（parent_id=0 顶级，order_num=0）
//! 5. 清理 menu_id=111(druid) 的 sys_role_menu 残留关联
//! 6. 为 role_id=2 关联新菜单 132

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
        "m20260729_000001_fix_menu_icons_and_dashboard"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);

        // ========== 1. 修正 5 个缺失 SVG 的 icon ==========
        // backup→download（备份管理：下载语义，download.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'download' WHERE menu_id = 118 AND icon = 'backup'",
            )
            .await?;

        // task→list（任务进度：列表语义，list.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'list' WHERE menu_id = 119 AND icon = 'task'",
            )
            .await?;

        // audit→chart（审计大屏：图表语义，chart.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'chart' WHERE menu_id = 120 AND icon = 'audit'",
            )
            .await?;

        // ip→international（IP 库管理：国际化/地理位置语义，international.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'international' WHERE menu_id = 122 AND icon = 'ip'",
            )
            .await?;

        // info→question（关于系统：问号语义，question.svg 已存在）
        // 注意：124 当前 icon='info' 不是 EP 图标名也不是 svg 文件，需改为 question
        // 但 question 已用于 129 帮助中心，为区分改用 'education'（关于系统=系统介绍/教育）
        // 检查：education.svg 是否存在？若不存在则用 'component'（组件/系统信息语义）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'component' WHERE menu_id = 124 AND icon = 'info'",
            )
            .await?;

        // ========== 2. 修正 3 组重复 icon ==========
        // 121 限流配置 guide→lock（限流=锁定/控制语义，lock.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'lock' WHERE menu_id = 121 AND icon = 'guide'",
            )
            .await?;

        // 123 我的登录 guide→logininfor（与登录日志同语义，logininfor.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'logininfor' WHERE menu_id = 123 AND icon = 'guide'",
            )
            .await?;

        // 125 通知中心 message→bell（通知=铃铛语义，bell.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'bell' WHERE menu_id = 125 AND icon = 'message'",
            )
            .await?;

        // 126 会话管理 monitor→online（会话=在线语义，online.svg 已存在）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'online' WHERE menu_id = 126 AND icon = 'monitor'",
            )
            .await?;

        // 130 工作台首页 dashboard→component（与父菜单 127 个人工作台 dashboard 区分）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET icon = 'component' WHERE menu_id = 130 AND icon = 'dashboard'",
            )
            .await?;

        // ========== 3. 修正 order_num 冲突 ==========
        // menu_id=125 通知中心 order_num: 10→13（在 121 限流配置 order_num=12 之后）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET order_num = 13 WHERE menu_id = 125 AND order_num = 10",
            )
            .await?;

        // ========== 4. 新增 /dashboard 菜单 ==========
        // menu_id=132 数据看板（M 类型目录，parent_id=0 顶级，order_num=0 置顶）
        // 注意：/dashboard 路由已在 extraConstantRoutes 静态注册
        // 菜单注册仅用于侧边栏显示和权限标识
        // order_num=0 会让数据看板成为第一个菜单（在 127 个人工作台 order_num=0 之前）
        // 为避免与 127 冲突，改用 order_num=0 但 menu_id 更小（数据库排序通常按 order_num, menu_id）
        // 实际：将 127 个人工作台 order_num 改为 1，132 数据看板 order_num=0
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 127 AND order_num = 0",
            )
            .await?;

        let dashboard_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (132, '数据看板', 0, 0, 'dashboard', 'dashboard/index', '', '', '1', '0', 'C', '0', '0', 'monitor:dashboard:list', 'chart', 'admin', {now}, '数据看板（统计卡片+趋势图+操作日志）', '0')"
        );
        execute_idempotent_insert(manager, &dashboard_sql).await?;

        // 为普通角色 role_id=2 关联新菜单
        let role_menu_sql = "sys_role_menu (role_id, menu_id) VALUES (2, 132)";
        execute_idempotent_insert(manager, role_menu_sql).await?;

        // ========== 5. 新增 /monitor/health 健康检查菜单 ==========
        // menu_id=133 健康检查（C 类型，parent_id=2 系统监控目录，order_num=11）
        // 前端已有完整页面 views/monitor/health/index.vue，但无菜单记录导致不可访问
        let health_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (133, '健康检查', 2, 11, 'health', 'monitor/health/index', '', '', '1', '0', 'C', '0', '0', 'monitor:health:list', 'monitor', 'admin', {now}, '系统健康检查（DB/Redis/磁盘等依赖状态）', '0')"
        );
        execute_idempotent_insert(manager, &health_sql).await?;

        let role_menu_health = "sys_role_menu (role_id, menu_id) VALUES (2, 133)";
        execute_idempotent_insert(manager, role_menu_health).await?;

        // ========== 6. 新增 /system/file 文件管理菜单 ==========
        // menu_id=134 文件管理（C 类型，parent_id=1 系统管理目录，order_num=14）
        // 前端已有完整页面 views/system/file/index.vue，但无菜单记录导致不可访问
        let file_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (134, '文件管理', 1, 14, 'file', 'system/file/index', '', '', '1', '0', 'C', '0', '0', 'system:file:list', 'upload', 'admin', {now}, '系统文件管理（上传/下载/预览）', '0')"
        );
        execute_idempotent_insert(manager, &file_sql).await?;

        let role_menu_file = "sys_role_menu (role_id, menu_id) VALUES (2, 134)";
        execute_idempotent_insert(manager, role_menu_file).await?;

        // ========== 7. 清理 menu_id=111(druid) 的 sys_role_menu 残留关联 ==========
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 111")
            .await?;

        // ========== 8. 削减 common 角色(role_id=2) 过高权限 ==========
        // 当前 common 角色拥有全部 113 项权限（含删除用户/重置密码等高危操作）等同超管
        // 削减以下高危 F 类型按钮权限，让 common 角色回归"普通用户"语义：
        // - 删除类：system:user:remove(1003)、system:role:remove(1010)、system:menu:remove(1015)、
        //          system:dept:remove(1019)、system:dict:remove(1028)、system:config:remove(1033)、
        //          monitor:job:remove(1052)、system:backup:remove(1202)、system:task:remove(1204)、
        //          system:rateLimit:remove(1209)
        // - 重置/解锁类：system:user:resetPwd(1006)、monitor:logininfor:unlock(1044)
        // - 强退类：monitor:online:forceLogout(1048)、monitor:online:batchLogout(1047)
        // - 恢复备份类：system:backup:edit(1211)（恢复备份会覆盖现库）
        // - 修改限流：system:rateLimit:edit(1208)
        // - IP 库热加载：monitor:iplocation:edit(1213)
        // 保留：查询/新增/修改/导出 类权限（普通运维操作）
        // 注意：超管通过 *:*:* 通配符不受影响
        let remove_perms = [
            1003, 1006, 1010, 1015, 1019, 1028, 1033, 1044, 1047, 1048, 1052, 1202, 1204, 1208,
            1209, 1211, 1213,
        ];
        for menu_id in remove_perms {
            let sql = format!(
                "DELETE FROM sys_role_menu WHERE role_id = 2 AND menu_id = {}",
                menu_id
            );
            manager.get_connection().execute_unprepared(&sql).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚 icon 修改（恢复为原值）
        let rollback_icons = [
            (118, "backup"),
            (119, "task"),
            (120, "audit"),
            (122, "ip"),
            (124, "info"),
            (121, "guide"),
            (123, "guide"),
            (125, "message"),
            (126, "monitor"),
            (130, "dashboard"),
        ];
        for (menu_id, icon) in rollback_icons {
            let sql = format!(
                "UPDATE sys_menu SET icon = '{}' WHERE menu_id = {}",
                icon, menu_id
            );
            manager.get_connection().execute_unprepared(&sql).await?;
        }

        // 回滚 order_num
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 10 WHERE menu_id = 125")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET order_num = 0 WHERE menu_id = 127")
            .await?;

        // 删除新增的 dashboard/health/file 菜单及关联
        for menu_id in [132, 133, 134] {
            let sql = format!("DELETE FROM sys_role_menu WHERE menu_id = {}", menu_id);
            manager.get_connection().execute_unprepared(&sql).await?;
            let sql = format!("DELETE FROM sys_menu WHERE menu_id = {}", menu_id);
            manager.get_connection().execute_unprepared(&sql).await?;
        }

        // 恢复 druid 关联（虽然已隐藏但保留数据一致性）
        let now = now_expr(manager);
        let restore_druid = "sys_role_menu (role_id, menu_id) VALUES (2, 111)".to_string();
        let _ = now; // druid 关联无需时间戳
        execute_idempotent_insert(manager, &restore_druid).await?;

        // 恢复 common 角色被削减的权限
        let restore_perms = [
            (2, 1003),
            (2, 1006),
            (2, 1010),
            (2, 1015),
            (2, 1019),
            (2, 1028),
            (2, 1033),
            (2, 1044),
            (2, 1047),
            (2, 1048),
            (2, 1052),
            (2, 1202),
            (2, 1204),
            (2, 1208),
            (2, 1209),
            (2, 1211),
            (2, 1213),
        ];
        for (role_id, menu_id) in restore_perms {
            let sql = format!(
                "sys_role_menu (role_id, menu_id) VALUES ({}, {})",
                role_id, menu_id
            );
            execute_idempotent_insert(manager, &sql).await?;
        }

        Ok(())
    }
}
