// axum-backend/migration/src/m20260725_000002_add_menu_i18n_key.rs
//! 菜单 i18n_key 字段迁移：为 sys_menu 添加 i18n_key 列并填充内置菜单翻译 key
//!
//! 背景：
//!   - sys_menu.menu_name 存储原始中文（如 "用户管理"），前端无法按 locale 翻译
//!   - 切换语言时菜单名不变化，且 LangSelect 只能 location.reload() 粗暴重载
//!   - 现新增 i18n_key 字段（nullable），前端优先用 t(i18nKey) 翻译，回退到 menu_name 原文
//!
//! 操作：
//!   1. ALTER TABLE sys_menu ADD COLUMN i18n_key VARCHAR(100) NULL
//!   2. UPDATE 填充 38 条内置菜单（M/C 类型，menu_id < 1000）的 i18n_key
//!      映射规则：menu_id → menu.{对应 i18n key}
//!      F 类型按钮（menu_id >= 1000）不进入路由树，不需要 i18n_key
//!
//! 回滚：
//!   down 方法删除 i18n_key 列（SQLite 不支持 DROP COLUMN，需重建表）
//!   为简化回滚，这里采用"重命名为旧表→新建无 i18n_key 的表→复制数据→删除旧表"方案

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{DatabaseBackend, Statement};

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260725_000002_add_menu_i18n_key"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let conn = manager.get_connection();

        // ========== 1. 添加 i18n_key 列（三库统一语法） ==========
        // SQLite/Postgres/MySQL 均支持 ALTER TABLE ADD COLUMN
        conn.execute_unprepared("ALTER TABLE sys_menu ADD COLUMN i18n_key VARCHAR(100) NULL")
            .await?;

        // ========== 2. 填充内置菜单 i18n_key ==========
        // 仅 M（目录）和 C（菜单）类型需要 i18n_key，F（按钮）类型不进入路由树
        // 映射表：menu_id → i18n_key（对应前端 menu.* 命名空间）
        let updates: &[(i64, &str)] = &[
            // 顶级目录
            (1, "menu.system"),
            (2, "menu.monitor"),
            (3, "menu.tool"),
            (4, "menu.website"),
            (127, "menu.workbench"),
            (132, "menu.dashboard"),
            // 系统管理子菜单
            (100, "menu.user"),
            (101, "menu.role"),
            (102, "menu.menu"),
            (103, "menu.dept"),
            (104, "menu.post"),
            (105, "menu.dict"),
            (106, "menu.config"),
            (107, "menu.notice"),
            (108, "menu.log"),
            (118, "menu.backup"),
            (119, "menu.task"),
            (121, "menu.rateLimit"),
            (125, "menu.noticeCenter"),
            (134, "menu.file"),
            // 系统监控子菜单
            (109, "menu.online"),
            (110, "menu.job"),
            (111, "menu.druid"),
            (112, "menu.server"),
            (113, "menu.cache"),
            (114, "menu.cacheList"),
            (120, "menu.auditDashboard"),
            (122, "menu.ipLocation"),
            (123, "menu.myLogin"),
            (126, "menu.mySession"),
            (133, "menu.health"),
            // 系统工具子菜单
            (115, "menu.build"),
            (116, "menu.gen"),
            (117, "menu.swagger"),
            (124, "menu.about"),
            (128, "menu.shortcuts"),
            (129, "menu.help"),
            (131, "menu.changelog"),
            // 日志管理子菜单
            (500, "menu.operlog"),
            (501, "menu.logininfor"),
            // 工作台子菜单
            (130, "menu.workbenchIndex"),
        ];

        for (menu_id, i18n_key) in updates {
            conn.execute(Statement::from_sql_and_values(
                backend,
                "UPDATE sys_menu SET i18n_key = $1 WHERE menu_id = $2",
                [(*i18n_key).into(), (*menu_id).into()],
            ))
            .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let conn = manager.get_connection();

        // SQLite 不支持 DROP COLUMN（旧版本），需重建表
        // Postgres/MySQL 支持 DROP COLUMN
        match backend {
            DatabaseBackend::Sqlite => {
                // SQLite: 重建表方案
                // 1. 重命名旧表
                conn.execute_unprepared("ALTER TABLE sys_menu RENAME TO sys_menu_old_i18n")
                    .await?;

                // 2. 创建新表（无 i18n_key 列）— 复制原始 schema
                conn.execute_unprepared(
                    r#"CREATE TABLE sys_menu (
                        menu_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        menu_name TEXT NOT NULL,
                        parent_id INTEGER,
                        order_num INTEGER,
                        path TEXT,
                        component TEXT,
                        query TEXT,
                        route_name TEXT,
                        is_frame TEXT,
                        is_cache TEXT,
                        menu_type TEXT,
                        visible TEXT,
                        status TEXT,
                        perms TEXT,
                        icon TEXT,
                        create_by TEXT,
                        create_time TEXT,
                        update_by TEXT,
                        update_time TEXT,
                        remark TEXT,
                        del_flag TEXT
                    )"#,
                )
                .await?;

                // 3. 复制数据（排除 i18n_key 列）
                conn.execute_unprepared(
                    r#"INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, update_by, update_time, remark, del_flag)
                       SELECT menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, update_by, update_time, remark, del_flag
                       FROM sys_menu_old_i18n"#,
                )
                .await?;

                // 4. 删除旧表
                conn.execute_unprepared("DROP TABLE sys_menu_old_i18n")
                    .await?;
            }
            _ => {
                // Postgres/MySQL: 直接 DROP COLUMN
                conn.execute_unprepared("ALTER TABLE sys_menu DROP COLUMN i18n_key")
                    .await?;
            }
        }

        Ok(())
    }
}
