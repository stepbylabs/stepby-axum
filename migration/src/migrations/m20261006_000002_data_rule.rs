// stepby-axum/migration/src/migrations/m20261006_000002_data_rule.rs
//! DP-01 结构化数据权限规则引擎（§5.52，JeecgBoot 数据权限规则模式对标、
//! sea-orm 显式 Condition 注入方案——否决裸 SQL 改写与 PG RLS，理由见 link-audit）：
//!
//! 1. `sys_data_rule`：规则定义（目标表/列/操作符/值类型/值）——**挂角色**生效
//!    （对齐 data_scope 三层收敛语义：规则归角色，角色归用户）。
//! 2. `sys_role_data_rule`：角色-规则多对多。
//! 3. 菜单种子：C 4117"数据权限规则"（system/dataRule/index）+ F 按钮 4118/4119/4120。
//!
//! ## 安全设计
//! - table_name/field_name 录入时正则白名单（^[a-z_][a-z0-9_]*$），值经参数绑定零注入；
//! - 求值期多规则 **OR 合并**（任一命中即可见，对齐 data_scope"最宽松优先"）；
//! - 无规则/引擎未接入 = 零注入（现状行为，opt-in 渐进）；
//! - 规则行带 tenant_id，租户管理员仅能管理本租户规则（行级隔离）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261006_000002_data_rule"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "NOW()",
            _ => "CURRENT_TIMESTAMP",
        };

        manager
            .create_table(
                Table::create()
                    .table(Alias::new("sys_data_rule"))
                    .col(
                        ColumnDef::new(Alias::new("rule_id"))
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Alias::new("rule_name")).string_len(64).not_null())
                    .col(ColumnDef::new(Alias::new("table_name")).string_len(64).not_null())
                    .col(ColumnDef::new(Alias::new("field_name")).string_len(64).not_null())
                    .col(ColumnDef::new(Alias::new("op")).string_len(8).not_null())
                    .col(ColumnDef::new(Alias::new("value_type")).string_len(24).not_null())
                    .col(ColumnDef::new(Alias::new("rule_value")).string_len(255))
                    .col(ColumnDef::new(Alias::new("status")).char_len(1).not_null().default("0"))
                    .col(ColumnDef::new(Alias::new("del_flag")).char_len(1).not_null().default("0"))
                    .col(ColumnDef::new(Alias::new("tenant_id")).big_integer().not_null().default(0))
                    .col(ColumnDef::new(Alias::new("create_by")).string_len(64))
                    .col(ColumnDef::new(Alias::new("create_time")).date_time())
                    .col(ColumnDef::new(Alias::new("update_by")).string_len(64))
                    .col(ColumnDef::new(Alias::new("update_time")).date_time())
                    .col(ColumnDef::new(Alias::new("remark")).string_len(255))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_data_rule_tenant_table")
                    .table(Alias::new("sys_data_rule"))
                    .col(Alias::new("tenant_id"))
                    .col(Alias::new("table_name"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Alias::new("sys_role_data_rule"))
                    .col(ColumnDef::new(Alias::new("role_id")).big_integer().not_null())
                    .col(ColumnDef::new(Alias::new("rule_id")).big_integer().not_null())
                    .primary_key(
                        Index::create()
                            .col(Alias::new("role_id"))
                            .col(Alias::new("rule_id")),
                    )
                    .to_owned(),
            )
            .await?;

        // 菜单：C 页面 + 三个 F 按钮（perms 与 P1 契约测试口径一致）
        let menus_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (4117, '数据权限规则', 1, 15, 'dataRule', 'system/dataRule/index', '', '', '1', '0', 'C', '0', '0', 'system:dataRule:list', 'rule', 'admin', {now}, 'DP-01 结构化数据权限规则（挂角色生效，查询期显式注入）', '0'), \
            (4118, '规则新增', 4117, 1, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:dataRule:add', '#', 'admin', {now}, '', '0'), \
            (4119, '规则编辑', 4117, 2, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:dataRule:edit', '#', 'admin', {now}, '', '0'), \
            (4120, '规则删除', 4117, 3, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:dataRule:remove', '#', 'admin', {now}, '', '0')"
        );
        let menu_sql = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {}", menus_sql),
            sea_orm::DatabaseBackend::Postgres => {
                format!("INSERT INTO {} ON CONFLICT DO NOTHING", menus_sql)
            }
            _ => format!("INSERT IGNORE INTO {}", menus_sql),
        };
        manager
            .get_connection()
            .execute_unprepared(&menu_sql)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_menu WHERE menu_id IN (4117, 4118, 4119, 4120)",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_role_data_rule")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_data_rule")
            .await?;
        Ok(())
    }
}
