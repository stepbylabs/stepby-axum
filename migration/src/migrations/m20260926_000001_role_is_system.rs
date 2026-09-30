// stepby-axum/migration/src/m20260926_000001_role_is_system.rs
//! 台账 P0-2：sys_role 增 `is_system` 系统标记列（超管判定与可变 role_key 解耦）。
//!
//! 背景（`docs/optimization/multitenant-pending-items-ledger-2026-09-25.md` §1.1 P0-2）：
//! 超管判定原为 `role_key == "admin"`（`sys_menu_service.rs:655/:779`），而 `role_key`
//! 是业务可写字段（`edit_role` 允许改名，仅 SUPER_ADMIN_ROLE_ID 单点保护）——一旦
//! 提权判定依赖可变值，租户侧自建同名 `admin` 角色即可短路拿到全量菜单与 `*:*:*`。
//!
//! 目标状态：平台超管 = `is_system = 1 AND tenant_id = 0`（双条件，见
//! `entity/sys_role.rs::is_platform_super_admin`）。回填口径按语义（tenant_id=0 且
//! role_key='admin'）而非固定 role_id，避免种子 ID 漂移导致漏回填。
//!
//! 存量库兜底：`initialize::ensure_role_is_system_column`（启动不跑 Migrator::up
//! 的架构约定，见 initialize/mod.rs 头部说明）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000001_role_is_system"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. 加列（boolean 由 sea-query 按方言渲染：PG BOOLEAN / MySQL TINYINT(1) / SQLite INTEGER）
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_role"))
                    .add_column(
                        ColumnDef::new(Alias::new("is_system"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        // 2. 语义回填：平台租户（tid=0）的 admin 角色标记为系统角色
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_role SET is_system = 1 WHERE tenant_id = 0 AND role_key = 'admin' \
                 AND del_flag = '0'",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_role"))
                    .drop_column(Alias::new("is_system"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
