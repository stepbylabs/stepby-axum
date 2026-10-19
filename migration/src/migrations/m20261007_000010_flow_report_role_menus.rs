//! 批次十三：平台普通角色（role 2）补授 G-01/G-02 菜单 4140-4148
//!
//! 背景：m20261007_000005 只建了菜单行，**未发 role_menu 授权**——超管经
//! `isAdmin` 特判拥有全部 perms 无需授权行，但平台普通角色（role 2，租户角色
//! 菜单上限的复制源）看不到任何 G-01/G-02 新功能入口（存量库 role_menu 真值实锤）。
//! 用户拍板：**全量授权**（对齐菜单 148/3950 惯例——新业务菜单默认授予 role 2）；
//! 写权限仍受三层守卫兜底（菜单 perms 契约 + `report.designer`/`flow.designer`
//! 能力位 + 租户过滤）。
//!
//! 幂等：三方言 IGNORE 前后缀（与 m20261007_000002 同构），可重复执行。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000010_flow_report_role_menus"
    }
}

/// 幂等 INSERT（方言感知 IGNORE 前后缀，与 m20261007_000002 同构）
fn idempotent_insert(backend: sea_orm::DatabaseBackend, body: &str) -> String {
    match backend {
        sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {body}"),
        sea_orm::DatabaseBackend::Postgres => format!("INSERT INTO {body} ON CONFLICT DO NOTHING"),
        _ => format!("INSERT IGNORE INTO {body}"),
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // b73 轮 15：改走 governance 策略体（SELECT 侧过滤）。与批次十三"全量授权"拍板
        // 当前等价——本段写按钮 4142-4145 / 4147 已逐条登记进 COMMON_ROLE_WRITE_EXCEPTIONS，
        // 其余为 M/C 页面或 `:query` 只读按钮；今后往本段加未登记的写按钮将被拒发。
        manager
            .get_connection()
            .execute_unprepared(&idempotent_insert(
                manager.get_connection().get_database_backend(),
                &governance::common_role_grant_select_body(&[
                    4140, 4141, 4142, 4143, 4144, 4145, 4146, 4147, 4148,
                ]),
            ))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_role_menu WHERE role_id = 2 AND menu_id BETWEEN 4140 AND 4148",
            )
            .await?;
        Ok(())
    }
}
