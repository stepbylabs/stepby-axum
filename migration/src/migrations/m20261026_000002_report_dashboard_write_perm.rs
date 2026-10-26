//! 报告大屏写权限拆分（批九十四）。
//!
//! 立项事实：`POST /report/dashboard`（新增/保存）与 `DELETE /report/dashboard/{ids}`
//! 在 `PERM_ROUTE_TABLE` 里都挂在**读权限** `report:dashboard:view` 下；菜单 4148 的
//! C 行也只承载这一个键，前端新增/保存/删除按钮全部用 `v-hasPermi="['report:dashboard:view']"`。
//! ⇒ 任何只有"查看大屏"权限的角色都能改写和软删共享大屏，与 b93 修复的可观测清空
//! 属同一族（写操作挂在只读键下）。
//!
//! 本迁移只补两个 F 按钮并收敛文案，均幂等：
//! 1. 新增 4149（`report:dashboard:edit`）/ 4150（`report:dashboard:remove`）；
//! 2. 4148 的 remark 从"save/view 同权限键"改为"查看入口，写权限见按钮"；
//! 3. 窄撤销 role_id=2 对两个新按钮的授权（此前不存在，防御历史上被 e2e/手工写入）。
//!
//! 不回填任何 `sys_role_menu` 新授权：平台超管走 `*:*:*`；其它角色需管理员显式授权。
//! 存量库的 4148 文案由 `initialize::ensure_flow_report_menus` 同口径幂等收敛。

use sea_orm_migration::prelude::*;

pub struct Migration;

const OLD_4148_REMARK: &str =
    "G-01 大屏查看/保存/删除入口（save/view 同权限键，M2 前端上线时翻转可见）";
const NEW_4148_REMARK: &str = "G-01 大屏查看入口（写权限见「大屏编辑」「大屏删除」按钮）";

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261026_000002_report_dashboard_write_perm"
    }
}

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
        let conn = manager.get_connection();
        let backend = conn.get_database_backend();
        let now = crate::seed_now_expr();
        for (menu_id, name, order_num, perms, remark) in [
            (
                4149_i64,
                "大屏编辑",
                1_i64,
                "report:dashboard:edit",
                "大屏新增/保存按钮（写权限）",
            ),
            (
                4150_i64,
                "大屏删除",
                2_i64,
                "report:dashboard:remove",
                "大屏删除按钮（写权限）",
            ),
        ] {
            conn.execute_unprepared(&idempotent_insert(
                backend,
                &format!(
                    "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, \
                     route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, \
                     create_by, create_time, remark, del_flag) VALUES \
                     ({menu_id}, '{name}', 4148, {order_num}, '', '', '', '', '1', '0', 'F', \
                     '1', '0', '{perms}', '#', 'admin', {now}, '{remark}', '0')"
                ),
            ))
            .await?;
        }
        conn.execute_unprepared(&format!(
            "UPDATE sys_menu SET remark = '{NEW_4148_REMARK}' \
             WHERE menu_id = 4148 AND remark = '{OLD_4148_REMARK}'"
        ))
        .await?;
        conn.execute_unprepared(
            "DELETE FROM sys_role_menu WHERE role_id = 2 AND menu_id IN (4149, 4150)",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id IN (4149, 4150)")
            .await?;
        conn.execute_unprepared("DELETE FROM sys_menu WHERE menu_id IN (4149, 4150)")
            .await?;
        conn.execute_unprepared(&format!(
            "UPDATE sys_menu SET remark = '{OLD_4148_REMARK}' \
             WHERE menu_id = 4148 AND remark = '{NEW_4148_REMARK}'"
        ))
        .await?;
        Ok(())
    }
}
