//! 运行监控「清空」按钮改挂写权限（批九十三 N-92-1）。
//!
//! 立项事实：`DELETE /monitor/slow-sql/clear` 与 `DELETE /monitor/error-log/clear`
//! 在 `PERM_ROUTE_TABLE` 里都挂在**读权限** `monitor:slowSql:list` 下，菜单 F 按钮 3551
//! 也使用同一读权限 ⇒ 任何只有"查看运行监控"权限的平台角色都能清空进程内缓冲。
//! 同页其它监控域的 clear/clean 端点全部使用写权限（`monitor:operlog:remove` /
//! `monitor:frontendError:remove` / `monitor:cache:clearName`…），本迁移把这条口径拉齐。
//!
//! 语句只做两件事，均按"仍是历史字面量"守卫 ⇒ 幂等：
//! 1. 菜单 3551 的 perms 由 `monitor:slowSql:list` 改为 `monitor:slowSql:remove`；
//! 2. 窄撤销 `role_id=2`（common，租户管理员菜单模板源）对 3551 的授权——写权限不得
//!    习惯性发放给 common（AGENTS 全局铁律 2），且 `monitor:slowSql:` 本身是平台专属前缀，
//!    `ensure_tenant_role_menu_governance` 在运行期同样会剔除它。存量 runtime 库已有治理
//!    兜底，不在 initialize 里重复挂回收（回收只允许挂在一次性迁移）。
//!
//! 不回填 `sys_role_menu` 新授权：平台超管走 `*:*:*`；其它平台角色需要清空能力时由管理员
//! 显式授权，这正是拆权限的目的。`down` 只还原 perms 字面量，不恢复 common 的写授权。

use sea_orm_migration::prelude::*;

pub struct Migration;

const BTN_MENU_ID: i64 = 3551;
const NEW_PERM: &str = "monitor:slowSql:remove";
const OLD_PERM: &str = "monitor:slowSql:list";

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261026_000001_observability_clear_perm"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(&format!(
            "UPDATE sys_menu SET perms = '{NEW_PERM}' WHERE menu_id = {BTN_MENU_ID} AND perms = '{OLD_PERM}'"
        ))
        .await?;
        conn.execute_unprepared(&format!(
            "DELETE FROM sys_role_menu WHERE role_id = 2 AND menu_id = {BTN_MENU_ID}"
        ))
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(&format!(
            "UPDATE sys_menu SET perms = '{OLD_PERM}' WHERE menu_id = {BTN_MENU_ID} AND perms = '{NEW_PERM}'"
        ))
        .await?;
        Ok(())
    }
}
