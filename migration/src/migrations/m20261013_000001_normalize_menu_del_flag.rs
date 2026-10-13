// stepby-axum/migration/src/migrations/m20261013_000001_normalize_menu_del_flag.rs
//! 批次六十四：统一菜单软删标记（`del_flag` 双表示收敛为 `'2'`）
//!
//! 缺陷（回库取证，批六十四）：
//! - 应用层删除菜单写入 `del_flag = '2'`（`sys_menu_service::delete_menu`），
//!   详情/删除守卫亦以 `== "2"` 判定"已删"；
//! - 但 `m20261007_000011_config_seed_and_menu_hygiene`（批十四菜单卫生）对手工软删的
//!   3800-3804（域名按钮重复组）与 4115（AI 历史冗余死页面）写的是 `del_flag = '1'`
//!   ——一个**应用从不写入、也无任何代码消费**的取值。
//!
//! 影响（真实、但低危）：
//! - 列表/树查询过滤 `del_flag = '0'` ⇒ `'1'` 与 `'2'` 均被隐藏，**无用户可见影响**；
//! - 但 `get_menu_by_id` 只在 `== "2"` 时返回 404 ⇒ 对 `del_flag='1'` 的"已删"菜单
//!   **`GET /system/menu/{id}` 仍可取回**（已删数据可被直连 API 读取）——与"软删即不可见"
//!   的语义不一致；`delete_menu` 守卫同理不识别 `'1'`。
//!
//! 修复：把历史遗留的 `del_flag = '1'` 归一为应用约定值 `'2'`，使"已删"表示单值化，
//! 详情/删除守卫对历史软删行同样生效。
//!
//! 多租户与权限（全局铁律第一问）：
//! - 本迁移**只改 del_flag 取值**，不改菜单可见范围（`'1'`→`'2'` 前后均被 `= '0'` 过滤隐藏）、
//!   不改 perms/parent/path/component ⇒ 权限契约与租户可见性零变化；
//! - 3800-3804 的 role_menu 已在批十四清理，4115 的 role_menu 由 m20261007_000011 删除，
//!   本迁移不涉及授权行。
//!
//! 存量库兜底：`initialize` 的 `ensure_menu_del_flag_normalized`（幂等 UPDATE）。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 幂等：仅归一 `'1'` 遗留值（重复执行 / 新库已为 '2' 时为空操作）。
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_menu SET del_flag = '2' WHERE del_flag = '1'")
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // 不可逆语义：'2' 与 '1' 在修复后不可区分（均为"已删"），down 为空操作。
        Ok(())
    }
}
