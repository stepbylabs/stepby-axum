// stepby-axum/migration/src/migrations/m20261018_000001_flow_action_dict.rs
//! 批次七十六：字典 `sys_flow_action` 补齐审批引擎真实可写入的三个动作
//!
//! ## 缺陷（机械取证，见 `docs/optimization/quality-batch-76-2026-10-19.md` §7 R-1）
//!
//! 审批引擎写入 `sys_flow_log.action` 的字面量全集为 9 个值（由
//! `sys_flow_service.rs` 的 `write_log(…)` 第 5 参数与 `action: Set("…")` 两处
//! 穷举得出）：
//! `submit / approve / reject / withdraw / transfer / delegate / countersign_add /
//! countersign_del / timeout_remind`。
//! 但 `m20260923_000002_flow_module` §4.5 与 `initialize::flow` 的字典种子只有
//! 7 个 `dict_value`（710-716），其中 `delegate / countersign_add / countersign_del`
//! **三个缺失**，另有一个引擎从不写入的预留值 `auto_approve`（716，登记为 R-4）。
//!
//! ## 影响
//!
//! - 字典管理页 `/system/dict/data?type=sys_flow_action` 的可选值少 3 个 ⇒ 任何按字典
//!   驱动的下拉过滤/翻译都解析不出这三个动作（前端页面当前用 i18n `flow.action.*`
//!   渲染标签，故**列表显示不受影响**；受影响的是"字典即真值"的下游：数据翻译导出、
//!   以字典为准的统计维度、运维按字典核对动作口径）；
//! - 更关键的是**契约漂移**：实体注释、前端类型联合、字典三处各自声明动作集合，
//!   没有任何机械门禁比对 ⇒ 加签/减签/委派上线时字典被漏掉，属可复现的同族缺陷。
//!
//! ## 修复
//!
//! 幂等补 3 行（717 `delegate`、718 `countersign_add`、719 `countersign_del`），
//! 双语标签与前端 i18n `flow.action.*` 逐字对齐；`initialize::flow` 的 `action_rows`
//! 同步补同三行（与 §4.5 同构）。回归锁为
//! `src/integration_tests/flow_action_dict.rs`：它先从 `sys_flow_service.rs` 穷举引擎
//! 实际写入的动作字面量（不硬编码清单），再查**迁移建出来的测试隔离库**字典值域做
//! 包含判定，并比对迁移/兜底两侧种子文本 ⇒ 三处任一漂移都直接判红。
//!
//! ## 多租户与权限（全局铁律第一问）
//!
//! - 只新增 `sys_dict_data` 三行，不改任何 `sys_menu.perms`、不授权、不改角色
//!   ⇒ 权限契约零变化；字典是平台级全局表（无 `tenant_id` 列），租户管理员本就
//!   可见全部字典类型，新增行不改变可见范围；
//! - 本迁移不碰 `auto_approve`：预留值问题（R-4）由后继迁移
//!   `m20261019_000001_flow_action_dict_drop_reserved` 单独收口并附数据取证，
//!   两条迁移各管一件事，回滚粒度才能对上问题粒度。

use sea_orm_migration::prelude::*;

pub struct Migration;

/// 种子时间表达式（批七十四 B1 口径：归口 `crate::seed_now_expr`，不得在此另拼时间）
fn now_expr(_manager: &SchemaManager<'_>) -> String {
    crate::seed_now_expr()
}

/// 幂等 INSERT（跨库三方言，与 `m20260923_000002_flow_module` 同一实现）
///
/// 用 if/else 而非 `match`：`DatabaseBackend` 是 `#[non_exhaustive]`，
/// 穷尽匹配三variants 会 E0004（sea-orm 加新后端时本迁移不该跟着改）。
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let backend = manager.get_connection().get_database_backend();
    let sql = if backend == sea_orm_migration::sea_orm::DatabaseBackend::Sqlite {
        format!("INSERT OR IGNORE INTO {}", body)
    } else if backend == sea_orm_migration::sea_orm::DatabaseBackend::Postgres {
        format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
    } else {
        format!("INSERT IGNORE INTO {}", body)
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261018_000001_flow_action_dict"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);
        // (dict_code, dict_label, dict_value, dict_label_en) —— 与 initialize::flow 逐字同构
        let rows: [(&str, &str, &str, &str); 3] = [
            ("717", "委托", "delegate", "Delegate"),
            ("718", "加签", "countersign_add", "Approver Added"),
            ("719", "减签", "countersign_del", "Approver Removed"),
        ];
        for (code, label, value, label_en) in rows {
            execute_idempotent_insert(
                manager,
                &format!(
                    "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                    ({code}, {code}, '{label}', '{value}', 'sys_flow_action', '', 'info', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
                ),
            )
            .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 可逆：这三行由本迁移新增，按主键精确删除，不触碰 710-716 与任何手工档位
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_dict_data WHERE dict_type = 'sys_flow_action' \
                 AND dict_value IN ('delegate','countersign_add','countersign_del')",
            )
            .await?;
        Ok(())
    }
}
