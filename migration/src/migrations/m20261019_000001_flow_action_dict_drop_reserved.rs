// stepby-axum/migration/src/migrations/m20261019_000001_flow_action_dict_drop_reserved.rs
//! 批次七十六 R-4：摘除字典 `sys_flow_action` 中引擎永不写入的预留值 `auto_approve`
//!
//! ## 缺陷（机械取证）
//!
//! `m20260923_000002_flow_module` §4.5 种下 7 个动作值，其中 `auto_approve`（dict_code 716）
//! **没有任何写入点**，三条独立证据：
//!
//! 1. 源码穷举：`src/integration_tests/flow_action_dict.rs` 从 `sys_flow_service.rs` 抽出的
//!    引擎可写动作全集为 9 个值，不含 `auto_approve`（`grep -rn '"auto_approve"' src/` 仅命中
//!    注释与字典种子两处，无 `write_log` / `action: Set` 实参）；
//! 2. 设计口径冲突：引擎在“节点唯一审批人就是提交人”时**显式 400 拒绝**
//!    （`sys_flow_service.rs:852` “剔除后为空 → 全链自审 → 调用层显式 400”），
//!    不存在“自动通过”这条产品语义，因此该值不是“待实现”，而是与既有设计相矛盾的残留；
//! 3. 数据事实：运行库（SQLite 193 MB、被 e2e 持续写入）`sys_flow_log` 的 action 分布为
//!    `submit / approve / withdraw / countersign_add / countersign_del`，
//!    `auto_approve` **0 行**（取证脚本 `C:\stepby-restore\_probe\flow_action_live.py`）
//!    ⇒ 删除字典行不改变任何历史流水的可读性。
//!
//! ## 影响
//!
//! - 字典是“动作域真值”的对外口径：留一个永不出现的枚举值，等于让字典与引擎各说一套。
//!   本批 R-1 的漂移（三个动作漏种）正是这种“两套真值并存”的产物；
//! - 更实的影响：`sys_flow_action` 是字典管理页 `/system/dict/data?type=sys_flow_action`
//!   的可见行，也是运维按字典核对审批口径的依据 ⇒ 运维会去找一个永远不会有的值。
//!
//! ## 修复
//!
//! 删除 `dict_type='sys_flow_action' AND dict_value='auto_approve'`（按 `dict_value` 精确命中，
//! 不触碰 710-715/717-719 与任何运维自定义行）。DELETE 天然幂等，重复执行 0 行受影响。
//! 同步收口四处同源声明：`initialize::flow` 兜底种子去掉 716 行、实体注释、前端
//! `api/flow.ts` 的 `action` 联合类型、i18n `flow.action.auto_approve`（zh/en）与
//! `flow/index.vue` 的 `auto_approve` 着色分支。
//! 回归锁升级为**双向**：`flow_action_dict.rs` 既要求“引擎动作 ⊆ 字典值”，也要求
//! “字典值 ⊆ 引擎动作”——以后往字典里塞“预留值”会当场判红，而不是像本条一样靠人肉发现。
//!
//! ## 多租户与权限（全局铁律第一问）
//!
//! - 只删一行字典数据，不动 `sys_menu.perms`、不授权、不改角色 ⇒ 权限契约零变化；
//!   字典是平台级全局表（无 `tenant_id`），删除对所有租户一致生效；
//! - 存量库需由运维执行迁移 CLI（`DATABASE_URL=… cargo run -p migration`）才会收敛：
//!   启动兜底只补漏、不删陈旧行，这是本仓“迁移/兜底两条独立路径”的既知形态。

use sea_orm_migration::prelude::*;

pub struct Migration;

/// 种子时间表达式（批七十四 B1 口径：归口 `crate::seed_now_expr`，不得在此另拼时间）
fn now_expr(_manager: &SchemaManager<'_>) -> String {
    crate::seed_now_expr()
}

/// 幂等 INSERT（跨库三方言，与 `m20261018_000001_flow_action_dict` 同一实现）
///
/// 用 if/else 而非 `match`：`DatabaseBackend` 是 `#[non_exhaustive]`，
/// 穷尽匹配三个 variants 会 E0004（sea-orm 加新后端时本迁移不该跟着改）。
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
        "m20261019_000001_flow_action_dict_drop_reserved"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_dict_data WHERE dict_type = 'sys_flow_action' \
                 AND dict_value = 'auto_approve'",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 可逆：仅还原本迁移删除的这一行（原 716 值逐字回种，双语标签沿用原种子文案）
        let now = now_expr(manager);
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                 (716, 716, '自动通过', 'auto_approve', 'sys_flow_action', '', 'info', 'N', '0', 'admin', {now}, '', '0', 'Auto Approve')"
            ),
        )
        .await?;
        Ok(())
    }
}
