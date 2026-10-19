// stepby-axum/migration/src/migrations/m20261017_000001_common_role_grant_erosion.rs
//! 批次七十三：回收平台普通角色（role_id=2 / `common`）的**写权限按钮侵蚀**
//!
//! ## 缺陷（b73 轮 15 机械取证）
//!
//! `m20260924_000010_common_role_readonly`（§8.2 安全发现修复）把 common 收紧为
//! "页面可见 + 只读按钮"。但收紧之后新增菜单的**迁移与 initialize 兜底**沿用 RuoYi
//! 上游习惯，把写权限按钮逐条授权给 common，判据散落十余处而没有任何一处引用收紧规则
//! ⇒ 种子逐批复潮。纯种子库（全新空库跑完整迁移 + 全部兜底）实测 12 条越权授权：
//!
//! | menu_id | perms | 语义 |
//! |---|---|---|
//! | 3561 | `monitor:pat:revoke` | 吊销**他人**个人访问令牌 |
//! | 3563 | `system:webhook:test-send` | 构造**真实出站投递** |
//! | 3564 | `system:webhook:event:edit` | 事件目录停用/启用 |
//! | 3620 | `system:scimgroup:edit` | 改"SCIM 组→角色/部门"映射＝间接提权 |
//! | 3621 | `system:scimgroup:remove` | 删组映射 |
//! | 4002 | `system:audit-change:export` | 导出审计留痕（数据外泄面） |
//!
//! 另外 6 条（4131 `tool:reportBoard:save`、4142-4145 `flow:definition:*`、
//! 4147 `report:dataset:edit`）属**例外**：作用域限本人或受能力位（默认 off）封顶，
//! 批次十三 用户拍板保留，现逐条登记在 `COMMON_ROLE_WRITE_EXCEPTIONS`。
//!
//! 对照真值：运行库（e2e 前置按 §8.2 收紧后）为 0 条 ⇒ `scripts/seed_diff.py` 报
//! "漂移 12"。两侧判据不一致，**且没有任何机械门禁能发现**——因为种子侧一直在漂。
//!
//! ## 根因与本轮口径
//!
//! 根因不是"某个迁移写错了"，而是**判据没有单一事实源**。本轮把策略收进
//! `governance::common_role_*`（只读后缀集合 + 例外登记 + SQL 子句 + Rust 谓词），
//! 并让所有 common 授权点改走策略体：
//! - 迁移侧：`audit_change` / `webhook_event` / `webhook_event_edit` / `report_board` /
//!   `sys_pat` / `flow_report_role_menus` 种子生成按策略过滤或改 `INSERT … SELECT`；
//! - 兜底侧：`initialize::{menu, scim, flow, tenant}` 的 role_menu 补授全部改走
//!   `governance::common_role_grant_select_body`；
//! - 本迁移：对**已经跑过迁移的部署**做一次窄撤销，让升级路径同样收敛到策略终态。
//!
//! ## 为何用"窄撤销"而非全量重排
//!
//! [`governance::common_role_erosion_sql`] 只 `DELETE` 违反策略的授权行，不重排、
//! 不新增 ⇒ 管理员在角色授权页手工勾选的**页面 / 只读按钮**授权一律保留（全量
//! DELETE+INSERT 会把它们一起抹掉）。写权限按钮被回收是本次安全收紧的目的，
//! 需要保留者可在管理端重新勾选（升级公告见 `deploy/README.md`）。
//!
//! ## 多租户与权限（全局铁律第一问）
//!
//! - **权限**：只影响 role_id=2 的 `sys_role_menu` 行，不改 `sys_menu.perms` 契约、
//!   不改 `PERM_ROUTE_TABLE`、不改角色本身；超管经 `isAdmin` 特判不依赖授权行，
//!   租户管理员角色（`tenant_id <> 0`）由套餐白名单 + 各自授权决定，本迁移不触碰。
//! - **多租户**：common 是"新建租户默认管理员角色"的菜单模板复制源
//!   （`sys_tenant_service::tenant_role_menu_ids`）⇒ 回收后新租户管理员同样拿不到
//!   这 6 个越权 perms，与租户隔离预期一致；租户自助能力按钮的补齐仍由
//!   `ensure_tenant_role_menu_governance` ② 负责，本迁移不影响该链路。
//! - **例外保留**：6 条例外逐条登记在 `COMMON_ROLE_WRITE_EXCEPTIONS`（带理由），
//!   与批次十三 拍板等价，未砍任何能力（开源"能力全备、默认安全"准则）。
//!
//! ## 存量库兜底：刻意**没有** ensure 孪生
//!
//! 回收类语句若挂到每次启动，会把管理员事后手工勾选的写按钮反复砍掉（静默摧毁运营
//! 意图），与 AGENTS《开关类能力设计规范》第 6 条"存量授权回收只在显式动作触发"一致。
//! 因此不跑 `Migrator::up` 的存量库保持现状，由运维在管理端按需收紧（已登记
//! `docs/SECURITY.md` 与批七十三台账）。schema 等价性总锁只比 schema 与
//! 菜单/字典/参数种子键集，不含 `sys_role_menu` ⇒ 本迁移不触发该锁。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 幂等：第二次执行影响 0 行（判据来自 governance 单一事实源，不在本文件复制）
        manager
            .get_connection()
            .execute_unprepared(&governance::common_role_erosion_sql())
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // 不回滚：回收的授权行无法区分"种子误发"与"管理员手工勾选"，
        // 反向恢复等于把越权面重新打开。需要写权限的部署请在管理端重新授权。
        Ok(())
    }
}
