// stepby-axum/migration/src/migrations/m20261012_000001_config_governance_and_archive_menus.rs
//! 批五十六（数据治理第三轮种子漂移审计）：config 治理种子修正 + 归档按钮菜单补种
//!
//! 发现路径：以 initialize 兜底路径构建纯种子临时库，与生产库逐行逐列 diff（种子漂移审计）。
//!
//! # 1. 皮肤/主题键治理列（真实种子缺陷）
//!
//! `sys.index.skinName` / `sys.index.sideTheme` 在 init 迁移（m20250711）中插入时
//! 未指定治理列 → 列默认 fail-closed `platform_only`。但产品语义上皮肤/主题是
//! **租户个性化项**（tenant override 能力位的设计载体）：
//! - e2e 功能 72 的「租户覆盖 platform_default 键」以 skinName 为标准载体，
//!   前置断言即要求 `scope='platform_default' && tenant_editable='1'`；
//! - 2026-09-26 部分更新语义修复的注释亦以「skinName 被静默降级为 platform_only
//!   ⇒ 功能 72 断言 403」为缺陷叙事。
//!
//! 即：**全新部署的库该键恒为 platform_only，功能 72 在新库必失败**——种子与
//! 产品语义冲突，以本迁移落定 `platform_default`/可覆盖/可见。
//!
//! # 2. 归档按钮菜单补种（批次十九手工遗漏）
//!
//! 「审计归档下载」(4180, perms=monitor:operlogArchive:download) 与「链完整性校验」
//! (4181, perms=monitor:operlogArchive:verify) 为批次十九（链感知保留）的功能按钮
//! 菜单（F 型，挂「操作日志」500 之下），2026-10-08 以菜单管理页手工创建，
//! **未登记种子** → 全新部署缺失两个功能入口。本迁移按生产行逐列复刻
//! （INSERT OR IGNORE；role_menu 授权为部署决策，不随种子）。
//!
//! # 幂等性
//!
//! UPDATE 为终态赋值（重复执行零影响）；INSERT OR IGNORE 按主键防重。
//! 兜底边界：治理 UPDATE 不镜像进 initialize 兜底（避免每次启动覆盖管理员
//! 后续治理变更——迁移版本号保证恰执行一次）；菜单 INSERT 在
//! `initialize/menu.rs::ensure_archive_menus` 幂等镜像（对齐
//! ensure_ai_history_menu_parent 先例）。

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // 1. 皮肤/主题键 → 租户可覆盖（平台默认层，platform_default 语义）
        db.execute_unprepared(
            "UPDATE sys_config SET scope = 'platform_default', tenant_editable = '1', \
             visible_to_tenant = '1' \
             WHERE config_key IN ('sys.index.skinName', 'sys.index.sideTheme') AND tenant_id = 0",
        )
        .await?;

        // 2. 归档按钮菜单补种（F 型按钮，挂「操作日志」500 之下；逐列复刻生产行）
        // 幂等前缀按方言分支（INSERT OR IGNORE 为 SQLite 专属——run 38328469439 实证）
        // b83：`create_time` 不再交给 `CURRENT_TIMESTAMP`（SQLite 落 UTC、MySQL/PG 落会话时区，
        // 本机 PG 容器 TZ=Asia/Shanghai 实测差 8 小时），改绑应用侧 UTC 时钟——
        // 与启动兜底 `initialize/menu.rs::ensure_archive_menus` 逐字同口径（两处是镜像关系）。
        let now = chrono::Utc::now()
            .naive_utc()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        let seed_body = format!(
            "\
             (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, \
              is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, \
              remark, del_flag) \
             VALUES \
             (4180, '审计归档下载', 500, 4, '#', '', '', '', '1', '0', 'F', '0', '0', \
              'monitor:operlogArchive:download', '#', 'admin', '{now}', \
              '链感知保留：归档对象下载（平台专属，monitor:operlogArchive: 前缀）', '0'), \
             (4181, '链完整性校验', 500, 5, '#', '', '', '', '1', '0', 'F', '0', '0', \
              'monitor:operlogArchive:verify', '#', 'admin', '{now}', \
              '批次十九收尾：verify-chain 收紧平台专属（原复用 monitor:operlog:query，租户可见即泄漏全平台链统计）', '0')"
        );
        let seed_sql = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::Sqlite => {
                format!("INSERT OR IGNORE INTO sys_menu {seed_body}")
            }
            sea_orm::DatabaseBackend::Postgres => {
                format!("INSERT INTO sys_menu {seed_body} ON CONFLICT DO NOTHING")
            }
            _ => format!("INSERT IGNORE INTO sys_menu {seed_body}"),
        };
        db.execute_unprepared(&seed_sql).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        // 治理回落 fail-closed 缺省；菜单行删除（种子回滚）
        db.execute_unprepared(
            "UPDATE sys_config SET scope = 'platform_only', tenant_editable = '0', \
             visible_to_tenant = '0' \
             WHERE config_key IN ('sys.index.skinName', 'sys.index.sideTheme') AND tenant_id = 0",
        )
        .await?;
        db.execute_unprepared("DELETE FROM sys_menu WHERE menu_id IN (4180, 4181)")
            .await?;
        Ok(())
    }
}
