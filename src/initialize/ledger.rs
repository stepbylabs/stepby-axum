// stepby-axum/src/initialize/ledger.rs

use sea_orm::DatabaseConnection;

// ==================== 2026-10-03 三迁移兜底（audit_change / webhook_event / alert_rule） ====================
// 存量库不跑 `Migrator::up`，以下三个兜底函数与迁移共享**单一事实源**：
// 建表 SQL / 索引清单 / 加列 DDL / 种子数据全部抽在各迁移文件导出的 pub 常量与函数中，
// 本侧仅引用（原手抄 DDL/种子副本已删除，漂移物理不可能）。
// 全部幂等：建表 IF NOT EXISTS、索引经 ensure_tenant_index（MySQL 查 statistics 判存在）、
// 加列前 sso_has_column 检查、种子走 flow_insert（三方言 INSERT OR IGNORE / ON CONFLICT / IGNORE）。

/// 审计合规域兜底（等价迁移 `m20261003_000001_audit_change`）：
/// - 建表 `sys_audit_change`（业务数据变更留痕，三方言幂等）
/// - 三个审计查询索引（row / time / tenant）
/// - `sys_oper_log.chain_hash` 列存在性检查加列（操作日志 HMAC-SHA256 防篡改链；
///   NULL = 未入链，校验接口跳过 NULL 行不误报）
/// - 菜单种子幂等：变更留痕页面 4000 + 按钮 4001/4002 + role_menu(role_id=2)
pub(crate) async fn ensure_audit_change_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    // 单一事实源：迁移文件导出的建表 SQL / 索引 / 加列 DDL / 菜单种子
    use migration::m20261003_000001_audit_change as mig;

    let backend = db.get_database_backend();

    // 1) 建表（引用迁移 create_table_sql，三方言分支收敛于迁移文件）
    flow_exec(db, mig::create_table_sql(backend)).await?;

    // 2) 三个审计查询索引（引用迁移 AUDIT_INDEXES；ensure_tenant_index 委托
    //    migration::ensure_index_ddl：三方言都先探测存在性再建，不分岔、不吞错）
    for (name, table, cols) in mig::AUDIT_INDEXES {
        ensure_tenant_index(db, table, name, cols, false).await?;
    }

    // 3) sys_oper_log.chain_hash 列（DDL 片段引用迁移常量；表已存在才检查，
    //    极老空库由 migration 负责建表）
    if sso_table_exists(db, "sys_oper_log").await?
        && !sso_has_column(db, "sys_oper_log", "chain_hash").await?
    {
        tracing::info!("sys_oper_log 缺少 chain_hash 列，执行幂等 ALTER 添加");
        flow_exec(
            db,
            format!(
                "ALTER TABLE sys_oper_log ADD COLUMN {}",
                mig::OPER_LOG_CHAIN_HASH_DDL
            ),
        )
        .await?;
    }

    // 4) 菜单种子（引用迁移 audit_menu_seed_bodies；flow_insert 拼幂等前缀，
    //    与迁移 execute_idempotent_insert 语义等价）
    let now = flow_now(db);
    for body in mig::audit_menu_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    tracing::info!("审计合规域兜底完成（sys_audit_change / chain_hash / 菜单 4000-4002，幂等）");
    Ok(())
}

/// 开放域集成兜底（等价迁移 `m20261003_000002_webhook_event`）：
/// - 建表 `sys_webhook_event`（事件目录）+ event_key 唯一索引
/// - 16 个种子事件幂等 INSERT
/// - 加列（存在性检查）：sys_web_hook.subscribed_events / sys_web_hook_log.source /
///   sys_pat.access_key + secret_key（AK/SK 开放 API 凭据，SK 信封加密存 VARCHAR(255)）
/// - `uk_sys_pat_access_key` 唯一索引（AK 鉴权查库）
/// - 菜单按钮种子：事件目录 3562 / 测试发送 3563（挂回调配置页面 158，授予 role_id=2）
pub(crate) async fn ensure_webhook_event_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    // 单一事实源：迁移文件导出的建表 SQL / 索引 / 加列 DDL / 种子事件 / 菜单按钮
    // （原本地 WEBHOOK_SEED_EVENTS 手抄副本已删除；sys_web_hook_service.rs 侧不受影响）
    use migration::m20261003_000002_webhook_event as mig;
    use migration::m20261004_000002_webhook_event_edit as mig_edit;

    let backend = db.get_database_backend();

    // 1) 建表（引用迁移 create_table_sql）
    flow_exec(db, mig::create_table_sql(backend)).await?;

    // 2) 加列（DDL 片段引用迁移常量，表存在才检查；存量行 NULL 兼容）
    if sso_table_exists(db, "sys_web_hook").await?
        && !sso_has_column(db, "sys_web_hook", "subscribed_events").await?
    {
        flow_exec(
            db,
            format!(
                "ALTER TABLE sys_web_hook ADD COLUMN {}",
                mig::WEB_HOOK_SUBSCRIBED_EVENTS_DDL
            ),
        )
        .await?;
    }
    if sso_table_exists(db, "sys_web_hook_log").await?
        && !sso_has_column(db, "sys_web_hook_log", "source").await?
    {
        flow_exec(
            db,
            format!(
                "ALTER TABLE sys_web_hook_log ADD COLUMN {}",
                mig::WEB_HOOK_LOG_SOURCE_DDL
            ),
        )
        .await?;
    }
    if sso_table_exists(db, "sys_pat").await? {
        if !sso_has_column(db, "sys_pat", "access_key").await? {
            flow_exec(
                db,
                format!("ALTER TABLE sys_pat ADD COLUMN {}", mig::PAT_ACCESS_KEY_DDL),
            )
            .await?;
        }
        if !sso_has_column(db, "sys_pat", "secret_key").await? {
            flow_exec(
                db,
                format!("ALTER TABLE sys_pat ADD COLUMN {}", mig::PAT_SECRET_KEY_DDL),
            )
            .await?;
        }
    }

    // 3) 索引（引用迁移 WEBHOOK_INDEXES；在加列之后执行——uk_sys_pat_access_key
    //    依赖 access_key 列已存在。ensure_tenant_index 三方言幂等）
    for (name, table, cols, unique) in mig::WEBHOOK_INDEXES {
        if !sso_table_exists(db, table).await? {
            continue;
        }
        ensure_tenant_index(db, table, name, cols, *unique).await?;
    }

    // 4) 种子事件（引用迁移 webhook_event_seed_bodies；flow_insert 拼幂等前缀）
    let now = flow_now(db);
    for body in mig::webhook_event_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    // 5) 菜单按钮权限（引用迁移 webhook_menu_seed_bodies；
    //    挂「回调配置」页面 menu_id=158 下，授予超管角色 role_id=2）
    for body in mig::webhook_menu_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    // 6) 目录停用/启用按钮（引用迁移 webhook_event_edit_menu_bodies，m20261004_000002；
    //    同挂 menu_id=158 下，授予超管角色 role_id=2）
    for body in mig_edit::webhook_event_edit_menu_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    tracing::info!("Webhook 事件域兜底完成（sys_webhook_event / AK/SK 列 / 菜单 3562-3564，幂等）");
    Ok(())
}

/// Webhook 订阅双轨收敛兜底（等价迁移 `m20261003_000004_webhook_unify`）：
/// 存量 `event_types`（逗号口径）幂等转换为 `subscribed_events`（JSON 数组口径），
/// 仅处理 `subscribed_events IS NULL` 且 `event_types` 非空的行；事件名映射与
/// SQL 单一来源 = 迁移文件 `build_unify_update_sql`（与 service 的 LEGACY_EVENT_KEY_MAP
/// 由集成测试双向断言防漂移）。
pub(crate) async fn ensure_webhook_subscription_unify(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    // 表未建（极老空库）或缺列（迁移未跑过加列）时跳过——由迁移负责全新库
    if !sso_table_exists(db, "sys_web_hook").await? {
        tracing::info!("sys_web_hook 表不存在，跳过订阅收敛（由迁移负责全新库）");
        return Ok(());
    }
    if !sso_has_column(db, "sys_web_hook", "subscribed_events").await?
        || !sso_has_column(db, "sys_web_hook", "event_types").await?
    {
        tracing::info!("sys_web_hook 缺少 subscribed_events/event_types 列，跳过订阅收敛");
        return Ok(());
    }
    let backend = db.get_database_backend();
    let sql = migration::m20261003_000004_webhook_unify::build_unify_update_sql(backend);
    flow_exec(db, &sql).await?;
    tracing::info!("Webhook 订阅收敛完成（存量 event_types → subscribed_events，幂等）");
    Ok(())
}

/// 告警规则引擎兜底（等价迁移 `m20261003_000003_alert_rule`）：
/// - 建表 `sys_alert_rule`（三方言幂等；metric/comparator 白名单在 service 层校验）
/// - `idx_alert_rule_enabled` 索引（评估轮询按 enabled 过滤）
/// - 告警菜单种子：页面 4110（挂系统监控目录 2）+ 按钮 4111-4114（与
///   PERM_ROUTE_TABLE 对齐），页面对通用角色 role_id=2 可见
pub(crate) async fn ensure_alert_rule_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    // 单一事实源：迁移文件导出的建表 SQL / 索引 / 菜单种子
    use migration::m20261003_000003_alert_rule as mig;

    let backend = db.get_database_backend();

    // 1) 建表（引用迁移 create_table_sql）
    flow_exec(db, mig::create_table_sql(backend)).await?;

    // 2) enabled 过滤索引（引用迁移 ALERT_INDEXES；评估轮询用，三方言幂等）
    for (name, table, cols, unique) in mig::ALERT_INDEXES {
        ensure_tenant_index(db, table, name, cols, *unique).await?;
    }

    // 3) 菜单元数据（引用迁移 alert_menu_seed_bodies；perms 与 PERM_ROUTE_TABLE 对齐）
    let now = flow_now(db);
    for body in mig::alert_menu_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    tracing::info!("告警规则兜底完成（sys_alert_rule / enabled 索引 / 菜单 4110-4114，幂等）");
    Ok(())
}

/// 字段级权限 M2 兜底（等价迁移 `m20261003_000005_role_field_perm`）：
/// - 建表 `sys_role_field_perm`（角色字段权限矩阵，UNIQUE(role_id, table_key, field_key)）
/// - 角色查询索引 idx_role_field_perm_role
/// - 菜单种子幂等：角色管理按钮 4120（system:role:fieldPerm）/ 4121（fieldPermSave）
///   + role_menu(role_id=1)
/// - sys_config 种子幂等：平台开关 `sys.fieldPerm.enabled`（默认 'false' = 关闭态即安全态）
pub(crate) async fn ensure_role_field_perm_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    // 单一事实源：迁移文件导出的建表 SQL / 索引 / 菜单种子 / config 种子
    use migration::m20261003_000005_role_field_perm as mig;

    let backend = db.get_database_backend();

    // 1) 建表（引用迁移 create_table_sql；UNIQUE 约束随 IF NOT EXISTS 建表幂等）
    flow_exec(db, mig::create_table_sql(backend)).await?;

    // 2) 角色查询索引（引用迁移 ROLE_FIELD_PERM_INDEXES；ensure_tenant_index 三方言幂等）
    for (name, table, cols) in mig::ROLE_FIELD_PERM_INDEXES {
        ensure_tenant_index(db, table, name, cols, false).await?;
    }

    // 3) 菜单种子（引用迁移 field_perm_menu_seed_bodies；perms 与 PERM_ROUTE_TABLE 对齐）
    let now = flow_now(db);
    for body in mig::field_perm_menu_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    // 4) sys_config 平台开关种子（默认 'false'；幂等冲突忽略 = 保留运维已改的值）
    flow_insert(db, &mig::field_perm_config_seed_body(&now)).await?;

    tracing::info!(
        "字段级权限 M2 兜底完成（sys_role_field_perm / 菜单 4120-4121 / sys.fieldPerm.enabled，幂等）"
    );
    Ok(())
}

/// 报表看板兜底（等价迁移 `m20261003_000006_report_board`）：
/// - 建表 `sys_report_board`（配置化只读报表看板，UNIQUE(user_id, name)）
/// - 属主查询索引 idx_report_board_user
/// - 菜单种子幂等：系统工具目录 C 页面 4130（tool:reportBoard:list）/
///   F 按钮 4131（tool:reportBoard:save）+ role_menu(role_id=2)
pub(crate) async fn ensure_report_board_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    // 单一事实源：迁移文件导出的建表 SQL / 索引 / 菜单种子
    use migration::m20261003_000006_report_board as mig;

    let backend = db.get_database_backend();

    // 1) 建表（引用迁移 create_table_sql；UNIQUE 约束随 IF NOT EXISTS 建表幂等）
    flow_exec(db, mig::create_table_sql(backend)).await?;

    // 2) 属主查询索引（引用迁移 REPORT_BOARD_INDEXES；ensure_tenant_index 三方言幂等）
    for (name, table, cols) in mig::REPORT_BOARD_INDEXES {
        ensure_tenant_index(db, table, name, cols, false).await?;
    }

    // 3) 菜单种子（引用迁移 report_board_menu_seed_bodies；perms 与 PERM_ROUTE_TABLE 对齐）
    let now = flow_now(db);
    for body in mig::report_board_menu_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    tracing::info!("报表看板兜底完成（sys_report_board / 菜单 4130-4131，幂等）");
    Ok(())
}

use super::*;
