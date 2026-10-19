// stepby-axum/migration/src/migrations/m20261003_000002_webhook_event.rs
//! 开放域集成迁移（Webhook 事件目录 + 订阅过滤 + AK/SK）：
//!
//! 1. 建表 sys_webhook_event（事件目录，跨 sqlite/postgres/mysql 兼容，幂等）：
//!    - id              自增主键
//!    - event_key       事件键（user.created 等，UNIQUE NOT NULL）
//!    - name            事件名称（展示用）
//!    - description     事件说明
//!    - payload_example 负载样例（JSON 文本，test-send 用其构造真实投递）
//!    - enabled         '1'=启用 '0'=停用
//!    - created_at / updated_at
//! 2. 种子事件 16 个（真实业务事件源盘点）：
//!    user.created/updated/deleted、role.created/updated/deleted、
//!    login.success/failed、tenant.created/disabled、config.updated、dict.updated、
//!    notice.published、job.executed/failed、webhook.test
//! 3. 加列（幂等，NULL 兼容存量行）：
//!    - sys_web_hook.subscribed_events TEXT NULL（NULL/空=订阅全部，兼容存量）
//!    - sys_web_hook_log.source VARCHAR(16) NULL（NULL=事件派发，'test'=手动测试发送）
//!    - sys_pat.access_key VARCHAR(32) NULL + secret_key VARCHAR(255) NULL
//!      （AK/SK 开放 API 凭据；SK 信封加密存储，跟随 oauth client_secret 机制）
//! 4. 索引：uk_sys_pat_access_key（AK 鉴权查库，唯一）
//! 5. 菜单按钮：sys_menu 3562「事件目录」(system:webhook:event:list) /
//!    3563「测试发送」(system:webhook:test-send)，挂回调配置页面 158 下，授予 role_id=2。
//!
//! ## 口径
//!
//! 与既有迁移同款：幂等（CREATE TABLE IF NOT EXISTS / 列存在性检查 / INSERT 去重）；
//! 索引 DDL 经 IndexDdlExt 容错 MySQL「索引已存在」。
//! `initialize/mod.rs` 兜底片段（存量库不跑 Migrator::up）由集成方追加，见交付报告。

use crate::IndexDdlExt;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::Statement;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261003_000002_webhook_event"
    }
}

fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite
    )
}

fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

/// 种子时间表达式（批七十四 B1：归口到 `crate::seed_now_expr`，三方言统一 UTC 字面量）。
/// 本函数只是委托，**不得**在此另拼时间 ⇒ 换库/换时区不再换口径。
fn now_expr(_manager: &SchemaManager<'_>) -> String {
    crate::seed_now_expr()
}

/// 幂等 INSERT（种子数据按唯一约束去重）
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        format!("INSERT OR IGNORE INTO {}", body)
    } else if is_postgres(manager) {
        format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
    } else {
        format!("INSERT IGNORE INTO {}", body)
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

/// 幂等检查列是否存在（三方言；与 initialize::sso_has_column 同口径）
async fn has_column(manager: &SchemaManager<'_>, table: &str, column: &str) -> Result<bool, DbErr> {
    let conn = manager.get_connection();
    let backend = conn.get_database_backend();
    let rows = match backend {
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
            conn.query_all_raw(Statement::from_string(
                backend,
                format!("PRAGMA table_info({table})"),
            ))
            .await?
        }
        _ => {
            let schema = if is_postgres(manager) {
                "table_schema=current_schema()"
            } else {
                "table_schema=DATABASE()"
            };
            conn.query_all_raw(Statement::from_string(
                backend,
                format!(
                    "SELECT 1 FROM information_schema.columns WHERE table_name='{table}' AND column_name='{column}' AND {schema} LIMIT 1"
                ),
            ))
            .await?
        }
    };
    if is_sqlite(manager) {
        Ok(rows.iter().any(|row| {
            row.try_get::<String>("", "name")
                .map(|n| n.eq_ignore_ascii_case(column))
                .unwrap_or(false)
        }))
    } else {
        Ok(!rows.is_empty())
    }
}

/// 幂等加列（表需已存在；列存在则跳过）
async fn add_column_if_absent(
    manager: &SchemaManager<'_>,
    table: &str,
    column: &str,
    ddl: &str,
) -> Result<(), DbErr> {
    if has_column(manager, table, column).await? {
        return Ok(());
    }
    manager
        .get_connection()
        .execute_unprepared(&format!("ALTER TABLE {table} ADD COLUMN {ddl}"))
        .await?;
    Ok(())
}

/// 幂等检查表是否存在（三方言）
async fn table_exists(manager: &SchemaManager<'_>, table: &str) -> Result<bool, DbErr> {
    let conn = manager.get_connection();
    let backend = conn.get_database_backend();
    let sql = match backend {
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
            format!("SELECT 1 FROM sqlite_master WHERE type='table' AND name='{table}'")
        }
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres => format!(
            "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema=current_schema() LIMIT 1"
        ),
        sea_orm_migration::sea_orm::DatabaseBackend::MySql => format!(
            "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema=DATABASE() LIMIT 1"
        ),
        _ => unreachable!("unknown backend"),
    };
    Ok(!conn
        .query_all_raw(Statement::from_string(backend, sql))
        .await?
        .is_empty())
}

/// 种子事件（event_key, name, description, payload_example）
///
/// payload_example 为真实字段样例：emit_event 各接入点的实际 payload 与此对齐，
/// test-send 直接以本样例构造真实出站投递（含 HMAC 签名）。
/// **单一事实源**：迁移 up 与 initialize 兜底（原 WEBHOOK_SEED_EVENTS 手抄副本已删除）
/// 共用本常量。
pub const WEBHOOK_SEED_EVENTS: &[(&str, &str, &str, &str)] = &[
    (
        "user.created",
        "用户创建",
        "新用户创建成功后触发（sys_user 新增事务提交后）",
        r#"{"userId":1,"userName":"admin","nickName":"超级管理员","tenantId":0,"time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "user.updated",
        "用户修改",
        "用户信息修改成功后触发（sys_user 编辑事务提交后）",
        r#"{"userId":1,"userName":"admin","nickName":"超级管理员","tenantId":0,"time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "user.deleted",
        "用户删除",
        "用户删除成功后触发（软删 + 关联清理事务提交后）",
        r#"{"userId":1,"userName":"admin","tenantId":0,"time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "role.created",
        "角色创建",
        "新角色创建成功后触发（sys_role 新增事务提交后）",
        r#"{"roleId":2,"roleKey":"common","roleName":"普通角色","tenantId":0,"time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "role.updated",
        "角色修改",
        "角色信息/菜单授权修改成功后触发（sys_role 编辑事务提交后）",
        r#"{"roleId":2,"roleKey":"common","roleName":"普通角色","tenantId":0,"time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "role.deleted",
        "角色删除",
        "角色删除成功后触发（软删 + 关联清理事务提交后）",
        r#"{"roleId":2,"roleKey":"common","tenantId":0,"time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "login.success",
        "登录成功",
        "账号密码登录成功后触发（payload 含用户名/IP/租户）",
        r#"{"username":"admin","ip":"10.0.0.1","tenantId":0,"time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "login.failed",
        "登录失败",
        "账号密码登录失败后触发（payload 含用户名/IP/失败原因）",
        r#"{"username":"admin","ip":"10.0.0.1","reason":"用户名或密码错误","time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "tenant.created",
        "租户创建",
        "新租户创建成功后触发（sys_tenant 新增事务提交后）",
        r#"{"tenantId":2,"tenantName":"示例租户","time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "tenant.disabled",
        "租户停用",
        "租户被停用/到期后触发（运行时状态键切换时）",
        r#"{"tenantId":2,"tenantName":"示例租户","time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "config.updated",
        "参数修改",
        "系统参数配置修改成功后触发（sys_config 编辑后）",
        r#"{"configKey":"sys.account.captchaEnabled","configValue":"false","tenantId":0,"time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "dict.updated",
        "字典变更",
        "字典类型/字典数据变更成功后触发（sys_dict_* 编辑后）",
        r#"{"dictType":"sys_normal_disable","tenantId":0,"time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "notice.published",
        "公告发布",
        "通知公告发布成功后触发（sys_notice 新增后）",
        r#"{"noticeId":1,"noticeTitle":"系统维护公告","noticeType":"1","tenantId":0,"time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "job.executed",
        "任务执行成功",
        "定时任务执行成功后触发（payload 含任务与调用目标）",
        r#"{"jobId":1,"jobName":"数据备份","invokeTarget":"backup.run","status":"0","time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "job.failed",
        "任务执行失败",
        "定时任务执行失败后触发（payload 含任务与错误信息）",
        r#"{"jobId":1,"jobName":"数据备份","invokeTarget":"backup.run","error":"连接超时","time":"2026-10-03 00:00:00"}"#,
    ),
    (
        "webhook.test",
        "回调测试",
        "回调配置手动测试发送时触发（test-send / test 通用样例事件）",
        r#"{"hookId":1,"hookName":"示例回调","eventKey":"webhook.test","time":"2026-10-03 00:00:00"}"#,
    ),
];

// ==================== 单一事实源（迁移 up 与 initialize 兜底共用） ====================
//
// 存量库不跑 Migrator::up，`initialize/mod.rs::ensure_webhook_event_tables` 每次启动
// 幂等兜底。建表 SQL / 索引 / 加列 DDL / 种子事件 / 菜单按钮全部以本文件导出项为准
// （initialize 侧原手抄副本已删除，漂移在物理上不可能）。幂等前缀（INSERT OR IGNORE /
// ON CONFLICT / IGNORE）、索引容错与列存在性检查是执行机制而非 SQL 内容，
// 由两侧各自的执行器负责（迁移：execute_idempotent_insert / IndexDdlExt /
// add_column_if_absent；兜底：flow_insert / ensure_tenant_index / sso_has_column）。

/// webhook 域索引（迁移与兜底共用）
///
/// 元组：(索引名, 表名, 列清单, 是否唯一)。`sys_pat` 上的索引两侧均在
/// "表存在"前提下执行（极老存量库可能没有该表）。
pub const WEBHOOK_INDEXES: &[(&str, &str, &str, bool)] = &[
    (
        "uk_sys_webhook_event_key",
        "sys_webhook_event",
        "event_key",
        true,
    ),
    ("uk_sys_pat_access_key", "sys_pat", "access_key", true),
];

/// 加列 DDL 片段（迁移与兜底共用；列存在性检查各侧自持）
/// sys_web_hook.subscribed_events：JSON 数组字符串；NULL/空 = 订阅全部（兼容存量行为）
pub const WEB_HOOK_SUBSCRIBED_EVENTS_DDL: &str = "subscribed_events TEXT NULL";
/// sys_web_hook_log.source：NULL = 事件派发，'test' = 手动测试发送
pub const WEB_HOOK_LOG_SOURCE_DDL: &str = "source VARCHAR(16) NULL";
/// sys_pat.access_key：AK/SK 开放 API 凭据
pub const PAT_ACCESS_KEY_DDL: &str = "access_key VARCHAR(32) NULL";
/// sys_pat.secret_key：信封加密存储（跟随 oauth client_secret 的 CONFIG_ENC_KEY 机制），
/// VARCHAR(255) 容纳密文
pub const PAT_SECRET_KEY_DDL: &str = "secret_key VARCHAR(255) NULL";

/// 三方言建表 SQL（迁移 up 与 initialize 兜底共用单一来源）
///
/// `id` 跨方言自增主键：SQLite INTEGER PRIMARY KEY / MySQL AUTO_INCREMENT / PG BIGSERIAL。
pub fn create_table_sql(backend: sea_orm_migration::sea_orm::DatabaseBackend) -> String {
    use sea_orm_migration::sea_orm::DatabaseBackend;
    let id_col = match backend {
        DatabaseBackend::Sqlite => "id INTEGER PRIMARY KEY AUTOINCREMENT",
        DatabaseBackend::Postgres => "id BIGSERIAL PRIMARY KEY",
        DatabaseBackend::MySql => "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        _ => unreachable!("unknown backend"),
    };
    format!(
        "CREATE TABLE IF NOT EXISTS sys_webhook_event (
            {id_col},
            event_key       VARCHAR(64) NOT NULL,
            name            VARCHAR(64) NOT NULL,
            description     VARCHAR(255) NULL,
            payload_example TEXT NULL,
            enabled         CHAR(1) NOT NULL DEFAULT '1',
            created_at      TIMESTAMP NULL,
            updated_at      TIMESTAMP NULL
        )"
    )
}

/// 种子事件 INSERT 语句体（不含幂等前缀——迁移 execute_idempotent_insert /
/// 兜底 flow_insert 各自拼接，语义等价）
///
/// 单引号防御性转义（payload_example 含 JSON 双引号无需处理；描述含单引号场景防御）。
pub fn webhook_event_seed_bodies(now_expr: &str) -> Vec<String> {
    let esc = |s: &str| s.replace('\'', "''");
    WEBHOOK_SEED_EVENTS
        .iter()
        .map(|(event_key, name, desc, example)| {
            format!(
                "sys_webhook_event (event_key, name, description, payload_example, enabled, created_at, updated_at) VALUES \
                ('{}', '{}', '{}', '{}', '1', {now_expr}, {now_expr})",
                esc(event_key),
                esc(name),
                esc(desc),
                esc(example),
            )
        })
        .collect()
}

/// webhook 菜单按钮种子列清单（迁移与兜底共用）
pub const WEBHOOK_MENU_COLS: &str = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag)";

/// 菜单按钮种子行（结构化元组，迁移与兜底共用）
///
/// 元组：(menu_id, menu_name, parent_id, order_num, perms, icon, remark)
/// 挂「回调配置」页面（menu_id=158）下，F 按钮形态。
pub const WEBHOOK_MENU_ROWS: &[(i64, &str, i64, i64, &str, &str, &str)] = &[
    (
        3562,
        "事件目录",
        158,
        1,
        "system:webhook:event:list",
        "list",
        "WebHook 事件目录查询",
    ),
    (
        3563,
        "测试发送",
        158,
        2,
        "system:webhook:test-send",
        "message",
        "按事件样例构造真实测试发送",
    ),
];

/// 菜单按钮角色关联（role_id=2 平台普通角色 common）
pub const WEBHOOK_MENU_ROLE_ID: i64 = 2;

/// 菜单按钮 INSERT 语句体（不含幂等前缀，语义同上）
///
/// 返回顺序：菜单 3562 → role_menu(2,3562) → 菜单 3563 **无 role_menu**。
/// b73 轮 15：授权行按 [`governance::common_role_may_grant`] 过滤——3563「测试发送」
/// 会构造**真实出站投递**（`system:webhook:test-send`），属越权面，不再默认授予 common
/// （§8.2 只读姿态）；3562 事件目录查询为 `:list` 只读，照常授予。
pub fn webhook_menu_seed_bodies(now_expr: &str) -> Vec<String> {
    let mut bodies = Vec::with_capacity(WEBHOOK_MENU_ROWS.len() * 2);
    for (menu_id, name, parent_id, order_num, perms, icon, remark) in WEBHOOK_MENU_ROWS {
        bodies.push(format!(
            "{WEBHOOK_MENU_COLS} VALUES \
            ({menu_id}, '{name}', {parent_id}, {order_num}, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '{icon}', 'admin', {now_expr}, '{remark}', '0')"
        ));
        if governance::common_role_may_grant(*menu_id, "F", perms) {
            bodies.push(format!(
                "sys_role_menu (role_id, menu_id) VALUES ({WEBHOOK_MENU_ROLE_ID}, {menu_id})"
            ));
        }
    }
    bodies
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表 sys_webhook_event（单一事实源） ====================
        let backend = manager.get_connection().get_database_backend();
        manager
            .get_connection()
            .execute_unprepared(&create_table_sql(backend))
            .await?;

        // ==================== 2. 加列（单一事实源 DDL；幂等，存量行 NULL 兼容） ====================
        // sys_web_hook.subscribed_events：JSON 数组字符串；NULL/空 = 订阅全部（兼容存量行为）
        if table_exists(manager, "sys_web_hook").await? {
            add_column_if_absent(
                manager,
                "sys_web_hook",
                "subscribed_events",
                WEB_HOOK_SUBSCRIBED_EVENTS_DDL,
            )
            .await?;
        }
        // sys_web_hook_log.source：NULL=事件派发，'test'=手动测试发送
        if table_exists(manager, "sys_web_hook_log").await? {
            add_column_if_absent(
                manager,
                "sys_web_hook_log",
                "source",
                WEB_HOOK_LOG_SOURCE_DDL,
            )
            .await?;
        }
        // sys_pat.access_key / secret_key：AK/SK 开放 API 凭据
        // SK 信封加密存储（跟随 oauth client_secret 的 CONFIG_ENC_KEY 机制），VARCHAR(255) 容纳密文
        if table_exists(manager, "sys_pat").await? {
            add_column_if_absent(manager, "sys_pat", "access_key", PAT_ACCESS_KEY_DDL).await?;
            add_column_if_absent(manager, "sys_pat", "secret_key", PAT_SECRET_KEY_DDL).await?;
        }

        // ==================== 3. 索引（单一事实源；幂等） ====================
        // 加列之后执行：uk_sys_pat_access_key 依赖 access_key 列已存在。
        // sys_webhook_event 刚建表必存在；sys_pat 不存在（极老存量库）时跳过。
        // MySQL 不支持 CREATE INDEX IF NOT EXISTS（run 38328469439 实证）——
        // 方言分支：MySQL 发裸语句，重复场景由 IndexDdlExt 容错"已存在"兜底。
        for (idx_name, table, cols, unique) in WEBHOOK_INDEXES {
            if !table_exists(manager, table).await? {
                continue;
            }
            let unique_kw = if *unique { "UNIQUE " } else { "" };
            let ine = match manager.get_connection().get_database_backend() {
                sea_orm::DatabaseBackend::MySql => "",
                _ => "IF NOT EXISTS ",
            };
            manager
                .get_connection()
                .execute_index_ddl_ic(&format!(
                    "CREATE {unique_kw}INDEX {ine}{idx_name} ON {table} ({cols})"
                ))
                .await?;
        }

        // ==================== 4. 种子事件（单一事实源） ====================
        let now = now_expr(manager);
        for body in webhook_event_seed_bodies(&now) {
            execute_idempotent_insert(manager, &body).await?;
        }

        // ==================== 5. 菜单按钮权限（单一事实源） ====================
        // 事件目录列表 / 测试发送，挂「回调配置」页面（menu_id=158）下，授予超管角色 role_id=2
        for body in webhook_menu_seed_bodies(&now) {
            execute_idempotent_insert(manager, &body).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 菜单 id 从种子行单一事实源推导（3562/3563）
        let menu_ids = WEBHOOK_MENU_ROWS
            .iter()
            .map(|(id, ..)| id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_role_menu WHERE menu_id IN ({menu_ids})"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_menu WHERE menu_id IN ({menu_ids})"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_webhook_event")
            .await?;
        Ok(())
    }
}
