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

fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        format!("'{}'", now)
    } else {
        "NOW()".to_string()
    }
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
async fn has_column(
    manager: &SchemaManager<'_>,
    table: &str,
    column: &str,
) -> Result<bool, DbErr> {
    let conn = manager.get_connection();
    let backend = conn.get_database_backend();
    let rows = match backend {
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
            conn.query_all(Statement::from_string(
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
            conn.query_all(Statement::from_string(
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
    };
    Ok(!conn
        .query_all(Statement::from_string(backend, sql))
        .await?
        .is_empty())
}

/// 种子事件（event_key, name, description, payload_example）
///
/// payload_example 为真实字段样例：emit_event 各接入点的实际 payload 与此对齐，
/// test-send 直接以本样例构造真实出站投递（含 HMAC 签名）。
const SEED_EVENTS: &[(&str, &str, &str, &str)] = &[
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

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表 sys_webhook_event ====================
        // id 跨方言自增主键：SQLite INTEGER PRIMARY KEY / MySQL AUTO_INCREMENT / PG BIGSERIAL
        let id_col = if is_sqlite(manager) {
            "id INTEGER PRIMARY KEY AUTOINCREMENT"
        } else if is_postgres(manager) {
            "id BIGSERIAL PRIMARY KEY"
        } else {
            "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY"
        };
        let create_sql = format!(
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
        );
        manager
            .get_connection()
            .execute_unprepared(&create_sql)
            .await?;
        // event_key 唯一索引（幂等；MySQL 经 IndexDdlExt 容错"索引已存在"）
        manager
            .get_connection()
            .execute_index_ddl_ic(
                "CREATE UNIQUE INDEX IF NOT EXISTS uk_sys_webhook_event_key ON sys_webhook_event (event_key)",
            )
            .await?;

        // ==================== 2. 种子事件 ====================
        let now = now_expr(manager);
        for (event_key, name, desc, example) in SEED_EVENTS {
            // 单引号转义（payload_example 含 JSON 双引号，无需处理；描述含单引号场景防御性替换）
            let esc = |s: &str| s.replace('\'', "''");
            execute_idempotent_insert(
                manager,
                &format!(
                    "sys_webhook_event (event_key, name, description, payload_example, enabled, created_at, updated_at) VALUES \
                    ('{}', '{}', '{}', '{}', '1', {now}, {now})",
                    esc(event_key),
                    esc(name),
                    esc(desc),
                    esc(example),
                ),
            )
            .await?;
        }

        // ==================== 3. 加列（幂等，存量行 NULL 兼容） ====================
        // sys_web_hook.subscribed_events：JSON 数组字符串；NULL/空 = 订阅全部（兼容存量行为）
        if table_exists(manager, "sys_web_hook").await? {
            add_column_if_absent(
                manager,
                "sys_web_hook",
                "subscribed_events",
                "subscribed_events TEXT NULL",
            )
            .await?;
        }
        // sys_web_hook_log.source：NULL=事件派发，'test'=手动测试发送
        if table_exists(manager, "sys_web_hook_log").await? {
            add_column_if_absent(
                manager,
                "sys_web_hook_log",
                "source",
                "source VARCHAR(16) NULL",
            )
            .await?;
        }
        // sys_pat.access_key / secret_key：AK/SK 开放 API 凭据
        // SK 信封加密存储（跟随 oauth client_secret 的 CONFIG_ENC_KEY 机制），VARCHAR(255) 容纳密文
        if table_exists(manager, "sys_pat").await? {
            add_column_if_absent(manager, "sys_pat", "access_key", "access_key VARCHAR(32) NULL")
                .await?;
            add_column_if_absent(manager, "sys_pat", "secret_key", "secret_key VARCHAR(255) NULL")
                .await?;
            // AK 鉴权查库唯一索引
            manager
                .get_connection()
                .execute_index_ddl_ic(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uk_sys_pat_access_key ON sys_pat (access_key)",
                )
                .await?;
        }

        // ==================== 4. 菜单按钮权限 ====================
        // 事件目录列表 / 测试发送，挂「回调配置」页面（menu_id=158）下，授予超管角色 role_id=2
        const BTN_EVENT_LIST_ID: i64 = 3562;
        const BTN_TEST_SEND_ID: i64 = 3563;
        const PARENT_PAGE_ID: i64 = 158;

        let btn_event = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            ({BTN_EVENT_LIST_ID}, '事件目录', {PARENT_PAGE_ID}, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:webhook:event:list', 'list', 'admin', {now}, 'WebHook 事件目录查询', '0')"
        );
        execute_idempotent_insert(manager, &btn_event).await?;
        execute_idempotent_insert(
            manager,
            &format!("sys_role_menu (role_id, menu_id) VALUES (2, {BTN_EVENT_LIST_ID})"),
        )
        .await?;

        let btn_test = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            ({BTN_TEST_SEND_ID}, '测试发送', {PARENT_PAGE_ID}, 2, '', '', '', '', '1', '0', 'F', '0', '0', 'system:webhook:test-send', 'message', 'admin', {now}, '按事件样例构造真实测试发送', '0')"
        );
        execute_idempotent_insert(manager, &btn_test).await?;
        execute_idempotent_insert(
            manager,
            &format!("sys_role_menu (role_id, menu_id) VALUES (2, {BTN_TEST_SEND_ID})"),
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        const BTN_EVENT_LIST_ID: i64 = 3562;
        const BTN_TEST_SEND_ID: i64 = 3563;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_role_menu WHERE menu_id IN ({BTN_EVENT_LIST_ID}, {BTN_TEST_SEND_ID})"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_menu WHERE menu_id IN ({BTN_EVENT_LIST_ID}, {BTN_TEST_SEND_ID})"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_webhook_event")
            .await?;
        Ok(())
    }
}
