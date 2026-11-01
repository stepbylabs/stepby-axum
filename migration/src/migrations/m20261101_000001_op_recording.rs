// stepby-axum/migration/src/migrations/m20261101_000001_op_recording.rs
//! 操作录制与回放（Operation Recording & Replay）——建表 + 菜单 + 最小授权。
//!
//! ## 立项事实
//!
//! 本仓此前**没有任何"把用户操作存下来再执行一遍"的能力**（全仓 `录制` / `replay` 生产码
//! 零命中，`sys_task` 只是进度看板，`sys_http_debug` 是一次性手工转发）。于是"这条业务
//! 流程在我这里能跑通，在客户环境跑不通"只能靠人来复述，复述必然丢参数、丢顺序、丢前置
//! 条件；回归时也只能靠人再点一遍。
//!
//! ## 三张表的分工（不是把步骤塞进一个 JSON 列）
//!
//! - `sys_op_recording`：一次录制的抬头（名称/来源/状态/步数/最近一次运行结论）。
//! - `sys_op_recording_step`：步骤明细。**独立成表**的理由是回放要按 `seq` 单步取、
//!   单步改（跳过某步、改期望状态码）、单步断言；塞进 JSON 列则每次改动都是整份重写，
//!   并发两步追加会互相覆盖（`(recording_id, seq)` 唯一约束在这里是判据而不是装饰）。
//! - `sys_op_recording_run`：一次回放的结论（成功/失败/部分成功 + 逐步骤结局）。
//!   **不复用 `sys_task.result_msg`**：任务进度行是"人要看的进度"，一次回放有 N 条步骤
//!   结论，塞进 1000 字符的消息列等于把结构化事实压成一句话，事后无法归因是哪一步坏了。
//!   两张表通过 `task_id` 关联，进度看板照旧、明细在这里。
//!
//! ## 多租户与权限（立项第一问）
//!
//! - 三张表都带 `tenant_id`，写入取**操作者租户**（`Operator::tenant_id()`），读侧一律经
//!   `tenant_scope(...)` 收敛：平台（tid=0）可见全部，租户只见自己的行。
//! - 录制是**租户级工具**（每个租户录自己的业务流程），因此 perms 前缀取 `tool:recording:`
//!   ——它**不在** `PLATFORM_ONLY_PERM_PREFIXES` 里，与 `tool:gen:` / `tool:httpDebug:` 的
//!   平台专属判定不冲突（那两条判的是"能改全局定义"与"能对任意地址出站"）。
//! - 授权只给 `role_id=2`（租户管理员模板源）**读面**：页面 + `query`，且必须走
//!   `governance::common_role_grant_select_body` 策略体（AGENTS 铁律：禁止裸
//!   `VALUES (2, id)`，棘轮只许下降）。写权限（add/edit/remove/replay/record）
//!   **不发放**给 common——replay 是对本租户执行任意已录写请求，属"能改变数据"的动作，
//!   按 AGENTS 全局铁律 2 只能由管理员显式授予。
//!
//! 菜单号段：**4200-4207**。此前误用 4000-4002，与 `m20261003_000001_audit_change`
//! 的「变更留痕」页面/按钮撞号，幂等插入按主键冲突静默跳过 ⇒ 页面菜单根本没建、
//! 而 `menu_perm_contract` 立刻报 `tool:recording:list/query/add` 无法授予。
//! 4200 段经全仓扫描确认空闲（4000-4002 归 audit_change，4100-4180 归租户/平台模块）。
//!
//! 幂等：建表 `IF NOT EXISTS`、索引 `execute_index_ddl_ic`、菜单 `INSERT OR IGNORE` /
//! `ON CONFLICT DO NOTHING`，重复执行 0 行。

use crate::IndexDdlExt;
use governance::common_role_grant_select_body;
use sea_orm_migration::prelude::*;

pub struct Migration;

/// 页面菜单（系统工具目录下的"操作录制"）
const PAGE_MENU_ID: i64 = 4200;
/// 系统工具目录
const PARENT_DIR_ID: i64 = 3;
/// 只读按钮：查询录制详情
const BTN_QUERY_ID: i64 = 4201;
/// 写按钮：新建录制
const BTN_ADD_ID: i64 = 4202;
/// 写按钮：编辑录制/步骤
const BTN_EDIT_ID: i64 = 4203;
/// 写按钮：删除录制
const BTN_REMOVE_ID: i64 = 4204;
/// 写按钮：回放执行
const BTN_REPLAY_ID: i64 = 4205;
/// 写按钮：导出脚本（会带出请求体，属数据出口）
const BTN_EXPORT_ID: i64 = 4206;
/// 写按钮：把请求记录进某个录制（中间件采集开关）
const BTN_RECORD_ID: i64 = 4207;

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

async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        format!("INSERT OR IGNORE INTO {body}")
    } else if is_postgres(manager) {
        format!("INSERT INTO {body} ON CONFLICT DO NOTHING")
    } else {
        format!("INSERT IGNORE INTO {body}")
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261101_000001_op_recording"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();

        // ---------- ① 录制抬头 ----------
        let recording_sql = if is_sqlite(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_op_recording (
                recording_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id       BIGINT NOT NULL DEFAULT 0,
                name            VARCHAR(120) NOT NULL,
                description     VARCHAR(500),
                source          VARCHAR(16) NOT NULL DEFAULT 'ui',
                status          VARCHAR(16) NOT NULL DEFAULT 'ready',
                step_count      INTEGER NOT NULL DEFAULT 0,
                last_run_status VARCHAR(16),
                last_run_time   DATETIME,
                owner_id        BIGINT,
                owner_name      VARCHAR(64),
                create_time     DATETIME,
                update_time     DATETIME
            )"#
        } else if is_postgres(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_op_recording (
                recording_id    BIGSERIAL PRIMARY KEY,
                tenant_id       BIGINT NOT NULL DEFAULT 0,
                name            VARCHAR(120) NOT NULL,
                description     VARCHAR(500),
                source          VARCHAR(16) NOT NULL DEFAULT 'ui',
                status          VARCHAR(16) NOT NULL DEFAULT 'ready',
                step_count      INTEGER NOT NULL DEFAULT 0,
                last_run_status VARCHAR(16),
                last_run_time   TIMESTAMP,
                owner_id        BIGINT,
                owner_name      VARCHAR(64),
                create_time     TIMESTAMP,
                update_time     TIMESTAMP
            )"#
        } else {
            r#"CREATE TABLE IF NOT EXISTS sys_op_recording (
                recording_id    BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                tenant_id       BIGINT NOT NULL DEFAULT 0,
                name            VARCHAR(120) NOT NULL,
                description     VARCHAR(500),
                source          VARCHAR(16) NOT NULL DEFAULT 'ui',
                status          VARCHAR(16) NOT NULL DEFAULT 'ready',
                step_count      INTEGER NOT NULL DEFAULT 0,
                last_run_status VARCHAR(16),
                last_run_time   DATETIME,
                owner_id        BIGINT,
                owner_name      VARCHAR(64),
                create_time     DATETIME,
                update_time     DATETIME
            )"#
        };
        conn.execute_unprepared(recording_sql).await?;

        // ---------- ② 步骤明细 ----------
        let step_sql = if is_sqlite(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_op_recording_step (
                step_id       INTEGER PRIMARY KEY AUTOINCREMENT,
                recording_id  BIGINT NOT NULL,
                tenant_id     BIGINT NOT NULL DEFAULT 0,
                seq           INTEGER NOT NULL,
                method        VARCHAR(10) NOT NULL,
                path          VARCHAR(512) NOT NULL,
                query_string  VARCHAR(2048),
                content_type  VARCHAR(120),
                body          TEXT,
                headers_json  TEXT,
                extract_json  TEXT,
                expect_status INTEGER,
                note          VARCHAR(200),
                create_time   DATETIME
            )"#
        } else if is_postgres(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_op_recording_step (
                step_id       BIGSERIAL PRIMARY KEY,
                recording_id  BIGINT NOT NULL,
                tenant_id     BIGINT NOT NULL DEFAULT 0,
                seq           INTEGER NOT NULL,
                method        VARCHAR(10) NOT NULL,
                path          VARCHAR(512) NOT NULL,
                query_string  VARCHAR(2048),
                content_type  VARCHAR(120),
                body          TEXT,
                headers_json  TEXT,
                extract_json  TEXT,
                expect_status INTEGER,
                note          VARCHAR(200),
                create_time   TIMESTAMP
            )"#
        } else {
            r#"CREATE TABLE IF NOT EXISTS sys_op_recording_step (
                step_id       BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                recording_id  BIGINT NOT NULL,
                tenant_id     BIGINT NOT NULL DEFAULT 0,
                seq           INTEGER NOT NULL,
                method        VARCHAR(10) NOT NULL,
                path          VARCHAR(512) NOT NULL,
                query_string  VARCHAR(2048),
                content_type  VARCHAR(120),
                body          TEXT,
                headers_json  TEXT,
                extract_json  TEXT,
                expect_status INTEGER,
                note          VARCHAR(200),
                create_time   DATETIME
            )"#
        };
        conn.execute_unprepared(step_sql).await?;

        // ---------- ③ 运行结论 ----------
        let run_sql = if is_sqlite(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_op_recording_run (
                run_id       INTEGER PRIMARY KEY AUTOINCREMENT,
                recording_id BIGINT NOT NULL,
                tenant_id    BIGINT NOT NULL DEFAULT 0,
                task_id      BIGINT,
                status       VARCHAR(16) NOT NULL,
                total        INTEGER NOT NULL DEFAULT 0,
                succeeded    INTEGER NOT NULL DEFAULT 0,
                failed       INTEGER NOT NULL DEFAULT 0,
                skipped      INTEGER NOT NULL DEFAULT 0,
                detail_json  TEXT,
                operator     VARCHAR(64),
                started_at   DATETIME,
                finished_at  DATETIME
            )"#
        } else if is_postgres(manager) {
            r#"CREATE TABLE IF NOT EXISTS sys_op_recording_run (
                run_id       BIGSERIAL PRIMARY KEY,
                recording_id BIGINT NOT NULL,
                tenant_id    BIGINT NOT NULL DEFAULT 0,
                task_id      BIGINT,
                status       VARCHAR(16) NOT NULL,
                total        INTEGER NOT NULL DEFAULT 0,
                succeeded    INTEGER NOT NULL DEFAULT 0,
                failed       INTEGER NOT NULL DEFAULT 0,
                skipped      INTEGER NOT NULL DEFAULT 0,
                detail_json  TEXT,
                operator     VARCHAR(64),
                started_at   TIMESTAMP,
                finished_at  TIMESTAMP
            )"#
        } else {
            r#"CREATE TABLE IF NOT EXISTS sys_op_recording_run (
                run_id       BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                recording_id BIGINT NOT NULL,
                tenant_id    BIGINT NOT NULL DEFAULT 0,
                task_id      BIGINT,
                status       VARCHAR(16) NOT NULL,
                total        INTEGER NOT NULL DEFAULT 0,
                succeeded    INTEGER NOT NULL DEFAULT 0,
                failed       INTEGER NOT NULL DEFAULT 0,
                skipped      INTEGER NOT NULL DEFAULT 0,
                detail_json  TEXT,
                operator     VARCHAR(64),
                started_at   DATETIME,
                finished_at  DATETIME
            )"#
        };
        conn.execute_unprepared(run_sql).await?;

        // ---------- ④ 索引 ----------
        // (recording_id, seq) 唯一：并发两步追加不得写出同序号（回放顺序是判据，不是展示）
        conn.execute_index_ddl_ic(
            "CREATE UNIQUE INDEX uk_op_recording_step_seq ON sys_op_recording_step (recording_id, seq)",
        )
        .await?;
        conn.execute_index_ddl_ic(
            "CREATE INDEX idx_op_recording_tenant ON sys_op_recording (tenant_id)",
        )
        .await?;
        conn.execute_index_ddl_ic(
            "CREATE INDEX idx_op_recording_step_rid ON sys_op_recording_step (recording_id)",
        )
        .await?;
        conn.execute_index_ddl_ic(
            "CREATE INDEX idx_op_recording_run_rid ON sys_op_recording_run (recording_id)",
        )
        .await?;

        // ---------- ⑤ 菜单 ----------
        let now = crate::seed_now_expr();
        let page_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, \
             is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
             ({PAGE_MENU_ID}, '操作录制', {PARENT_DIR_ID}, 10, 'recording', 'tool/recording/index', '', '', \
             '1', '0', 'C', '0', '0', 'tool:recording:list', 'video', 'admin', {now}, \
             '录制用户操作并可回放（HTTP 边界采集 + 脚本导出）', '0')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;

        // 菜单标题走 i18n（`i18n_key` 列由 m20260725_000002 引入，nullable）。
        // 值必须是**前端语言包里已存在的键**：`sys_menu.i18n_key` 的约定是 `menu.*`
        // （见 locales/zh-CN/system.ts 的 `menu` 表），`useMenuTitle` 用 `t(key)`
        // 翻译、未命中才回退 menu_name——写 `route.opRecording` 在这条链上找不到词条。
        // 单独一条 UPDATE 而不塞进 INSERT：列清单一旦变化，那条 INSERT 会在旧库上失败；
        // 这里只按"仍是空值"守卫，幂等且不覆盖管理员改过的标题。
        conn.execute_unprepared(&format!(
            "UPDATE sys_menu SET i18n_key = 'menu.opRecording' \
             WHERE menu_id = {PAGE_MENU_ID} AND (i18n_key IS NULL OR i18n_key = '')"
        ))
        .await?;

        // 按钮：menu_type='F'，parent 指向页面
        let buttons: [(i64, &str, &str, i32); 7] = [
            (BTN_QUERY_ID, "录制详情", "tool:recording:query", 1),
            (BTN_ADD_ID, "新建录制", "tool:recording:add", 2),
            (BTN_EDIT_ID, "编辑录制", "tool:recording:edit", 3),
            (BTN_REMOVE_ID, "删除录制", "tool:recording:remove", 4),
            (BTN_REPLAY_ID, "回放执行", "tool:recording:replay", 5),
            (BTN_EXPORT_ID, "导出脚本", "tool:recording:export", 6),
            (BTN_RECORD_ID, "采集开关", "tool:recording:record", 7),
        ];
        for (id, name, perm, order) in buttons {
            let sql = format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, \
                 is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                 ({id}, '{name}', {PAGE_MENU_ID}, {order}, '', '', '', '', '1', '0', 'F', '0', '0', '{perm}', '#', 'admin', {now}, '', '0')"
            );
            execute_idempotent_insert(manager, &sql).await?;
        }

        // ---------- ⑥ 授权：common 只拿读面，且必须走治理策略体 ----------
        // 策略体自己套 `common_role_grant_where`（M/C 全放行 + F 只放 ":list/:query/:view/:center"），
        // 所以把写按钮 id 一起传进来也不会产生越权授权——判据落在数据层而不是调用方自觉。
        // 这也是棘轮（`fallback_grants_never_use_bare_common_role_values`）唯一的合法写法：
        // 裸 `VALUES (2, id)` 每加一处就把棘轮往上顶，而棘轮只许下降。
        execute_idempotent_insert(
            manager,
            &common_role_grant_select_body(&[PAGE_MENU_ID, BTN_QUERY_ID]),
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let all_ids = [
            PAGE_MENU_ID,
            BTN_QUERY_ID,
            BTN_ADD_ID,
            BTN_EDIT_ID,
            BTN_REMOVE_ID,
            BTN_REPLAY_ID,
            BTN_EXPORT_ID,
            BTN_RECORD_ID,
        ];
        let list = all_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute_unprepared(&format!(
            "DELETE FROM sys_role_menu WHERE menu_id IN ({list})"
        ))
        .await?;
        conn.execute_unprepared(&format!("DELETE FROM sys_menu WHERE menu_id IN ({list})"))
            .await?;
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_op_recording_run")
            .await?;
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_op_recording_step")
            .await?;
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_op_recording")
            .await?;
        Ok(())
    }
}
