// axum-backend/migration/src/m20260923_000002_flow_module.rs
//! 审批工作流模块迁移（方案 B′：`sys_flow_task` + `sys_flow_log` 两表，无 `flow_instance`）
//!
//! 设计依据：`docs/optimization/topic-workflow-approval-final-2026-09-23.md`（v5+第六/七轮）
//! - sys_flow_task  审批待办（唯一事实源：谁还没审）；冗余 title/applicant 供跨单据聚合列表
//!   - 唯一索引 (biz_type, biz_id, round_no, node_seq, assignee_id)（V4-E1：含类型与轮次维度）
//!   - round_no 轮次：退回重开/驳回后重新提交时 +1（V4-E4）
//! - sys_flow_log   审批流水（谁已审 + 意见；独立于日志保留期，永不参与 cleanup_expired_logs）
//! - flow_demo_doc  示例业务单据（请假申请）：承载完整审批链路的真实宿主
//! - sys_dept.leader_user_id 部门主管 user_id（原 leader 为姓名 String，无法定位审批人；V2-P0-5）
//!
//! 菜单：3600 段全新号（当前最大 3544，见 m20260820_000002_web_hook_module）；i18n_key 必填
//! 字典：dict_type 70/71/72 段（init 仅用 1-10），中英双语（dict_label_en）
//! 渠道：种 `site` 站内渠道（sys_msg_channel 此前无任何种子数据；V7-E2）
//! 模板：`flow_todo` 站内提醒模板（{{title}} 变量）
//!
//! 幂等：全部走 execute_idempotent_insert / CREATE TABLE IF NOT EXISTS / 判列存在再加列。

use sea_orm_migration::prelude::*;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite
    )
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

/// 当前时间表达式（跨数据库兼容）
fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        format!("'{}'", now)
    } else {
        "NOW()".to_string()
    }
}

/// 幂等 INSERT（跨库三方言）
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

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260923_000002_flow_module"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ==================== 1. 建表 ====================
        up_create_tables(manager).await?;

        // ==================== 2. sys_dept.leader_user_id（P0-5：主管可定位） ====================
        up_dept_leader_user_id(manager).await?;

        // ==================== 3. 索引 ====================
        up_indexes(manager).await?;

        // ==================== 4. 菜单（3600 段）+ 字典（70 段）+ 渠道/模板 ====================
        let now = now_expr(manager);

        // 4.1 M 目录「审批中心」（parent_id=1 系统管理；order_num=95）
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES \
                (3600, '审批中心', 1, 95, 'flow', 'ParentView', '', '', '1', '0', 'M', '0', '0', '', 'example', 'admin', {now}, '审批工作流', '0', 'route.flow')"
            ),
        )
        .await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 3600)")
            .await?;

        // 4.2 C 页面「审批中心」（待办 / 我发起 / 全部单据 三个 tab；component 对应前端视图）
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES \
                (3601, '审批中心', 3600, 1, 'todo', 'system/flow/index', '', '', '1', '0', 'C', '0', '0', 'system:flow:list', 'checkbox', 'admin', {now}, '审批待办/我发起/全部单据', '0', 'route.flowTodo')"
            ),
        )
        .await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 3601)")
            .await?;

        // 4.3 F 按钮（3601 下：全部单据查询/导出留待后续；本页核心接口均为仅登录个人数据接口）
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                (3611, '全部单据查询', 3601, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:flow:list', '#', 'admin', {now}, '', '0')"
            ),
        )
        .await?;
        execute_idempotent_insert(manager, "sys_role_menu (role_id, menu_id) VALUES (2, 3611)")
            .await?;

        // 4.4 字典 sys_flow_task_status（审批任务/单据状态；双语）
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_dict_type (dict_id, dict_name, dict_type, status, create_by, create_time, remark, del_flag) VALUES \
                (70, '审批状态', 'sys_flow_task_status', '0', 'admin', {now}, '审批任务与单据状态', '0')"
            ),
        )
        .await?;
        let status_rows: &[(i64, &str, &str, &str, &str)] = &[
            (700, "待审批", "pending", "warning", "To Approve"),
            (701, "已通过", "approved", "success", "Approved"),
            (702, "已驳回", "rejected", "danger", "Rejected"),
            (703, "已取消", "cancelled", "info", "Cancelled"),
            (704, "已转办", "transferred", "info", "Transferred"),
            (705, "已撤回", "withdrawn", "info", "Withdrawn"),
            (706, "草稿", "draft", "info", "Draft"),
        ];
        for (dict_code, label, value, css, label_en) in status_rows {
            execute_idempotent_insert(
                manager,
                &format!(
                    "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                    ({dict_code}, {dict_code}, '{label}', '{value}', 'sys_flow_task_status', '', '{css}', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
                ),
            )
            .await?;
        }

        // 4.5 字典 sys_flow_action（审批动作；双语）
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_dict_type (dict_id, dict_name, dict_type, status, create_by, create_time, remark, del_flag) VALUES \
                (71, '审批动作', 'sys_flow_action', '0', 'admin', {now}, '审批流水动作', '0')"
            ),
        )
        .await?;
        let action_rows: &[(i64, &str, &str, &str)] = &[
            (710, "提交", "submit", "To Submit"),
            (711, "同意", "approve", "Approve"),
            (712, "驳回", "reject", "Reject"),
            (713, "撤回", "withdraw", "Withdraw"),
            (714, "转办", "transfer", "Transfer"),
            (715, "超时提醒", "timeout_remind", "Timeout Remind"),
            (716, "自动通过", "auto_approve", "Auto Approve"),
        ];
        for (dict_code, label, value, label_en) in action_rows {
            execute_idempotent_insert(
                manager,
                &format!(
                    "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                    ({dict_code}, {dict_code}, '{label}', '{value}', 'sys_flow_action', '', 'info', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
                ),
            )
            .await?;
        }

        // 4.6 字典 sys_flow_leave_type（示例单据-请假类型；双语）
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_dict_type (dict_id, dict_name, dict_type, status, create_by, create_time, remark, del_flag) VALUES \
                (72, '请假类型', 'sys_flow_leave_type', '0', 'admin', {now}, '示例审批单据-请假类型', '0')"
            ),
        )
        .await?;
        let leave_rows: &[(i64, &str, &str, &str)] = &[
            (720, "年假", "annual", "Annual Leave"),
            (721, "病假", "sick", "Sick Leave"),
            (722, "事假", "personal", "Personal Leave"),
        ];
        for (dict_code, label, value, label_en) in leave_rows {
            execute_idempotent_insert(
                manager,
                &format!(
                    "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                    ({dict_code}, {dict_code}, '{label}', '{value}', 'sys_flow_leave_type', '', 'primary', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
                ),
            )
            .await?;
        }

        // 4.7 消息渠道种子：`site` 站内（此前 sys_msg_channel 无任何种子；V7-E2）
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_msg_channel (channel_name, channel_code, channel_type, config_json, status, remark, create_by, create_time, del_flag) VALUES \
                ('站内信', 'site', 'site', NULL, '0', '审批/系统站内提醒', 'admin', {now}, '0')"
            ),
        )
        .await?;

        // 4.8 消息模板种子：flow_todo（{{title}} 变量；channel_code=site）
        execute_idempotent_insert(
            manager,
            &format!(
                "sys_msg_template (template_name, template_code, channel_code, template_subject, template_content, status, remark, create_by, create_time, del_flag) VALUES \
                ('审批待办提醒', 'flow_todo', 'site', '您有新的审批待办', '单据「{{{{title}}}}」等待您审批，请及时处理。', '0', '审批待办站内提醒', 'admin', {now}, '0')"
            ),
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 菜单/字典/渠道/模板
        let menu_ids = [3600, 3601, 3611];
        for id in menu_ids {
            conn.execute_unprepared(&format!("DELETE FROM sys_role_menu WHERE menu_id = {}", id))
                .await?;
            conn.execute_unprepared(&format!("DELETE FROM sys_menu WHERE menu_id = {}", id))
                .await?;
        }
        conn.execute_unprepared(
            "DELETE FROM sys_dict_data WHERE dict_type IN ('sys_flow_task_status','sys_flow_action','sys_flow_leave_type')",
        )
        .await?;
        conn.execute_unprepared(
            "DELETE FROM sys_dict_type WHERE dict_type IN ('sys_flow_task_status','sys_flow_action','sys_flow_leave_type')",
        )
        .await?;
        conn.execute_unprepared("DELETE FROM sys_msg_template WHERE template_code = 'flow_todo'")
            .await?;
        conn.execute_unprepared("DELETE FROM sys_msg_channel WHERE channel_code = 'site'")
            .await?;
        // 表
        conn.execute_unprepared("DROP TABLE IF EXISTS flow_demo_doc")
            .await?;
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_flow_log")
            .await?;
        conn.execute_unprepared("DROP TABLE IF EXISTS sys_flow_task")
            .await?;
        Ok(())
    }
}

/// 建三张表（跨库兼容；列注释见文件头）
async fn up_create_tables(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let conn = manager.get_connection();

    // -------- sys_flow_task（审批待办：唯一事实源） --------
    let task_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_flow_task (
            task_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            biz_type       VARCHAR(64) NOT NULL,
            biz_id         BIGINT NOT NULL,
            round_no       INTEGER NOT NULL DEFAULT 1,
            node_seq       INTEGER NOT NULL,
            node_name      VARCHAR(64),
            assignee_id    BIGINT NOT NULL,
            task_type      VARCHAR(16) NOT NULL DEFAULT 'single',
            status         VARCHAR(16) NOT NULL DEFAULT 'pending',
            title          VARCHAR(200),
            applicant_id   BIGINT NOT NULL,
            applicant_name VARCHAR(64),
            comment        VARCHAR(500),
            acted_at       DATETIME,
            due_at         DATETIME,
            last_reminded_at DATETIME,
            tenant_id      BIGINT NOT NULL DEFAULT 0,
            create_by      VARCHAR(64),
            create_time    DATETIME,
            update_by      VARCHAR(64),
            update_time    DATETIME
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_flow_task (
            task_id        BIGSERIAL PRIMARY KEY,
            biz_type       VARCHAR(64) NOT NULL,
            biz_id         BIGINT NOT NULL,
            round_no       INTEGER NOT NULL DEFAULT 1,
            node_seq       INTEGER NOT NULL,
            node_name      VARCHAR(64),
            assignee_id    BIGINT NOT NULL,
            task_type      VARCHAR(16) NOT NULL DEFAULT 'single',
            status         VARCHAR(16) NOT NULL DEFAULT 'pending',
            title          VARCHAR(200),
            applicant_id   BIGINT NOT NULL,
            applicant_name VARCHAR(64),
            comment        VARCHAR(500),
            acted_at       TIMESTAMP,
            due_at         TIMESTAMP,
            last_reminded_at TIMESTAMP,
            tenant_id      BIGINT NOT NULL DEFAULT 0,
            create_by      VARCHAR(64),
            create_time    TIMESTAMP,
            update_by      VARCHAR(64),
            update_time    TIMESTAMP
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_flow_task (
            task_id        BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            biz_type       VARCHAR(64) NOT NULL,
            biz_id         BIGINT NOT NULL,
            round_no       INTEGER NOT NULL DEFAULT 1,
            node_seq       INTEGER NOT NULL,
            node_name      VARCHAR(64),
            assignee_id    BIGINT NOT NULL,
            task_type      VARCHAR(16) NOT NULL DEFAULT 'single',
            status         VARCHAR(16) NOT NULL DEFAULT 'pending',
            title          VARCHAR(200),
            applicant_id   BIGINT NOT NULL,
            applicant_name VARCHAR(64),
            comment        VARCHAR(500),
            acted_at       DATETIME,
            due_at         DATETIME,
            last_reminded_at DATETIME,
            tenant_id      BIGINT NOT NULL DEFAULT 0,
            create_by      VARCHAR(64),
            create_time    DATETIME,
            update_by      VARCHAR(64),
            update_time    DATETIME
        )"#
    };
    conn.execute_unprepared(task_sql).await?;

    // -------- sys_flow_log（审批流水：永不参与日志保留期清理） --------
    let log_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_flow_log (
            log_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            biz_type     VARCHAR(64) NOT NULL,
            biz_id       BIGINT NOT NULL,
            round_no     INTEGER NOT NULL DEFAULT 1,
            node_seq     INTEGER,
            action       VARCHAR(24) NOT NULL,
            from_status  VARCHAR(16),
            to_status    VARCHAR(16),
            operator_id  BIGINT,
            to_user_id   BIGINT,
            comment      VARCHAR(500),
            acted_at     DATETIME,
            tenant_id    BIGINT NOT NULL DEFAULT 0,
            create_by    VARCHAR(64),
            create_time  DATETIME,
            update_by    VARCHAR(64),
            update_time  DATETIME
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_flow_log (
            log_id       BIGSERIAL PRIMARY KEY,
            biz_type     VARCHAR(64) NOT NULL,
            biz_id       BIGINT NOT NULL,
            round_no     INTEGER NOT NULL DEFAULT 1,
            node_seq     INTEGER,
            action       VARCHAR(24) NOT NULL,
            from_status  VARCHAR(16),
            to_status    VARCHAR(16),
            operator_id  BIGINT,
            to_user_id   BIGINT,
            comment      VARCHAR(500),
            acted_at     TIMESTAMP,
            tenant_id    BIGINT NOT NULL DEFAULT 0,
            create_by    VARCHAR(64),
            create_time  TIMESTAMP,
            update_by    VARCHAR(64),
            update_time  TIMESTAMP
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_flow_log (
            log_id       BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            biz_type     VARCHAR(64) NOT NULL,
            biz_id       BIGINT NOT NULL,
            round_no     INTEGER NOT NULL DEFAULT 1,
            node_seq     INTEGER,
            action       VARCHAR(24) NOT NULL,
            from_status  VARCHAR(16),
            to_status    VARCHAR(16),
            operator_id  BIGINT,
            to_user_id   BIGINT,
            comment      VARCHAR(500),
            acted_at     DATETIME,
            tenant_id    BIGINT NOT NULL DEFAULT 0,
            create_by    VARCHAR(64),
            create_time  DATETIME,
            update_by    VARCHAR(64),
            update_time  DATETIME
        )"#
    };
    conn.execute_unprepared(log_sql).await?;

    // -------- flow_demo_doc（示例业务单据：请假申请） --------
    let doc_sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS flow_demo_doc (
            doc_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            title            VARCHAR(200) NOT NULL,
            applicant_id     BIGINT NOT NULL,
            applicant_name   VARCHAR(64),
            dept_id          BIGINT,
            leave_type       VARCHAR(16) NOT NULL DEFAULT 'annual',
            days             INTEGER NOT NULL DEFAULT 1,
            reason           VARCHAR(500),
            flow_mode        VARCHAR(16) NOT NULL DEFAULT 'single',
            status           VARCHAR(16) NOT NULL DEFAULT 'draft',
            current_round    INTEGER NOT NULL DEFAULT 0,
            current_node_seq INTEGER,
            submitted_at     DATETIME,
            finished_at      DATETIME,
            tenant_id        BIGINT NOT NULL DEFAULT 0,
            create_by        VARCHAR(64),
            create_time      DATETIME,
            update_by        VARCHAR(64),
            update_time      DATETIME
        )"#
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS flow_demo_doc (
            doc_id           BIGSERIAL PRIMARY KEY,
            title            VARCHAR(200) NOT NULL,
            applicant_id     BIGINT NOT NULL,
            applicant_name   VARCHAR(64),
            dept_id          BIGINT,
            leave_type       VARCHAR(16) NOT NULL DEFAULT 'annual',
            days             INTEGER NOT NULL DEFAULT 1,
            reason           VARCHAR(500),
            flow_mode        VARCHAR(16) NOT NULL DEFAULT 'single',
            status           VARCHAR(16) NOT NULL DEFAULT 'draft',
            current_round    INTEGER NOT NULL DEFAULT 0,
            current_node_seq INTEGER,
            submitted_at     TIMESTAMP,
            finished_at      TIMESTAMP,
            tenant_id        BIGINT NOT NULL DEFAULT 0,
            create_by        VARCHAR(64),
            create_time      TIMESTAMP,
            update_by        VARCHAR(64),
            update_time      TIMESTAMP
        )"#
    } else {
        r#"CREATE TABLE IF NOT EXISTS flow_demo_doc (
            doc_id           BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            title            VARCHAR(200) NOT NULL,
            applicant_id     BIGINT NOT NULL,
            applicant_name   VARCHAR(64),
            dept_id          BIGINT,
            leave_type       VARCHAR(16) NOT NULL DEFAULT 'annual',
            days             INTEGER NOT NULL DEFAULT 1,
            reason           VARCHAR(500),
            flow_mode        VARCHAR(16) NOT NULL DEFAULT 'single',
            status           VARCHAR(16) NOT NULL DEFAULT 'draft',
            current_round    INTEGER NOT NULL DEFAULT 0,
            current_node_seq INTEGER,
            submitted_at     DATETIME,
            finished_at      DATETIME,
            tenant_id        BIGINT NOT NULL DEFAULT 0,
            create_by        VARCHAR(64),
            create_time      DATETIME,
            update_by        VARCHAR(64),
            update_time      DATETIME
        )"#
    };
    conn.execute_unprepared(doc_sql).await?;
    Ok(())
}

/// sys_dept.leader_user_id（判定列存在再加，跨库 ALTER）
async fn up_dept_leader_user_id(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    if manager.has_column("sys_dept", "leader_user_id").await? {
        return Ok(());
    }
    // 跨库统一语法：ALTER TABLE ... ADD COLUMN <col> BIGINT（sqlite/pg/mysql 兼容）
    manager
        .get_connection()
        .execute_unprepared("ALTER TABLE sys_dept ADD COLUMN leader_user_id BIGINT")
        .await?;
    // 回填：现有部门主管统一指向 admin（user_id=1），保证「部门主管审批」链路可跑通
    manager
        .get_connection()
        .execute_unprepared("UPDATE sys_dept SET leader_user_id = 1 WHERE leader_user_id IS NULL")
        .await?;
    Ok(())
}

/// 索引（唯一索引含 biz_type + round_no；assignee 过滤索引供待办列表）
async fn up_indexes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let conn = manager.get_connection();
    // mysql 不支持 CREATE INDEX IF NOT EXISTS；迁移由 seaql_migrations 保证只执行一次
    let ine = if is_postgres(manager) || is_sqlite(manager) {
        "IF NOT EXISTS "
    } else {
        ""
    };
    let normal = [
        // 待办列表（assignee + status）
        "idx_flow_task_assignee ON sys_flow_task (assignee_id, status)",
        // 超时扫描（status + due_at）
        "idx_flow_task_due ON sys_flow_task (status, due_at)",
        // 流水时间线
        "idx_flow_log_biz ON sys_flow_log (biz_type, biz_id, round_no)",
        // 示例单据（发起人列表 + 状态过滤）
        "idx_flow_doc_applicant ON flow_demo_doc (applicant_id, status)",
    ];
    for stmt in normal {
        conn.execute_unprepared(&format!("CREATE INDEX {ine}{stmt}"))
            .await?;
    }
    // 幂等唯一键（V4-E1：biz_type + round_no 维度）
    conn.execute_unprepared(&format!(
        "CREATE UNIQUE INDEX {ine}uk_flow_task_biz ON sys_flow_task (biz_type, biz_id, round_no, node_seq, assignee_id)"
    ))
    .await?;
    Ok(())
}
