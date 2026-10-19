// stepby-axum/src/initialize/flow.rs

use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, Statement};

// ==================== 审批工作流模块（flow_module）存量库兜底 ====================
// 与迁移 m20260923_000002_flow_module 等价：三表 + 索引 + 菜单/字典/渠道/模板种子。
// DDL 与种子 SQL 必须与迁移保持同步（双写惯例，参照 ensure_sys_pat_table）；
// 所有种子依赖主键/唯一键（menu_id/dict_code/channel_code/template_code UNIQUE）幂等，
// 每次启动重复执行不产生重复行。

/// 幂等执行一条 SQL（flow 双写内部用；错误向上传播由调用方统一 anyhow 包装）
pub(crate) async fn flow_exec(
    db: &DatabaseConnection,
    sql: impl Into<String>,
) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        sql.into(),
    ))
    .await
    .map(|_| ())
}

/// 三方言幂等 INSERT 前缀（对齐迁移 execute_idempotent_insert）
pub(crate) fn flow_insert_prefix(backend: DatabaseBackend) -> &'static str {
    match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        _ => "INSERT IGNORE INTO ",
    }
}

/// 三方言幂等 INSERT 后缀（仅 PostgreSQL 需要 ON CONFLICT）
pub(crate) fn flow_insert_suffix(backend: DatabaseBackend) -> &'static str {
    if backend == DatabaseBackend::Postgres {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    }
}

/// 幂等 INSERT（body 为 "表名 (列...) VALUES (...)" 形式，与迁移 execute_idempotent_insert 同构）
pub(crate) async fn flow_insert(db: &DatabaseConnection, body: &str) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let sql = format!(
        "{}{}{}",
        flow_insert_prefix(backend),
        body,
        flow_insert_suffix(backend)
    );
    flow_exec(db, sql).await
}

/// flow 种子用当前时间表达式（批七十四 B1：归口到 `migration::seed_now_expr`，
/// 与迁移侧 40 份 `now_expr` 副本共用同一个函数对象 ⇒ 不再可能出现"换库换口径 /
/// 种子挂钟 vs 运行 UTC"的分裂。本函数保留仅为既有调用点可读性，**不得**再自行拼时间。）
pub(crate) fn flow_now(_db: &DatabaseConnection) -> String {
    crate::common::datetime::seed_now_expr()
}

/// 幂等确保审批工作流三张表存在（三方言 DDL 与迁移逐字对齐）
pub(crate) async fn ensure_flow_tables(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let (id_task, id_log, id_doc) = match backend {
        DatabaseBackend::Sqlite => (
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "INTEGER PRIMARY KEY AUTOINCREMENT",
        ),
        DatabaseBackend::Postgres => (
            "BIGSERIAL PRIMARY KEY",
            "BIGSERIAL PRIMARY KEY",
            "BIGSERIAL PRIMARY KEY",
        ),
        _ => (
            "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        ),
    };
    let ts = match backend {
        DatabaseBackend::Postgres => "TIMESTAMP",
        _ => "DATETIME",
    };

    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_flow_task (\n\
             \x20 task_id        {id_task},\n\
             \x20 biz_type       VARCHAR(64) NOT NULL,\n\
             \x20 biz_id         BIGINT NOT NULL,\n\
             \x20 round_no       INTEGER NOT NULL DEFAULT 1,\n\
             \x20 node_seq       INTEGER NOT NULL,\n\
             \x20 node_name      VARCHAR(64),\n\
             \x20 assignee_id    BIGINT NOT NULL,\n\
             \x20 task_type      VARCHAR(16) NOT NULL DEFAULT 'single',\n\
             \x20 status         VARCHAR(16) NOT NULL DEFAULT 'pending',\n\
             \x20 title          VARCHAR(200),\n\
             \x20 applicant_id   BIGINT NOT NULL,\n\
             \x20 applicant_name VARCHAR(64),\n\
             \x20 comment        VARCHAR(500),\n\
             \x20 acted_at       {ts},\n\
             \x20 due_at         {ts},\n\
             \x20 last_reminded_at {ts},\n\
             \x20 tenant_id      BIGINT NOT NULL DEFAULT 0,\n\
             \x20 create_by      VARCHAR(64),\n\
             \x20 create_time    {ts},\n\
             \x20 update_by      VARCHAR(64),\n\
             \x20 update_time    {ts}\n\
             )"
        ),
    )
    .await?;

    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_flow_log (\n\
             \x20 log_id       {id_log},\n\
             \x20 biz_type     VARCHAR(64) NOT NULL,\n\
             \x20 biz_id       BIGINT NOT NULL,\n\
             \x20 round_no     INTEGER NOT NULL DEFAULT 1,\n\
             \x20 node_seq     INTEGER,\n\
             \x20 action       VARCHAR(24) NOT NULL,\n\
             \x20 from_status  VARCHAR(16),\n\
             \x20 to_status    VARCHAR(16),\n\
             \x20 operator_id  BIGINT,\n\
             \x20 to_user_id   BIGINT,\n\
             \x20 comment      VARCHAR(500),\n\
             \x20 acted_at     {ts},\n\
             \x20 tenant_id    BIGINT NOT NULL DEFAULT 0,\n\
             \x20 create_by    VARCHAR(64),\n\
             \x20 create_time  {ts},\n\
             \x20 update_by    VARCHAR(64),\n\
             \x20 update_time  {ts}\n\
             )"
        ),
    )
    .await?;

    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS flow_demo_doc (\n\
             \x20 doc_id           {id_doc},\n\
             \x20 title            VARCHAR(200) NOT NULL,\n\
             \x20 applicant_id     BIGINT NOT NULL,\n\
             \x20 applicant_name   VARCHAR(64),\n\
             \x20 dept_id          BIGINT,\n\
             \x20 leave_type       VARCHAR(16) NOT NULL DEFAULT 'annual',\n\
             \x20 days             INTEGER NOT NULL DEFAULT 1,\n\
             \x20 reason           VARCHAR(500),\n\
             \x20 flow_mode        VARCHAR(16) NOT NULL DEFAULT 'single',\n\
             \x20 status           VARCHAR(16) NOT NULL DEFAULT 'draft',\n\
             \x20 current_round    INTEGER NOT NULL DEFAULT 0,\n\
             \x20 current_node_seq INTEGER,\n\
             \x20 submitted_at     {ts},\n\
             \x20 finished_at      {ts},\n\
             \x20 tenant_id        BIGINT NOT NULL DEFAULT 0,\n\
             \x20 create_by        VARCHAR(64),\n\
             \x20 create_time      {ts},\n\
             \x20 update_by        VARCHAR(64),\n\
             \x20 update_time      {ts}\n\
             )"
        ),
    )
    .await
}

/// 幂等回填平台部门主管（`sys_dept.leader_user_id` → admin，审批链前置条件）
///
/// 作用域限定**平台部门（tenant_id = 0）**：租户部门的审批人应由租户自行指派，
/// 不可把平台 admin 注入为租户部门主管（跨租户越权审批风险）。
/// 返回受影响行数（0 = 已全部有主管，天然幂等）。列缺失时安全跳过。
pub(crate) async fn ensure_platform_dept_leaders(db: &DatabaseConnection) -> anyhow::Result<u64> {
    if !sso_has_column(db, "sys_dept", "leader_user_id").await? {
        return Ok(0);
    }
    let sql = if sso_has_column(db, "sys_dept", "tenant_id").await? {
        "UPDATE sys_dept SET leader_user_id = 1 WHERE leader_user_id IS NULL AND tenant_id = 0"
    } else {
        "UPDATE sys_dept SET leader_user_id = 1 WHERE leader_user_id IS NULL"
    };
    let res = db
        .execute_raw(Statement::from_string(
            db.get_database_backend(),
            sql.to_string(),
        ))
        .await?;
    if res.rows_affected() > 0 {
        tracing::info!(
            "平台部门主管回填完成（leader_user_id → 1，保证部门主管审批链可用）rows={}",
            res.rows_affected()
        );
    }
    Ok(res.rows_affected())
}

/// 幂等建 flow 索引（三方言统一经 `migration::ensure_index_ddl`，见 R-11/R-12 注释）
pub(crate) async fn ensure_flow_indexes(db: &DatabaseConnection) -> Result<(), DbErr> {
    let indexes = [
        "CREATE UNIQUE INDEX uk_flow_task_biz ON sys_flow_task (biz_type, biz_id, round_no, node_seq, assignee_id)",
        "CREATE INDEX idx_flow_task_assignee ON sys_flow_task (assignee_id, status)",
        "CREATE INDEX idx_flow_task_due ON sys_flow_task (status, due_at)",
        "CREATE INDEX idx_flow_log_biz ON sys_flow_log (biz_type, biz_id, round_no)",
        // W-12：已办视图（operator_id + acted_at）覆盖索引，避免全表扫描
        "CREATE INDEX idx_flow_log_operator ON sys_flow_log (operator_id, acted_at)",
        "CREATE INDEX idx_flow_doc_applicant ON flow_demo_doc (applicant_id, status)",
    ];
    for stmt in indexes {
        // 真失败（表缺失/列缺失/权限）只告警不阻断启动，但必须可见——旧的 debug 级
        // "可能已存在"容错会把这类错误一起吞掉（批七十七 R-11）
        if let Err(e) = migration::ensure_index_ddl(db, stmt).await {
            tracing::warn!("flow 索引创建失败（不阻断启动）: {}", e);
        }
    }
    Ok(())
}

/// 幂等补种 flow 菜单（3600 段）/字典（70 段）/site 渠道/flow_* 模板
pub(crate) async fn ensure_flow_seeds(db: &DatabaseConnection) -> Result<(), DbErr> {
    // sys_menu 表存在性保护：全新空库未建系统表时跳过种子（交由 migration 初始种子负责），
    // 与 ensure_sys_pat_menu 同范式——否则空库启动会因种子 INSERT 失败而阻断（影响面回归修复）
    let sys_menu_exists = sso_table_exists(db, "sys_menu")
        .await
        .map_err(|e| DbErr::Custom(format!("flow 种子表存在性检查失败: {}", e)))?;
    if !sys_menu_exists {
        tracing::info!("flow 种子跳过（sys_menu 不存在，空库交由 migration 负责初始种子）");
        return Ok(());
    }
    let now = flow_now(db);

    // 菜单 3600/3601/3611 + role 2 授权（与迁移 4.1-4.3 同构；remark 亦对齐迁移）
    // 类型标注省略（11 元元组触发 clippy type_complexity，交给编译器推断）
    let menus = &[
        (
            3600,
            "审批中心",
            1,
            95,
            "flow",
            "ParentView",
            "M",
            "",
            "example",
            "审批工作流",
            "route.flow",
        ),
        (
            3601,
            "审批中心",
            3600,
            1,
            "todo",
            "system/flow/index",
            "C",
            "system:flow:list",
            "checkbox",
            "审批待办/我发起/全部单据",
            "route.flowTodo",
        ),
        (
            3611,
            "全部单据查询",
            3601,
            1,
            "",
            "",
            "F",
            "system:flow:list",
            "#",
            "",
            "",
        ),
    ];
    for (menu_id, name, parent, order, path, component, mtype, perms, icon, remark, i18n_key) in
        menus
    {
        // F 按钮（3611）无 i18n_key 列值，与其余 C/M 分支拼列
        if *mtype == "F" {
            flow_insert(
                db,
                &format!(
                    "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                     ({menu_id}, '{name}', {parent}, {order}, '{path}', '{component}', '', '', '1', '0', '{mtype}', '0', '0', '{perms}', '{icon}', 'admin', {now}, '{remark}', '0')"
                ),
            )
            .await?;
        } else {
            flow_insert(
                db,
                &format!(
                    "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES \
                     ({menu_id}, '{name}', {parent}, {order}, '{path}', '{component}', '', '', '1', '0', '{mtype}', '0', '0', '{perms}', '{icon}', 'admin', {now}, '{remark}', '0', '{i18n_key}')"
                ),
            )
            .await?;
        }
        // common 授权走策略体（b73 轮 15 单一事实源）：本段 3600/3601 页面与 3611
        // `system:flow:list` 只读按钮均放行 ⇒ 与改造前等价；今后往本表加写按钮将被拒发。
        flow_insert(db, &governance::common_role_grant_select_body(&[*menu_id])).await?;
    }

    // 字典 70/71/72 段（与迁移 4.4-4.6 同构）
    let dict_types: &[(i64, &str, &str, &str)] = &[
        (70, "审批状态", "sys_flow_task_status", "审批任务与单据状态"),
        (71, "审批动作", "sys_flow_action", "审批流水动作"),
        (
            72,
            "请假类型",
            "sys_flow_leave_type",
            "示例审批单据-请假类型",
        ),
    ];
    for (dict_id, name, dtype, remark) in dict_types {
        flow_insert(
            db,
            &format!(
                "sys_dict_type (dict_id, dict_name, dict_type, status, create_by, create_time, remark, del_flag) VALUES \
                 ({dict_id}, '{name}', '{dtype}', '0', 'admin', {now}, '{remark}', '0')"
            ),
        )
        .await?;
    }
    let status_rows: &[(i64, &str, &str, &str, &str)] = &[
        (700, "待审批", "pending", "warning", "To Approve"),
        (701, "已通过", "approved", "success", "Approved"),
        (702, "已驳回", "rejected", "danger", "Rejected"),
        (703, "已取消", "cancelled", "info", "Cancelled"),
        (704, "已转办", "transferred", "info", "Transferred"),
        (705, "已撤回", "withdrawn", "info", "Withdrawn"),
        (706, "草稿", "draft", "info", "Draft"),
    ];
    for (code, label, value, css, label_en) in status_rows {
        flow_insert(
            db,
            &format!(
                "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                 ({code}, {code}, '{label}', '{value}', 'sys_flow_task_status', '', '{css}', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
            ),
        )
        .await?;
    }
    let action_rows: &[(i64, &str, &str, &str)] = &[
        (710, "提交", "submit", "To Submit"),
        (711, "同意", "approve", "Approve"),
        (712, "驳回", "reject", "Reject"),
        (713, "撤回", "withdraw", "Withdraw"),
        (714, "转办", "transfer", "Transfer"),
        (715, "超时提醒", "timeout_remind", "Timeout Remind"),
        // 批七十六 R-4：原 716（"自动通过"/auto_approve）摘除。引擎无该动作写入点，
        // 且"节点唯一审批人=提交人"在 sys_flow_service.rs:852 显式 400 拒绝（不做自动通过）
        // ⇒ 它是与既有设计相矛盾的预留值。存量库由迁移 m20261019_000001 删除同一行。
        // 兜底侧与迁移侧的一致性现由 `integration_tests::flow_action_dict` **双向**锁定：
        // 引擎动作 ⊆ 字典值（R-1，漏种即红）且字典值 ⊆ 引擎动作（R-4，塞预留值即红）。
        // 批七十六 R-1：引擎实际可写入的另三个动作（委派 / 加签 / 减签）。
        // 与迁移 m20261018_000001_flow_action_dict 逐字同构；两侧同时被
        // `integration_tests::flow_action_dict` 的"引擎字面量 ⊆ 字典值"总锁约束。
        (717, "委托", "delegate", "Delegate"),
        (718, "加签", "countersign_add", "Approver Added"),
        (719, "减签", "countersign_del", "Approver Removed"),
    ];
    for (code, label, value, label_en) in action_rows {
        flow_insert(
            db,
            &format!(
                "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                 ({code}, {code}, '{label}', '{value}', 'sys_flow_action', '', 'info', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
            ),
        )
        .await?;
    }
    let leave_rows: &[(i64, &str, &str, &str)] = &[
        (720, "年假", "annual", "Annual Leave"),
        (721, "病假", "sick", "Sick Leave"),
        (722, "事假", "personal", "Personal Leave"),
    ];
    for (code, label, value, label_en) in leave_rows {
        flow_insert(
            db,
            &format!(
                "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                 ({code}, {code}, '{label}', '{value}', 'sys_flow_leave_type', '', 'primary', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
            ),
        )
        .await?;
    }

    // site 渠道 + flow_* 模板（与迁移 4.7/4.8 同构；channel_code/template_code UNIQUE 幂等）
    // ⚠️ msg 两表由 m20260818_000002_msg_module 迁移负责建表（极老存量库可能没有），
    // 与 ensure_msg_template_seeds 同口径：表不存在则跳过种子（schema 等价性总锁实测发现）。
    let has_channel = sso_table_exists(db, "sys_msg_channel")
        .await
        .map_err(|e| sea_orm::DbErr::Custom(e.to_string()))?;
    let has_template = sso_table_exists(db, "sys_msg_template")
        .await
        .map_err(|e| sea_orm::DbErr::Custom(e.to_string()))?;
    if has_channel && has_template {
        flow_insert(
            db,
            &format!(
                "sys_msg_channel (channel_name, channel_code, channel_type, config_json, status, remark, create_by, create_time, del_flag) VALUES \
                 ('站内信', 'site', 'site', NULL, '0', '审批/系统站内提醒', 'admin', {now}, '0')"
            ),
        )
        .await?;
        let templates: &[(&str, &str, &str, &str)] = &[
            (
                "审批待办提醒",
                "flow_todo",
                "您有新的审批待办",
                "单据「{{{{title}}}}」等待您审批，请及时处理。",
            ),
            (
                "审批超时提醒",
                "flow_timeout",
                "审批待办已超时",
                "单据「{{{{title}}}}」已超过办理时限，请尽快处理。",
            ),
            (
                "审批驳回通知",
                "flow_reject",
                "您的单据已被驳回",
                "您提交的单据「{{{{title}}}}」已被驳回，请查看审批意见。",
            ),
        ];
        for (name, code, subject, content) in templates {
            flow_insert(
            db,
            &format!(
                "sys_msg_template (template_name, template_code, channel_code, template_subject, template_content, status, remark, create_by, create_time, del_flag) VALUES \
                 ('{name}', '{code}', 'site', '{subject}', '{content}', '0', '审批站内提醒', 'admin', {now}, '0')"
            ),
        )
        .await?;
        }
    }
    Ok(())
}

/// 幂等确保审批工作流模块完整就绪（表 + 索引 + 种子；存量库向后兼容，与迁移等价）
pub(crate) async fn ensure_flow_module(db: &DatabaseConnection) -> anyhow::Result<()> {
    ensure_flow_tables(db)
        .await
        .map_err(|e| anyhow::anyhow!("flow 建表失败: {}", e))?;
    ensure_flow_indexes(db)
        .await
        .map_err(|e| anyhow::anyhow!("flow 索引创建失败: {}", e))?;
    // 存量库 leader_user_id 已由 AppInitializer 3.1.2 统一兜底（sys_dept 漂移修复），此处无需重复
    ensure_flow_seeds(db)
        .await
        .map_err(|e| anyhow::anyhow!("flow 种子补齐失败: {}", e))?;
    tracing::info!("审批工作流模块已就绪（幂等确保完成）");
    Ok(())
}

/// 台账（G-02 M1，存量库兜底，等价迁移 `m20261007_000003`）：flow_definition 表。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而
/// `flow_definition_service` 已读写该表 ⇒ 缺此兜底则流程定义 CRUD/发布全链 500。
/// 幂等：表存在即跳过；唯一索引容错"已存在"；demo_v2 种子 WHERE NOT EXISTS。
pub(crate) async fn ensure_flow_definition_table(db: &DatabaseConnection) -> anyhow::Result<()> {
    if sso_table_exists(db, "flow_definition").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let (pk, text_type) = match backend {
        DatabaseBackend::Sqlite => ("INTEGER PRIMARY KEY AUTOINCREMENT", "TEXT"),
        DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "TEXT"),
        _ => ("BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY", "LONGTEXT"),
    };
    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS flow_definition (\
         flow_id {pk},\
         tenant_id BIGINT NOT NULL DEFAULT 0,\
         flow_code VARCHAR(64) NOT NULL,\
         flow_name VARCHAR(128) NOT NULL,\
         graph_json {text_type} NOT NULL,\
         version INT NOT NULL DEFAULT 1,\
         is_latest CHAR(1) NOT NULL DEFAULT '1',\
         status CHAR(1) NOT NULL DEFAULT '0',\
         create_by VARCHAR(64),\
         create_time DATETIME,\
         update_by VARCHAR(64),\
         update_time DATETIME,\
         remark VARCHAR(500),\
         del_flag CHAR(1) DEFAULT '0')"
    );
    db.execute_raw(Statement::from_string(backend, create_sql))
        .await?;
    // 统一走 `migration::ensure_index_ddl`（先按方言探测存在性、必要时 SAVEPOINT 隔离）。
    // 此前是"拼 IF NOT EXISTS + 按错误文案吞掉"的本地副本：MySQL 无 IF NOT EXISTS 子句
    // 所以靠吞错兜，而 PG 事务里首错即 aborted，吞掉它等于废掉后续所有语句（批七十七 R-11）。
    migration::ensure_index_ddl(
        db,
        "CREATE UNIQUE INDEX uq_flow_def_code_ver ON flow_definition (tenant_id, flow_code, version)",
    )
    .await?;
    // demo_v2 种子（与迁移同构，幂等）
    let graph = r#"{"nodes":[{"id":"start","type":"start"},{"id":"a1","type":"approve","name":"部门主管审批","assignees":["dept_leader"],"quorum":"any"},{"id":"a2","type":"approve","name":"管理员审批","assignees":["role:admin"],"quorum":"any"},{"id":"end","type":"end"}],"edges":[{"from":"start","to":"a1"},{"from":"a1","to":"a2"},{"from":"a2","to":"end"}]}"#;
    let now = flow_now(db);
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            "INSERT INTO flow_definition (tenant_id, flow_code, flow_name, graph_json, version, is_latest, status, create_by, create_time, remark, del_flag) \
             SELECT 0, 'demo_v2', '可配置演示审批流', '{graph}', 1, '1', '0', 'admin', {now}, 'G-02 M1 种子：两级单审（对齐 demo single 模式）', '0' \
             WHERE NOT EXISTS (SELECT 1 FROM flow_definition WHERE tenant_id = 0 AND flow_code = 'demo_v2')"
        ),
    ))
    .await?;
    tracing::info!("flow_definition 表已补建（G-02 存量库兜底）");
    Ok(())
}

/// 台账（批次十六，存量库兜底，等价迁移 m20261007_000012）：
/// 图驱动单据表 `flow_graph_doc`——任一已发布流程图驱动审批的实例承载表。
/// 缺此兜底时：存量库启动后 /system/flow/graph/submit 全链 500（表不存在）。
/// 幂等：CREATE TABLE IF NOT EXISTS；列名/类型与迁移逐列一致（双写关系）。
pub(crate) async fn ensure_flow_graph_doc_table(db: &DatabaseConnection) -> anyhow::Result<()> {
    if sso_table_exists(db, "flow_graph_doc").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let auto = match backend {
        sea_orm::DatabaseBackend::Sqlite => "INTEGER PRIMARY KEY AUTOINCREMENT",
        sea_orm::DatabaseBackend::Postgres => "BIGSERIAL PRIMARY KEY",
        _ => "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
    };
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            "CREATE TABLE IF NOT EXISTS flow_graph_doc (\
             doc_id {auto},\
             tenant_id BIGINT NOT NULL DEFAULT 0,\
             dept_id BIGINT NULL,\
             flow_id BIGINT NOT NULL,\
             flow_code VARCHAR(64) NOT NULL,\
             title VARCHAR(200) NOT NULL,\
             fields_json TEXT NOT NULL DEFAULT '{{}}',\
             status VARCHAR(16) NOT NULL DEFAULT 'pending',\
             current_round INT NOT NULL DEFAULT 1,\
             current_node_seq INT NULL,\
             submitted_at DATETIME NULL,\
             finished_at DATETIME NULL,\
             create_by VARCHAR(64) DEFAULT '',\
             create_time DATETIME NULL,\
             update_by VARCHAR(64) DEFAULT '',\
             update_time DATETIME NULL,\
             del_flag VARCHAR(1) DEFAULT '0'\
             )"
        ),
    ))
    .await?;
    migration::ensure_index_ddl(
        db,
        "CREATE INDEX idx_flow_graph_doc_tenant ON flow_graph_doc (tenant_id, status)",
    )
    .await?;
    tracing::info!("flow_graph_doc 表已补建（批次十六图驱动单据，存量库兜底）");
    Ok(())
}

/// 台账（G-02 M2，存量库兜底，等价迁移 `m20261007_000006`）：
/// sys_flow_task 动作矩阵扩展列——`weight`（加权票快照，DEFAULT 1）、
/// `threshold`（weighted 节点门槛快照）、`delegate_from`（委派转出人）。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而
/// 引擎加权/委派链路已读写新列 ⇒ 缺此兜底则 or_sign/weighted/delegate 全链 500。
/// 幂等：has_column 守卫逐列判定；表不存在时安全返回。
pub(crate) async fn ensure_flow_task_action_columns(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_flow_task").await? {
        return Ok(());
    }
    let adds: [(&str, &str); 4] = [
        ("weight", "INT NOT NULL DEFAULT 1"),
        ("threshold", "INT NULL"),
        ("delegate_from", "BIGINT NULL"),
        ("actions_json", "TEXT NULL"),
    ];
    for (col, ddl) in adds {
        if sso_has_column(db, "sys_flow_task", col).await? {
            continue;
        }
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            format!("ALTER TABLE sys_flow_task ADD COLUMN {col} {ddl}"),
        ))
        .await?;
        tracing::info!("sys_flow_task.{col} 已补列（G-02 M2 存量库兜底）");
    }
    Ok(())
}

use super::*;
