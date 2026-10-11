use super::*;

#[cfg(test)]
mod single_source_sql_tests {
    //! 「迁移 ↔ initialize 兜底」单一事实源回归锁：
    //! 断言迁移文件导出的建表 SQL / 种子集合与重构前两侧手抄的 DDL/种子
    //! **逐字段等价**（期望值取自重构前 git 基线的手抄字面量）。
    //! 兜底函数与本测试引用同一导出项——迁移侧产出与兜底侧产出天然恒等；
    //! 若有人改动列定义/种子内容而未同步期望值，本模块必红。
    use migration::m20261003_000001_audit_change as audit_mig;
    use migration::m20261003_000002_webhook_event as webhook_mig;
    use migration::m20261003_000003_alert_rule as alert_mig;
    use sea_orm::DatabaseBackend;

    /// sys_audit_change 建表 SQL：三方言列清单/类型/约束与重构前手抄 DDL 逐字段等价
    #[test]
    fn audit_create_table_sql_matches_legacy_ddl() {
        for (backend, id_col, operated_at) in [
            (
                DatabaseBackend::Sqlite,
                "id INTEGER PRIMARY KEY AUTOINCREMENT",
                "TIMESTAMP NOT NULL",
            ),
            (
                DatabaseBackend::Postgres,
                "id BIGSERIAL PRIMARY KEY",
                "TIMESTAMP NOT NULL",
            ),
            (
                DatabaseBackend::MySql,
                "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
                "DATETIME NOT NULL",
            ),
        ] {
            let sql = audit_mig::create_table_sql(backend);
            assert!(
                sql.starts_with("CREATE TABLE IF NOT EXISTS sys_audit_change"),
                "{backend:?} 建表语句前缀不符: {sql}"
            );
            // 方言差异列
            assert!(sql.contains(id_col), "{backend:?} id 列不符: {sql}");
            assert!(
                sql.contains(&format!("operated_at     {operated_at}")),
                "{backend:?} operated_at 列不符: {sql}"
            );
            // 三方言共享列（含对齐空格，锁定列名/类型/约束不被漂移）
            for frag in [
                "tenant_id       BIGINT NOT NULL DEFAULT 0",
                "table_name      VARCHAR(64) NOT NULL",
                "row_pk          VARCHAR(64) NOT NULL",
                "action          VARCHAR(16) NOT NULL",
                "changed_fields  TEXT NOT NULL",
                "before_data     TEXT,",
                "after_data      TEXT,",
                "operator_id     BIGINT,",
                "operator_name   VARCHAR(64),",
            ] {
                assert!(sql.contains(frag), "{backend:?} 缺列片段 [{frag}]: {sql}");
            }
        }
    }

    /// 审计菜单种子：语句体与重构前手抄 SQL 逐字符等价（NOW() 形态下）
    #[test]
    fn audit_menu_seed_bodies_match_legacy_sql() {
        let bodies = audit_mig::audit_menu_seed_bodies("NOW()");
        assert_eq!(bodies.len(), 6, "3 菜单行 + 3 role_menu 行");
        assert_eq!(
            bodies[0],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES (4000, '变更留痕', 108, 4, 'auditChange', 'system/auditChange/index', '', '', '1', '0', 'C', '0', '0', 'system:audit-change:list', 'log', 'admin', NOW(), '业务数据变更留痕审计（前后快照 + 字段差异）', '0', 'menu.audit_change')"
        );
        assert_eq!(
            bodies[1],
            "sys_role_menu (role_id, menu_id) VALUES (2, 4000)"
        );
        assert_eq!(
            bodies[2],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES (4001, '变更查询', 4000, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:audit-change:query', '#', 'admin', NOW(), '', '0', NULL)"
        );
        assert_eq!(
            bodies[3],
            "sys_role_menu (role_id, menu_id) VALUES (2, 4001)"
        );
        assert_eq!(
            bodies[4],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES (4002, '变更导出', 4000, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:audit-change:export', '#', 'admin', NOW(), '', '0', NULL)"
        );
        assert_eq!(
            bodies[5],
            "sys_role_menu (role_id, menu_id) VALUES (2, 4002)"
        );
    }

    /// sys_webhook_event 建表 SQL：三方言与重构前手抄 DDL 等价
    #[test]
    fn webhook_create_table_sql_matches_legacy_ddl() {
        for (backend, id_col) in [
            (
                DatabaseBackend::Sqlite,
                "id INTEGER PRIMARY KEY AUTOINCREMENT",
            ),
            (DatabaseBackend::Postgres, "id BIGSERIAL PRIMARY KEY"),
            (
                DatabaseBackend::MySql,
                "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            ),
        ] {
            let sql = webhook_mig::create_table_sql(backend);
            assert!(sql.starts_with("CREATE TABLE IF NOT EXISTS sys_webhook_event"));
            assert!(sql.contains(id_col));
            for frag in [
                "event_key       VARCHAR(64) NOT NULL",
                "name            VARCHAR(64) NOT NULL",
                "description     VARCHAR(255) NULL",
                "payload_example TEXT NULL",
                "enabled         CHAR(1) NOT NULL DEFAULT '1'",
                "created_at      TIMESTAMP NULL,",
                "updated_at      TIMESTAMP NULL",
            ] {
                assert!(sql.contains(frag), "{backend:?} 缺列片段 [{frag}]: {sql}");
            }
        }
    }

    /// sys_alert_rule 建表 SQL：三方言与重构前手抄 DDL 等价
    /// （threshold：PG 为 DOUBLE PRECISION，其余 DOUBLE；时间列：PG TIMESTAMP，其余 DATETIME）
    #[test]
    fn alert_create_table_sql_matches_legacy_ddl() {
        for (backend, threshold, last_fired, created, updated) in [
            (
                DatabaseBackend::Sqlite,
                "DOUBLE NOT NULL",
                "last_fired_at      DATETIME,",
                "created_at         DATETIME,",
                "updated_at         DATETIME",
            ),
            (
                DatabaseBackend::MySql,
                "DOUBLE NOT NULL",
                "last_fired_at      DATETIME NULL,",
                "created_at         DATETIME,",
                "updated_at         DATETIME",
            ),
            (
                DatabaseBackend::Postgres,
                "DOUBLE PRECISION NOT NULL",
                "last_fired_at      TIMESTAMP,",
                "created_at         TIMESTAMP,",
                "updated_at         TIMESTAMP",
            ),
        ] {
            let sql = alert_mig::create_table_sql(backend);
            assert!(sql.starts_with("CREATE TABLE IF NOT EXISTS sys_alert_rule"));
            assert!(sql.contains(&format!("threshold          {threshold}")));
            assert!(sql.contains(last_fired), "{backend:?} last_fired_at 不符");
            assert!(sql.contains(created), "{backend:?} created_at 不符");
            assert!(sql.contains(updated), "{backend:?} updated_at 不符");
            for frag in [
                "name               VARCHAR(64) NOT NULL",
                "metric             VARCHAR(64) NOT NULL",
                "comparator         VARCHAR(2) NOT NULL",
                "silent_minutes     INT NOT NULL DEFAULT 30",
                "notify_channel_id  BIGINT",
                "notify_template_id BIGINT",
                "enabled            CHAR(1) DEFAULT '1'",
            ] {
                assert!(sql.contains(frag), "{backend:?} 缺列片段 [{frag}]: {sql}");
            }
        }
    }

    /// webhook 种子事件：16 个事件键集合与重构前手抄 WEBHOOK_SEED_EVENTS 一致
    #[test]
    fn webhook_seed_events_match_legacy_set() {
        const LEGACY_KEYS: &[&str] = &[
            "user.created",
            "user.updated",
            "user.deleted",
            "role.created",
            "role.updated",
            "role.deleted",
            "login.success",
            "login.failed",
            "tenant.created",
            "tenant.disabled",
            "config.updated",
            "dict.updated",
            "notice.published",
            "job.executed",
            "job.failed",
            "webhook.test",
        ];
        let events = webhook_mig::WEBHOOK_SEED_EVENTS;
        assert_eq!(events.len(), 16, "种子事件应为 16 个");
        for (i, key) in LEGACY_KEYS.iter().enumerate() {
            assert_eq!(&events[i].0, key, "第 {i} 个事件键漂移");
        }
        // 语句体：转义 + NOW() 形态 + enabled '1' 与重构前手抄一致
        let bodies = webhook_mig::webhook_event_seed_bodies("NOW()");
        assert_eq!(bodies.len(), 16);
        assert_eq!(
            bodies[0],
            "sys_webhook_event (event_key, name, description, payload_example, enabled, created_at, updated_at) VALUES ('user.created', '用户创建', '新用户创建成功后触发（sys_user 新增事务提交后）', '{\"userId\":1,\"userName\":\"admin\",\"nickName\":\"超级管理员\",\"tenantId\":0,\"time\":\"2026-10-03 00:00:00\"}', '1', NOW(), NOW())"
        );
        for body in &bodies {
            assert!(body.contains(", '1', NOW(), NOW())"), "语句体尾部形态漂移");
        }
    }

    /// webhook 菜单按钮：3562/3563 + role_menu(2,·)，语句体与重构前手抄逐字符等价
    #[test]
    fn webhook_menu_seed_bodies_match_legacy_sql() {
        let bodies = webhook_mig::webhook_menu_seed_bodies("NOW()");
        assert_eq!(bodies.len(), 4);
        assert_eq!(
            bodies[0],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES (3562, '事件目录', 158, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:webhook:event:list', 'list', 'admin', NOW(), 'WebHook 事件目录查询', '0')"
        );
        assert_eq!(
            bodies[1],
            "sys_role_menu (role_id, menu_id) VALUES (2, 3562)"
        );
        assert_eq!(
            bodies[2],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES (3563, '测试发送', 158, 2, '', '', '', '', '1', '0', 'F', '0', '0', 'system:webhook:test-send', 'message', 'admin', NOW(), '按事件样例构造真实测试发送', '0')"
        );
        assert_eq!(
            bodies[3],
            "sys_role_menu (role_id, menu_id) VALUES (2, 3563)"
        );
    }

    /// 告警菜单种子：4110-4114 集合一致；仅页面 4110 授予 role_menu(2,·)
    #[test]
    fn alert_menu_seed_bodies_match_legacy_sql() {
        let bodies = alert_mig::alert_menu_seed_bodies("NOW()");
        assert_eq!(bodies.len(), 6, "页面 role_menu + 5 菜单行");
        assert_eq!(
            bodies[0],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES (4110, '告警规则', 2, 60, 'alert', 'monitor/alert/index', '', '', '1', '0', 'C', '0', '0', 'monitor:alert:list', 'alert', 'admin', NOW(), '告警规则引擎菜单', '0')"
        );
        assert_eq!(
            bodies[1],
            "sys_role_menu (role_id, menu_id) VALUES (2, 4110)"
        );
        // 按钮 4111-4114 不授予 role_menu（与迁移/兜底原行为一致）
        let joined = bodies.join("\n");
        for (id, perms) in [
            (4111, "monitor:alert:query"),
            (4112, "monitor:alert:add"),
            (4113, "monitor:alert:edit"),
            (4114, "monitor:alert:remove"),
        ] {
            assert!(
                joined.contains(&format!("VALUES ({id}, '告警")),
                "按钮 {id} 缺失"
            );
            assert!(joined.contains(perms), "按钮 {id} perms 漂移");
        }
        assert_eq!(
            joined.matches("sys_role_menu").count(),
            1,
            "仅页面 4110 有 role_menu"
        );
    }

    /// 索引单一事实源：迁移导出的索引清单与重构前两侧手抄一致
    #[test]
    fn index_consts_match_legacy_sets() {
        assert_eq!(
            audit_mig::AUDIT_INDEXES,
            &[
                (
                    "idx_audit_change_row",
                    "sys_audit_change",
                    "table_name, row_pk"
                ),
                ("idx_audit_change_time", "sys_audit_change", "operated_at"),
                ("idx_audit_change_tenant", "sys_audit_change", "tenant_id"),
            ]
        );
        assert_eq!(
            webhook_mig::WEBHOOK_INDEXES,
            &[
                (
                    "uk_sys_webhook_event_key",
                    "sys_webhook_event",
                    "event_key",
                    true
                ),
                ("uk_sys_pat_access_key", "sys_pat", "access_key", true),
            ]
        );
        assert_eq!(
            alert_mig::ALERT_INDEXES,
            &[("idx_alert_rule_enabled", "sys_alert_rule", "enabled", false)]
        );
    }
}

#[cfg(test)]
mod flow_backfill_tests {
    use super::*;
    use sea_orm::Database;

    /// 依赖表最小 DDL（种子写入目标：sys_menu/sys_role_menu/sys_dict_type/sys_dict_data/
    /// sys_msg_channel/sys_msg_template；列结构对齐各自迁移，仅保留种子涉及列 + 唯一键）
    const MIN_SEED_TABLES: &[&str] = &[
        "CREATE TABLE sys_menu (menu_id INTEGER PRIMARY KEY, menu_name VARCHAR(64), parent_id INTEGER, order_num INTEGER, path VARCHAR(64), component VARCHAR(64), query VARCHAR(64), route_name VARCHAR(64), is_frame VARCHAR(2), is_cache VARCHAR(2), menu_type VARCHAR(2), visible VARCHAR(2), status VARCHAR(2), perms VARCHAR(64), icon VARCHAR(64), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1), i18n_key VARCHAR(64))",
        "CREATE TABLE sys_role_menu (role_id BIGINT, menu_id BIGINT, PRIMARY KEY (role_id, menu_id))",
        "CREATE TABLE sys_dict_type (dict_id INTEGER PRIMARY KEY, dict_name VARCHAR(64), dict_type VARCHAR(64) UNIQUE, status VARCHAR(2), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1))",
        "CREATE TABLE sys_dict_data (dict_code INTEGER PRIMARY KEY, dict_sort INTEGER, dict_label VARCHAR(64), dict_value VARCHAR(64), dict_type VARCHAR(64), css_class VARCHAR(64), list_class VARCHAR(64), is_default VARCHAR(2), status VARCHAR(2), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1), dict_label_en VARCHAR(64))",
        "CREATE TABLE sys_msg_channel (channel_id INTEGER PRIMARY KEY AUTOINCREMENT, channel_name VARCHAR(64), channel_code VARCHAR(64) UNIQUE, channel_type VARCHAR(32), config_json TEXT, status VARCHAR(2), remark VARCHAR(500), create_by VARCHAR(64), create_time DATETIME, del_flag VARCHAR(1))",
        "CREATE TABLE sys_msg_template (template_id INTEGER PRIMARY KEY AUTOINCREMENT, template_name VARCHAR(64), template_code VARCHAR(64) UNIQUE, channel_code VARCHAR(64), template_subject VARCHAR(200), template_content TEXT, status VARCHAR(2), remark VARCHAR(500), create_by VARCHAR(64), create_time DATETIME, del_flag VARCHAR(1))",
    ];

    /// 场景 1：全新空库（连 sys_menu 都没有）→ 三表兜底建出、种子安全跳过、不阻断启动
    #[tokio::test]
    async fn flow_backfill_on_empty_db_creates_tables_and_skips_seeds() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        ensure_flow_module(&db).await.unwrap();
        let tables = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('sys_flow_task','sys_flow_log','flow_demo_doc')".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(tables.len(), 3, "空库应兜底建出三张 flow 表");
    }

    /// 场景 2：存量库（有 sys_menu 等系统表）→ 种子落库 + 重复调用幂等（不报错、不重复行）
    #[tokio::test]
    async fn flow_backfill_is_idempotent_on_existing_db() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        for ddl in MIN_SEED_TABLES {
            db.execute_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                ddl.to_string(),
            ))
            .await
            .unwrap();
        }
        // 首次调用：种子落库
        ensure_flow_module(&db).await.unwrap();
        // 重复调用（模拟每次启动）：幂等不报错
        ensure_flow_module(&db).await.unwrap();

        let count_menu: u64 = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_menu WHERE menu_id = 3600".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap() as u64;
        assert_eq!(count_menu, 1, "menu 3600 应恰一条（幂等防重）");

        let count_tpl: u64 = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_msg_template WHERE template_code IN ('flow_todo','flow_timeout','flow_reject')".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap() as u64;
        assert_eq!(count_tpl, 3, "三条 flow 模板应恰各一条（UNIQUE 幂等）");

        let count_dict: u64 = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_dict_data WHERE dict_type = 'sys_flow_task_status'"
                    .to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap() as u64;
        assert_eq!(count_dict, 7, "审批状态字典应恰 7 条");
    }
}

#[cfg(test)]
mod tenant_host_chain_self_check_tests {
    use super::*;

    /// 台账 MT-4 / E-2（第十批）：域名链路「静默失效」自检的**可证伪**回归锁。
    ///
    /// 语义：`trusted_proxies` 为空 **且** 存在启用中的 `sys_tenant_domain` 行
    /// ⇒ 域名链路必然静默失效，自检必须"报出来"（返回告警计数）。
    ///
    /// 三条断言分别锁住：① 该组合**确实触发**（不是恒 None 的死检查）；
    /// ② 配了白名单即**不再告警**（避免噪音）；③ 无域名绑定即**不告警**
    /// （开发/单机环境的正常态）。任一条件被写反/写漏，本测试即红。
    #[tokio::test]
    async fn warns_only_when_proxies_empty_and_domain_bound() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("建库失败");
        let backend = db.get_database_backend();

        // 干净起点：清空域名表（迁移可能已带入种子，避免依赖其数量）
        db.execute_raw(Statement::from_string(
            backend,
            "DELETE FROM sys_tenant_domain".to_string(),
        ))
        .await
        .expect("清空 sys_tenant_domain 失败");

        let empty: Vec<String> = vec![];
        let non_empty = vec!["127.0.0.1".to_string()];

        // ③ 无域名绑定 + 白名单为空 ⇒ 不告警（开发/单机正常态）
        assert_eq!(
            tenant_host_chain_self_check(&db, &empty).await,
            None,
            "无启用域名绑定时不应告警"
        );

        // 插入 1 条启用中的绑定 + 1 条已停用（不应计入）
        db.execute_raw(Statement::from_string(
            backend,
            "INSERT INTO sys_tenant_domain (tenant_id, domain, domain_type, is_primary, \
             verify_status, status, del_flag) \
             VALUES (9030, 'mt4-active.test', '0', '0', '1', '0', '0')"
                .to_string(),
        ))
        .await
        .expect("插入启用域名失败");
        db.execute_raw(Statement::from_string(
            backend,
            "INSERT INTO sys_tenant_domain (tenant_id, domain, domain_type, is_primary, \
             verify_status, status, del_flag) \
             VALUES (9030, 'mt4-disabled.test', '0', '1', '1', '1', '0')"
                .to_string(),
        ))
        .await
        .expect("插入停用域名失败");
        // 启用但**未验证**：不参与 host→tid 解析（`find_active_by_domain` 要求 verify_status='1'），
        // 故不应计入告警数——锁住"自检口径 == 真实解析口径"，避免未验证绑定引发误报。
        db.execute_raw(Statement::from_string(
            backend,
            "INSERT INTO sys_tenant_domain (tenant_id, domain, domain_type, is_primary, \
             verify_status, status, del_flag) \
             VALUES (9030, 'mt4-unverified.test', '0', '1', '0', '0', '0')"
                .to_string(),
        ))
        .await
        .expect("插入未验证域名失败");

        // ① 白名单为空 + 有可解析域名 ⇒ 必须告警，且计数只含"可解析"行（=1：启用+已验证）
        assert_eq!(
            tenant_host_chain_self_check(&db, &empty).await,
            Some(1),
            "trusted_proxies 为空且存在**可解析**域名绑定时应告警，且计数仅含 \
             status='0' AND verify_status='1' 的行（停用/未验证行不得计入）"
        );

        // ② 配了白名单 ⇒ 不告警（域名链路可用，无需提示）
        assert_eq!(
            tenant_host_chain_self_check(&db, &non_empty).await,
            None,
            "已配置 trusted_proxies 时不应告警"
        );

        // 清理
        db.execute_raw(Statement::from_string(
            backend,
            "DELETE FROM sys_tenant_domain WHERE domain LIKE 'mt4-%'".to_string(),
        ))
        .await
        .expect("清理域名样本失败");
    }
}

#[cfg(test)]
mod dept_leader_backfill_tests {
    use super::*;
    use sea_orm::Database;

    /// 平台部门主管回填：作用域正确 + 可证伪 + 幂等
    ///
    /// 背景（P0 业务阻断）：`ApproverPolicy::DeptLeader` 依赖 `sys_dept.leader_user_id`。
    /// 迁移 `m20260923_000002` 的回填只在「列刚新建」时执行（`has_column` 即早退），
    /// 存量库（列为历史 initialize 所加）会全部为 NULL ⇒ 提交单据必然 400
    /// `error.flow.leader_missing`，部门主管审批整链不可用。故 `initialize` 增加
    /// 每次启动都执行的幂等回填。本测试**主动构造存量库漂移**（主管全部置 NULL），
    /// 因此能真正证伪：若回填函数被移除、作用域写错（漏 `tenant_id = 0`）或失去幂等性，
    /// 断言必红。（不放集成测试：集成库会跑 `Migrator::up`，迁移自身已回填 ⇒ 不可证伪。）
    #[tokio::test]
    async fn ensure_platform_dept_leaders_backfills_platform_only_and_is_idempotent() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("建库失败");
        let backend = db.get_database_backend();

        // 构造两个确定性样本：平台部门（tenant_id=0）与租户部门（tenant_id=7）
        db.execute_raw(Statement::from_string(
            backend,
            "INSERT INTO sys_dept (tenant_id, dept_id, dept_name, leader_user_id, status, del_flag) \
             VALUES (0, 910001, '回填测试-平台部门', NULL, '0', '0')"
                .to_string(),
        ))
        .await
        .expect("插入平台样本部门失败");
        db.execute_raw(Statement::from_string(
            backend,
            "INSERT INTO sys_dept (tenant_id, dept_id, dept_name, leader_user_id, status, del_flag) \
             VALUES (7, 910002, '回填测试-租户部门', NULL, '0', '0')"
                .to_string(),
        ))
        .await
        .expect("插入租户样本部门失败");

        // 模拟存量库漂移：全部主管置空
        db.execute_raw(Statement::from_string(
            backend,
            "UPDATE sys_dept SET leader_user_id = NULL".to_string(),
        ))
        .await
        .expect("模拟漂移失败");

        // 首次调用：平台部门应被回填
        let first = ensure_platform_dept_leaders(&db)
            .await
            .expect("平台部门主管回填失败");
        assert!(first >= 1, "存量库应至少回填 1 个平台部门，实际 {first}");
        assert_eq!(
            dept_leader(&db, 910001).await,
            Some(1),
            "平台部门主管应回填为 admin(1)"
        );
        assert_eq!(
            dept_leader(&db, 910002).await,
            None,
            "租户部门不得被平台回填（否则构成跨租户越权审批）"
        );
        let null_platform = scalar(
            &db,
            "SELECT COUNT(*) AS c FROM sys_dept WHERE tenant_id = 0 AND leader_user_id IS NULL",
        )
        .await;
        assert_eq!(null_platform, 0, "平台部门不得残留无主管");

        // 二次调用：天然幂等（0 行受影响）
        let second = ensure_platform_dept_leaders(&db)
            .await
            .expect("二次回填失败");
        assert_eq!(second, 0, "重复调用应无副作用（幂等）");
    }

    /// 列缺失时安全跳过（老库尚未补列不应报错中断启动）
    #[tokio::test]
    async fn ensure_platform_dept_leaders_skips_when_table_missing() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let rows = ensure_platform_dept_leaders(&db).await.unwrap();
        assert_eq!(rows, 0, "无 sys_dept 表时应安全返回 0 而非报错");
    }

    /// 读取某部门的主管（None = 未设置）
    async fn dept_leader(db: &DatabaseConnection, dept_id: i64) -> Option<i64> {
        let row = db
            .query_one_raw(Statement::from_string(
                db.get_database_backend(),
                format!("SELECT leader_user_id FROM sys_dept WHERE dept_id = {dept_id}"),
            ))
            .await
            .expect("查询部门主管失败")
            .expect("样本部门不存在");
        row.try_get::<Option<i64>>("", "leader_user_id")
            .expect("读取 leader_user_id 失败")
    }

    /// 单列单行标量查询（列须 `AS c` 别名）
    async fn scalar(db: &DatabaseConnection, sql: &str) -> i64 {
        db.query_one_raw(Statement::from_string(
            db.get_database_backend(),
            sql.to_string(),
        ))
        .await
        .expect("查询失败")
        .expect("无结果行")
        .try_get::<i64>("", "c")
        .expect("读取标量失败")
    }
}

#[cfg(test)]
mod scim_group_backfill_tests {
    use super::*;
    use sea_orm::Database;

    /// 存量库最小 DDL（sys_user_role **无 source 列**——模拟迁移 000008 之前的存量结构）
    const MIN_EXISTING_TABLES: &[&str] = &[
        "CREATE TABLE sys_user_role (user_id BIGINT, role_id BIGINT, PRIMARY KEY (user_id, role_id))",
        "CREATE TABLE sys_menu (menu_id INTEGER PRIMARY KEY, menu_name VARCHAR(64), parent_id INTEGER, order_num INTEGER, path VARCHAR(64), component VARCHAR(64), query VARCHAR(64), route_name VARCHAR(64), is_frame VARCHAR(2), is_cache VARCHAR(2), menu_type VARCHAR(2), visible VARCHAR(2), status VARCHAR(2), perms VARCHAR(64), icon VARCHAR(64), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1))",
        "CREATE TABLE sys_role_menu (role_id BIGINT, menu_id BIGINT, PRIMARY KEY (role_id, menu_id))",
    ];

    /// 场景 1：全新空库（连 sys_user_role/sys_menu 都没有）→ 三表 + 兼职表兜底建出、
    /// source 列检查与种子安全跳过、不阻断启动
    #[tokio::test]
    async fn scim_group_backfill_on_empty_db_creates_tables_and_skips_seeds() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        ensure_scim_group_module(&db).await.unwrap();
        let tables = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('sys_scim_group','sys_scim_group_binding','sys_scim_group_member','sys_user_dept')".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(tables.len(), 4, "空库应兜底建出 SCIM 三表 + 兼职表");
        // 空库无 sys_menu：菜单种子应跳过
        let menu = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sqlite_master WHERE type='table' AND name='sys_menu'"
                    .to_string(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            menu.try_get::<i64>("", "c").unwrap(),
            0,
            "空库不应凭空建出 sys_menu"
        );
    }

    /// 场景 2：存量库（sys_user_role 无 source 列 + 有 sys_menu 等系统表）→
    /// source 列补上 + 菜单种子落库 + 重复调用幂等（不报错、不重复行）
    #[tokio::test]
    async fn scim_group_backfill_is_idempotent_on_existing_db() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        for ddl in MIN_EXISTING_TABLES {
            db.execute_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                ddl.to_string(),
            ))
            .await
            .unwrap();
        }
        // 首次调用：source 列补建 + 种子落库
        ensure_scim_group_module(&db).await.unwrap();
        // 重复调用（模拟每次启动）：幂等不报错
        ensure_scim_group_module(&db).await.unwrap();

        // source 列已存在
        assert!(
            sso_has_column(&db, "sys_user_role", "source")
                .await
                .unwrap(),
            "存量库 sys_user_role 应补出 source 列"
        );

        // 菜单 148 + 3 按钮幂等防重（各恰一条）
        for menu_id in [148i64, 3620, 3621, 3622] {
            let count: i64 = db
                .query_one_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("SELECT COUNT(*) AS c FROM sys_menu WHERE menu_id = {menu_id}"),
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get::<i64>("", "c")
                .unwrap();
            assert_eq!(count, 1, "menu {menu_id} 应恰一条（幂等防重）");
        }
        let role_menu: i64 = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_role_menu WHERE role_id = 2 AND menu_id IN (148,3620,3621,3622)".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap();
        assert_eq!(role_menu, 4, "role_menu 授权应恰 4 条");
    }
}
