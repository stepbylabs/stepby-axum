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

#[cfg(test)]
mod schema_equivalence_lock_tests {
    //! 「迁移 ↔ initialize 兜底」schema 等价性总锁。
    //!
    //! 架构约定：存量库启动**不跑 `Migrator::up`**，靠 `initialize` 的 ensure_* 幂等兜底
    //! 把 schema/种子收敛到与最新迁移**等价**。本模块用两个隔离临时 SQLite 把这条约定
    //! 变成可证伪断言：
    //!
    //! - 库 A（迁移侧）：全新空库 → 仅 `Migrator::up`（全部迁移）。
    //! - 库 B（兜底侧）：全新空库 → 仅跑到**兜底约定起点**的迁移（模拟最老存量库，
    //!   见 `FALLBACK_BASELINE_MIGRATION`）→ 按 mod.rs `run()` 原始顺序执行全部兜底
    //!   （`run_all_initialize_fallbacks`，即 `AppInitializer::run` 的「最小可调用形态」）。
    //!
    //! 然后逐表对比 `PRAGMA table_info` 指纹（列名/归一化类型/notnull/pk）：
    //! - 表名集合差异必须逐一登记在显式白名单（`MIGRATION_ONLY_TABLES` /
    //!   `FALLBACK_ONLY_TABLES`）并附理由——白名单不是豁免，而是「已判定为合理」的台账；
    //! - 未登记的任何结构差异（缺表/缺列/类型实质冲突）直接红。
    //!
    //! 若有人新增迁移而未同步兜底（或反之），本测试必红，迫使作者在
    //! 「补兜底 / 登记白名单」之间做出显式决定，杜绝静默漂移。
    use super::*;
    use crate::config::UploadConfig;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 兜底约定起点：首个带「存量库启动不跑 Migrator::up，需 ensure_* 兜底」注释的
    /// 等价迁移是 m20260806_000002_add_task_operator_id（ensure_task_operator_id_column），
    /// 故基线取其前一条（m20260806_000001，纯索引迁移，schema 与其前一条相同）。
    /// 在该基线之上的所有 schema/种子差异都必须由 ensure_* 兜底或显式白名单解释。
    const FALLBACK_BASELINE_MIGRATION: &str = "m20260806_000001_add_log_time_indexes";

    /// 库 A 有而库 B 无的表：**纯迁移管理表**白名单（显式命名 + 理由）。
    /// 判定标准：initialize 侧对该模块有**显式让位证据**——相关兜底均以
    /// `sso_table_exists` 守卫跳过（「由 migration 负责建表」口径），
    /// 即架构已裁决该模块的存量库补齐走迁移而非兜底。
    /// ⚠️ 若下表新增成员而无对应让位守卫，说明存在真漂移（存量库 500）。
    const MIGRATION_ONLY_TABLES: &[&str] = &[
        // 消息模块（m20260818_000002_msg_module）：ensure_flow_seeds /
        // ensure_msg_template_seeds / ensure_sms_cloud_columns 均以表存在性守卫让位。
        "sys_msg_channel",
        "sys_msg_template",
        "sys_msg_send_log",
        // SSO/OAuth 模块（m20260819_000001 / m20260922_000001）：全部 sso 兜底
        // （ensure_sso_v4_columns / ensure_sso_rs256_keys / ensure_sso_consent_unique /
        //   ensure_oauth_client_key_id_column / ensure_oauth_client_prev_secret_column）
        // 均以 sso_table_exists 守卫让位（「SSO 表尚未创建，跳过（由 migration 负责建表）」）。
        "sys_oauth_client",
        "sys_oauth_consent",
        "sys_oauth_provider",
        "sys_oauth_user",
        // 报表模块（m20260819_000003）：G-01 只兜新增的 report_dataset/report_dashboard，
        // 老报表两表归迁移管理。
        "sys_report",
        "sys_report_sub",
        // 用户偏好（m20260819_000004）：无兜底，migration 管理。
        "sys_user_pref",
        // WebHook 模块（m20260820_000002）：ensure_webhook_subscription_unify 列兜底与
        // ensure_perf_indexes 索引兜底均以表存在性守卫让位。
        "sys_web_hook",
        "sys_web_hook_log",
        // 前端错误（m20260821_000001）：ensure_frontend_error_device_type 表不存在即跳过。
        "sys_frontend_error",
    ];

    /// 库 B 有而库 A 无的表：**兜底超集**白名单（显式命名 + 理由）。
    /// 兜底侧建出的表而全量迁移没有——通常是历史兼容遗留。
    const FALLBACK_ONLY_TABLES: &[&str] = &[];

    /// 列级差异白名单：确证合理的「兜底超集」列（迁移侧缺失、由兜底每次启动幂等补齐）。
    /// (表, 列) —— 理由注释必须随行给出。
    const COLUMN_SUPERSET_OK: &[(&str, &str)] = &[
        // sys_user.password_version：迁移 m20261001_000001_shared_store 建三表但未含该列；
        // ensure_user_password_version_column 每次启动幂等补列（全新部署路径同样执行，
        // 行为不依赖迁移侧提供）——属兜底超集（合理）而非漂移。
        ("sys_user", "password_version"),
    ];

    /// 进程内自增序号：保证临时库路径唯一（与 repository/test_support 同款防撞）。
    static LOCK_DB_SEQ: AtomicU64 = AtomicU64::new(0);

    /// 唯一临时 sqlite 文件库
    async fn fresh_db(tag: &str) -> (DatabaseConnection, std::path::PathBuf) {
        let pid = std::process::id();
        let seq = LOCK_DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let p =
            std::env::temp_dir().join(format!("stepby_schema_lock_{tag}_{pid}_{seq}_{nanos}.db"));
        let url = format!("sqlite://{}?mode=rwc", p.to_string_lossy());
        (Database::connect(&url).await.unwrap(), p)
    }

    /// `AppInitializer::run()` 的最小可调用形态：按 mod.rs `run()` 的**原始顺序**
    /// 调用全部会动 schema/种子的兜底。与 `run()` 的刻意差异（均不产 schema/种子）：
    /// logger / 能力位注入（进程级全局态，测试禁触）、SharedStore/Redis/scheduler/
    /// storage/AppState 组装、三个仅告警的自检、以及需要 SharedStore 的数据治理收敛。
    /// 覆盖完整性由 `fallback_harness_covers_all_ensure_calls_in_run` 静态锁保证。
    async fn run_all_initialize_fallbacks(db: &DatabaseConnection) -> anyhow::Result<()> {
        let upload_cfg = UploadConfig::default();
        // 3.1 G18：sys_user.country_code
        ensure_user_country_code_column(db).await?;
        // 3.1.1 v5-N2 Phase 2：sys_user.tenant_id
        ensure_user_tenant_id_column(db).await?;
        // 3.1.3 v5-D12：sys_user.scim_external_id（mod.rs 内联兜底，逐字同口径）
        if !sso_has_column(db, "sys_user", "scim_external_id").await? {
            db.execute_raw(Statement::from_string(
                db.get_database_backend(),
                "ALTER TABLE sys_user ADD COLUMN scim_external_id VARCHAR(255)".to_string(),
            ))
            .await?;
        }
        // 3.1.4 v5-D5：sys_oauth_client.sector_identifier_uri（表由 migration 管理，缺表安全跳过）
        if sso_table_exists(db, "sys_oauth_client").await?
            && !sso_has_column(db, "sys_oauth_client", "sector_identifier_uri").await?
        {
            db.execute_raw(Statement::from_string(
                db.get_database_backend(),
                "ALTER TABLE sys_oauth_client ADD COLUMN sector_identifier_uri VARCHAR(255)"
                    .to_string(),
            ))
            .await?;
        }
        // 3.1.2：sys_dept.leader_user_id（真实运行验证发现的存量库漂移）
        if sso_table_exists(db, "sys_dept").await?
            && !sso_has_column(db, "sys_dept", "leader_user_id").await?
        {
            db.execute_raw(Statement::from_string(
                db.get_database_backend(),
                "ALTER TABLE sys_dept ADD COLUMN leader_user_id BIGINT".to_string(),
            ))
            .await?;
        }
        // 3.1.2b 主管回填（审批链前置条件）
        ensure_platform_dept_leaders(db).await?;
        // 3.2 P0-2：sys_task.operator_id
        ensure_task_operator_id_column(db).await?;
        // 3.3 Tier-S #2：sys_oper_log.oper_diff
        ensure_oper_log_diff_column(db).await?;
        // 3.4 Tier-S #3：data_rule 两表 + sys_pat
        ensure_data_rule_tables(db).await?;
        ensure_sys_pat_table(db).await?;
        // 3.5 PAT 管理菜单
        ensure_sys_pat_menu(db).await?;
        // 3.5b 审批工作流模块（等价 m20260923_000002）
        ensure_flow_module(db).await?;
        // 3.5c SCIM Group + 多部门任职（等价 m20260924_000008/000009）
        ensure_scim_group_module(db).await?;
        // 3.5d 多租户 Phase 2（等价 m20260925_000001/000002）
        ensure_multitenant_module(db).await?;
        // 3.5d-2 租户自助域名菜单（等价 m20260926_000011）
        ensure_domain_self_service_menu(db).await?;
        // 3.5d-3 备份权限粒度化菜单（等价 m20260926_000012）
        ensure_backup_permission_menus(db).await?;
        // 3.5d-4 前端错误 device_type（等价 m20260928_000002）
        ensure_frontend_error_device_type(db).await?;
        // 3.5d-5 数据看板菜单去重（等价 m20260928_000003）
        ensure_dashboard_menu_dedupe(db).await?;
        // 3.5d-6' 菜单-only 迁移兜底（135/3410/3550/3551）
        ensure_menu_only_migration_menus(db).await?;
        // 3.5d-6 菜单信息架构优化（等价 m20260928_000004）
        ensure_menu_structure_optimize(db).await?;
        // 3.5d-8 AI 助手菜单
        ensure_ai_menu(db).await?;
        // 3.5d-4(3) 租户自建导航菜单（等价 m20260926_000014）
        ensure_tenant_nav_menu(db).await?;
        // 3.5e 多租户 Phase 3（等价 m20260925_000003）
        ensure_tenant_phase3(db).await?;
        // 3.5f 多租户 SaaS 治理（等价 m20260925_000004）
        ensure_tenant_saas_governance(db).await?;
        // 3.5f' 治理参数项缺行补齐（批次十四）
        ensure_governance_config_rows(db).await?;
        // 3.5g 唯一域租户化（等价 m20260925_000005）
        ensure_tenant_unique_scope(db).await?;
        // 3.5h 租户角色菜单治理
        ensure_tenant_role_menu_governance(db).await?;
        // 3.5i 存量上传路径回填（数据级；默认 local 档）
        ensure_legacy_upload_paths(db, &upload_cfg).await?;
        // 3.5j 台账 P0-2：sys_role.is_system
        ensure_role_is_system_column(db).await?;
        // 3.5j-b 台账：sys_role.custom_sql（等价 m20260819_000005）
        ensure_role_custom_sql_column(db).await?;
        // 3.5k 台账 F-8：sys_logininfor.user_id
        ensure_logininfor_user_id_column(db).await?;
        // 3.5.5 gen_table_column Rust 命名（等价 m20260926_000009）
        ensure_gen_column_rust_naming(db).await?;
        // 3.5.6 sys_tenant_package.features（等价 m20260926_000010）
        ensure_tenant_package_features(db).await?;
        // 3.5.7 WebAuthn 凭据表（等价 m20260927_000002）
        ensure_sys_user_credential_table(db).await?;
        // 3.6 SSO v4 列（等价 m20260923_000001；空 enc_key = 迁移期 fail-open 同口径）
        ensure_sso_v4_columns(db, "").await?;
        // 3.9 共享态存储持久层（等价 m20261001_000001）
        ensure_shared_store_tables(db).await?;
        ensure_user_password_version_column(db).await?;
        ensure_user_must_change_pwd_column(db).await?;
        // 3.10 链感知保留（等价 m20261008_000001）
        migration::migrations::m20261008_000001_log_archive_anchor::init_log_archive_anchor(db)
            .await?;
        // 4.2 SSO 限流分档（等价 m20260924_000001）
        ensure_sso_rate_limit_tiers(db).await?;
        // 4.3 运行期敏感凭据回填（空 enc_key = 跳过，与迁移期 fail-open 一致；数据级）
        ensure_runtime_secrets_encrypted(db, "").await;
        // 4.4 SSO consent 唯一索引（等价 m20260924_000002）
        ensure_sso_consent_unique(db).await?;
        // 4.5 RS256 列补齐（等价 m20260924_000003/000004；空 enc_key 跳过密钥生成）
        ensure_sso_rs256_keys(db, "").await?;
        // 4.5b key_id 列（等价 m20260926_000004）
        ensure_oauth_client_key_id_column(db).await?;
        // 4.5c previous_client_secret_hash 列（等价 m20260927_000001）
        ensure_oauth_client_prev_secret_column(db).await?;
        // 4.5c-b sys_job_log.duration_ms（等价 m20261007_000001）
        ensure_job_log_duration_column(db).await?;
        // 4.5c-c 消息模板 seed（G-16）
        ensure_msg_template_seeds(db).await?;
        // 4.5c-d OSS 配置菜单（等价 m20261007_000002）
        ensure_upload_config_menu(db).await?;
        // 4.5c-e flow_definition + report 两表 + 菜单（等价 m20261007_000003/4/5）
        ensure_flow_definition_table(db).await?;
        ensure_report_tables(db).await?;
        ensure_flow_report_menus(db).await?;
        ensure_report_menus_visible(db).await?;
        ensure_ai_history_menu_parent(db).await?;
        // 4.5c-h 批五十六：归档按钮菜单补种（等价迁移 m20261012_000001；幂等）
        ensure_archive_menus(db).await?;
        // 4.5c-i 批五十六：皮肤/主题键治理修正（legacy 三元组守卫；幂等）
        ensure_skin_governance(db).await?;
        // 4.5c-j 批六十：菜单 4122 终态收敛（等价迁移 m20261006_000002 种子；幂等）
        ensure_data_rule_menu_alignment(db).await?;
        ensure_flow_designer_menu_visible(db).await?;
        // 4.5c-k 批六十四：菜单软删标记归一（等价迁移 m20261013_000001；幂等）
        ensure_menu_del_flag_normalized(db).await?;
        ensure_flow_task_action_columns(db).await?;
        ensure_flow_graph_doc_table(db).await?;
        ensure_sms_cloud_columns(db).await?;
        // 4.5d 性能索引（等价 m20261002_000001）
        ensure_perf_indexes(db).await?;
        // 4.5e 审计合规域（等价 m20261003_000001）
        ensure_audit_change_tables(db).await?;
        // 4.5f Webhook 事件域（等价 m20261003_000002）
        ensure_webhook_event_tables(db).await?;
        // 4.5g 告警规则（等价 m20261003_000003）
        ensure_alert_rule_tables(db).await?;
        // 4.5h Webhook 订阅双轨收敛（等价 m20261003_000004）
        ensure_webhook_subscription_unify(db).await?;
        // 4.5i 字段级权限（等价 m20261003_000005）
        ensure_role_field_perm_tables(db).await?;
        // 4.5j 报表看板（等价 m20261003_000006）
        ensure_report_board_tables(db).await?;
        Ok(())
    }

    /// 归一化列类型：仅收编**经真实 diff 确证等价**的写法族（SQLite 类型亲和规则）。
    /// 归一化依据（SQLite affinity 判定：含 INT → INTEGER；含 CHAR/TEXT → TEXT；否则 NUMERIC；
    /// 且 SQLite 不强制 VARCHAR/CHAR 长度——迁移侧 m20260719_000001 的 WARN 即此口径）：
    /// - INTEGER ↔ BIGINT：同属 INTEGER 亲和，sea-orm 同映射 i64
    ///   （观测对：sys_task.operator_id / sys_job_log.duration_ms / *_expire_at 等）；
    /// - CHAR(N) ↔ VARCHAR(N)：同属 TEXT 亲和，无长度强制
    ///   （观测对：sys_data_rule.del_flag/status）；
    /// - DATETIME ↔ DATETIME_TEXT ↔ TIMESTAMP：值恒为 sea-orm 渲染的非数值时间字符串，
    ///   NUMERIC/TEXT 亲和对其存取行为一致（观测对：sys_data_rule/sys_user_credential 时间列）。
    ///
    /// 不在族内的写法差异（如 VARCHAR(N) vs TEXT、缺列）一律视为漂移。
    fn normalize_col_type(ty: &str) -> String {
        let up = ty.trim().to_ascii_uppercase();
        let collapsed: String = up.split_whitespace().collect::<Vec<_>>().join(" ");
        match collapsed.as_str() {
            "DATETIME" | "DATETIME_TEXT" | "TIMESTAMP" => "DATETIME".to_string(),
            _ if collapsed.starts_with("CHAR") => format!("VARCHAR{}", &collapsed[4..]),
            _ if collapsed.contains("INT") => "INTEGER".to_string(),
            _ => collapsed,
        }
    }

    /// 每表列指纹：(列名, 归一化类型, notnull, pk) 排序串
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct ColFp {
        name: String,
        ty: String,
        notnull: bool,
        pk: bool,
    }

    async fn load_schema(db: &DatabaseConnection) -> anyhow::Result<BTreeMap<String, Vec<ColFp>>> {
        let backend = DatabaseBackend::Sqlite;
        let tables = db
            .query_all_raw(Statement::from_string(
                backend,
                "SELECT name FROM sqlite_master WHERE type='table' \
                 AND name NOT LIKE 'sqlite_%' AND name != 'seaql_migrations'"
                    .to_string(),
            ))
            .await?;
        let mut map = BTreeMap::new();
        for t in tables {
            let name: String = t.try_get("", "name")?;
            let cols = db
                .query_all_raw(Statement::from_string(
                    backend,
                    format!("PRAGMA table_info({name})"),
                ))
                .await?;
            let mut fps = Vec::new();
            for c in &cols {
                let ty = normalize_col_type(&c.try_get::<String>("", "type").unwrap_or_default());
                let pk = c.try_get::<i64>("", "pk").unwrap_or(0) != 0;
                let mut notnull = c.try_get::<i64>("", "notnull").unwrap_or(0) != 0;
                // 单列 INTEGER PRIMARY KEY 是 rowid 别名：显式 NULL 会自动生成 rowid，
                // PRAGMA notnull 位不影响行为（观测对：sys_user_credential.cred_id /
                // sys_data_rule.rule_id 迁移与兜底对同一逻辑列 notnull 标记不同）。
                // 复合主键不受此豁免（NOT NULL 真实生效）。
                let pk_cols = cols
                    .iter()
                    .filter(|x| x.try_get::<i64>("", "pk").unwrap_or(0) != 0)
                    .count();
                if pk && pk_cols == 1 && ty == "INTEGER" {
                    notnull = false;
                }
                fps.push(ColFp {
                    name: c.try_get::<String>("", "name")?,
                    ty,
                    notnull,
                    pk,
                });
            }
            fps.sort();
            map.insert(name, fps);
        }
        Ok(map)
    }

    /// 单值键集查询：sql 须返回一列字符串
    async fn key_set(db: &DatabaseConnection, sql: &str) -> anyhow::Result<BTreeSet<String>> {
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                sql.to_string(),
            ))
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.try_get::<String>("", "k").unwrap_or_default())
            .collect())
    }

    /// 种子差异白名单：与 MIGRATION_ONLY_TABLES **共退让**的模块菜单。
    /// 这些菜单所属模块的表均为纯迁移管理（见 MIGRATION_ONLY_TABLES 理由）：
    /// 表与菜单同进同退——极老存量库补齐该模块须整模块跑迁移，只补菜单
    /// 反而制造「入口可见但页面 500」的假入口。键形如 "menu_id:perms"。
    fn seed_diff_whitelisted(table: &str, key: &str) -> bool {
        if table != "sys_menu" {
            return false;
        }
        let id: i64 = key
            .split(':')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(-1);
        // 消息模块：140 目录 + 141-143 页面 + 3101-3123 按钮
        // OAuth 模块：145 目录 + 146-147 页面 + 3261-3268 按钮
        // 报表模块：151 目录 + 152-153 页面 + 3431-3445 按钮
        // WebHook 模块：157 目录 + 158-159 页面 + 3531-3544 按钮
        // 前端错误模块：160 页面 + 1061 按钮
        (140..=143).contains(&id)
            || (145..=147).contains(&id)
            || (151..=153).contains(&id)
            || (157..=159).contains(&id)
            || (3101..=3123).contains(&id)
            || (3261..=3268).contains(&id)
            || (3431..=3445).contains(&id)
            || (3531..=3544).contains(&id)
            || id == 160
            || id == 1061
    }

    /// 总锁：迁移侧 vs 兜底侧的表集合 + 每表列指纹 + 种子键集 全量对比
    #[tokio::test]
    async fn schema_equivalence_lock() {
        // ---- 库 A：迁移侧（全部迁移） ----
        let (db_a, path_a) = fresh_db("migr").await;
        migration::Migrator::up(&db_a, None)
            .await
            .expect("迁移侧建库失败");

        // ---- 库 B：兜底侧（基线迁移 + initialize 兜底） ----
        let (db_b, path_b) = fresh_db("fallback").await;
        // 基线 = 兜底约定起点（含）之前的全部迁移
        let mut baseline = 0u32;
        for m in migration::Migrator::migrations() {
            baseline += 1;
            if m.name() == FALLBACK_BASELINE_MIGRATION {
                break;
            }
        }
        assert!(
            baseline > 0,
            "兜底基线迁移未找到: {FALLBACK_BASELINE_MIGRATION}"
        );
        migration::Migrator::up(&db_b, Some(baseline))
            .await
            .expect("兜底侧基线建库失败");
        run_all_initialize_fallbacks(&db_b)
            .await
            .expect("initialize 兜底 harness 执行失败（存量库启动路径在真实环境会同样失败）");

        // ---- 指纹提取与对比 ----
        let sa = load_schema(&db_a).await.unwrap();
        let sb = load_schema(&db_b).await.unwrap();
        let mut report = String::new();
        let mut problems = 0usize;

        // 1) 表集合差异（白名单须逐一登记）
        let only_a: Vec<&String> = sa.keys().filter(|t| !sb.contains_key(*t)).collect();
        let only_b: Vec<&String> = sb.keys().filter(|t| !sa.contains_key(*t)).collect();
        for t in &only_a {
            if MIGRATION_ONLY_TABLES.contains(&t.as_str()) {
                report.push_str(&format!("[表] {t}: 仅迁移侧（已登记白名单）\n"));
            } else {
                problems += 1;
                report.push_str(&format!(
                    "[表] {t}: 仅迁移侧，兜底缺失且未登记 MIGRATION_ONLY_TABLES —— 存量库将 500，须补兜底或登记白名单\n"
                ));
            }
        }
        for t in &only_b {
            if FALLBACK_ONLY_TABLES.contains(&t.as_str()) {
                report.push_str(&format!("[表] {t}: 仅兜底侧（已登记白名单）\n"));
            } else {
                problems += 1;
                report.push_str(&format!(
                    "[表] {t}: 仅兜底侧，迁移缺失且未登记 FALLBACK_ONLY_TABLES —— 须对齐迁移或登记白名单\n"
                ));
            }
        }

        // 2) 共有表的列指纹差异
        let mut col_diffs = 0usize;
        for (t, fa) in &sa {
            let Some(fb) = sb.get(t) else { continue };
            let set_a: BTreeSet<&ColFp> = fa.iter().collect();
            let set_b: BTreeSet<&ColFp> = fb.iter().collect();
            for fp in set_a.difference(&set_b) {
                if COLUMN_SUPERSET_OK.contains(&(t, fp.name.as_str())) {
                    report.push_str(&format!(
                        "[列] {t}.{}: 仅兜底侧（已登记列级超集白名单）\n",
                        fp.name
                    ));
                    continue;
                }
                col_diffs += 1;
                problems += 1;
                report.push_str(&format!(
                    "[列] {t}.{}: 仅迁移侧（迁移侧指纹 {fp:?}）—— 存量库实体 SELECT 将 500\n",
                    fp.name
                ));
            }
            for fp in set_b.difference(&set_a) {
                if COLUMN_SUPERSET_OK.contains(&(t, fp.name.as_str())) {
                    report.push_str(&format!(
                        "[列] {t}.{}: 仅兜底侧（已登记列级超集白名单）\n",
                        fp.name
                    ));
                    continue;
                }
                col_diffs += 1;
                problems += 1;
                report.push_str(&format!(
                    "[列] {t}.{}: 仅兜底侧（兜底侧指纹 {fp:?}）—— 迁移与兜底 DDL 漂移\n",
                    fp.name
                ));
            }
        }

        // 3) 种子等价：兜底侧 seed 的主要表，A/B 键集必须一致。
        // sys_menu 仅比对**未软删**行（del_flag='0'：软删菜单非功能入口，
        // 且 A 侧存在 m20261007_000011 软删 4115 的记账行，B 不应有）。
        // 「迁移侧有兜底无」的差集须为空或全部命中 SEED_MENU_MODULE_DEFER_OK。
        let mut seed_problems = 0usize;
        let mut seed_report = String::new();
        for (table, sql, desc) in [
            (
                "sys_menu",
                "SELECT menu_id || ':' || perms AS k FROM sys_menu WHERE del_flag = '0'",
                "菜单（menu_id+perms）",
            ),
            (
                "sys_dict_type",
                "SELECT dict_type AS k FROM sys_dict_type",
                "字典类型",
            ),
            (
                "sys_dict_data",
                "SELECT dict_type || ':' || dict_value AS k FROM sys_dict_data",
                "字典数据（type+value）",
            ),
            (
                "sys_config",
                "SELECT config_key AS k FROM sys_config",
                "参数配置",
            ),
            (
                "sys_webhook_event",
                "SELECT event_key AS k FROM sys_webhook_event",
                "Webhook 事件",
            ),
            (
                "sys_msg_template",
                "SELECT template_code AS k FROM sys_msg_template",
                "消息模板",
            ),
        ] {
            if !sa.contains_key(table) || !sb.contains_key(table) {
                continue;
            }
            let ka = key_set(&db_a, sql).await.unwrap();
            let kb = key_set(&db_b, sql).await.unwrap();
            let miss_b: Vec<_> = ka
                .difference(&kb)
                .filter(|k| !seed_diff_whitelisted(table, k))
                .collect();
            let miss_a: Vec<_> = kb.difference(&ka).collect();
            if !miss_b.is_empty() || !miss_a.is_empty() {
                seed_problems += miss_b.len() + miss_a.len();
                seed_report.push_str(&format!(
                    "[种子] {desc}（{table}）: 迁移侧有兜底无 {miss_b:?}；兜底侧有迁移无 {miss_a:?}\n"
                ));
            }
        }

        assert_eq!(
            problems,
            0,
            "迁移侧 ↔ initialize 兜底侧 schema 漂移 {problems} 处（表集合差异 {}+{}，列指纹差异 {col_diffs}）：\n\
             ===== 真实 diff 报告 =====\n{report}\n\
             处理规则：补齐兜底（首选）或将确证合理的差异显式登记入 MIGRATION_ONLY_TABLES / FALLBACK_ONLY_TABLES 并附理由",
            only_a.len(),
            only_b.len()
        );
        assert_eq!(
            seed_problems, 0,
            "种子等价性破坏 {seed_problems} 处：\n{seed_report}"
        );

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    /// 覆盖静态锁：`mod.rs` `run()` 中出现的每个 `ensure_*(` 调用都必须被
    /// `run_all_initialize_fallbacks` 覆盖。防止 harness 与生产编排漂移——
    /// 新增兜底函数接入 run() 后若未纳入本测试，此处必红。
    #[test]
    fn fallback_harness_covers_all_ensure_calls_in_run() {
        // 经 concat! 间接引用：`include_str!(` 的尾部 `tr!(` 会被 i18n key 扫描正则
        // （tr!\s*\(\s*"…"）误捕为 key "mod.rs"（all_tr_keys_exist_in_both_locale_files 实测）。
        let source = include_str!(concat!("mod.rs"));
        let mut called = BTreeSet::new();
        let bytes = source.as_bytes();
        let mut i = 0;
        while let Some(pos) = source[i..].find("ensure_") {
            let abs = i + pos;
            let mut j = abs;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let name = &source[abs..j];
            // 仅统计后随 '(' 的标识符（真实调用形态），注释散文中的 ensure_* 不计
            if name.len() > "ensure_".len() && source[j..].trim_start().starts_with('(') {
                called.insert(name.to_string());
            }
            i = j.max(abs + 1);
        }
        assert!(
            !called.is_empty(),
            "mod.rs 解析结果为空——解析逻辑与源码形态失配，须修复本测试"
        );
        // harness 覆盖的 ensure_* 名单（与 run_all_initialize_fallbacks 内的调用一一对应）
        // 显式豁免（非 schema/种子兜底，与数据库结构无关）：
        // - ensure_sqlite_parent_dir：纯文件系统兜底（为 sqlite 文件建父目录），无 SQL 执行。
        const NON_SCHEMA_EXEMPT: &[&str] = &["ensure_sqlite_parent_dir"];
        let harness_covers: &[&str] = &[
            "ensure_user_country_code_column",
            "ensure_user_tenant_id_column",
            "ensure_platform_dept_leaders",
            "ensure_task_operator_id_column",
            "ensure_oper_log_diff_column",
            "ensure_data_rule_tables",
            "ensure_sys_pat_table",
            "ensure_sys_pat_menu",
            "ensure_flow_module",
            "ensure_scim_group_module",
            "ensure_multitenant_module",
            "ensure_domain_self_service_menu",
            "ensure_backup_permission_menus",
            "ensure_frontend_error_device_type",
            "ensure_dashboard_menu_dedupe",
            "ensure_menu_structure_optimize",
            "ensure_menu_only_migration_menus",
            "ensure_ai_menu",
            "ensure_tenant_nav_menu",
            "ensure_tenant_phase3",
            "ensure_tenant_saas_governance",
            "ensure_governance_config_rows",
            "ensure_tenant_unique_scope",
            "ensure_tenant_role_menu_governance",
            "ensure_legacy_upload_paths",
            "ensure_role_is_system_column",
            "ensure_role_custom_sql_column",
            "ensure_logininfor_user_id_column",
            "ensure_gen_column_rust_naming",
            "ensure_tenant_package_features",
            "ensure_sys_user_credential_table",
            "ensure_sso_v4_columns",
            "ensure_shared_store_tables",
            "ensure_user_password_version_column",
            "ensure_user_must_change_pwd_column",
            "ensure_sso_rate_limit_tiers",
            "ensure_runtime_secrets_encrypted",
            "ensure_sso_consent_unique",
            "ensure_sso_rs256_keys",
            "ensure_oauth_client_key_id_column",
            "ensure_oauth_client_prev_secret_column",
            "ensure_job_log_duration_column",
            "ensure_msg_template_seeds",
            "ensure_upload_config_menu",
            "ensure_flow_definition_table",
            "ensure_report_tables",
            "ensure_flow_report_menus",
            "ensure_report_menus_visible",
            "ensure_ai_history_menu_parent",
            "ensure_archive_menus",
            "ensure_skin_governance",
            "ensure_data_rule_menu_alignment",
            "ensure_flow_designer_menu_visible",
            "ensure_menu_del_flag_normalized",
            "ensure_flow_task_action_columns",
            "ensure_flow_graph_doc_table",
            "ensure_sms_cloud_columns",
            "ensure_perf_indexes",
            "ensure_audit_change_tables",
            "ensure_webhook_event_tables",
            "ensure_alert_rule_tables",
            "ensure_webhook_subscription_unify",
            "ensure_role_field_perm_tables",
            "ensure_report_board_tables",
        ];
        let missing: Vec<_> = called
            .iter()
            .filter(|n| {
                !harness_covers.contains(&n.as_str()) && !NON_SCHEMA_EXEMPT.contains(&n.as_str())
            })
            .collect();
        assert!(
            missing.is_empty(),
            "mod.rs run() 中存在未被 schema 等价性总锁覆盖的兜底调用 {missing:?}——\
             请将其纳入 run_all_initialize_fallbacks（保持 run() 原始顺序），\
             若确认与 schema/种子无关须在此说明并同步更新本清单"
        );
    }
}

#[cfg(test)]
mod rate_limit_guard_tests {
    use super::*;
    use crate::config::settings::RateLimitMode;

    /// 多实例 + 限流档位自检的**可证伪**回归锁（M-8）。
    ///
    /// 语义：`[scheduler].replicas > 1` 且 `[rate_limit].mode = "local"` ⇒ 进程内令牌桶
    /// 各副本独立计数，攻击者轮询不同副本即可把配额放大 N 倍，自检必须"报出来"。
    ///
    /// 四象限全覆盖——任一角写反/写漏即红：
    /// ① 多实例 + local ⇒ **命中**（真实缺口）；
    /// ② 多实例 + redis ⇒ 不命中（分布式桶共享配额，正确配置不告警）；
    /// ③ 单实例 + local ⇒ 不命中（默认部署，零行为变更）；
    /// ④ 单实例 + redis ⇒ 不命中（显式升级，合法）。
    #[test]
    fn rate_limit_local_multi_instance_guard_matrix() {
        // ① 多实例 + local ⇒ 命中
        assert!(
            rate_limit_local_multi_instance_misconfigured(3, RateLimitMode::Local),
            "多副本 + local 档必须命中（配额可被放大 N 倍）"
        );
        // ② 多实例 + redis ⇒ 不命中
        assert!(
            !rate_limit_local_multi_instance_misconfigured(3, RateLimitMode::Redis),
            "多副本 + redis 档不应命中（分布式令牌桶共享配额）"
        );
        // ③ 单实例 + local ⇒ 不命中（默认部署零行为变更）
        assert!(
            !rate_limit_local_multi_instance_misconfigured(1, RateLimitMode::Local),
            "单实例 + local 档不应命中（默认部署，零行为变更）"
        );
        // ④ 单实例 + redis ⇒ 不命中
        assert!(
            !rate_limit_local_multi_instance_misconfigured(1, RateLimitMode::Redis),
            "单实例 + redis 档不应命中"
        );
    }

    /// 默认档位（`SchedulerConfig::default().replicas = 1` + `RateLimitSettings::default().mode() = local`）
    /// ⇒ 守卫**不得**触发，锁住"缺省值 = 现状 = 安全态"这一铁律
    /// （新增开关/守卫不得改变存量部署行为）。
    #[test]
    fn default_config_does_not_trigger_rate_limit_guard() {
        use crate::config::settings::{RateLimitSettings, SchedulerConfig};
        let scheduler = SchedulerConfig::default();
        let rate_limit = RateLimitSettings::default();
        assert_eq!(scheduler.replicas, 1, "默认副本数必须为 1");
        assert_eq!(
            rate_limit.mode(),
            RateLimitMode::Local,
            "默认限流档位必须为 local（= 现状）"
        );
        assert!(
            !rate_limit_local_multi_instance_misconfigured(scheduler.replicas, rate_limit.mode()),
            "默认配置（单实例 + local）不得触发多实例限流告警"
        );
    }
}

#[cfg(test)]
mod menu_del_flag_normalize_tests {
    use super::*;
    use sea_orm::ConnectionTrait;

    /// 批六十四：菜单软删标记归一（`del_flag='1'` → `'2'`）——可证伪回归锁。
    ///
    /// 语义：应用层 `delete_menu` 写 `'2'`、守卫以 `== "2"` 判定"已删"，而历史遗留
    /// （m20261007_000011 批十四菜单卫生）写的是 `'1'`。归一后"已删"表示单值化，
    /// 详情/删除守卫对历史软删行同样生效。任一处写反（归一值/WHERE 条件）即红。
    #[tokio::test]
    async fn normalizes_legacy_del_flag_one_to_two() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("建库失败");
        let backend = db.get_database_backend();

        // 造一条 del_flag='1' 遗留行（迁移已归一为 '2'，此处回退模拟存量库遗留态）
        db.execute_raw(Statement::from_string(
            backend,
            "UPDATE sys_menu SET del_flag = '1' WHERE menu_id = 4115".to_string(),
        ))
        .await
        .expect("造数失败");

        ensure_menu_del_flag_normalized(&db)
            .await
            .expect("归一失败");

        let row = db
            .query_one_raw(Statement::from_string(
                backend,
                "SELECT del_flag FROM sys_menu WHERE menu_id = 4115".to_string(),
            ))
            .await
            .expect("查询失败")
            .expect("行不存在");
        let flag: String = row.try_get("", "del_flag").unwrap_or_default();
        assert_eq!(flag, "2", "遗留 del_flag='1' 应归一为 '2'");

        // 幂等：再跑一次不改变结果、不报错
        ensure_menu_del_flag_normalized(&db)
            .await
            .expect("二次归一失败");
    }
}
