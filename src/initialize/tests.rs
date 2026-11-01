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
    ///
    /// b73 轮 15：4002「变更导出」的 role_menu 授权按 common 只读策略**不再发放**
    /// （菜单行照旧）。对照组：4000/4001 的授权必须仍在——若策略判据失效（例如
    /// 例外表被清空或后缀集合写错），本用例的两处 `assert_eq!` 会同时变红。
    #[test]
    fn audit_menu_seed_bodies_match_legacy_sql() {
        let bodies = audit_mig::audit_menu_seed_bodies("NOW()");
        assert_eq!(
            bodies.len(),
            5,
            "3 菜单行 + 2 role_menu 行（4002 按策略拒发）"
        );
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
        assert!(
            !bodies.iter().any(|b| b.contains("(2, 4002)")),
            "4002 导出授权复活——common 只读策略被绕过"
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

    /// webhook 菜单按钮：3562 授予、3563 按策略拒发；语句体与重构前手抄逐字符等价
    ///
    /// b73 轮 15：3563「测试发送」构造**真实出站投递**，属越权面，不再默认授予 common。
    /// 对照组：3562 的 `:list` 授权仍在（判据若整体失效，两处断言同时变红）。
    #[test]
    fn webhook_menu_seed_bodies_match_legacy_sql() {
        let bodies = webhook_mig::webhook_menu_seed_bodies("NOW()");
        assert_eq!(
            bodies.len(),
            3,
            "2 菜单行 + 1 role_menu 行（3563 按策略拒发）"
        );
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
        assert!(
            !bodies.iter().any(|b| b.contains("(2, 3563)")),
            "3563 测试发送授权复活——common 只读策略被绕过"
        );
    }

    /// 告警菜单种子：4110-4114 集合一致；仅页面 4110 授予 role_menu，且**必须走策略体**
    #[test]
    fn alert_menu_seed_bodies_match_legacy_sql() {
        let bodies = alert_mig::alert_menu_seed_bodies("NOW()");
        assert_eq!(bodies.len(), 6, "页面 role_menu + 5 菜单行");
        assert_eq!(
            bodies[0],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES (4110, '告警规则', 2, 60, 'alert', 'monitor/alert/index', '', '', '1', '0', 'C', '0', '0', 'monitor:alert:list', 'alert', 'admin', NOW(), '告警规则引擎菜单', '0')"
        );
        // 批七十四 B3：本条被 `ensure_alert_rule_tables` 每次启动执行 ⇒ 属"兜底发放"，
        // 按 AGENTS 铁律必须套 governance 策略子句，不得是裸 `VALUES (2, id)`。
        assert_eq!(
            bodies[1],
            governance::common_role_grant_select_body(&[4110]),
            "common 授权未走 governance 策略体（裸 VALUES 会绕过策略子句）"
        );
        assert!(
            !bodies[1].contains("VALUES (2"),
            "告警种子残留裸 common 授权形态：{}",
            bodies[1]
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
        // b73 轮 15：common 授权改由 governance 策略体发放 ⇒ 只保留页面 148 与
        // `:query` 按钮 3622；3620（组绑定编辑）/3621（组删除）改的是"组→角色/部门"
        // 映射，等同间接为他人提权，属越权面不再默认授予 common（§8.2 只读姿态）。
        // 对照组：148/3622 仍在 ⇒ 拒发来自策略判据而非"授权整体丢失"。
        assert_eq!(
            role_menu, 2,
            "role_menu 授权应恰 2 条（148 页面 + 3622 查询）"
        );
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
        // 操作录制模块（m20261101_000001）：整模块由迁移管理，initialize 侧**没有任何兜底**
        // （也没有菜单兜底）——表与菜单同进同退，极老存量库补齐须整模块跑迁移；
        // 只补菜单会造出「入口可见但页面 500」的假入口，故与 MIGRATION_ONLY_TABLES 共退让。
        "sys_op_recording",
        "sys_op_recording_step",
        "sys_op_recording_run",
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
    ///
    /// `pub(super)`：同一份 fixture 也被 `tenant_phase3_read_failure_tests` 用（兄弟模块
    /// 经 `super::schema_equivalence_lock_tests::fresh_db` 取用）。复制第二份临时库构造
    /// 会让"进程内序号唯一"这条约束出现两个实现，路径撞了就是随机红（AGENTS ㉘）。
    pub(super) async fn fresh_db(tag: &str) -> (DatabaseConnection, std::path::PathBuf) {
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
        // 3.5h 租户角色菜单治理 —— **已下移到全部菜单兜底之后**（见 4.5z），
        // 与 mod.rs `run()` 同序；收回必须晚于发放，否则被兜底洗回 role 2。
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
        ensure_user_pwd_expire_policy(db).await?;
        // 3.10 链感知保留（等价 m20261008_000001）
        migration::migrations::m20261008_000001_log_archive_anchor::init_log_archive_anchor(db)
            .await?;
        // 4.2 SSO 限流分档（等价 m20260924_000001）
        ensure_sso_rate_limit_tiers(db).await?;
        // 4.2a b72（AGENTS C.10）敏感操作独立限流档位（数据级兜底，幂等：只补缺失键）
        ensure_sensitive_rate_limit_tiers(db).await?;
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
        // 4.5c-i 批八十六：sideTheme 缺省/说明归一 + 退役键死行清理（等价迁移 m20261022_000002）
        ensure_side_theme_defaults(db).await?;
        ensure_dead_config_keys_retired(db).await?;
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
        // 4.5z 租户角色菜单治理（与 mod.rs 同序：收回必须晚于全部发放类兜底）
        ensure_tenant_role_menu_governance(db).await?;
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
        // 操作录制模块：4200 页面 + 4201-4207 按钮（m20261101_000001，纯迁移管理）
        (140..=143).contains(&id)
            || (145..=147).contains(&id)
            || (151..=153).contains(&id)
            || (157..=159).contains(&id)
            || (3101..=3123).contains(&id)
            || (3261..=3268).contains(&id)
            || (3431..=3445).contains(&id)
            || (3531..=3544).contains(&id)
            || (4200..=4207).contains(&id)
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

    /// b73 轮 15 终态形状锁：**迁移路径**（新装部署）的 common 授权必须逐条落在策略内。
    ///
    /// 库 A = 全新空库 + 完整 `Migrator::up`，即开源用户 `cargo run` 首次建库的真实姿态。
    /// 三条断言各自可证伪：
    /// 1. **反向侵蚀锁**：common 持有的 F 按钮授权，若不命中只读后缀，其 menu_id 必须
    ///    出现在例外表内。今后任何新菜单迁移/兜底再"习惯性"把写按钮授给 common，本用例立即红。
    /// 2. **例外有效性**：例外表每个 id 必须真实存在、确为 F、perms 非只读后缀——
    ///    防止把只读按钮冗余登记成例外（豁免表膨胀），也防止 id 拼错使策略静默空转。
    /// 3. **已知越权面回收 + 对照组**：6 条实测越权授权必须不在；同时页面 148 与
    ///    `:query` 按钮 3622 必须仍在（证明"不在"来自策略判定而非授权整体丢失）。
    #[tokio::test]
    async fn migration_path_common_role_grants_follow_policy() {
        let (db, path) = fresh_db("common_policy").await;
        migration::Migrator::up(&db, None)
            .await
            .expect("迁移侧建库失败（common 策略终态锁）");

        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT rm.menu_id AS menu_id, m.menu_type AS menu_type, m.perms AS perms \
                 FROM sys_role_menu rm JOIN sys_menu m ON m.menu_id = rm.menu_id \
                 WHERE rm.role_id = 2 AND m.del_flag = '0'"
                    .to_string(),
            ))
            .await
            .unwrap();
        let granted: Vec<(i64, String, String)> = rows
            .iter()
            .map(|r| {
                (
                    r.try_get::<i64>("", "menu_id").unwrap_or_default(),
                    r.try_get::<String>("", "menu_type").unwrap_or_default(),
                    r.try_get::<String>("", "perms").unwrap_or_default(),
                )
            })
            .collect();
        assert!(
            granted.len() > 50,
            "common 授权行过少（{}）——迁移种子未落库，本用例失去意义",
            granted.len()
        );

        let readonly = governance::COMMON_ROLE_READONLY_PERM_SUFFIXES;
        let is_readonly = |p: &str| readonly.iter().any(|s| p.ends_with(s));
        let exception_ids = governance::common_role_write_exception_ids();

        // 1. 反向侵蚀锁
        let erosion: Vec<String> = granted
            .iter()
            .filter(|(id, mt, perms)| {
                mt == "F" && !is_readonly(perms) && !exception_ids.contains(id)
            })
            .map(|(id, _, perms)| format!("{id}:{perms}"))
            .collect();
        assert!(
            erosion.is_empty(),
            "common 角色持有未登记的写权限授权（种子侵蚀复发）：{erosion:?}；\
             修复方式：让该菜单的种子授权走 governance::common_role_grant_select_body，\
             或（确属本人作用域/能力位封顶时）在 COMMON_ROLE_WRITE_EXCEPTIONS 带理由登记"
        );

        // 2. 例外有效性（逐条回库核验）
        for (id, reason) in governance::COMMON_ROLE_WRITE_EXCEPTIONS {
            let hit = granted.iter().find(|(gid, _, _)| gid == id);
            let meta = db
                .query_all_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("SELECT menu_type AS t, perms AS p FROM sys_menu WHERE menu_id = {id}"),
                ))
                .await
                .unwrap();
            assert_eq!(
                meta.len(),
                1,
                "例外 {id} 在 sys_menu 无对应行（{reason}）——空转豁免"
            );
            let mtype: String = meta[0].try_get("", "t").unwrap_or_default();
            let perms: String = meta[0].try_get("", "p").unwrap_or_default();
            assert_eq!(
                mtype, "F",
                "例外 {id} 应为写权限按钮，实际 menu_type={mtype}（{reason}）"
            );
            assert!(
                !is_readonly(&perms),
                "例外 {id} 的 perms {perms} 本就被只读后缀放行，登记属冗余豁免（{reason}）"
            );
            assert!(
                hit.is_some(),
                "例外 {id}（{perms}）未被授权——发放点未走策略体或策略子句未展开例外"
            );
        }

        // 3. 已知越权面回收 + 对照组仍在
        for id in [3561i64, 3563, 3564, 3620, 3621, 4002] {
            assert!(
                !granted.iter().any(|(gid, _, _)| *gid == id),
                "common 仍持有越权授权 menu_id={id}——窄撤销迁移或策略过滤未生效"
            );
        }
        for id in [148i64, 3622, 3560, 3700] {
            assert!(
                granted.iter().any(|(gid, _, _)| *gid == id),
                "对照组 menu_id={id}（页面 / 只读按钮）应仍授予 common——缺失说明授权整体丢失"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    /// b73 轮 15 源码形状锁：`initialize` 兜底里不得再出现裸 `sys_role_menu … VALUES (2, id)`
    ///
    /// 兜底是**存量库**的交付机制，裸 VALUES 形态绕过策略 ⇒ 越权授权在每次启动复活。
    /// 唯一合法写法是 `governance::common_role_grant_select_body`（DB 侧套用判据）。
    /// 参数化补授（租户自助 perms 回填，目标角色非 common 的写按钮）不在此列，
    /// 故匹配串取"字面 `(2` 前缀"而非通用 VALUES。
    ///
    /// **批七十四 B3 扩面（原锁有别名盲区）**：原实现只扫 `initialize` 的 4 个文件，
    /// 而 `ensure_alert_rule_tables` 把种子 SQL 委托给 `migration` crate 的
    /// `alert_menu_seed_bodies()` —— 裸 `VALUES (2, 4110)` 就在**那一侧**，
    /// 于是"每次启动都跑的发放语句"完全落在锁的扫描面之外（隔一层函数调用即洗白，
    /// 与 §一.10 `routeParamNumber.guard` 只匹配同行 `Number(` 是同一种缺陷）。
    /// 故本轮：① 补齐 `initialize` 全部文件；② 对 `migration` crate 的**种子体函数**
    /// 单列判据；③ 对 migration 历史一次性迁移的裸授权数取**棘轮**（只许降）。
    #[test]
    fn fallback_grants_never_use_bare_common_role_values() {
        const BARE: &str = "sys_role_menu (role_id, menu_id) VALUES (2";
        // ① initialize 侧：全部兜底源文件（本轮实测清单，漏列文件由下面总数锁兜住）
        for (file, src) in [
            ("menu.rs", include_str!(concat!("menu.rs"))),
            ("scim.rs", include_str!(concat!("scim.rs"))),
            ("flow.rs", include_str!(concat!("flow.rs"))),
            ("tenant.rs", include_str!(concat!("tenant.rs"))),
            ("ledger.rs", include_str!(concat!("ledger.rs"))),
            ("schema.rs", include_str!(concat!("schema.rs"))),
            ("mod.rs", include_str!(concat!("mod.rs"))),
        ] {
            let bare = src.matches(BARE).count();
            assert_eq!(
                bare, 0,
                "{file} 存在 {bare} 处裸 common 授权 VALUES 形态，绕过 governance 策略体"
            );
        }

        // ② 兜底可达的 migration 种子体：**必须真调用**再检查产出文本。
        //    文本扫描对这一类无效——告警种子原形是
        //    `format!("… VALUES ({role_id}, {granted_menu_id})")`，源码里没有字面 `(2`，
        //    所以 ① 那套字符串判据**天生看不见**它（这才是 B3 盲区的真正成因：
        //    不是"漏扫了 ledger.rs"，而是"裸形态被 format! 模板化后任何字符串锁都抓不到"）。
        //    唯一可靠的判据是把单一事实源**跑一遍**，再判它吐出的语句。
        let alert_bodies = migration::m20261003_000003_alert_rule::alert_menu_seed_bodies("NOW()");
        assert_eq!(
            alert_bodies
                .iter()
                .filter(|b| b.contains("(2, 4110)"))
                .count(),
            0,
            "告警种子产出的仍是裸 common 授权 VALUES 形态（会被 ensure_alert_rule_tables 每次启动执行）：{:?}",
            alert_bodies
        );
        assert!(
            alert_bodies
                .iter()
                .any(|b| b.contains("sys_role_menu") && b.contains("FROM sys_menu")),
            "告警种子的 common 授权未走 governance 策略体（应形如 SELECT 2, menu_id FROM sys_menu WHERE …）"
        );

        // ③ migration crate 历史一次性迁移：取**棘轮**而非硬 0（本轮实测 47 处属 `up()`
        //    一次性授权，逐条改写属独立工程，不得混入本项；但新增必须走策略体 ⇒ 只许下降）。
        let mig_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migration/src/migrations");
        let mut total = 0usize;
        let mut files = 0usize;
        let mut entries: Vec<_> = std::fs::read_dir(&mig_dir)
            .unwrap_or_else(|e| panic!("迁移目录不可读 {}：{e}", mig_dir.display()))
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.path());
        for entry in entries {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            files += 1;
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            total += text.matches(BARE).count();
        }
        // 控制组：目录必须真被读到（否则 0 == 0 的"通过"毫无判据力）
        assert!(
            files >= 60,
            "迁移目录只读到 {files} 个 .rs ⇒ 扫描面失效，棘轮空转（不是通过）"
        );
        assert!(
            total <= 47,
            "migration crate 裸 common 授权现有 {total} 处，超过棘轮基线 47 ⇒ 只许下降"
        );
    }

    /// b89 项 2 结构锁：`SELECT <role>, menu_id FROM sys_menu` 形态也不得自己拼。
    ///
    /// 这条锁补的是 b74 B3 那条锁的**第二个盲区**：原 needle 是字面
    /// `sys_role_menu (role_id, menu_id) VALUES (2`，而 `ensure_multitenant_module` 的
    /// Phase 3.5h 能力位回填写的是 `SELECT 2, menu_id …`——同一件事换一种 SQL 形状就绕过去
    /// 了。实测后果：平台能力位一开，「备份下载 3625 / 数据包导出 3626 / 租户导航
    /// 3628-3630 / 租户域名 3901-3904」这 **9 个写按钮**会被发给 common（`role_id=2` 是新建
    /// 租户管理员的菜单模板源），而它们与 `COMMON_ROLE_WRITE_EXCEPTIONS` 的交集是 0。
    ///
    /// 判据形状取自 AGENTS 那条纪律：**真调用单一事实源、检查它吐出的语句文本**，
    /// 而不是继续加字符串 needle —— 字符串锁永远落后于"下一种写法"。
    #[test]
    fn fallback_grants_select_shape_must_route_through_governance() {
        // ① initialize 侧：兜底里不得再出现手写的 `… SELECT …, menu_id FROM sys_menu`
        const SELECT_SHAPE: &str = "sys_role_menu (role_id, menu_id) SELECT";
        // 采集面**直接由磁盘派生**（b149 收口改的这一步）：原先是一张 `include_str!` 名字表
        // 配一条"磁盘上有但表里没有就点名"的反查，实测新加一个兜底文件时**必然**红——
        // 而红的那句是"面不全"，不是"这文件写了裸授权"，人还得再来一遍才拿到结论。
        // 名字表永远落后于事实一种写法（本表前言 ⑬/㉔ 同族），所以让磁盘自己当面：
        // 新增文件自动受约束，漏判这一族在结构上不再可能。
        //
        // 反真空由两头给：① 体量下限（读到的面比既有兜底文件数还少 ⇒ 目录坏了，拒绝判据）；
        // ② must-hit 正控（下列文件确实必须进面，一旦目录/过滤条件坏了立刻点名）。
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("initialize");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| {
                panic!("initialize 目录读不到 ⇒ 采集面反查失去输入：{dir:?}（{e}）")
            })
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.ends_with(".rs") && name != "tests.rs")
            .collect();
        on_disk.sort();
        assert!(
            on_disk.len() >= 10,
            "initialize 的兜底文件面只数到 {} 个（既有下限 10）⇒ 目录或过滤条件坏了，             本轮不作数（\"扫不到\"与\"扫了且干净\"必须可区分，前言 ⑥）",
            on_disk.len()
        );
        for must_hit in ["helpers.rs", "mod.rs", "rate_limit.rs", "tenant.rs"] {
            assert!(
                on_disk.iter().any(|n| n == must_hit),
                "采集面必须含 initialize/{must_hit}（它一直写着兜底授权）⇒ 面为空就是在判空气"
            );
        }
        let sources: Vec<(String, String)> = on_disk
            .iter()
            .map(|name| {
                let full = dir.join(name);
                (
                    name.clone(),
                    std::fs::read_to_string(&full)
                        .unwrap_or_else(|e| panic!("读 initialize/{name} 失败 ⇒ 输入坏：{e}")),
                )
            })
            .collect();
        for (file, src) in &sources {
            let hand = src.matches(SELECT_SHAPE).count();
            assert_eq!(
                hand, 0,
                "{file} 里有 {hand} 处手写 common 授权 SELECT 形态 ⇒ 绕过 governance 策略体，\
                 必须改走 common_role_grant_select_body / _by_perms"
            );
        }

        // ② 单一事实源真跑一遍：两条 body 都必须带策略谓词，且 role 取 COMMON_ROLE_ID
        let by_perms = governance::common_role_grant_select_body_by_perms("$1, $2");
        let by_ids = governance::common_role_grant_select_body(&[4110]);
        let policy = governance::common_role_grant_where();
        for (name, body) in [("by_perms", &by_perms), ("by_ids", &by_ids)] {
            assert!(
                body.contains(&policy),
                "{name} 产出的语句没带上 common 授权策略谓词：{body}"
            );
            assert!(
                body.contains(&format!(
                    "SELECT {}, menu_id FROM sys_menu",
                    governance::COMMON_ROLE_ID
                )),
                "{name} 的角色 id 不是 COMMON_ROLE_ID：{body}"
            );
            assert!(
                body.contains("del_flag = '0'"),
                "{name} 必须只授未删除菜单：{body}"
            );
        }
        assert!(
            by_perms.contains("$1, $2"),
            "by_perms 必须原样使用调用方给的占位符列表（参数化不能进 governance）：{by_perms}"
        );
        assert!(
            by_perms.contains("perms IN ($1, $2)") && by_ids.contains("menu_id IN (4110)"),
            "两条 body 的选择轴不得互相顶替：{by_perms} / {by_ids}"
        );
        // 例外必须真在产出里（否则 4142-4145 这类拍板过的写按钮会被静默收回）
        for (id, _) in governance::COMMON_ROLE_WRITE_EXCEPTIONS {
            assert!(
                by_perms.contains(&id.to_string()),
                "写权限例外 {id} 未出现在产出的策略子句里 ⇒ 判据与例外表已脱钩：{by_perms}"
            );
        }

        // ③ 反证：判据必须真抓得住缺陷形状（本批立案时 tenant.rs 的原形），且不误报合规形状
        let defect = "INSERT OR IGNORE INTO sys_role_menu (role_id, menu_id) \
                      SELECT 2, menu_id FROM sys_menu WHERE del_flag = '0' AND perms IN (?)";
        assert!(
            defect.contains(SELECT_SHAPE),
            "反证夹具必须能被本锁的形状串抓到，否则这把锁是空转的"
        );
        assert!(
            !defect.contains(&policy),
            "反证夹具不得自带策略谓词（否则第 ② 段的断言等于没判）"
        );
        assert!(
            by_perms.contains(&format!("perms IN ($1, $2) AND {policy}")),
            "by_perms 必须在 perms 选择轴**之后**接上策略谓词（这正是裸 SELECT 缺的那一段）：{by_perms}"
        );
    }

    /// b89 项 2 行为锁：能力位全开跑完 initialize 后，common 不得持有平台专属写按钮。
    ///
    /// ②③ 那两段判的是"语句形状与产出文本"，这一把判的是**终态**——两条路方向相反：
    /// 形状锁挡住"绕过策略体的新写法"，终态锁挡住"策略体本身被改松"。
    #[test]
    fn common_role_never_gains_non_exception_write_buttons_when_features_unlocked() {
        // 与 ①' 回填清单同源：unlocked_capability_perms 在**全开档**下给出的 perms。
        // 全开档由注册表自己派生（每个能力位取 `modes` 末项＝最开放的一档），不手写第二份
        // 清单——否则注册表新增能力位时这条锁会静默少约束一项（AGENTS「扫描面由事实派生」）。
        let all_on = crate::common::features::FeatureSet::sanitized(
            crate::common::features::KNOWN_FEATURES
                .iter()
                .filter_map(|def| {
                    def.modes
                        .last()
                        .map(|top| (def.key.to_string(), (*top).to_string()))
                }),
        );
        assert!(
            !all_on.overrides().is_empty(),
            "全开档夹具一个覆盖项都没有 ⇒ 注册表档位为空，本锁失去约束对象（不是通过）"
        );
        // 全开档的解锁面必须**等于注册表登记的全部 unlocked**（数量由事实派生，不记数字）：
        // 注册表新增一个下放项而本锁的夹具没跟上 ⇒ 这里立刻点名，而不是悄悄少约束一项。
        let mut expected: Vec<&'static str> = Vec::new();
        for def in crate::common::features::KNOWN_FEATURES {
            for (_, perms) in def.unlocked {
                for p in *perms {
                    if !expected.contains(p) {
                        expected.push(p);
                    }
                }
            }
        }
        assert!(
            !expected.is_empty(),
            "注册表里一条下放项都没有 ⇒ Phase 3.5h 回填面空转，本锁失去约束对象（不是通过）"
        );
        let unlocked = crate::common::features::unlocked_capability_perms(&all_on);
        for p in &expected {
            assert!(
                unlocked.contains(p),
                "全开档必须解锁 {p}（注册表已登记）；取不到就是采集面坏了"
            );
        }
        assert_eq!(
            unlocked.len(),
            expected.len(),
            "全开档解锁数与注册表登记数不一致（多＝凭空下放，少＝档不足）"
        );
        // 这三条是本批立案时实测被裸 SELECT 发出去的写按钮，必须仍然**不在** common 可得集合里
        for perm in [
            "system:backup:download",
            "system:tenantMenu:add",
            "system:tenant:domain:remove",
        ] {
            assert!(
                unlocked.contains(&perm),
                "夹具前提失效：{perm} 本应属能力位解锁面（否则这条锁什么也没约束）"
            );
            let menu_type = "F";
            assert!(
                !governance::common_role_may_grant(
                    // menu_id 取一个不在例外表里的值：判据对写按钮只看后缀与例外 id
                    999_999, menu_type, perm
                ),
                "{perm} 是写按钮且不在 COMMON_ROLE_WRITE_EXCEPTIONS ⇒ common 不得可授"
            );
        }
        // 对照组：拍板过的例外必须真的可授（否则上面那段可以靠"全都不可授"蒙绿）
        let exception_perm = governance::COMMON_ROLE_WRITE_EXCEPTIONS
            .iter()
            .find(|(id, _)| *id == 4142)
            .map(|(_, p)| *p)
            .expect("例外表应含 4142");
        assert!(
            governance::common_role_may_grant(4142, "F", exception_perm),
            "写权限例外 4142 必须可授（本批不得顺手把它收回）"
        );
    }

    ///
    /// 机理：`ensure_tenant_role_menu_governance` ① 是 `DELETE … role_id = 2 OR tenant_id <> 0`，
    /// 而若干 `ensure_*` 兜底**发放** `sys_role_menu`。若治理在前、发放在后，则平台专属菜单
    /// 每次启动都被洗回模板源 role 2 ⇒ 注册表形同虚设（本轮实证：登记 `monitor:alert:` 后
    /// 按原序跑完 initialize，4110 仍在 role 2）。这不是"顺序偏好"而是**不变式**。
    #[test]
    fn governance_runs_after_all_menu_granting_fallbacks() {
        let mod_src = include_str!(concat!("mod.rs"));
        let gov_pos = mod_src
            .find("ensure_tenant_role_menu_governance(&db)")
            .expect("run() 中不再调用租户角色菜单治理 ⇒ 结构锁失去约束对象（不是通过）");

        // 发放类兜底 = 其函数体出现 sys_role_menu 的 ensure_*
        let grant_sources: [(&str, &str); 5] = [
            ("ledger.rs", include_str!(concat!("ledger.rs"))),
            ("menu.rs", include_str!(concat!("menu.rs"))),
            ("flow.rs", include_str!(concat!("flow.rs"))),
            ("scim.rs", include_str!(concat!("scim.rs"))),
            ("tenant.rs", include_str!(concat!("tenant.rs"))),
        ];
        let mut granting_fns: Vec<String> = Vec::new();
        for (file, src) in grant_sources {
            // 逐个 ensure_* 函数切段：边界取"下一个 `async fn` 出现处"（而非字面
            // `\nasync fn `——多数函数声明带 `pub(crate) ` 前缀，按字面行匹配会让第一段
            // 吞掉整个文件，导致后续函数一律漏检；本轮首跑实测只数出 2 个即此因）。
            let starts: Vec<usize> = src
                .match_indices("async fn ensure_")
                .map(|(i, _)| i)
                .collect();
            for (idx, &start) in starts.iter().enumerate() {
                let end = starts.get(idx + 1).copied().unwrap_or(src.len());
                let seg = &src[start..end];
                let name_end = seg
                    .find('(')
                    .unwrap_or_else(|| panic!("{file} 中 ensure_* 函数名未闭合"));
                let name = seg["async fn ".len()..name_end].to_string();
                if seg.contains("sys_role_menu") {
                    granting_fns.push(format!("{file}::{name}"));
                }
            }
        }
        assert!(
            granting_fns.len() >= 5,
            "只识别出 {} 个发放 sys_role_menu 的兜底函数 ⇒ 判据扫描面失效（不是通过）",
            granting_fns.len()
        );

        let mut violations: Vec<String> = Vec::new();
        for entry in &granting_fns {
            let name = entry.split("::").nth(1).unwrap_or(entry);
            // 治理自身不计（它既剔也补）
            if name == "ensure_tenant_role_menu_governance" {
                continue;
            }
            if let Some(pos) = mod_src.find(&format!("{name}(&db)"))
                && pos > gov_pos
            {
                violations.push(format!("{entry} 在 mod.rs:{pos} 晚于治理 {gov_pos}"));
            }
        }
        assert!(
            violations.is_empty(),
            "以下发放类兜底排在收回类治理**之后**，会把平台专属菜单洗回 role 2（假入口复活）：\n{}",
            violations.join("\n")
        );

        // 同一不变式也必须钉在**测试 harness** 上：`run_all_initialize_fallbacks` 自称
        // "按 mod.rs run() 的原始顺序"，但它自成一套调用序列——本轮首跑即实测到 harness
        // 仍是"治理(3.5h) 在前、告警(4.5e) 在后"的旧序。既有覆盖锁只判**集合**、不判**顺序**，
        // 于是"测试验的序"与"生产跑的序"可以静默相反 ⇒ 行为测试全绿也证不了生产正确。
        let harness = include_str!(concat!("tests.rs"));
        let harness_gov = harness
            .find("ensure_tenant_role_menu_governance(db).await?")
            .expect("harness 不再调用治理 ⇒ 本判据失去约束对象");
        let mut harness_violations: Vec<String> = Vec::new();
        for entry in &granting_fns {
            let name = entry.split("::").nth(1).unwrap_or(entry);
            if name == "ensure_tenant_role_menu_governance" {
                continue;
            }
            if let Some(pos) = harness.find(&format!("{name}(db).await?"))
                && pos > harness_gov
            {
                harness_violations.push(format!("{entry} 在 harness 晚于治理 {harness_gov}"));
            }
        }
        assert!(
            harness_violations.is_empty(),
            "harness 的发放类兜底晚于收回类治理，与 mod.rs 不同序：\n{}",
            harness_violations.join("\n")
        );
    }

    /// 批七十四 B3 **终态行为锁**：跑完两条真实交付路径后，`common`（role_id=2，
    /// 新建租户管理员的菜单模板源）**不得持有任一平台专属菜单**，且告警页面 4110 必不在。
    ///
    /// 为什么必须测到"终态"而不满足于源码形状：本轮实证链条是
    /// 注册表 → 授权判定 → 模板复制 → **兜底发放** 四层，前三层都有静态锁，
    /// 而第四层（`ensure_alert_rule_tables` 把 4110 发回 role 2）把整条治理洗成空转。
    /// 只有落到库上数行，才能证明"假入口真的没了"。
    ///
    /// 两条路径各自代表一种真实部署姿态：
    /// - **A 新装**：全新空库 + 完整 `Migrator::up`（开源用户首次 `cargo run`）；
    /// - **B 存量升级**：基线迁移 + `run_all_initialize_fallbacks`（启动不跑 Migrator::up
    ///   的既有约定，即 4.5z 治理在兜底末尾执行的新序）。
    ///
    /// 对照组（B3 的"不在"必须来自判据、而非授权整体丢失）：页面 148 与只读按钮 3622
    /// 必须仍在 role 2 —— 与 b73 轮 15 的对照组同口径。
    #[tokio::test]
    async fn common_role_never_holds_platform_only_menus_on_either_path() {
        /// 数库断言（写成 async fn 而非闭包：异步闭包的引用生命周期推不出来）
        async fn probe(db: &DatabaseConnection) {
            let rows = db
                .query_all_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    "SELECT rm.menu_id AS menu_id, m.perms AS perms \
                     FROM sys_role_menu rm JOIN sys_menu m ON m.menu_id = rm.menu_id \
                     WHERE rm.role_id = 2 AND m.del_flag = '0'"
                        .to_string(),
                ))
                .await
                .unwrap();
            let granted: Vec<(i64, String)> = rows
                .iter()
                .map(|r| {
                    (
                        r.try_get::<i64>("", "menu_id").unwrap_or_default(),
                        r.try_get::<String>("", "perms").unwrap_or_default(),
                    )
                })
                .collect();
            assert!(
                granted.len() > 50,
                "role 2 授权行仅 {} 条 ⇒ 种子未落库，本用例失去约束对象（不是通过）",
                granted.len()
            );
            let leaked: Vec<String> = granted
                .iter()
                .filter(|(_, perms)| crate::common::tenant::is_platform_only_perm(perms))
                .map(|(id, perms)| format!("{id}:{perms}"))
                .collect();
            assert!(
                leaked.is_empty(),
                "common 仍持有平台专属菜单 ⇒ 租户管理员模板会继承假入口：{leaked:?}"
            );
            assert!(
                !granted.iter().any(|(id, _)| *id == 4110),
                "告警页面 4110 仍在 role 2 ⇒ B3 未生效（真缺陷回归）"
            );
            for id in [148i64, 3622] {
                assert!(
                    granted.iter().any(|(gid, _)| *gid == id),
                    "对照组 menu_id={id} 缺失 ⇒ '平台专属不在'来自授权整体丢失而非判据生效"
                );
            }
        }

        // ---- 路径 A：新装（完整迁移）----
        let (db_a, path_a) = fresh_db("b3_migr").await;
        migration::Migrator::up(&db_a, None)
            .await
            .expect("迁移侧建库失败（B3 终态锁 A）");
        probe(&db_a).await;
        let _ = std::fs::remove_file(&path_a);

        // ---- 路径 B：存量升级（基线迁移 + 全部兜底）----
        let (db_b, path_b) = fresh_db("b3_fallb").await;
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
            .expect("兜底侧基线建库失败（B3 终态锁 B）");
        run_all_initialize_fallbacks(&db_b)
            .await
            .expect("initialize 兜底 harness 执行失败（B3 终态锁 B）");
        probe(&db_b).await;
        let _ = std::fs::remove_file(&path_b);

        // ---- 对照组 C：**只发放、不收回** ⇒ 4110 必须**在** role 2 ----
        // 这一条才证明上面两条"不在"来自治理判据，而不是"从来就没发过"。
        // 同时它复现了 B3 修复前的真实故障姿态（治理跑在告警兜底之前）。
        let (db_c, path_c) = fresh_db("b3_grant").await;
        let mut baseline_c = 0u32;
        for m in migration::Migrator::migrations() {
            baseline_c += 1;
            if m.name() == FALLBACK_BASELINE_MIGRATION {
                break;
            }
        }
        migration::Migrator::up(&db_c, Some(baseline_c))
            .await
            .expect("对照组基线建库失败");
        crate::initialize::ledger::ensure_alert_rule_tables(&db_c)
            .await
            .expect("告警兜底执行失败（对照组）");
        let c_rows = db_c
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT rm.menu_id AS menu_id FROM sys_role_menu rm \
                 WHERE rm.role_id = 2 AND rm.menu_id = 4110"
                    .to_string(),
            ))
            .await
            .unwrap();
        assert!(
            !c_rows.is_empty(),
            "对照组失效：仅跑告警兜底时 4110 **未**发给 role 2 ⇒ 发放路径本就不产生该授权，\
             上面两条'不在'的断言是在测空气（须重查判据）"
        );
        let _ = std::fs::remove_file(&path_c);
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
            "ensure_user_pwd_expire_policy",
            "ensure_sso_rate_limit_tiers",
            "ensure_sensitive_rate_limit_tiers",
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
            "ensure_side_theme_defaults",
            "ensure_dead_config_keys_retired",
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

    /// 默认档位（`SchedulerConfig::default().replicas = 1` + `RateLimitSettings::default()` 声明
    /// 档 = `local`）⇒ 守卫**不得**触发，锁住"缺省值 = 现状 = 安全态"这一铁律
    /// （新增开关/守卫不得改变存量部署行为）。
    ///
    /// b146 加了 `auto` 档之后，这一条还多证明一件事：**默认值不是 auto**。
    /// 默认若是 auto，则"配了 Redis 的单实例部署"升级后会突然变成共享桶
    /// （Redis 抖一下就 503）——那是把行为变更塞进一次无关升级。
    #[test]
    fn default_config_does_not_trigger_rate_limit_guard() {
        use crate::config::settings::{RateLimitSettings, SchedulerConfig};
        let scheduler = SchedulerConfig::default();
        let rate_limit = RateLimitSettings::default();
        assert_eq!(scheduler.replicas, 1, "默认副本数必须为 1");
        assert_eq!(rate_limit.mode, "local", "默认声明档必须是 local（= 现状）");
        assert_eq!(
            rate_limit.mode(false),
            RateLimitMode::Local,
            "默认限流档位必须为 local（= 现状）"
        );
        // 对照组：默认档在"共享态确实在 Redis"时也不许自己升档（升档只能是运维显式写的）
        assert_eq!(
            rate_limit.mode(true),
            RateLimitMode::Local,
            "默认档不得因为 cache 在 Redis 就升成共享桶（那是行为变更，不是默认值）"
        );
        assert!(
            !rate_limit_local_multi_instance_misconfigured(
                scheduler.replicas,
                rate_limit.mode(false)
            ),
            "默认配置（单实例 + local）不得触发多实例限流告警"
        );
    }

    /// b146：chart 形态（多副本 + `auto`）在 Redis 可用时必须落到共享桶，
    /// 且**此时守卫不得再报** local 放大——否则"auto 修好了默认值"这句话没有载体。
    #[test]
    fn auto_mode_on_multi_replica_lands_on_shared_bucket() {
        use crate::config::settings::{RateLimitMode, RateLimitSettings};
        let auto = RateLimitSettings {
            mode: "auto".to_string(),
            ..RateLimitSettings::default()
        };
        assert_eq!(
            auto.mode(true),
            RateLimitMode::Redis,
            "auto + Redis ⇒ 共享桶"
        );
        assert!(
            !rate_limit_local_multi_instance_misconfigured(2, auto.mode(true)),
            "chart 默认形态（2 副本 + auto 且 Redis 可用）不得再被判成 local 放大"
        );
        // 反向：auto 但 Redis 没配 ⇒ 仍是 local，此时**必须**告警（多副本各算各的桶是真的）
        assert_eq!(auto.mode(false), RateLimitMode::Local);
        assert!(
            rate_limit_local_multi_instance_misconfigured(2, auto.mode(false)),
            "多副本 + 实际 local 必须告警——不得因为\"写了 auto\"就把真风险洗掉"
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

#[cfg(test)]
mod pwd_expire_policy_backfill_tests {
    //! 批八十四 项 A 的**存量库兜底**判据：旧键名就地改名、种子真的落库、回填只在建列时发生。
    //!
    //! 立这条的动因是 e2e M91 实测抓到的静默失效：`sys_config` 种子走 `INSERT OR IGNORE`
    //! 且两版键名**共用 `config_id=9011`** ⇒ 跑过旧版的存量库里 9011 被旧键占着，
    //! 新键那条被忽略、参数面从此看不见这个能力，而启动日志一个字都不报。
    //! "键名换了但没迁移"正是本仓配置版本化基线明令禁止的那一类。
    use super::*;
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement};

    const MIN_SYS_USER: &str =
        "CREATE TABLE sys_user (user_id INTEGER PRIMARY KEY, user_name TEXT, create_time DATETIME)";
    // 列结构对齐真实 sys_config 的**约束面**（ UNIQUE(tenant_id, config_key) 是本批事故的主角，
    // 缺了它这个夹具就测不出改名撞键）
    const MIN_SYS_CONFIG: &str = "CREATE TABLE sys_config (config_id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL DEFAULT 0, config_name TEXT, config_key TEXT, config_value TEXT, config_type TEXT, create_by TEXT, create_time DATETIME, remark TEXT, UNIQUE (tenant_id, config_key))";

    async fn exec(db: &DatabaseConnection, sql: &str) {
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            sql.to_string(),
        ))
        .await
        .unwrap_or_else(|e| panic!("建夹具失败: {e}\n{sql}"));
    }

    async fn one(db: &DatabaseConnection, sql: &str) -> sea_orm::QueryResult {
        db.query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            sql.to_string(),
        ))
        .await
        .expect("查询失败")
        .pop()
        .expect("必须有这一行——没有就说明判据在拿空集当通过")
    }

    /// 造"跑过改名前那一版"的库：有旧键（值被管理员改成 15）、没有 pwd_update_time 列
    async fn legacy_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        exec(&db, MIN_SYS_USER).await;
        exec(&db, MIN_SYS_CONFIG).await;
        exec(
            &db,
            "INSERT INTO sys_user (user_id, user_name, create_time) VALUES (1, 'admin', '2020-01-02 03:04:05')",
        )
        .await;
        exec(
            &db,
            "INSERT INTO sys_config (config_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) \
             VALUES (9011, '口令有效期天数', 'sys.user.passwordExpireDays', '15', 'Y', 'admin', '2020-01-02 03:04:05', '旧版键名')",
        )
        .await;
        db
    }

    /// ① 改名必须发生在种子**之前**：旧键消失、新键出现、管理员改过的值 15 原样保留
    #[tokio::test]
    async fn legacy_key_is_renamed_in_place_and_value_survives() {
        let db = legacy_db().await;
        ensure_user_pwd_expire_policy(&db).await.expect("兜底失败");

        let old_rows: i64 = one(
            &db,
            "SELECT COUNT(*) AS c FROM sys_config WHERE config_key = 'sys.user.passwordExpireDays'",
        )
        .await
        .try_get("", "c")
        .unwrap();
        assert_eq!(
            old_rows, 0,
            "旧键名必须已被就地改名（留着就是两份同义键并存）"
        );

        let row = one(&db, "SELECT config_value, config_id FROM sys_config WHERE config_key = 'sys.user.pwdExpireDays'").await;
        let val: String = row.try_get("", "config_value").unwrap();
        let id: i64 = row.try_get("", "config_id").unwrap();
        assert_eq!(
            val, "15",
            "改名必须保住管理员已改的值（种子不得覆盖成默认 0）"
        );
        assert_eq!(id, 9011, "改名应原地更新同一行，不新插一条");

        // 闸门键此前不存在 ⇒ 种子必须补出来，且种的是关闭态
        let gate: String = one(
            &db,
            "SELECT config_value FROM sys_config WHERE config_key = 'sys.user.pwdChangeGate'",
        )
        .await
        .try_get("", "config_value")
        .unwrap();
        assert_eq!(gate, "off", "闸门键必须被种子补齐且为关闭态");
    }

    /// ② 建列 + 回填只在新建列时发生；二次启动幂等且不得把口令年龄洗成"刚刚"
    #[tokio::test]
    async fn column_backfill_runs_once_and_is_idempotent() {
        let db = legacy_db().await;
        ensure_user_pwd_expire_policy(&db)
            .await
            .expect("首次兜底失败");

        let age: String = one(
            &db,
            "SELECT pwd_update_time FROM sys_user WHERE user_id = 1",
        )
        .await
        .try_get("", "pwd_update_time")
        .unwrap();
        assert_eq!(
            age, "2020-01-02 03:04:05",
            "存量行必须按 create_time 代理回填，不能取当前时刻"
        );

        // 模拟"管理员改了口令"后的时间戳，二次启动不得被回填覆盖
        exec(
            &db,
            "UPDATE sys_user SET pwd_update_time = '2026-10-01 00:00:00' WHERE user_id = 1",
        )
        .await;
        ensure_user_pwd_expire_policy(&db)
            .await
            .expect("二次兜底失败");
        let age2: String = one(
            &db,
            "SELECT pwd_update_time FROM sys_user WHERE user_id = 1",
        )
        .await
        .try_get("", "pwd_update_time")
        .unwrap();
        assert_eq!(
            age2, "2026-10-01 00:00:00",
            "列已存在时不得重跑回填（把口令年龄洗成刚改过 = 策略看不见真实年龄）"
        );

        let dup: i64 = one(
            &db,
            "SELECT COUNT(*) AS c FROM sys_config WHERE config_key = 'sys.user.pwdExpireDays'",
        )
        .await
        .try_get("", "c")
        .unwrap();
        assert_eq!(dup, 1, "二次启动不得种出第二行");
    }

    /// ③ 启动事故回归锁：新键默认行**已被治理补齐建出来**时，改名不得撞
    ///    `UNIQUE(tenant_id, config_key)` 打死 initialize，且管理员改过的值必须搬过去。
    ///    这是 b84 实测把服务起不来逼出来的那一条：`UPDATE ... SET config_key=新名`
    ///    看着幂等，实际与 `治理参数项缺行补齐`（启动序在前）直接对撞。
    #[tokio::test]
    async fn rename_survives_pre_existing_target_row() {
        let db = legacy_db().await;
        exec(
            &db,
            "INSERT INTO sys_config (config_id, tenant_id, config_name, config_key, config_value, config_type, create_by, create_time, remark)              VALUES (9500, 0, '口令有效期天数', 'sys.user.pwdExpireDays', '0', 'Y', 'admin', '2026-01-01 00:00:00', '治理补齐建的默认行')",
        )
        .await;
        ensure_user_pwd_expire_policy(&db)
            .await
            .expect("兜底不得因唯一键冲突打断启动（启动被打死 = 整套判据都没有机会跑）");

        let legacy_left: i64 = one(
            &db,
            "SELECT COUNT(*) AS c FROM sys_config WHERE config_key = 'sys.user.passwordExpireDays'",
        )
        .await
        .try_get("", "c")
        .unwrap();
        assert_eq!(legacy_left, 0, "旧键必须被收敛掉，否则参数面两行同义键并存");
        let row = one(&db, "SELECT config_id, config_value FROM sys_config WHERE config_key = 'sys.user.pwdExpireDays'").await;
        let id: i64 = row.try_get("", "config_id").unwrap();
        let val: String = row.try_get("", "config_value").unwrap();
        assert_eq!(id, 9500, "保留既有行（治理补齐那条），不新插一条同义行");
        assert_eq!(
            val, "15",
            "管理员在旧键上改过的值必须搬进新键，不得被默认值 0 洗掉"
        );
    }

    /// ④ 按租户逐行收敛：租户层若也有旧行，不得与平台层的新行互相撞键
    #[tokio::test]
    async fn rename_is_per_tenant_not_only_platform_layer() {
        let db = legacy_db().await;
        exec(
            &db,
            "INSERT INTO sys_config (config_id, tenant_id, config_name, config_key, config_value, config_type, create_by, create_time, remark)              VALUES (9600, 7, '口令有效期天数', 'sys.user.passwordExpireDays', '45', 'Y', 'admin', '2026-01-01 00:00:00', '租户层旧行')",
        )
        .await;
        ensure_user_pwd_expire_policy(&db)
            .await
            .expect("含租户层旧行时兜底也必须跑通");
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT tenant_id, config_value FROM sys_config WHERE config_key = 'sys.user.pwdExpireDays' ORDER BY tenant_id".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "两层各一行（读侧与写侧共用同一租户谓词）");
        let t7: String = rows[1].try_get("", "config_value").unwrap();
        assert_eq!(t7, "45", "租户层已改值不得被平台层默认洗掉");
    }

    /// ⑤ 全新库（连 sys_user 都没有）必须安全跳过而不是报错——兜底排在迁移之前的启动序里
    #[tokio::test]
    async fn empty_db_skips_quietly() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        ensure_user_pwd_expire_policy(&db)
            .await
            .expect("空库应静默跳过");
        let cols: i64 = one(
            &db,
            "SELECT COUNT(*) AS c FROM sqlite_master WHERE type='table' AND name='sys_user'",
        )
        .await
        .try_get("", "c")
        .unwrap();
        assert_eq!(cols, 0, "兜底不得凭空建 sys_user 表（那是迁移的职责）");
    }

    /// ⑥ 存量库上由治理注册表**兜底先建行**的那两个键，remark 必须归一到种子文案；
    ///    管理员自己写过的说明一律不动（对照组）。
    ///
    /// 立这条的实证：本机运行库 seed_diff 报出 2 处真实漂移——兜底建的行 remark 是
    /// 通用文案"治理注册表缺行补齐（批次十四）"，而 `off / deny_write / deny_all`
    /// 三档的**语义只写在种子的 remark 里** ⇒ 存量部署的参数管理页看不出区别（读不出
    /// 说明就会配错，属真实能力缺口，不只是文案漂移）。新库走迁移种子不受影响，
    /// 所以这一支在集成测试（新库）里永远看不见——只能由这条存量库夹具钉住。
    #[tokio::test]
    async fn backfilled_remark_converges_but_admin_text_survives() {
        use migration::migrations::m20261022_000001_pwd_expire_policy as pwd_expire;

        let db = Database::connect("sqlite::memory:").await.unwrap();
        exec(&db, MIN_SYS_USER).await;
        exec(&db, MIN_SYS_CONFIG).await;
        exec(
            &db,
            "INSERT INTO sys_user (user_id, user_name, create_time) VALUES (1, 'admin', '2020-01-02 03:04:05')",
        )
        .await;
        // 治理兜底建行的实测形状：config_id 与种子不同（14820）、remark 是通用文案
        exec(
            &db,
            &format!(
                "INSERT INTO sys_config (config_id, tenant_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) \
                 VALUES (14820, 0, '口令有效期天数', 'sys.user.pwdExpireDays', '30', 'Y', 'admin', '2020-01-02 03:04:05', '{}')",
                governance::GOVERNANCE_BACKFILL_REMARK
            ),
        )
        .await;
        exec(
            &db,
            "INSERT INTO sys_config (config_id, tenant_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) \
             VALUES (14821, 0, '强改密服务端闸门', 'sys.user.pwdChangeGate', 'off', 'Y', 'admin', '2020-01-02 03:04:05', '管理员自己写的说明')",
        )
        .await;

        ensure_user_pwd_expire_policy(&db).await.expect("兜底失败");

        let r1: String = one(
            &db,
            "SELECT remark FROM sys_config WHERE config_key='sys.user.pwdExpireDays'",
        )
        .await
        .try_get("", "remark")
        .unwrap();
        assert_eq!(
            r1,
            pwd_expire::PWD_EXPIRE_DAYS_REMARK,
            "兜底建的行必须归一到种子说明（同一常量 = 单一事实源，两处各写一份就会静默不归一）"
        );
        let v1: String = one(
            &db,
            "SELECT config_value FROM sys_config WHERE config_key='sys.user.pwdExpireDays'",
        )
        .await
        .try_get("", "config_value")
        .unwrap();
        assert_eq!(v1, "30", "归一只动说明，不得改管理员设过的值");

        let r2: String = one(
            &db,
            "SELECT remark FROM sys_config WHERE config_key='sys.user.pwdChangeGate'",
        )
        .await
        .try_get("", "remark")
        .unwrap();
        assert_eq!(
            r2, "管理员自己写的说明",
            "UPDATE 谓词限定 remark=兜底文案 ⇒ 人工说明必须原样保留"
        );

        let n: i64 = one(&db, "SELECT COUNT(*) AS c FROM sys_config")
            .await
            .try_get("", "c")
            .unwrap();
        assert_eq!(
            n, 2,
            "种子那条撞 UNIQUE(tenant_id, config_key) 必须被忽略，不得多插一行"
        );
    }
}

#[cfg(test)]
mod dead_config_key_retire_tests {
    //! 批八十六 项 N-1 的两条交付路径：**全新库走窄迁移**、**存量库走启动兜底**。
    //!
    //! 为什么两条都要判：§5.23 那次只写了注释说"数据保留"，于是假入口留在参数页；
    //! 而若只判迁移，存量库（启动不跑 `Migrator::up`）的清理通道坏掉也无人知道——
    //! 正是本仓反复踩过的"新库对、老库错"这一族（同 G-11 八键缺行、pwd 键名改名）。
    use super::*;
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

    /// 夹具建库后追加语句的小助手（本模块走**真实迁移库**，列结构无需自建最小表）。
    async fn exec_sql(db: &DatabaseConnection, sql: &str) {
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            sql.to_string(),
        ))
        .await
        .unwrap_or_else(|e| panic!("造夹具失败: {e}\n{sql}"));
    }

    async fn count(db: &DatabaseConnection, sql: &str) -> i64 {
        db.query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            sql.to_string(),
        ))
        .await
        .expect("查询失败")
        .pop()
        .expect("COUNT 查询必须返回一行——返回空集说明判据在拿「查不到」当「等于零」")
        .try_get("", "c")
        .unwrap_or_default()
    }

    async fn text(db: &DatabaseConnection, sql: &str) -> String {
        db.query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            sql.to_string(),
        ))
        .await
        .expect("查询失败")
        .pop()
        .expect("必须有这一行——没有就说明夹具没建起来")
        .try_get("", "v")
        .unwrap_or_default()
    }

    const SIDE_PLATFORM: &str = "SELECT config_value AS v FROM sys_config WHERE config_key = 'sys.index.sideTheme' AND tenant_id = 0";
    const REMARK_PLATFORM: &str = "SELECT remark AS v FROM sys_config WHERE config_key = 'sys.index.sideTheme' AND tenant_id = 0";
    const LIVE_KEYS: &str = "SELECT COUNT(*) AS c FROM sys_config WHERE config_key IN \
         ('sys.account.captchaEnabled','sys.user.initPassword','sys.login.blackIPList')";

    /// ① 全新库：窄迁移必须已经把两个退役键清干净，并把 sideTheme 归一到真旋钮缺省。
    #[tokio::test]
    async fn fresh_database_has_no_dead_keys_and_knob_is_normalized() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("建库失败");

        for key in governance::RETIRED_CONFIG_KEYS {
            let c = count(
                &db,
                &format!("SELECT COUNT(*) AS c FROM sys_config WHERE config_key = '{key}'"),
            )
            .await;
            assert_eq!(
                c, 0,
                "全新库里退役键 {key} 的行必须已被窄迁移清除（留在参数页即假入口）"
            );
        }

        assert_eq!(
            text(&db, SIDE_PLATFORM).await,
            governance::SIDE_THEME_DOMAIN[0],
            "init 迁移那个从未被消费的 theme-dark 必须归一到 theme-auto（= 改造前现状）"
        );
        assert_eq!(
            text(&db, REMARK_PLATFORM).await,
            governance::SIDE_THEME_REMARK,
            "合法取值必须写进说明，管理员在参数页就读得见"
        );
        // 治理姿态由注册表 seed：Free ⇒ platform_default/1/1（e2e F72 覆盖载体的前提）
        assert_eq!(
            text(
                &db,
                "SELECT scope AS v FROM sys_config WHERE config_key = 'sys.index.sideTheme' AND tenant_id = 0",
            )
            .await,
            "platform_default",
            "Free 参数项的平台层治理姿态必须由注册表给出"
        );
    }

    /// ② 存量库：兜底补齐三件事（归一值 / 归一说明 / 删死行），且**幂等**、
    ///    不碰管理员事后改的值、不碰在册键（对照组）。
    #[tokio::test]
    async fn stock_database_fallback_sweeps_dead_rows_idempotently() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("建库失败");
        // 造"跑过 b86 之前那一版"的形状：窄迁移没执行过，死行还在，sideTheme 仍是历史缺省
        exec_sql(
            &db,
            "INSERT INTO sys_config (tenant_id, config_name, config_key, config_value, config_type, create_by, remark) \
             VALUES (0, '主框架页-默认皮肤主题名称', 'sys.index.skinName', 'skin-blue', 'Y', 'admin', '蓝色 skin-blue')",
        )
        .await;
        exec_sql(
            &db,
            "INSERT INTO sys_config (tenant_id, config_name, config_key, config_value, config_type, create_by, remark) \
             VALUES (7, '租户皮肤覆盖', 'sys.index.skinName', 'skin-e2e-1', 'Y', 'admin', '租户覆盖行')",
        )
        .await;
        exec_sql(
            &db,
            "INSERT INTO sys_config (tenant_id, config_name, config_key, config_value, config_type, create_by, remark) \
             VALUES (0, '登录背景图', 'sys.login.background', '/uploads/demo-bg.svg', 'Y', 'demo', '演示登录背景图配置')",
        )
        .await;
        exec_sql(
            &db,
            &format!(
                "UPDATE sys_config SET config_value = '{}', remark = '{}' \
                 WHERE config_key = 'sys.index.sideTheme' AND tenant_id = 0",
                governance::SIDE_THEME_LEGACY_VALUE,
                governance::SIDE_THEME_LEGACY_REMARK
            ),
        )
        .await;

        ensure_side_theme_defaults(&db).await.expect("归一兜底失败");
        ensure_dead_config_keys_retired(&db)
            .await
            .expect("清理兜底失败");

        for key in governance::RETIRED_CONFIG_KEYS {
            assert_eq!(
                count(
                    &db,
                    &format!("SELECT COUNT(*) AS c FROM sys_config WHERE config_key = '{key}'")
                )
                .await,
                0,
                "退役键 {key} 的平台行与租户覆盖行都必须被清掉"
            );
        }
        assert_eq!(
            text(&db, SIDE_PLATFORM).await,
            governance::SIDE_THEME_DOMAIN[0],
            "存量库的历史缺省必须归一"
        );
        // 对照组：在册键一行都不能少（清理语句若误含在册键，本条立刻红）
        let live_before = count(&db, LIVE_KEYS).await;
        assert!(
            live_before >= 3,
            "夹具里必须在册键齐备（判据的输入非空才算真跑过）：实际 {live_before}"
        );

        // 幂等 + 尊重管理员：改成合法但非缺省的值，再跑一次不得被洗回 theme-auto
        exec_sql(
            &db,
            "UPDATE sys_config SET config_value = 'theme-light' \
             WHERE config_key = 'sys.index.sideTheme' AND tenant_id = 0",
        )
        .await;
        ensure_side_theme_defaults(&db).await.expect("二次归一失败");
        ensure_dead_config_keys_retired(&db)
            .await
            .expect("二次清理失败");
        assert_eq!(
            text(&db, SIDE_PLATFORM).await,
            "theme-light",
            "守卫取「仍是历史字面量」⇒ 管理员改过的值不得被启动流程洗回缺省"
        );
        assert_eq!(
            count(&db, LIVE_KEYS).await,
            live_before,
            "二次执行不得影响任何在册键"
        );
    }

    /// ③ 治理收敛只作用于平台层：同 key 的租户覆盖行不得被洗成 platform_default。
    ///
    /// 这是 sideTheme 成为**第一个** `Coverage::Free` 参数项后才够得着的一支：
    /// 此前注册表清一色 Locked，而 Locked 键租户根本写不进来（`ensure_tenant_can_write`
    /// 直接 403），"UPDATE 不带 tenant_id 条件"在结构上碰不到任何行；补上 Free 项之后，
    /// 不带条件的收敛会在每次启动把租户覆盖行的治理列伪装成平台默认行——读侧按
    /// `(tenant_id, key)` 取行、治理侧按 `scope` 判权限，当场分裂。
    #[tokio::test]
    async fn governance_convergence_touches_platform_layer_only() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("建库失败");
        exec_sql(
            &db,
            "INSERT INTO sys_config (tenant_id, config_name, config_key, config_value, config_type, \
             create_by, scope, tenant_editable, visible_to_tenant) \
             VALUES (7, '租户侧边栏主题覆盖', 'sys.index.sideTheme', 'theme-dark', 'Y', 'admin', \
             'tenant_private', '1', '1')",
        )
        .await;

        ensure_tenant_saas_governance(&db)
            .await
            .expect("治理收敛兜底失败");

        assert_eq!(
            text(
                &db,
                "SELECT scope AS v FROM sys_config WHERE config_key = 'sys.index.sideTheme' AND tenant_id = 7",
            )
            .await,
            "tenant_private",
            "租户覆盖行的治理列由服务层固定，启动收敛不得越层改写"
        );
        // 对照组：平台行仍按注册表收敛（否则这条判据可以是"什么都不做"）
        assert_eq!(
            text(
                &db,
                "SELECT scope AS v FROM sys_config WHERE config_key = 'sys.index.sideTheme' AND tenant_id = 0",
            )
            .await,
            "platform_default",
            "平台层必须照常收敛"
        );
    }
}

#[cfg(test)]
mod flow_index_scope_tests {
    //! 形状锁（b102）：flow 兜底建索引段**不得**再创建被租户作用域取代的旧全局唯一索引。
    //!
    //! 立案事实：`uk_flow_task_biz` 已被 `uk_flow_task_tenant_biz` 取代
    //! （迁移 `m20260925_000005_tenant_unique_scope` + `ensure_tenant_unique_scope`
    //! 每次启动兜底删除旧索引），而 `ensure_flow_indexes`（3.5b）排在 3.5g **之前**
    //! ⇒ 旧实现每轮启动先整表重建该唯一索引、再在 3.5g 删掉。`sys_flow_task` 涨大后
    //! 这条 DDL 越过 sqlx 慢语句阈值被记成 WARN（`19:26:18.789899Z slow statement …
    //! CREATE UNIQUE INDEX uk_flow_task_biz`），生产大表上就是启动期分钟级无用功，
    //! 期间还多出一条本不该存在的全局唯一约束（跨租户同业务键会互相顶撞）。
    use super::*;

    #[test]
    fn flow_fallback_ddls_must_not_resurrect_the_superseded_global_unique() {
        assert!(
            !FLOW_INDEXES.iter().any(|s| s.contains("uk_flow_task_biz")),
            "ensure_flow_indexes 不得再创建 uk_flow_task_biz：它已被 uk_flow_task_tenant_biz \
             取代，且 3.5g 每次启动都会删掉它（先建后删 = 每轮启动整表重建索引）"
        );
        // 反向：性能索引一条都不能少，否则"删空整段"也能让上面那条变绿
        for name in [
            "idx_flow_task_assignee",
            "idx_flow_task_due",
            "idx_flow_log_biz",
            "idx_flow_log_operator",
            "idx_flow_doc_applicant",
        ] {
            assert_eq!(
                FLOW_INDEXES.iter().filter(|s| s.contains(name)).count(),
                1,
                "flow 兜底索引清单缺 {name}（或重复）：{FLOW_INDEXES:?}"
            );
        }
        // 唯一的租户作用域索引必须仍在 3.5g 的兜底表里——两边同时被删才是真缺口
        let tenant_scope_src = include_str!("tenant.rs");
        assert!(
            tenant_scope_src.contains("\"uk_flow_task_tenant_biz\"")
                && tenant_scope_src.contains("\"uk_flow_task_biz\""),
            "ensure_tenant_unique_scope 必须同时知道旧索引（删）与新索引（建）"
        );
    }
}

/// Phase 3 换源（唯一不可逆点）的读失败面：`sys_dept` 读不出来必须**中止**，不得剔行。
///
/// 立案（b146）：改造前三处读点是 `continue` 与 `if let Ok(Some(pid))`——`Err`（列形状 /
/// affinity 不符）与 `NULL`（旧模型根 / 孤儿行）走同一条"跳过"路径。而入口用
/// `sys_tenant > 0 || 映射 > 0` 判"已完成"：按残缺父子图跑完一次，漏掉的部门就带着旧
/// `tenant_id` 永久留在原处，重启也不再修——"做错一半"比"没做"更坏。
///
/// 两条判据缺一不可：
/// 1. **中止面**：树里一条 `parent_id` 不可解码 ⇒ 返回 Err（点名 parent_id）且 `sys_tenant` 0 行；
/// 2. **不过度**：`parent_id` 为 NULL 的行照常跳过、换源照样成功——NULL 是**值**不是故障，
///    若它同样触发中止，正常存量库会一个租户都换不过来（把"默认安全"做成"默认不可用"）。
mod tenant_phase3_read_failure_tests {
    use crate::initialize::ensure_tenant_phase3;
    use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};

    async fn create_dept_table(db: &DatabaseConnection) {
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "CREATE TABLE sys_dept (\
                 dept_id INTEGER PRIMARY KEY, \
                 parent_id BIGINT NULL, \
                 dept_name VARCHAR(64) NULL, \
                 status VARCHAR(1) NULL, \
                 tenant_id BIGINT NOT NULL DEFAULT 0, \
                 del_flag VARCHAR(1) NOT NULL DEFAULT '0'\
             )"
            .to_string(),
        ))
        .await
        .expect("建 sys_dept 失败");
        // remap 子树段对 sys_user 的 `UPDATE … tenant_id` 是无条件语句（真实库里 Phase 2
        // 兜底已保证这两列存在），因此这里按真实形态给出最小列集，而不是让它去撞"表不存在"
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "CREATE TABLE sys_user (\
                 user_id INTEGER PRIMARY KEY, \
                 dept_id BIGINT NULL, \
                 tenant_id BIGINT NOT NULL DEFAULT 0\
             )"
            .to_string(),
        ))
        .await
        .expect("建 sys_user 失败");
    }

    async fn exec(db: &DatabaseConnection, sql: &str) {
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            sql.to_string(),
        ))
        .await
        .unwrap_or_else(|e| panic!("执行失败：{sql} ⇒ {e}"));
    }

    /// 根部门 200 + 子部门 201（parent_id = 200）：正常换源的最小形状。
    async fn seed_root_and_child(db: &DatabaseConnection) {
        exec(
            db,
            "INSERT INTO sys_dept (dept_id, parent_id, dept_name, status) \
             VALUES (200, 0, '旧租户A', '0')",
        )
        .await;
        exec(
            db,
            "INSERT INTO sys_dept (dept_id, parent_id, dept_name, status) \
             VALUES (201, 200, '子部门', '0')",
        )
        .await;
    }

    async fn count_tenants(db: &DatabaseConnection) -> i64 {
        db.query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS n FROM sys_tenant".to_string(),
        ))
        .await
        .expect("读 sys_tenant 失败")
        .and_then(|r| r.try_get::<i64>("", "n").ok())
        .expect("sys_tenant 计数取不出来（表未建？）")
    }

    #[tokio::test]
    async fn undecodable_parent_id_aborts_instead_of_remapping_a_partial_tree() {
        let (db, path) = super::schema_equivalence_lock_tests::fresh_db("phase3_bad_parent").await;
        create_dept_table(&db).await;
        seed_root_and_child(&db).await;
        // 一条不可按 BIGINT 解码的 parent_id：SQLite 动态类型允许它落库，读侧必然 Err
        exec(
            &db,
            "INSERT INTO sys_dept (dept_id, parent_id, dept_name, status) \
             VALUES (202, '不是数字', '坏行', '0')",
        )
        .await;

        let err = ensure_tenant_phase3(&db)
            .await
            .expect_err("parent_id 读不出来时必须中止换源（剔行会让残缺子树永久留在旧租户下）");
        assert!(
            err.to_string().contains("sys_dept.parent_id"),
            "中止原因必须点名 parent_id（运维据此去查列形状）：{err}"
        );
        assert_eq!(
            count_tenants(&db).await,
            0,
            "中止后不得留下任何已建租户行——这是唯一不可逆点的半成品"
        );

        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn null_parent_id_is_a_value_and_still_remaps() {
        let (db, path) = super::schema_equivalence_lock_tests::fresh_db("phase3_null_parent").await;
        create_dept_table(&db).await;
        seed_root_and_child(&db).await;
        // 旧模型里 parent_id 为 NULL 的根/孤儿行：值不是故障，必须照常跳过
        exec(
            &db,
            "INSERT INTO sys_dept (dept_id, parent_id, dept_name, status) \
             VALUES (203, NULL, '孤儿部门', '0')",
        )
        .await;

        ensure_tenant_phase3(&db)
            .await
            .expect("NULL parent_id 不是读失败，换源必须成功（否则正常存量库一个租户都换不过来）");
        assert_eq!(
            count_tenants(&db).await,
            1,
            "只有一个根部门（200）⇒ 只建一个租户；203 只是孤儿行"
        );
        let code = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT tenant_code AS c FROM sys_tenant".to_string(),
            ))
            .await
            .expect("读 sys_tenant 失败")
            .and_then(|r| r.try_get::<String>("", "c").ok())
            .expect("tenant_code 取不出来");
        assert_eq!(code, "t200", "租户 code 由根部门 dept_id 确定性生成");

        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
