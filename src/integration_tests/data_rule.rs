// stepby-axum/src/integration_tests/data_rule.rs
//! DP-01 数据权限规则引擎集成测试（§5.53）：
//! 真实建规则 → build_conditions 求值 → 以 Condition 执行查询验证注入效果。

use super::TestContext;
use sea_orm::{ColumnTrait, Condition, DatabaseBackend, EntityTrait, QueryFilter, Statement};
use sea_orm::ConnectionTrait;

/// 端到端：fixed 规则 + current_user 规则 OR 合并 → 查询仅命中满足任一规则的行。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_data_rule_conditions_inject_and_evaluate() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    let backend = DatabaseBackend::Sqlite;

    // 规则 1（挂角色 2）：sys_user.user_name eq fixed 'stepby'
    // 规则 2（挂角色 2）：sys_user.user_id ge fixed '1'（uid=1 → 所有 id>=1 都命中）
    let rules: Vec<(i64, &str, &str, &str, &str, &str, &str)> = vec![
        (9101, "仅 stepby", "sys_user", "user_name", "eq", "fixed", "stepby"),
        (9102, "本人 ID 起", "sys_user", "user_id", "ge", "fixed", "1"),
    ];
    for (id, name, field, op, vt, val, rv) in rules {
        db.execute_raw(Statement::from_sql_and_values(
            backend,
            "INSERT OR IGNORE INTO sys_data_rule (rule_id, rule_name, table_name, field_name, op, value_type, rule_value, status, tenant_id, create_by, create_time, del_flag) \
             VALUES (?, ?, ?, ?, ?, ?, ?, '0', 0, 'admin', CURRENT_TIMESTAMP, '0')",
            [id.into(), name.into(), field.into(), op.into(), vt.into(), val.into(), rv.into()],
        ))
        .await
        .expect("插入规则失败");
    }
    for (rid, rule) in [(2i64, 9101i64), (2, 9102)] {
        db.execute_raw(Statement::from_sql_and_values(
            backend,
            "INSERT OR IGNORE INTO sys_role_data_rule (role_id, rule_id) VALUES (?, ?)",
            [rid.into(), rule.into()],
        ))
        .await
        .expect("绑定规则失败");
    }

    let service = crate::service::data_rule_service::DataRuleService::new(std::sync::Arc::new(ctx.state.db.clone()));
    let rule_ctx = crate::service::data_rule_service::DataRuleContext {
        tenant_id: 0,
        user_id: 1,
        dept_id: Some(103),
        dept_children: vec![103],
    };
    let cond: Option<Condition> = service
        .build_conditions(&rule_ctx, "sys_user", &[2])
        .await
        .expect("求值失败");

    // OR 合并语义：user_name='stepby' OR user_id >= 1 → 两条种子用户都可见
    let visible = crate::entity::sys_user::Entity::find()
        .filter(crate::entity::sys_user::Column::DelFlag.eq("0"))
        .filter(cond.unwrap_or_else(Condition::any))
        .all(db)
        .await
        .expect("带规则条件查询失败");
    let names: Vec<&str> = visible.iter().map(|u| u.user_name.as_str()).collect();
    assert!(
        names.contains(&"stepby"),
        "规则 OR 合并后 stepby 必须可见: {names:?}"
    );
    assert!(
        names.contains(&"admin"),
        "user_id>=1（current_user=1）应命中 admin: {names:?}"
    );

    // 收窄对照：把规则 2 的值类型改为 current_tenant 不改变（tid=0 平台），
    // 改为仅规则 1 生效（停用规则 2）→ 只剩 stepby 可见
    db.execute_raw(Statement::from_string(
        backend,
        "UPDATE sys_data_rule SET status='1' WHERE rule_id=9102",
    ))
    .await
    .expect("停用规则失败");
    let cond2: Option<Condition> = service
        .build_conditions(&rule_ctx, "sys_user", &[2])
        .await
        .expect("二次求值失败");
    let visible2 = crate::entity::sys_user::Entity::find()
        .filter(crate::entity::sys_user::Column::DelFlag.eq("0"))
        .filter(cond2.unwrap())
        .all(db)
        .await
        .expect("二次查询失败");
    assert_eq!(visible2.len(), 1, "停用规则 2 后仅 stepby 可见");
    assert_eq!(visible2[0].user_name, "stepby");

    // 横向越权对照：租户管理员（tid=2）求值 → 规则归属平台（tenant_id=0）按租户过滤
    // 不可见 → build_conditions 返回 None（不注入——租户数据面不受平台规则影响）
    let tenant_ctx = crate::service::data_rule_service::DataRuleContext {
        tenant_id: 2,
        user_id: 100,
        dept_id: None,
        dept_children: vec![],
    };
    let cond3 = service
        .build_conditions(&tenant_ctx, "sys_user", &[2])
        .await
        .expect("租户求值失败");
    assert!(
        cond3.is_none(),
        "平台规则对租户管理员必须不可见（None=不注入，租户隔离语义）"
    );
}

/// 无规则场景：返回空 Condition，调用方查询行为与未接入一致（opt-in 渐进）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_data_rule_no_rules_is_noop() {
    let ctx = TestContext::new().await;
    let service = crate::service::data_rule_service::DataRuleService::new(std::sync::Arc::new(ctx.state.db.clone()));
    let rule_ctx = crate::service::data_rule_service::DataRuleContext {
        tenant_id: 0,
        user_id: 1,
        dept_id: None,
        dept_children: vec![],
    };
    let cond = service
        .build_conditions(&rule_ctx, "sys_user", &[2])
        .await
        .expect("无规则求值不应报错");
    assert!(cond.is_none(), "无规则必须返回 None（不得恒假注入）");
    let visible = crate::entity::sys_user::Entity::find()
        .filter(crate::entity::sys_user::Column::DelFlag.eq("0"))
        .all(&ctx.state.db)
        .await
        .expect("空条件查询失败");
    assert!(visible.len() >= 2, "无规则时不应收窄数据面");
}
