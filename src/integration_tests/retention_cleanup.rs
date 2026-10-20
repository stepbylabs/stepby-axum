// stepby-axum/src/integration_tests/retention_cleanup.rs
//! 保留期清理链路集成测试（批五十八，对齐 b57 接线的方法级覆盖）：
//! - sys_audit_change clean_expired：过期行删除、新鲜行保留、返回受影响行数
//! - sys_msg_send_log delete_older_than（经 clean_send_logs_expired）：
//!   过期已完成行删除、**待发送（send_time NULL）永不清理**、新鲜行保留
//!
//! 数据说明：迁移种子无 audit_change / msg_send_log 行，本测试直插带可控时间戳的
//! 行（实体 ActiveModel），清理断言按标记行精确核对，不触碰其他数据。

use chrono::{Duration, NaiveDateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

use super::TestContext;

fn now_naive() -> NaiveDateTime {
    Utc::now().naive_utc()
}

/// 变更留痕保留期清理：180 天语义下，200 天旧行删除、1 天新行保留。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ret_audit_change_clean_expired() {
    let ctx = TestContext::new().await;
    let db = ctx.state.db.clone();
    let now = now_naive();

    // 插入过期（200 天）与新鲜（1 天）各一行
    for (days_ago, marker) in [(200i64, "it_ret_old"), (1i64, "it_ret_fresh")] {
        audit_change_insert(&db, now - Duration::days(days_ago), marker).await;
    }

    let svc = crate::service::sys_audit_change_service::SysAuditChangeService::new(db.clone());
    let affected = svc.clean_expired(180).await.expect("clean_expired 应成功");
    assert_eq!(affected, 1, "应恰好清理 1 条过期留痕，实际 {affected}");

    let all = crate::entity::sys_audit_change::Entity::find()
        .all(&db)
        .await
        .expect("查询应成功");
    assert!(
        all.iter()
            .all(|r| r.table_name != "it_retention" || r.row_pk == "it_ret_fresh"),
        "过期行应被删除、新鲜行应保留，实际: {all:?}"
    );
    assert!(
        all.iter().any(|r| r.row_pk == "it_ret_fresh"),
        "新鲜行必须保留"
    );
}

/// 变更留痕行插入辅助
async fn audit_change_insert(
    db: &sea_orm::DatabaseConnection,
    operated_at: NaiveDateTime,
    marker: &str,
) {
    use crate::entity::sys_audit_change::ActiveModel;
    let am = ActiveModel {
        id: sea_orm::ActiveValue::NotSet,
        tenant_id: Set(0),
        table_name: Set("it_retention".to_string()),
        row_pk: Set(marker.to_string()),
        action: Set("UPDATE".to_string()),
        changed_fields: Set("[]".to_string()),
        before_data: Set(None),
        after_data: Set(None),
        operator_id: Set(None),
        operator_name: Set(Some("it_retention".to_string())),
        operated_at: Set(operated_at),
    };
    am.insert(db).await.expect("留痕行插入应成功");
}

/// 消息发送记录保留期清理：过期已完成删除、**待发送（send_time NULL）保留**、新鲜行保留。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ret_msg_send_log_clean_expired() {
    let ctx = TestContext::new().await;
    let db = ctx.state.db.clone();
    let now = now_naive();

    use crate::entity::sys_msg_send_log::{ActiveModel, Entity};
    // (send_time, marker)
    let cases: [(Option<NaiveDateTime>, &str); 3] = [
        (Some(now - Duration::days(120)), "it_ret_old_done"),
        (None, "it_ret_pending"),
        (Some(now - Duration::days(1)), "it_ret_fresh_done"),
    ];
    for (send_time, marker) in cases {
        let am = ActiveModel {
            log_id: sea_orm::ActiveValue::NotSet,
            tenant_id: Set(0),
            template_code: Set(Some("it_ret".to_string())),
            channel_code: Set(Some("email".to_string())),
            to_addr: Set(format!("{marker}@it.test")),
            subject: Set(Some(marker.to_string())),
            content: Set(Some("it".to_string())),
            sms_params: Set(None),
            status: Set(Some("1".to_string())),
            retry_count: Set(Some(0)),
            max_retry_count: Set(Some(3)),
            last_error: Set(None),
            send_time: Set(send_time),
            remark: Set(None),
            create_time: Set(Some(now)),
        };
        am.insert(&db).await.expect("发送记录插入应成功");
    }

    // 与生产同参构造（Settings 复用应用实例的，保证 MailerService 等协作者一致）
    let svc =
        crate::service::sys_msg_service::SysMsgService::new(db.clone(), ctx.state.config.clone());
    let affected = svc
        .clean_send_logs_expired(90)
        .await
        .expect("clean_send_logs_expired 应成功");
    assert_eq!(
        affected, 1,
        "应恰好清理 1 条过期已完成记录，实际 {affected}"
    );

    let all = Entity::find().all(&db).await.expect("查询应成功");
    let markers: Vec<&str> = all.iter().map(|r| r.to_addr.as_str()).collect();
    assert!(
        !markers.contains(&"it_ret_old_done@it.test"),
        "过期已完成记录应被删除，实际: {markers:?}"
    );
    assert!(
        markers.contains(&"it_ret_pending@it.test"),
        "待发送（send_time NULL）记录永不清理"
    );
    assert!(
        markers.contains(&"it_ret_fresh_done@it.test"),
        "新鲜记录必须保留"
    );
}

/// b73：清理体成功后必须写「上次成功」标记——它是启动补跑判定的**唯一依据**。
///
/// 为什么值得单独锁：错过 03:00 的补跑逻辑完全依赖这个键；键没写 ⇒ 每次启动都补跑（白扫全表），
/// 键写了但格式不是 RFC3339 ⇒ 判定侧解析失败被当作"无标记"（同样每轮补跑）。
/// 两种退化都不会报错，只会静默多做功——正是"没有断言就看不见"的形态。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ret_cleanup_writes_last_success_marker() {
    let ctx = TestContext::new().await;
    let key = crate::scheduler::RETENTION_LAST_RUN_KEY;

    // 前置：隔离库启动时不得已有标记（否则"首轮必补"的语义无从验证）
    let before = ctx.state.store.get(key).await.unwrap();
    assert!(
        before.is_none(),
        "隔离库初始不得已有清理标记，实际: {before:?}"
    );

    let archive: Option<std::sync::Arc<dyn crate::storage::StorageBackend>> = None;
    let summary = crate::scheduler::run_cleanup_expired_logs(
        ctx.state.db.clone(),
        &ctx.state.config,
        archive,
        ctx.state.store.clone(),
    )
    .await
    .expect("清理体必须执行成功（隔离库无过期数据也应正常收尾）");

    let after = ctx.state.store.get(key).await.unwrap();
    let marker = after.expect("清理成功后必须写标记，否则每次启动都会补跑一轮");
    // 必须是 RFC3339：判定侧按 rfc3339 解析，格式漂移 = 静默当作"无标记"
    let parsed = chrono::DateTime::parse_from_rfc3339(&marker);
    assert!(
        parsed.is_ok(),
        "标记必须是 RFC3339 文本（判定侧唯一可解析格式），实际: {marker}"
    );
    assert!(
        parsed.unwrap().with_timezone(&chrono::Utc)
            > chrono::Utc::now() - chrono::Duration::minutes(5),
        "标记必须写的是「刚刚完成」的时间，实际: {marker}"
    );
    // 运行态表计数不阻断（K4 口径），只确认清理确实跑过一轮并留下可读结论
    assert!(
        !summary.is_empty(),
        "清理体必须返回汇总消息供日志/审计，实际: {summary}"
    );

    // 二次调用：标记必须被**刷新**而不是追加新键（键名是单一事实源，写歪就永远读不到）
    ctx.state.store.set_ex(key, "sentinel", 60).await.unwrap();
    crate::scheduler::run_cleanup_expired_logs(
        ctx.state.db.clone(),
        &ctx.state.config,
        None,
        ctx.state.store.clone(),
    )
    .await
    .unwrap();
    let third = ctx.state.store.get(key).await.unwrap();
    assert_ne!(
        third.as_deref(),
        Some("sentinel"),
        "清理必须覆盖同一个键刷新标记（键名漂移=判定侧永远读不到，会退化成每轮都补跑）"
    );
}

// ==================== 批七十九：前端埋点按来源分档保留 ====================

/// 插入一行前端埋点并回改到 N 天前。
///
/// 必须回改：`ActiveModelBehavior::before_save` 对 insert 无条件把 create_time 写成当前时间，
/// 直插指定历史值会被静默覆盖（那样所有"过期"断言都变成"新鲜"，测试恒绿）。
async fn frontend_error_insert(
    db: &sea_orm::DatabaseConnection,
    source: &str,
    level: &str,
    name: &str,
    days_ago: i64,
    tenant_id: i64,
) {
    use crate::entity::sys_frontend_error::{ActiveModel, Column, Entity};
    let am = ActiveModel {
        id: sea_orm::ActiveValue::NotSet,
        tenant_id: Set(tenant_id),
        level: Set(level.to_string()),
        source: Set(source.to_string()),
        name: Set(Some(name.to_string())),
        message: Set(Some("it-retention-probe".to_string())),
        stack: Set(None),
        page_url: Set(None),
        user_agent: Set(None),
        device_type: Set(None),
        view_width: Set(None),
        view_height: Set(None),
        value: Set(None),
        user_name: Set(None),
        create_time: Set(None),
    };
    let saved = am.insert(db).await.expect("插入前端埋点行应成功");
    let past = now_naive() - Duration::days(days_ago);
    Entity::update_many()
        .col_expr(Column::CreateTime, sea_orm::sea_query::Expr::value(past))
        .filter(Column::Id.eq(saved.id))
        .exec(db)
        .await
        .expect("回写历史时间应成功");
}

/// 按名字前缀取回本测试自己插的行（不触碰隔离库里的其它数据）
async fn frontend_error_names(db: &sea_orm::DatabaseConnection, prefix: &str) -> Vec<String> {
    use crate::entity::sys_frontend_error::{Column, Entity};
    Entity::find()
        .filter(Column::Name.like(format!("{prefix}%")))
        .all(db)
        .await
        .expect("查询前端埋点行应成功")
        .into_iter()
        .filter_map(|r| r.name)
        .collect()
}

/// 分档生效：采样按 30 天保留、错误按 7 天清，**走调度体的真实分派路径**。
///
/// 为什么值得单锁：两档的选择发生在 `SysLogConfig::frontend_vital_retention_days()`
/// （含"与错误档相等就不分档"的短路）。写反的后果是"配置显示 30 天、数据按 7 天删"——
/// 没有任何日志或错误会提示，运维只能在基线消失后事后发现。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ret_frontend_vital_split_keeps_vitals_longer() {
    let ctx = TestContext::new().await;
    let db = ctx.state.db.clone();
    let marker = "it-ret-vsplit";
    frontend_error_insert(&db, "vital", "info", &format!("{marker}-vital"), 20, 0).await;
    frontend_error_insert(&db, "api", "error", &format!("{marker}-error"), 20, 0).await;

    let mut cfg = (*ctx.state.config).clone();
    cfg.sys_log.frontend_error_retention_days = 7;
    cfg.sys_log.frontend_vital_retention_days = Some(30);
    crate::scheduler::run_cleanup_expired_logs(db.clone(), &cfg, None, ctx.state.store.clone())
        .await
        .expect("分档清理必须执行成功");

    let names = frontend_error_names(&db, marker).await;
    assert!(
        names.contains(&format!("{marker}-vital")),
        "20 天前的性能采样在 30 天档下必须幸存，实际残留: {names:?}"
    );
    assert!(
        !names.contains(&format!("{marker}-error")),
        "20 天前的错误埋点在 7 天档下必须被清（分档不得把错误信号也一起留着），实际: {names:?}"
    );
}

/// 未配第二档 = 与改造前逐行等价（两类来源都按错误档清）。
///
/// 这是"默认值=现状"的可证伪单测：若 None 分支误走了 `Except(vital)`，采样会被留下；
/// 若误走了 `Only(vital)`，错误信号会被留下。两种退化都只在这一条里能被发现。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ret_frontend_vital_default_is_single_bucket() {
    let ctx = TestContext::new().await;
    let db = ctx.state.db.clone();
    let marker = "it-ret-vsingle";
    frontend_error_insert(&db, "vital", "info", &format!("{marker}-vital"), 20, 0).await;
    frontend_error_insert(&db, "api", "error", &format!("{marker}-error"), 20, 0).await;

    let mut cfg = (*ctx.state.config).clone();
    cfg.sys_log.frontend_error_retention_days = 7;
    cfg.sys_log.frontend_vital_retention_days = None;
    crate::scheduler::run_cleanup_expired_logs(db.clone(), &cfg, None, ctx.state.store.clone())
        .await
        .expect("单档清理必须执行成功");

    let names = frontend_error_names(&db, marker).await;
    assert!(
        names.is_empty(),
        "缺省档必须与改造前一致：两类来源都按 7 天清光，实际残留: {names:?}"
    );
}

/// 采样档比错误档短时同样成立（分档不是"只许更长"的单向开关）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ret_frontend_vital_split_can_keep_vitals_shorter() {
    let ctx = TestContext::new().await;
    let db = ctx.state.db.clone();
    let marker = "it-ret-vshort";
    frontend_error_insert(&db, "vital", "info", &format!("{marker}-vital"), 5, 0).await;
    frontend_error_insert(&db, "resource", "warning", &format!("{marker}-error"), 5, 0).await;

    let svc = crate::service::sys_frontend_error_service::SysFrontendErrorService::new(db.clone());
    let (vitals, others) = svc
        .clean_split_vital(3, 7, None)
        .await
        .expect("分档清理应成功");
    let names = frontend_error_names(&db, marker).await;
    assert_eq!(vitals, 1, "5 天前的采样在 3 天档下应删 1 条，实际 {vitals}");
    assert_eq!(
        others, 0,
        "5 天前的非采样行在 7 天档下不应被删，实际 {others}"
    );
    assert_eq!(names, vec![format!("{marker}-error")], "只剩非采样行");
}

/// 多租户：`tenant_scope` 在分档路径上仍然是硬边界（铁律一）。
///
/// 两档删除都带同一个租户谓词；漏掉一个就是"租户 A 的清理动作删到租户 B 的数据"。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ret_frontend_vital_split_respects_tenant_scope() {
    let ctx = TestContext::new().await;
    let db = ctx.state.db.clone();
    let marker = "it-ret-vtenant";
    frontend_error_insert(&db, "vital", "info", &format!("{marker}-t1-vital"), 20, 1).await;
    frontend_error_insert(&db, "api", "error", &format!("{marker}-t1-error"), 20, 1).await;
    frontend_error_insert(&db, "vital", "info", &format!("{marker}-t2-vital"), 20, 2).await;
    frontend_error_insert(&db, "api", "error", &format!("{marker}-t2-error"), 20, 2).await;

    let svc = crate::service::sys_frontend_error_service::SysFrontendErrorService::new(db.clone());
    let (vitals, others) = svc
        .clean_split_vital(7, 7, Some(1))
        .await
        .expect("本租户分档清理应成功");
    assert_eq!(
        vitals + others,
        2,
        "只应清掉租户 1 的两行，实际 {vitals}+{others}"
    );

    let names = frontend_error_names(&db, marker).await;
    assert!(
        names.contains(&format!("{marker}-t2-vital"))
            && names.contains(&format!("{marker}-t2-error")),
        "租户 2 的行必须一条不动，实际: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n.contains("-t1-")),
        "租户 1 的两行都应被清掉，实际: {names:?}"
    );
}
