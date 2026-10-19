// stepby-axum/src/integration_tests/retention_cleanup.rs
//! 保留期清理链路集成测试（批五十八，对齐 b57 接线的方法级覆盖）：
//! - sys_audit_change clean_expired：过期行删除、新鲜行保留、返回受影响行数
//! - sys_msg_send_log delete_older_than（经 clean_send_logs_expired）：
//!   过期已完成行删除、**待发送（send_time NULL）永不清理**、新鲜行保留
//!
//! 数据说明：迁移种子无 audit_change / msg_send_log 行，本测试直插带可控时间戳的
//! 行（实体 ActiveModel），清理断言按标记行精确核对，不触碰其他数据。

use chrono::{Duration, NaiveDateTime, Utc};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};

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
