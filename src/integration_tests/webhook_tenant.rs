// stepby-axum/src/integration_tests/webhook_tenant.rs
//! WebHook 事件租户隔离集成测试（P0 跨租户泄漏修复防回归）：
//! - 同租户：租户 X 的事件（user.created）→ 租户 X 的 hook 收到（web_hook_log 留痕）
//! - 跨租户：租户 X 的事件 → 租户 Y 的 hook **不**收到（严禁跨租户触达）
//!
//! 范式说明：无本地 receiver，采用 webhook_unify 同款「必拒绝端口 + web_hook_log
//! 留痕断言」——事件派发为 fire-and-forget，投递必然失败但会先落库留痕，
//! 轮询等待留痕出现即可证明「已触达该 hook」；反之留痕恒为 0 即「未触达」。
//!
//! 口径备注：emit_event（目录事件链）修复后与 dispatch_event 严格同租户过滤
//! （精确同租户，tid=0 平台事件仅投平台租户回调组）。留痕计数走直查 DB
//! （sys_web_hook_log），避免 log list API 的租户范围过滤干扰跨租户断言。

use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use super::TestContext;

/// 查询登录用户（admin）所属租户 ID（事件租户口径的事实源）
async fn query_admin_tenant_id(ctx: &TestContext) -> i64 {
    let rows = ctx
        .state
        .db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT tenant_id FROM sys_user WHERE user_name = 'admin'".to_string(),
        ))
        .await
        .expect("查询 admin 租户失败");
    rows.first()
        .and_then(|r| r.try_get::<i64>("", "tenant_id").ok())
        .expect("种子 admin 必须存在")
}

/// 以指定租户直插启用回调（绕过 SSRF/DTO 校验；subscribed_events=NULL=订阅全部，
/// 使租户过滤成为唯一命中变量）。target_url 指向必拒绝端口，投递必然失败但留痕。
async fn insert_hook(ctx: &TestContext, tenant_id: i64, name: &str) -> i64 {
    let sql = format!(
        "INSERT INTO sys_web_hook \
         (tenant_id, hook_name, event_types, subscribed_events, target_url, content_type, \
          timeout_secs, status, del_flag, create_time, update_time) \
         VALUES ({tenant_id}, '{name}', '', NULL, 'http://127.0.0.1:1/hook', 'json', \
          2, '0', '0', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    );
    let res = ctx
        .state
        .db
        .execute_raw(Statement::from_string(DatabaseBackend::Sqlite, sql))
        .await
        .expect("插入回调失败");
    res.last_insert_id() as i64
}

/// 直查 DB 统计某 hook 的指定事件名留痕条数（绕过 log list API 的租户范围过滤，
/// 保证跨租户「未触达」断言读到的是全量事实）
async fn count_logs_sql(ctx: &TestContext, hook_id: i64, event_type: &str) -> i64 {
    let sql = format!(
        "SELECT COUNT(*) AS n FROM sys_web_hook_log \
         WHERE hook_id = {hook_id} AND event_type = '{event_type}'"
    );
    let rows = ctx
        .state
        .db
        .query_all_raw(Statement::from_string(DatabaseBackend::Sqlite, sql))
        .await
        .expect("统计 web_hook_log 失败");
    rows.first()
        .and_then(|r| r.try_get::<i64>("", "n").ok())
        .unwrap_or(0)
}

/// 轮询等待某 hook 的指定事件留痕出现（异步 fire-and-forget，最多 ~8s）
async fn wait_for_log(ctx: &TestContext, hook_id: i64, event_type: &str) {
    for _ in 0..40 {
        if count_logs_sql(ctx, hook_id, event_type).await > 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    panic!("等待事件 {event_type} 留痕超时（hook {hook_id}）");
}

/// P0 跨租户泄漏防回归：同租户事件命中本租户 hook，异租户 hook 永不触达。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webhook_emit_is_tenant_isolated() {
    let ctx = TestContext::new().await;
    let admin_tid = query_admin_tenant_id(&ctx).await;
    // 异租户：取一个必然不同于 admin 租户的 ID（9999 在种子数据中不存在）
    let other_tid = if admin_tid == 9999 { 9998 } else { 9999 };

    // ---- 1. 造数据：admin 租户 hook + 异租户 hook（均订阅全部）----
    let hook_same = insert_hook(&ctx, admin_tid, "it_tenant_hook_same").await;
    let hook_other = insert_hook(&ctx, other_tid, "it_tenant_hook_other").await;
    assert!(hook_same > 0 && hook_other > 0, "hook 应插入成功");

    // ---- 2. 以 admin（admin 租户操作者）新增用户 → 派发 user.created ----
    // emit_event 的 tenant_id 取事件主体（新用户）租户 = admin 租户
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": "it_tenant_user",
                "nickName": "租户隔离测试用户",
                "email": "stepby@tzkj.net",
                "phonenumber": "13800009999",
                "sex": "0",
                "password": "Stepby@12345",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // ---- 3. 同租户：admin 租户的 hook 必须收到 user.created ----
    wait_for_log(&ctx, hook_same, "user.created").await;

    // ---- 4. 跨租户：异租户 hook 严禁收到（先留缓冲窗口再断言恒为 0）----
    // 与 webhook_unify 同款：多等 800ms 收尾异步派发，再断言零留痕
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    assert_eq!(
        count_logs_sql(&ctx, hook_other, "user.created").await,
        0,
        "跨租户泄漏：异租户 hook 不得收到 admin 租户的 user.created 事件"
    );

    // ---- 5. 清理（逻辑删除 + 级联清留痕）----
    ctx.delete_json(&format!("/monitor/webHook/{hook_same}")).await;
    ctx.delete_json(&format!("/monitor/webHook/{hook_other}")).await;
}
