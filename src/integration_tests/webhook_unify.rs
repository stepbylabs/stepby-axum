// stepby-axum/src/integration_tests/webhook_unify.rs
//! WebHook 订阅双轨合并（方案 C）集成测试：
//! - ① 存量形态 hook（event_types='login'）经数据收敛 SQL 转换后，login.success 事件命中
//! - ② 登录事件只触发一次（双发删除回归锁：接收计数 = 1，且无旧事件名 login_success 留痕）
//! - ③ 空 event_types 转换后保持 NULL = 订阅全部（行为无损）
//!
//! 数据收敛 SQL 直接复用迁移 `m20261003_000004_webhook_unify` 的
//! `build_unify_update_sql`（单一事实源，兜底片段与迁移同款）。

use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use std::net::IpAddr;

use super::TestContext;

/// 本用例触发登录所用的来源 IP：**刻意与 `TestContext::new()` 的上下文登录不同**。
///
/// 根因（b90 实测）：`new()` 会用 `peer_ip` 登录一次以取得 token，登录处理器把
/// `login.success` 交给 `tokio::spawn` 火后即忘；负载高时该任务可能在本用例插入 hook
/// **之后**才查询 hook 表，于是同一个 hook 上出现两条 login.success（整跑门禁时
/// `left: 2 / right: 1`，隔离复跑恒绿）。按来源 IP 计数既保留"一次登录只派发一次"
/// 的回归锁，又不依赖后台任务的调度时机。
const TRIGGER_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 42));

/// 查询 sys_web_hook 单列值的辅助（sqlite）
async fn query_subscribed_events(ctx: &TestContext, id: i64) -> Option<String> {
    let sql = format!("SELECT subscribed_events FROM sys_web_hook WHERE id = {id}");
    let rows = ctx
        .state
        .db
        .query_all_raw(Statement::from_string(DatabaseBackend::Sqlite, sql))
        .await
        .expect("查询 subscribed_events 失败");
    rows.first()
        .and_then(|r| r.try_get::<Option<String>>("", "subscribed_events").ok())
        .flatten()
}

/// 查询登录用户（admin）所属租户 ID（P0 跨租户修复后事件按租户过滤，hook 必须插在同租户）
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

/// 以存量形态直插回调（绕过 SSRF/DTO 校验，模拟迁移前的库内数据）。
/// `tenant_id`：回调归属租户（事件按租户过滤，须与登录用户同租户才会命中）。
/// target_url 指向必拒绝端口，投递必然失败但会留痕（web_hook_log），供计数断言。
async fn insert_legacy_hook(
    ctx: &TestContext,
    tenant_id: i64,
    name: &str,
    event_types: &str,
) -> i64 {
    let sql = format!(
        "INSERT INTO sys_web_hook \
         (tenant_id, hook_name, event_types, subscribed_events, target_url, content_type, \
          timeout_secs, status, del_flag, create_time, update_time) \
         VALUES ({tenant_id}, '{name}', '{event_types}', NULL, 'http://127.0.0.1:1/hook', 'json', \
          2, '0', '0', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    );
    let res = ctx
        .state
        .db
        .execute_raw(Statement::from_string(DatabaseBackend::Sqlite, sql))
        .await
        .expect("插入存量形态回调失败");
    res.last_insert_id() as i64
}

/// 统计某 hook 的指定事件名留痕条数
async fn count_logs(ctx: &TestContext, hook_id: i64, event_type: &str) -> usize {
    let v = ctx
        .get_json(&format!(
            "/monitor/webHook/log/list?hookId={hook_id}&pageSize=50"
        ))
        .await;
    v["rows"]
        .as_array()
        .expect("log rows 应为数组")
        .iter()
        .filter(|r| r["eventType"].as_str() == Some(event_type))
        .count()
}

/// 只统计**本用例来源 IP** 派发的那一次（见 [`TRIGGER_IP`] 的根因说明）。
async fn count_logs_from_ip(
    ctx: &TestContext,
    hook_id: i64,
    event_type: &str,
    ip: IpAddr,
) -> usize {
    let v = ctx
        .get_json(&format!(
            "/monitor/webHook/log/list?hookId={hook_id}&pageSize=50"
        ))
        .await;
    let want = ip.to_string();
    v["rows"]
        .as_array()
        .expect("log rows 应为数组")
        .iter()
        .filter(|r| r["eventType"].as_str() == Some(event_type))
        .filter(|r| {
            r["payload"]
                .as_str()
                .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok())
                .and_then(|p| p["ip"].as_str().map(|s| s == want))
                .unwrap_or(false)
        })
        .count()
}

/// 触发一次真实登录（成功路径）→ 派发 login.success
async fn trigger_login(ctx: &TestContext) {
    let v = ctx
        .post_json_from(
            TRIGGER_IP,
            "/login",
            serde_json::json!({
                "username": "admin",
                "password": "admin123",
                "code": "",
                "uuid": ""
            }),
        )
        .await;
    assert_eq!(v["code"], 200, "登录应成功，实际: {v}");
}

/// 轮询等待**本用例来源 IP** 的留痕出现（异步 fire-and-forget，最多 ~8s）：
/// 上下文登录的迟到事件不得提前满足这条等待。
async fn wait_for_log_from_ip(ctx: &TestContext, hook_id: i64, event_type: &str, ip: IpAddr) {
    for _ in 0..40 {
        if count_logs_from_ip(ctx, hook_id, event_type, ip).await > 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    panic!("等待事件 {event_type}（来源 {ip}）留痕超时（hook {hook_id}）");
}

/// 方案 C 全链路：存量形态收敛 + 登录事件单次派发 + 空订阅无损。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webhook_unify_and_login_dispatched_once() {
    let ctx = TestContext::new().await;

    // ---- 1. 造存量数据：'login' 订阅 + 空订阅（= 全部）----
    // P0 跨租户修复后事件按租户过滤：hook 必须插在登录用户（admin）同租户才会命中
    let admin_tid = query_admin_tenant_id(&ctx).await;
    let hook_login =
        insert_legacy_hook(&ctx, admin_tid, "it_unify_login", " login , my_event ").await;
    let hook_all = insert_legacy_hook(&ctx, admin_tid, "it_unify_all", "").await;
    assert!(hook_login > 0 && hook_all > 0, "存量 hook 应插入成功");
    assert_eq!(
        query_subscribed_events(&ctx, hook_login).await,
        None,
        "插入时 subscribed_events 应为 NULL（存量形态）"
    );

    // ---- 2. 执行数据收敛 SQL（与迁移/兜底同款，sqlite 方言）----
    let unify_sql =
        migration::m20261003_000004_webhook_unify::build_unify_update_sql(DatabaseBackend::Sqlite);
    ctx.state
        .db
        .execute_raw(Statement::from_string(DatabaseBackend::Sqlite, unify_sql))
        .await
        .expect("执行收敛 SQL 失败");

    // ① 存量形态：' login , my_event ' → ["login.success","my_event"]（映射 + 自定义串保留）
    assert_eq!(
        query_subscribed_events(&ctx, hook_login).await,
        Some(r#"["login.success","my_event"]"#.to_string()),
        "存量 'login' 订阅应收敛为 [\"login.success\",\"my_event\"]"
    );
    // ③ 空 event_types → 保持 NULL（= 订阅全部，行为无损）
    assert_eq!(
        query_subscribed_events(&ctx, hook_all).await,
        None,
        "空 event_types 应保持 NULL（订阅全部）"
    );
    // 幂等：重复执行不产生二次改写
    let again =
        migration::m20261003_000004_webhook_unify::build_unify_update_sql(DatabaseBackend::Sqlite);
    ctx.state
        .db
        .execute_raw(Statement::from_string(DatabaseBackend::Sqlite, again))
        .await
        .expect("重复执行收敛 SQL 失败");
    assert_eq!(
        query_subscribed_events(&ctx, hook_login).await,
        Some(r#"["login.success","my_event"]"#.to_string()),
        "收敛 SQL 应幂等（重复执行结果不变）"
    );

    // ---- 3. 触发登录成功事件 ----
    trigger_login(&ctx).await;

    // ① login.success 命中存量订阅（映射后新口径匹配）——按本用例来源 IP 等待，
    //    上下文登录的迟到事件不算数
    wait_for_log_from_ip(&ctx, hook_login, "login.success", TRIGGER_IP).await;
    // ② 双发删除回归锁：该 hook 上**本用例那次登录**的 login.success 留痕恰好 1 条，
    //    且不存在旧事件名 login_success（若双发未删干净，会出现第二条同事件或旧名留痕）
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    assert_eq!(
        count_logs_from_ip(&ctx, hook_login, "login.success", TRIGGER_IP).await,
        1,
        "登录成功事件必须只派发一次（方案 C 双发删除）"
    );
    assert_eq!(
        count_logs(&ctx, hook_login, "login_success").await,
        0,
        "不得再以旧事件名 login_success 派发"
    );
    // ③ 空 event_types（NULL = 全部）hook 同样命中 → 存量「空 = 全部」语义无损
    wait_for_log_from_ip(&ctx, hook_all, "login.success", TRIGGER_IP).await;

    // ---- 4. 清理（逻辑删除 + 级联清留痕）----
    ctx.delete_json(&format!("/monitor/webHook/{hook_login}"))
        .await;
    ctx.delete_json(&format!("/monitor/webHook/{hook_all}"))
        .await;
}
