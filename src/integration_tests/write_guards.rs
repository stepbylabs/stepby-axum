// stepby-axum/src/integration_tests/write_guards.rs
//! 「读-判断-写」并发敏感路径的守护（台账 b129 §1）
//!
//! 四条路径的**互斥/认领**都必须能在串行测试里被证伪——并发窗口本身不可复现，
//! 但「闸已被占用时请求必须被拒且副作用为零」与「同一快照版本只能认领一次」
//! 都可以用确定性夹具造出来：
//!
//! - A：PAT 签发配额（`common::write_guard::pat_create_key`）
//! - B：部门移动成环（`common::write_guard::dept_tree_key`）
//! - C：消息重试原子认领（`repository::sys_msg_send_log::claim_retry`）
//!
//! 每条用例都带**对照组**：释放闸 / 推进版本号之后，同一请求必须照常成功——
//! 否则「闸永远拒绝」也能让 429 断言变绿（AGENTS 前端归一规范 §3.③）。

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use std::net::SocketAddr;

use super::TestContext;

/// 构造带鉴权头 + ConnectInfo 的原始请求（用于断言非 200 状态码与响应体）。
fn raw_req(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", ctx.token));
    let mut req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .expect("构造请求失败"),
        None => builder.body(Body::empty()).expect("构造请求失败"),
    };
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// 单值查询（sqlite 夹具库）。调用方 SQL 必须给结果列起别名 `v`。
async fn query_scalar<T>(ctx: &TestContext, sql: &str) -> T
where
    T: sea_orm::TryGetable,
{
    ctx.state
        .db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            sql.to_string(),
        ))
        .await
        .expect("查询失败")
        .expect("夹具行必须存在")
        .try_get::<T>("", "v")
        .expect("标量类型不匹配")
}

/// A：PAT 签发闸被占用时，创建请求必须 429 且**不落库**；释放后同一请求照常成功。
///
/// 缺陷形状（台账 §1 A）：`count_by_user` → 与 `max_per_user` 比较 → `insert` 三步之间
/// 没有互斥，两个并发请求都读到 N-1 时各自插入 ⇒ 有效令牌数突破上限（用户无法自行修复：
/// 多出来的令牌仍然可用，只能逐条手工吊销）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pat_create_rejected_while_quota_guard_held() {
    let ctx = TestContext::new().await;
    let uid: i64 = query_scalar(
        &ctx,
        "SELECT user_id AS v FROM sys_user WHERE user_name = 'admin'",
    )
    .await;
    let key = crate::common::write_guard::pat_create_key(uid);

    let count_before: i64 = query_scalar(
        &ctx,
        &format!("SELECT COUNT(*) AS v FROM sys_pat WHERE user_id = {uid}"),
    )
    .await;

    // 抢住闸（等价于「另一个并发请求正在做配额判断」）
    assert!(
        ctx.state
            .store
            .set_nx_ex(&key, "1", 30)
            .await
            .expect("占用闸失败"),
        "首次占用必须成功"
    );

    let (status, body) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::POST,
            "/system/user/profile/tokens",
            Some(serde_json::json!({
                "name": "it_b129_guard",
                "scopes": ["system:config:list"],
                "expireDays": 30
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "闸被占用时必须 429，实际 body={body}"
    );
    assert_eq!(
        body["code"].as_i64(),
        Some(429),
        "业务码必须同步为 429: {body}"
    );
    let count_blocked: i64 = query_scalar(
        &ctx,
        &format!("SELECT COUNT(*) AS v FROM sys_pat WHERE user_id = {uid}"),
    )
    .await;
    assert_eq!(
        count_blocked, count_before,
        "被拒的请求不得落库（否则闸只是把错误提前报出来）"
    );

    // 对照组：释放闸之后，同一请求必须成功（否则「永远拒绝」也能过上面两条断言）
    ctx.state
        .store
        .del(std::slice::from_ref(&key))
        .await
        .expect("释放闸失败");
    let v = ctx
        .post_json(
            "/system/user/profile/tokens",
            serde_json::json!({
                "name": "it_b129_guard",
                "scopes": ["system:config:list"],
                "expireDays": 30
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let count_after: i64 = query_scalar(
        &ctx,
        &format!("SELECT COUNT(*) AS v FROM sys_pat WHERE user_id = {uid}"),
    )
    .await;
    assert_eq!(count_after, count_before + 1, "释放后必须真正落库一条");
}

/// B：部门移动闸被占用时，移动请求必须 429 且部门数据**一字未改**；释放后照常生效。
///
/// 缺陷形状（台账 §1 B，最严重）：防环校验在事务外、事务内不复核 ⇒ 两个管理员并发
/// 把 A 挂到 B、B 挂到 A 时各自都判「无环」，提交后成环。成环后部门树从根不可达
/// （前端消失）、双方都因「有子部门」无法删除、`ancestors` 链污染被后续移动继承。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dept_edit_rejected_while_tree_guard_held() {
    let ctx = TestContext::new().await;
    let (tid, original_name): (i64, String) = {
        let row = ctx
            .state
            .db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT tenant_id, dept_name FROM sys_dept WHERE dept_id = 103".to_string(),
            ))
            .await
            .expect("查询部门失败")
            .expect("种子部门 103 必须存在");
        (
            row.try_get::<i64>("", "tenant_id").expect("tenant_id"),
            row.try_get::<String>("", "dept_name").expect("dept_name"),
        )
    };
    let key = crate::common::write_guard::dept_tree_key(tid);
    assert!(
        ctx.state
            .store
            .set_nx_ex(&key, "1", 30)
            .await
            .expect("占用闸失败"),
        "首次占用必须成功"
    );

    let new_name = format!("{original_name}-b129");
    let (status, body) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::PUT,
            "/system/dept",
            Some(serde_json::json!({ "deptId": 103, "deptName": new_name })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "闸被占用时必须 429，实际 body={body}"
    );
    assert_eq!(
        body["code"].as_i64(),
        Some(429),
        "业务码必须同步为 429: {body}"
    );
    let name_blocked: String = query_scalar(
        &ctx,
        "SELECT dept_name AS v FROM sys_dept WHERE dept_id = 103",
    )
    .await;
    assert_eq!(
        name_blocked, original_name,
        "被拒的移动不得产生任何写入（半截更新比不做更糟）"
    );

    // 对照组：释放闸后同一请求必须生效
    ctx.state
        .store
        .del(std::slice::from_ref(&key))
        .await
        .expect("释放闸失败");
    let v = ctx
        .put_json(
            "/system/dept",
            serde_json::json!({ "deptId": 103, "deptName": new_name }),
        )
        .await;
    ctx.assert_ok(&v);
    let name_after: String = query_scalar(
        &ctx,
        "SELECT dept_name AS v FROM sys_dept WHERE dept_id = 103",
    )
    .await;
    assert_eq!(name_after, new_name, "释放后移动必须真正生效");
}

/// C：同一快照版本的重试只能被认领一次；版本号前移后下一次快照仍可认领。
///
/// 缺陷形状（台账 §1 C）：两个并发重试都从 `retry_count=0` 的快照出发，各自
/// `dispatch` 一次（重复短信/邮件，**不可撤回**），并互相覆盖结局。
/// 这里用确定性顺序复现同一个快照：两次都以 `expected=0` 认领。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_retry_claim_rejects_the_same_snapshot_twice() {
    let ctx = TestContext::new().await;
    let repo =
        crate::repository::sys_msg_send_log::SysMsgSendLogRepository::new(ctx.state.db.clone());

    ctx.state
        .db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO sys_msg_send_log \
             (tenant_id, channel_code, to_addr, status, retry_count, max_retry_count, create_time) \
             VALUES (1, 'it_b129_no_channel', 'it_b129@example.com', '2', 0, 3, datetime('now'))"
                .to_string(),
        ))
        .await
        .expect("插入发送记录夹具失败");
    let log_id: i64 = query_scalar(
        &ctx,
        "SELECT MAX(log_id) AS v FROM sys_msg_send_log WHERE channel_code = 'it_b129_no_channel'",
    )
    .await;

    // 两个请求都在 retry_count=0 这一版上：只有第一个能认领
    assert!(
        repo.claim_retry(log_id, 0).await.expect("认领查询失败"),
        "第一个请求必须认领成功"
    );
    assert!(
        !repo.claim_retry(log_id, 0).await.expect("认领查询失败"),
        "同一快照版本的第二个请求必须被拒（否则会重复外部投递）"
    );
    let after: i32 = query_scalar(
        &ctx,
        &format!("SELECT retry_count AS v FROM sys_msg_send_log WHERE log_id = {log_id}"),
    )
    .await;
    assert_eq!(after, 1, "两次认领只能把版本号推进一格（不是 2）");

    // 对照组：版本号前移后的新快照仍可认领（正常重试不能被闸死）
    assert!(
        repo.claim_retry(log_id, 1).await.expect("认领查询失败"),
        "新快照（expected=1）必须能认领"
    );

    // 历史数据兼容：retry_count 为 NULL 的行必须能被 expected=0 认领
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO sys_msg_send_log \
             (tenant_id, channel_code, to_addr, status, retry_count, max_retry_count, create_time) \
             VALUES (1, 'it_b129_null_rc', 'it_b129@example.com', '2', NULL, 3, datetime('now'))"
                .to_string(),
        ))
        .await
        .expect("插入 NULL 版本夹具失败");
    let null_id: i64 = query_scalar(
        &ctx,
        "SELECT MAX(log_id) AS v FROM sys_msg_send_log WHERE channel_code = 'it_b129_null_rc'",
    )
    .await;
    assert!(
        repo.claim_retry(null_id, 0).await.expect("认领查询失败"),
        "retry_count 为 NULL 的旧行必须能被首次认领（否则它永远抢不到、死信永远发不出去）"
    );
    let null_after: i32 = query_scalar(
        &ctx,
        &format!("SELECT retry_count AS v FROM sys_msg_send_log WHERE log_id = {null_id}"),
    )
    .await;
    assert_eq!(null_after, 1, "NULL 认领后必须落成 1（不是 NULL+1 丢值）");
}
