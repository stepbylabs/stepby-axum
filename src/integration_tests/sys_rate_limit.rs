// stepby-axum/src/integration_tests/sys_rate_limit.rs
//! API 限流配置模块链路集成测试：
//! - 分页列表 / 详情（种子全局默认 "*"）
//! - 新增 → 修改 → 删除 / 状态切换（enabled 布尔开关）
//! - 异常路径（查询不存在的配置 → 404）
//! - M-8 收口：`[rate_limit].mode = "redis"` 的分布式令牌桶（**真 Redis**，非 mock）

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use std::net::SocketAddr;

use super::TestContext;

/// 限流配置全链路（CRUD + 状态切换 + 异常路径）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rate_limit_chain() {
    let ctx = TestContext::new().await;

    // 1. 分页列表（种子含全局默认 "*"）
    let v = ctx
        .get_json("/system/rateLimit/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(!rows.is_empty(), "种子应至少 1 条限流配置，实际: {v}");

    // 2. 详情（定位全局默认 "*" 并校验字段）
    let default_id = rows
        .iter()
        .find(|r| r["routePattern"] == "*")
        .and_then(|r| r["id"].as_i64())
        .expect("种子应有全局默认限流配置");
    let v = ctx
        .get_json(&format!("/system/rateLimit/{}", default_id))
        .await;
    assert_eq!(v["data"]["id"], default_id, "详情 id 应匹配，实际: {v}");
    assert_eq!(
        v["data"]["routePattern"].as_str(),
        Some("*"),
        "全局默认 routePattern 应为 *，实际: {v}"
    );

    // 3. 新增限流规则（it_rl_ 前缀避免与种子冲突）
    let v = ctx
        .post_json(
            "/system/rateLimit",
            serde_json::json!({
                "routePattern": "it_rl_test",
                "capacity": 50,
                "refillPerSecond": 5.0,
                "enabled": true,
                "description": "集成测试限流规则"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 4. 按 routePattern 查询到新规则
    let v = ctx
        .get_json("/system/rateLimit/list?routePattern=it_rl_test")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条新限流规则，实际: {v}");
    let rl_id = rows[0]["id"].as_i64().expect("id 应为数字");

    // 5. 修改（调整容量与补充速率）
    let v = ctx
        .put_json(
            "/system/rateLimit",
            serde_json::json!({
                "id": rl_id,
                "routePattern": "it_rl_test",
                "capacity": 200,
                "refillPerSecond": 20.0,
                "enabled": true,
                "description": "集成测试限流规则改"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/rateLimit/{}", rl_id)).await;
    assert_eq!(v["data"]["capacity"], 200, "修改后容量应为 200，实际: {v}");

    // 6. 状态切换（enabled 由 true 改为 false = 禁用）
    let v = ctx
        .put_json(
            "/system/rateLimit",
            serde_json::json!({
                "id": rl_id,
                "routePattern": "it_rl_test",
                "capacity": 200,
                "refillPerSecond": 20.0,
                "enabled": false,
                "description": "集成测试限流规则改"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/rateLimit/{}", rl_id)).await;
    assert_eq!(
        v["data"]["enabled"], false,
        "状态切换后 enabled 应为 false，实际: {v}"
    );

    // 7. 删除限流规则（物理删除 + 失效缓存）
    let v = ctx
        .delete_json(&format!("/system/rateLimit/{}", rl_id))
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/rateLimit/list?routePattern=it_rl_test")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "删除后不应再查到该限流规则，实际: {v}");

    // 8. 异常路径：查询不存在的限流配置 → 404
    let mut req = Request::builder()
        .method("GET")
        .uri("/system/rateLimit/999999")
        .header("authorization", format!("Bearer {}", ctx.token))
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, v) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "查询不存在的限流配置应返回 404，实际: {status} {v}"
    );
}

// ==================== M-8 收口：Redis 分布式令牌桶 ====================

/// `try_acquire_redis` 的原子语义与 TTL（**真 Redis**，非 mock）。
///
/// 可证伪性：若 Lua 脚本未真正执行/未真正落库，则第 3 次必然仍被放行；
/// 若未设置 PEXPIRE，则 PTTL 恒为 -1（永久键）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_redis_token_bucket_atomic_and_ttl() {
    use crate::middleware::rate_limit::{RateLimitConfig, try_acquire_redis};

    let ctx = TestContext::new().await;
    let mut redis = ctx.redis();
    let key = "rate_limit:it:redis-bucket";
    let _: () = redis::cmd("DEL")
        .arg(key)
        .query_async(&mut redis)
        .await
        .unwrap();

    // 容量 2、不补充：前 2 次放行，第 3 次拒绝且 Retry-After 回落 60s（与内存实现一致）
    let cfg = RateLimitConfig {
        capacity: 2,
        refill_per_second: 0.0,
    };
    let (a1, r1) = try_acquire_redis(&mut redis, key, cfg, 60).await.unwrap();
    let (a2, r2) = try_acquire_redis(&mut redis, key, cfg, 60).await.unwrap();
    let (a3, r3) = try_acquire_redis(&mut redis, key, cfg, 60).await.unwrap();
    assert!((a1, r1) == (true, 0), "第 1 次应放行");
    assert!((a2, r2) == (true, 0), "第 2 次应放行");
    assert!(!a3, "桶用尽后第 3 次必须拒绝（证明计数真的落在 Redis）");
    assert_eq!(r3, 60, "refill=0 时 Retry-After 应回落 60s");

    // 桶键必须带正 TTL（TTL 取 max(配置 60s, 补满时间×2)）
    let pttl: i64 = redis::cmd("PTTL")
        .arg(key)
        .query_async(&mut redis)
        .await
        .unwrap();
    assert!(pttl > 0, "桶键必须带正 TTL，实际 PTTL={pttl}");

    // 补充速率 > 0 时，等待后应能恢复。
    // ⚠️ 补充速率**刻意**取 10/s（而非 1000/s）：高补充速率下"紧邻的第二次"会因毫秒级
    //    间隔就回补 ≥1 个令牌而偶发放行，属 flaky 用例；10/s 下 1ms 仅回补 0.01 个令牌，确定性拒绝。
    let key2 = "rate_limit:it:redis-bucket-refill";
    let _: () = redis::cmd("DEL")
        .arg(key2)
        .query_async(&mut redis)
        .await
        .unwrap();
    let slow = RateLimitConfig {
        capacity: 1,
        refill_per_second: 10.0,
    };
    let (b1, _) = try_acquire_redis(&mut redis, key2, slow, 60).await.unwrap();
    let (b2, _) = try_acquire_redis(&mut redis, key2, slow, 60).await.unwrap();
    assert!(b1, "首次应放行");
    assert!(!b2, "桶空后紧邻的第二次必须被拒绝");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (b3, _) = try_acquire_redis(&mut redis, key2, slow, 60).await.unwrap();
    assert!(
        b3,
        "等待 200ms（回补 2 个令牌，夹取到容量 1）后应可再次放行"
    );

    // 不同键互相隔离（多租户/多 IP 维度不复用配额）
    let key3 = "rate_limit:it:redis-bucket-other";
    let _: () = redis::cmd("DEL")
        .arg(key3)
        .query_async(&mut redis)
        .await
        .unwrap();
    let (c1, _) = try_acquire_redis(&mut redis, key3, cfg, 60).await.unwrap();
    assert!(c1, "新键应独立计数，不得受其它桶影响");

    let _: () = redis::cmd("DEL")
        .arg(key)
        .query_async(&mut redis)
        .await
        .unwrap();
    let _: () = redis::cmd("DEL")
        .arg(key2)
        .query_async(&mut redis)
        .await
        .unwrap();
    let _: () = redis::cmd("DEL")
        .arg(key3)
        .query_async(&mut redis)
        .await
        .unwrap();
}

/// `[rate_limit].mode` 的**中间件链路**：local（默认）不写 Redis，redis 档真写并真限流。
///
/// 可证伪性：
/// - local 档：请求 `/captchaImage` 后 Redis 中**不存在**桶键 ⇒ 证明走的是进程内令牌桶（= 现状）；
/// - redis 档：同一请求后桶键**存在且带 tokens** ⇒ 证明中间件确实改走 Redis（多实例共享配额）；
/// - 收紧配额后第 3 次请求返回 429 且带 Retry-After ⇒ 证明限流真的生效（而非只是写了键）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rate_limit_mode_switch_local_vs_redis() {
    // ---- A. 默认 local 档：Redis 中不得出现桶键 ----
    let ctx_local = TestContext::new().await;
    let local_key = format!("rate_limit:0:{}", ctx_local.peer_ip);
    let _ = ctx_local.get_json("/captchaImage").await;
    let mut redis = ctx_local.redis();
    let exists: bool = redis::cmd("EXISTS")
        .arg(&local_key)
        .query_async(&mut redis)
        .await
        .unwrap();
    assert!(
        !exists,
        "local 档（默认）不得向 Redis 写桶键（证明仍是进程内令牌桶，行为与改造前一致）：{local_key}"
    );

    // ---- B. redis 档：桶键真实落到 Redis ----
    let ctx = TestContext::new_with(&[], |s| {
        s.rate_limit.mode = "redis".to_string();
        s.rate_limit.key_ttl_secs = 60;
    })
    .await;
    let key = format!("rate_limit:0:{}", ctx.peer_ip);
    let mut redis = ctx.redis();
    let _ = ctx.get_json("/captchaImage").await;
    let exists: bool = redis::cmd("EXISTS")
        .arg(&key)
        .query_async(&mut redis)
        .await
        .unwrap();
    assert!(exists, "redis 档必须在 Redis 中留下桶键：{key}");
    let tokens: Option<String> = redis::cmd("HGET")
        .arg(&key)
        .arg("tokens")
        .query_async(&mut redis)
        .await
        .unwrap();
    assert!(tokens.is_some(), "桶键必须带 tokens 字段，实际: {tokens:?}");
    let pttl: i64 = redis::cmd("PTTL")
        .arg(&key)
        .query_async(&mut redis)
        .await
        .unwrap();
    assert!(pttl > 0, "桶键必须带正 TTL（防永久残留），实际 PTTL={pttl}");

    // ---- C. 收紧配额 → 第 3 次请求被限流（429 + Retry-After）----
    // `/captchaImage` 无精确规则 ⇒ 回落 `*` 全局默认；直接改库（DTO 校验不允许 refill=0）
    ctx.state
        .db
        .execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "UPDATE sys_rate_limit SET capacity=2, refill_per_second=0.1 WHERE route_pattern='*'",
        ))
        .await
        .expect("收紧限流配额失败");
    // 失效配置缓存（进程内 10s + Redis 300s），否则仍读到旧的大配额
    ctx.state.rate_limit_service.invalidate_all_cache().await;
    // 清掉已消耗的桶，保证从"满桶（2 个令牌）"开始
    let _: () = redis::cmd("DEL")
        .arg(&key)
        .query_async(&mut redis)
        .await
        .unwrap();

    for i in 1..=2 {
        let (status, body) = ctx
            .send_raw(ctx.request(Method::GET, "/captchaImage", None))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "第 {i} 次请求应在配额内（HTTP {status}）: {body}"
        );
    }
    let (status, body) = ctx
        .send_raw(ctx.request(Method::GET, "/captchaImage", None))
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "配额耗尽后第 3 次请求必须 429，实际: {status} {body}"
    );
    assert_eq!(body["code"], 429, "限流业务码应为 429，实际: {body}");
}
