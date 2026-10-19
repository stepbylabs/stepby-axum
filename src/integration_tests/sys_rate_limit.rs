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
        .execute_raw(Statement::from_string(
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

/// b72（AGENTS C.10）：敏感操作独立限流档位必须**真的被解析到**。
///
/// 这是"静默回落 `*`"的唯一机械证伪手段：`route_pattern` 与 `MatchedPath` 模板差一个字符
/// （漏 `{id}`、写成 `:id`、多一段前缀）时，中间件不会报错、不会变红，只会永远走全局兜底
/// ——配置看起来"已限流"，实际形同虚设。故逐条按**运行时查表口径**对账。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sensitive_operations_resolve_own_buckets() {
    let ctx = TestContext::new().await;
    // 本套件的 TestContext 不走完整 `initialize::run`（只按需调用 ensure_*），
    // 故这里显式执行播种——与生产启动路径同一个函数，断言的是"真播种 + 真查表"。
    let inserted = crate::initialize::ensure_sensitive_rate_limit_tiers(&ctx.state.db)
        .await
        .expect("敏感操作限流播种失败");
    assert_eq!(
        inserted,
        crate::initialize::SENSITIVE_LIMIT_TIERS.len(),
        "首次播种应插入全部档位；说明矩阵与表内容不一致或播种非幂等"
    );
    // 幂等复跑必须 0 插入（管理员调过的值不得被启动流程覆盖）
    let again = crate::initialize::ensure_sensitive_rate_limit_tiers(&ctx.state.db)
        .await
        .expect("二次播种应幂等成功");
    assert_eq!(again, 0, "重复播种必须零插入（幂等），实际插入 {again} 条");
    ctx.state.rate_limit_service.invalidate_all_cache().await;
    // 未注册路径 ⇒ 必然回落全局默认，作为"更宽"的参照系
    let global = ctx
        .state
        .rate_limit_service
        .get_config_for_route("/definitely/not/registered/anywhere")
        .await
        .expect("全局默认档位读取失败");
    let mut verified = 0usize;
    for (pattern, capacity, refill, _) in crate::initialize::SENSITIVE_LIMIT_TIERS {
        let cfg = ctx
            .state
            .rate_limit_service
            .get_config_for_route(pattern)
            .await
            .unwrap_or_else(|e| panic!("{pattern} 限流配置读取失败: {e}"));
        assert_eq!(
            cfg.capacity, *capacity as u32,
            "{pattern} 未命中独立档位（期望 capacity={capacity}，实际 {}）——\
             疑为路由模板不一致而静默回落全局 `*`",
            cfg.capacity
        );
        assert!(
            (cfg.refill_per_second - *refill).abs() < f64::EPSILON,
            "{pattern} refill_per_second 应为 {refill}，实际 {}",
            cfg.refill_per_second
        );
        assert!(
            cfg.capacity < global.capacity,
            "{pattern} 独立档位必须严格严于全局默认（{} < {}）",
            cfg.capacity,
            global.capacity
        );
        verified += 1;
    }
    assert!(
        verified >= 15,
        "本批应至少对账 15 条敏感档位，实际 {verified} 条（矩阵被裁剪需同步更新本锁）"
    );
}

/// 端到端：敏感写端点桶耗尽后必须 429 + Retry-After（证明中间件确实挂在业务路由上，
/// 而不是只在配置表里"存在"）。请求体故意留空——限流发生在业务处理**之前**，
/// 因此结局只反映闸门，不受参数校验影响。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_update_pwd_bucket_exhaustion_returns_429() {
    let ctx = TestContext::new().await;
    crate::initialize::ensure_sensitive_rate_limit_tiers(&ctx.state.db)
        .await
        .expect("敏感操作限流播种失败");
    // 配置有 10s 进程内 / 300s Redis 缓存，播种后必须失效才能读到新档位
    ctx.state.rate_limit_service.invalidate_all_cache().await;
    // 档位 capacity=5：前 5 次放行（业务码可能是 400/200，但不是 429）
    for i in 1..=5 {
        let (status, body) = ctx
            .send_raw(ctx.request(Method::PUT, "/system/user/profile/updatePwd", None))
            .await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "第 {i} 次改密请求应落在独立桶容量内，却被限流: {body}"
        );
    }
    let (status, body) = ctx
        .send_raw(ctx.request(Method::PUT, "/system/user/profile/updatePwd", None))
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "改密连续第 6 次必须触发独立限流（防在线爆破），实际: {status} {body}"
    );
    assert_eq!(body["code"], 429, "限流业务码应为 429，实际: {body}");
}

/// b72 跨档位隔离端到端锁：打满一个独立档位之后，**其它接口必须照常放行**。
///
/// 旧形态（复现即红）：限流桶只有 `(租户, IP)` 一个维度、参数取"本次请求命中的行"，
/// 于是 5 次/20s 的改密档位会把同客户端的无关接口一起掐断——b72 敏感操作分档落地后
/// e2e 功能 71 实跑直接红（租户恢复 → 域名 verify 429），本用例把该根因钉成回归锁。
/// 修法见 `middleware::rate_limit::rate_limit_route_bucket_key`：独立档位各自成桶，
/// 回落 `*` 的流量仍共用总闸（与改造前逐字节等价）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_own_tier_exhaustion_does_not_starve_other_routes() {
    let ctx = TestContext::new().await;
    crate::initialize::ensure_sensitive_rate_limit_tiers(&ctx.state.db)
        .await
        .expect("敏感操作限流播种失败");
    // 测试 harness 把 `*` 钉成 1e6/1e6（防并行用例自我节流，mod.rs:407）——那会让"共享桶
    // 被紧档位污染"在毫秒级补充下看不出来，本锁就成虚锁。这里**还原生产量级**（100/10，
    // 与入库种子/data/stepby.db 实测一致），使"串桶外溢"必须真的发生才能通过。
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "UPDATE sys_rate_limit SET capacity=100, refill_per_second=10.0 WHERE route_pattern='*'"
                .to_string(),
        ))
        .await
        .expect("还原全局档位失败");
    ctx.state.rate_limit_service.invalidate_all_cache().await;

    // 1) 打满改密独立档位（capacity=5）：第 6 次必须 429（档位真的在生效）
    let mut sixth = None;
    for i in 1..=6 {
        let (status, body) = ctx
            .send_raw(ctx.request(
                Method::PUT,
                "/system/user/profile/updatePwd",
                Some(serde_json::json!({"oldPassword": "x", "newPassword": "yyyyyyyy"})),
            ))
            .await;
        if i == 6 {
            sixth = Some((status, body));
        }
    }
    let (status, body) = sixth.expect("循环必然产生第 6 次响应");
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "改密第 6 次应被自己的档位限流，实际: {status} {body}"
    );

    // 2) 关键断言：同客户端的其它接口完全不受牵连（旧形态此处 429）
    for _ in 0..20 {
        let (status, body) = ctx
            .send_raw(ctx.request(Method::GET, "/system/user/list?pageNum=1&pageSize=10", None))
            .await;
        assert_ne!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "无关接口不得被紧档位掐断（跨档位串桶缺陷形态），实际: {status} {body}"
        );
        assert_eq!(body["code"], 200, "用户列表应正常返回，实际: {body}");
    }

    // 3) 另一个独立档位（PAT AK 轮换）也各自成桶：改密档位的耗尽不得外溢。
    //    用**不存在的 patId** ⇒ 只走校验分支、无任何凭据状态变化（绝不动 admin 口令，
    //    否则会连带打挂并行运行的其它用例如登录）。
    let (status, body) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/pat/999999/rotate-ak",
            Some(serde_json::json!({})),
        ))
        .await;
    assert_ne!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "AK 轮换档位应有自己的桶，实际: {status} {body}"
    );
}
