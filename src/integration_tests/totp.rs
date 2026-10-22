// stepby-axum/src/integration_tests/totp.rs
//! TOTP 多因子认证链路集成测试：
//! - 初始状态（enabled=false）
//! - setup（生成 secret + otpauthUrl + qrCode）→ verify（校验验证码启用）→ status（enabled=true）
//! - disable（密码 + 验证码双重校验）→ status（enabled=false）
//! - 参数校验错误分支（未 setup 直接 verify / 格式非法 / 错误验证码）
//!
//! 依赖：TOTP secret 由 CONFIG_ENC_KEY（AES-256-GCM）加密缓存于 Redis，
//! 测试需在构造 TestContext 前通过环境变量注入 CONFIG_ENC_KEY（settings 的 env override 读取）。
//!
//! 验证码生成：复用 totp-rs（SHA1 / 6 位 / 30 秒步长，与 totp_handler 参数一致）。
//!
//! 唯一前缀：it_totp（无 DB 持久化数据，主要操作 Redis key：totp:pending:{uid} / totp:enabled:{uid}）。

use super::TestContext;
use axum::http::Method;
use totp_rs::{Algorithm, Builder, Secret};

// `CONFIG_ENC_KEY` 由 harness 在 `TEST_ENV.call_once` 里统一注入（见 `mod.rs`）。
// 这里原先还有一次 `ensure_config_enc_key()` 写**另一个**值——环境是进程共享的，
// 两个值互相覆盖 ⇒ 上一个用例用 A 密钥加密的 TOTP secret，下一个用例起的应用实例
// 可能读到 B 密钥而解不开。注释写着"全部测试写入同一常量，无实际竞争"，而两个常量
// 本就不同（b85 的 `env_discipline` 锁 + `Once` 装载块把这类站点全部拦下）。

/// 根据 Base32 secret 生成当前 TOTP 验证码（与 totp_handler 使用完全相同的参数）。
fn generate_totp_code(secret: &str) -> String {
    let secret = Secret::try_from_base32(secret).expect("Base32 secret 解码失败");
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some("Stepby"))
        .with_account_name("stepby-user")
        .build()
        .expect("构造 TOTP 失败");
    totp.generate_current().to_string()
}

/// 生成一个必然与正确验证码不同的 6 位验证码（翻转最后一位）。
fn wrong_code(correct: &str) -> String {
    let mut chars: Vec<char> = correct.chars().collect();
    let last = chars.pop().expect("验证码至少 6 位");
    chars.push(if last == '0' { '1' } else { '0' });
    chars.into_iter().collect()
}

/// TOTP 全链路：status → setup → verify → status → disable → status。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_totp_setup_verify_disable_chain() {
    let ctx = TestContext::new().await;

    // 1. 初始状态：未启用
    let v = ctx.get_json("/system/user/totp/status").await;
    assert_eq!(v["data"]["enabled"], false, "初始应未启用 TOTP，实际: {v}");

    // 2. setup：返回 secret / otpauthUrl / qrCode
    let v = ctx
        .post_json("/system/user/totp/setup", serde_json::json!({}))
        .await;
    let secret = v["data"]["secret"]
        .as_str()
        .expect("setup 应返回 secret")
        .to_string();
    let otpauth_url = v["data"]["otpauthUrl"]
        .as_str()
        .expect("setup 应返回 otpauthUrl");
    let qr_code = v["data"]["qrCode"].as_str().expect("setup 应返回 qrCode");
    assert!(!secret.is_empty(), "secret 不应为空");
    assert!(
        otpauth_url.starts_with("otpauth://totp/"),
        "otpauthUrl 应为 otpauth://totp/ 开头，实际: {otpauth_url}"
    );
    assert!(
        qr_code.starts_with("data:image/png;base64,"),
        "qrCode 应为 data URL，实际前 20 字符: {}",
        &qr_code[..qr_code.len().min(20)]
    );

    // 3. setup 后（未 verify）状态仍为未启用
    let v = ctx.get_json("/system/user/totp/status").await;
    assert_eq!(
        v["data"]["enabled"], false,
        "verify 前应仍为未启用，实际: {v}"
    );

    // 4. 用错误验证码 verify → 400
    let correct = generate_totp_code(&secret);
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/user/totp/verify",
            Some(serde_json::json!({
                "code": wrong_code(&correct),
                "secret": secret
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "错误验证码 verify 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "错误验证码应 400，实际: {status}"
    );

    // 5. 用正确验证码 verify → 200
    let v = ctx
        .post_json(
            "/system/user/totp/verify",
            serde_json::json!({
                "code": generate_totp_code(&secret),
                "secret": secret
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 6. 状态应为已启用
    let v = ctx.get_json("/system/user/totp/status").await;
    assert_eq!(v["data"]["enabled"], true, "verify 后应已启用，实际: {v}");

    // 7. 已启用后再 verify → 400（already_enabled）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/user/totp/verify",
            Some(serde_json::json!({
                "code": generate_totp_code(&secret),
                "secret": secret
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "重复 verify 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "重复 verify 应 400，实际: {status}"
    );

    // 8. disable 用错误验证码 → 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/user/totp/disable",
            Some(serde_json::json!({
                "password": "admin123",
                "code": wrong_code(&generate_totp_code(&secret))
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "错误验证码 disable 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "错误验证码 disable 应 400，实际: {status}"
    );

    // 9. disable 用错误密码 → 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/user/totp/disable",
            Some(serde_json::json!({
                "password": "wrong-password",
                "code": generate_totp_code(&secret)
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "错误密码 disable 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "错误密码 disable 应 400，实际: {status}"
    );

    // 10. disable 用正确密码 + 验证码 → 200
    let v = ctx
        .post_json(
            "/system/user/totp/disable",
            serde_json::json!({
                "password": "admin123",
                "code": generate_totp_code(&secret)
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 11. 状态应恢复为未启用
    let v = ctx.get_json("/system/user/totp/status").await;
    assert_eq!(v["data"]["enabled"], false, "disable 后应未启用，实际: {v}");
}

/// TOTP 参数校验错误分支（确定性，无需依赖外部）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_totp_validation_errors() {
    let ctx = TestContext::new().await;

    // 1. 未 setup 直接 verify → 400（pending_expired）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/user/totp/verify",
            Some(serde_json::json!({
                "code": "123456",
                "secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "未 setup verify 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "未 setup verify 应 400，实际: {status}"
    );

    // 2. verify 验证码格式非法（5 位）→ 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/user/totp/verify",
            Some(serde_json::json!({
                "code": "12345",
                "secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "非法验证码 verify 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "非法验证码 verify 应 400，实际: {status}"
    );

    // 3. verify 验证码超长（7 位）→ 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/user/totp/verify",
            Some(serde_json::json!({
                "code": "1234567",
                "secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "超长验证码 verify 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "超长验证码 verify 应 400，实际: {status}"
    );

    // 4. disable 密码为空 → 400（garde 校验）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/user/totp/disable",
            Some(serde_json::json!({
                "password": "",
                "code": "123456"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "空密码 disable 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "空密码 disable 应 400，实际: {status}"
    );

    // 5. disable 验证码格式非法（4 位）→ 400（garde 校验）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/user/totp/disable",
            Some(serde_json::json!({
                "password": "admin123",
                "code": "1234"
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "非法验证码 disable 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "非法验证码 disable 应 400，实际: {status}"
    );
}

/// b83（N-24）：TOTP 失败锁定必须以 **429 + `Retry-After`** 呈现，且窗口内**连正确码也不放行**。
///
/// 三条判据各管一件事：
/// ① 状态码：文案是"请 10 分钟后再试"，语义是"稍后再试"（AGENTS C.8/C.10），不是参数错。
///    改造前 verify/disable 分支是 400、登录链是 1003（也映射 400），而密码锁定早就是 429
///    ⇒ 同一语义三种码，客户端与监控都没法按码聚合。
/// ② `Retry-After`：值来自 `SharedStore::ttl`（读不到才回落窗口上限）。集成测试固定走
///    redis 档，所以这一条同时是 `RedisStore::ttl` 的唯一载体——不是顺带，是刻意。
/// ③ 锁定期间正确码必须仍然失败：否则 429 只是一句提示，不是闸门（防暴力枚举的存在理由）。
///
/// 收尾删掉 `totp:verify_fail:*`：admin 是全套件共用账号，留着计数会让本进程后续
/// TOTP 用例在 10 分钟内全部撞锁（那种"上一把用例把下一把洗红"最难查）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_totp_verify_lockout_is_429_with_retry_after() {
    let ctx = TestContext::new().await;

    let v = ctx
        .post_json("/system/user/totp/setup", serde_json::json!({}))
        .await;
    let secret = v["data"]["secret"]
        .as_str()
        .expect("setup 应返回 secret")
        .to_string();
    let correct = generate_totp_code(&secret);

    // 1. 打满阈值（`MAX_TOTP_VERIFY_FAIL = 5`）：每一次都仍是 400（参数级失败）
    for i in 0..5i32 {
        let (status, _h, body) = ctx
            .send_with_headers(ctx.request(
                Method::POST,
                "/system/user/totp/verify",
                Some(serde_json::json!({ "code": wrong_code(&correct), "secret": secret })),
            ))
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::BAD_REQUEST,
            "第 {} 次错误码应是 400（验证码错，不是频率锁），实际 {status}，body {body}",
            i + 1
        );
        assert_ne!(body["code"], 200, "错误码 verify 不应成功，body {body}");
    }

    // 2. 第 6 次即使带**正确码**也必须被拒，且是 429 + Retry-After + body.code=429
    let (status, headers, body) = ctx
        .send_with_headers(ctx.request(
            Method::POST,
            "/system/user/totp/verify",
            Some(serde_json::json!({ "code": correct, "secret": secret })),
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "锁定态必须 429（b83 前是 400），实际 {status}，body {body}"
    );
    assert_eq!(
        body["code"], 429,
        "body.code 必须与 HTTP 状态同值（C.8 契约），实际 {body}"
    );
    let msg = body["msg"].as_str().unwrap_or_default().to_string();
    assert!(
        msg.contains("TOTP"),
        "文案必须是 TOTP 锁定而不是通用限流（若是 `error.rate_limit.*` 说明撞上的是\
         路由级限流中间件，本用例的 429 就不是被测行为），实际: {msg}"
    );
    let retry = headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("锁定响应必须带数字 Retry-After，头={headers:?}，body {body}"));
    assert!(
        (1..=600).contains(&retry),
        "Retry-After 必须落在窗口 1..=600 秒内（取键的真实剩余 TTL），实际 {retry}"
    );

    // 3. 闸门而不是提示：状态仍未启用，说明正确码没有被这次请求消费掉
    let v = ctx.get_json("/system/user/totp/status").await;
    assert_eq!(
        v["data"]["enabled"], false,
        "锁定期间正确码不得生效，实际: {v}"
    );

    // 4. 复原：清掉失败计数键族（见函数头说明）
    let keys = ctx
        .state
        .store
        .scan("totp:verify_fail:*", None)
        .await
        .expect("scan 失败计数键");
    ctx.state.store.del(&keys).await.expect("清理失败计数键");
    assert!(
        !keys.is_empty(),
        "清理面扫到 0 个键 ⇒ 失败计数键族命名变了，本用例的复原形同虚设"
    );
}
