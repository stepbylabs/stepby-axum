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

/// 注入 CONFIG_ENC_KEY（≥32 字符），供 TOTP secret 加解密使用。
///
/// 与 mod.rs 中 JWT_SECRET 的注入方式一致：进程级环境变量，全部测试写入同一常量，
/// 无实际竞争；settings 通过 `apply_env_overrides` 在构造时读取。
fn ensure_config_enc_key() {
    unsafe {
        std::env::set_var(
            "CONFIG_ENC_KEY",
            "it-test-config-enc-key-0123456789abcdef-32chars",
        );
    }
}

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
    ensure_config_enc_key();
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
    ensure_config_enc_key();
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
