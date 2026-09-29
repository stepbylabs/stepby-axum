// stepby-axum/src/integration_tests/ip_location.rs
//! IP 归属地库管理链路集成测试：
//! - GET  /system/ipLocation/status   状态结构断言
//! - GET  /system/ipLocation/config   脱敏配置结构断言
//! - PUT  /system/ipLocation/config   保存快乐路径（p3terx）+ 参数校验失败分支（400）
//!
//! 说明：
//! - /system/ipLocation/* 为受保护路由；admin 是超管（*:*:*，权限中间件短路）可直接访问。
//! - 测试环境 mmdb/xdb 库文件可能不存在，服务优雅降级：mmdbLoaded/xdbLoaded 为布尔并反映真实状态，
//!   此处只断言字段结构（is_boolean），不断言具体加载值，保证文件存在与否都稳定通过。
//! - update / reload 等端点会真实下载/读取 IP 库文件，依赖外部环境，不在集成测试覆盖范围内。
//! - 所有断言仅做加法（put_json 快乐路径 / send_raw 校验分支），不触发任何真实外部调用。

use axum::http::{Method, StatusCode};

use super::TestContext;

/// IP 库状态：断言结构字段存在且类型正确（文件加载状态为布尔，实时反映文件是否存在）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ipl_status_structure() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/system/ipLocation/status").await;
    let d = &v["data"];
    assert!(
        d["mmdbLoaded"].is_boolean(),
        "mmdbLoaded 应为布尔，实际: {v}"
    );
    assert!(d["mmdbPath"].is_string(), "mmdbPath 应为字符串，实际: {v}");
    assert!(d["mmdbSize"].is_number(), "mmdbSize 应为数字，实际: {v}");
    assert!(
        d["xdbEnabled"].is_boolean(),
        "xdbEnabled 应为布尔，实际: {v}"
    );
    assert!(d["xdbLoaded"].is_boolean(), "xdbLoaded 应为布尔，实际: {v}");
    assert!(
        d["autoUpdateCron"].is_string(),
        "autoUpdateCron 应为字符串，实际: {v}"
    );
    assert!(
        !d["currentSource"].as_str().unwrap_or("").is_empty() && d["currentSource"].is_string(),
        "currentSource 应为非空字符串（默认 p3terx），实际: {v}"
    );
    assert!(
        d["maxmindAccountIdConfigured"].is_boolean(),
        "maxmindAccountIdConfigured 应为布尔，实际: {v}"
    );
    assert!(
        d["maxmindLicenseKeyConfigured"].is_boolean(),
        "maxmindLicenseKeyConfigured 应为布尔，实际: {v}"
    );
}

/// IP 库配置读取 + 保存快乐路径：GET 结构 → PUT(p3terx) → GET 反映更新。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ipl_config_get_and_save_ok() {
    let ctx = TestContext::new().await;

    // 1. GET config：脱敏结构
    let v = ctx.get_json("/system/ipLocation/config").await;
    let d = &v["data"];
    assert!(
        d["updateSource"].is_string(),
        "updateSource 应为字符串，实际: {v}"
    );
    assert!(
        d["maxmindAccountIdConfigured"].is_boolean(),
        "maxmindAccountIdConfigured 应为布尔，实际: {v}"
    );
    assert!(
        d["maxmindLicenseKeyConfigured"].is_boolean(),
        "maxmindLicenseKeyConfigured 应为布尔，实际: {v}"
    );
    assert!(
        d["autoUpdateEnabled"].is_boolean(),
        "autoUpdateEnabled 应为布尔，实际: {v}"
    );

    // 2. 保存：切到 p3terx（空凭据，不要求 CONFIG_ENC_KEY），纯 DB upsert，稳定通过
    let v = ctx
        .put_json(
            "/system/ipLocation/config",
            serde_json::json!({
                "updateSource": "p3terx",
                "maxmindAccountId": "",
                "maxmindLicenseKey": "",
                "autoUpdateEnabled": false,
                "clearCredentials": false
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 3. 保存后 GET 反映 updateSource=p3terx
    let v = ctx.get_json("/system/ipLocation/config").await;
    assert_eq!(
        v["data"]["updateSource"].as_str(),
        Some("p3terx"),
        "保存后 updateSource 应为 p3terx，实际: {v}"
    );
}

/// IP 库配置保存参数校验失败分支（无外部依赖，命中 handler 显式 bad_request 即 400）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ipl_config_save_validation_errors() {
    let ctx = TestContext::new().await;
    let uri = "/system/ipLocation/config";

    // 1. 非法 update_source → 400（source_invalid）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            uri,
            Some(serde_json::json!({
                "updateSource": "bad_source",
                "maxmindAccountId": "",
                "maxmindLicenseKey": "",
                "autoUpdateEnabled": false,
                "clearCredentials": false
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "非法 update_source 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 update_source 应 400，实际: {status}"
    );

    // 2. 切到 maxmind 但未提供凭据 → 400（maxmind_credentials_required）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            uri,
            Some(serde_json::json!({
                "updateSource": "maxmind",
                "maxmindAccountId": "",
                "maxmindLicenseKey": "",
                "autoUpdateEnabled": false,
                "clearCredentials": false
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "maxmind 缺凭据业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "maxmind 缺凭据应 400，实际: {status}"
    );
}
