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
//! - update / reload 会真实下载/读取 IP 库文件，依赖外部环境，**下载链路**不在集成测试覆盖范围内；
//!   `POST /update` 只覆盖它的入参闸门（源非法 / maxmind 缺凭据 ⇒ 400，且抢锁与换文件之前就被拒）。
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

/// `POST /system/ipLocation/update` 的入参闸门（b82 新增，实测抓回两处契约漂移）。
///
/// 修前的真实响应（本机取证）：`?source=e2e90bad` ⇒ **HTTP 500** `{"code":500,"msg":"系统内部错误，
/// 请联系管理员"}`——因为 service 用 `anyhow` 把 `FromStr` 的 Err 一路抛出，而兄弟端点
/// `PUT /config` 对同一个非法值给的是 400 + `source_invalid`。同一个参数两套契约，
/// 违反 C.8；且缺凭据分支同样以 500 呈现，还会先抢走 10 分钟更新锁。
///
/// 三侧判据（缺一即虚锁）：
/// ① 非法源 ⇒ 400 且文案可解析（不得是 500、不得回显裸键名、不得把用户输入写进响应）；
/// ② **对照组证明闸门不是"一律拒绝"**：`?source=MAXMIND`（大写，归一化后合法）也 400，
///    但**失败原因必须换成凭据缺失**——两条 400 的 msg 不同，才证明闸门按语义分派；
/// ③ 无副作用：闸门跑完后 `GET /status` 的库文件事实（size/loaded/currentSource）逐字段不变，
///    且没有一次"更新任务正在进行中"——拒绝发生在抢锁与任何文件 IO 之前。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_ipl_update_gate_rejects_before_side_effects() {
    let ctx = TestContext::new().await;

    let before = ctx.get_json("/system/ipLocation/status").await;

    // ① 非法更新源 → 400（修前是 500）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/ipLocation/update?source=e2e90bad",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 source 应 400（不得以 500 呈现参数错误），实际: {status} {v}"
    );
    assert_eq!(v["code"], 400, "业务码应与 HTTP 同值，实际: {v}");
    let msg_bad = v["msg"].as_str().unwrap_or_default().to_string();
    assert!(!msg_bad.is_empty(), "拒绝必须给可读原因，实际: {v}");
    assert!(
        !msg_bad.starts_with("error."),
        "文案必须是已解析的 i18n 文本，不得回显键名，实际: {msg_bad}"
    );
    assert!(
        !msg_bad.contains("e2e90bad"),
        "不得把用户输入原样写进错误响应，实际: {msg_bad}"
    );

    // ② 对照组：大写 maxmind 归一化后被接受为「合法源」，于是撞到凭据闸门而不是源闸门
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/ipLocation/update?source=MAXMIND",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "maxmind 未配凭据应 400 而非 500，实际: {status} {v}"
    );
    let msg_cred = v["msg"].as_str().unwrap_or_default().to_string();
    assert!(
        msg_cred != msg_bad,
        "两条 400 的原因必须不同，否则闸门退化成一律拒绝：bad={msg_bad} cred={msg_cred}"
    );
    assert!(
        !msg_cred.contains("更新任务正在进行中"),
        "闸门不得排在抢锁之后（否则被拒的请求也会占用 10 分钟锁），实际: {msg_cred}"
    );

    // ③ 无副作用：库文件事实逐字段不变
    let after = ctx.get_json("/system/ipLocation/status").await;
    for key in ["mmdbLoaded", "mmdbSize", "currentSource"] {
        assert_eq!(
            before["data"][key], after["data"][key],
            "{key} 应逐字段不变（两次拒绝之间不得发生下载或换文件），前={before} 后={after}"
        );
    }
}
