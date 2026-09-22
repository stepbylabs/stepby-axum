// axum-backend/src/integration_tests/file_common.rs
//! 文件与公共端点链路集成测试：
//! - 健康检查 /health（真实探测 DB/Redis）与 Prometheus 指标 /metrics（免鉴权）
//! - 验证码 /captchaImage：默认关闭态（img/uuid 为空）与开启态（真实生成 + Redis 存储）
//! - 通用上传 / 下载：multipart txt 快乐路径（上传 → 下载 → 删除 → 再下载 404）+ 参数校验错误分支
//! - 系统文件管理 /system/file/*：list 结构 / upload 危险扩展名与缺字段错误 / delete 非法文件名 400
//! - IP 归属地库管理 /system/ipLocation/*：status / config 结构断言 + 保存（p3terx）与参数错误分支
//! - 在线 HTTP 调试器 /tool/http-debug/execute：非法方法 / 非法 scheme / SSRF 内网地址 → 400
//!
//! 数据说明：
//! - 健康检查真实探测 DB 与 Redis（TestContext 保证隔离 Redis 可达），应为 UP。
//! - 上传写盘到 CWD/uploads/file（与生产同路径解析，本地存储后端），文件名 UUID 命名，
//!   快乐路径末尾通过 /system/file/delete 清理，避免残留。
//! - 验证码开启态依赖测试库中 sys_config 的 captchaEnabled 开关，单独用 build_isolated_state 隔离。
//! - admin 是超管（*:*:*），所有受保护端点均可访问。

use std::net::SocketAddr;

use axum::body::{Body, to_bytes};
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use tower::ServiceExt;

use super::TestContext;
use super::next_peer_ip;

/// 健康检查：真实探测 DB 与 Redis，均应 UP，版本非空。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_health_check() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/health").await;
    assert_eq!(
        v["data"]["status"].as_str(),
        Some("UP"),
        "整体状态应为 UP，实际: {v}"
    );
    assert_eq!(v["data"]["db"].as_str(), Some("UP"), "DB 应 UP，实际: {v}");
    assert_eq!(
        v["data"]["redis"].as_str(),
        Some("UP"),
        "Redis 应 UP，实际: {v}"
    );
    assert!(
        !v["data"]["version"].as_str().unwrap_or("").is_empty(),
        "version 不应为空，实际: {v}"
    );
}

/// Prometheus 指标端点：返回文本格式指标（uptime / db_backend）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metrics_prometheus_text() {
    let ctx = TestContext::new().await;

    let mut req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .expect("构造 /metrics 请求失败");
    // 全局中间件不要求 ConnectInfo，补一个无害的 peer 信息保证与测试客户端一致
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));

    let resp = ctx
        .app
        .clone()
        .oneshot(req)
        .await
        .expect("metrics 请求执行失败");
    assert_eq!(resp.status(), StatusCode::OK, "/metrics 应返回 HTTP 200");
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取 metrics 响应体失败");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("yebot_uptime_seconds"),
        "应包含 uptime 指标，实际: {text}"
    );
    assert!(
        text.contains("yebot_db_backend"),
        "应包含 db_backend 指标，实际: {text}"
    );
}

/// 验证码默认关闭态：测试 harness 强制 captchaEnabled=false，img / uuid 应为空。
/// 注意：CaptchaResult 字段在响应顶层（code/captchaEnabled/img/uuid/registerEnabled），无 data 包装。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_captcha_disabled_default() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/captchaImage").await;
    assert_eq!(v["captchaEnabled"], false, "默认应关闭验证码，实际: {v}");
    assert_eq!(v["img"].as_str(), Some(""), "关闭态 img 应为空，实际: {v}");
    assert_eq!(
        v["uuid"].as_str(),
        Some(""),
        "关闭态 uuid 应为空，实际: {v}"
    );
    assert!(
        v["registerEnabled"].is_boolean(),
        "registerEnabled 应为布尔，实际: {v}"
    );
}

/// 验证码开启态：真实生成图片 + Redis 存储，img / uuid 非空。
/// 与 auth.rs 的 test_captcha_public 区别：此处显式断言 captchaEnabled=true 与 img/uuid 非空。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_captcha_enabled_generates_image() {
    let (state, _slot) = super::build_isolated_state().await;
    // 验证码默认被测试 harness 关闭，这里显式开启，走真实的图片生成 + Redis 存储链路
    state
        .db
        .execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "UPDATE sys_config SET config_value='true' WHERE config_key='sys.account.captchaEnabled'",
        ))
        .await
        .expect("开启验证码开关失败");
    let app = crate::router::build_app(state);
    let peer_ip = next_peer_ip();

    let mut req = Request::builder()
        .method("GET")
        .uri("/captchaImage")
        .body(Body::empty())
        .expect("构造 captchaImage 请求失败");
    // captcha handler 需要 ConnectInfo<SocketAddr>，oneshot 不会自动注入，这里手动补
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((peer_ip, 1234))));

    let resp = app.oneshot(req).await.expect("captchaImage 请求执行失败");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "captchaImage 应返回 HTTP 200"
    );
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取 captchaImage 响应体失败");
    let v: serde_json::Value =
        serde_json::from_slice(&body).expect("captchaImage 响应 JSON 解析失败");
    assert_eq!(v["code"], 200, "captchaImage 业务码应为 200，实际: {v}");
    assert_eq!(
        v["captchaEnabled"], true,
        "开启后 captchaEnabled 应为 true，实际: {v}"
    );
    assert!(
        v["img"].is_string() && !v["img"].as_str().unwrap().is_empty(),
        "开启后应返回 base64 图片，实际: {v}"
    );
    assert!(
        v["uuid"].is_string() && !v["uuid"].as_str().unwrap().is_empty(),
        "开启后应返回非空 uuid，实际: {v}"
    );
}

/// 构造 multipart/form-data 请求体（单个 file 字段），供上传测试使用。
fn multipart_body(
    boundary: &str,
    field: &str,
    filename: &str,
    content_type: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

/// 构造带鉴权头 + ConnectInfo + 自定义 Content-Type 的 multipart 请求
/// （TestContext::request 只支持 JSON body，multipart 需自行构造）。
fn raw_multipart_request(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    boundary: &str,
    body: Vec<u8>,
) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", ctx.token))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("构造 multipart 请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// 通用上传 → 下载 → 删除 → 再下载 404 全链路（txt 白名单快乐路径）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_common_upload_download_delete_chain() {
    let ctx = TestContext::new().await;
    let boundary = "it-file-boundary";
    let content: &[u8] = b"it_file upload hello 2026";

    // 1. 上传：multipart 字段名 file，扩展名 txt（白名单内，纯文本通过 magic 校验）
    let body = multipart_body(boundary, "file", "it-file.txt", "text/plain", content);
    let mut req = Request::builder()
        .method("POST")
        .uri("/common/upload")
        .header("authorization", format!("Bearer {}", ctx.token))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("构造 multipart 上传请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));

    let v = ctx.send_json(req).await;
    let url = v["url"]
        .as_str()
        .expect("应返回 url，实际: {v}")
        .to_string();
    assert!(
        url.starts_with("/uploads/file/"),
        "url 应位于 /uploads/file/ 下，实际: {v}"
    );
    assert_eq!(
        v["fileName"].as_str(),
        Some(url.as_str()),
        "fileName 应等于 url，实际: {v}"
    );
    let new_file_name = v["newFileName"]
        .as_str()
        .expect("应返回 newFileName，实际: {v}")
        .to_string();
    assert!(
        new_file_name.ends_with(".txt"),
        "newFileName 应保留 .txt，实际: {v}"
    );
    assert_eq!(
        v["originalFilename"].as_str(),
        Some("it-file.txt"),
        "originalFilename 应回显，实际: {v}"
    );

    // 2. 下载：二进制流（Content-Type: octet-stream），内容与上传一致
    let req = ctx.request(
        Method::GET,
        &format!("/common/download?fileName={}", new_file_name),
        None,
    );
    let resp = ctx
        .app
        .clone()
        .oneshot(req)
        .await
        .expect("下载请求执行失败");
    assert_eq!(resp.status(), StatusCode::OK, "下载应返回 HTTP 200");
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/octet-stream"),
        "下载 Content-Type 应为 octet-stream"
    );
    let downloaded = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取下载响应体失败");
    assert_eq!(&downloaded[..], content, "下载内容应与上传一致");

    // 3. 删除：按服务器端文件名删除 → 200
    let del_req = ctx.request(
        Method::DELETE,
        "/system/file/delete",
        Some(serde_json::json!({ "fileName": new_file_name })),
    );
    let v = ctx.send_json(del_req).await;
    ctx.assert_ok(&v);

    // 4. 删除后再次下载 → 404（file_not_found）
    let req = ctx.request(
        Method::GET,
        &format!("/common/download?fileName={}", new_file_name),
        None,
    );
    let (status, v) = ctx.send_raw(req).await;
    assert_ne!(v["code"], 200, "删除后下载业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除后下载应 404，实际: {status}"
    );
}

/// 文件模块参数校验错误分支：危险扩展名 / magic 不匹配 / 缺 file 字段 / 非法删除名。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_file_upload_delete_validation_errors() {
    let ctx = TestContext::new().await;
    let boundary = "it-file-err-boundary";

    // 1. 系统文件列表：结构断言（data 为空数组也合法，因无种子文件）
    let v = ctx
        .get_json("/system/file/list?pageNum=1&pageSize=20")
        .await;
    v["data"]["rows"]
        .as_array()
        .expect("rows 应为数组，实际: {v}");
    assert!(v["data"]["total"].is_number(), "total 应为数字，实际: {v}");

    // 2. 危险扩展名（.exe 不在白名单）→ 400
    let body = multipart_body(
        boundary,
        "file",
        "it-evil.exe",
        "application/octet-stream",
        b"MZit-evil",
    );
    let (status, v) = ctx
        .send_raw(raw_multipart_request(
            &ctx,
            Method::POST,
            "/common/upload",
            boundary,
            body,
        ))
        .await;
    assert_ne!(v["code"], 200, "危险扩展名业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "危险扩展名应 400，实际: {status}"
    );

    // 3. txt 声明但内容是 HTML/脚本（magic 校验拒绝伪装标记）→ 400
    let body = multipart_body(
        boundary,
        "file",
        "it-fake.txt",
        "text/plain",
        b"<html><script>alert(1)</script></html>",
    );
    let (status, v) = ctx
        .send_raw(raw_multipart_request(
            &ctx,
            Method::POST,
            "/common/upload",
            boundary,
            body,
        ))
        .await;
    assert_ne!(v["code"], 200, "magic 不匹配业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "magic 不匹配应 400，实际: {status}"
    );

    // 4. 缺少 file 字段 → 400（field_not_found）
    let body = multipart_body(boundary, "notfile", "it-other.txt", "text/plain", b"hello");
    let (status, v) = ctx
        .send_raw(raw_multipart_request(
            &ctx,
            Method::POST,
            "/system/file/upload",
            boundary,
            body,
        ))
        .await;
    assert_ne!(v["code"], 200, "缺 file 字段业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "缺 file 字段应 400，实际: {status}"
    );

    // 5. 删除非法文件名（路径穿越）→ 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            "/system/file/delete",
            Some(serde_json::json!({ "fileName": "../it-evil.txt" })),
        ))
        .await;
    assert_ne!(v["code"], 200, "路径穿越删除业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "路径穿越删除应 400，实际: {status}"
    );

    // 6. 下载非法文件名（路径穿越）→ 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/common/download?fileName=..%2F..%2Fetc%2Fpasswd",
            None,
        ))
        .await;
    assert_ne!(v["code"], 200, "路径穿越下载业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "路径穿越下载应 400，实际: {status}"
    );
}

/// IP 归属地库管理：status / config 结构断言 + 保存（p3terx）+ 参数错误分支。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ip_location_status_config_save() {
    let ctx = TestContext::new().await;

    // 1. status：文件加载状态 + 自动更新 cron 结构
    let v = ctx.get_json("/system/ipLocation/status").await;
    assert!(
        v["data"]["mmdbLoaded"].is_boolean(),
        "mmdbLoaded 应为布尔，实际: {v}"
    );
    assert!(
        v["data"]["xdbEnabled"].is_boolean(),
        "xdbEnabled 应为布尔，实际: {v}"
    );
    assert!(
        v["data"]["autoUpdateCron"].is_string(),
        "autoUpdateCron 应为字符串，实际: {v}"
    );

    // 2. config：脱敏配置结构
    let v = ctx.get_json("/system/ipLocation/config").await;
    assert!(
        v["data"]["updateSource"].is_string(),
        "updateSource 应为字符串，实际: {v}"
    );
    assert!(
        v["data"]["maxmindAccountIdConfigured"].is_boolean(),
        "maxmindAccountIdConfigured 应为布尔，实际: {v}"
    );
    assert!(
        v["data"]["maxmindLicenseKeyConfigured"].is_boolean(),
        "maxmindLicenseKeyConfigured 应为布尔，实际: {v}"
    );
    assert!(
        v["data"]["autoUpdateEnabled"].is_boolean(),
        "autoUpdateEnabled 应为布尔，实际: {v}"
    );

    // 3. 保存：切到 p3terx（空凭据，不要求 CONFIG_ENC_KEY）→ 200
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

    // 4. 非法 update_source → 400（source_invalid）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/ipLocation/config",
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

    // 5. 切到 maxmind 但未提供凭据 → 400（maxmind_credentials_required）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/ipLocation/config",
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

/// 在线 HTTP 调试器参数校验错误分支：非法方法 / 非法 scheme / SSRF 内网地址。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_http_debugger_validation_errors() {
    let ctx = TestContext::new().await;
    let uri = "/tool/http-debug/execute";

    // 1. 非法 HTTP 方法 → 400（不支持的 HTTP 方法）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "method": "FOO",
                "url": "https://example.com",
                "headers": []
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "非法方法业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法方法应 400，实际: {status}"
    );

    // 2. 非法 scheme（ftp）→ 400（仅允许 http/https）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "method": "GET",
                "url": "ftp://example.com/file",
                "headers": []
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "非法 scheme 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 scheme 应 400，实际: {status}"
    );

    // 3. SSRF 拦截：内网/保留地址 → 400（禁止访问内网）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "method": "GET",
                "url": "http://127.0.0.1:8080/status",
                "headers": []
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "SSRF 内网地址业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "SSRF 内网地址应 400，实际: {status}"
    );

    // 4. 缺主机名 URL → 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "method": "GET",
                "url": "http://",
                "headers": []
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "缺主机名业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "缺主机名应 400，实际: {status}"
    );
}
