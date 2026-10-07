// stepby-axum/src/integration_tests/sys_msg.rs
//! 消息中心模块链路集成测试：
//! - 消息渠道 CRUD（列表/新增/详情/修改/删除 + 异常路径）
//! - 渠道连通性测试 channel/test
//! - 消息模板 CRUD（列表/新增/详情/修改/删除 + 异常路径）
//! - 发送记录生命周期（send → 日志查询 → retry → markPending → retryPending → clean → 删除单条）
//!
//! 说明：admin 为超管会短路 permission 中间件，直接经 TestContext 接口即可，无需权限头。
//! 为避免真实 SMTP/外部网关，全部使用 type=sms 的渠道（dispatch 模拟成功，status='0'）。

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;

/// 构造带鉴权头 + ConnectInfo 的原始请求（用于 send_raw 断言非 200 状态码）。
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

/// 消息渠道全链路（分页列表 → 新增 → 详情 → 修改 → 删除）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_channel_crud_chain() {
    let ctx = TestContext::new().await;

    // 1. 分页列表（表无种子渠道，初始为空）
    let v = ctx
        .get_json("/system/msg/channel/list?pageNum=1&pageSize=10")
        .await;
    assert!(v["rows"].is_array(), "rows 应为数组，实际: {v}");

    // 2. 新增渠道（sms 类型模拟投递，it_msg_ 前缀避免冲突）
    let v = ctx
        .post_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelName": "it_msg_集成测试渠道",
                "channelCode": "it_msg_sms",
                "channelType": "sms",
                "configJson": r#"{"access_key":"x","secret_key":"y"}"#,
                "status": "0",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let channel_id = v["data"]["channelId"].as_i64().expect("channelId 应为数字");

    // 3. 详情
    let v = ctx
        .get_json(&format!("/system/msg/channel/{}", channel_id))
        .await;
    assert_eq!(
        v["data"]["channelId"], channel_id,
        "详情 channelId 应一致，实际: {v}"
    );
    assert_eq!(
        v["data"]["channelCode"].as_str(),
        Some("it_msg_sms"),
        "详情 channelCode 应一致，实际: {v}"
    );

    // 4. 按名称分页查询到新渠道
    let v = ctx
        .get_json("/system/msg/channel/list?channelName=it_msg_")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(!rows.is_empty(), "应查到新渠道，实际: {v}");

    // 5. 修改渠道
    let v = ctx
        .put_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelId": channel_id,
                "channelName": "it_msg_集成测试渠道改",
                "channelCode": "it_msg_sms",
                "channelType": "sms",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!("/system/msg/channel/{}", channel_id))
        .await;
    assert_eq!(
        v["data"]["channelName"].as_str(),
        Some("it_msg_集成测试渠道改"),
        "修改后的渠道名称应生效，实际: {v}"
    );

    // 6. 删除渠道
    let v = ctx
        .delete_json(&format!("/system/msg/channel/{}", channel_id))
        .await;
    ctx.assert_ok(&v);

    // 7. 删除后详情应 404
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::GET,
            &format!("/system/msg/channel/{}", channel_id),
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除后详情应 404，实际: {status}"
    );
}

/// 消息渠道异常路径（非法 ID / 不存在 / 缺字段 / 超批量上限）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_channel_error_paths() {
    let ctx = TestContext::new().await;

    // 非法 ID 删除（非数字）→ 400
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::DELETE,
            "/system/msg/channel/abc",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 ID 应 400，实际: {status}"
    );

    // 删除不存在的渠道 → 404
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::DELETE,
            "/system/msg/channel/999999",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除不存在应 404，实际: {status}"
    );

    // 缺少渠道名（garde length min=1）→ 400
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::POST,
            "/system/msg/channel",
            Some(serde_json::json!({
                "channelName": "",
                "channelCode": "it_msg_bad",
                "channelType": "sms"
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "缺渠道名应 400，实际: {status}"
    );

    // 批量删除超过上限（101 个 id > MAX_BATCH_DELETE_SIZE=100）→ 400
    let over = (1..=101)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::DELETE,
            &format!("/system/msg/channel/{}", over),
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "超批量上限应 400，实际: {status}"
    );

    // 非法渠道类型 → 400
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::POST,
            "/system/msg/channel",
            Some(serde_json::json!({
                "channelName": "it_msg_坏类型",
                "channelCode": "it_msg_bad_type",
                "channelType": "wechat"
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法渠道类型应 400，实际: {status}"
    );
}

/// 渠道连通性测试接口（sms 渠道返回 200）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_channel_test() {
    let ctx = TestContext::new().await;

    let v = ctx
        .post_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelName": "it_msg_测试渠道",
                "channelCode": "it_msg_ch_test",
                "channelType": "sms",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let channel_id = v["data"]["channelId"].as_i64().expect("channelId 应为数字");

    // G-07：sms 渠道无 config_json → 连通性测试 fail-closed 400（配置无效）
    let (status, v) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::POST,
            &format!("/system/msg/channel/test/{}", channel_id),
            Some(serde_json::json!({})),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "无配置 sms 渠道测试应 400，实际: {v}"
    );
    assert!(
        v["msg"].as_str().unwrap_or_default().contains("配置无效"),
        "错误消息应提示配置无效，实际: {v}"
    );

    // 补全合法 config_json（gateway_url 指向本地不在线端口——probe 仅校验配置形态）
    // → 配置合法即 200
    let v = ctx
        .put_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelId": channel_id,
                "channelName": "it_msg_测试渠道",
                "channelCode": "it_msg_ch_test",
                "channelType": "sms",
                "status": "0",
                "configJson": r#"{"gateway_url":"http://127.0.0.1:1/send"}"#
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .post_json(
            &format!("/system/msg/channel/test/{}", channel_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);

    // 测试不存在的渠道 → 404
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::POST,
            "/system/msg/channel/test/999999",
            Some(serde_json::json!({})),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "测试不存在渠道应 404，实际: {status}"
    );
}

/// 消息模板全链路（新增 sms 渠道 → 列表 → 新增模板 → 详情 → 修改 → 删除 + 异常路径）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_template_crud_chain() {
    let ctx = TestContext::new().await;

    // 前置：创建 sms 渠道（模板绑定需要渠道存在且启用）
    let v = ctx
        .post_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelName": "it_msg_模板渠道",
                "channelCode": "it_msg_tpl_ch",
                "channelType": "sms",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 1. 分页列表（空）
    let v = ctx
        .get_json("/system/msg/template/list?pageNum=1&pageSize=10")
        .await;
    assert!(v["rows"].is_array(), "rows 应为数组，实际: {v}");

    // 2. 新增模板（绑定 sms 渠道）
    let v = ctx
        .post_json(
            "/system/msg/template",
            serde_json::json!({
                "templateName": "it_msg_集成测试模板",
                "templateCode": "it_msg_tpl",
                "channelCode": "it_msg_tpl_ch",
                "templateSubject": "【it_msg】你好 {{name}}",
                "templateContent": "验证码 {{code}}",
                "status": "0",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let template_id = v["data"]["templateId"]
        .as_i64()
        .expect("templateId 应为数字");

    // 3. 详情
    let v = ctx
        .get_json(&format!("/system/msg/template/{}", template_id))
        .await;
    assert_eq!(
        v["data"]["templateId"], template_id,
        "详情 templateId 应一致，实际: {v}"
    );
    assert_eq!(
        v["data"]["templateCode"].as_str(),
        Some("it_msg_tpl"),
        "详情 templateCode 应一致，实际: {v}"
    );

    // 4. 按名称查询到新模板
    let v = ctx
        .get_json("/system/msg/template/list?templateName=it_msg_")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(!rows.is_empty(), "应查到新模板，实际: {v}");

    // 5. 修改模板
    let v = ctx
        .put_json(
            "/system/msg/template",
            serde_json::json!({
                "templateId": template_id,
                "templateName": "it_msg_集成测试模板改",
                "templateCode": "it_msg_tpl",
                "channelCode": "it_msg_tpl_ch",
                "templateSubject": "【it_msg】您好 {{name}}",
                "templateContent": "验证码 {{code}}",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!("/system/msg/template/{}", template_id))
        .await;
    assert_eq!(
        v["data"]["templateName"].as_str(),
        Some("it_msg_集成测试模板改"),
        "修改后的模板名称应生效，实际: {v}"
    );

    // 6. 删除模板
    let v = ctx
        .delete_json(&format!("/system/msg/template/{}", template_id))
        .await;
    ctx.assert_ok(&v);

    // 7. 删除后详情应 404
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::GET,
            &format!("/system/msg/template/{}", template_id),
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除后详情应 404，实际: {status}"
    );

    // 8. 异常路径：非法 ID 删除 → 400
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::DELETE,
            "/system/msg/template/xyz",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 ID 应 400，实际: {status}"
    );

    // 9. 异常路径：删除不存在模板 → 404
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::DELETE,
            "/system/msg/template/999999",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除不存在模板应 404，实际: {status}"
    );

    // 10. 异常路径：缺少模板内容（garde length min=1）→ 400
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::POST,
            "/system/msg/template",
            Some(serde_json::json!({
                "templateName": "it_msg_缺内容",
                "templateCode": "it_msg_tpl_no_content",
                "templateSubject": "主题",
                "templateContent": ""
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "缺模板内容应 400，实际: {status}"
    );
}

/// 发送记录生命周期：send → 查询日志 → retry → markPending → retryPending → clean → 删除单条 + 非法 ID 400。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_send_log_lifecycle() {
    let ctx = TestContext::new().await;

    // 前置：本地短信网关（真实 HTTP listener，验证 G-07 完整投递链）
    let gateway = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway_addr = gateway.local_addr().unwrap();
    let gateway_handle = std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, Read, Write};
        let (stream, _) = gateway.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line.trim().is_empty() {
                break;
            }
        }
        let mut len_line = String::new();
        // 重新读已消费的请求体长度不可行——简化：读取 content-length 在头里已消费，
        // 改为循环读头时记录 content-length（上面循环已丢）——直接再读一行兜底不可靠。
        // 因此本网关在响应后由断言侧校验 dispatch 状态即可。
        let _ = len_line;
        let mut body = String::new();
        // 读取剩余字节（POST body）
        let mut buf = [0u8; 4096];
        if let Ok(n) = std::io::Read::read(&mut reader, &mut buf) {
            body = String::from_utf8_lossy(&buf[..n]).to_string();
        }
        let resp = "HTTP/1.1 200 OK
Content-Length: 2
Connection: close

ok";
        let mut w = stream;
        w.write_all(resp.as_bytes()).unwrap();
        body
    });

    // 前置：sms 渠道（configJson 带本地网关 URL）+ sms 模板
    let v = ctx
        .post_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelName": "it_msg_日志渠道",
                "channelCode": "it_msg_log_ch",
                "channelType": "sms",
                "status": "0",
                "configJson": format!("{{\"gateway_url\":\"http://{gateway_addr}/send\"}}")
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .post_json(
            "/system/msg/template",
            serde_json::json!({
                "templateName": "it_msg_日志模板",
                "templateCode": "it_msg_log_tpl",
                "channelCode": "it_msg_log_ch",
                "templateSubject": "【it_msg】日志 {{name}}",
                "templateContent": "验证码 {{code}}",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 1. 日志列表（空）
    let v = ctx
        .get_json("/system/msg/log/list?pageNum=1&pageSize=10")
        .await;
    assert!(v["rows"].is_array(), "rows 应为数组，实际: {v}");

    // 2. 发送一条记录（sms 模拟投递成功，status='0'）
    let v = ctx
        .post_json(
            "/system/msg/send",
            serde_json::json!({
                "templateCode": "it_msg_log_tpl",
                "channelCode": "it_msg_log_ch",
                "toAddr": "13800000000",
                "params": { "name": "Alice", "code": "123456" }
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let log_id = v["data"]["logId"].as_i64().expect("send 应返回 logId");
    assert_eq!(
        v["data"]["status"].as_str(),
        Some("0"),
        "sms 真实投递应成功 status='0'，实际: {v}"
    );
    // 网关应收到真实 POST body（G-07 投递链实证）
    let gateway_body = gateway_handle.join().unwrap();
    assert!(
        gateway_body.contains("13800000000"),
        "网关应收到手机号字段，body={gateway_body}"
    );

    // 3. 查询日志（按类型 + toAddr 过滤）
    let v = ctx
        .get_json("/system/msg/log/list?toAddr=13800000000&channelCode=it_msg_log_ch")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(!rows.is_empty(), "应查到发送记录，实际: {v}");

    // 4. 重试（status='0' 记录重发，仍成功）
    let v = ctx
        .post_json(
            &format!("/system/msg/log/retry/{}", log_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"].as_u64(),
        Some(1),
        "retry 应返回处理条数，实际: {v}"
    );

    // 5. 标记待重试 → status='2'
    let v = ctx
        .post_json(
            &format!("/system/msg/log/markPending/{}", log_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"].as_u64(),
        Some(1),
        "markPending 应返回标记条数，实际: {v}"
    );

    // 6. retryPending 处理待重试批次（status='2' 记录被消费，返回 >=1）
    let v = ctx
        .post_json("/system/msg/log/retryPending/10", serde_json::json!({}))
        .await;
    ctx.assert_ok(&v);
    assert!(
        v["data"].as_u64().unwrap_or(0) >= 1,
        "retryPending 应至少处理 1 条待重试记录，实际: {v}"
    );

    // 7. 清空发送记录
    let v = ctx.delete_json("/system/msg/log/clean").await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/msg/log/list?pageNum=1&pageSize=10")
        .await;
    assert!(
        v["rows"].as_array().expect("rows 应为数组").is_empty(),
        "清空后日志应为空，实际: {v}"
    );

    // 8. 再发送一条用于删除单条测试
    let v = ctx
        .post_json(
            "/system/msg/send",
            serde_json::json!({
                "templateCode": "it_msg_log_tpl",
                "channelCode": "it_msg_log_ch",
                "toAddr": "13900000000",
                "params": { "name": "Bob", "code": "654321" }
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let del_log_id = v["data"]["logId"].as_i64().expect("send 应返回 logId");

    // 9. 删除单条发送记录
    let v = ctx
        .delete_json(&format!("/system/msg/log/{}", del_log_id))
        .await;
    ctx.assert_ok(&v);

    // 10. 非法 ID 删除日志 → 400
    let (status, _) = ctx
        .send_raw(raw_req(&ctx, Method::DELETE, "/system/msg/log/bad", None))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 ID 应 400，实际: {status}"
    );

    // 11. 非法 ID 重试 → 400
    let (status, _) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::POST,
            "/system/msg/log/retry/bad",
            Some(serde_json::json!({})),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 ID 重试应 400，实际: {status}"
    );
}

/// S-2 契约锁定：`site` 渠道的**非法 `to_addr`** 仍然静默成功（`status='0'`）
///
/// 决策依据（方案 §7.6 定案，2026-09-26 拍板「维持关闭」）：dispatch 静默成功是
/// **全系统既有契约**（`sms`/`site` 均无外部网关，投递即"记录成功"），单改 flow 的
/// fail-fast 会造成同一系统内语义分裂；因此不改行为，而是用本用例把**既有行为焊死**：
/// 若将来有人把非法 to_addr 改成失败（status='2'）或抛错，本用例会立即变红，
/// 迫使改动者显式评估对全系统（邮件/短信/站内）的影响面。
///
/// flow 侧的正确性由 `sys_flow_service::tests::site_to_addr_is_numeric_string_of_user_id`
/// 保证（flow 只会传字符串化 user_id，不会产生非法 to_addr）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_site_illegal_to_addr_silently_succeeds() {
    let ctx = TestContext::new().await;

    // 前置：site 渠道 + 模板（site 无外部网关，与 flow 站内审计同款）
    let v = ctx
        .post_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelName": "it_msg_站内渠道",
                "channelCode": "it_msg_site_ch",
                "channelType": "site",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .post_json(
            "/system/msg/template",
            serde_json::json!({
                "templateName": "it_msg_站内模板",
                "templateCode": "it_msg_site_tpl",
                "channelCode": "it_msg_site_ch",
                "templateSubject": "【it_msg】站内 {{title}}",
                "templateContent": "你有一条待办：{{title}}",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 非法 to_addr（不可解析为 user_id）：dispatch 直接 Ok(()) → 发送记录 status='0'
    let v = ctx
        .post_json(
            "/system/msg/send",
            serde_json::json!({
                "templateCode": "it_msg_site_tpl",
                "channelCode": "it_msg_site_ch",
                "toAddr": "not-a-user-id",
                "params": { "title": "S-2 契约" }
            }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["status"].as_str(),
        Some("0"),
        "site 渠道非法 to_addr 必须**静默成功**（既有契约，S-2 决策关闭 fail-fast），实际: {v}"
    );
    let log_id = v["data"]["logId"].as_i64().expect("send 应返回 logId");
    assert!(
        v["data"]["lastError"].is_null(),
        "静默成功不得写入 lastError（否则重试机制会被误触发），实际: {v}"
    );

    // 落库核对：记录确实以 status='0' 持久化，且 to_addr 原样保留（便于审计定位）
    let v = ctx
        .get_json("/system/msg/log/list?toAddr=not-a-user-id&channelCode=it_msg_site_ch")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应恰有 1 条记录，实际: {v}");
    assert_eq!(rows[0]["status"].as_str(), Some("0"), "落库状态应为 '0'");
    assert_eq!(
        rows[0]["logId"].as_i64(),
        Some(log_id),
        "落库记录应与 send 返回为同一条"
    );

    // 清理（保持隔离用例不污染其它用例的日志断言）
    let v = ctx
        .delete_json(&format!("/system/msg/log/{}", log_id))
        .await;
    ctx.assert_ok(&v);
}
