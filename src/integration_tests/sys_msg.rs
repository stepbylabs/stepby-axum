// stepby-axum/src/integration_tests/sys_msg.rs
//! 消息中心模块链路集成测试：
//! - 消息渠道 CRUD（列表/新增/详情/修改/删除 + 异常路径）
//! - 渠道连通性测试 channel/test
//! - 消息模板 CRUD（列表/新增/详情/修改/删除 + 异常路径）
//! - 发送记录生命周期（send → 日志查询 → retry → markPending → retryPending → clean → 删除单条）
//! - markPending 交回队列语义（只认失败终态 + 重算额度，见
//!   `test_msg_mark_pending_requeues_failed_log`）
//!
//! 说明：admin 为超管会短路 permission 中间件，直接经 TestContext 接口即可，无需权限头。
//! 为避免真实 SMTP/外部网关，全部使用 type=sms 的渠道（dispatch 模拟成功，status='0'）。

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;

/// `retryPending` 挂 `HeavyEntry::MsgOutbound`（`permits=1`：防两个管理员同时触发批量出站重投）。
/// 本文件有两个用例都会打这条入口，并行跑时后到者会收到 429（b93 全量实测：
/// `test_msg_send_log_lifecycle` 的 retryPending 被闸满拒成业务失败）。闸是产品护栏，
/// 不因测试放宽；用例侧用同一把锁把这条入口串起来（与既有 `CONVENTION_TEST_MUTEX` 同取向）。
static MSG_OUTBOUND_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

/// 读取某条发送记录的最新行（列表接口按 toAddr 精确过滤，再按 logId 定位）。
/// 找不到即 panic —— 重试状态机的断言必须建立在"行确实存在"之上。
async fn log_row(ctx: &TestContext, to_addr: &str, log_id: i64) -> serde_json::Value {
    let v = ctx
        .get_json(&format!(
            "/system/msg/log/list?toAddr={to_addr}&pageNum=1&pageSize=20"
        ))
        .await;
    v["rows"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|r| r["logId"].as_i64() == Some(log_id))
                .cloned()
        })
        .unwrap_or_else(|| panic!("应查到 logId={log_id} 的发送记录，实际: {v}"))
}

/// 建一个 sms 渠道并返回 channelId（b130 用例共用）。
///
/// 网关指向 `127.0.0.1:1`（必然连接被拒）：用例只关心"有没有被投递过"，
/// 用死端口让每次真实投递都留下确定结局，而不是靠超时抢时序。
async fn create_sms_channel(ctx: &TestContext, code: &str) -> i64 {
    let v = ctx
        .post_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelName": format!("it_msg_{code}"),
                "channelCode": code,
                "channelType": "sms",
                "configJson": r#"{"gateway_url":"http://127.0.0.1:1/send"}"#,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    v["data"]["channelId"].as_i64().expect("channelId 应为数字")
}

/// 渠道是否仍存在（详情 200 = 存在，404 = 已删）。
async fn channel_exists(ctx: &TestContext, channel_id: i64) -> bool {
    let (status, body) = ctx
        .send_raw(raw_req(
            ctx,
            Method::GET,
            &format!("/system/msg/channel/{}", channel_id),
            None,
        ))
        .await;
    match status {
        StatusCode::OK => true,
        StatusCode::NOT_FOUND => false,
        other => panic!("详情应回 200/404，实际 {other}：{body}"),
    }
}

/// 运行时唯一后缀：让本文件的用例可重跑、且与残留/并行夹具不撞唯一键。
fn unique_suffix() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("系统时间应晚于 UNIX_EPOCH")
        .as_millis()
        .to_string()
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
    let _outbound = MSG_OUTBOUND_TEST_LOCK.lock().await;
    let ctx = TestContext::new().await;

    // 前置：本地短信网关（真实 HTTP listener，验证 G-07 完整投递链）。
    // 服务**两次**请求（第 2 次给步骤 4 的 retry 用），否则 retry 的投递会连不上而
    // 变成待重试态，后续 markPending/retryPending 的判定点就不可预测了。
    // ⚠️ 用共享缓冲而非 `join()` 取回：`join` 会等到第 2 次连接才返回，而那次连接
    //    发生在步骤 4——join 在前就是死锁（本批实测踩到，测试挂死 15 分钟）。
    let gateway = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway_addr = gateway.local_addr().unwrap();
    let gateway_bodies = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    {
        let sink = std::sync::Arc::clone(&gateway_bodies);
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            for _ in 0..2 {
                let (stream, _) = gateway.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                }
                // 读取剩余字节（POST body）
                let mut body = String::new();
                let mut buf = [0u8; 4096];
                if let Ok(n) = std::io::Read::read(&mut reader, &mut buf) {
                    body = String::from_utf8_lossy(&buf[..n]).to_string();
                }
                // 先入账再应答：调用方拿到 2xx 时该次请求体必定已在缓冲里
                sink.lock().unwrap().push_str(&body);
                let resp = "HTTP/1.1 200 OK
Content-Length: 2
Connection: close

ok";
                let mut w = stream;
                w.write_all(resp.as_bytes()).unwrap();
            }
        });
    }

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
    // 网关应收到真实 POST body（G-07 投递链实证）：应答已发出 ⇒ 缓冲必已入账
    let gateway_body = gateway_bodies.lock().unwrap().clone();
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
    // 第二次投递确实打到网关（本步之后该行仍是 '0'，步骤 5/6 的判定点才成立）
    let bodies_after_retry = gateway_bodies.lock().unwrap().clone();
    assert_eq!(
        bodies_after_retry.matches("13800000000").count(),
        2,
        "send 与 retry 应各产生一次真实网关请求，实际缓冲={bodies_after_retry}"
    );
    let row_after_retry = log_row(&ctx, "13800000000", log_id).await;
    assert_eq!(
        row_after_retry["status"].as_str(),
        Some("0"),
        "网关应答 2xx 时 retry 后仍应是成功态，实际: {row_after_retry}"
    );

    // 5. 标记待重试：**成功记录不得被交回队列**（批七十六防线，防重复投递）
    let v = ctx
        .post_json(
            &format!("/system/msg/log/markPending/{}", log_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"].as_u64(),
        Some(0),
        "markPending 对 status='0' 成功记录应跳过（返回 0），实际: {v}"
    );
    // 复核：该行仍是成功态
    let v = ctx
        .get_json("/system/msg/log/list?toAddr=13800000000&pageNum=1&pageSize=10")
        .await;
    let row = v["rows"]
        .as_array()
        .and_then(|a| a.iter().find(|r| r["logId"].as_i64() == Some(log_id)))
        .expect("应查到刚发送的记录");
    assert_eq!(
        row["status"].as_str(),
        Some("0"),
        "成功记录不应被 markPending 改判，实际: {row}"
    );

    // 6. retryPending 处理待重试批次：此刻**没有**待重试记录（第 5 步被拦下），
    //    所以必须返回 0——这条断言是第 5 步防线的可证伪对照（若 markPending
    //    仍无条件置 '2'，这里会变成 >=1 并把成功消息重发一遍）。
    //    待重试批次的正向消费在 test_msg_mark_pending_requeues_failed_log 里取证。
    let v = ctx
        .post_json("/system/msg/log/retryPending/10", serde_json::json!({}))
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"].as_u64(),
        Some(0),
        "无待重试记录时 retryPending 应处理 0 条，实际: {v}"
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

/// 批七十六：markPending 的交回队列语义（只认失败终态，且必须重算重试额度）。
///
/// 用"端口已关闭"的真实网关让投递必然失败，把行推到耗尽终态，再验三步闭环：
/// - 待重试('2')/成功('0') 行都不被重复标记（`status='1'` 过滤 = 防重复投递防线）；
/// - 失败终态('1') 行被交回：返回 1、状态回到 '2'、**retry_count 归零**
///   （`find_pending_retry` 只取 retry_count<max 的行，不归零就等于把死信换成死循环）；
/// - 交回的行真的被批次消费（retryPending 返回 ≥1），链路闭合可跑通。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_mark_pending_requeues_failed_log() {
    let _outbound = MSG_OUTBOUND_TEST_LOCK.lock().await;
    let ctx = TestContext::new().await;

    // 死网关：绑定取号后立即 drop → 端口无人监听，dispatch 必然连接被拒（真实失败，非模拟）
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let v = ctx
        .post_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelName": "it_msg_死网关渠道",
                "channelCode": "it_msg_dead_ch",
                "channelType": "sms",
                "status": "0",
                "configJson": format!("{{\"gateway_url\":\"http://{dead_addr}/send\"}}")
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .post_json(
            "/system/msg/template",
            serde_json::json!({
                "templateName": "it_msg_死网关模板",
                "templateCode": "it_msg_dead_tpl",
                "channelCode": "it_msg_dead_ch",
                "templateSubject": "【it_msg】死链 {{name}}",
                "templateContent": "验证码 {{code}}",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    let to_addr = "13711000000";
    let v = ctx
        .post_json(
            "/system/msg/send",
            serde_json::json!({
                "templateCode": "it_msg_dead_tpl",
                "channelCode": "it_msg_dead_ch",
                "toAddr": to_addr,
                "params": { "name": "Carol", "code": "111111" }
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let log_id = v["data"]["logId"].as_i64().expect("send 应返回 logId");

    // 1. 投递失败 → 待重试 '2'（retry_count 从 0 起算）
    let row = log_row(&ctx, to_addr, log_id).await;
    assert_eq!(
        row["status"].as_str(),
        Some("2"),
        "死网关首次投递应落待重试，实际: {row}"
    );

    // 2. 待重试行重复标记必须被跳过（幂等：不重算额度、不产生第二条队列）
    let v = ctx
        .post_json(
            &format!("/system/msg/log/markPending/{}", log_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"].as_u64(),
        Some(0),
        "待重试('2')行不应被 markPending 重复标记，实际: {v}"
    );

    // 3. 跑满重试额度 → 失败终态 '1'（DEFAULT_MAX_RETRY=3，逐轮 +1）
    let mut exhausted = false;
    for round in 1..=4 {
        let v = ctx
            .post_json("/system/msg/log/retryPending/10", serde_json::json!({}))
            .await;
        ctx.assert_ok(&v);
        let row = log_row(&ctx, to_addr, log_id).await;
        if row["status"].as_str() == Some("1") {
            exhausted = true;
            assert!(
                row["retryCount"].as_i64().unwrap_or(0) >= 3,
                "进入失败终态应已耗尽额度，实际: {row}"
            );
            break;
        }
        assert!(
            row["retryCount"].as_i64().unwrap_or(0) >= round,
            "每轮 retryPending 应让 retry_count 递增，round={round} 实际: {row}"
        );
    }
    assert!(exhausted, "重试耗尽后应进入失败终态 status='1'");

    // 4. markPending 交回队列：恰 1 条，状态回 '2' 且额度重算
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
        "失败终态行应被交回队列，实际: {v}"
    );
    let row = log_row(&ctx, to_addr, log_id).await;
    assert_eq!(
        row["status"].as_str(),
        Some("2"),
        "交回后应回到待重试，实际: {row}"
    );
    assert_eq!(
        row["retryCount"].as_i64(),
        Some(0),
        "交回后必须重算重试额度（否则调度器永不取它），实际: {row}"
    );

    // 5. 调度侧真的消费得动（闭环可跑通，不是"标了就完"）
    let v = ctx
        .post_json("/system/msg/log/retryPending/10", serde_json::json!({}))
        .await;
    ctx.assert_ok(&v);
    assert!(
        v["data"].as_u64().unwrap_or(0) >= 1,
        "交回的行应被批次消费，实际: {v}"
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

/// b130：批量删除的入参归一（重复 id 是**合法的幂等请求**，混入真缺失仍整批拒绝）。
///
/// 立案取证（台账 b130 §1）：`DELETE /system/msg/channel/735,735` 曾回
/// 404「消息渠道不存在」而该行仍在——存在性校验拿**原始列表长度**跟查回行数比，
/// 同一真实 id 写两遍（前端勾选重复拼参 / 脚本重试 / 幂等重放）就被判成"有行不存在"，
/// 用户无法自行修复（行确实在，只能改客户端）。
///
/// 三条判据各自独立，缺一条这个用例就能被"永远 200"或"永远 404"的实现骗过：
/// ① 重复 id ⇒ 200 且行**真的**被删（正向能力）；
/// ② 真缺失混入 ⇒ 404 且**零删除**（b127 的"整批要么全做、要么一条不做"不得被去重顺手破坏）；
/// ③ 对照组：单 id 删除照常 200（证明 ① 不是"这个入口根本不会拒绝"）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_channel_batch_delete_dedupes_repeated_ids() {
    let ctx = TestContext::new().await;
    let suffix = unique_suffix();

    // ① 重复 id：`735,735` 必须删掉那一行（曾整批拒绝且零删除）
    let dup_id = create_sms_channel(&ctx, &format!("it_bdel_dup_{suffix}")).await;
    let v = ctx
        .delete_json(&format!("/system/msg/channel/{dup_id},{dup_id}"))
        .await;
    ctx.assert_ok(&v);
    assert!(
        !channel_exists(&ctx, dup_id).await,
        "重复 id 的批量删除必须真的删掉（去重后长度一致才过存在性校验）"
    );

    // ② 真缺失混入：整批拒绝且一条都不删
    let keep_id = create_sms_channel(&ctx, &format!("it_bdel_keep_{suffix}")).await;
    let (status, body) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::DELETE,
            &format!("/system/msg/channel/{keep_id},999999999"),
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "批内有真缺失时必须 404，实际 {status}：{body}"
    );
    assert!(
        body["msg"].as_str().unwrap_or_default().contains("不存在"),
        "错误消息应说明渠道不存在，实际：{body}"
    );
    assert!(
        channel_exists(&ctx, keep_id).await,
        "批内混入缺失 id 时**一条都不许删**（去重不得把原子语义改坏）：{body}"
    );

    // ③ 对照组：单 id 删除照常成功（同一入口，证明 ① 的 200 是真删而不是"永远 200"）
    let v = ctx
        .delete_json(&format!("/system/msg/channel/{keep_id}"))
        .await;
    ctx.assert_ok(&v);
    assert!(
        !channel_exists(&ctx, keep_id).await,
        "对照组：单 id 删除必须真的删掉"
    );
}

/// b130（N-129-B）：批量重试的渠道解析必须在**任何认领与投递之前**整批校验。
///
/// 立案取证：`retry_loaded_logs` 把 `find_by_code` 写在投递循环里 `?` 上抛 ⇒
/// 批内第 3 条的渠道已被删除时，前 2 条**已经真实投递出去**（dispatch 不可回滚），
/// 接口却回 404 且不返回 `processed`——用户无法判断哪些真的发出去了。
/// 这是"静默的部分成功"，比整批拒绝坏得多。
///
/// 判据的观察量选 `retry_count`：认领（`claim_retry`）成功即 +1 并写回，
/// 所以 **0 就是"投递循环一次都没进"** 的运行时事实；对照组（单条重试）证明
/// 这个记号在认领发生时确实会动——否则"retry_count=0"也能被"这个字段根本没人写"满足。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_retry_batch_preflights_channels_before_any_delivery() {
    let ctx = TestContext::new().await;
    let suffix = unique_suffix();

    // 两条记录都指向死网关（连接被拒 = 真实投递失败，行落 status='2' 待重试）
    let ch_a = format!("it_pf_a_{suffix}");
    let ch_b = format!("it_pf_b_{suffix}");
    let tpl_a = format!("it_pf_a_tpl_{suffix}");
    let tpl_b = format!("it_pf_b_tpl_{suffix}");
    let mut ch_ids = Vec::new();
    let mut tpl_ids = Vec::new();
    for (ch, tpl) in [(&ch_a, &tpl_a), (&ch_b, &tpl_b)] {
        ch_ids.push(create_sms_channel(&ctx, ch).await);
        let v = ctx
            .post_json(
                "/system/msg/template",
                serde_json::json!({
                    "templateName": format!("it_msg_{tpl}"),
                    "templateCode": tpl,
                    "channelCode": ch,
                    "templateSubject": "【it_pf】{{name}}",
                    "templateContent": "内容 {{code}}",
                    "status": "0"
                }),
            )
            .await;
        ctx.assert_ok(&v);
        tpl_ids.push(
            v["data"]["templateId"]
                .as_i64()
                .expect("templateId 应为数字"),
        );
    }
    // id 一律取创建响应，不依赖 list 端点的过滤字段（那是另一个契约，与本判据无关）
    let ch_b_id = ch_ids[1];
    let tpl_b_id = tpl_ids[1];

    let mut log_ids = Vec::new();
    let mut to_addrs = Vec::new();
    for (idx, tpl) in [&tpl_a, &tpl_b].into_iter().enumerate() {
        let to = format!("1380000{:04}", idx);
        let v = ctx
            .post_json(
                "/system/msg/send",
                serde_json::json!({
                    "templateCode": tpl,
                    "toAddr": to,
                    "params": { "name": "pf", "code": "1" }
                }),
            )
            .await;
        ctx.assert_ok(&v);
        assert_eq!(
            v["data"]["status"].as_str(),
            Some("2"),
            "死网关必须投递失败并入待重试，实际：{v}"
        );
        assert_eq!(
            v["data"]["retryCount"].as_i64(),
            Some(0),
            "send 失败只入队、不算一次重试，实际：{v}"
        );
        log_ids.push(v["data"]["logId"].as_i64().expect("send 应返回 logId"));
        to_addrs.push(to);
    }
    let (log_a, log_b) = (log_ids[0], log_ids[1]);

    // 拆掉 B 的渠道：先删模板（否则 channel_in_use 400 拦住），再删渠道
    let v = ctx
        .delete_json(&format!("/system/msg/template/{tpl_b_id}"))
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .delete_json(&format!("/system/msg/channel/{ch_b_id}"))
        .await;
    ctx.assert_ok(&v);

    // 批量重试（批内含一条渠道已消失的记录）⇒ 整批拒绝，且点名是哪条记录
    let (status, body) = ctx
        .send_raw(raw_req(
            &ctx,
            Method::POST,
            &format!("/system/msg/log/retry/{log_a},{log_b}"),
            Some(serde_json::json!({})),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "渠道缺失的批次必须整批 404，实际 {status}：{body}"
    );
    let msg = body["msg"].as_str().unwrap_or_default();
    assert!(
        msg.contains("渠道不存在"),
        "错误消息应说明渠道不存在，实际：{body}"
    );
    assert!(
        msg.contains(&log_b.to_string()),
        "错误消息应点名是哪条记录的前置条件不成立（{log_b}），实际：{body}"
    );

    // 关键判据：A 一次都没被认领/投递（retry_count 是认领记号，仍是 0）
    let row_a = log_row(&ctx, &to_addrs[0], log_a).await;
    assert_eq!(
        row_a["retryCount"].as_i64(),
        Some(0),
        "前置校验失败时**任何一条都不许被认领**（认领会 +1 并真实投递）：{row_a}"
    );
    assert_eq!(
        row_a["status"].as_str(),
        Some("2"),
        "A 行应保持原待重试态，实际：{row_a}"
    );

    // 对照组：单条重试照常走到投递（死网关 ⇒ 仍失败），认领记号必须真的动
    let v = ctx
        .post_json(
            &format!("/system/msg/log/retry/{log_a}"),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"].as_u64(),
        Some(1),
        "对照组的单条重试必须真的处理 1 条，实际：{v}"
    );
    let row_a2 = log_row(&ctx, &to_addrs[0], log_a).await;
    assert_eq!(
        row_a2["retryCount"].as_i64(),
        Some(1),
        "认领必须留下 retry_count+1 的记号——上一条断言（=0）依赖它可证伪：{row_a2}"
    );
    assert_eq!(
        row_a2["status"].as_str(),
        Some("2"),
        "死网关下重试仍失败、仍保持待重试态，实际：{row_a2}"
    );
}

/// b130：调度器自选的待重试批次**不得**被单行前置失效卡死（`OrphanChannelPolicy::FailRow`）。
///
/// 与上一条用例是同一缺陷的两个相反方向：显式 id 的批次要原子拒绝，而调度器批次若也整批
/// 失败，那一行**永远**投不出去（渠道已删），每轮调度都会在同一行上终止 ⇒ 待重试队列
/// 永不排空。正确语义是该行落终态失败（写明原因，用户补建渠道后可手动交回），其余行照常投递。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_retry_pending_fails_orphan_row_without_blocking_batch() {
    let _outbound = MSG_OUTBOUND_TEST_LOCK.lock().await;
    let ctx = TestContext::new().await;
    let suffix = unique_suffix();

    let ch_a = format!("it_rp_a_{suffix}");
    let ch_b = format!("it_rp_b_{suffix}");
    let tpl_a = format!("it_rp_a_tpl_{suffix}");
    let tpl_b = format!("it_rp_b_tpl_{suffix}");
    let mut ch_ids = Vec::new();
    let mut tpl_ids = Vec::new();
    for (ch, tpl) in [(&ch_a, &tpl_a), (&ch_b, &tpl_b)] {
        ch_ids.push(create_sms_channel(&ctx, ch).await);
        let v = ctx
            .post_json(
                "/system/msg/template",
                serde_json::json!({
                    "templateName": format!("it_msg_{tpl}"),
                    "templateCode": tpl,
                    "channelCode": ch,
                    "templateSubject": "【it_rp】{{name}}",
                    "templateContent": "内容 {{code}}",
                    "status": "0"
                }),
            )
            .await;
        ctx.assert_ok(&v);
        tpl_ids.push(
            v["data"]["templateId"]
                .as_i64()
                .expect("templateId 应为数字"),
        );
    }

    let mut log_ids = Vec::new();
    let mut to_addrs = Vec::new();
    for (idx, tpl) in [&tpl_a, &tpl_b].into_iter().enumerate() {
        let to = format!("1390000{:04}", idx);
        let v = ctx
            .post_json(
                "/system/msg/send",
                serde_json::json!({
                    "templateCode": tpl,
                    "toAddr": to,
                    "params": { "name": "rp", "code": "1" }
                }),
            )
            .await;
        ctx.assert_ok(&v);
        assert_eq!(
            v["data"]["status"].as_str(),
            Some("2"),
            "死网关必入待重试：{v}"
        );
        log_ids.push(v["data"]["logId"].as_i64().expect("send 应返回 logId"));
        to_addrs.push(to);
    }
    let (log_a, log_b) = (log_ids[0], log_ids[1]);

    // 拆掉 B 的渠道（先删模板，否则 channel_in_use 拦住）
    let v = ctx
        .delete_json(&format!("/system/msg/template/{}", tpl_ids[1]))
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .delete_json(&format!("/system/msg/channel/{}", ch_ids[1]))
        .await;
    ctx.assert_ok(&v);

    // 调度器入口：批内含一条渠道已消失的记录 ⇒ 该行落终态、其余行照常重试
    let v = ctx
        .post_json("/system/msg/log/retryPending/10", serde_json::json!({}))
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"].as_u64(),
        Some(2),
        "返回值是「本轮处理的条数」= 投递 1 条 + 落终态 1 条，实际：{v}"
    );

    let orphan = log_row(&ctx, &to_addrs[1], log_b).await;
    assert_eq!(
        orphan["status"].as_str(),
        Some("1"),
        "渠道已消失的行必须落**终态失败**（否则队列永不排空），实际：{orphan}"
    );
    assert_eq!(
        orphan["retryCount"].as_i64(),
        Some(1),
        "落终态也要记一次已处理的重试，实际：{orphan}"
    );
    assert!(
        orphan["lastError"]
            .as_str()
            .unwrap_or_default()
            .contains("渠道不存在"),
        "失败原因必须写明渠道不存在（用户据此去补建），实际：{orphan}"
    );

    let delivered = log_row(&ctx, &to_addrs[0], log_a).await;
    assert_eq!(
        delivered["retryCount"].as_i64(),
        Some(1),
        "同一批里渠道正常的行必须照常被认领并投递，实际：{delivered}"
    );
    assert_eq!(
        delivered["status"].as_str(),
        Some("2"),
        "死网关下仍失败、保持待重试（未达上限），实际：{delivered}"
    );
}

/// b144（B1）：渠道连通性测试必须拒绝"永不可用"的网关地址，同时**照常放行**内网网关。
///
/// 两侧都是判据，缺一半都不算证伪：
/// - 只测"元数据段被拒"，实现可以是"任何地址都拒"——那会把自托管形态砍掉
///   （AGENTS 项目定位），而集成测试自己用的 `http://127.0.0.1:{port}` 恰好是这一形态；
/// - 只测"内网被放"，实现可以是"任何地址都放"。
///
/// 第二个断面是这一批顺带修掉的形状错配：`test_channel` 的 sms 分支原先无条件按
/// `SmsChannelConfig`（通用网关形态，必含 `gateway_url`）解析，而云厂商渠道的配置里
/// 没有那个键 ⇒ **合法配置的阿里云/腾讯云渠道，"测试"按钮永远报"配置无效"**。
/// 现在按 `detect_provider_kind` 分流（与 `dispatch` 同一把尺），aliyun 合法配置必须 200。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_channel_test_guards_gateway_address_shape() {
    let ctx = TestContext::new().await;
    let created = ctx
        .post_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelName": "it_msg_b144_网关守卫",
                "channelCode": "it_msg_b144_guard",
                "channelType": "sms",
                "status": "0",
                "configJson": r#"{"gateway_url":"http://127.0.0.1:1/send"}"#
            }),
        )
        .await;
    ctx.assert_ok(&created);
    let channel_id = created["data"]["channelId"]
        .as_i64()
        .expect("channelId 应为数字");

    /// 写入一种配置形态并跑一次"渠道连通性测试"，返回状态码。
    /// 走 HTTP 而不是直插库：这一条链的交付形态就是"管理端点一下测试按钮"。
    async fn step(
        ctx: &TestContext,
        channel_id: i64,
        channel_type: &str,
        config_json: &str,
    ) -> (StatusCode, serde_json::Value) {
        let put = ctx
            .send_raw(raw_req(
                ctx,
                Method::PUT,
                "/system/msg/channel",
                Some(serde_json::json!({
                    "channelId": channel_id,
                    "channelName": "it_msg_b144_网关守卫",
                    "channelCode": "it_msg_b144_guard",
                    "channelType": channel_type,
                    "status": "0",
                    "configJson": config_json,
                })),
            ))
            .await;
        assert_eq!(
            put.0,
            StatusCode::OK,
            "写入测试配置本身必须成功（否则后面的断言判的是上一条配置）：{}",
            put.1
        );
        ctx.send_raw(raw_req(
            ctx,
            Method::POST,
            &format!("/system/msg/channel/test/{channel_id}"),
            Some(serde_json::json!({})),
        ))
        .await
    }

    let cases: [(&str, &str, &str, StatusCode); 8] = [
        (
            "generic 内网网关",
            "sms",
            r#"{"gateway_url":"http://127.0.0.1:1/send"}"#,
            StatusCode::OK,
        ),
        (
            "generic 元数据段",
            "sms",
            r#"{"gateway_url":"http://169.254.169.254/latest/meta-data/"}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "generic 非 http(s)",
            "sms",
            r#"{"gateway_url":"ftp://gw.example.com/send"}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "aliyun 合法配置",
            "sms",
            r#"{"provider":"aliyun","endpoint":"https://dysmsapi.aliyuncs.com","access_key_id":"AK","access_key_secret":"SK","sign_name":"签名"}"#,
            StatusCode::OK,
        ),
        (
            "aliyun endpoint 指向元数据段",
            "sms",
            r#"{"provider":"aliyun","endpoint":"http://169.254.169.254","access_key_id":"AK","access_key_secret":"SK","sign_name":"签名"}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "企微内网 webhook",
            "wecom_robot",
            r#"{"webhookUrl":"http://127.0.0.1:1/hook"}"#,
            StatusCode::OK,
        ),
        (
            "企微链路本地 webhook",
            "wecom_robot",
            r#"{"webhookUrl":"http://[fe80::1]/hook"}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "钉钉非 http(s) webhook",
            "dingtalk_robot",
            r#"{"webhookUrl":"ftp://oapi.dingtalk.com/robot/send","secret":"s"}"#,
            StatusCode::BAD_REQUEST,
        ),
    ];
    // 具体原因走日志（`tracing::warn!` 带渠道号），对外只给统一的"配置无效"——
    // 所以判据取状态码这一侧，不把文案当第二判据（那会让 i18n 改动误伤安全断言）。
    let mut verdicts = Vec::new();
    for (name, channel_type, config_json, expected) in cases {
        let (status, body) = step(&ctx, channel_id, channel_type, config_json).await;
        assert_eq!(
            status,
            expected,
            "『{name}』的渠道连通性测试结局应为 {}，实际 {status}：{body}",
            expected.as_u16()
        );
        verdicts.push((name, status.as_u16()));
    }
    // 采集面自证：8 条必须逐条真跑过，且拒绝侧确实出现过（防"循环空转/恒 200"洗成通过）
    assert_eq!(verdicts.len(), 8, "用例集必须完整执行：{verdicts:?}");
    assert_eq!(
        verdicts.iter().filter(|(_, code)| *code == 400).count(),
        5,
        "五个坏形状必须都落到 400：{verdicts:?}"
    );
    assert_eq!(
        verdicts.iter().filter(|(_, code)| *code == 200).count(),
        3,
        "三个合法形态（含自托管内网网关）必须都放行：{verdicts:?}"
    );
}
