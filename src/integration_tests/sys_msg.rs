// axum-backend/src/integration_tests/sys_msg.rs
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
    let v = ctx.get_json("/system/msg/channel/list?pageNum=1&pageSize=10").await;
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
        .send_raw(raw_req(&ctx, Method::DELETE, "/system/msg/channel/abc", None))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "非法 ID 应 400，实际: {status}");

    // 删除不存在的渠道 → 404
    let (status, _) = ctx
        .send_raw(
            raw_req(&ctx, Method::DELETE, "/system/msg/channel/999999", None),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "删除不存在应 404，实际: {status}");

    // 缺少渠道名（garde length min=1）→ 400
    let (status, _) = ctx
        .send_raw(
            raw_req(
                &ctx,
                Method::POST,
                "/system/msg/channel",
                Some(serde_json::json!({
                    "channelName": "",
                    "channelCode": "it_msg_bad",
                    "channelType": "sms"
                })),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "缺渠道名应 400，实际: {status}");

    // 批量删除超过上限（101 个 id > MAX_BATCH_DELETE_SIZE=100）→ 400
    let over = (1..=101).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let (status, _) = ctx
        .send_raw(
            raw_req(
                &ctx,
                Method::DELETE,
                &format!("/system/msg/channel/{}", over),
                None,
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "超批量上限应 400，实际: {status}");

    // 非法渠道类型 → 400
    let (status, _) = ctx
        .send_raw(
            raw_req(
                &ctx,
                Method::POST,
                "/system/msg/channel",
                Some(serde_json::json!({
                    "channelName": "it_msg_坏类型",
                    "channelCode": "it_msg_bad_type",
                    "channelType": "wechat"
                })),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "非法渠道类型应 400，实际: {status}");
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

    // sms 渠道无外部网关，连通性校验通过即 200
    let v = ctx
        .post_json(
            &format!("/system/msg/channel/test/{}", channel_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);

    // 测试不存在的渠道 → 404
    let (status, _) = ctx
        .send_raw(raw_req(&ctx, Method::POST, "/system/msg/channel/test/999999", Some(serde_json::json!({}))))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "测试不存在渠道应 404，实际: {status}");
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
    let v = ctx.get_json("/system/msg/template/list?pageNum=1&pageSize=10").await;
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
    let template_id = v["data"]["templateId"].as_i64().expect("templateId 应为数字");

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
    assert_eq!(status, StatusCode::NOT_FOUND, "删除后详情应 404，实际: {status}");

    // 8. 异常路径：非法 ID 删除 → 400
    let (status, _) = ctx
        .send_raw(raw_req(&ctx, Method::DELETE, "/system/msg/template/xyz", None))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "非法 ID 应 400，实际: {status}");

    // 9. 异常路径：删除不存在模板 → 404
    let (status, _) = ctx
        .send_raw(
            raw_req(&ctx, Method::DELETE, "/system/msg/template/999999", None),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "删除不存在模板应 404，实际: {status}");

    // 10. 异常路径：缺少模板内容（garde length min=1）→ 400
    let (status, _) = ctx
        .send_raw(
            raw_req(
                &ctx,
                Method::POST,
                "/system/msg/template",
                Some(serde_json::json!({
                    "templateName": "it_msg_缺内容",
                    "templateCode": "it_msg_tpl_no_content",
                    "templateSubject": "主题",
                    "templateContent": ""
                })),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "缺模板内容应 400，实际: {status}");
}

/// 发送记录生命周期：send → 查询日志 → retry → markPending → retryPending → clean → 删除单条 + 非法 ID 400。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_send_log_lifecycle() {
    let ctx = TestContext::new().await;

    // 前置：sm 渠道 + sms 模板
    let v = ctx
        .post_json(
            "/system/msg/channel",
            serde_json::json!({
                "channelName": "it_msg_日志渠道",
                "channelCode": "it_msg_log_ch",
                "channelType": "sms",
                "status": "0"
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
    let v = ctx.get_json("/system/msg/log/list?pageNum=1&pageSize=10").await;
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
        "sms 模拟投递应成功 status='0'，实际: {v}"
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
    assert_eq!(v["data"].as_u64(), Some(1), "retry 应返回处理条数，实际: {v}");

    // 5. 标记待重试 → status='2'
    let v = ctx
        .post_json(
            &format!("/system/msg/log/markPending/{}", log_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(v["data"].as_u64(), Some(1), "markPending 应返回标记条数，实际: {v}");

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
    let v = ctx.get_json("/system/msg/log/list?pageNum=1&pageSize=10").await;
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
    assert_eq!(status, StatusCode::BAD_REQUEST, "非法 ID 应 400，实际: {status}");

    // 11. 非法 ID 重试 → 400
    let (status, _) = ctx
        .send_raw(
            raw_req(
                &ctx,
                Method::POST,
                "/system/msg/log/retry/bad",
                Some(serde_json::json!({})),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "非法 ID 重试应 400，实际: {status}");
}