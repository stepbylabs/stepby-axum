// axum-backend/src/integration_tests/sys_web_hook.rs
//! WebHook 事件订阅模块链路集成测试（HTTP 端到端）：
//! - 分页列表 / 详情
//! - 新增 → 查询 → 修改 → 启停 → 手动测试推送 → 删除
//! - 推送记录（投递留痕）列表 / 详情
//! - 校验分支：空名称（400）/ SSRF 内网目标（400）/ 不存在 ID（404）
//!
//! 说明：新增回调的 target_url 会经过 SSRF 双层校验（静态 + DNS 解析），
//! 故选用可公开直连的 IP 字面量（8.8.8.8）作为目标，避免依赖真实域名解析；
//! 手动测试推送端口为关闭端口，投递必然失败但接口仍返回 code=200 的投递结果，
//! 且超时被限制在 2s 内，不会挂起。

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;

/// 构造带鉴权头 + Content-Type + ConnectInfo 的原始请求（用于非快乐路径断言）。
fn auth_json_request(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    body: serde_json::Value,
) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", ctx.token))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// WebHook 全链路（CRUD + 启停 + 手动测试推送 + 留痕 + 校验/异常路径）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_web_hook_chain() {
    let ctx = TestContext::new().await;

    // 1. 初始分页列表（种子为空也应为合法响应）
    let v = ctx
        .get_json("/monitor/webHook/list?pageNum=1&pageSize=10")
        .await;
    assert!(v["rows"].is_array(), "list rows 应为数组，实际: {v}");

    // 2. 新增回调（it_webhook_ 前缀避免与既有数据冲突；SSRF 友好公网 IP 字面量）
    let target = "http://8.8.8.8:59999/webhook";
    let v = ctx
        .post_json(
            "/monitor/webHook",
            serde_json::json!({
                "hookName": "it_webhook_集成测试回调",
                "eventTypes": "login_success",
                "targetUrl": target,
                "contentType": "json",
                "timeoutSecs": 2,
                "status": "0",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 3. 按名称模糊查询到新回调，取出 id
    let v = ctx
        .get_json("/monitor/webHook/list?hookName=it_webhook_")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条新回调，实际: {v}");
    let hook_id = rows[0]["id"].as_i64().expect("id 应为数字");
    assert_eq!(
        rows[0]["hookName"].as_str(),
        Some("it_webhook_集成测试回调")
    );
    assert_eq!(rows[0]["status"].as_str(), Some("0"), "初始状态应为启用 0");

    // 4. 详情
    let v = ctx.get_json(&format!("/monitor/webHook/{}", hook_id)).await;
    assert_eq!(v["data"]["id"], hook_id, "详情 id 应一致，实际: {v}");
    assert_eq!(v["data"]["targetUrl"].as_str(), Some(target));
    assert_eq!(v["data"]["contentType"].as_str(), Some("json"));

    // 5. 修改回调（改名 + 停用）
    let v = ctx
        .put_json(
            "/monitor/webHook",
            serde_json::json!({
                "id": hook_id,
                "hookName": "it_webhook_集成测试回调改",
                "eventTypes": "login_success,login_failure",
                "targetUrl": target,
                "contentType": "json",
                "timeoutSecs": 2,
                "status": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/monitor/webHook/{}", hook_id)).await;
    assert_eq!(
        v["data"]["hookName"].as_str(),
        Some("it_webhook_集成测试回调改"),
        "修改后的名称应生效，实际: {v}"
    );
    assert_eq!(v["data"]["status"].as_str(), Some("1"), "修改后应停用");

    // 6. 启停回调（重新启用）
    let v = ctx
        .put_json(
            &format!("/monitor/webHook/{}/status", hook_id),
            serde_json::json!({ "status": "0" }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/monitor/webHook/{}", hook_id)).await;
    assert_eq!(v["data"]["status"].as_str(), Some("0"), "启停后应为启用");

    // 7. 手动测试推送（目标端口关闭 → 投递失败，但接口仍返回 code=200 的投递结果，
    //    且被 timeoutSecs=2 限制在 2s 内返回，不挂起、不 panic）
    let v = ctx
        .post_json(
            &format!("/monitor/webHook/{}/test", hook_id),
            serde_json::json!({ "eventType": "login_success" }),
        )
        .await;
    ctx.assert_ok(&v);
    assert!(
        v["data"]["ok"].is_boolean(),
        "test 应返回布尔 ok，实际: {v}"
    );
    let log_id = v["data"]["logId"]
        .as_i64()
        .expect("test 应返回已落库的 logId");
    assert!(log_id > 0, "logId 应为正整数，实际: {v}");

    // 8. 推送记录列表（按 hookId 过滤应至少 1 条留痕）
    let v = ctx
        .get_json(&format!(
            "/monitor/webHook/log/list?hookId={}&pageSize=10",
            hook_id
        ))
        .await;
    let logs = v["rows"].as_array().expect("rows 应为数组");
    assert!(!logs.is_empty(), "测试推送应产生留痕，实际: {v}");

    // 9. 推送记录详情
    let v = ctx
        .get_json(&format!("/monitor/webHook/log/{}", log_id))
        .await;
    assert_eq!(v["data"]["id"], log_id, "留痕详情 id 应一致，实际: {v}");
    assert_eq!(v["data"]["eventType"].as_str(), Some("login_success"));

    // 10. 删除回调（逻辑删除 + 级联清理留痕）
    let v = ctx
        .delete_json(&format!("/monitor/webHook/{}", hook_id))
        .await;
    ctx.assert_ok(&v);

    // 11. 删除后：详情 404 + 列表查不到
    let (status, body) = ctx
        .send_raw(auth_json_request(
            &ctx,
            Method::GET,
            &format!("/monitor/webHook/{}", hook_id),
            serde_json::Value::Null,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除后详情应 404，实际: {status} {body}"
    );
    let v = ctx
        .get_json("/monitor/webHook/list?hookName=it_webhook_")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "删除后不应再查到该回调，实际: {v}");

    // 12. 校验分支：空 hookName → 400（garde 校验）
    let (status, body) = ctx
        .send_raw(auth_json_request(
            &ctx,
            Method::POST,
            "/monitor/webHook",
            serde_json::json!({
                "hookName": "",
                "eventTypes": "login_success",
                "targetUrl": target,
                "status": "0"
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "空名称新增应 400，实际: {status} {body}"
    );
    assert_eq!(body["code"], 400, "空名称业务码应为 400，实际: {body}");

    // 13. 校验分支：SSRF 内网目标 → 400（保存时拦截）
    let (status, body) = ctx
        .send_raw(auth_json_request(
            &ctx,
            Method::POST,
            "/monitor/webHook",
            serde_json::json!({
                "hookName": "it_webhook_ssrf",
                "eventTypes": "login_success",
                "targetUrl": "http://127.0.0.1/secret",
                "status": "0"
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "内网目标新增应被 SSRF 拦截返回 400，实际: {status} {body}"
    );
    assert_eq!(body["code"], 400, "SSRF 拦截业务码应为 400，实际: {body}");

    // 14. 异常路径：查询不存在的回调 → 404
    let (status, body) = ctx
        .send_raw(auth_json_request(
            &ctx,
            Method::GET,
            "/monitor/webHook/999999",
            serde_json::Value::Null,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "不存在的回调详情应 404，实际: {status} {body}"
    );
}
