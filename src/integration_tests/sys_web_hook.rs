// stepby-axum/src/integration_tests/sys_web_hook.rs
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

/// WebHook 出参脱敏 + 密钥写入语义（安全回归锁）。
///
/// 可证伪性：
/// - 修复前 `list` / `{id}` **直出实体**，JSON 会带 `secret` 原文 ⇒ 本测试的
///   `get("secret").is_none()` 断言失败（这是"任何持有 list 权限者都能读到签名
///   密钥并伪造第三方回调"的真实漏洞）；
/// - 修复前 `edit` 用 `Set(None)` 无条件覆盖 ⇒ 第 4 步「不传 secret」后
///   `hasSecret` 会由 true 变 false（静默清空密钥），断言失败。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_web_hook_secret_masked_and_preserved_on_edit() {
    let ctx = TestContext::new().await;
    let target = "http://8.8.8.8:59998/webhook";

    // 1. 新增：带签名密钥
    let v = ctx
        .post_json(
            "/monitor/webHook",
            serde_json::json!({
                "hookName": "it_webhook_secret_脱敏",
                "eventTypes": "login_success",
                "targetUrl": target,
                "secret": "it-secret-value-001",
                "contentType": "json",
                "timeoutSecs": 2,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 2. 列表：不含 secret / tenantId / delFlag，且 hasSecret = true
    let v = ctx
        .get_json("/monitor/webHook/list?hookName=it_webhook_secret_")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条，实际: {v}");
    let row = &rows[0];
    assert!(
        row.get("secret").is_none(),
        "列表禁止回传 secret，实际: {v}"
    );
    assert!(
        row.get("tenantId").is_none(),
        "列表禁止回传 tenantId，实际: {v}"
    );
    assert!(
        row.get("delFlag").is_none(),
        "列表禁止回传 delFlag，实际: {v}"
    );
    assert_eq!(
        row["hasSecret"],
        serde_json::json!(true),
        "已配置密钥时 hasSecret 应为 true，实际: {v}"
    );
    let hook_id = row["id"].as_i64().expect("id 应为数字");

    // 3. 详情：同样脱敏
    let v = ctx.get_json(&format!("/monitor/webHook/{}", hook_id)).await;
    assert!(
        v["data"].get("secret").is_none(),
        "详情禁止回传 secret，实际: {v}"
    );
    assert!(
        v["data"].get("tenantId").is_none(),
        "详情禁止回传 tenantId，实际: {v}"
    );
    assert_eq!(
        v["data"]["hasSecret"],
        serde_json::json!(true),
        "详情 hasSecret 应为 true，实际: {v}"
    );

    // 4. 修改时**不传 secret**（只改名称）→ 已配置的密钥必须保留
    let v = ctx
        .put_json(
            "/monitor/webHook",
            serde_json::json!({
                "id": hook_id,
                "hookName": "it_webhook_secret_脱敏改",
                "eventTypes": "login_success",
                "targetUrl": target,
                "contentType": "json",
                "timeoutSecs": 2,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/monitor/webHook/{}", hook_id)).await;
    assert_eq!(
        v["data"]["hookName"].as_str(),
        Some("it_webhook_secret_脱敏改"),
        "改名应生效，实际: {v}"
    );
    assert_eq!(
        v["data"]["hasSecret"],
        serde_json::json!(true),
        "编辑时留空 secret 必须保持原密钥（不得静默清空），实际: {v}"
    );

    // 5. 修改时传**空串** → 同为「不改变」语义
    let v = ctx
        .put_json(
            "/monitor/webHook",
            serde_json::json!({
                "id": hook_id,
                "hookName": "it_webhook_secret_脱敏改",
                "eventTypes": "login_success",
                "targetUrl": target,
                "secret": "",
                "contentType": "json",
                "timeoutSecs": 2,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/monitor/webHook/{}", hook_id)).await;
    assert_eq!(
        v["data"]["hasSecret"],
        serde_json::json!(true),
        "空串 secret 应视为不改变，实际: {v}"
    );

    // 6. 修改时传**新密钥** → 覆盖生效（仍为已配置态）
    let v = ctx
        .put_json(
            "/monitor/webHook",
            serde_json::json!({
                "id": hook_id,
                "hookName": "it_webhook_secret_脱敏改",
                "eventTypes": "login_success",
                "targetUrl": target,
                "secret": "it-secret-value-002",
                "contentType": "json",
                "timeoutSecs": 2,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/monitor/webHook/{}", hook_id)).await;
    assert_eq!(
        v["data"]["hasSecret"],
        serde_json::json!(true),
        "覆盖新密钥后仍应为已配置态，实际: {v}"
    );

    // 7. 新增：不带 secret → hasSecret = false
    let v = ctx
        .post_json(
            "/monitor/webHook",
            serde_json::json!({
                "hookName": "it_webhook_secret_无密钥",
                "eventTypes": "",
                "targetUrl": target,
                "contentType": "json",
                "timeoutSecs": 2,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/monitor/webHook/list?hookName=it_webhook_secret_无密钥")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条无密钥回调，实际: {v}");
    assert_eq!(
        rows[0]["hasSecret"],
        serde_json::json!(false),
        "未配置密钥时 hasSecret 应为 false，实际: {v}"
    );
    let hook_id_no_secret = rows[0]["id"].as_i64().expect("id 应为数字");

    // 清理，避免污染同库其它用例
    ctx.delete_json(&format!("/monitor/webHook/{}", hook_id))
        .await;
    ctx.delete_json(&format!("/monitor/webHook/{}", hook_id_no_secret))
        .await;
}

/// 事件目录停用/启用链路（m20261004_000002_webhook_event_edit）：
/// 停用 → 目录 enabled=0 生效 → 新订阅与测试发送被拒绝 → 启用恢复订阅可用。
/// 语义边界（存量 hook 不中断）不在此验证（派发链不查目录，属服务内部路径）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webhook_event_enabled_chain() {
    let ctx = TestContext::new().await;
    let target = "http://8.8.8.8:59999/webhook";
    let catalog_key = "user.created"; // 种子事件（WEBHOOK_SEED_EVENTS 首个）

    // 1. 目录列表应含种子事件且 enabled='1'
    let v = ctx
        .get_json("/system/webhook/event/list?pageNum=1&pageSize=50")
        .await;
    ctx.assert_ok(&v);
    let rows = v["rows"].as_array().expect("事件目录 rows 应为数组");
    assert!(!rows.is_empty(), "种子事件目录不应为空");
    let event = rows
        .iter()
        .find(|r| r["eventKey"] == catalog_key)
        .expect("目录应含 user.created 种子事件")
        .clone();
    let event_id = event["id"].as_i64().expect("事件 id 应为数字");
    assert_eq!(
        event["enabled"],
        serde_json::json!("1"),
        "种子事件默认启用，实际: {event}"
    );

    // 2. 停用事件 → 目录查询确认 enabled='0'
    let v = ctx
        .put_json(
            &format!("/system/webhook/event/{}/enabled", event_id),
            serde_json::json!({ "enabled": "0" }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!(
            "/system/webhook/event/list?eventKey={}&enabled=0",
            catalog_key
        ))
        .await;
    ctx.assert_ok(&v);
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "停用过滤应命中该事件，实际: {v}");

    // 3. 新订阅被拒绝：subscribedEvents 含停用事件 → 400
    let (status, body) = ctx
        .send_raw(auth_json_request(
            &ctx,
            Method::POST,
            "/monitor/webHook",
            serde_json::json!({
                "hookName": "it_webhook_订阅停用事件",
                "subscribedEvents": [catalog_key],
                "targetUrl": target,
                "contentType": "json",
                "timeoutSecs": 2,
                "status": "0"
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "订阅停用事件应被拒绝（事件键不在目录口径），实际: {status} {body}"
    );
    assert_eq!(
        body["code"], 400,
        "订阅停用事件业务码应为 400，实际: {body}"
    );

    // 4. 测试发送被拒绝：对停用事件 test-send → 400
    //    先建一个订阅其它事件的 hook 作为载体
    let v = ctx
        .post_json(
            "/monitor/webHook",
            serde_json::json!({
                "hookName": "it_webhook_停用测试载体",
                "subscribedEvents": ["login.failed"],
                "targetUrl": target,
                "contentType": "json",
                "timeoutSecs": 2,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/monitor/webHook/list?hookName=it_webhook_停用测试载体")
        .await;
    let carrier_id = v["rows"][0]["id"].as_i64().expect("载体 hook id 应为数字");
    let (status, body) = ctx
        .send_raw(auth_json_request(
            &ctx,
            Method::POST,
            &format!("/system/webhook/{}/test-send", carrier_id),
            serde_json::json!({ "eventKey": catalog_key }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "停用事件测试发送应被拒绝，实际: {status} {body}"
    );
    assert_eq!(
        body["code"], 400,
        "停用事件测试发送业务码应为 400，实际: {body}"
    );

    // 5. 启用恢复 → 订阅该事件成功
    let v = ctx
        .put_json(
            &format!("/system/webhook/event/{}/enabled", event_id),
            serde_json::json!({ "enabled": "1" }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .post_json(
            "/monitor/webHook",
            serde_json::json!({
                "hookName": "it_webhook_订阅恢复事件",
                "subscribedEvents": [catalog_key],
                "targetUrl": target,
                "contentType": "json",
                "timeoutSecs": 2,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 6. 校验分支：非法 enabled 值 → 400；不存在的事件 id → 404（not_found）
    let (status, body) = ctx
        .send_raw(auth_json_request(
            &ctx,
            Method::PUT,
            &format!("/system/webhook/event/{}/enabled", event_id),
            serde_json::json!({ "enabled": "x" }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 enabled 取值应被拒绝，实际: {status} {body}"
    );
    assert_eq!(
        body["code"], 400,
        "非法 enabled 业务码应为 400，实际: {body}"
    );
    let (status, body) = ctx
        .send_raw(auth_json_request(
            &ctx,
            Method::PUT,
            "/system/webhook/event/999999999/enabled",
            serde_json::json!({ "enabled": "1" }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "不存在的事件应 404，实际: {status} {body}"
    );
    assert_eq!(
        body["code"], 404,
        "不存在的事件业务码应为 404，实际: {body}"
    );

    // 清理
    let v = ctx
        .get_json("/monitor/webHook/list?hookName=it_webhook_停用测试载体")
        .await;
    for row in v["rows"].as_array().unwrap() {
        ctx.delete_json(&format!("/monitor/webHook/{}", row["id"]))
            .await;
    }
    let v = ctx
        .get_json("/monitor/webHook/list?hookName=it_webhook_订阅恢复事件")
        .await;
    for row in v["rows"].as_array().unwrap() {
        ctx.delete_json(&format!("/monitor/webHook/{}", row["id"]))
            .await;
    }
    ctx.delete_json(&format!("/monitor/webHook/{}", carrier_id))
        .await;
}
