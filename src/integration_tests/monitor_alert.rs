// stepby-axum/src/integration_tests/monitor_alert.rs
//! 告警引擎链路集成测试（b71 T1 补测：此前单测仅覆盖 `compare()` 比较器，
//! 集成层 0 覆盖、全靠 e2e F77 兜底）：
//! - 规则 CRUD 全链：add → list（名称过滤）→ detail → edit → changeEnabled → remove → 404
//! - 评估引擎：命中触发（`http_5xx_5m ge 0` 恒命中口径，断言确定性来源）→
//!   静默窗口抑制（立即二次评估 fired=false）→ `silentMinutes=0` 后重新可触发
//! - 参数校验：非法 metric / 非法 comparator → 400
//! - 平台专属守卫：租户操作者（tid=5 合成令牌，复用超管主体过 RBAC 层）→ 403
//!
//! 复用全局 `TestContext` harness（隔离 sqlite + 独占 Redis DB + 真实 `build_app` 路由栈）。

use std::net::SocketAddr;

use super::TestContext;
use crate::jwt::JwtUtils;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};

/// 租户操作者合成令牌（与 platform_guard.rs 同构：超管主体短路 RBAC，403 归因到守卫层）
fn token_with_tid(ctx: &TestContext, tid: i64) -> String {
    let (token, _claims) = JwtUtils::generate_token("1", "admin", &ctx.state.config.jwt, 0, tid)
        .expect("签发合成租户令牌失败");
    token
}

/// 带指定 Bearer 令牌的 JSON 请求（与 `TestContext::request` 同构）
fn auth_json(
    ctx: &TestContext,
    token: &str,
    method: Method,
    uri: &str,
    body: serde_json::Value,
) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// 新增恒命中规则（http_5xx_5m ≥ 0 恒真：进程内 5xx 计数下界为 0），返回规则 id。
async fn add_always_firing_rule(ctx: &TestContext, name: &str, silent_minutes: i32) -> i64 {
    let v = ctx
        .post_json(
            "/monitor/alert",
            serde_json::json!({
                "name": name,
                "metric": "http_5xx_5m",
                "comparator": "ge",
                "threshold": 0,
                "silentMinutes": silent_minutes,
                "enabled": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    v["data"]["id"].as_i64().expect("add 响应缺 data.id")
}

/// (1) CRUD 全链：add → list 过滤 → detail → edit → changeEnabled → remove → 404。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alert_rule_crud_chain() {
    let ctx = TestContext::new().await;
    let name = "it_alert_crud";

    // 1. 新增
    let id = add_always_firing_rule(&ctx, name, 30).await;

    // 2. list 按名称模糊过滤命中且字段回读一致
    let v = ctx
        .get_json("/monitor/alert/list?pageNum=1&pageSize=10&name=it_alert_crud")
        .await;
    ctx.assert_ok(&v);
    let rows = v["rows"].as_array().expect("list 响应缺 rows");
    assert!(
        rows.iter().any(|r| r["id"].as_i64() == Some(id)),
        "list 未包含新建规则 id={id}"
    );

    // 3. 详情回读
    let v = ctx.get_json(&format!("/monitor/alert/{id}")).await;
    ctx.assert_ok(&v);
    assert_eq!(v["data"]["name"].as_str(), Some(name));
    assert_eq!(v["data"]["metric"].as_str(), Some("http_5xx_5m"));
    assert_eq!(v["data"]["comparator"].as_str(), Some("ge"));
    assert_eq!(v["data"]["enabled"].as_str(), Some("1"));

    // 4. edit：改阈值与静默分钟数
    let v = ctx
        .put_json(
            "/monitor/alert",
            serde_json::json!({
                "id": id,
                "name": name,
                "metric": "http_5xx_5m",
                "comparator": "ge",
                "threshold": 5,
                "silentMinutes": 0,
                "enabled": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/monitor/alert/{id}")).await;
    ctx.assert_ok(&v);
    assert_eq!(v["data"]["threshold"].as_f64(), Some(5.0));
    assert_eq!(v["data"]["silentMinutes"].as_i64(), Some(0));

    // 5. changeEnabled 停用 → 启用往返
    let v = ctx
        .put_json(
            "/monitor/alert/changeEnabled",
            serde_json::json!({ "id": id, "enabled": "0" }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/monitor/alert/{id}")).await;
    ctx.assert_ok(&v);
    assert_eq!(v["data"]["enabled"].as_str(), Some("0"));
    let v = ctx
        .put_json(
            "/monitor/alert/changeEnabled",
            serde_json::json!({ "id": id, "enabled": "1" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 6. 删除 → 详情 404
    let v = ctx.delete_json(&format!("/monitor/alert/{id}")).await;
    ctx.assert_ok(&v);
    let (status, _v) = ctx
        .send_raw(auth_json(
            &ctx,
            &ctx.token,
            Method::GET,
            &format!("/monitor/alert/{id}"),
            serde_json::json!(null),
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "删除后详情应 404");
}

/// (2) 评估引擎：恒命中规则触发 → 静默窗口抑制 → silentMinutes=0 重新触发。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alert_evaluate_fire_and_silence_window() {
    let ctx = TestContext::new().await;
    let id = add_always_firing_rule(&ctx, "it_alert_silence", 30).await;

    // 1. 首次评估：http_5xx_5m ge 0 恒命中 → fired=true
    let v = ctx
        .post_json(
            &format!("/monitor/alert/{id}/evaluate"),
            serde_json::json!(null),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["fired"].as_bool(),
        Some(true),
        "恒命中规则首次评估应触发：{v}"
    );
    assert!(v["data"]["metricValue"].as_f64().is_some());

    // 2. 立即二次评估：静默期（silentMinutes=30）内抢占失败 → fired=false
    let v = ctx
        .post_json(
            &format!("/monitor/alert/{id}/evaluate"),
            serde_json::json!(null),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["fired"].as_bool(),
        Some(false),
        "静默期内二次评估应被抑制：{v}"
    );

    // 3. edit 置 silentMinutes=0 → 第三次评估重新可触发
    let v = ctx
        .put_json(
            "/monitor/alert",
            serde_json::json!({
                "id": id,
                "name": "it_alert_silence",
                "metric": "http_5xx_5m",
                "comparator": "ge",
                "threshold": 0,
                "silentMinutes": 0,
                "enabled": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .post_json(
            &format!("/monitor/alert/{id}/evaluate"),
            serde_json::json!(null),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["fired"].as_bool(),
        Some(true),
        "silentMinutes=0 后评估应重新触发：{v}"
    );

    // 清尾：删除规则（有状态用例尾部恢复初态）
    let v = ctx.delete_json(&format!("/monitor/alert/{id}")).await;
    ctx.assert_ok(&v);
}

/// (3) 参数校验：非法 metric / 非法 comparator → 400。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alert_add_validates_metric_and_comparator() {
    let ctx = TestContext::new().await;

    let (status, _v) = ctx
        .send_raw(auth_json(
            &ctx,
            &ctx.token,
            Method::POST,
            "/monitor/alert",
            serde_json::json!({
                "name": "it_alert_bad_metric",
                "metric": "not_a_metric",
                "comparator": "ge",
                "threshold": 0
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "非法 metric 应 400");

    let (status, _v) = ctx
        .send_raw(auth_json(
            &ctx,
            &ctx.token,
            Method::POST,
            "/monitor/alert",
            serde_json::json!({
                "name": "it_alert_bad_cmp",
                "metric": "http_5xx_5m",
                "comparator": "eq",
                "threshold": 0
            }),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "非法 comparator 应 400");
}

/// (4) 平台专属守卫：租户操作者（tid=5）→ 403（精确归因 platform_only_guard）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alert_tenant_operator_forbidden() {
    let ctx = TestContext::new().await;
    let tenant_token = token_with_tid(&ctx, 5);

    let (status, _v) = ctx
        .send_raw(auth_json(
            &ctx,
            &tenant_token,
            Method::GET,
            "/monitor/alert/list?pageNum=1&pageSize=10",
            serde_json::json!(null),
        ))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "租户操作者访问告警面应 403");

    let (status, _v) = ctx
        .send_raw(auth_json(
            &ctx,
            &tenant_token,
            Method::POST,
            "/monitor/alert",
            serde_json::json!({
                "name": "it_alert_tenant",
                "metric": "http_5xx_5m",
                "comparator": "ge",
                "threshold": 0
            }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "租户操作者新增告警规则应 403"
    );
}
