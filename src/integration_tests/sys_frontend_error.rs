// backend-axum/src/integration_tests/sys_frontend_error.rs
//! 前端异常与性能监控模块链路集成测试（HTTP 端到端，Tier-S #1）：
//! - 批量上报（异常 + Web Vitals 指标混批）
//! - 分页列表（按名称模糊 / 按来源过滤）
//! - 详情查询
//! - 概览统计（来源分布 + 每日趋势）
//! - 字段归一化（非法 level/source 归一为 info/other）
//! - 删除（批量）+ 清空（按过去时间范围，删 0 条不污染既有数据）
//! - 异常路径：未登录上报 → 401

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;

/// 不带鉴权头的 JSON 请求（用于 401 断言）。
fn anonymous_json_request(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    body: serde_json::Value,
) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// 带鉴权头的 JSON 请求（用于 404 等非快乐路径但需登录态的断言）。
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_frontend_error_chain() {
    let ctx = TestContext::new().await;

    // 1. 批量上报：一条 Vue error、一条资源 warning、一条 Web Vitals(info)。
    //    名称统一 it_fe_ 前缀，便于后续模糊过滤且不与既有数据冲突。
    let v = ctx
        .post_json(
            "/monitor/frontendError/report",
            serde_json::json!({
                "items": [
                    {
                        "level": "error",
                        "source": "vue",
                        "name": "it_fe_TypeError",
                        "message": "it_fe_测试异常",
                        "stack": "at Foo.vue:10:1",
                        "pageUrl": "/monitor/frontendError",
                        "userAgent": "itest-ua",
                        "viewWidth": 1280,
                        "viewHeight": 800
                    },
                    {
                        "level": "warning",
                        "source": "resource",
                        "name": "it_fe_img_load",
                        "message": "it_fe_资源加载失败"
                    },
                    {
                        "level": "info",
                        "source": "vital",
                        "name": "it_fe_LCP",
                        "value": 2.34
                    }
                ]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["reported"].as_i64(),
        Some(3),
        "应上报落库 3 条，实际: {v}"
    );

    // 2. 列表（名称模糊 it_fe_）：应查到全部 3 条
    let v = ctx
        .get_json("/monitor/frontendError/list?name=it_fe_&pageSize=50")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 3, "应查到 3 条 it_fe_ 记录，实际: {v}");

    // 3. 校验 error 行：level/source/stack/value
    let err = rows
        .iter()
        .find(|r| r["source"] == "vue")
        .expect("应存在 vue 来源记录");
    assert_eq!(err["level"], "error");
    assert_eq!(err["name"], "it_fe_TypeError");
    assert_eq!(err["stack"], "at Foo.vue:10:1");
    assert!(err["value"].is_null(), "error 行 value 应为 null");
    // create_time 必须由服务端在批量落库时写入（insert_many 不触发 before_save），
    // 否则按天聚合统计会把记录漏掉。
    assert!(
        err["createTime"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "落库记录 create_time 不应为空，实际: {err}"
    );
    let err_id = err["id"].as_i64().expect("id 应为数字");

    // 4. 校验 vital 行：level=info、value 有值
    let vital = rows
        .iter()
        .find(|r| r["source"] == "vital")
        .expect("应存在 vital 来源记录");
    assert_eq!(vital["level"], "info");
    assert_eq!(vital["value"].as_f64(), Some(2.34));

    // 5. 详情
    let v = ctx
        .get_json(&format!("/monitor/frontendError/{}", err_id))
        .await;
    assert_eq!(v["data"]["id"], err_id, "详情 id 应一致，实际: {v}");

    // 6. 概览统计：来源分布非空，每日趋势长度 == days
    let v = ctx.get_json("/monitor/frontendError/stats?days=7").await;
    ctx.assert_ok(&v);
    assert!(
        v["data"]["bySource"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "bySource 应非空，实际: {v}"
    );
    assert_eq!(
        v["data"]["daily"].as_array().map(|a| a.len()).unwrap_or(0),
        7,
        "daily 长度应为 7，实际: {v}"
    );
    // 今天已上报 1 条 error，每日趋势中今天应 >=1（校验 create_time 与按天聚合链路真正打通）。
    // 时钟口径：后端 now_naive()/today_utc() 统一以 UTC 为准（create_time 落 UTC、按天聚合按 UTC），
    // 故此处必须用 Utc 而非 Local，否则本地跨零点（UTC+8 的凌晨）会让「今日」桶漂移到昨天。
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let today_count = v["data"]["daily"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|d| d["date"].as_str() == Some(today.as_str()))
                .and_then(|d| d["count"].as_i64())
        })
        .unwrap_or(-1);
    assert!(
        today_count >= 1,
        "今日 error 数应 >=1（create_time 落库+按天聚合生效），实际: {today_count}，{v}"
    );

    // 7. 字段归一化：非法 level=critical / source=bogus → 归一为 info / other
    ctx.post_json(
        "/monitor/frontendError/report",
        serde_json::json!({
            "items": [
                { "level": "CRITICAL", "source": "not-a-real-source", "name": "it_fe_norm" }
            ]
        }),
    )
    .await;
    let v = ctx
        .get_json("/monitor/frontendError/list?name=it_fe_norm")
        .await;
    let norm = v["rows"]
        .as_array()
        .and_then(|a| a.first())
        .expect("归一化记录应可查到");
    assert_eq!(norm["level"], "info", "非法 level 应归一为 info");
    assert_eq!(norm["source"], "other", "非法 source 应归一为 other");
    let norm_id = norm["id"].as_i64().unwrap();

    // 8. 批量删除上两步产生的记录（err_id + norm_id）
    let v = ctx
        .delete_json(&format!("/monitor/frontendError/{},{}", err_id, norm_id))
        .await;
    ctx.assert_ok(&v);

    // 9. 删除后详情 404（带 token 的原始请求，绕开 get_json 的 code==200 断言）
    let (status, body) = ctx
        .send_raw(auth_json_request(
            &ctx,
            Method::GET,
            &format!("/monitor/frontendError/{}", err_id),
            serde_json::Value::Null,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除后详情应 404，实际: {status} {body}"
    );

    // 10. 清空（过去时间范围，删 0 条，不污染其它数据）
    let v = ctx
        .delete_json("/monitor/frontendError/clean?beginTime=2000-01-01&endTime=2000-01-02")
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["affected"].as_i64(),
        Some(0),
        "过去范围清理应删 0 条，实际: {v}"
    );

    // 11. 未登录上报 → 401
    let (status, _body) = ctx
        .send_raw(anonymous_json_request(
            &ctx,
            Method::POST,
            "/monitor/frontendError/report",
            serde_json::json!({ "items": [{ "level": "error", "source": "vue" }] }),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "未登录上报应 401，实际: {status} {_body}"
    );
}
