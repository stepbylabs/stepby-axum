// backend-axum/src/integration_tests/sys_oper_log.rs
//! 操作日志模块链路集成测试：
//! - 分页列表 + 审计大屏统计（stats / stats-by-type / alarm-status）
//! - 批量删除（正常 + 非法 id 400）
//! - 清空（clean）
//! - 导出（export，Excel 二进制）
//!
//! 数据说明：
//! - 迁移种子无操作日志。本测试通过一次写操作（admin 新增通知 POST /system/notice）触发
//!   oper_log 中间件异步写入日志，再轮询列表等待其落库（写为 tokio::spawn，非同步返回）。
//! - admin 是超管（`*:*:*`），所有受保护端点均可访问，无需权限头。

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;
use std::time::Duration;

use super::TestContext;
use tower::ServiceExt;

/// 轮询 /monitor/operlog/list 直到出现指定 operUrl 的日志，返回其 operId。
///
/// oper_log 由中间件 tokio::spawn 异步写入，需轮询等待以免竞态。
async fn wait_operlog_by_url(ctx: &TestContext, expected_url: &str) -> i64 {
    for _ in 0..50 {
        let v = ctx
            .get_json("/monitor/operlog/list?pageNum=1&pageSize=50")
            .await;
        if let Some(rows) = v["rows"].as_array()
            && let Some(r) = rows
                .iter()
                .find(|r| r["operUrl"].as_str() == Some(expected_url))
        {
            return r["operId"].as_i64().expect("operId 应为数字，实际: {r}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("oper_log 记录未在超时内出现（operUrl={expected_url}）");
}

/// 通过一次写操作（admin 新增通知）触发一条操作日志写入，并轮询等待其落库。
/// 返回新落库的 operId。
async fn create_oper_log(ctx: &TestContext) -> i64 {
    let v = ctx
        .post_json(
            "/system/notice",
            serde_json::json!({
                "noticeTitle": "it_opl_集成测试操作",
                "noticeType": "1",
                "noticeContent": "it_opl 内容",
                "status": "0",
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    wait_operlog_by_url(ctx, "/system/notice").await
}

/// 操作日志列表分页 + 审计大屏三个统计端点。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_opl_list_and_stats() {
    let ctx = TestContext::new().await;
    create_oper_log(&ctx).await;

    // 1. 分页列表：应包含刚写入的 it_opl 操作日志（operName=admin）
    let v = ctx
        .get_json("/monitor/operlog/list?pageNum=1&pageSize=20")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组，实际: {v}");
    assert!(
        v["total"].as_u64().unwrap_or(0) >= 1,
        "total 应 >= 1，实际: {v}"
    );
    let admin_row = rows
        .iter()
        .find(|r| r["operName"].as_str() == Some("admin"))
        .expect("操作日志应包含 admin 的记录，实际: {v}");
    assert!(
        admin_row["operUrl"].is_string() && admin_row["title"].is_string(),
        "操作日志行应含 operUrl/title，实际: {v}"
    );

    // 2. /monitor/operlog/stats：审计大屏综合统计
    let v = ctx.get_json("/monitor/operlog/stats?days=7").await;
    let data = &v["data"];
    assert!(
        data["summary"]["total"].as_i64().unwrap_or(0) >= 1,
        "summary.total 应 >= 1，实际: {v}"
    );
    assert!(
        data["businessTypes"].is_array() && data["topOperators"].is_array(),
        "businessTypes/topOperators 应为数组，实际: {v}"
    );
    assert!(
        data["topOperators"]
            .as_array()
            .is_some_and(|a| a.iter().any(|o| o["operName"].as_str() == Some("admin"))),
        "top_operators 应包含 admin，实际: {v}"
    );
    assert!(
        data["topModules"].is_array() && data["daily"].is_array(),
        "topModules/daily 应为数组，实际: {v}"
    );

    // 3. /monitor/operlog/stats-by-type：业务类型分布（insert/update/delete/other 四桶）
    let v = ctx.get_json("/monitor/operlog/stats-by-type").await;
    for key in ["insert", "update", "delete", "other"] {
        assert!(
            v["data"][key].is_number(),
            "stats-by-type 应含 {key} 字段，实际: {v}"
        );
    }
    assert!(
        v["data"]["insert"].as_i64().unwrap_or(0)
            + v["data"]["update"].as_i64().unwrap_or(0)
            + v["data"]["delete"].as_i64().unwrap_or(0)
            + v["data"]["other"].as_i64().unwrap_or(0)
            >= 1,
        "业务类型分布总数应 >= 1，实际: {v}"
    );

    // 4. /monitor/operlog/alarm-status：异常告警状态（结构断言，容忍任一告警结果）
    let v = ctx.get_json("/monitor/operlog/alarm-status").await;
    let data = &v["data"];
    assert!(
        data["config"]["windowMinutes"].is_number()
            && data["config"]["failThreshold"].is_number()
            && data["config"]["failRateThreshold"].is_number(),
        "alarm-status config 应含窗口/阈值配置，实际: {v}"
    );
    assert!(
        data["totalInWindow"].is_number()
            && data["failInWindow"].is_number()
            && data["failRate"].is_number()
            && data["alertTriggered"].is_boolean(),
        "alarm-status 应含统计与告警标记，实际: {v}"
    );
    assert!(
        data["operatorBursts"].is_array() && data["moduleBursts"].is_array(),
        "alarm-status 应含 burst 数组，实际: {v}"
    );
}

/// 轮询直到出现指定 operUrl 且指定 businessType 的日志行，返回该行 JSON。
/// business_type：1=新增 2=修改 3=删除。
async fn wait_operlog_row(
    ctx: &TestContext,
    expected_url: &str,
    business_type: i64,
) -> serde_json::Value {
    for _ in 0..50 {
        let v = ctx
            .get_json("/monitor/operlog/list?pageNum=1&pageSize=50")
            .await;
        if let Some(rows) = v["rows"].as_array()
            && let Some(r) = rows.iter().find(|r| {
                r["operUrl"].as_str() == Some(expected_url)
                    && r["businessType"].as_i64() == Some(business_type)
            })
        {
            return r.clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("oper_log 记录未在超时内出现（operUrl={expected_url}, businessType={business_type}）");
}

/// Tier-S #2：PUT 成功后中间件应写入变更前快照（operBefore）与字段级差异（operDiff）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_opl_field_level_diff() {
    let ctx = TestContext::new().await;

    // 1. 新增一条通知（唯一标题），从列表取回其 noticeId
    let title = "it_opldiff_原始标题";
    let v = ctx
        .post_json(
            "/system/notice",
            serde_json::json!({
                "noticeTitle": title,
                "noticeType": "1",
                "noticeContent": "原始内容",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let list = ctx
        .get_json("/system/notice/list?pageNum=1&pageSize=50")
        .await;
    let notice_id = list["rows"]
        .as_array()
        .expect("rows 应为数组")
        .iter()
        .find(|r| r["noticeTitle"].as_str() == Some(title))
        .and_then(|r| r["noticeId"].as_i64())
        .expect("应能找到刚新增的通知 noticeId");

    // 2. PUT 修改标题与内容 → 触发 oper_log 中间件计算字段级 diff
    let v = ctx
        .put_json(
            "/system/notice",
            serde_json::json!({
                "noticeId": notice_id,
                "noticeTitle": "it_opldiff_已改标题",
                "noticeType": "1",
                "noticeContent": "修改后的内容",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 3. 轮询到该 PUT 修改类操作日志行（businessType=2）
    let row = wait_operlog_row(&ctx, "/system/notice", 2).await;

    // 4. 变更前快照应存在且为合法 JSON 对象字符串
    let before = row["operBefore"].as_str().unwrap_or("");
    assert!(
        !before.is_empty() && before.contains(title),
        "operBefore 应包含变更前标题，实际: {row}"
    );

    // 5. 字段级差异应存在、为合法 JSON 数组、包含被改字段（noticeTitle/noticeContent），
    //    且每条目含 field/old/new 且 old != new
    let diff_str = row["operDiff"].as_str().unwrap_or("");
    assert!(
        !diff_str.is_empty(),
        "PUT 成功修改应写入 operDiff，实际行: {row}"
    );
    let diffs: serde_json::Value = serde_json::from_str(diff_str).expect("operDiff 应为合法 JSON");
    let arr = diffs.as_array().expect("operDiff 应为数组");
    assert!(!arr.is_empty(), "operDiff 数组不应为空");
    let fields: Vec<&str> = arr.iter().filter_map(|d| d["field"].as_str()).collect();
    assert!(
        fields.iter().any(|f| f.ends_with("oticeTitle")),
        "operDiff 应含标题字段变更，实际: {diff_str}"
    );
    for d in arr.iter() {
        assert_ne!(
            d["old"], d["new"],
            "operDiff 每条 old 应不等于 new，实际: {d}"
        );
    }
}

/// 操作日志批量删除（正常 + 非法 id）+ 清空 + 导出。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_opl_delete_clean_export() {
    let ctx = TestContext::new().await;
    let oper_id = create_oper_log(&ctx).await;

    // 1. 批量删除：正常 id → 200
    let v = ctx
        .delete_json(&format!("/monitor/operlog/{}", oper_id))
        .await;
    ctx.assert_ok(&v);

    // 删除后再查，该 id 不应存在（物理删除）
    let v = ctx
        .get_json("/monitor/operlog/list?pageNum=1&pageSize=50")
        .await;
    assert!(
        !v["rows"]
            .as_array()
            .expect("rows 数组")
            .iter()
            .any(|r| r["operId"].as_i64() == Some(oper_id)),
        "删除后不应再查到该操作日志，实际: {v}"
    );

    // 2. 批量删除：非法 id（非数字）→ 400
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/monitor/operlog/abc", None))
        .await;
    assert_ne!(v["code"], 200, "非法 id 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 id 应返回 400，实际: {status}"
    );

    // 3. 清空（clean）：返回受影响条数，业务码 200
    let v = ctx.delete_json("/monitor/operlog/clean").await;
    ctx.assert_ok(&v);
    assert!(
        v["data"]["affected"].is_number(),
        "clean 应返回 affected 数字，实际: {v}"
    );

    // 4. 导出（export，POST x-www-form-urlencoded）→ HTTP 200 + Excel content-type
    let mut req = Request::builder()
        .method("POST")
        .uri("/monitor/operlog/export")
        .header("authorization", format!("Bearer {}", ctx.token))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(String::new()))
        .expect("构造导出请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let resp = ctx
        .app
        .clone()
        .oneshot(req)
        .await
        .expect("导出请求执行失败");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "导出应返回 200，实际: {}",
        resp.status()
    );
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("spreadsheetml"),
        "导出应返回 Excel content-type，实际: {content_type}"
    );
}
