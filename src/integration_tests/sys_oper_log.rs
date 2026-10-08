// stepby-axum/src/integration_tests/sys_oper_log.rs
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

/// 批次十九链感知保留黄金路径：真链写入 → service 层锚点编排部分清理 →
/// verify-chain 经锚点续接仍 valid（旧"链首起验"逻辑在此场景必报 broken）→
/// keep 模式空转 → stats 窗口排除窗口外数据。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_opl_chain_anchor_retention() {
    use sea_orm::ColumnTrait;
    use sea_orm::EntityTrait;
    use sea_orm::QueryFilter;

    let ctx = TestContext::new().await;
    // 1. 真链写入两条（中间件 spawn 异步写，chain_hash 由写侧 HMAC 计算）
    let id1 = create_oper_log(&ctx).await;
    let id2 = create_oper_log(&ctx).await;
    assert!(id1 < id2, "两次写入 oper_id 应递增");

    // 2. 直查两条的 oper_time，取中点作清理切点（切走第一条、保留第二条）
    let rows = crate::entity::sys_oper_log::Entity::find()
        .all(&ctx.state.db)
        .await
        .expect("直查 oper_log");
    let t1 = rows
        .iter()
        .find(|r| r.oper_id == id1)
        .map(|r| r.oper_time)
        .flatten()
        .expect("id1 行应存在");
    let t2 = rows
        .iter()
        .find(|r| r.oper_id == id2)
        .map(|r| r.oper_time)
        .flatten()
        .expect("id2 行应存在");
    let cutoff = t1 + (t2 - t1) / 2;

    // 3. keep 模式空转：不应删除任何行
    let affected = ctx
        .state
        .oper_log_service
        .cleanup_before(cutoff, crate::config::settings::LogRetentionMode::Keep, None)
        .await
        .expect("keep 模式应成功");
    assert_eq!(affected, 0, "keep 模式不应删除任何行");

    // 4. delete 模式部分清理：删除切点前的行（含真链节点）→ 锚点登记
    let affected = ctx
        .state
        .oper_log_service
        .cleanup_before(
            cutoff,
            crate::config::settings::LogRetentionMode::Delete,
            None,
        )
        .await
        .expect("delete 模式应成功");
    assert!(affected >= 1, "部分清理应至少删除 1 行，实际: {affected}");

    // 锚点应恰好登记 1 行（一次清理一个区间）
    let anchors = crate::entity::sys_log_archive_anchor::Entity::find()
        .all(&ctx.state.db)
        .await
        .expect("直查锚点表");
    assert_eq!(anchors.len(), 1, "应登记恰好 1 条锚点，实际: {anchors:?}");
    assert!(
        anchors[0].last_chain_hash.len() == 64,
        "锚点应记录被删尾行 chain_hash（64 hex），实际: {anchors:?}"
    );

    // 5. verify-chain 黄金断言：幸存行的真实前驱已被删——锚点续接必须 valid
    //    （旧"链首空种子起验"逻辑在此场景恒 broken）
    let v = ctx.get_json("/monitor/operlog/verify-chain").await;
    let data = &v["data"];
    assert_eq!(
        data["valid"].as_bool(),
        Some(true),
        "锚点续接后链校验应 valid，实际: {v}"
    );
    assert!(
        data["gapCount"].as_i64().unwrap_or(0) >= 1,
        "gapCount 应 >= 1（存在清理缺口），实际: {v}"
    );
    assert_eq!(
        data["checked"].as_i64(),
        Some(1),
        "幸存链行应只剩 1 条（id2），实际: {v}"
    );

    // 6. stats 窗口：把幸存行改到 40 天前 → days=7 不计入、days=90 计入
    let new_time = chrono::Local::now().naive_local() - chrono::Duration::days(40);
    let id2_val = id2;
    crate::entity::sys_oper_log::Entity::update_many()
        .col_expr(
            crate::entity::sys_oper_log::Column::OperTime,
            sea_orm::sea_query::Expr::value(new_time),
        )
        .filter(crate::entity::sys_oper_log::Column::OperId.eq(id2_val))
        .exec(&ctx.state.db)
        .await
        .expect("回写旧时间");

    let v = ctx.get_json("/monitor/operlog/stats?days=7").await;
    assert_eq!(
        v["data"]["summary"]["total"].as_i64(),
        Some(0),
        "7 天窗不应计入 40 天前的日志，实际: {v}"
    );
    let v = ctx.get_json("/monitor/operlog/stats?days=90").await;
    assert_eq!(
        v["data"]["summary"]["total"].as_i64(),
        Some(1),
        "90 天窗应计入 40 天前的日志，实际: {v}"
    );
}

/// 批次十九 archive 档：导出 JSONL 到存储后端 + 锚点关联对象 key + 下载端点读回。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_opl_archive_mode_exports_and_downloads() {
    use sea_orm::EntityTrait;
    use sea_orm::ColumnTrait;
    use sea_orm::QueryFilter;

    let ctx = TestContext::new().await;
    let id1 = create_oper_log(&ctx).await;
    let id2 = create_oper_log(&ctx).await;
    assert!(id1 < id2);

    // 直查两条 oper_time 取中点切点
    let rows = crate::entity::sys_oper_log::Entity::find()
        .all(&ctx.state.db)
        .await
        .expect("直查 oper_log");
    let t = |oid: i64| {
        rows.iter()
            .find(|r| r.oper_id == oid)
            .and_then(|r| r.oper_time)
            .expect("行应存在")
    };
    let cutoff = t(id1) + (t(id2) - t(id1)) / 2;

    // archive 档清理（注入出厂档存储）
    let affected = ctx
        .state
        .oper_log_service
        .cleanup_before(
            cutoff,
            crate::config::settings::LogRetentionMode::Archive,
            Some(ctx.state.storage.clone()),
        )
        .await
        .expect("archive 模式应成功");
    assert!(affected >= 1, "archive 清理应至少删除 1 行，实际: {affected}");

    // 锚点应关联 archive_object_key
    let anchors = crate::entity::sys_log_archive_anchor::Entity::find()
        .all(&ctx.state.db)
        .await
        .expect("直查锚点表");
    assert_eq!(anchors.len(), 1, "应登记 1 条锚点");
    let key = anchors[0]
        .archive_object_key
        .clone()
        .expect("archive 档锚点应关联对象 key");

    // 下载端点读回：平台管理员（admin tenant_id=0）→ 200 + 内容为 JSONL（逐行 JSON）
    // （端点返回 octet-stream，走原始请求取字节而非 get_json）
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/monitor/operlog/archive/{}", anchors[0].anchor_id))
        .header("authorization", format!("Bearer {}", ctx.token))
        .body(axum::body::Body::empty())
        .expect("构造下载请求");
    let resp = ctx
        .app
        .clone()
        .oneshot(req)
        .await
        .expect("下载请求执行失败");
    assert_eq!(resp.status(), axum::http::StatusCode::OK, "下载应 200");
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("octet-stream"),
        "下载 content-type 应为 octet-stream，实际: {content_type}"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读下载体");
    let text = String::from_utf8(bytes.to_vec()).expect("JSONL 应为 UTF-8");
    let lines: Vec<&str> = text.lines().collect();
    assert!(!lines.is_empty(), "JSONL 不应为空");
    for line in &lines {
        serde_json::from_str::<serde_json::Value>(line).expect("每行应为合法 JSON");
    }
    // 导出的行应包含被删行（oper_id ≤ cutoff 窗口内）
    assert!(
        text.contains(&format!("\"operId\":{}", id1)),
        "JSONL 应含被删行 id1，实际首行: {}",
        lines[0]
    );

    // delete 档锚点（无对象 key）→ 400 archive_not_ready：造一个锚点场景
    // （再清理一次剩余区间，delete 档，无归档）
    let affected2 = ctx
        .state
        .oper_log_service
        .cleanup_before(
            chrono::Utc::now().naive_utc() + chrono::Duration::hours(1),
            crate::config::settings::LogRetentionMode::Delete,
            None,
        )
        .await
        .expect("delete 模式应成功");
    assert!(affected2 >= 1);
    let anchors2 = crate::entity::sys_log_archive_anchor::Entity::find()
        .all(&ctx.state.db)
        .await
        .expect("直查锚点表");
    let delete_anchor = anchors2
        .iter()
        .find(|a| a.mode == "delete")
        .expect("应存在 delete 档锚点");
    let _ = key; // 保持 key 作用域
    let (status, _) = ctx
        .send_raw(
            ctx.request(
                axum::http::Method::GET,
                &format!("/monitor/operlog/archive/{}", delete_anchor.anchor_id),
                None,
            ),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "delete 档锚点下载应 400（archive_not_ready），实际: {status}"
    );
}
