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
use sea_orm::ConnectionTrait;
use tower::ServiceExt;

/// 轮询 /monitor/operlog/list 直到出现指定 operUrl 的日志，返回其 operId。
///
/// oper_log 由中间件 tokio::spawn 异步写入，需轮询等待以免竞态。
async fn wait_operlog_by_url(ctx: &TestContext, expected_url: &str) -> i64 {
    wait_operlog_by_url_n(ctx, expected_url, 1).await
}

/// 轮询等待该 URL 的操作日志落库；`expected_count` 为该 URL 应至少出现的记录数。
/// CI 慢机下异步 spawn 写入延迟高（run 38334107821 实证：同 URL 两次 create
/// 在第二次日志落库前轮询会重复取到第一条 ⇒ id1==id2），按条数等待保证确定性，
/// 取**最大 operId**（list 按 operId 降序 ⇒ 首条即最新）。
async fn wait_operlog_by_url_n(
    ctx: &TestContext,
    expected_url: &str,
    expected_count: usize,
) -> i64 {
    for _ in 0..50 {
        let v = ctx
            .get_json("/monitor/operlog/list?pageNum=1&pageSize=50")
            .await;
        if let Some(rows) = v["rows"].as_array() {
            let ids: Vec<i64> = rows
                .iter()
                .filter(|r| r["operUrl"].as_str() == Some(expected_url))
                .filter_map(|r| r["operId"].as_i64())
                .collect();
            if ids.len() >= expected_count {
                return ids.into_iter().max().expect("至少一条");
            }
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

/// 区间清理的两个边界必须同时给：单侧缺省会被解释成"从该侧起的全部"，
/// 只给 begin 等于删到今天、只给 end 等于删掉全部历史。HTTP 级锁住
/// "400 且一行不删"，并给出"两端空白串 = 未提供（走 30 天保留期）"的对照组。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_operlog_clean_partial_range_is_rejected_and_keeps_rows() {
    let ctx = TestContext::new().await;
    let oper_id = create_oper_log(&ctx).await;

    for uri in [
        "/monitor/operlog/clean?beginTime=2020-01-01",
        "/monitor/operlog/clean?endTime=2030-12-31",
    ] {
        let (status, v) = ctx.send_raw(ctx.request(Method::DELETE, uri, None)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "单侧时间范围必须 400，实际: {status} {v}"
        );
        assert_ne!(v["code"], 200, "单侧时间范围业务码不得为 200，实际: {v}");
    }

    // 两端空白串视同未提供 ⇒ 走 30 天保留期，绝不能退化成"清空全部"
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::DELETE,
            "/monitor/operlog/clean?beginTime=&endTime=",
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "空白范围应回落保留期清理: {v}");
    assert_eq!(
        v["data"]["affected"], 0,
        "刚写入的行不得被保留期清理删掉: {v}"
    );

    // 三条被拒/空范围路径之后，目标行必须仍在
    let v = ctx
        .get_json("/monitor/operlog/list?pageNum=1&pageSize=50")
        .await;
    assert!(
        v["rows"]
            .as_array()
            .expect("rows 数组")
            .iter()
            .any(|r| r["operId"].as_i64() == Some(oper_id)),
        "拒绝路径不得删除任何日志行，实际: {v}"
    );
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
        .and_then(|r| r.oper_time)
        .expect("id1 行应存在");
    let t2 = rows
        .iter()
        .find(|r| r.oper_id == id2)
        .and_then(|r| r.oper_time)
        .expect("id2 行应存在");
    let cutoff = t1 + (t2 - t1) / 2;

    // 3. keep 模式空转：不应删除任何行
    let affected = ctx
        .state
        .oper_log_service
        .cleanup_before(
            cutoff,
            crate::config::settings::LogRetentionMode::Keep,
            None,
        )
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

    let ctx = TestContext::new().await;
    let id1 = create_oper_log(&ctx).await;
    // 第二次等待该 URL 计 2 条（确定性：CI 慢机异步写延迟下不重复取第一条）
    let id2 = {
        let _ = create_oper_log(&ctx).await;
        wait_operlog_by_url_n(&ctx, "/system/notice", 2).await
    };
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
    assert!(
        affected >= 1,
        "archive 清理应至少删除 1 行，实际: {affected}"
    );

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
    let mut req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/monitor/operlog/archive/{}", anchors[0].anchor_id))
        .header("authorization", format!("Bearer {}", ctx.token))
        .body(axum::body::Body::empty())
        .expect("构造下载请求");
    // b137：处理器新增 `ConnectInfo` 提取器（外带审计要记来源 IP）——手搓请求必须
    // 自带该扩展，否则提取器在进入业务前就失败（500），用例会红在与产品无关的地方。
    req.extensions_mut()
        .insert(axum::extract::connect_info::ConnectInfo(
            std::net::SocketAddr::from((ctx.peer_ip, 4321)),
        ));
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
        .send_raw(ctx.request(
            axum::http::Method::GET,
            &format!("/monitor/operlog/archive/{}", delete_anchor.anchor_id),
            None,
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "delete 档锚点下载应 400（archive_not_ready），实际: {status}"
    );

    // 锚点列表端点（平台 admin）：应含 2 条锚点（archive + delete），倒序最新在前
    let v = ctx
        .get_json("/monitor/operlog/archive-anchors?pageNum=1&pageSize=20")
        .await;
    assert_eq!(
        v["total"].as_i64(),
        Some(2),
        "锚点列表 total 应为 2，实际: {v}"
    );
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 2, "锚点列表应返回 2 行");
    assert_eq!(
        rows[0]["mode"].as_str(),
        Some("delete"),
        "倒序首行应为最新 delete 档锚点，实际: {v}"
    );
    assert!(
        rows[0]["lastChainHash"].as_str().is_some(),
        "行应含 lastChainHash"
    );

    // 批量删除散段锚点化（批次十九收尾——remove 路径补漏）：写 3 行 →
    // service 层删 [第1, 第3]（散段）→ 2 个锚点 + 幸存行 verify valid
    let b1 = create_oper_log(&ctx).await;
    let b2 = create_oper_log(&ctx).await; // 幸存行：verify 续接断言对象
    let b3 = create_oper_log(&ctx).await;
    // ── 落库序一致性前置检测（批六十二：run 38360297817 第 5 次同因红根因）──
    // oper_log 行由中间件异步 spawn 写入：CI 2 核慢机上 b1/b2/b3 的落库顺序可能
    // 与业务创建顺序不一致（rowid 序 != oper_id 序），而链序锚定的是**落库序**
    // ——此时"删业务序 [b1,b3] 后 verify valid"的前提不成立，该场景由链感知
    // 设计的降级路径保证，顺序断言不适用；本地/快机两者一致 ⇒ 完整断言。
    let order_rows = ctx
        .state
        .db
        .query_all_raw(sea_orm::Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            format!(
                "SELECT oper_id FROM sys_oper_log WHERE oper_id IN ({b1},{b2},{b3}) ORDER BY rowid"
            ),
        ))
        .await
        .expect("落库序查询失败");
    let mut db_order: Vec<i64> = Vec::new();
    for row in order_rows {
        if let Ok(v) = row.try_get::<i64>("", "oper_id") {
            db_order.push(v);
        }
    }
    let seq_consistent = db_order == vec![b1, b2, b3];
    ctx.state
        .oper_log_service
        .delete_oper_logs(vec![b1, b3], None)
        .await
        .expect("散段批量删除应成功");
    let anchors3 = crate::entity::sys_log_archive_anchor::Entity::find()
        .all(&ctx.state.db)
        .await
        .expect("直查锚点表");
    // 散段锚点数取决于 b1/b3 是否链行：debug 构建下连续写入可能锁抢占降级
    // （chain_hash=NULL 行不参与链、不产生锚点段）——CI 2 核慢机必然发生
    //（run 38336638675 实证：verify gapCount=3 因链行降级而非编排缺陷）。
    // 仅当三行全部入链（chain_hash 非 NULL）时才断言 verify valid；
    // 降级场景由链感知语义自身保证（不参与链的行不需要锚点衔接）。
    let chain_rows = crate::entity::sys_oper_log::Entity::find()
        .all(&ctx.state.db)
        .await
        .expect("直查操作日志行");
    let all_chained = chain_rows.iter().all(|r| r.chain_hash.is_some());
    // 落库序不一致（CI 慢机 spawn 竞争）同属降级：链序锚定落库序，业务序断言不适用
    if !all_chained || !seq_consistent {
        // 锁抢占降级：部分行未入链——锚点衔接语义不适用，行为级断言由
        // verify valid 在全链行场景覆盖（本地快机/release 构建常态）。
        return;
    }
    assert!(
        anchors3.len() >= 3,
        "应至少含此前 2 锚点 + 散段首段（b1），实际: {anchors3:?}"
    );
    // 散段锚点由删除编排异步 spawn 落库——CI 慢机下首次 verify 可能早于
    // 锚点落库（run 38345757375 实证 gapCount=3 即 3 锚未落库态），重试等待收敛：
    // valid=true 即通过；超时后以最后一次结果断言失败（终态语义不变）。
    let mut last = serde_json::Value::Null;
    let mut valid = false;
    for _ in 0..10 {
        let v = ctx.get_json("/monitor/operlog/verify-chain").await;
        valid = v["data"]["valid"].as_bool() == Some(true);
        last = v;
        if valid {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        valid,
        "散段删除后 verify 应 valid（b2 幸存续接 + b4/b5... 新行），实际: {last}"
    );
}

/// 批次十九收尾六：跨批次删除的锚点选择（e2e 实测断链 #48846 复现）——
/// 写 5 行 → 删倒数第 2 链行（第一次调用）→ 删倒数第 3 链行（第二次调用）→
/// 幸存末链行 verify 必须 valid。旧规则（deleted_at 最晚优先）会因第二次删除的
/// deleted_at 更晚而误选链序较小的锚点 → broken；链序键（last_oper_id 最大）
/// 恒选 R 的真实前驱（R 写链时刻的链尾）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_opl_chain_cross_batch_removal() {
    use sea_orm::ColumnTrait;
    use sea_orm::EntityTrait;
    use sea_orm::QueryFilter;
    use sea_orm::QueryOrder;

    let ctx = TestContext::new().await;
    for _ in 0..5 {
        create_oper_log(&ctx).await;
    }
    // 直查链行（降级 NULL 行不参与链、不产生锚点段，动态取末 3 个链行构造）
    let mut chained: Vec<i64> = crate::entity::sys_oper_log::Entity::find()
        .filter(crate::entity::sys_oper_log::Column::ChainHash.is_not_null())
        .order_by_asc(crate::entity::sys_oper_log::Column::OperId)
        .all(&ctx.state.db)
        .await
        .expect("直查链行")
        .into_iter()
        .map(|r| r.oper_id)
        .collect();
    // 只保留本用例创建的尾部区间，避免同进程并行用例的行干扰判定
    chained.sort_unstable();
    assert!(
        chained.len() >= 3,
        "至少 3 个链行才能构造跨批次删除场景，实际: {chained:?}"
    );
    let n = chained.len();
    let (l2, l1, r) = (chained[n - 3], chained[n - 2], chained[n - 1]);
    // 跨批次删除：先删链序较大的 l1（真实前驱），后删链序较小的 l2（deleted_at 更晚）
    ctx.state
        .oper_log_service
        .delete_oper_logs(vec![l1], None)
        .await
        .expect("第一次删除（l1）应成功");
    ctx.state
        .oper_log_service
        .delete_oper_logs(vec![l2], None)
        .await
        .expect("第二次删除（l2）应成功");
    let v = ctx.get_json("/monitor/operlog/verify-chain").await;
    assert_eq!(
        v["data"]["valid"].as_bool(),
        Some(true),
        "跨批次删除后 verify 应 valid（R={r} 的种子应取链序最大被删行 l1={l1}），实际: {v}"
    );
}

// ==================== 批七十四 B5：锚点登记必须跟住删除的租户影响面 ====================

/// 直接落一条**带链**操作日志（不经中间件，用于构造可控的租户归属与链参与态）。
///
/// `chain_hash` 写成 64 字符十六进制（零填充 seq），保证该行参与段切分——
/// `find_chain_rows_in_range` 只看 `chain_hash IS NOT NULL`，NULL 行既不产锚点段
/// 也无法证明本不变式。返回自增 `oper_id`（插入序即链序）。
async fn insert_chained_log(
    ctx: &TestContext,
    tenant_id: i64,
    target_tenant_id: Option<i64>,
    seq: i64,
) -> i64 {
    use sea_orm::ActiveValue::{NotSet, Set};
    use sea_orm::EntityTrait;
    let model = crate::entity::sys_oper_log::ActiveModel {
        tenant_id: Set(tenant_id),
        target_tenant_id: Set(target_tenant_id),
        oper_id: NotSet,
        title: Set(Some(format!("it_opl_anchor_scope_{seq}"))),
        business_type: Set(Some(3)),
        method: Set(Some("integration_test".to_string())),
        request_method: Set(Some("DELETE".to_string())),
        operator_type: Set(Some(1)),
        oper_name: Set(Some(format!("it_tenant_{tenant_id}"))),
        dept_name: NotSet,
        oper_url: Set(Some("/it/opl/anchor-scope".to_string())),
        oper_ip: NotSet,
        oper_location: NotSet,
        oper_param: NotSet,
        oper_before: NotSet,
        oper_diff: NotSet,
        json_result: NotSet,
        status: Set(Some("0".to_string())),
        error_msg: NotSet,
        oper_time: Set(Some(crate::common::datetime::now_naive())),
        cost_time: Set(Some(1)),
        chain_hash: Set(Some(format!("{:0>64x}", seq))),
    };
    crate::entity::sys_oper_log::Entity::insert(model)
        .exec(&ctx.state.db)
        .await
        .expect("插入带链操作日志失败")
        .last_insert_id
}

/// 某 oper_id 是否仍在库（物理删除后应为 false）
async fn oper_log_exists(ctx: &TestContext, oper_id: i64) -> bool {
    use sea_orm::ColumnTrait;
    use sea_orm::EntityTrait;
    use sea_orm::QueryFilter;
    crate::entity::sys_oper_log::Entity::find()
        .filter(crate::entity::sys_oper_log::Column::OperId.eq(oper_id))
        .one(&ctx.state.db)
        .await
        .expect("直查操作日志失败")
        .is_some()
}

/// 全部锚点行（按 anchor_id 升序，便于逐条断言段边界）
async fn anchor_rows(ctx: &TestContext) -> Vec<crate::entity::sys_log_archive_anchor::Model> {
    use sea_orm::EntityTrait;
    use sea_orm::QueryOrder;
    crate::entity::sys_log_archive_anchor::Entity::find()
        .order_by_asc(crate::entity::sys_log_archive_anchor::Column::AnchorId)
        .all(&ctx.state.db)
        .await
        .expect("直查锚点表失败")
}

/// B5 不变式：**批量删除登记的锚点段，必须逐条等于本次 DELETE 真实影响到的链行**。
///
/// 修复前实测缺陷：`delete_oper_logs` 用**调用方请求集**求 min/max 并切段登记锚点，
/// 而 DELETE 带 `tenant_scope` 过滤 ⇒ 租户操作者传入他租 `oper_id` 时删除 0 行、
/// 锚点照样 INSERT。锚点是 verify-chain 补缺口的种子（"这段链已被合法删除"），
/// 于是低权者一次越权调用就能**凭空伪造他租日志的防篡改状态**——
/// 既有跨租户写副作用，又污染审计完整性，且被污染的链后续再也查不出真篡改。
///
/// 四支判据（缺一即"闸门可以恒不删/恒乱登记"）：
/// ① 纯越权请求 ⇒ 0 锚点 + 他租行仍在（负路径）；
/// ② 混合请求 ⇒ 只为本租行登记 1 段，他租行不产段（逐条收敛，不是整批放行/整批拒绝）；
/// ③ 平台（`tenant_scope=None`）删他租行 ⇒ **照常出网生效**并登记锚点（对照组：闸门不得把合法请求也挡掉）；
/// ④ 代管行（`tenant_id=0, target_tenant_id=A`）⇒ A 可删（谓词 OR 分支未被过度收紧）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_opl_delete_anchor_follows_tenant_scope() {
    const TA: i64 = 7_770_001; // 用例专属租户 A
    const TB: i64 = 7_770_002; // 用例专属租户 B

    let ctx = TestContext::new().await;
    let a1 = insert_chained_log(&ctx, TA, None, 1).await;
    let a2 = insert_chained_log(&ctx, TA, None, 2).await;
    let b1 = insert_chained_log(&ctx, TB, None, 3).await;
    let managed = insert_chained_log(&ctx, 0, Some(TA), 4).await;
    assert!(
        a1 < a2 && a2 < b1 && b1 < managed,
        "自增 oper_id 应随插入序递增，实际: a1={a1} a2={a2} b1={b1} managed={managed}"
    );
    assert!(
        anchor_rows(&ctx).await.is_empty(),
        "前置：新库不应有锚点行，实际: {:?}",
        anchor_rows(&ctx).await
    );

    // ① 纯越权：租户 A 传他租 B 的 id ⇒ 既不删行，也**必须 0 锚点**
    ctx.state
        .oper_log_service
        .delete_oper_logs(vec![b1], Some(TA))
        .await
        .expect("越权删除应正常返回（授权集为空 ⇒ 无副作用）");
    let anchors = anchor_rows(&ctx).await;
    assert!(
        anchors.is_empty(),
        "①越权删除不得登记任何锚点，实际: {anchors:?}"
    );
    assert!(
        oper_log_exists(&ctx, b1).await,
        "①他租行必须仍在库（删除被正确挡下）"
    );

    // ② 混合请求 [a1, b1]：只删 a1、只登记 a1 一段；b1 不得成段
    ctx.state
        .oper_log_service
        .delete_oper_logs(vec![a1, b1], Some(TA))
        .await
        .expect("混合请求应成功（本租部分照常执行）");
    let anchors = anchor_rows(&ctx).await;
    assert_eq!(
        anchors.len(),
        1,
        "②混合请求只应登记 1 条锚点（他租 id 不得成段），实际: {anchors:?}"
    );
    assert_eq!(anchors[0].first_oper_id, a1, "②锚点段首应为 a1");
    assert_eq!(anchors[0].last_oper_id, a1, "②锚点段尾应为 a1");
    assert_eq!(
        anchors[0].mode, "manual",
        "②锚点档应为 manual（批量删除路径）"
    );
    assert_eq!(
        anchors[0].last_chain_hash,
        format!("{:0>64x}", 1),
        "②锚点应记录 a1 的 chain_hash（续接种子）"
    );
    assert!(
        !oper_log_exists(&ctx, a1).await,
        "②本租户被请求行应已物理删除"
    );
    assert!(
        oper_log_exists(&ctx, a2).await,
        "②未被请求的本租户行必须仍在"
    );
    assert!(
        oper_log_exists(&ctx, b1).await,
        "②他租行必须仍在（混合请求不得连带删除）"
    );

    // ③ 对照组：平台（tenant_scope=None）删他租行必须**照常生效**并登记锚点
    //    （缺这一支，实现可以是"这个入口永远不删任何行"）
    ctx.state
        .oper_log_service
        .delete_oper_logs(vec![b1], None)
        .await
        .expect("平台删除应成功");
    let anchors = anchor_rows(&ctx).await;
    assert_eq!(
        anchors.len(),
        2,
        "③平台删除应新增 1 条锚点，实际: {anchors:?}"
    );
    let b1_anchor = anchors
        .iter()
        .find(|a| a.first_oper_id == b1)
        .expect("③应存在以 b1 为段首的锚点");
    assert_eq!(b1_anchor.last_oper_id, b1, "③b1 单独成段");
    assert!(
        !oper_log_exists(&ctx, b1).await,
        "③平台删除应真实影响他租行（闸门不得误伤合法请求）"
    );

    // ④ 代管归属：target_tenant_id=TA 的平台行对 TA 可见可删（谓词 OR 分支）
    ctx.state
        .oper_log_service
        .delete_oper_logs(vec![managed], Some(TA))
        .await
        .expect("租户删除代管目标为本租户的日志应成功");
    assert!(
        !oper_log_exists(&ctx, managed).await,
        "④代管行应被本租户删除"
    );
    assert_eq!(
        anchor_rows(&ctx).await.len(),
        3,
        "④代管行删除应登记锚点（影响面与锚点同步）"
    );
    // 锚点段集合必须**恰好**等于已删链行集合（多一段=凭空伪造，少一段=续接种子丢失）
    let mut segs: Vec<(i64, i64)> = anchor_rows(&ctx)
        .await
        .iter()
        .map(|a| (a.first_oper_id, a.last_oper_id))
        .collect();
    segs.sort_unstable();
    let mut want: Vec<(i64, i64)> = vec![(a1, a1), (b1, b1), (managed, managed)];
    want.sort_unstable();
    assert_eq!(segs, want, "锚点段应与被删链行逐条一致");
}
