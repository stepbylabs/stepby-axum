//! 审批工作流模块链路集成测试（方案 B′）：
//! - 提交（single 两级单审）→ 待办 → 同意 → 推进第二级 → 办结（approved）
//! - 会签（countersign）：task_type 由节点 Quorum 决定（与审批人数量无关）
//! - 驳回终止 + 重新提交（round_no + 1）
//! - 撤回（发起人按单据维度）+ 重新提交
//! - 水平越权：非 assignee 审批 → 403
//! - 全链自审拒绝：审批人仅为提交人本人 → 400（防单据卡死）
//! - 管理视图 list 走权限键 system:flow:list
//!
//! 账号：ry（普通用户，提交方）/ admin（部门主管 + admin 角色，审批方）。
//! 数据前缀：it_flow

use super::TestContext;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request};
use std::net::SocketAddr;

/// 用指定 token 构造 JSON 请求（ry 等非 admin 账号复用）
fn token_request(
    ctx: &TestContext,
    token: &str,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
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

/// 用 ry 的会话发 POST 并断言业务码 200
async fn ry_post_json(
    ctx: &TestContext,
    token: &str,
    uri: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let req = token_request(ctx, token, Method::POST, uri, Some(body));
    ctx.send_json(req).await
}

async fn ry_get_json(ctx: &TestContext, token: &str, uri: &str) -> serde_json::Value {
    let req = token_request(ctx, token, Method::GET, uri, None);
    ctx.send_json(req).await
}

/// ry 提交一张示例请假单（返回 docId）
async fn submit_as_ry(ctx: &TestContext, ry_token: &str, title: &str, mode: &str) -> i64 {
    let v = ry_post_json(
        ctx,
        ry_token,
        "/system/flow/demo/submit",
        serde_json::json!({
            "title": title,
            "leaveType": "annual",
            "days": 2,
            "reason": "integration test",
            "flowMode": mode
        }),
    )
    .await;
    v["data"]["docId"].as_i64().expect("docId 应为数字")
}

/// admin 取自己待办中属于某单据的任务（可选过滤节点）
async fn admin_todo_task_for(ctx: &TestContext, doc_id: i64, node_seq: Option<i64>) -> i64 {
    let v = ctx
        .get_json("/system/flow/todo?pageNum=1&pageSize=50")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    let mut candidates = rows.iter().filter(|r| r["bizId"].as_i64() == Some(doc_id));
    match node_seq {
        Some(seq) => candidates
            .find(|r| r["nodeSeq"].as_i64() == Some(seq))
            .and_then(|r| r["taskId"].as_i64()),
        None => candidates.next().and_then(|r| r["taskId"].as_i64()),
    }
    .unwrap_or_else(|| panic!("admin 待办中应存在单据 {doc_id} 的任务，实际: {v}"))
}

/// 链路 1：single 模式两级审批全部通过（ry 提交 → admin 两级审批）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_single_mode_full_chain() {
    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;

    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_single", "single").await;

    // 第一级（部门主管 = admin）
    let task1 = admin_todo_task_for(&ctx, doc_id, Some(1)).await;
    let v = ctx
        .post_json(
            &format!("/system/flow/task/{task1}/action"),
            serde_json::json!({ "action": "approve", "comment": "ok" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 第二级（管理员角色）出现
    let task2 = admin_todo_task_for(&ctx, doc_id, Some(2)).await;
    let v = ctx
        .post_json(
            &format!("/system/flow/task/{task2}/action"),
            serde_json::json!({ "action": "approve" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 办结：ry 视角单据 approved；流水含 submit + approve×2
    let v = ry_get_json(&ctx, &ry_token, "/system/flow/mine?pageNum=1&pageSize=50").await;
    let doc = v["rows"]
        .as_array()
        .expect("rows 应为数组")
        .iter()
        .find(|r| r["docId"].as_i64() == Some(doc_id))
        .expect("我发起的列表应含该单据");
    assert_eq!(doc["status"], "approved", "两级同意后应办结，实际: {doc}");

    let v = ctx.get_json(&format!("/system/flow/task/{task2}")).await;
    ctx.assert_ok(&v);
    let timeline = v["data"]["timeline"].as_array().expect("timeline 应为数组");
    assert_eq!(timeline.len(), 3, "应有三条流水（提交+两级同意）");
    assert_eq!(timeline[0]["action"], "submit");
}

/// 链路 2：驳回终止 + 重新提交（round_no + 1）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_reject_then_resubmit() {
    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;

    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_reject", "single").await;
    let task1 = admin_todo_task_for(&ctx, doc_id, Some(1)).await;

    // 驳回（admin）
    let v = ctx
        .post_json(
            &format!("/system/flow/task/{task1}/action"),
            serde_json::json!({ "action": "reject", "comment": "材料不全" }),
        )
        .await;
    ctx.assert_ok(&v);

    // ry 视角单据 rejected
    let v = ry_get_json(&ctx, &ry_token, "/system/flow/mine?pageNum=1&pageSize=50").await;
    let doc = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["docId"].as_i64() == Some(doc_id))
        .expect("列表应含该单据");
    assert_eq!(doc["status"], "rejected", "驳回后单据应为 rejected");

    // ry 重新提交 → round 2
    let v = ry_post_json(
        &ctx,
        &ry_token,
        &format!("/system/flow/demo/{doc_id}/resubmit"),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        v["data"]["currentRound"], 2,
        "重新提交后应为 round 2，实际: {v}"
    );
    assert_eq!(v["data"]["status"], "pending");
}

/// 链路 3：撤回（发起人按单据维度）→ withdrawn → 可重新提交
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_withdraw() {
    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;

    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_withdraw", "single").await;

    let v = ry_post_json(
        &ctx,
        &ry_token,
        &format!("/system/flow/demo/{doc_id}/withdraw"),
        serde_json::json!({}),
    )
    .await;
    ctx.assert_ok(&v);

    let v = ry_get_json(&ctx, &ry_token, "/system/flow/mine?pageNum=1&pageSize=50").await;
    let doc = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["docId"].as_i64() == Some(doc_id))
        .expect("列表应含该单据");
    assert_eq!(doc["status"], "withdrawn", "撤回后应为 withdrawn");

    // 撤回后可重新提交
    let v = ry_post_json(
        &ctx,
        &ry_token,
        &format!("/system/flow/demo/{doc_id}/resubmit"),
        serde_json::json!({}),
    )
    .await;
    ctx.assert_ok(&v);
    assert_eq!(v["data"]["status"], "pending");
}

/// 链路 4：会签节点 —— task_type 由 Quorum 决定（与实际审批人数无关，V7 系修正）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_countersign_mode() {
    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;

    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_countersign", "countersign").await;

    // 会签节点（Quorum::All）→ task_type 必须为 countersign（即便解析后仅 1 个审批人）
    let v = ctx
        .get_json("/system/flow/todo?pageNum=1&pageSize=50")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    let countersign_tasks: Vec<i64> = rows
        .iter()
        .filter(|r| {
            r["bizId"].as_i64() == Some(doc_id)
                && r["taskType"] == "countersign"
                && r["status"] == "pending"
        })
        .filter_map(|r| r["taskId"].as_i64())
        .collect();
    assert!(
        !countersign_tasks.is_empty(),
        "应存在 countersign 类型待办，实际: {v}"
    );

    // 全部通过后办结
    for tid in countersign_tasks {
        let v = ctx
            .post_json(
                &format!("/system/flow/task/{tid}/action"),
                serde_json::json!({ "action": "approve" }),
            )
            .await;
        ctx.assert_ok(&v);
    }

    let v = ry_get_json(&ctx, &ry_token, "/system/flow/mine?pageNum=1&pageSize=50").await;
    let doc = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["docId"].as_i64() == Some(doc_id))
        .expect("列表应含该单据");
    assert_eq!(doc["status"], "approved", "会签全部通过后应办结");
}

/// 链路 5：水平越权 —— 非 assignee（ry）对 admin 的待办发起审批 → 403
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_horizontal_forbidden() {
    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;

    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_forbidden", "single").await;
    let task1 = admin_todo_task_for(&ctx, doc_id, Some(1)).await;

    // ry 用自己的会话审批 admin 的待办（assignee=1 != ry）→ 403
    let req = token_request(
        &ctx,
        &ry_token,
        Method::POST,
        &format!("/system/flow/task/{task1}/action"),
        Some(serde_json::json!({ "action": "approve" })),
    );
    let (status, _) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        axum::http::StatusCode::FORBIDDEN,
        "非 assignee 审批应 403，实际: {status}"
    );
}

/// 链路 6：全链自审拒绝 —— admin 提交时链路审批人仅为 admin 本人 → 400
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_self_approve_chain_rejected() {
    let ctx = TestContext::new().await;

    // admin 提交：部门主管（回填=admin）与 admin 角色用户均为 admin 本人 → 全链自审 → 400
    let req = token_request(
        &ctx,
        &ctx.token,
        Method::POST,
        "/system/flow/demo/submit",
        Some(serde_json::json!({
            "title": "it_flow_selfchain",
            "leaveType": "annual",
            "days": 1,
            "flowMode": "single"
        })),
    );
    let (status, v) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "全链自审提交应 400，实际: {status} {v}"
    );
    assert_eq!(v["code"], 400, "业务码应为 400，实际: {v}");
}

/// 链路 7：管理视图 list（权限键 system:flow:list；admin 属超管角色可访问）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_admin_list() {
    let ctx = TestContext::new().await;
    let v = ctx
        .get_json("/system/flow/list?pageNum=1&pageSize=10")
        .await;
    ctx.assert_ok(&v);
    assert!(v["rows"].is_array(), "rows 应为数组，实际: {v}");
    assert!(v["total"].is_u64(), "total 应为数字，实际: {v}");
}
