//! 审批工作流模块链路集成测试（方案 B′）：
//! - 提交（single 两级单审）→ 待办 → 同意 → 推进第二级 → 办结（approved）
//! - 会签（countersign）：task_type 由节点 Quorum 决定（与审批人数量无关）
//! - 驳回终止 + 重新提交（round_no + 1）
//! - 撤回（发起人按单据维度）+ 重新提交
//! - 水平越权：非 assignee 审批 → 403
//! - 全链自审拒绝：审批人仅为提交人本人 → 400（防单据卡死）
//! - 管理视图 list 走权限键 system:flow:list
//! - PAT 边界（W-14）：审批写动作禁 PAT、只读放行
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

/// 链路 8：转办边界 —— admin 把待办转回给提交人本人必须 400（防绕过自审禁令），且无副作用
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_transfer_back_to_applicant_rejected() {
    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;

    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_transfer", "single").await;
    let task1 = admin_todo_task_for(&ctx, doc_id, Some(1)).await;

    // 动态取提交人 user_id（不硬编码 ry=2）
    let v = ry_get_json(&ctx, &ry_token, "/system/flow/mine?pageNum=1&pageSize=50").await;
    let applicant_id = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["docId"].as_i64() == Some(doc_id))
        .and_then(|r| r["applicantId"].as_i64())
        .expect("mine 列表应含该单据且带 applicantId");

    // admin 转办给提交人本人 → 400（transfer 校验 to_user_id != applicant_id）
    let req = token_request(
        &ctx,
        &ctx.token,
        Method::POST,
        &format!("/system/flow/task/{task1}/action"),
        Some(serde_json::json!({ "action": "transfer", "toUserId": applicant_id })),
    );
    let (status, _) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "转办给提交人本人应 400，实际: {status}"
    );

    // 被拒后 ry 不应出现该单据待办（无副作用）
    let v = ry_get_json(&ctx, &ry_token, "/system/flow/todo?pageNum=1&pageSize=50").await;
    let leaked = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["bizId"].as_i64() == Some(doc_id));
    assert!(!leaked, "转办被拒后提交人不应出现该单据待办，实际: {v}");
}

/// 链路 9：并发双审 —— 3 个并发审批同一 pending 任务，恰 1 个 200、其余 400（条件更新幂等，V4-E1/V3-E1）
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_flow_concurrent_approve_exactly_one_wins() {
    use futures::future::join_all;

    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;

    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_concurrent", "single").await;
    let task1 = admin_todo_task_for(&ctx, doc_id, Some(1)).await;

    let reqs: Vec<_> = (0..3)
        .map(|_| {
            token_request(
                &ctx,
                &ctx.token,
                Method::POST,
                &format!("/system/flow/task/{task1}/action"),
                Some(serde_json::json!({ "action": "approve", "comment": "race" })),
            )
        })
        .collect();
    let results = join_all(reqs.into_iter().map(|req| {
        let ctx = &ctx;
        async move { ctx.send_raw(req).await }
    }))
    .await;

    let ok = results
        .iter()
        .filter(|(status, _)| *status == axum::http::StatusCode::OK)
        .count();
    let rejected = results
        .iter()
        .filter(|(status, _)| *status == axum::http::StatusCode::BAD_REQUEST)
        .count();
    assert_eq!(ok, 1, "并发 3 审应恰有 1 个成功，实际 ok={ok}");
    assert_eq!(
        rejected, 2,
        "其余应 400（task_not_pending），实际 rejected={rejected}"
    );

    // 唯一赢家推进到第二级（node 2）
    let v = ctx
        .get_json("/system/flow/todo?pageNum=1&pageSize=50")
        .await;
    let node2 = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["bizId"].as_i64() == Some(doc_id) && r["nodeSeq"].as_i64() == Some(2));
    assert!(node2.is_some(), "并发赢家应推进到第二级，实际: {v}");
}

/// 链路 10：PAT 边界（V7-E1 方案 S / W-14）—— 审批写动作禁 PAT，只读放行
///
/// 设计口径（方案 §3.5.5 / §3.6.1 / D6）：**同意/驳回/转办/加签禁 PAT**（弱化不可否认性），
/// **只读列表放行**，**提交（submit）按设计放行**（视为草稿创建，非审批裁决）。
/// 本用例同时锁住"禁"与"放行"两侧，防止后续重构静默破坏安全边界。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_pat_boundary() {
    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;

    // 1) ry 提交一张 single 单据：admin（部门主管）持有第一级待办
    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_pat", "single").await;
    let task1 = admin_todo_task_for(&ctx, doc_id, Some(1)).await;

    // 2) admin（超管）签发宽作用域 PAT —— scope 覆盖 system:flow:list 与管理视图
    let v = ctx
        .post_json(
            "/system/user/profile/tokens",
            serde_json::json!({ "name": "it_flow_pat", "scopes": ["*:*:*"], "expireDays": 30 }),
        )
        .await;
    let pat = v["data"]["token"]
        .as_str()
        .expect("应返回 PAT 明文")
        .to_string();

    // 3) 只读放行：待办（仅登录）与管理视图（system:flow:list，由 scope 覆盖）
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &pat,
            Method::GET,
            "/system/flow/todo?pageNum=1&pageSize=5",
            None,
        ))
        .await;
    assert_eq!(status, 200, "PAT 只读待办应放行，实际: {status} {body}");

    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &pat,
            Method::GET,
            "/system/flow/list?pageNum=1&pageSize=5",
            None,
        ))
        .await;
    assert_eq!(
        status, 200,
        "PAT 只读管理列表应放行（scope 覆盖 system:flow:list），实际: {status} {body}"
    );

    // 4) 写动作禁 PAT：审批（approve）→ 400 pat_forbidden
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &pat,
            Method::POST,
            &format!("/system/flow/task/{task1}/action"),
            Some(serde_json::json!({ "action": "approve" })),
        ))
        .await;
    assert_eq!(status, 400, "PAT 审批应 400（禁写），实际: {status} {body}");
    assert_eq!(body["code"], 400, "业务码应为 400，实际: {body}");

    // 5) 写动作禁 PAT：撤回（withdraw）—— is_pat 校验先于属主校验，故非提交人亦返回 400
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &pat,
            Method::POST,
            &format!("/system/flow/demo/{doc_id}/withdraw"),
            None,
        ))
        .await;
    assert_eq!(status, 400, "PAT 撤回应 400（禁写），实际: {status} {body}");

    // 6) 写动作禁 PAT：重新提交（resubmit）
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &pat,
            Method::POST,
            &format!("/system/flow/demo/{doc_id}/resubmit"),
            None,
        ))
        .await;
    assert_eq!(
        status, 400,
        "PAT 重新提交应 400（禁写），实际: {status} {body}"
    );

    // 7) 写动作禁 PAT：转办（transfer）
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &pat,
            Method::POST,
            &format!("/system/flow/task/{task1}/action"),
            Some(serde_json::json!({ "action": "transfer", "toUserId": 1 })),
        ))
        .await;
    assert_eq!(status, 400, "PAT 转办应 400（禁写），实际: {status} {body}");

    // 8) 无副作用：审批未生效，admin 待办仍在（task1 仍 pending）
    let v = ctx
        .get_json("/system/flow/todo?pageNum=1&pageSize=50")
        .await;
    assert!(
        v["rows"]
            .as_array()
            .expect("rows 应为数组")
            .iter()
            .any(|r| r["taskId"].as_i64() == Some(task1)),
        "PAT 被拒后 task {task1} 应仍为 pending 待办，实际: {v}"
    );
}

/// 链路 11：管理视图 data_scope 的仓储层可见范围过滤（W-5 / 方案 §7.6「部门树 + 本人」）
///
/// 覆盖 `FlowDocScope` 三个分支在真实 SQL 上的行为（`All` / `Depts` / `Applicant`），
/// 并验证空部门集合短路（不生成 `IN ()`）与超管全量不受影响。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_doc_scope_filtering() {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

    use crate::repository::flow_demo_doc::{FlowDemoDocRepository, FlowDocScope};

    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;
    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_scope", "single").await;

    // 取 ry 的 user_id 与部门（单据 dept_id 为提交人部门快照）
    let ry = crate::entity::sys_user::Entity::find()
        .filter(crate::entity::sys_user::Column::UserName.eq("ry"))
        .one(&ctx.state.db)
        .await
        .expect("查询 ry 失败")
        .expect("ry 应存在");
    let ry_dept = ry.dept_id.expect("ry 应有部门");

    let repo = FlowDemoDocRepository::new(ctx.state.db.clone());
    let has_doc =
        |rows: &[crate::entity::flow_demo_doc::Model]| rows.iter().any(|r| r.doc_id == doc_id);

    // All：可见
    let (rows, _) = repo
        .find_all_page(None, 0, 100, None, &FlowDocScope::All)
        .await
        .expect("All 查询失败");
    assert!(has_doc(&rows), "All 范围应含该单据");

    // Depts([ry_dept])：可见（单据 dept_id = 提交人部门）
    let (rows, _) = repo
        .find_all_page(None, 0, 100, None, &FlowDocScope::Depts(vec![ry_dept]))
        .await
        .expect("Depts 查询失败");
    assert!(has_doc(&rows), "本部门范围应含该单据");

    // Depts([-1])：不可见（部门不匹配）
    let (rows, _) = repo
        .find_all_page(None, 0, 100, None, &FlowDocScope::Depts(vec![-1]))
        .await
        .expect("Depts 查询失败");
    assert!(!has_doc(&rows), "其他部门范围不应含该单据");

    // Depts([])：空集合短路，返回空且不报 SQL 错误
    let (rows, total) = repo
        .find_all_page(None, 0, 100, None, &FlowDocScope::Depts(vec![]))
        .await
        .expect("空部门集合查询失败");
    assert!(rows.is_empty() && total == 0, "空部门集合应不可见任何单据");

    // Applicant(ry)：可见；Applicant(admin=1)：不可见
    let (rows, _) = repo
        .find_all_page(None, 0, 100, None, &FlowDocScope::Applicant(ry.user_id))
        .await
        .expect("Applicant 查询失败");
    assert!(has_doc(&rows), "仅本人范围应含本人单据");
    let (rows, _) = repo
        .find_all_page(None, 0, 100, None, &FlowDocScope::Applicant(1))
        .await
        .expect("Applicant 查询失败");
    assert!(!has_doc(&rows), "仅本人范围不应含他人单据");

    // 超管（admin=1）解析为 All：接口仍可见该单据（回归：W-5 不得收窄超管可见面）
    let scope = ctx
        .state
        .flow_service
        .resolve_doc_scope(1)
        .await
        .expect("解析超管 data_scope 失败");
    assert_eq!(scope, FlowDocScope::All, "超管应解析为全量");
}

/// 链路 12：离岗自动转办（W-4）—— 停用待办持有人后自动转办 + 系统归因流水
///
/// 场景：管理员把 ry 单据的第一级待办**转办**给一个新用户（该用户所在部门主管 = admin），
/// 随后停用该用户 ⇒ 待办应自动转出（部门主管 admin）并写入 `operator_id = NULL` 的
/// `transfer` 系统流水。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_user_disabled_auto_transfer() {
    use sea_orm::{EntityTrait, Set};

    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;

    // 1) 新建"离岗"用户（部门 103），并固定部门 103 主管 = admin(1)（保证转办目标确定）
    ctx.post_json(
        "/system/user",
        serde_json::json!({
            "deptId": 103,
            "userName": "it_flow_leave",
            "nickName": "离岗测试",
            "email": "it.flow.leave@yebot.dev",
            "phonenumber": "13800005555",
            "password": "Yebot@12345",
            "status": "0",
            "roleIds": [2]
        }),
    )
    .await;
    let v = ctx
        .get_json("/system/user/list?userName=it_flow_leave")
        .await;
    let leave_uid = v["rows"][0]["userId"]
        .as_i64()
        .expect("应查到离岗用户 userId");

    let mut dept_am: crate::entity::sys_dept::ActiveModel =
        crate::entity::sys_dept::Entity::find_by_id(103)
            .one(&ctx.state.db)
            .await
            .expect("查询部门失败")
            .expect("部门 103 应存在")
            .into();
    dept_am.leader_user_id = Set(Some(1));
    crate::entity::sys_dept::Entity::update(dept_am)
        .exec(&ctx.state.db)
        .await
        .expect("更新部门主管失败");

    // 2) ry 提交 → 第一级待办归 admin；admin 将其转办给离岗用户
    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_leave_auto", "single").await;
    let task_id = admin_todo_task_for(&ctx, doc_id, Some(1)).await;
    let v = ctx
        .post_json(
            &format!("/system/flow/task/{task_id}/action"),
            serde_json::json!({ "action": "transfer", "toUserId": leave_uid }),
        )
        .await;
    ctx.assert_ok(&v);

    let task_repo =
        crate::repository::sys_flow_task::SysFlowTaskRepository::new(ctx.state.db.clone());
    assert!(
        task_repo
            .find_pending_by_assignee(leave_uid)
            .await
            .expect("查询待办失败")
            .iter()
            .any(|t| t.task_id == task_id),
        "转办后待办应归离岗用户"
    );

    // 3) 管理员停用该用户 ⇒ 触发离岗自动转办
    let v = ctx
        .put_json(
            "/system/user/changeStatus",
            serde_json::json!({ "userId": leave_uid, "status": "1" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 4) 待办已转出：离岗用户名下无 pending；任务回到 admin（部门主管）
    let left = task_repo
        .find_pending_by_assignee(leave_uid)
        .await
        .expect("查询离岗用户待办失败");
    assert!(
        left.is_empty(),
        "离岗用户不应再有 pending 待办，实际: {left:?}"
    );
    let admin_pending = task_repo
        .find_pending_by_assignee(1)
        .await
        .expect("查询 admin 待办失败");
    assert!(
        admin_pending.iter().any(|t| t.task_id == task_id),
        "待办应自动转办给部门主管 admin(1)，实际: {admin_pending:?}"
    );

    // 5) 系统归因流水：自动转办那条 transfer 的 operatorId 为 null（区别于手工转办）
    let v = ctx.get_json(&format!("/system/flow/task/{task_id}")).await;
    let timeline = v["data"]["timeline"].as_array().expect("timeline 应为数组");
    let auto_transfer = timeline
        .iter()
        .find(|x| x["action"] == "transfer" && x["operatorId"].is_null())
        .unwrap_or_else(|| panic!("应写入 operator_id=NULL 的自动转办流水，实际: {timeline:?}"));
    assert_eq!(
        auto_transfer["toUserId"].as_i64(),
        Some(1),
        "自动转办目标应为 admin(1)，实际: {auto_transfer}"
    );
}

/// 链路 13：加签（W-3）—— 当前节点追加会签人，节点由单审升级为会签（须全部通过）
///
/// 断言：加签后目标出现待办且 taskType=countersign；重复加签 400；
/// 原审批人单独同意**不足以**推进节点；加签人同意后节点完成并推进第二级直至办结。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_countersign_add() {
    let ctx = TestContext::new().await;
    let ry_token = super::login(&ctx.app, ctx.peer_ip, "ry", "admin123").await;

    // 1) 建加签目标用户并登录
    ctx.post_json(
        "/system/user",
        serde_json::json!({
            "deptId": 103,
            "userName": "it_flow_cs",
            "nickName": "加签目标",
            "email": "it.flow.cs@yebot.dev",
            "phonenumber": "13800006666",
            "password": "Yebot@12345",
            "status": "0",
            "roleIds": [2]
        }),
    )
    .await;
    let v = ctx.get_json("/system/user/list?userName=it_flow_cs").await;
    let cs_uid = v["rows"][0]["userId"]
        .as_i64()
        .expect("应查到加签目标 userId");
    let cs_token = super::login(&ctx.app, super::next_peer_ip(), "it_flow_cs", "Yebot@12345").await;

    let doc_id = submit_as_ry(&ctx, &ry_token, "it_flow_countersign_add", "single").await;
    let task1 = admin_todo_task_for(&ctx, doc_id, Some(1)).await;

    // 2) admin（当前节点审批人）加签 cs_uid
    let v = ctx
        .post_json(
            &format!("/system/flow/task/{task1}/countersign-add"),
            serde_json::json!({ "toUserId": cs_uid }),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"]["taskType"], "countersign",
        "当前节点应升级为会签，实际: {v}"
    );

    // 3) 重复加签 → 400（防重，避免唯一索引报错暴露 500）
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &ctx.token,
            Method::POST,
            &format!("/system/flow/task/{task1}/countersign-add"),
            Some(serde_json::json!({ "toUserId": cs_uid })),
        ))
        .await;
    assert_eq!(status, 400, "重复加签应 400，实际: {status} {body}");

    // 4) 加签目标出现同一单据待办
    let v = ry_get_json(&ctx, &cs_token, "/system/flow/todo?pageNum=1&pageSize=50").await;
    let cs_task = v["rows"]
        .as_array()
        .expect("rows 应为数组")
        .iter()
        .find(|r| r["bizId"].as_i64() == Some(doc_id))
        .and_then(|r| r["taskId"].as_i64())
        .expect("加签目标应有该单据待办");

    // 5) 原审批人单独同意：会签未全部通过 → 单据仍 pending，不推进第二级
    let v = ctx
        .post_json(
            &format!("/system/flow/task/{task1}/action"),
            serde_json::json!({ "action": "approve" }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ry_get_json(&ctx, &ry_token, "/system/flow/mine?pageNum=1&pageSize=50").await;
    let doc = v["rows"]
        .as_array()
        .expect("rows 应为数组")
        .iter()
        .find(|r| r["docId"].as_i64() == Some(doc_id))
        .expect("我发起的列表应含该单据");
    assert_eq!(
        doc["status"], "pending",
        "会签未全部通过前单据不应推进，实际: {doc}"
    );

    // 6) 加签人同意 → 节点完成 → 第二级出现 → 办结
    let v = ry_post_json(
        &ctx,
        &cs_token,
        &format!("/system/flow/task/{cs_task}/action"),
        serde_json::json!({ "action": "approve" }),
    )
    .await;
    ctx.assert_ok(&v);
    let task2 = admin_todo_task_for(&ctx, doc_id, Some(2)).await;
    let v = ctx
        .post_json(
            &format!("/system/flow/task/{task2}/action"),
            serde_json::json!({ "action": "approve" }),
        )
        .await;
    ctx.assert_ok(&v);

    let v = ry_get_json(&ctx, &ry_token, "/system/flow/mine?pageNum=1&pageSize=50").await;
    let doc = v["rows"]
        .as_array()
        .expect("rows 应为数组")
        .iter()
        .find(|r| r["docId"].as_i64() == Some(doc_id))
        .expect("我发起的列表应含该单据");
    assert_eq!(
        doc["status"], "approved",
        "会签通过并二级同意后应办结，实际: {doc}"
    );
}
