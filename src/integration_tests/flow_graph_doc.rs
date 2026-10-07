//! 图驱动单据集成测试（批次十六：G-02「按图推进」闭环验收）：
//! - 建图（多分支：days>3 走二级加权审批，否则默认直达办结）→ 发布 → 提交
//! - **条件真**：路由经二级节点——approve 首节点 → 推进二级 → approve → 办结
//! - **条件假**：默认边直达办结（一节点）
//! - fail-closed：字段快照缺条件字段 → 400；流程未发布 → 404
//!
//! 账号：admin（平台 tid=0；图节点审批人全用 role:admin——免部门依赖）。

use super::TestContext;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request};
use std::net::SocketAddr;

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

async fn post_json(
    ctx: &TestContext,
    token: &str,
    uri: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    ctx.send_json(token_request(ctx, token, Method::POST, uri, Some(body)))
        .await
}

/// 建图 + 发布（多分支：days>3 走 a2 加权二级，否则 a1 默认直达 end）
async fn setup_published_flow(ctx: &TestContext, flow_code: &str) {
    let graph = serde_json::json!({
        "nodes": [
            {"id": "s", "type": "start", "name": "开始"},
            {"id": "a1", "type": "approve", "name": "主管审批", "assignees": ["role:admin"], "multi": "single", "threshold": 1, "actions": []},
            {"id": "a2", "type": "approve", "name": "总监加权", "assignees": ["role:admin"], "multi": "weighted", "threshold": 1, "actions": []},
            {"id": "e", "type": "end", "name": "结束"}
        ],
        "edges": [
            {"from": "s", "to": "a1"},
            {"from": "a1", "to": "a2", "condition": {"field": "days", "op": ">", "value": 3}},
            {"from": "a1", "to": "e"},
            {"from": "a2", "to": "e"}
        ]
    })
    .to_string();
    let v = post_json(
        ctx,
        &ctx.token,
        "/system/flow/definition",
        serde_json::json!({
            "flowCode": flow_code,
            "flowName": "集成测试·图驱动",
            "graphJson": graph
        }),
    )
    .await;
    ctx.assert_ok(&v);
    let flow_id = v["data"]["flowId"].as_i64().expect("应返回 flowId");
    let v = ctx
        .send_json(token_request(
            ctx,
            &ctx.token,
            Method::POST,
            &format!("/system/flow/definition/publish/{flow_id}"),
            None,
        ))
        .await;
    ctx.assert_ok(&v);
}

/// admin 取自己待办中属于某图单据的任务（按 nodeSeq 过滤）
async fn admin_todo_task_for(ctx: &TestContext, doc_id: i64, node_seq: i64) -> i64 {
    let v = ctx
        .get_json("/system/flow/todo?pageNum=1&pageSize=50")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    rows.iter()
        .find(|r| {
            r["bizId"].as_i64() == Some(doc_id)
                && r["bizType"].as_str() == Some("flow_graph_doc")
                && r["nodeSeq"].as_i64() == Some(node_seq)
        })
        .and_then(|r| r["taskId"].as_i64())
        .unwrap_or_else(|| panic!("待办应含 doc={doc_id} node={node_seq}: {v}"))
}

async fn stepby_token(ctx: &TestContext) -> String {
    super::login(&ctx.app, super::next_peer_ip(), "stepby", "admin123").await
}

/// 链路①：条件真（days=5）→ 两节点链 → 逐级审批 → 办结
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_graph_doc_conditional_true_two_nodes() {
    let ctx = TestContext::new().await;
    setup_published_flow(&ctx, "it_graph_true").await;

    // 提交（字段快照冻结；条件真 → a1 → a2 → e）
    let ry_token = stepby_token(&ctx).await;
    let v = post_json(
        &ctx,
        &ry_token,
        "/system/flow/graph/submit",
        serde_json::json!({
            "flowCode": "it_graph_true",
            "title": "集成测试·图驱动（长链）",
            "fields": {"days": 5}
        }),
    )
    .await;
    ctx.assert_ok(&v);
    let doc_id = v["data"]["docId"].as_i64().expect("应返回 docId");

    // 首节点（主管审批）
    let task1 = admin_todo_task_for(&ctx, doc_id, 1).await;
    let v = ctx
        .post_json(
            &format!("/system/flow/task/{task1}/action"),
            serde_json::json!({ "action": "approve", "comment": "ok" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 推进到二级（总监加权，threshold=1 单票达标）
    let task2 = admin_todo_task_for(&ctx, doc_id, 2).await;
    let v = ctx
        .post_json(
            &format!("/system/flow/task/{task2}/action"),
            serde_json::json!({ "action": "approve" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 办结断言：done 流水含该单据两条 approve（推进链完整走完）
    let v = ctx
        .get_json("/system/flow/done?pageNum=1&pageSize=50")
        .await;
    let approvals = v["rows"]
        .as_array()
        .expect("done rows")
        .iter()
        .filter(|r| r["bizId"].as_i64() == Some(doc_id) && r["action"].as_str() == Some("approve"))
        .count();
    assert_eq!(approvals, 2, "长链应产生两条 approve 流水: {v}");
    // todo 中不再有该单据任务（办结）
    let v = ctx
        .get_json("/system/flow/todo?pageNum=1&pageSize=50")
        .await;
    assert!(
        !v["rows"]
            .as_array()
            .expect("todo rows")
            .iter()
            .any(|r| r["bizId"].as_i64() == Some(doc_id)),
        "办结后待办应清空: {v}"
    );
}

/// 链路②：条件假（days=1）→ 默认边直达办结（单节点）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_graph_doc_conditional_false_default_edge() {
    let ctx = TestContext::new().await;
    setup_published_flow(&ctx, "it_graph_short").await;

    let ry_token = stepby_token(&ctx).await;
    let v = post_json(
        &ctx,
        &ry_token,
        "/system/flow/graph/submit",
        serde_json::json!({
            "flowCode": "it_graph_short",
            "title": "集成测试·图驱动（短链）",
            "fields": {"days": 1}
        }),
    )
    .await;
    ctx.assert_ok(&v);
    let doc_id = v["data"]["docId"].as_i64().expect("应返回 docId");

    // 单节点审批 → 办结（无二级待办产生）
    let task1 = admin_todo_task_for(&ctx, doc_id, 1).await;
    let v = ctx
        .post_json(
            &format!("/system/flow/task/{task1}/action"),
            serde_json::json!({ "action": "approve" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 办结断言：done 流水恰一条 approve（默认边未进二级）+ todo 清空
    let v = ctx
        .get_json("/system/flow/done?pageNum=1&pageSize=50")
        .await;
    let approvals = v["rows"]
        .as_array()
        .expect("done rows")
        .iter()
        .filter(|r| r["bizId"].as_i64() == Some(doc_id) && r["action"].as_str() == Some("approve"))
        .count();
    assert_eq!(approvals, 1, "默认边应只产生一条 approve 流水: {v}");
    let v = ctx
        .get_json("/system/flow/todo?pageNum=1&pageSize=50")
        .await;
    assert!(
        !v["rows"]
            .as_array()
            .expect("todo rows")
            .iter()
            .any(|r| r["bizId"].as_i64() == Some(doc_id)),
        "办结后待办应清空: {v}"
    );
}

/// fail-closed：字段快照缺条件字段（图引用 days 而提交未带）→ 400
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_graph_doc_missing_field_rejected() {
    let ctx = TestContext::new().await;
    setup_published_flow(&ctx, "it_graph_miss").await;
    let (status, _) = ctx
        .send_raw(token_request(
            &ctx,
            &ctx.token,
            Method::POST,
            "/system/flow/graph/submit",
            Some(serde_json::json!({
                "flowCode": "it_graph_miss",
                "title": "缺字段",
                "fields": {}
            })),
        ))
        .await;
    assert_eq!(
        status, 400,
        "字段快照缺条件字段必须 400（fail-closed，不静默选边）"
    );
}

/// fail-closed：flow_code 未发布/不存在 → 404
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_graph_doc_unpublished_flow_rejected() {
    let ctx = TestContext::new().await;
    let (status, _) = ctx
        .send_raw(token_request(
            &ctx,
            &ctx.token,
            Method::POST,
            "/system/flow/graph/submit",
            Some(serde_json::json!({
                "flowCode": "it_graph_never",
                "title": "不存在的流程",
                "fields": {"days": 1}
            })),
        ))
        .await;
    assert_eq!(status, 404, "未发布流程必须 404");
}

/// 链路③：actions 白名单收窄——a1 未勾 delegate → delegate 调用 403
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_graph_doc_action_whitelist_denies_delegate() {
    let ctx = TestContext::new().await;
    // 图定义：a1 仅勾 countersign_add（不含 delegate）
    let graph = serde_json::json!({
        "nodes": [
            {"id": "s", "type": "start", "name": "开始"},
            {"id": "a1", "type": "approve", "name": "主管", "assignees": ["role:admin"], "multi": "single", "threshold": 1, "actions": ["countersign_add"]},
            {"id": "e", "type": "end", "name": "结束"}
        ],
        "edges": [
            {"from": "s", "to": "a1"},
            {"from": "a1", "to": "e"}
        ]
    })
    .to_string();
    let v = post_json(
        &ctx,
        &ctx.token,
        "/system/flow/definition",
        serde_json::json!({
            "flowCode": "it_graph_actions",
            "flowName": "集成测试·动作收窄",
            "graphJson": graph
        }),
    )
    .await;
    ctx.assert_ok(&v);
    let flow_id = v["data"]["flowId"].as_i64().expect("flowId");
    let v = ctx
        .send_json(token_request(
            &ctx,
            &ctx.token,
            Method::POST,
            &format!("/system/flow/definition/publish/{flow_id}"),
            None,
        ))
        .await;
    ctx.assert_ok(&v);

    let ry_token = stepby_token(&ctx).await;
    let v = post_json(
        &ctx,
        &ry_token,
        "/system/flow/graph/submit",
        serde_json::json!({
            "flowCode": "it_graph_actions",
            "title": "动作收窄",
            "fields": {"days": 1}
        }),
    )
    .await;
    ctx.assert_ok(&v);
    let doc_id = v["data"]["docId"].as_i64().expect("docId");
    let task1 = admin_todo_task_for(&ctx, doc_id, 1).await;

    // delegate 经通用 action 端点分发；未在白名单 → 403
    let (status, _) = ctx
        .send_raw(token_request(
            &ctx,
            &ctx.token,
            Method::POST,
            &format!("/system/flow/task/{task1}/action"),
            Some(serde_json::json!({
                "action": "delegate",
                "toUserId": 2,
                "comment": "不在白名单"
            })),
        ))
        .await;
    assert_eq!(status, 403, "未勾 delegate 必须被白名单拦截: {status}");
}
