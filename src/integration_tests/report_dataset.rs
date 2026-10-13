//! 报表数据集集成测试（G-01 M1 验收欠账补齐，批次九）：
//! - CRUD 全链：建（合法 SELECT 模板）→ list → info → edit → preview → remove
//! - SQL 白名单 fail-closed：INSERT 模板 → 400
//! - 租户隔离：dataset 行归属租户 2 时，平台（tenant 0）操作者 ensure_access → 403
//!   （tenant_allowed 单向语义：平台操作租户行 = 越权，与 e2e 功能 74 同口径）
//!
//! 账号：admin（平台，tenant 0，持 report:dataset:* 全部权限）。

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

async fn put_json(
    ctx: &TestContext,
    token: &str,
    uri: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    ctx.send_json(token_request(ctx, token, Method::PUT, uri, Some(body)))
        .await
}

async fn get_json(ctx: &TestContext, token: &str, uri: &str) -> serde_json::Value {
    ctx.send_json(token_request(ctx, token, Method::GET, uri, None))
        .await
}

/// 链路：合法数据集 CRUD 全链 + 白名单拒绝 + preview
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_report_dataset_crud_chain() {
    let ctx = TestContext::new().await;
    let admin_token = ctx.token.clone();

    // 1) 新增（合法参数化 SELECT）
    let v = post_json(
        &ctx,
        &admin_token,
        "/report/dataset",
        serde_json::json!({
            "datasetCode": "it_ds_daily",
            "datasetName": "集成测试·日报数据集",
            "sqlTemplate": "SELECT user_id, user_name FROM sys_user WHERE status = :status",
            "paramsSchema": [{"name": "status", "type": "string", "required": true}],
            "status": "0",
            "remark": "it"
        }),
    )
    .await;
    ctx.assert_ok(&v);
    let dataset_id = v["data"]["datasetId"].as_i64().expect("应返回 datasetId");

    // 2) list 命中
    let v = get_json(
        &ctx,
        &admin_token,
        "/report/dataset/list?pageNum=1&pageSize=50",
    )
    .await;
    assert!(
        v["rows"]
            .as_array()
            .expect("rows 应为数组")
            .iter()
            .any(|r| r["datasetId"].as_i64() == Some(dataset_id)),
        "list 应含新建数据集: {v}"
    );

    // 3) SQL 明文经专用端点回填：admin（持 edit 键）得明文；info 出参恒无明文（零泄漏面）
    let v = post_json(
        &ctx,
        &admin_token,
        &format!("/report/dataset/{dataset_id}/sql"),
        serde_json::json!({}),
    )
    .await;
    ctx.assert_ok(&v);
    assert_eq!(
        v["data"].as_str(),
        Some("SELECT user_id, user_name FROM sys_user WHERE status = :status"),
        "持 edit 权限者经专用端点应得 SQL 明文，实际: {v}"
    );
    let v = get_json(&ctx, &admin_token, &format!("/report/dataset/{dataset_id}")).await;
    assert!(
        v["data"]["sqlTemplate"].is_null(),
        "info 出参不得携带 SQL 明文，实际: {v}"
    );

    // 3b) 无 edit 权限者调 SQL 端点 → 403（权限键 fail-closed 拦截）
    // 批次十三起 role 2 全量授权 G-01/G-02 菜单（用户拍板），种子 stepby 用户（role 2）
    // 已合法持有 report:dataset:edit ⇒ 临时摘除其角色构造"真正无权限者"，断言后恢复。
    {
        use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
        let db = &ctx.state.db;
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "DELETE FROM sys_user_role WHERE user_id = \
             (SELECT user_id FROM sys_user WHERE user_name = 'stepby')"
                .to_string(),
        ))
        .await
        .expect("摘除 stepby 角色失败");
        let stepby_token =
            super::login(&ctx.app, super::next_peer_ip(), "stepby", "admin123").await;
        let (status, _) = ctx
            .send_raw(token_request(
                &ctx,
                &stepby_token,
                Method::POST,
                &format!("/report/dataset/{dataset_id}/sql"),
                Some(serde_json::json!({})),
            ))
            .await;
        assert_eq!(
            status, 403,
            "无 edit 权限取 SQL 明文必须 403，实际: {status}"
        );
        // 恢复 stepby ↔ role 2（不影响其它用例的种子假设）
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO sys_user_role (user_id, role_id) \
             SELECT user_id, 2 FROM sys_user WHERE user_name = 'stepby'"
                .to_string(),
        ))
        .await
        .expect("恢复 stepby 角色失败");
    }

    // 4) 非法模板（INSERT）→ 400（白名单 fail-closed；走 send_raw，不触发 200 断言）
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &admin_token,
            Method::POST,
            "/report/dataset",
            Some(serde_json::json!({
                "datasetCode": "it_ds_bad",
                "datasetName": "非法模板",
                "sqlTemplate": "DELETE FROM sys_user",
                "status": "0"
            })),
        ))
        .await;
    assert_eq!(status, 400, "DML 模板必须 400，实际: {status} {body}");
    assert!(
        body["msg"]
            .as_str()
            .unwrap_or_default()
            .contains("SQL 模板校验失败"),
        "错误消息应来自白名单校验器: {body}"
    );

    // 5) preview（带参数）→ 返回列与行
    let v = post_json(
        &ctx,
        &admin_token,
        "/report/dataset/preview",
        serde_json::json!({
            "datasetId": dataset_id,
            "params": {"status": "0"}
        }),
    )
    .await;
    ctx.assert_ok(&v);
    // G-01 M3：columns_meta 走临时视图探针——应返回真实列名（而非 colN 占位）
    let cols = v["data"]["columns"]
        .as_array()
        .expect("columns 应为数组")
        .iter()
        .map(|c| c.as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert!(!cols.is_empty(), "preview 应返回列元数据");
    assert!(
        cols.iter()
            .all(|c| !c.starts_with("col1") || *c == "user_id"),
        "探针应取真实列名，实际: {cols:?}"
    );
    assert!(
        cols.contains(&"user_id".to_string()) && cols.contains(&"user_name".to_string()),
        "探针应取到真实列名 user_id/user_name，实际: {cols:?}"
    );

    // 6) 编辑（改名）
    let v = put_json(
        &ctx,
        &admin_token,
        "/report/dataset",
        serde_json::json!({
            "datasetId": dataset_id,
            "datasetCode": "it_ds_daily",
            "datasetName": "集成测试·日报数据集（改）",
            "sqlTemplate": "SELECT user_id, user_name FROM sys_user WHERE status = :status",
            "status": "0"
        }),
    )
    .await;
    ctx.assert_ok(&v);

    // 7) 删除
    let v = ctx
        .send_json(token_request(
            &ctx,
            &admin_token,
            Method::DELETE,
            &format!("/report/dataset/{dataset_id}"),
            None,
        ))
        .await;
    ctx.assert_ok(&v);
    // 删除后 info 应 not_found——用 send_raw（get_json 内部断言 200，无法表达预期 404）
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &admin_token,
            Method::GET,
            &format!("/report/dataset/{dataset_id}"),
            None,
        ))
        .await;
    assert_eq!(
        status, 404,
        "删除后 info 应 not_found（数据集不存在），实际: {status} {body}"
    );
}
