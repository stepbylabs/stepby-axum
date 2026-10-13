//! 流程定义集成测试（G-02 M1 验收欠账补齐 + 批次十二设计器能力位收口）：
//! - CRUD 全链：add → list → info → edit → publish（version+1 / is_latest 切换）→
//!   remove（软删）→ info 404
//! - graph_json fail-closed：非法图直投 API → 400（后端复验兜底，防绕过前端）
//! - 设计器能力位守卫（`flow.designer` / `report.designer`，批次十二接入端点消费）：
//!   租户（套餐 features 未开通）写面 403 fail-closed + 读面放行；
//!   平台操作者（tid=0）不受能力位限制（与 nav.l3 同语义）。
//!   三档语义矩阵（off/view/full × 平台/租户）由 `common::features` 纯函数单测锁定，
//!   此处锁真实 DB 链路（套餐行 → tenant_features_conn → 守卫）的 fail-closed 姿态。
//!
//! 账号：admin（平台，tenant 0，持 flow:definition:* / report:dataset:* 全部权限）。

use super::TestContext;
use crate::service::flow_definition_service::{FlowDefUpsertDto, FlowDefinitionService};
use crate::service::report_dataset_service::{DatasetUpsertDto, ReportDatasetService};
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
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

/// 合法 BPMN-lite 图（start → dept_leader 审批 → end，最小合法骨架）
fn valid_graph_json() -> String {
    serde_json::json!({
        "nodes": [
            {"id": "start", "type": "start", "name": "开始"},
            {"id": "a1", "type": "approve", "name": "主管审批", "assignees": ["dept_leader"], "multi": "single", "threshold": 1, "actions": []},
            {"id": "end", "type": "end", "name": "结束"}
        ],
        "edges": [
            {"from": "start", "to": "a1"},
            {"from": "a1", "to": "end"}
        ]
    })
    .to_string()
}

/// 变体图（审批节点名不同）——用于验证"已发布版本不可改图"的差分判定
fn variant_graph_json() -> String {
    serde_json::json!({
        "nodes": [
            {"id": "start", "type": "start", "name": "开始"},
            {"id": "a1", "type": "approve", "name": "主管审批（改）", "assignees": ["dept_leader"], "multi": "single", "threshold": 1, "actions": []},
            {"id": "end", "type": "end", "name": "结束"}
        ],
        "edges": [
            {"from": "start", "to": "a1"},
            {"from": "a1", "to": "end"}
        ]
    })
    .to_string()
}

/// 链路：合法定义 CRUD 全链 + 发布版本机制 + 软删后 404
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_definition_crud_chain() {
    let ctx = TestContext::new().await;
    let admin_token = ctx.token.clone();

    // 1) 新增（草稿，version=1）
    let v = post_json(
        &ctx,
        &admin_token,
        "/system/flow/definition",
        serde_json::json!({
            "flowCode": "it_def_leave",
            "flowName": "集成测试·请假流程",
            "graphJson": valid_graph_json(),
            "remark": "it"
        }),
    )
    .await;
    ctx.assert_ok(&v);
    let flow_id = v["data"]["flowId"].as_i64().expect("应返回 flowId");
    assert_eq!(v["data"]["version"].as_i64(), Some(1), "新增即 version=1");
    assert_eq!(v["data"]["isLatest"].as_str(), Some("0"), "草稿非 latest");

    // 2) list 命中
    let v = get_json(
        &ctx,
        &admin_token,
        "/system/flow/definition/list?pageNum=1&pageSize=50&flowCode=it_def_leave",
    )
    .await;
    assert!(
        v["rows"]
            .as_array()
            .expect("rows 应为数组")
            .iter()
            .any(|r| r["flowId"].as_i64() == Some(flow_id)),
        "list 应含新建定义: {v}"
    );

    // 3) info 命中
    let v = get_json(
        &ctx,
        &admin_token,
        &format!("/system/flow/definition/{flow_id}"),
    )
    .await;
    ctx.assert_ok(&v);
    assert_eq!(v["data"]["flowCode"].as_str(), Some("it_def_leave"));

    // 4) edit（草稿态改名）
    let v = put_json(
        &ctx,
        &admin_token,
        "/system/flow/definition",
        serde_json::json!({
            "flowId": flow_id,
            "flowCode": "it_def_leave",
            "flowName": "集成测试·请假流程v2",
            "graphJson": valid_graph_json()
        }),
    )
    .await;
    ctx.assert_ok(&v);
    assert_eq!(v["data"]["flowName"].as_str(), Some("集成测试·请假流程v2"));

    // 5) publish：version+1 新行 is_latest='1' status='1'
    let v = ctx
        .send_json(token_request(
            &ctx,
            &admin_token,
            Method::POST,
            &format!("/system/flow/definition/publish/{flow_id}"),
            None,
        ))
        .await;
    ctx.assert_ok(&v);
    let published_id = v["data"]["flowId"].as_i64().expect("发布应返回新行 flowId");
    assert_eq!(
        v["data"]["version"].as_i64(),
        Some(2),
        "发布后 version 应为 2: {v}"
    );
    assert_ne!(published_id, flow_id, "发布产生新版本行（历史保留）");

    // 6) 已发布版本不可改图 → 400（发**不同图**——改名合法、改图拦截）
    let (status, _) = ctx
        .send_raw(token_request(
            &ctx,
            &admin_token,
            Method::PUT,
            "/system/flow/definition",
            Some(serde_json::json!({
                "flowId": published_id,
                "flowCode": "it_def_leave",
                "flowName": "试图改已发布版本",
                "graphJson": variant_graph_json()
            })),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "已发布版本改图必须 400");

    // 7) 软删后 list 不再显示、info 404
    let (status, _) = ctx
        .send_raw(token_request(
            &ctx,
            &admin_token,
            Method::DELETE,
            &format!("/system/flow/definition/{published_id}"),
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "删除应成功");
    let (status, _) = ctx
        .send_raw(token_request(
            &ctx,
            &admin_token,
            Method::GET,
            &format!("/system/flow/definition/{published_id}"),
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "软删后 info 必须 404");

    // teardown：物理清理本用例创建的 flow_definition（含软删行），防 it_ 残留累积
    super::cleanup_flow_defs(&ctx, &["it_def_leave"]).await;
}

/// graph_json fail-closed：非法图（断链）直投 API → 400
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_definition_invalid_graph_rejected() {
    let ctx = TestContext::new().await;
    // 断链图：start 不可达 a2（无边）——负路径断言必须 send_raw（send_json 内部断言 code==200）
    let (status, body) = ctx
        .send_raw(token_request(
            &ctx,
            &ctx.token,
            Method::POST,
            "/system/flow/definition",
            Some(
                serde_json::json!({
                    "flowCode": "it_def_broken",
                    "flowName": "断链图",
                    "graphJson": serde_json::json!({
                        "nodes": [
                            {"id": "start", "type": "start", "name": "开始"},
                            {"id": "a2", "type": "approve", "name": "孤立审批", "assignees": ["dept_leader"]}
                        ],
                        "edges": []
                    })
                    .to_string()
                }),
            ),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "断链图必须 HTTP 400: {body}"
    );
}

/// 构造「套餐 features=NULL + 租户」→ 租户有效能力集恒全 off（平台天花板 fail-closed）。
/// 命名空间隔离：套餐 9252 / 租户 9052（避开 capability 9250/9050 与 ai 901/2）。
async fn insert_off_package_tenant(ctx: &TestContext) {
    let db = &ctx.state.db;
    let backend = DatabaseBackend::Sqlite;
    db.execute_raw(Statement::from_sql_and_values(
        backend,
        "INSERT OR IGNORE INTO sys_tenant_package (package_id, package_name, menu_ids, features, default_account_count, status, del_flag) \
         VALUES (9252, 'designer-pkg', NULL, NULL, 0, '0', '0')",
        [],
    ))
    .await
    .expect("插入套餐失败");
    db.execute_raw(Statement::from_sql_and_values(
        backend,
        "INSERT OR IGNORE INTO sys_tenant (tenant_id, tenant_code, tenant_name, package_id, status, del_flag) \
         VALUES (9052, 'it_des', 'IT-DES', 9252, '0', '0')",
        [],
    ))
    .await
    .expect("插入租户失败");
}

/// flow.designer 守卫（service 层真实 DB 链路）：
/// 租户（off 档）写面 403 fail-closed + 读面放行；平台（tid=0）写面放行
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_flow_designer_tenant_gating() {
    let ctx = TestContext::new().await;
    insert_off_package_tenant(&ctx).await;
    let svc = FlowDefinitionService::new(ctx.state.db.clone());

    // 租户写面：off 档 fail-closed 403
    let dto = FlowDefUpsertDto {
        flow_id: None,
        flow_code: "it_gd_tenant".to_string(),
        flow_name: "租户尝试建定义".to_string(),
        graph_json: valid_graph_json(),
        remark: None,
    };
    let err = svc
        .add(dto, "t2", 9052)
        .await
        .expect_err("租户 off 档写面必须被拒");
    assert_eq!(err.code, 403, "flow.designer off 档租户写面必须 403");

    // 租户读面：放行（列表可见本租户空集）
    let (rows, total) = svc.get_page(0, 10, None, 9052).await.expect("读面应放行");
    assert_eq!(total, 0);
    assert!(rows.is_empty());

    // 平台（tid=0）不受能力位限制：写面放行
    let dto = FlowDefUpsertDto {
        flow_id: None,
        flow_code: "it_gd_platform".to_string(),
        flow_name: "平台建定义".to_string(),
        graph_json: valid_graph_json(),
        remark: None,
    };
    let vo = svc
        .add(dto, "admin", 0)
        .await
        .expect("平台 tid=0 写面不受能力位限制");
    assert_eq!(vo.version, 1);

    // 租户 publish/remove 同样被守卫拦截（写面全覆盖）
    let err = svc
        .publish(vo.flow_id, "t2", 9052)
        .await
        .expect_err("租户 off 档发布必须被拒");
    assert_eq!(err.code, 403, "flow.designer off 档租户发布必须 403");
    let err = svc
        .remove(vec![vo.flow_id], "t2", 9052)
        .await
        .expect_err("租户 off 档删除必须被拒");
    assert_eq!(err.code, 403, "flow.designer off 档租户删除必须 403");

    // teardown：物理清理平台侧创建的流程定义（it_gd_tenant 被 403 拒绝，未落库）
    super::cleanup_flow_defs(&ctx, &["it_gd_platform"]).await;
}

/// report.designer 守卫（service 层真实 DB 链路，与 flow 同构）：
/// 租户（off 档）写面 403 fail-closed + 读面放行；平台（tid=0）写面放行
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_report_designer_tenant_gating() {
    let ctx = TestContext::new().await;
    insert_off_package_tenant(&ctx).await;
    let svc = ReportDatasetService::new(ctx.state.db.clone());

    // 租户写面：off 档 fail-closed 403
    let dto = DatasetUpsertDto {
        dataset_id: None,
        dataset_code: "it_ds_g_tenant".to_string(),
        dataset_name: "租户尝试建数据集".to_string(),
        sql_template: "SELECT user_id FROM sys_user".to_string(),
        params_schema: None,
        status: None,
        remark: None,
    };
    let err = svc
        .add_dataset(dto, "t2", 9052)
        .await
        .expect_err("租户 off 档写面必须被拒");
    assert_eq!(err.code, 403, "report.designer off 档租户写面必须 403");

    // 租户读面：放行
    let (rows, total) = svc.get_dataset_page(0, 10, 9052).await.expect("读面应放行");
    assert_eq!(total, 0);
    assert!(rows.is_empty());

    // 平台（tid=0）不受能力位限制：写面放行（大屏写面同一守卫）
    let dto = DatasetUpsertDto {
        dataset_id: None,
        dataset_code: "it_ds_g_platform".to_string(),
        dataset_name: "平台建数据集".to_string(),
        sql_template: "SELECT user_id FROM sys_user".to_string(),
        params_schema: None,
        status: None,
        remark: None,
    };
    let vo = svc
        .add_dataset(dto, "admin", 0)
        .await
        .expect("平台 tid=0 写面不受能力位限制");
    assert!(vo.dataset_id > 0);

    // 大屏 save_dashboard 守卫（租户 off 403）
    let err = svc
        .save_dashboard(
            crate::service::report_dataset_service::DashboardUpsertDto {
                dashboard_id: None,
                dashboard_code: "it_db_g".to_string(),
                dashboard_name: "租户尝试建大屏".to_string(),
                layout_json: serde_json::json!({"schemaVersion": 1}),
                status: None,
                remark: None,
            },
            "t2",
            9052,
        )
        .await
        .expect_err("租户 off 档大屏写面必须被拒");
    assert_eq!(err.code, 403, "report.designer off 档大屏写面必须 403");
}
