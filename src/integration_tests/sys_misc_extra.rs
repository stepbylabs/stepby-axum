//! sys_job 相关低覆盖受保护端点的补充集成测试。
//!
//! sys_job.rs 已覆盖：list / 详情 / add / edit / changeStatus / run /
//! 无效 cron(400) / 删除任务 / jobLog list / jobLog 删除 / jobLog 空 id(400)。
//!
//! 本文件补齐 sys_job.rs 未覆盖、且路由真实存在的确定性端点：
//! - POST /monitor/job/export         导出任务列表（form → Excel 二进制，HTTP 200）
//! - POST /monitor/jobLog/export      导出任务日志（form → Excel 二进制，HTTP 200）
//! - DELETE /monitor/jobLog/clean     清空全部任务日志（code 200）
//! - DELETE /monitor/job/{emptyId}    空任务 ID 列表删除 → 400
//!
//! 不存在 resetCron / runOne 路由，故不测试。

use super::TestContext;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;
use tower::ServiceExt;

/// 构造带鉴权头 + ConnectInfo 的 form-urlencoded 导出请求。
fn form_request(ctx: &TestContext, uri: &str, form_body: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {}", ctx.token))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body.to_string()))
        .expect("构造 form 请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// 导出端点返回二进制 Excel：HTTP 200 且 content-type 含 spreadsheetml。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_job_and_job_log_export() {
    let ctx = TestContext::new().await;

    // POST /monitor/job/export（任务列表导出）
    let resp = ctx
        .app
        .clone()
        .oneshot(form_request(&ctx, "/monitor/job/export", ""))
        .await
        .expect("任务导出请求执行失败");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "任务导出应返回 HTTP 200，实际: {}",
        resp.status()
    );
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("spreadsheetml"),
        "任务导出应返回 Excel content-type，实际: {ct}"
    );

    // POST /monitor/jobLog/export（任务日志导出）
    let resp = ctx
        .app
        .clone()
        .oneshot(form_request(&ctx, "/monitor/jobLog/export", ""))
        .await
        .expect("任务日志导出请求执行失败");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "任务日志导出应返回 HTTP 200，实际: {}",
        resp.status()
    );
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("spreadsheetml"),
        "任务日志导出应返回 Excel content-type，实际: {ct}"
    );
}

/// 清空任务日志（DELETE /monitor/jobLog/clean）→ 业务码 200。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_job_log_clean() {
    let ctx = TestContext::new().await;

    // 先触发手动执行，确保存在日志可清（异步写入，失败仅 warn，clean 均能成功）
    let _ = ctx
        .put_json(
            "/monitor/job/run",
            serde_json::json!({ "jobId": 1, "jobGroup": "DEFAULT" }),
        )
        .await;

    let v = ctx.delete_json("/monitor/jobLog/clean").await;
    assert_eq!(v["code"], 200, "清空任务日志业务码应为 200，实际: {v}");

    // 清空后应无残留
    let v = ctx
        .get_json("/monitor/jobLog/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "清空后任务日志应为空，实际: {v}");
}

/// 删除任务时空 ID 列表 → HTTP 400（与 jobLog 空 id 校验一致）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_job_delete_empty_ids_returns_400() {
    let ctx = TestContext::new().await;
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/monitor/job/,", None))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "空任务 ID 删除应返回 400，实际: HTTP {status} body={v}"
    );
    assert_ne!(v["code"], 200, "空任务 ID 删除业务码不应为 200，实际: {v}");
}
