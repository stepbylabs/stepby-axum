//! 任务进度中心（系统任务）模块链路集成测试：
//! - 任务进度中心只有 list / detail / delete 三个 HTTP 路由；任务创建由其他业务模块触发
//!   （本测试通过 oper_log 字段选择导出流程间接创建一条任务，覆盖完整"创建 → 列表 → 详情 → 删除"链路）。
//! - 分页列表 / 详情 / 批量删除 / 空 id 参数校验。
//!
//! 数据前缀：it_task

use super::TestContext;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

/// 通过 oper_log 导出（带 fields 字段）间接创建一条任务，随后验证列表 / 详情 / 删除链路。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_task_chain() {
    let ctx = TestContext::new().await;

    // 1. 初始列表应为空（无种子任务数据）
    let v = ctx
        .get_json("/system/task/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "初始不应有任务数据，实际: {v}");

    // 2. 触发 oper_log 字段选择导出，间接创建并完成任务（返回 Excel 二进制，HTTP 200）
    let mut req = Request::builder()
        .method("POST")
        .uri("/monitor/operlog/export")
        .header("authorization", format!("Bearer {}", ctx.token))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("fields=title,operName".to_string()))
        .expect("构造导出请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, _) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "oper_log 导出应返回 HTTP 200，实际: {status}"
    );

    // 3. 任务列表应能查到该任务（task_type=operlog_export，状态 success）
    let v = ctx
        .get_json("/system/task/list?taskType=operlog_export&pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条导出任务，实际: {v}");
    let task_id = rows[0]["taskId"].as_i64().expect("taskId 应为数字");
    assert_eq!(
        rows[0]["taskType"], "operlog_export",
        "任务类型应为 operlog_export，实际: {v}"
    );
    assert_eq!(
        rows[0]["status"], "success",
        "导出完成后任务应标记为 success，实际: {v}"
    );
    assert_eq!(rows[0]["progress"], 100, "进度应为 100，实际: {v}");

    // 4. 任务详情
    let v = ctx.get_json(&format!("/system/task/{}", task_id)).await;
    assert_eq!(
        v["data"]["taskId"], task_id,
        "任务详情 taskId 应匹配，实际: {v}"
    );
    assert_eq!(
        v["data"]["operator"], "system",
        "系统任务 operator 应为 system，实际: {v}"
    );

    // 5. 批量删除该任务
    let v = ctx
        .delete_json(&format!("/system/task/{}", task_id))
        .await;
    ctx.assert_ok(&v);

    // 6. 删除后详情应 404
    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, &format!("/system/task/{}", task_id), None))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除后查询任务应 404，实际: {status}"
    );

    // 7. 空 id 列表删除应返回 400
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/system/task/,", None))
        .await;
    assert_ne!(v["code"], 200, "空 id 删除业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "空 id 删除应返回 400，实际: {status}"
    );
}
