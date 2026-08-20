//! 定时任务 + 任务日志模块链路集成测试：
//! - 定时任务：分页列表 / 详情 / 新增 → 修改 → 删除 / 状态切换 / 手动执行一次 / cron 校验
//! - 定时任务日志：分页列表 / 批量删除（含空 id 参数校验）
//!
//! 说明：
//! - 种子已有 3 条任务（job_id 1/2/3，invoke_target 已注册到调度器注册表），可复用做只读断言与手动执行。
//! - 手动执行 run_once 会 spawn 后台任务并立即返回；任务日志为异步写入，查询前需轮询等待。

use super::TestContext;
use axum::http::{Method, StatusCode};
use std::time::Duration;

/// 定时任务全链路：分页列表 → 详情 → 新增 → 修改 → 状态切换 → 手动执行 → 日志 → 删除。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_job_chain() {
    let ctx = TestContext::new().await;

    // 1. 分页列表（种子已有 3 条任务）
    let v = ctx
        .get_json("/monitor/job/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.len() >= 3, "种子应至少 3 条定时任务，实际: {v}");

    // 2. 详情查询（job_id=1；JobVo 展平 SysJobModel，字段在顶层）
    let v = ctx.get_json("/monitor/job/1").await;
    assert_eq!(v["data"]["jobId"], 1, "任务详情 jobId 应为 1，实际: {v}");
    assert_eq!(
        v["data"]["jobName"],
        "系统默认（无参）",
        "任务名称应匹配种子数据，实际: {v}"
    );

    // 3. 新增任务（合法 6 字段 cron）
    let v = ctx
        .post_json(
            "/monitor/job",
            serde_json::json!({
                "jobName": "it_job_test_task",
                "jobGroup": "DEFAULT",
                "invokeTarget": "ryTask.ryNoParams",
                "cronExpression": "0 0 1 * * *",
                "misfirePolicy": "3",
                "concurrent": "1",
                "status": "0",
                "remark": "集成测试新增任务"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 4. 按任务名称过滤查询到新任务
    let v = ctx
        .get_json("/monitor/job/list?jobName=it_job_test_task")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 条新增任务，实际: {v}");
    let job_id = rows[0]["jobId"].as_i64().expect("jobId 应为数字");

    // 5. 修改任务
    let v = ctx
        .put_json(
            "/monitor/job",
            serde_json::json!({
                "jobId": job_id,
                "jobName": "it_job_test_task_edited",
                "jobGroup": "DEFAULT",
                "invokeTarget": "ryTask.ryNoParams",
                "cronExpression": "0 0 2 * * *",
                "misfirePolicy": "3",
                "concurrent": "1",
                "status": "0",
                "remark": "集成测试修改后"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/monitor/job/{}", job_id)).await;
    assert_eq!(
        v["data"]["jobName"],
        "it_job_test_task_edited",
        "修改后任务名称应生效，实际: {v}"
    );

    // 6. 状态切换（0→1：正常→暂停）
    let v = ctx
        .put_json(
            "/monitor/job/changeStatus",
            serde_json::json!({
                "jobId": job_id,
                "status": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/monitor/job/{}", job_id)).await;
    assert_eq!(v["data"]["status"], "1", "状态应为 1(暂停)，实际: {v}");

    // 7. 无效 cron 表达式新增应拒绝（400）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/monitor/job",
            Some(serde_json::json!({
                "jobName": "it_job_invalid_cron",
                "jobGroup": "DEFAULT",
                "invokeTarget": "ryTask.ryNoParams",
                "cronExpression": "invalid cron",
                "status": "0"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "无效 cron 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "无效 cron 应返回 400，实际: {status}"
    );

    // 8. 手动执行一次种子任务（job_id=1，invoke_target 已注册，返回即 ok）
    let v = ctx
        .put_json(
            "/monitor/job/run",
            serde_json::json!({
                "jobId": 1,
                "jobGroup": "DEFAULT"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 9. 任务日志分页查询（run 后台异步写日志，轮询等待至非空）
    let rows = poll_job_logs(&ctx).await;
    assert!(!rows.is_empty(), "执行任务后应有日志记录");

    // 10. 删除新增的测试任务
    let v = ctx.delete_json(&format!("/monitor/job/{}", job_id)).await;
    ctx.assert_ok(&v);
    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, &format!("/monitor/job/{}", job_id), None))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除后查询该任务应 404，实际: {status}"
    );
}

/// 任务日志操作链路：列表过滤 → 批量删除单条 → 空 id 参数校验（400）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_job_log_chain() {
    let ctx = TestContext::new().await;

    // 1. 触发手动执行种子任务 job_id=2 生成至少一条日志
    let v = ctx
        .put_json(
            "/monitor/job/run",
            serde_json::json!({
                "jobId": 2,
                "jobGroup": "DEFAULT"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 2. 分页查询任务日志（轮询等待异步日志写入）
    let rows = poll_job_logs(&ctx).await;
    assert!(!rows.is_empty(), "应有至少一条任务日志");

    // 3. 按 jobName 过滤（种子 job 2 名称为"系统默认（有参）"）
    let v = ctx
        .get_json("/monitor/jobLog/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(!rows.is_empty(), "分页应能查到任务日志，实际: {v}");

    // 4. 获取第一条日志 id 用于删除测试
    let job_log_id = rows[0]["jobLogId"]
        .as_i64()
        .expect("jobLogId 应为数字");

    // 5. 批量删除单条日志
    let v = ctx
        .delete_json(&format!("/monitor/jobLog/{}", job_log_id))
        .await;
    ctx.assert_ok(&v);

    // 6. 空 id 列表删除应返回 400（路径参数为逗号，解析后为空）
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/monitor/jobLog/,", None))
        .await;
    assert_ne!(v["code"], 200, "空 id 删除业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "空 id 删除应返回 400，实际: {status}"
    );
}

/// 轮询任务日志列表直至非空（最多等待 ~2s，容忍 run 后台异步写日志的时序）。
async fn poll_job_logs(ctx: &TestContext) -> Vec<serde_json::Value> {
    let mut last: Vec<serde_json::Value> = Vec::new();
    for _ in 0..10 {
        let v = ctx
            .get_json("/monitor/jobLog/list?pageNum=1&pageSize=20")
            .await;
        let rows = v["rows"].as_array().expect("rows 应为数组");
        if !rows.is_empty() {
            return rows.clone();
        }
        last = rows.clone();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    last
}
