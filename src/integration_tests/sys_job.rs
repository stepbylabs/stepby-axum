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
        v["data"]["jobName"], "系统默认（无参）",
        "任务名称应匹配种子数据，实际: {v}"
    );

    // 3. 新增任务（合法 6 字段 cron）
    let v = ctx
        .post_json(
            "/monitor/job",
            serde_json::json!({
                "jobName": "it_job_test_task",
                "jobGroup": "DEFAULT",
                "invokeTarget": "demoTask.demoNoParams",
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
                "invokeTarget": "demoTask.demoNoParams",
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
        v["data"]["jobName"], "it_job_test_task_edited",
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
                "invokeTarget": "demoTask.demoNoParams",
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
    let job_log_id = rows[0]["jobLogId"].as_i64().expect("jobLogId 应为数字");

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

/// **租户任务不得指向平台专属 invoke_target**（b144，AGENTS 铁律「多租户」）。
///
/// 立案：`invoke_target` 是注册表查表调用 ⇒ "租户能填哪个目标"就是"租户能跑哪段代码"。
/// 改造前所有注册项一视同仁，租户管理员建一条 `cleanup_expired_logs` 的任务并点
/// 「执行一次」，就会触发**跨租户保留期清理**（删所有租户的
/// `sys_oper_log` / `sys_logininfor` / `sys_audit_change`，并推进平台标记
/// `retention:last_success_at`）。
///
/// 三条判据方向刻意不同，缺一都会让"闸"退化成"永远拒绝"：
/// ① 租户 + 平台专属目标 ⇒ 403 且**一行都不落库**；
/// ② 对照组：平台（tid=0）+ 同一目标 ⇒ 照常成功；
/// ③ 对照组：租户 + 租户中性目标（`demoTask.*`）⇒ 照常成功（能力没被砍掉）。
/// 编辑路径同样判，且用**行的归属租户**而不是操作者——平台代管租户行时
/// 执行侧读的仍是 `job.tenant_id`。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_tenant_job_cannot_target_platform_only_task() {
    use crate::service::sys_job_service::{JobAddDto, JobEditDto, SysJobService};

    let ctx = TestContext::new().await;
    let svc: &SysJobService = &ctx.state.job_service;

    let add_dto = |name: &str, target: &str| JobAddDto {
        job_name: name.to_string(),
        job_group: "DEFAULT".to_string(),
        invoke_target: target.to_string(),
        cron_expression: "0 0 4 * * *".to_string(),
        // status='1' = 暂停：用例不需要它真的被调度执行，只要保存路径受约束
        misfire_policy: Some("3".to_string()),
        concurrent: Some("1".to_string()),
        status: Some("1".to_string()),
        remark: Some("b144 档位闸用例".to_string()),
    };

    async fn list_rows(ctx: &TestContext, name: &str) -> Vec<serde_json::Value> {
        let v = ctx
            .get_json(&format!("/monitor/job/list?jobName={name}"))
            .await;
        v["rows"].as_array().cloned().unwrap_or_default()
    }

    // ① 租户 + 平台专属目标 ⇒ 403，且不得落库
    let denied = svc
        .add_job(
            add_dto("it_b144_denied", "cleanup_expired_logs"),
            "tenantadmin",
            7,
        )
        .await
        .expect_err("租户任务指向平台专属 invoke_target 必须被拒（否则可跨租户删日志）");
    assert_eq!(denied.code, 403, "实际码值 {}", denied.code);
    assert!(
        !denied.message.is_empty() && !denied.message.contains("error."),
        "必须是可读文案而非裸 i18n 键，实际: {}",
        denied.message
    );
    assert!(
        denied.message.contains("cleanup_expired_logs"),
        "拒绝必须点名是哪个目标，否则管理员只能盲猜，实际: {}",
        denied.message
    );
    assert!(
        list_rows(&ctx, "it_b144_denied").await.is_empty(),
        "被拒的新增一行都不许落库"
    );

    // ② 对照组：平台（tid=0）同一目标 ⇒ 照常成功（证明这不是一条"永远拒绝"的闸）
    let platform_job = svc
        .add_job(
            add_dto("it_b144_platform", "cleanup_expired_logs"),
            "admin",
            0,
        )
        .await
        .expect("平台任务触发平台专属目标必须放行（对照组）");

    // ③ 对照组：租户 + 租户中性目标 ⇒ 照常成功（示例任务这项既有能力不得消失）
    let tenant_job = svc
        .add_job(
            add_dto("it_b144_tenant_neutral", "demoTask.demoNoParams"),
            "tenantadmin",
            7,
        )
        .await
        .expect("租户任务指向租户中性目标必须放行（能力齐备，不得整块砍掉）");
    assert_eq!(tenant_job.tenant_id, 7, "新行必须归属该租户");

    // ④ 编辑路径：把租户已有的任务改成平台专属目标 ⇒ 403 且存量行一字未改
    let edit = |job_id: i64, target: &str| JobEditDto {
        job_id,
        job_name: "it_b144_tenant_neutral".to_string(),
        job_group: "DEFAULT".to_string(),
        invoke_target: target.to_string(),
        cron_expression: "0 0 4 * * *".to_string(),
        misfire_policy: Some("3".to_string()),
        concurrent: Some("1".to_string()),
        status: Some("1".to_string()),
        remark: Some("b144 档位闸用例".to_string()),
    };
    let edit_err = svc
        .edit_job(edit(tenant_job.job_id, "cleanup_expired_logs"), "admin", 0)
        .await
        // 操作者是平台（tid=0），但**行的归属**是租户 7 ⇒ 仍必须拒：
        // 执行侧判据取 job.tenant_id，若这里放行就会留下"保存成功、每次执行都失败"的行。
        .expect_err("平台代管租户行时，档位闸仍按行的归属租户判定");
    assert_eq!(edit_err.code, 403, "实际码值 {}", edit_err.code);
    let rows = list_rows(&ctx, "it_b144_tenant_neutral").await;
    assert_eq!(rows.len(), 1, "存量行必须还在，实际 {rows:?}");
    assert_eq!(
        rows[0]["invokeTarget"].as_str(),
        Some("demoTask.demoNoParams"),
        "被拒的编辑一字不得写进存量行"
    );

    // ⑤ 反向对照：同一行改成租户中性目标必须成功（否则 ④ 读成"编辑永远失败"）
    svc.edit_job(
        edit(tenant_job.job_id, "demoTask.demoParams('demo')"),
        "tenantadmin",
        7,
    )
    .await
    .expect("改成租户中性目标必须放行");

    // 收尾：手工探针必须自带回收（用例造的三行都删掉，避免污染数据面审计）
    svc.delete_jobs(vec![platform_job.job_id], "admin", 0)
        .await
        .expect("回收平台用例任务");
    svc.delete_jobs(vec![tenant_job.job_id], "tenantadmin", 7)
        .await
        .expect("回收租户用例任务");
    assert!(list_rows(&ctx, "it_b144_platform").await.is_empty());
    assert!(list_rows(&ctx, "it_b144_tenant_neutral").await.is_empty());
}
