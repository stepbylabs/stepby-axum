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
    let v = ctx.delete_json(&format!("/system/task/{}", task_id)).await;
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

/// b144 A5：任务终态是终点——迟到的回调不得把已结束的任务改回 running，
/// 已成功的事实不得被一条迟到的失败抹掉，已失败的行不得被迟到的成功洗成"这轮跑好了"。
///
/// 判据取**库里的行**而不是返回值（返回值可以由同一次读兜出来）；每条断言都对应
/// 改造前一个真实可达的形状：改造前三者都是无条件整行 `update`，读与写之间没有任何
/// 约束，两个执行者各自读到未结束态、各自写回，后写的赢。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_task_terminal_states_are_final() {
    use crate::service::sys_task_service::{SysTaskService, TaskCreateDto};

    let ctx = TestContext::new().await;
    let svc = SysTaskService::new(ctx.state.db.clone());

    let mk = |name: &str| TaskCreateDto {
        task_type: "other".to_string(),
        task_name: name.to_string(),
        total: 10,
        operator_id: None,
    };

    // ---------- 分支 1：success 之后，进度回调与失败回调都必须被忽略 ----------
    let done = svc
        .create_task(mk("b144-done"), "system", 0, &ctx.state)
        .await
        .expect("创建任务应成功");
    let done_id = done.task_id;
    svc.complete_task(done_id, Some("ok".to_string()), &ctx.state)
        .await
        .expect("完成应成功");

    // 迟到的进度回调：不得把 success 改回 running、不得把 progress 从 100 拉低
    let after = svc
        .update_progress(done_id, 1, Some(10), &ctx.state)
        .await
        .expect("进度更新应返回行现状（不是错误）");
    assert_eq!(
        after.status, "success",
        "success 不得被改回 running: {after:?}"
    );
    assert_eq!(after.progress, 100, "进度不得倒退: {after:?}");
    assert_eq!(after.current, 10, "current 不得被迟到回调改写: {after:?}");

    // 迟到的失败回调：不得抹掉已完成的事实
    let after = svc
        .fail_task(done_id, "late failure".to_string(), &ctx.state)
        .await
        .expect("fail 应返回行现状");
    assert_eq!(after.status, "success", "已成功不得被改成失败: {after:?}");

    // 重复 complete 幂等（同一任务被两个执行者各收尾一次）
    let again = svc
        .complete_task(done_id, Some("second".to_string()), &ctx.state)
        .await
        .expect("重复 complete 必须幂等成功");
    assert_eq!(again.status, "success");

    // ---------- 分支 2：failed 之后，成功回调必须被忽略 ----------
    let bad = svc
        .create_task(mk("b144-bad"), "system", 0, &ctx.state)
        .await
        .expect("创建任务应成功");
    svc.fail_task(bad.task_id, "boom".to_string(), &ctx.state)
        .await
        .expect("fail 应成功");
    let after = svc
        .complete_task(bad.task_id, Some("late success".to_string()), &ctx.state)
        .await
        .expect("complete 应返回行现状");
    assert_eq!(
        after.status, "failed",
        "已失败不得被迟到的成功洗白: {after:?}"
    );
    assert_eq!(
        after.result_msg.as_deref(),
        Some("boom"),
        "失败原因不得被覆盖: {after:?}"
    );

    // ---------- 分支 3：未结束态照常推进（对照组——证明上面不是"永远拒绝"） ----------
    let live = svc
        .create_task(mk("b144-live"), "system", 0, &ctx.state)
        .await
        .expect("创建任务应成功");
    let stepped = svc
        .update_progress(live.task_id, 4, Some(10), &ctx.state)
        .await
        .expect("未结束态应能推进");
    assert_eq!(
        stepped.status, "running",
        "pending→running 应放行: {stepped:?}"
    );
    assert_eq!(stepped.progress, 40, "进度应写入: {stepped:?}");
    let settled = svc
        .complete_task(live.task_id, None, &ctx.state)
        .await
        .expect("对照组：正常链路仍能落终态");
    assert_eq!(settled.status, "success");
    assert_eq!(settled.current, 10);
}

/// b148：任务类型必须是白名单里的一种。
///
/// 判据取**错误本身**而不是"没崩"：开放字符串的失效形态不是崩溃，而是"入库成功但界面上
/// 解释不了"——那是一种比报错更差的结局，因为它看起来成功了。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_task_type_must_be_in_whitelist() {
    use crate::service::sys_task_service::{SysTaskService, TaskCreateDto, TASK_TYPES};

    let ctx = TestContext::new().await;
    let svc = SysTaskService::new(ctx.state.db.clone());

    for bad in ["it_probe_type", "export", "", "REPLAY"] {
        let dto = TaskCreateDto {
            task_type: bad.to_string(),
            task_name: format!("b148-bad-{bad}"),
            total: 1,
            operator_id: None,
        };
        let err = svc
            .create_task(dto, "system", 0, &ctx.state)
            .await
            .expect_err("白名单外的类型必须拒绝");
        assert_eq!(err.code, 400, "应是 400 而不是 500: {err:?}");
        // 空串会先被 garde 的长度校验拦下（"长度不能少于 1"），那条信息同样准确；
        // 只有"格式合法但不在白名单"的情形才需要把合法值列出来。
        if !bad.is_empty() {
            assert!(
                err.message.contains("operlog_export"),
                "错误信息必须列出合法值，否则调用方只能猜: {}",
                err.message
            );
        }
    }

    // 正控：白名单里的每一条都必须能建成（否则"白名单"等于把功能一起关掉）
    for good in TASK_TYPES {
        let dto = TaskCreateDto {
            task_type: (*good).to_string(),
            task_name: format!("b148-ok-{good}"),
            total: 1,
            operator_id: None,
        };
        let created = svc
            .create_task(dto, "system", 0, &ctx.state)
            .await
            .unwrap_or_else(|e| panic!("白名单类型 {good} 必须能创建: {e:?}"));
        assert_eq!(created.task_type, *good);
    }
}

/// b148：进度上报越界必须被收敛到 `[0, total]`，并让 `current` 与 `progress` 不再互相矛盾。
///
/// 改造前：`progress` 被 `min(100)` 夹住，而 `current` 原样入库 ⇒ 界面出现"120 / 100"且
/// 进度条满格；负的 `current` 还会让进度条反向。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_task_progress_is_clamped_to_total() {
    use crate::service::sys_task_service::{SysTaskService, TaskCreateDto};

    let ctx = TestContext::new().await;
    let svc = SysTaskService::new(ctx.state.db.clone());
    let task = svc
        .create_task(
            TaskCreateDto {
                task_type: "other".to_string(),
                task_name: "b148-clamp".to_string(),
                total: 10,
                operator_id: None,
            },
            "system",
            0,
            &ctx.state,
        )
        .await
        .expect("创建任务应成功");

    let over = svc
        .update_progress(task.task_id, 15, None, &ctx.state)
        .await
        .expect("越界上报不得报错（它是调用方的口径问题，不是本行的失败）");
    assert_eq!(over.current, 10, "current 必须收敛到 total: {over:?}");
    assert_eq!(over.progress, 100, "progress 必须满格且与 current 自洽: {over:?}");

    let under = svc
        .update_progress(task.task_id, -5, None, &ctx.state)
        .await
        .expect("负数上报同样不得报错");
    assert_eq!(under.current, 0, "current 必须夹到 0: {under:?}");
    assert_eq!(under.progress, 0, "progress 不得为负: {under:?}");
}

/// b148：未结束的任务不得删除。
///
/// 删掉之后，后台执行者的下一次进度/终态回调会拿到 404（一次真实工作变成"任务不存在"
/// 告警），而界面上它已经"处理完了"——既看不到进度也看不到失败原因。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_open_task_cannot_be_deleted() {
    use crate::service::sys_task_service::{SysTaskService, TaskCreateDto};

    let ctx = TestContext::new().await;
    let svc = SysTaskService::new(ctx.state.db.clone());
    let task = svc
        .create_task(
            TaskCreateDto {
                task_type: "other".to_string(),
                task_name: "b148-open".to_string(),
                total: 2,
                operator_id: None,
            },
            "system",
            0,
            &ctx.state,
        )
        .await
        .expect("创建任务应成功");

    let err = svc
        .delete_tasks(vec![task.task_id], 0)
        .await
        .expect_err("未结束的任务必须拒绝删除");
    assert_eq!(err.code, 400, "应是 400: {err:?}");
    assert!(
        err.message.contains(&task.task_id.to_string()),
        "错误信息必须点名是哪条任务: {}",
        err.message
    );
    assert!(
        svc.get_task_by_id(task.task_id, None).await.is_ok(),
        "拒绝删除后该任务必须还在（不能先删后拒）"
    );

    // 对照组：落终态之后必须能删（否则"拒绝"就成了永久禁止）
    svc.complete_task(task.task_id, Some("done".to_string()), &ctx.state)
        .await
        .expect("完成应成功");
    svc.delete_tasks(vec![task.task_id], 0)
        .await
        .expect("已结束的任务必须可删");
    assert!(
        svc.get_task_by_id(task.task_id, None).await.is_err(),
        "删除后应查不到"
    );
}
