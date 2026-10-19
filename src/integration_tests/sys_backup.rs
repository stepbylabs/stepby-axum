//! 数据备份/恢复模块链路集成测试：
//! - 备份日志：分页列表 / 详情 / 创建手动备份 / 批量删除 / 空 id 参数校验
//! - 危险端点（下载 / 恢复）：仅测试参数校验与 404/400 分支，避免在测试库上执行真实恢复改写数据
//!
//! 说明：
//! - 种子无备份数据，初始列表为空。
//! - 创建备份需调用 sqlite3 CLI 子进程（本机缺失时记录 failed 日志并返回 500），
//!   测试对"成功/失败"两种结局均做确定性断言（成功或失败都会落一条日志）。
//! - 手动创建备份带 60s Redis 限流锁，60s 内二次创建必然返回 400（确定性）。
//! - 恢复是高危操作（会真实改写数据库），只对不存在的 backupId 断言 404，不触发真实恢复。

use super::TestContext;
use axum::http::{Method, StatusCode};

/// 备份全链路：空列表 → 创建 → 列表 → 详情 → 限流 400 → 下载/恢复 404 → 删除 → 空 id 400。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_backup_chain() {
    let ctx = TestContext::new().await;

    // 1. 初始列表应为空（无种子备份数据）
    let v = ctx
        .get_json("/system/backup/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "初始不应有备份数据，实际: {v}");

    // 2. 创建手动备份（依赖 sqlite3 CLI，缺失时记录 failed 日志并返回 500，两种结局都允许）
    let (create_status, v) = ctx
        .send_raw(ctx.request(Method::POST, "/system/backup", None))
        .await;
    let created_ok = create_status == StatusCode::OK;
    if created_ok {
        ctx.assert_ok(&v);
    }

    // 3. 列表应恰好 1 条 manual 备份（成功/失败都会落日志），状态与创建结果一致
    let v = ctx
        .get_json("/system/backup/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应恰好 1 条备份日志，实际: {v}");
    assert_eq!(
        rows[0]["backupType"], "manual",
        "备份类型应为 manual，实际: {v}"
    );
    assert_eq!(rows[0]["createBy"], "admin", "操作人应为 admin，实际: {v}");
    let backup_id = rows[0]["backupId"].as_i64().expect("backupId 应为数字");
    let row_status = rows[0]["status"]
        .as_str()
        .expect("备份日志应有 status")
        .to_string();
    assert_eq!(
        row_status == "success",
        created_ok,
        "备份日志状态应与创建结果一致，实际: {v}"
    );

    // 4. 详情
    let v = ctx.get_json(&format!("/system/backup/{}", backup_id)).await;
    assert_eq!(
        v["data"]["backupId"], backup_id,
        "备份详情 backupId 应匹配，实际: {v}"
    );

    // 5. 60s 内二次创建应被限流拒绝（400，确定性）
    let (status, v) = ctx
        .send_raw(ctx.request(Method::POST, "/system/backup", None))
        .await;
    assert_ne!(v["code"], 200, "限流拒绝业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "二次创建应 400（限流），实际: {status}"
    );

    // 6. 下载已创建备份：success 且文件存在时 200；failed 时 400
    let (status, _) = ctx
        .send_raw(ctx.request(
            Method::GET,
            &format!("/system/backup/download/{}", backup_id),
            None,
        ))
        .await;
    if row_status == "success" {
        assert_eq!(
            status,
            StatusCode::OK,
            "success 备份应可下载，实际: {status}"
        );
    } else {
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "failed 备份下载应 400，实际: {status}"
        );
    }

    // 7. 下载不存在的备份 → 404
    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, "/system/backup/download/999999", None))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "下载不存在的备份应 404，实际: {status}"
    );

    // 8. 恢复不存在的备份 → 404（恢复为高危操作，仅测 404 分支，避免真实改写测试库）
    let (status, _) = ctx
        .send_raw(ctx.request(Method::POST, "/system/backup/restore/999999", None))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "恢复不存在的备份应 404，实际: {status}"
    );

    // 9. 删除备份（会同时尽力删除备份文件）
    let v = ctx
        .delete_json(&format!("/system/backup/{}", backup_id))
        .await;
    ctx.assert_ok(&v);

    // 10. 删除后详情应 404
    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, &format!("/system/backup/{}", backup_id), None))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除后查询备份应 404，实际: {status}"
    );

    // 11. 空 id 列表删除应返回 400
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/system/backup/,", None))
        .await;
    assert_ne!(v["code"], 200, "空 id 删除业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "空 id 删除应返回 400，实际: {status}"
    );
}

/// b73 启动期收敛「卡在 running」的备份日志：只有**超过 2×子进程超时 + 余量**的行才被判失败。
///
/// 可证伪性：
/// - 阈值算错（用 `now` 而非 `now - 660s`）⇒ "本进程正在跑的备份"会被误判失败 ⇒ 新鲜行断言变红；
/// - 收敛体没写终态（只记日志不改状态）⇒ 旧行仍是 running ⇒ 第一条断言变红；
/// - 幂等性破坏（重复调用反复改写）⇒ 第二次调用计数非 0 ⇒ 末条断言变红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_backup_running_rows_reconciled_only_when_stale() {
    use sea_orm::{ConnectionTrait, DatabaseBackend, EntityTrait, Statement};

    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // 造两行 running：一行 6 天前（进程早已不在），一行刚刚（合法在途）。
    // create_time 与生产写入口径一致（naive UTC 文本），故比较基准必须同为 naive UTC。
    let naive = |d: chrono::Duration| {
        (chrono::Utc::now() + d)
            .naive_utc()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    };
    for (name, ts) in [
        ("reconcile_stale.db", naive(chrono::Duration::days(-6))),
        ("reconcile_fresh.db", naive(chrono::Duration::seconds(-5))),
    ] {
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "INSERT INTO sys_backup_log \
                 (file_name, file_path, file_size, backup_type, status, create_time, tenant_id) \
                 VALUES ('{name}', 'uploads/{name}', 0, 'manual', 'running', '{ts}', 0)"
            ),
        ))
        .await
        .unwrap();
    }

    let svc = crate::service::SysBackupService::new(db.clone(), ctx.state.config.clone());
    let reconciled = svc.reconcile_interrupted_backups().await.unwrap();
    assert!(
        reconciled >= 1,
        "6 天前的 running 行必须被收敛为 failed，实际收敛 {reconciled} 条"
    );

    let rows = crate::entity::sys_backup_log::Entity::find()
        .all(db)
        .await
        .unwrap();
    let stale = rows
        .iter()
        .find(|r| r.file_name == "reconcile_stale.db")
        .expect("stale 行必须仍在库（收敛只改状态、不删行，保留可追溯）");
    assert_eq!(stale.status, "failed", "stale running 行必须判为 failed");
    assert!(
        stale
            .error_msg
            .as_deref()
            .unwrap_or_default()
            .contains("running"),
        "error_msg 必须写明原判据（运维要能看出这是启动期收敛而非备份自身报错），实际: {:?}",
        stale.error_msg
    );
    let fresh = rows
        .iter()
        .find(|r| r.file_name == "reconcile_fresh.db")
        .expect("fresh 行应存在");
    assert_eq!(
        fresh.status, "running",
        "刚刚创建的 running 行**不得**被误判（本进程可能正在备份，阈值必须远大于子进程超时）"
    );

    // 幂等：再跑一次不重复改写（fresh 仍在阈值保护内）
    let again = svc.reconcile_interrupted_backups().await.unwrap();
    assert_eq!(again, 0, "二次调用必须零命中（幂等），实际 {again}");
}
