// stepby-axum/src/integration_tests/ai_history_http.rs
//! AI 历史删除 / 重放 的 **HTTP 层**集成测试（批八十五 项 C）。
//!
//! 为什么另立一档而不是扩展 `ai_config.rs`：那两条既有用例判的是 **service 层**
//! （`svc.delete_my_history` / `svc.replay`），路由、鉴权、提取器、DTO 线上名、响应体
//! 形状全都不在它们的视野里。`endpoint-coverage` 登记这两条写端点为
//! `needs-fixture: 需要真实 AI provider 凭据` ——**这句理由是错的**：
//! `AiService::replay`（`ai/service.rs:308-348`）只把库里存着的 SQL 重新过一遍
//! `sql_guard` 再本地执行，`token_usage: None`、一次网络都不发。夹具也就是一条 INSERT。
//!
//! 本文件因此把三件事钉在真实 HTTP 栈上：
//! ① **DTO 的线上键名**：前端 `views/ai/panel/index.vue` 发 `{historyId}`，而
//!    `AiReplayDto` 原先没有 `rename_all` ⇒ serde 按 `history_id` 解键 ⇒ **重放按钮自上线
//!    起每次都 400 `parse_failed`**，而两套件从没点过它。这一条是那个缺陷的回归锁。
//! ② **租户/主体边界落在 SQL 谓词上**：`(id, tenant_id, user_id)` 三元组，越权只回
//!    `deleted:false`（200，不泄露"存在与否"），且**别人的行必须还在**。
//! ③ **重放会重新过白名单**：白名单变更后重放历史必须被拒（这是设计内语义，
//!    不是"历史坏了"），并且拒绝时不得返回任何行。

use super::TestContext;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement, Value};

/// 本人历史行的 id（取高位常量，避免与既有用例的 9001-9003 段相撞）
const OWN_OK: i64 = 9101;
const OTHER_OK: i64 = 9102;
const OWN_OTHER_TENANT: i64 = 9103;
const OWN_FAILED: i64 = 9104;
const OWN_NOT_WHITELISTED: i64 = 9105;

/// 直插一条历史（列集合与 `ai_config.rs` 的既有用例同源）
async fn insert_history(ctx: &TestContext, id: i64, tid: i64, uid: i64, question: &str, sql: &str) {
    ctx.state
        .db
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT OR IGNORE INTO ai_chat_history \
             (id, tenant_id, user_id, question, sql_text, tables_used, rows_count, duration_ms, success, create_time) \
             VALUES (?, ?, ?, ?, ?, 'sys_user', 1, 5, '1', CURRENT_TIMESTAMP)",
            [
                Value::from(id),
                Value::from(tid),
                Value::from(uid),
                Value::from(question),
                Value::from(sql),
            ],
        ))
        .await
        .expect("插入 AI 历史失败");
}

/// 按 id 数行（用于"越权删除后幸存行不得被连坐"这类落库事实断言）
async fn hist_rows(ctx: &TestContext, id: i64) -> i64 {
    let row = ctx
        .state
        .db
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS n FROM ai_chat_history WHERE id = ?",
            [Value::from(id)],
        ))
        .await
        .expect("计数查询失败")
        .expect("COUNT 必有一行");
    row.try_get::<i64>("", "n").expect("n 列应为整数")
}

/// 按 question 前缀数行（重放成功后由 `spawn_tracked` 异步落库，需要轮询到落定）
async fn hist_by_question(ctx: &TestContext, prefix: &str) -> i64 {
    for _ in 0..50 {
        let row = ctx
            .state
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS n FROM ai_chat_history WHERE question LIKE ?",
                [Value::from(format!("{prefix}%"))],
            ))
            .await
            .expect("计数查询失败")
            .expect("COUNT 必有一行");
        let n = row.try_get::<i64>("", "n").expect("n 列应为整数");
        if n > 0 {
            return n;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    0
}

/// ②本人删除闭环 + 越权不连坐 + 跨租户同 user_id 不得删。
///
/// 关闭态（`sys.ai.enabled` 在夹具钳制下恒为 false）也照常可删——删自己的历史不需要
/// provider，这一点也在本例里判（先删一次再热开），免得"能力位关"被实现成"整块 403"
/// 那种假安全。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_history_delete_http_covers_own_and_foreign_rows() {
    let ctx = TestContext::new().await;
    insert_history(
        &ctx,
        OWN_OK,
        0,
        1,
        "本人成功行",
        "SELECT user_id FROM sys_user WHERE user_id = 1",
    )
    .await;
    insert_history(
        &ctx,
        OTHER_OK,
        0,
        200,
        "他人成功行",
        "SELECT user_id FROM sys_user WHERE user_id = 1",
    )
    .await;
    insert_history(
        &ctx,
        OWN_OTHER_TENANT,
        7,
        1,
        "同 user_id 但属另一租户",
        "SELECT user_id FROM sys_user WHERE user_id = 1",
    )
    .await;
    // 夹具自证：三行都真的在库里（否则下面的"删掉了"可以靠"根本没插进去"蒙过）
    for id in [OWN_OK, OTHER_OK, OWN_OTHER_TENANT] {
        assert_eq!(hist_rows(&ctx, id).await, 1, "夹具行 {id} 必须先在库里");
    }

    // 关闭态 + 本人行 ⇒ 200 且 deleted=true（`data.deleted` 是这条端点的结果通道，
    // 整体 200 不代表删到了——同 AGENTS 前端归一规范 §3.④"批量接口看响应体"）
    let v = ctx
        .delete_json(&format!("/system/ai/history/{OWN_OK}"))
        .await;
    assert_eq!(v["data"]["deleted"], true, "本人本租行必须删掉，实际 {v}");
    assert_eq!(hist_rows(&ctx, OWN_OK).await, 0, "落库事实：行必须真的消失");

    // 横向越权：同租户另一个人的行 ⇒ 200 + deleted=false + 幸存行不得被连坐
    let v = ctx
        .delete_json(&format!("/system/ai/history/{OTHER_OK}"))
        .await;
    assert_eq!(
        v["data"]["deleted"], false,
        "user 1 不得删掉 user 200 的行，实际 {v}"
    );
    assert_eq!(
        hist_rows(&ctx, OTHER_OK).await,
        1,
        "他人幸存行必须还在（谓词失效就是这里露馅）"
    );

    // 跨租户但同 user_id：谓词里的 tenant_id 必须真的参与（只按 user_id 过滤就删得掉）
    let v = ctx
        .delete_json(&format!("/system/ai/history/{OWN_OTHER_TENANT}"))
        .await;
    assert_eq!(
        v["data"]["deleted"], false,
        "tid=0 的操作者不得删掉 tenant 7 的同 uid 行，实际 {v}"
    );
    assert_eq!(
        hist_rows(&ctx, OWN_OTHER_TENANT).await,
        1,
        "他租户行必须还在"
    );

    // 不存在的 id ⇒ 200 + deleted=false（幂等语义：不回 404，也就不会把"是否存在"泄露给调用方）
    let (status, body) = ctx
        .send_raw(ctx.request(
            axum::http::Method::DELETE,
            "/system/ai/history/9999999",
            None,
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "不存在应为 200 幂等，实际 {status}"
    );
    assert_eq!(
        body["data"]["deleted"], false,
        "不存在时 deleted 必须是 false，实际 {body}"
    );
}

/// ①**DTO 线上键名契约** + 重放成功闭环（含异步留痕）。
///
/// 前半段判关闭态 403（能力位关 = 响亮拒绝，不是静默空结果），后半段热开后判真实重放：
/// 前端那把键（`historyId`）必须被接受并返回行；旧的 snake 键**不再**被接受——
/// 这条不是"兼容倒退"，而是把唯一的调用方（camelCase 前端）钉成事实契约：
/// 谁要改键名，必须同时改前端与本例，否则这里先红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_replay_http_accepts_the_frontend_key() {
    let ctx = TestContext::new().await;
    insert_history(
        &ctx,
        OWN_OK,
        0,
        1,
        "重放成功用例",
        "SELECT user_id, user_name FROM sys_user WHERE user_id = 1",
    )
    .await;

    // ---- 关闭态：403 + 契约体（不是 200 空结果）----
    let (status, body) = ctx
        .send_raw(ctx.request(
            axum::http::Method::POST,
            "/ai/replay",
            Some(serde_json::json!({ "historyId": OWN_OK })),
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::FORBIDDEN,
        "AI 关闭时重放必须 403，实际 {status}"
    );
    assert_eq!(body["code"], 403, "业务码必须与 HTTP 状态同向，实际 {body}");
    assert_eq!(
        body["msg"], "AI 助手未启用，请联系管理员在系统配置中开启",
        "拒绝文案必须是 error.ai.disabled 的当前语言文本，实际 {body}"
    );

    // ---- 热开启（与 ai_config.rs 既有用例同一通道：PUT /system/aiConfig 会刷新 cache-aside）----
    let v = ctx
        .put_json(
            "/system/aiConfig",
            serde_json::json!({
                "enabled": true,
                "provider": "openai",
                "baseUrl": "https://api.openai.com/v1",
                "apiKey": "sk-replay-it",
                "model": "gpt-4o-mini",
                "allowedTables": ["sys_user"]
            }),
        )
        .await;
    assert_eq!(v["code"], 200, "热开启 AI 应成功，实际 {v}");

    // ---- 前端真实形状：camelCase ⇒ 必须 200 并返回行 ----
    let v = ctx
        .post_json("/ai/replay", serde_json::json!({ "historyId": OWN_OK }))
        .await;
    let n = v["data"]["rowCount"].as_i64().unwrap_or(-1);
    assert!(n >= 1, "重放必须真执行 SQL 并返回行，实际 {v}");
    // guard 会按 max_rows 补 LIMIT（b83 之后 `guarded.sql` 才是执行体）——判"重新过了一遍
    // guard"，不判"与库里存的字节相同"（后者会把这条正常收敛误报成契约漂移）。
    let sql_back = v["data"]["sql"].as_str().unwrap_or_default();
    assert!(
        sql_back.starts_with("SELECT user_id, user_name FROM sys_user WHERE user_id = 1")
            && sql_back.contains("LIMIT"),
        "重放返回的必须是重新过 sql_guard 的 SQL（含 max_rows 的 LIMIT 收敛），实际 {sql_back}"
    );
    assert!(
        v["data"]["answer"]
            .as_str()
            .unwrap_or_default()
            .starts_with(&format!("重放自历史 #{OWN_OK}")),
        "answer 必须标明来源历史，实际 {}",
        v["data"]["answer"]
    );

    // 重放成功后由 `spawn_tracked("ai_save_history")` 异步留痕 ⇒ 轮询到落定（不得"看一眼"软断言）
    let saved = hist_by_question(&ctx, &format!("重放自历史 #{OWN_OK}")).await;
    assert!(
        saved >= 1,
        "重放必须留下一次执行留痕（异步写没接线就是 0），实际 {saved}"
    );

    // ---- 反向：snake 键不再被接受（唯一调用方是 camelCase 前端，键名必须只有一处事实源）----
    let (status, body) = ctx
        .send_raw(ctx.request(
            axum::http::Method::POST,
            "/ai/replay",
            Some(serde_json::json!({ "history_id": OWN_OK })),
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "snake 键必须被拒，实际 {status}"
    );
    assert_eq!(body["code"], 400, "业务码 400，实际 {body}");
    // C.9：拒绝理由不得把请求体/字段路径原样吐回去（`parse_failed` 是刻意含糊的那一版）
    let msg = body["msg"].as_str().unwrap_or_default();
    assert!(
        !msg.contains("history_id"),
        "错误文案不得回显字段名，实际 {msg}"
    );
}

/// ③三类必须被拒的重放：他人历史 / 失败留痕行 / 白名单已不含该表。
///
/// 每一类都断到"没有任何行返回"——只判状态码的话，"先返回行再报错"这种形状照样绿。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_replay_http_rejects_foreign_failed_and_unwhitelisted() {
    let ctx = TestContext::new().await;
    ctx.put_json(
        "/system/aiConfig",
        serde_json::json!({
            "enabled": true,
            "provider": "openai",
            "baseUrl": "https://api.openai.com/v1",
            "apiKey": "sk-replay-it2",
            "model": "gpt-4o-mini",
            "allowedTables": ["sys_user"]
        }),
    )
    .await;
    insert_history(
        &ctx,
        OTHER_OK,
        0,
        200,
        "他人成功行",
        "SELECT user_id FROM sys_user WHERE user_id = 1",
    )
    .await;
    insert_history(&ctx, OWN_FAILED, 0, 1, "失败留痕行", "").await;
    insert_history(
        &ctx,
        OWN_NOT_WHITELISTED,
        0,
        1,
        "白名单外表",
        "SELECT * FROM sys_config",
    )
    .await;

    for (id, label) in [
        (OTHER_OK, "他人历史不得重放"),
        (OWN_FAILED, "失败留痕行（无可重放 SQL）"),
        (
            OWN_NOT_WHITELISTED,
            "白名单已不含该表 ⇒ 重放必须被 guard 拒",
        ),
    ] {
        let (status, body) = ctx
            .send_raw(ctx.request(
                axum::http::Method::POST,
                "/ai/replay",
                Some(serde_json::json!({ "historyId": id })),
            ))
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::BAD_REQUEST,
            "{label}：实际 {status} {body}"
        );
        assert!(
            body.get("data").map(|d| d.is_null()).unwrap_or(true),
            "{label}：拒绝时不得返回任何数据体，实际 {body}"
        );
        assert!(
            body["msg"].as_str().map(|m| !m.is_empty()).unwrap_or(false),
            "{label}：必须有可读的失败理由，实际 {body}"
        );
    }
}

/// 关闭态下"删自己的历史"不得被整块 403（能力位关的是推理入口，不是本人数据的清理面）。
/// 这条是 `test_ai_history_delete_http_covers_own_and_foreign_rows` 里那一次显式判据的
/// 独立断面——把"删除依赖 provider"这种误实现单独钉住。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_history_delete_works_while_ai_is_off() {
    let ctx = TestContext::new().await;
    insert_history(
        &ctx,
        OWN_OK,
        0,
        1,
        "关闭态删除行",
        "SELECT user_id FROM sys_user WHERE user_id = 1",
    )
    .await;
    let (status, body) = ctx
        .send_raw(ctx.request(
            axum::http::Method::DELETE,
            &format!("/system/ai/history/{OWN_OK}"),
            None,
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "关闭态删除本人历史必须可用，实际 {status} {body}"
    );
    assert_eq!(
        body["data"]["deleted"], true,
        "必须判到删除结果，实际 {body}"
    );
    assert_eq!(hist_rows(&ctx, OWN_OK).await, 0, "行必须真的消失");
}
