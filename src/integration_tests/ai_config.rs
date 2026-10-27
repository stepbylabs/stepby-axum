// stepby-axum/src/integration_tests/ai_config.rs
//! AI-01/AI-02 集成测试（§5.39 设计文档步骤 6 验收）：
//!
//! - **AI-01**：平台门控 / 掩码回显（api_key 不泄露明文）/ seal 往返（热生效）/
//!   SSRF 拒绝（私网 base_url）
//! - **AI-02**：历史租户隔离（tenant A 写 → tenant B/平台条件查不到）/
//!   本人删除（横向越权防护：他人行删不掉）
//!
//! 开关矩阵说明：sys.ai.* 六键在夹具钳制下恒为缺省（enabled=false），
//! enabled=true 的行为经 update 热化路径在本组内验证（get_effective 断言）。

use super::TestContext;
use crate::common::features::FEATURE_OFF;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use std::net::SocketAddr;

/// 构造 JSON 请求（平台管理员 admin token）
fn admin_req(
    ctx: &TestContext,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", ctx.token));
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

/// 平台门控：租户管理员（非 tid=0）访问 aiConfig 一律 403
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_config_platform_only() {
    let ctx = TestContext::new().await;
    // stepby（普通用户，tid≠0）与 admin（平台）均走真实 token；
    // stepby 的 tid≠0 → handler 门控 403
    let stepby_token = super::login(&ctx.app, ctx.peer_ip, "stepby", "admin123").await;
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/system/aiConfig")
        .header("authorization", format!("Bearer {stepby_token}"))
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, _) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "非平台操作者访问 AI 配置必须 403，实际 {status}"
    );

    // 对照：admin（tid=0）→ 200
    let mut req = admin_req(&ctx, Method::GET, "/system/aiConfig", None);
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, body) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "平台管理员应能读取 AI 配置，实际 {status} {body}"
    );
}

/// 掩码回显：api_key 永不出现在响应体中（update 后 masked 只含掩码）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_config_mask_never_leaks_plaintext() {
    let ctx = TestContext::new().await;
    let secret = "sk-ai01-mask-test-987654321";
    let resp = ctx
        .send_raw(admin_req(
            &ctx,
            Method::PUT,
            "/system/aiConfig",
            Some(serde_json::json!({
                "enabled": true,
                "provider": "openai",
                "baseUrl": "https://api.openai.com/v1",
                "apiKey": secret,
                "model": "gpt-4o-mini",
                "allowedTables": ["sys_user"]
            })),
        ))
        .await;
    assert_eq!(resp.0, StatusCode::OK, "update 应成功，实际 {}", resp.0);

    // 读回：掩码断言（明文任何位置不得出现）
    let (_, body) = ctx
        .send_raw(admin_req(&ctx, Method::GET, "/system/aiConfig", None))
        .await;
    let body_str = body.to_string();
    assert!(
        !body_str.contains(secret),
        "AI 配置响应体不得泄露 api_key 明文: {body_str}"
    );
    assert!(body_str.contains("sk-"), "掩码应保留前缀特征: {body_str}");
}

/// 热生效：update 后 get_effective 立即反映（enabled/api_key seal 往返）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_config_update_hot_reload() {
    let ctx = TestContext::new().await;
    let svc = &ctx.state.ai_config_service;

    // 基线：缺省 enabled=false
    assert!(!svc.get_effective().await.unwrap().enabled);

    // update enabled=true + api_key（seal 落库）
    let resp = ctx
        .send_raw(admin_req(
            &ctx,
            Method::PUT,
            "/system/aiConfig",
            Some(serde_json::json!({
                "enabled": true,
                "provider": "openai",
                "baseUrl": "https://api.openai.com/v1",
                "apiKey": "sk-hot-reload-123",
                "model": "gpt-4o-mini",
                "allowedTables": ["sys_user", "sys_dept"]
            })),
        ))
        .await;
    assert_eq!(resp.0, StatusCode::OK, "update 应成功");

    // 热生效断言：enabled=true + api_key unseal 往返
    let eff = svc.get_effective().await.unwrap();
    assert!(eff.enabled, "update 后 enabled 应热生效");
    assert_eq!(eff.api_key, "sk-hot-reload-123", "api_key 应 seal 往返一致");
    assert_eq!(eff.allowed_tables, vec!["sys_user", "sys_dept"]);
}

/// 白名单表名非法必须 400，且**不得留下半应用配置**（b98）。
///
/// 这些名字会进入 `PRAGMA table_info(...)` 等无法参数化的位置。校验必须排在
/// 任何 `write_key` 之前：六键是逐条写的，先写 enabled/provider 再拒绝，会让
/// "保存失败"的页面底下偷偷生效了一半。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_config_rejects_invalid_allowed_table_without_partial_write() {
    let ctx = TestContext::new().await;
    let svc = &ctx.state.ai_config_service;
    let before = svc.get_effective().await.unwrap();

    let (status, body) = ctx
        .send_raw(admin_req(
            &ctx,
            Method::PUT,
            "/system/aiConfig",
            Some(serde_json::json!({
                "enabled": true,
                "provider": "openai",
                "baseUrl": "https://api.openai.com/v1",
                "apiKey": "sk-invalid-table",
                "model": "gpt-4o-mini",
                "allowedTables": ["sys_user", "sys_user; DROP TABLE sys_user"]
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法表名必须 400，实际 {status} / {body}"
    );
    let msg = body["msg"].as_str().unwrap_or_default();
    assert!(!msg.trim().is_empty(), "拒绝文案不得为空: {body}");
    assert!(
        !msg.contains("error.ai.allowed_table_invalid"),
        "i18n 键未被解析（页面会显示原始键名）: {body}"
    );

    // 半应用配置判据：enabled / 白名单都必须保持本用例开始前的值
    let after = svc.get_effective().await.unwrap();
    assert_eq!(
        after.enabled, before.enabled,
        "被拒绝的保存不得改动 enabled（校验必须排在首个 write_key 之前）"
    );
    assert_eq!(
        after.allowed_tables, before.allowed_tables,
        "被拒绝的保存不得改动白名单"
    );
}

/// SSRF：私网/环网 base_url 被拒绝（metadata 端点 169.254.169.254）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_config_ssrf_rejects_private_base_url() {
    let ctx = TestContext::new().await;
    let (status, body) = ctx
        .send_raw(admin_req(
            &ctx,
            Method::PUT,
            "/system/aiConfig",
            Some(serde_json::json!({
                "enabled": true,
                "provider": "openai",
                "baseUrl": "http://169.254.169.254/v1",
                "apiKey": "sk-x",
                "model": "m",
                "allowedTables": []
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "私网 base_url 应被 SSRF 校验拒绝（service 层 400），实际 {status}"
    );
    assert_eq!(
        body["code"], 400,
        "业务码应为 400（SSRF 拒绝语义），实际 {body}"
    );
}

/// AI-02 租户隔离：tenant A 写的历史，tenant B 与平台条件查询互不可见
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_history_tenant_isolation() {
    let ctx = TestContext::new().await;
    // 历史方法在 AiService（运行时配置由 ai_config_service.get_effective 提供）
    let effective = ctx.state.ai_config_service.get_effective().await.unwrap();
    let svc = crate::ai::service::AiService::new(ctx.state.db.clone(), effective);
    // 直插两条分属不同租户的历史（模拟 chat 写入）
    let db = &ctx.state.db;

    // 直插两条分属不同租户的历史（模拟 chat 写入）
    let backend = DatabaseBackend::Sqlite;
    for (tid, uid, q) in [
        (1i64, 100i64, "tenant-A 的问题"),
        (2, 200, "tenant-B 的问题"),
    ] {
        db.execute_raw(sea_orm::Statement::from_sql_and_values(
            backend,
            "INSERT INTO ai_chat_history (tenant_id, user_id, question, sql_text, tables_used, rows_count, duration_ms, success, create_time) \
             VALUES (?, ?, ?, 'SELECT 1', 'sys_user', 1, 5, '1', CURRENT_TIMESTAMP)",
            [tid.into(), uid.into(), q.into()],
        ))
        .await
        .expect("插入历史失败");
    }

    // tenant A 视角：只见到自己的
    let (items_a, total_a) = svc
        .list_admin_history(1, None, 1, 50)
        .await
        .expect("租户 A 查询失败");
    assert_eq!(total_a, 1, "租户 A 只能看到本租户 1 条");
    assert_eq!(items_a[0]["question"], "tenant-A 的问题");

    // tenant B 视角：只见到自己的
    let (items_b, total_b) = svc
        .list_admin_history(2, None, 1, 50)
        .await
        .expect("租户 B 查询失败");
    assert_eq!(total_b, 1, "租户 B 只能看到本租户 1 条");
    assert_eq!(items_b[0]["question"], "tenant-B 的问题");

    // 平台（tid=0）跨租户：两条全见
    let (_, total_p) = svc
        .list_admin_history(0, None, 1, 50)
        .await
        .expect("平台查询失败");
    assert!(total_p >= 2, "平台应跨租户看到全部");

    // 本人删除越权防护：user 100 删 user 200 的行 → rows_affected 0（行仍在）
    let deleted = svc
        .delete_my_history(2, 100, 1)
        .await
        .expect("越权删除调用不应报错");
    assert!(!deleted, "user 100 不得删除 tenant B user 200 的行");
}

/// AI-01/02 × **三种部署模式**交叉矩阵（§5.46 福哥令"开关×三模式"核查）：
///
/// | 场景 | aiConfig（平台专属） | /ai/chat（三层开关） |
/// |---|---|---|
/// | 单机（management=false） | 200（平台专属不受 management 影响） | 非 403（平台跳过能力位） |
/// | 服务器（management=true，features 全 off） | 200 | 非 403（平台跳过能力位） |
/// | 多租户租户用户（ai.copilot 默认 off） | 403（非平台操作者） | 403（能力位 fail-closed） |
/// | sys.ai.enabled=false（任何模式） | 200（配置页不受业务开关影响） | 403（平台层优先） |
///
/// 可证伪性：若 aiConfig 误挂 management 门控 → ①变红；若 /ai/chat 误用
/// 启动快照而非 get_effective → ④变红（update 热关闭后仍放行）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_config_across_deployment_modes() {
    // ---- ① 单机模式（management=false）：aiConfig 平台专属不受 management 影响 ----
    let ctx = TestContext::new_with(&[], |s| {
        s.tenant.management = false;
    })
    .await;
    let mut req = admin_req(&ctx, Method::GET, "/system/aiConfig", None);
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, _) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "单机模式下 aiConfig（平台专属）应 200，实际 {status}"
    );
    drop(ctx);

    // ---- ② 服务器模式（management=true + 平台 /ai/chat 能力位跳过）----
    // TestContext 默认 management=true；平台账号 tid=0 经 L42 跳过能力位校验
    let ctx = TestContext::new().await;
    // 热开启 sys.ai.enabled（AI-01 运行时配置）
    let (_, body) = ctx
        .send_raw(admin_req(
            &ctx,
            Method::PUT,
            "/system/aiConfig",
            Some(serde_json::json!({
                "enabled": true,
                "provider": "openai",
                "baseUrl": "https://api.openai.com/v1",
                "apiKey": "sk-mode-matrix",
                "model": "gpt-4o-mini",
                "allowedTables": ["sys_user"]
            })),
        ))
        .await;
    assert_eq!(body["code"], 200, "热开启应成功: {body}");

    let (status, _) = ctx
        .send_raw(admin_req(
            &ctx,
            Method::POST,
            "/ai/chat",
            Some(serde_json::json!({ "question": "矩阵探针" })),
        ))
        .await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "服务器模式平台账号 /ai/chat 不得 403（平台跳过能力位），实际 {status}"
    );

    // ---- ③ 多租户租户面（service 层验证，复用 capability 测试基建口径）----
    // 平台 ai.copilot 注册默认 OFF（governance feat 第一档）；套餐 features=NULL →
    // 租户有效能力集全 OFF（fail-closed）——租户用户即使热开启平台层也被能力位拦截
    let db2 = &ctx.state.db;
    let backend = DatabaseBackend::Sqlite;
    db2
        .execute_raw(Statement::from_sql_and_values(
            backend,
            "INSERT OR IGNORE INTO sys_tenant_package (package_id, package_name, menu_ids, features, default_account_count, status, del_flag) \
             VALUES (901, 'ai-mode-pkg', NULL, NULL, 0, '0', '0')",
            [],
        ))
        .await
        .expect("插入套餐失败");
    db2
        .execute_raw(Statement::from_sql_and_values(
            backend,
            "INSERT OR IGNORE INTO sys_tenant (tenant_id, tenant_code, tenant_name, package_id, status, del_flag) \
             VALUES (2, 'ai_mode_t2', 'AI-MODE-T2', 901, '0', '0')",
            [],
        ))
        .await
        .expect("插入租户失败");
    let effective = crate::service::sys_tenant_service::tenant_features_conn(db2, 2)
        .await
        .expect("解析租户有效能力集失败");
    assert_eq!(
        effective.mode("ai.copilot"),
        FEATURE_OFF,
        "套餐未配置 ai.copilot 时租户有效档必须 OFF（fail-closed——租户用户即使平台热开启也被能力位拦）"
    );

    // ---- ④ sys.ai.enabled=false（热关闭）→ 平台 /ai/chat 也 403（平台层优先）----
    let (_, body) = ctx
        .send_raw(admin_req(
            &ctx,
            Method::PUT,
            "/system/aiConfig",
            Some(serde_json::json!({
                "enabled": false,
                "provider": "openai",
                "baseUrl": "https://api.openai.com/v1",
                "apiKey": "sk-x",
                "model": "gpt-4o-mini",
                "allowedTables": ["sys_user"]
            })),
        ))
        .await;
    assert_eq!(body["code"], 200, "热关闭应成功");
    let (status, _) = ctx
        .send_raw(admin_req(
            &ctx,
            Method::POST,
            "/ai/chat",
            Some(serde_json::json!({ "question": "矩阵探针-关闭" })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "sys.ai.enabled=false 时平台 /ai/chat 也必须 403（平台层优先），实际 {status}"
    );
}

/// AI-02 重放三断言（§5.49 遗漏修复：决策 2"SQL 可重放"补真实实现）：
/// ①成功重放：本人成功历史 → guard 重校验 + 受控执行返回结果；
/// ②横向越权：他人历史 id 重放 → 拒绝；
/// ③失败留痕行（sql_text 空）→ 明确拒绝不可重放。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_replay_guard_and_ownership() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    let backend = DatabaseBackend::Sqlite;

    // 造三条历史：user 100 的成功行（真 SQL）/ 失败行（sql_text 空）/ user 200 的成功行
    for (id, uid, q, sql) in [
        (
            9001i64,
            100i64,
            "重放成功用例",
            "SELECT user_id, user_name FROM sys_user WHERE user_id = 1",
        ),
        (9002i64, 100i64, "失败留痕行", ""),
        (
            9003i64,
            200i64,
            "他人成功行",
            "SELECT user_id FROM sys_user WHERE user_id = 1",
        ),
    ] {
        db.execute_raw(Statement::from_sql_and_values(
            backend,
            "INSERT OR IGNORE INTO ai_chat_history (id, tenant_id, user_id, question, sql_text, tables_used, rows_count, duration_ms, success, create_time) \
             VALUES (?, 0, ?, ?, ?, 'sys_user', 1, 5, '1', CURRENT_TIMESTAMP)",
            [id.into(), uid.into(), q.into(), sql.into()],
        ))
        .await
        .expect("插入历史失败");
    }

    let effective = ctx.state.ai_config_service.get_effective().await.unwrap();
    let svc = crate::ai::service::AiService::new(ctx.state.db.clone(), effective);

    // ① 成功重放：guard 重校验通过 → 受控执行返回行
    let outcome = svc.replay(9001, 0, 100).await.expect("重放成功历史应通过");
    assert_eq!(outcome.tables, vec!["sys_user"], "重放应报告引用表");
    assert!(
        !outcome.rows.is_empty(),
        "sys_user 有种子行，重放应返回数据"
    );

    // ② 横向越权：user 100 重放 user 200 的行 → 拒绝
    let err = svc.replay(9003, 0, 100).await;
    assert!(err.is_err(), "重放他人历史必须被拒绝");

    // ③ 失败留痕行：sql_text 空 → 明确拒绝
    let err = svc.replay(9002, 0, 100).await;
    assert!(
        err.is_err() && err.unwrap_err().to_string().contains("失败留痕"),
        "失败留痕行不可重放（应给出明确语义）"
    );
}
