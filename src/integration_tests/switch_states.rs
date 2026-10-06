// stepby-axum/src/integration_tests/switch_states.rs
//! 进程级配置开关的两态集成测试（§5.23 开关总目录配套回归锁）。
//!
//! 背景：开关总目录盘点（switch-catalog-2026-10-05.md）发现若干开关仅有默认值路径
//! 被隐式覆盖、关闭态（或开启态）无任何测试锁定——本模块补齐最关键的两态断言。
//! 后续新增进程级开关时，两态断言优先落在本模块（对齐 AGENTS.md《开关类能力设计
//! 规范》第 8 条检查清单之⑦）。

use super::TestContext;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use sea_orm::ConnectionTrait;
use std::net::SocketAddr;

/// 构造带自定义 Authorization 头的请求（用于 PAT 前缀令牌路径；
/// TestContext::request 硬编码 JWT 头，无法表达 ybt_ 前缀令牌）。
fn req_with_token(ctx: &TestContext, method: Method, uri: &str, token: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// `[pat].enabled = false`：`ybt_` 前缀令牌一律 401（鉴权层 PAT 分支关闭），
/// 且合法 JWT 不受影响（证明拒绝来自 PAT 分支关闭，而非路由/权限层面故障）。
///
/// 可证伪性：若 PAT 关闭时误回退到 JWT 分支（ybt_ 令牌被当 JWT 解析），第一段
/// 断言可能意外 401（解析失败）但第二段无法区分——故补充第三段：开启态下同一
/// 假令牌同样 401，证明两段的 401 语义路径不同（关闭态=分支短路，开启态=查库失败）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pat_disabled_rejects_ybt_tokens_but_jwt_unaffected() {
    // ---------- ① 关闭态：ybt_ 假令牌 401 + 合法 JWT 200 ----------
    let ctx = TestContext::new_with(&[], |s| {
        s.pat.enabled = false;
    })
    .await;

    let (status, _) = ctx
        .send_raw(req_with_token(
            &ctx,
            Method::GET,
            "/system/user/list?pageNum=1&pageSize=1",
            "sb_fake_token",
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "PAT 关闭后 ybt_ 前缀令牌必须 401（不回退 JWT 分支），实际 {status}"
    );

    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, "/system/user/list?pageNum=1&pageSize=1", None))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PAT 关闭不得影响合法 JWT 链路，实际 {status}"
    );

    // ---------- ② 开启态（对照）：同一假令牌也 401，但路径不同（查库失败） ----------
    let ctx_on = TestContext::new().await;
    let (status, _) = ctx_on
        .send_raw(req_with_token(
            &ctx_on,
            Method::GET,
            "/system/user/list?pageNum=1&pageSize=1",
            "sb_fake_token",
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "PAT 开启时无效 ybt_ 令牌同样 401（查库失败路径），实际 {status}"
    );
}

/// `[ai].enabled = false`：`POST /ai/chat` 403（三层开关第一层——进程级主开关）。
///
/// 可证伪性：若 handler 丢失 `[ai].enabled` 守卫，断言 403 变 200/其它 ⇒ 变红。
/// （租户层 `ai.copilot` 与菜单剪除的关闭态由 capability_features / prune 单测覆盖，
/// 本用例专锁**进程级主开关**的 handler 守卫。）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ai_disabled_rejects_chat_with_forbidden() {
    let ctx = TestContext::new_with(&[], |s| {
        s.ai.enabled = false;
    })
    .await;

    let (status, body) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/ai/chat",
            Some(serde_json::json!({ "question": "有多少用户" })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "[ai].enabled=false 时 /ai/chat 必须 403，实际 {status} {body}"
    );
    assert_eq!(
        body["code"], 403,
        "业务码应为 403（error.ai.disabled 明确降级提示），实际 {body}"
    );
}

/// `sys.login.blackIPList` 真实消费回归（§5.23：补齐"登记死键"的运行时实现）。
///
/// 此前该键仅在治理注册表登记 + 参数页可配置，但登录链路**无任何消费**（管理员
/// 配置不生效）。本用例锁定：黑名单命中 ⇒ 登录 403；移除后恢复。
///
/// 实现细节：DB 直改 sys_config 值（等价参数页操作）后必须 **DEL 配置缓存键**
/// （config:def:*，TTL 300s——TestContext 构造期的首次 login 已把空值读入缓存）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_login_ip_blacklist_blocks_login() {
    use sea_orm::{DatabaseBackend, Statement};

    let ctx = TestContext::new().await;
    let blacklisted = "127.0.0.1";

    // 管理员配置黑名单（等价参数页写入）
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "UPDATE sys_config SET config_value='{blacklisted}' \
                 WHERE config_key='sys.login.blackIPList'"
            ),
        ))
        .await
        .expect("写入黑名单失败");
    // 失效配置缓存（TestContext 构造期首次 login 已把空值读入 cache-aside）
    let mut conn = ctx.redis();
    redis::cmd("DEL")
        .arg("config:def:sys.login.blackIPList")
        .query_async::<()>(&mut conn)
        .await
        .expect("失效配置缓存失败");

    // 黑名单命中（登录来源 127.0.0.1）⇒ 403；验证码已由 harness 关闭 ⇒ code/uuid 空串
    let login_req = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "username": "admin",
                "password": "admin123",
                "code": "",
                "uuid": ""
            })
            .to_string(),
        ))
        .expect("构造登录请求失败");
    let mut req = login_req;
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4321))));
    let (status, body) = ctx.send_raw(req).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "黑名单 IP 登录必须被拒绝，实际 {status} {body}"
    );

    // 清空黑名单 + 失效缓存 ⇒ 登录恢复 200
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "UPDATE sys_config SET config_value='' \
             WHERE config_key='sys.login.blackIPList'"
                .to_string(),
        ))
        .await
        .expect("清空黑名单失败");
    redis::cmd("DEL")
        .arg("config:def:sys.login.blackIPList")
        .query_async::<()>(&mut conn)
        .await
        .expect("二次失效缓存失败");

    let req = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "username": "admin",
                "password": "admin123",
                "code": "",
                "uuid": ""
            })
            .to_string(),
        ))
        .expect("构造恢复登录请求失败");
    let mut req = req;
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4321))));
    let (status, _) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "清空黑名单后同 IP 登录必须恢复，实际 {status}"
    );
}

/// `[risk_control].login_ua_filter = "block"`：工具型 UA 登录 ⇒ 403（登录链路两态
/// 集成锁定——判定内核单测已完备（risk_control.rs），本用例锁**真实登录链路**）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_login_ua_filter_block_rejects_tool_ua() {
    let ctx = TestContext::new_with(&[], |s| {
        s.risk_control.login_ua_filter = "block".to_string();
    })
    .await;

    // 工具型 UA（curl）+ 正确凭据 ⇒ 仍 403（UA 风控先于密码校验）
    let req = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header("content-type", "application/json")
        .header("user-agent", "curl/8.0")
        .body(Body::from(
            serde_json::json!({
                "username": "admin",
                "password": "admin123",
                "code": "",
                "uuid": ""
            })
            .to_string(),
        ))
        .expect("构造请求失败");
    let mut req = req;
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4321))));
    let (status, _) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "block 档下工具型 UA 登录必须 403，实际 {status}"
    );
}

/// `[server].docs_enabled = false`：Swagger UI / OpenAPI JSON 路由不注册
/// （§5.23 补两态——**注意**：嵌入式前端的 SPA fallback 会让未知路径返回 200
/// index.html，故断言用**内容判定**：响应不得含 OpenAPI 文档特征，即"功能不存在"；
/// 对照组 docs_enabled=true 时返回真 OpenAPI JSON）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_docs_disabled_serves_no_openapi() {
    // ---------- 关闭态：openapi.json 响应不含 OpenAPI 文档特征 ----------
    let ctx = TestContext::new_with(&[], |s| {
        s.server.docs_enabled = false;
    })
    .await;

    for path in ["/api-docs/openapi.json", "/swagger-ui"] {
        let (status, body) = ctx.send_raw(ctx.request(Method::GET, path, None)).await;
        let body_str = body.to_string();
        assert!(
            !body_str.contains("\"openapi\""),
            "docs_enabled=false 时 {path} 不得返回 OpenAPI 文档（status={status}）: {}",
            &body_str[..body_str.len().min(200)]
        );
    }

    // ---------- 对照组（默认开启，来自本机 config.toml docs_enabled=true）：
    //            /api-docs/openapi.json 返回真 OpenAPI 文档 ----------
    let ctx_on = TestContext::new().await;
    let (status, body) = ctx_on
        .send_raw(ctx_on.request(Method::GET, "/api-docs/openapi.json", None))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "docs_enabled=true 时 openapi.json 应 200，实际 {status}"
    );
    assert!(
        body.to_string().contains("\"openapi\""),
        "docs_enabled=true 时应返回真 OpenAPI 文档"
    );
}

/// `[monitor].metrics_token` 非空：/metrics 无令牌 ⇒ **401**、带令牌 ⇒ 200
/// （原仅匿名态被隐式覆盖，§5.23 补配置态两态）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metrics_token_requires_bearer() {
    let ctx = TestContext::new_with(&[], |s| {
        s.monitor.metrics_token = "it-metrics-secret".to_string();
    })
    .await;

    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, "/metrics", None))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "配置 token 后无凭据访问 /metrics 必须 401，实际 {status}"
    );

    // 带正确 Bearer ⇒ 200（存在性证明：拒绝来自 token 校验而非路由缺失）
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .header("authorization", "Bearer it-metrics-secret")
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4321))));
    let (status, _) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "正确 Bearer 访问 /metrics 必须 200，实际 {status}"
    );
}
