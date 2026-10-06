// stepby-axum/src/integration_tests/switch_modes.rs
//! 全量开关 × 三种发布模式正交性实证（§5.47 福哥令：所有带开关功能 × 三模式核查）。
//!
//! switch-catalog-2026-10-05.md 的核心声明：**"租户域开关随 management 联动收敛
//! （§5.20/§5.21），其余开关与模式正交（单一职责）"**。
//! 该声明此前只是文档结论——本模块用**测试证明"正交"**：
//! 在**单机模式**（`[tenant].management = false`）下重跑各代表开关的关闭态断言，
//! 若某开关行为随模式漂移（= 隐含模式耦合），断言变红即证伪文档声明。
//!
//! 三类覆盖：
//! 1. **正交组**（进程级配置开关代表 5 项）：PAT/AI 主开关/开放注册/Swagger 文档/
//!    metrics token——单机模式下的关闭态行为与默认模式**完全一致**；
//! 2. **能力位平台面**：`management=false` 不收敛平台功能面（backup 平台导出仍可用
//!    ——平台能力 ≠ 租户语义，剪除只针对后者）；
//! 3. **联动面**（对照组）：租户语义收敛已由 capability_features::test_standalone_
//!    mode_hides_all_tenant_surfaces 三段锁定，本模块不重复，仅作矩阵归属说明。

use super::TestContext;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

/// 单机模式 + PAT 关闭：ybt_ 令牌仍 401（PAT 开关与部署模式正交）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_standalone_pat_disabled_still_rejects_ybt() {
    let ctx = TestContext::new_with(&[], |s| {
        s.tenant.management = false;
        s.pat.enabled = false;
    })
    .await;

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/system/user/list?pageNum=1&pageSize=1")
        .header("authorization", "Bearer ybt_fake_token")
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, _) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "单机模式下 PAT 关闭仍必须 401（开关与模式正交），实际 {status}"
    );

    // 合法 JWT 链路不受双重影响（management=false 不破坏鉴权）
    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, "/system/user/list?pageNum=1&pageSize=1", None))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "单机模式下合法 JWT 链路应正常，实际 {status}"
    );
}

/// 单机模式 + AI 主开关关闭（config.toml 层）：/ai/chat 仍 403
/// （AI-01 运行时热化的第一层前置——启动快照层与模式正交）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_standalone_ai_disabled_still_forbidden() {
    let ctx = TestContext::new_with(&[], |s| {
        s.tenant.management = false;
        s.ai.enabled = false;
    })
    .await;

    let (status, body) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/ai/chat",
            Some(serde_json::json!({ "question": "正交探针" })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "单机模式下 [ai].enabled=false 时 /ai/chat 必须 403，实际 {status} {body}"
    );
}

/// 单机模式 + 开放注册关闭：/register 仍拒绝（sys_config 键与模式正交）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_standalone_register_disabled_still_rejected() {
    let ctx = TestContext::new_with(&[], |s| {
        s.tenant.management = false;
    })
    .await;

    // registerUser 默认 'false'（迁移种子）——夹具未钳制该键，走默认关闭态
    let (status, _) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/register",
            Some(serde_json::json!({
                "username": "orth_probe",
                "password": "Ortho@12345",
                "code": "",
                "uuid": ""
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "单机模式下 registerUser=false 的 /register 必须 403，实际 {status}"
    );
}

/// 单机模式 + docs 关闭：OpenAPI 特征不出现（文档开关与模式正交）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_standalone_docs_disabled_serves_no_openapi() {
    let ctx = TestContext::new_with(&[], |s| {
        s.tenant.management = false;
        s.server.docs_enabled = false;
    })
    .await;

    let (status, body) = ctx
        .send_raw(ctx.request(Method::GET, "/api-docs/openapi.json", None))
        .await;
    let body_str = body.to_string();
    assert!(
        !body_str.contains("\"openapi\""),
        "单机模式下 docs_enabled=false 不得返回 OpenAPI 文档（status={status}）"
    );
}

/// 单机模式 + metrics token：鉴权语义不变（可观测开关与模式正交）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_standalone_metrics_token_requires_bearer() {
    let ctx = TestContext::new_with(&[], |s| {
        s.tenant.management = false;
        s.monitor.metrics_token = "standalone-metrics-secret".to_string();
    })
    .await;

    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, "/metrics", None))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "单机模式下 metrics_token 无凭据必须 401，实际 {status}"
    );

    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .header("authorization", "Bearer standalone-metrics-secret")
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4321))));
    let (status, _) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "单机模式下正确 Bearer 访问 /metrics 必须 200，实际 {status}"
    );
}

/// 能力位平台面：`management=false` **不收敛平台功能面**（backup 平台导出仍可用）
/// ——PLATFORM_ONLY 剪除只针对"租户语义"菜单/API（tenant/menu domain），
/// 平台自身能力（备份/审计/生成器）与部署模式无关（单机用户就是平台管理员）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_standalone_capability_platform_surface_usable() {
    let ctx = TestContext::new_with(&[], |s| {
        s.tenant.management = false;
    })
    .await;

    // 备份平台面（PLATFORM_ONLY_PERM_PREFIXES 域）：单机模式不剪除、不 403
    let (status, _) = ctx
        .send_raw(ctx.request(Method::GET, "/system/backup/list", None))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "单机模式下备份平台面必须可用（平台能力≠租户语义，不被 management 收敛），实际 {status}"
    );

    // 对照：租户语义面同模式下被剪（capability test_standalone 已锁，此处快验一条）
    let (status, _) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/system/tenant/list?pageNum=1&pageSize=1",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "单机模式下租户语义 API 必须 403（联动收敛对照组），实际 {status}"
    );
}
