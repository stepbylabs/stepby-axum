// axum-backend/src/integration_tests/common_handler.rs
//! 公共端点 + 通用模块链路集成测试：
//! - 验证码 /captchaImage：测试库默认关闭验证码，img/uuid 优雅降级为空（读取 auth_service 真实行为）
//! - 登录后 /getInfo、/getRouters（公开/受保护链路）
//! - 注册 /register：参数校验分支（无效 uuid / 过短用户名 / 弱口令）与默认禁注册（403 防刷）
//! - 健康检查 /health（真实探测 DB/Redis）与 /metrics
//! - 通用文件下载参数校验（路径穿越 → 400）
//! - 仪表盘 /dashboard/stats 聚合结构
//!
//! 说明：
//! - 迁移种子中 sys.account.captchaEnabled 被测试 harness 强制改为 false，
//!   generate_captcha 在开关关闭时返回空 img/uuid（见 auth_service::generate_captcha），
//!   故此处断言关闭态降级行为；开启态真实图片由 auth.rs / file_common.rs 覆盖。
//! - 迁移种子中 sys.account.registerUser=false（默认禁注册，安全失败），
//!   /register 携带合法参数会被 403 拒绝（register_disabled），此为预期防刷行为。
//! - /common/download 等受保护端点复用 TestContext 的鉴权 token。

use axum::http::{Method, StatusCode};

use super::TestContext;

/// 健康检查：真实探测 DB 与 Redis，均应 UP，版本非空。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_health_check() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/health").await;
    assert_eq!(v["data"]["status"].as_str(), Some("UP"), "整体状态应为 UP，实际: {v}");
    assert_eq!(v["data"]["db"].as_str(), Some("UP"), "DB 应 UP，实际: {v}");
    assert_eq!(v["data"]["redis"].as_str(), Some("UP"), "Redis 应 UP，实际: {v}");
    assert!(
        !v["data"]["version"].as_str().unwrap_or("").is_empty(),
        "version 不应为空，实际: {v}"
    );
}

/// 验证码默认关闭态：测试 harness 强制 captchaEnabled=false，
/// generate_captcha 返回空 img/uuid（优雅降级），registerEnabled 为布尔。
/// 字段在响应顶层（无 data 包装）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_captcha_disabled_default() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/captchaImage").await;
    assert_eq!(v["code"], 200, "captchaImage 业务码应为 200，实际: {v}");
    assert_eq!(
        v["captchaEnabled"], false,
        "测试库默认应关闭验证码，实际: {v}"
    );
    assert_eq!(v["img"].as_str(), Some(""), "关闭态 img 应为空，实际: {v}");
    assert_eq!(v["uuid"].as_str(), Some(""), "关闭态 uuid 应为空，实际: {v}");
    assert!(
        v["registerEnabled"].is_boolean(),
        "registerEnabled 应为布尔，实际: {v}"
    );
}

/// 登录后的用户信息 /getInfo 与路由树 /getRouters。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_get_info_routers() {
    let ctx = TestContext::new().await;

    // getInfo：字段在顶层
    let v = ctx.get_json("/getInfo").await;
    assert_eq!(
        v["user"]["userName"].as_str(),
        Some("admin"),
        "getInfo 应返回 admin 用户，实际: {v}"
    );
    let roles = v["roles"].as_array().expect("roles 应为数组，实际: {v}");
    assert!(
        roles.iter().any(|r| r.as_str() == Some("admin")),
        "admin roles 应包含 admin，实际: {v}"
    );
    let perms = v["permissions"].as_array().expect("permissions 应为数组，实际: {v}");
    assert!(
        perms.iter().any(|p| p.as_str() == Some("*:*:*")),
        "超管权限应包含 *:*:*，实际: {v}"
    );

    // getRouters：data 为路由树数组
    let v = ctx.get_json("/getRouters").await;
    let routers = v["data"].as_array().expect("getRouters data 应为数组，实际: {v}");
    assert!(!routers.is_empty(), "admin 路由树不应为空，实际: {v}");
    assert!(
        routers.iter().all(|r| r.get("path").is_some() && r.get("name").is_some()),
        "路由节点应含 path/name，实际: {v}"
    );
}

/// 注册 /register 参数校验与默认禁注册防刷分支（均为公开接口，无需真实外部服务）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_register_validation_branches() {
    let ctx = TestContext::new().await;
    let uri = "/register";

    // 1. 无效 uuid 格式 → 400（garde custom validate_captcha_uuid_format）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "username": "it_com_user",
                "password": "It@12345z",
                "code": "1234",
                "uuid": "not-a-valid-uuid"
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "无效 uuid 业务码不应为 200，实际: {v}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "无效 uuid 应 400，实际: {status}");

    // 2. 用户名过短（< 2）→ 400（garde length）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "username": "a",
                "password": "It@12345z",
                "code": "",
                "uuid": ""
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "过短用户名业务码不应为 200，实际: {v}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "过短用户名应 400，实际: {status}");

    // 3. 弱口令（无数字）→ 400（password 复杂度校验，注册入口拦截）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "username": "it_com_user",
                "password": "onlyletters",
                "code": "",
                "uuid": ""
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "弱口令业务码不应为 200，实际: {v}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "弱口令应 400，实际: {status}");

    // 4. 合法参数 + 默认禁注册 → 403（registerUser 默认 false，安全失败禁止注册）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            uri,
            Some(serde_json::json!({
                "username": "it_com_fresh",
                "password": "It@12345z",
                "code": "",
                "uuid": ""
            })),
        ))
        .await;
    assert_ne!(v["code"], 200, "禁注册时业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "默认禁注册应 403，实际: {status} {v}"
    );
}

/// 通用文件下载参数校验失败分支（无需真实文件，命中 handler 的参数校验即返回 400）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_common_download_validation() {
    let ctx = TestContext::new().await;

    // 1. /common/download：fileName 含路径穿越符 `..` → 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/common/download?fileName=..%2F..%2Fetc%2Fpasswd",
            None,
        ))
        .await;
    assert_ne!(v["code"], 200, "路径穿越下载业务码不应为 200，实际: {v}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "路径穿越下载应 400，实际: {status}");

    // 2. /common/download/resource：resource 含 `..` → 400
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/common/download/resource?resource=uploads%2F..%2Fsecret.txt",
            None,
        ))
        .await;
    assert_ne!(v["code"], 200, "资源路径穿越业务码不应为 200，实际: {v}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "资源路径穿越应 400，实际: {status}");
}

/// 仪表盘聚合统计 /dashboard/stats（本地 DB/Redis 聚合，稳定通过）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_com_dashboard_stats_structure() {
    let ctx = TestContext::new().await;

    let v = ctx.get_json("/dashboard/stats").await;
    assert!(v["data"]["totalUsers"].is_number(), "totalUsers 应为数字，实际: {v}");
    assert!(v["data"]["totalRoles"].is_number(), "totalRoles 应为数字，实际: {v}");
    assert!(v["data"]["activeRoles"].is_number(), "activeRoles 应为数字，实际: {v}");
    assert!(v["data"]["onlineCount"].is_number(), "onlineCount 应为数字，实际: {v}");
    assert!(v["data"]["todayLogins"].is_number(), "todayLogins 应为数字，实际: {v}");
    assert!(
        v["data"]["recentOperLogs"].is_array(),
        "recentOperLogs 应为数组，实际: {v}"
    );
}