// stepby-axum/src/integration_tests/auth.rs
//! 认证链路集成测试：登录 → getInfo → getRouters → logout，以及未授权/伪造 token 拒绝。

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use tower::ServiceExt;

use super::TestContext;
use super::next_peer_ip;

/// 端到端冒烟：login → getInfo → 401 链路。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_login_then_getinfo_smoke() {
    let ctx = TestContext::new().await;
    let app = ctx.app;

    // 1. 登录（TestContext 已用 admin/admin123 登录，token 非空）
    assert!(!ctx.token.is_empty(), "token 不应为空");

    // 2. 携带 token 获取用户信息
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/getInfo")
                .header("authorization", format!("Bearer {}", ctx.token))
                .body(Body::empty())
                .expect("构造 getInfo 请求失败"),
        )
        .await
        .expect("getInfo 请求执行失败");
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "getInfo（带有效 token）应返回 HTTP 200"
    );

    let body2 = to_bytes(resp2.into_body(), usize::MAX)
        .await
        .expect("读取 getInfo 响应体失败");
    let v2: serde_json::Value = serde_json::from_slice(&body2).expect("getInfo 响应 JSON 解析失败");
    assert_eq!(v2["code"], 200, "getInfo 业务码应为 200，实际: {:?}", v2);
    assert_eq!(
        v2["user"]["userName"].as_str(),
        Some("admin"),
        "getInfo 应返回 admin 用户，实际: {:?}",
        v2
    );

    let roles = v2["roles"].as_array().expect("roles 应为数组");
    assert!(
        roles.iter().any(|r| r.as_str() == Some("admin")),
        "admin 用户的 roles 应包含 'admin'，实际: {:?}",
        v2
    );
    let perms = v2["permissions"].as_array().expect("permissions 应为数组");
    assert!(
        perms.iter().any(|p| p.as_str() == Some("*:*:*")),
        "admin 用户的 permissions 应包含 '*:*:*'，实际: {:?}",
        v2
    );

    // 3. 无 token 访问受保护接口 → 401
    let resp3 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/getInfo")
                .body(Body::empty())
                .expect("构造无 token getInfo 请求失败"),
        )
        .await
        .expect("无 token getInfo 请求执行失败");
    assert_eq!(
        resp3.status(),
        StatusCode::UNAUTHORIZED,
        "无 token 访问受保护接口应返回 401"
    );

    // 4. 伪造 token 访问受保护接口 → 401
    let resp4 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/getInfo")
                .header("authorization", "Bearer not.a.real.token")
                .body(Body::empty())
                .expect("构造伪造 token getInfo 请求失败"),
        )
        .await
        .expect("伪造 token getInfo 请求执行失败");
    assert_eq!(
        resp4.status(),
        StatusCode::UNAUTHORIZED,
        "伪造 token 访问受保护接口应返回 401"
    );
}

/// getRouters 返回路由树，logout 后旧 token 立即失效。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_getrouters_and_logout_chain() {
    let ctx = TestContext::new().await;

    // 1. getRouters → code 200，data 为路由数组
    let v = ctx.get_json("/getRouters").await;
    let routers = v["data"].as_array().expect("getRouters data 应为数组");
    assert!(
        !routers.is_empty(),
        "admin 的 getRouters 不应为空，实际: {:?}",
        v
    );

    // 2. logout → code 200
    let v = ctx.post_json("/logout", serde_json::json!({})).await;
    ctx.assert_ok(&v);

    // 3. logout 后旧 token 失效 → 401
    let (status, _) = ctx
        .send_raw(
            Request::builder()
                .method("GET")
                .uri("/getInfo")
                .header("authorization", format!("Bearer {}", ctx.token))
                .body(Body::empty())
                .expect("构造请求失败"),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "logout 后旧 token 应返回 401"
    );
}

/// 公开接口 /captchaImage 无需鉴权即可访问。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_captcha_public() {
    let (state, _slot) = super::build_isolated_state().await;
    // 验证码默认被测试 harness 关闭，这里显式开启，走真实的图片生成 + Redis 存储链路
    state
        .db
        .execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "UPDATE sys_config SET config_value='true' WHERE config_key='sys.account.captchaEnabled'",
        ))
        .await
        .expect("开启验证码开关失败");
    let app = crate::router::build_app(state);
    let peer_ip = next_peer_ip();

    let mut req = Request::builder()
        .method("GET")
        .uri("/captchaImage")
        .body(Body::empty())
        .expect("构造 captchaImage 请求失败");
    // captcha handler 需要 ConnectInfo<SocketAddr>，oneshot 不会自动注入，这里手动补
    req.extensions_mut()
        .insert(axum::extract::connect_info::ConnectInfo(
            std::net::SocketAddr::from((peer_ip, 1234)),
        ));

    let resp = app.oneshot(req).await.expect("captchaImage 请求执行失败");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "captchaImage 应返回 HTTP 200"
    );
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取 captchaImage 响应体失败");
    let v: serde_json::Value =
        serde_json::from_slice(&body).expect("captchaImage 响应 JSON 解析失败");
    assert_eq!(v["code"], 200, "captchaImage 业务码应为 200，实际: {:?}", v);
    assert!(
        v["img"].is_string() && !v["img"].as_str().unwrap().is_empty(),
        "captchaImage 应返回 base64 图片"
    );
    assert!(v["uuid"].is_string(), "captchaImage 应返回 uuid");
}

/// 嵌套前缀 /prod-api 下的登录与受保护接口同样可用（同源部署场景）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_prod_api_prefix() {
    let (state, _slot) = super::build_isolated_state().await;
    let app = crate::router::build_app(state);
    let peer_ip = next_peer_ip();

    let body = serde_json::json!({
        "username": "admin",
        "password": "admin123",
        "code": "",
        "uuid": ""
    })
    .to_string();
    let mut req = Request::builder()
        .method("POST")
        .uri("/prod-api/login")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("构造 login 请求失败");
    req.extensions_mut()
        .insert(axum::extract::connect_info::ConnectInfo(
            std::net::SocketAddr::from((peer_ip, 1234)),
        ));

    let resp = app.clone().oneshot(req).await.expect("login 请求执行失败");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "prod-api/login 应返回 HTTP 200"
    );
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取 login 响应体失败");
    let v: serde_json::Value = serde_json::from_slice(&body).expect("login 响应 JSON 解析失败");
    assert_eq!(
        v["code"], 200,
        "prod-api/login 业务码应为 200，实际: {:?}",
        v
    );
    let token = v["token"].as_str().expect("应返回 token").to_string();

    // 受保护接口带前缀访问
    let resp2 = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/prod-api/getInfo")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .expect("构造 getInfo 请求失败"),
        )
        .await
        .expect("getInfo 请求执行失败");
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "prod-api/getInfo 应返回 200"
    );
    let body2 = to_bytes(resp2.into_body(), usize::MAX)
        .await
        .expect("读取 getInfo 响应体失败");
    let v2: serde_json::Value = serde_json::from_slice(&body2).expect("getInfo 响应 JSON 解析失败");
    assert_eq!(
        v2["code"], 200,
        "prod-api/getInfo 业务码应为 200，实际: {:?}",
        v2
    );
}
