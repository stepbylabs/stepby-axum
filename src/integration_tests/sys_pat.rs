// stepby-axum/src/integration_tests/sys_pat.rs
//! 个人访问令牌（PAT）模块链路集成测试（HTTP 端到端，Tier-S #3）：
//! - 自助签发：POST /system/user/profile/tokens 返回一次性明文（ybt_ 前缀）+ 脱敏视图（不含 token_hash）
//! - 参数校验：空 scopes / 非法 scope / 空名称 → 400
//! - 有效 scope 内访问 → 200；scope 外访问 → 403（scope ∩ 用户权限，超管用户权限恒真，由 scope 决定）
//! - 令牌管理接口禁止由 PAT 调用（防自我扩权）→ 403
//! - 自助列表 / 管理员列表（联属主用户名）
//! - scope_options：超管可授予 *:*:* 及通配分组
//! - 吊销即时生效：自助吊销后旧令牌 → 401；管理员吊销任意令牌 → 200 且旧令牌失效
//! - 未鉴权访问受保护接口 → 401

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

use super::TestContext;

/// 以指定 bearer 令牌（JWT 或 PAT 明文）构造请求，用于验证令牌维度的鉴权/授权行为。
fn bearer_request(
    ctx: &TestContext,
    bearer: &str,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", bearer));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pat_chain() {
    let ctx = TestContext::new().await;

    // 1. scope 选项：超管应能授予 *:*:* 与常用通配分组
    let v = ctx.get_json("/system/user/profile/tokens/scopes").await;
    let opts = v["data"].as_array().expect("scope 选项应为数组");
    assert!(
        opts.iter().any(|s| s.as_str() == Some("*:*:*")),
        "超管 scope 选项应含 *:*:*，实际: {opts:?}"
    );
    assert!(
        opts.iter().any(|s| s.as_str() == Some("system:*:*")),
        "超管 scope 选项应含 system:*:*，实际: {opts:?}"
    );

    // 2. 参数校验：空 scopes → 400
    let (status, _) = ctx
        .send_raw(bearer_request(
            &ctx,
            &ctx.token,
            Method::POST,
            "/system/user/profile/tokens",
            Some(serde_json::json!({ "name": "it_pat_empty", "scopes": [] })),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "空 scopes 应 400");

    // 3. 参数校验：非法 scope key → 400
    let (status, _) = ctx
        .send_raw(bearer_request(
            &ctx,
            &ctx.token,
            Method::POST,
            "/system/user/profile/tokens",
            Some(serde_json::json!({ "name": "it_pat_bad", "scopes": ["bad scope!"] })),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "非法 scope 应 400");

    // 4. 正常签发：仅授予 system:config:list（GET /system/config/list 所需权限）
    let v = ctx
        .post_json(
            "/system/user/profile/tokens",
            serde_json::json!({
                "name": "it_pat_config",
                "scopes": ["system:config:list"],
                "expireDays": 30
            }),
        )
        .await;
    let token = v["data"]["token"]
        .as_str()
        .expect("应返回明文 token")
        .to_string();
    assert!(
        token.starts_with("ybt_"),
        "明文令牌应以 ybt_ 前缀开头，实际: {token}"
    );
    let pat_id = v["data"]["pat"]["patId"]
        .as_str()
        .expect("patId")
        .to_string();
    assert_eq!(v["data"]["pat"]["name"], "it_pat_config");
    assert_eq!(v["data"]["pat"]["status"], "0");
    // 脱敏红线：出参绝不包含 token_hash
    assert!(
        v["data"]["pat"].get("tokenHash").is_none(),
        "脱敏视图不应泄漏 tokenHash，实际: {}",
        v["data"]["pat"]
    );

    // 5. PAT 访问 scope 内接口 → 200
    let (status, body) = ctx
        .send_raw(bearer_request(
            &ctx,
            &token,
            Method::GET,
            "/system/config/list?pageSize=5",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "scope 内访问应 200，实际: {status} {body}"
    );

    // 6. PAT 访问 scope 外接口 → 403（用户为超管权限恒真，但令牌 scope 不含）
    let (status, body) = ctx
        .send_raw(bearer_request(
            &ctx,
            &token,
            Method::GET,
            "/monitor/operlog/list?pageSize=5",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "scope 外访问应 403，实际: {status} {body}"
    );

    // 7. PAT 不得管理令牌本身（防自我签发/扩权）→ 403
    let (status, body) = ctx
        .send_raw(bearer_request(
            &ctx,
            &token,
            Method::GET,
            "/system/user/profile/tokens",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "PAT 访问令牌管理接口应 403，实际: {status} {body}"
    );

    // 8. 通配 scope：授予 monitor:*:* 的令牌可访问 monitor:operlog:list
    let v = ctx
        .post_json(
            "/system/user/profile/tokens",
            serde_json::json!({
                "name": "it_pat_monitor",
                "scopes": ["monitor:*:*"],
                "expireDays": 30
            }),
        )
        .await;
    let monitor_token = v["data"]["token"].as_str().expect("token").to_string();
    let (status, body) = ctx
        .send_raw(bearer_request(
            &ctx,
            &monitor_token,
            Method::GET,
            "/monitor/operlog/list?pageSize=5",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "monitor:*:* 令牌应可访问 operlog 列表，实际: {status} {body}"
    );

    // 9. 自助列表应含刚创建的 2 个令牌
    let v = ctx
        .get_json("/system/user/profile/tokens?pageSize=50")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 2, "自助列表应有 2 条令牌，实际: {rows:?}");
    assert!(
        rows.iter().all(|r| r.get("tokenHash").is_none()),
        "列表出参不得含 tokenHash"
    );

    // 10. 管理员列表（联属主用户名）：应显示 admin
    let v = ctx.get_json("/monitor/pat/list?pageSize=50").await;
    let arows = v["rows"].as_array().expect("管理员 rows 应为数组");
    assert!(
        arows
            .iter()
            .any(|r| r["userName"].as_str() == Some("admin")),
        "管理员列表应含属主 admin，实际: {arows:?}"
    );

    // 11. 自助吊销 config 令牌 → 旧令牌即时失效（401）
    ctx.delete_json(&format!("/system/user/profile/tokens/{}", pat_id))
        .await;
    let (status, body) = ctx
        .send_raw(bearer_request(
            &ctx,
            &token,
            Method::GET,
            "/system/config/list?pageSize=5",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "已吊销令牌应 401，实际: {status} {body}"
    );

    // 12. 管理员吊销 monitor 令牌 → 200 且旧令牌失效
    let monitor_pat_id = arows
        .iter()
        .find(|r| r["name"].as_str() == Some("it_pat_monitor"))
        .and_then(|r| r["patId"].as_str())
        .expect("管理员列表应含 it_pat_monitor")
        .to_string();
    let v = ctx
        .delete_json(&format!("/monitor/pat/{}", monitor_pat_id))
        .await;
    ctx.assert_ok(&v);
    let (status, _) = ctx
        .send_raw(bearer_request(
            &ctx,
            &monitor_token,
            Method::GET,
            "/monitor/operlog/list?pageSize=5",
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "管理员吊销后应 401");

    // 13. 吊销不存在/非本人的令牌 → 404（自助吊销越权保护）
    let (status, _) = ctx
        .send_raw(bearer_request(
            &ctx,
            &ctx.token,
            Method::DELETE,
            "/system/user/profile/tokens/nonexistent-pat-id",
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "吊销不存在令牌应 404");

    // 14. 无鉴权访问受保护接口 → 401
    let (status, _) = ctx
        .send_raw(
            Request::builder()
                .method(Method::GET)
                .uri("/system/config/list")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "无鉴权应 401");
}
