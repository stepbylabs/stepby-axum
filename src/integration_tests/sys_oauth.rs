// axum-backend/src/integration_tests/sys_oauth.rs
//! 第三方登录 / OAuth2 / OIDC 提供商链路集成测试：
//! - 公开端点：GET /oauth2/providers（启用提供商列表）、GET /oauth2/authorize
//! - 提供商管理：列表 / 详情 / 新增 → 修改 → 删除 / 启停（status）
//! - 绑定管理：GET /oauth2/my-bindings（当前账号绑定列表）
//!
//! 种子数据（m20260819_000001_oauth_module）：
//! github / gitee / wecom / oidc 四个提供商（provider_id 1..=4，enabled='0'）。
//!
//! 唯一前缀：it_oa。

use super::TestContext;
use axum::http::Method;

/// 公开端点 + 提供商分页/详情：种子数据与脱敏校验。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oauth_provider_list_and_detail() {
    let ctx = TestContext::new().await;

    // 1. 公开：启用提供商列表（种子均未启用，应为空数组）
    let v = ctx.get_json("/oauth2/providers").await;
    let providers = v["data"].as_array().expect("data 应为数组");
    assert!(
        providers.is_empty(),
        "种子提供商默认未启用，公开列表应为空，实际: {v}"
    );

    // 2. 分页列表（需登录）
    let v = ctx
        .get_json("/system/oauth/provider/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.len() >= 4, "种子应至少 4 个提供商，实际: {v}");
    assert_eq!(v["total"].as_u64(), Some(4), "提供商总数应为 4，实际: {v}");

    // 3. 详情（provider_id=1 为 github）——client_secret 必须脱敏
    let v = ctx.get_json("/system/oauth/provider/1").await;
    assert_eq!(v["data"]["providerId"], 1, "providerId 应为 1，实际: {v}");
    assert_eq!(
        v["data"]["providerCode"].as_str(),
        Some("github"),
        "providerCode 应为 github，实际: {v}"
    );
    assert_eq!(
        v["data"]["clientSecret"].as_str(),
        Some(""),
        "出参 client_secret 应脱敏为空串，实际: {v}"
    );
}

/// 提供商 CRUD 全链路：新增 → 修改 → 启停 → 删除。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oauth_provider_crud_chain() {
    let ctx = TestContext::new().await;

    // 1. 新增提供商
    let v = ctx
        .post_json(
            "/system/oauth/provider",
            serde_json::json!({
                "providerCode": "it_oa_github",
                "providerName": "集成测试 OAuth",
                "providerType": "github",
                "clientId": "it-client-id",
                "clientSecret": "it-client-secret",
                "authorizeUrl": "https://example.com/oauth/authorize",
                "tokenUrl": "https://example.com/oauth/token",
                "userInfoUrl": "https://example.com/oauth/userinfo",
                "scope": "read:user",
                "redirectUri": "http://localhost:5173/oauth-login",
                "autoCreateUser": "1",
                "enabled": "1",
                "displayOrder": 99,
                "remark": "集成测试"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let new_id = v["data"]["providerId"].as_i64().expect("应返回 providerId");

    // 2. 按 providerCode 过滤查询
    let v = ctx
        .get_json("/system/oauth/provider/list?providerCode=it_oa_github")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 个新提供商，实际: {v}");
    assert_eq!(
        rows[0]["clientSecret"].as_str(),
        Some(""),
        "列表出参 client_secret 应脱敏，实际: {v}"
    );

    // 3. 修改提供商
    let v = ctx
        .put_json(
            "/system/oauth/provider",
            serde_json::json!({
                "providerId": new_id,
                "providerCode": "it_oa_github",
                "providerName": "集成测试 OAuth 改",
                "providerType": "github",
                "clientId": "it-client-id-2",
                "clientSecret": "",
                "authorizeUrl": "https://example.com/oauth/authorize",
                "tokenUrl": "https://example.com/oauth/token",
                "userInfoUrl": "https://example.com/oauth/userinfo",
                "scope": "read:user",
                "redirectUri": "http://localhost:5173/oauth-login",
                "autoCreateUser": "1",
                "enabled": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 4. 详情确认修改生效
    let v = ctx
        .get_json(&format!("/system/oauth/provider/{}", new_id))
        .await;
    assert_eq!(
        v["data"]["providerName"].as_str(),
        Some("集成测试 OAuth 改"),
        "修改后的 providerName 应生效，实际: {v}"
    );

    // 5. 启停：停用（enabled=0）
    let v = ctx
        .put_json(
            &format!("/system/oauth/provider/{}/status?enabled=0", new_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!("/system/oauth/provider/{}", new_id))
        .await;
    assert_eq!(
        v["data"]["enabled"].as_str(),
        Some("0"),
        "停用后 enabled 应为 0，实际: {v}"
    );

    // 6. 再启用（enabled=1）后，公开端点应能看到该提供商
    let v = ctx
        .put_json(
            &format!("/system/oauth/provider/{}/status?enabled=1", new_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json("/oauth2/providers").await;
    let providers = v["data"].as_array().expect("data 应为数组");
    assert!(
        providers
            .iter()
            .any(|p| p["providerCode"] == "it_oa_github"),
        "启用后公开列表应包含新提供商，实际: {v}"
    );

    // 7. 删除提供商
    let v = ctx
        .delete_json(&format!("/system/oauth/provider/{}", new_id))
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/oauth/provider/list?providerCode=it_oa_github")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "删除后不应再查到该提供商，实际: {v}");
}

/// 提供商参数校验错误分支（确定性，无需外部依赖）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oauth_provider_validation_errors() {
    let ctx = TestContext::new().await;

    // 1. 非法 providerType → 400（provider_type_invalid）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/oauth/provider",
            Some(serde_json::json!({
                "providerCode": "it_oa_bad",
                "providerName": "非法类型",
                "providerType": "not-a-provider",
                "clientId": "x",
                "clientSecret": "x",
                "authorizeUrl": "https://example.com",
                "tokenUrl": "https://example.com",
                "userInfoUrl": "https://example.com",
                "scope": "read:user",
                "redirectUri": "https://example.com/callback"
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "非法 providerType 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "非法 providerType 应 400，实际: {status}"
    );

    // 2. 重复 providerCode → 400（provider_code_exists）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/oauth/provider",
            Some(serde_json::json!({
                "providerCode": "github",
                "providerName": "重复 code",
                "providerType": "github",
                "clientId": "x",
                "clientSecret": "x",
                "authorizeUrl": "https://example.com",
                "tokenUrl": "https://example.com",
                "userInfoUrl": "https://example.com",
                "scope": "read:user",
                "redirectUri": "https://example.com/callback"
            })),
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "重复 providerCode 业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "重复 providerCode 应 400，实际: {status}"
    );

    // 3. 批量删除传非法 ID（abc）→ 400（provider_id_invalid）
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/system/oauth/provider/abc", None))
        .await;
    assert_ne!(v["code"], 200, "非法 ID 删除业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "非法 ID 删除应 400，实际: {status}"
    );

    // 4. 删除不存在的提供商 → 404（provider_not_found）
    let (status, v) = ctx
        .send_raw(ctx.request(Method::DELETE, "/system/oauth/provider/999999", None))
        .await;
    assert_ne!(
        v["code"], 200,
        "删除不存在提供商业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "删除不存在提供商应 404，实际: {status}"
    );

    // 5. 启停非法 enabled 值 → 400（enabled_invalid）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/oauth/provider/1/status?enabled=2",
            Some(serde_json::json!({})),
        ))
        .await;
    assert_ne!(v["code"], 200, "非法 enabled 业务码不应为 200，实际: {v}");
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "非法 enabled 应 400，实际: {status}"
    );
}

/// 授权发起与绑定管理端点。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oauth_authorize_and_bindings() {
    let ctx = TestContext::new().await;

    // 1. 未启用提供商发起授权 → 400（provider_disabled）
    let (status, v) = ctx
        .send_raw(ctx.request(Method::GET, "/oauth2/authorize?providerCode=github", None))
        .await;
    assert_ne!(
        v["code"], 200,
        "未启用提供商授权业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "未启用提供商授权应 400，实际: {status}"
    );

    // 2. 不存在的提供商 → 404（provider_not_found）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::GET,
            "/oauth2/authorize?providerCode=nonexistent",
            None,
        ))
        .await;
    assert_ne!(
        v["code"], 200,
        "不存在提供商授权业务码不应为 200，实际: {v}"
    );
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "不存在提供商授权应 404，实际: {status}"
    );

    // 3. 当前账号绑定列表（新上下文无绑定，应为空数组）
    let v = ctx.get_json("/oauth2/my-bindings").await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(data.is_empty(), "初始应无任何第三方绑定，实际: {v}");
}
