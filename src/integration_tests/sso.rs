// axum-backend/src/integration_tests/sso.rs
//! 单点登录 / OIDC Provider（本系统作为授权服务器）端到端链路集成测试。
//!
//! 覆盖真实 HTTP 全栈（build_app + auth/permission/rate-limit 中间件 + Redis + sqlite），
//! 验证规范要求的授权码 + PKCE(S256) 流程与各安全红线：
//! - 发现文档 / 客户端 CRUD / 启停 / 删除；
//! - consent_required='0'：authorize 直接签发一次性授权码 → token(code+PKCE) → userinfo；
//! - 安全负向：授权码重放、PKCE 校验失败、redirect_uri 不在白名单、未登录引导、错误凭据；
//! - consent_required='1'：authorize → NeedConsent 引导同意页 → POST /sso/consent 批准 → token。
//!
//! PKCE 使用 RFC 7636 附录 B 已知向量（确定性，无需在测试内实现哈希）：
//!   verifier  = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
//!   challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
//!
//! 唯一 clientName 前缀：it_sso。

use std::net::SocketAddr;

use super::TestContext;
use axum::Router;
use axum::body::Body;
use axum::body::to_bytes;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{HeaderMap, HeaderName, Method, Request, StatusCode};
use tower::ServiceExt;

/// RFC 7636 附录 B 固定向量
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// 客户端登记的回调地址（与 authorize/token 携带值保持一致）
const REDIRECT_URI: &str = "https://app.test/sso/callback";
/// REDIRECT_URI 的 percent-encoded 形式（用于 query / 表单）
const REDIRECT_URI_ENC: &str = "https%3A%2F%2Fapp.test%2Fsso%2Fcallback";

/// 构建启用了 SSO 的隔离测试上下文。
///
/// 通过 `SSO_ENABLED=true` 环境变量注入（与集成测试框架注入 JWT_SECRET 同一手法）；
/// 该开关仅被 5 个 OIDC 公开端点与 /sso/consent 读取，对其它并行测试无副作用。
async fn sso_ctx() -> TestContext {
    unsafe {
        std::env::set_var("SSO_ENABLED", "true");
    }
    TestContext::new().await
}

/// 低层 GET 请求（可带任意头，如 Cookie / Bearer），返回状态码 + 头 + 体。
async fn raw_get(
    app: &Router,
    peer: std::net::IpAddr,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut b = Request::builder().method(Method::GET).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let mut req = b.body(Body::empty()).expect("构造 GET 请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((peer, 1234))));
    let resp = app.clone().oneshot(req).await.expect("GET 执行失败");
    decode(resp).await
}

/// 低层 POST 请求（任意 content-type + 原始体），返回状态码 + 头 + 体。
async fn raw_post(
    app: &Router,
    peer: std::net::IpAddr,
    uri: &str,
    content_type: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", content_type);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let mut req = b
        .body(Body::from(body.to_string()))
        .expect("构造 POST 请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((peer, 1234))));
    let resp = app.clone().oneshot(req).await.expect("POST 执行失败");
    decode(resp).await
}

async fn decode(resp: axum::response::Response) -> (StatusCode, HeaderMap, Vec<u8>) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取响应体失败")
        .to_vec();
    (status, headers, body)
}

fn json_of(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap_or_else(|e| {
        panic!(
            "响应非合法 JSON: {e}\nbody={}",
            String::from_utf8_lossy(body)
        )
    })
}

fn location_of(headers: &HeaderMap) -> String {
    headers
        .get(HeaderName::from_static("location"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| panic!("302 响应应含 Location 头，实际: {headers:?}"))
        .to_string()
}

/// 从回跳 URL 中解析 query 参数值（仅本测试用，够精确即可）。
fn query_param(url: &str, key: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(v.to_string());
        }
    }
    None
}

/// 组装授权端点 URL。
fn authorize_url(client_id: &str, challenge: &str, redirect_uri_enc: &str) -> String {
    format!(
        "/sso/authorize?client_id={}&response_type=code&scope=openid%20profile&redirect_uri={}&state=st_42&code_challenge={}&code_challenge_method=S256",
        urlenc(client_id),
        redirect_uri_enc,
        urlenc(challenge)
    )
}

fn urlenc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// 解码 JWT 的 payload 段（base64url，不校验签名——仅用于断言声明不变量）。
fn decode_jwt_payload(jwt: &str) -> serde_json::Value {
    use base64::Engine;
    let payload = jwt.split('.').nth(1).expect("id_token 应为三段 JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .expect("id_token payload 应为合法 base64url");
    serde_json::from_slice(&bytes).expect("id_token payload 应为合法 JSON")
}

/// 组装令牌端点表单体。
fn token_form(code: &str, client_id: &str, client_secret: &str, verifier: &str) -> String {
    format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
        urlenc(code),
        REDIRECT_URI_ENC,
        urlenc(client_id),
        urlenc(client_secret),
        urlenc(verifier),
    )
}

/// 新增一个 consent_required 可控的客户端，返回 (clientId, 一次性明文 clientSecret)。
async fn add_client(ctx: &TestContext, consent_required: &str, name: &str) -> (String, String) {
    let v = ctx
        .post_json(
            "/system/oauth/client",
            serde_json::json!({
                "clientName": name,
                "redirectUris": [REDIRECT_URI],
                "scopes": ["openid", "profile", "email"],
                "consentRequired": consent_required,
                "enabled": "1",
                "remark": "集成测试 SSO 客户端"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let cid = v["data"]["clientId"]
        .as_str()
        .expect("新增应返回 clientId")
        .to_string();
    let secret = v["data"]["clientSecret"]
        .as_str()
        .expect("新增应返回一次性明文 clientSecret")
        .to_string();
    assert!(!secret.is_empty(), "clientSecret 不应为空");
    (cid, secret)
}

/// 完整快乐路径：发现文档 → 新增客户端(免同意) → authorize(带会话 Cookie) 拿 code →
/// token(code+PKCE) → userinfo(Bearer)。并验证授权码一次性（重放失败）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_full_flow_and_replay() {
    let ctx = sso_ctx().await;

    // 1. 发现文档（公开，bare JSON）
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        "/.well-known/openid-configuration",
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "发现文档应 200");
    let doc = json_of(&body);
    assert_eq!(doc["response_types_supported"][0], "code");
    assert_eq!(doc["code_challenge_methods_supported"][0], "S256");
    assert_eq!(doc["id_token_signing_alg_values_supported"][0], "HS256");
    assert!(
        doc["token_endpoint"]
            .as_str()
            .unwrap_or_default()
            .ends_with("/sso/token"),
        "发现文档端点应指向 /sso/*，实际: {doc}"
    );

    // 2. 新增免同意客户端
    let (cid, secret) = add_client(&ctx, "0", "it_sso_flow").await;

    // 3. authorize（携带 Admin-Token 会话 Cookie）→ 302 回跳带 code
    let cookie = format!("Admin-Token={}", ctx.token);
    let (status, headers, abody) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &authorize_url(&cid, PKCE_CHALLENGE, REDIRECT_URI_ENC),
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "免同意 authorize 应 302，body={}", String::from_utf8_lossy(&abody));
    let loc = location_of(&headers);
    assert!(
        loc.starts_with(REDIRECT_URI),
        "回跳应指向登记地址，实际: {loc}"
    );
    assert_eq!(
        query_param(&loc, "state").as_deref(),
        Some("st_42"),
        "state 应回显"
    );
    let code = query_param(&loc, "code").expect("回跳应含 code");

    // 4. token 交换（code + PKCE verifier）→ 200 含 access_token + id_token
    let (status, _, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &token_form(&code, &cid, &secret, PKCE_VERIFIER),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token 交换应 200，body={}",
        String::from_utf8_lossy(&body)
    );
    let tr = json_of(&body);
    assert_eq!(tr["token_type"], "Bearer");
    let access_token = tr["access_token"]
        .as_str()
        .expect("应返回 access_token")
        .to_string();
    assert!(
        !tr["id_token"].as_str().unwrap_or_default().is_empty(),
        "应返回 id_token，实际: {tr}"
    );

    // 4b. id_token 声明不变量：iss 必须恒等于发现文档 advertised issuer（否则合规 RP 校验 iss 会拒绝）。
    //     这是曾经的真实缺陷：SSO_ISSUER 未配置时 discovery 回退 base_url、而 id_token 误回退 jwt.issuer。
    let id_claims = decode_jwt_payload(tr["id_token"].as_str().unwrap());
    assert_eq!(
        id_claims["iss"].as_str().unwrap_or_default(),
        doc["issuer"].as_str().unwrap_or_default(),
        "id_token iss 必须等于发现文档 issuer，iss={:?} discovery={:?}",
        id_claims["iss"].as_str(),
        doc["issuer"].as_str()
    );
    assert_eq!(id_claims["aud"].as_str().unwrap_or_default(), cid, "id_token aud 应为 client_id");
    assert!(
        !id_claims["sub"].as_str().unwrap_or_default().is_empty(),
        "id_token sub 应非空，实际: {id_claims}"
    );
    assert!(id_claims["exp"].as_i64().unwrap_or(0) > id_claims["iat"].as_i64().unwrap_or(0), "exp 应晚于 iat");

    // 5. userinfo（Bearer access_token）→ 200，sub 非空
    let bearer = format!("Bearer {access_token}");
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        "/sso/userinfo",
        &[("authorization", bearer.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "userinfo 应 200");
    let ui = json_of(&body);
    assert!(
        ui["sub"].as_str().is_some_and(|s| !s.is_empty()),
        "userinfo sub 应非空，实际: {ui}"
    );
    // scope 含 profile → 返回 preferred_username
    assert_eq!(
        ui["preferred_username"].as_str(),
        Some("admin"),
        "profile scope 应回显 preferred_username，实际: {ui}"
    );

    // 6. 授权码一次性：重放同一 code → 400 invalid_grant
    let (status, _, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &token_form(&code, &cid, &secret, PKCE_VERIFIER),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "重放授权码应 400");
    assert_eq!(
        json_of(&body)["error"].as_str(),
        Some("invalid_grant"),
        "重放应返回 invalid_grant，实际: {}",
        String::from_utf8_lossy(&body)
    );

    // 7. 清理：删除客户端
    let v = ctx
        .delete_json(&format!(
            "/system/oauth/client/{}",
            cid_pk(&ctx, &cid).await
        ))
        .await;
    ctx.assert_ok(&v);
}

/// 负向安全：PKCE 校验失败、错误 client_secret、未登录引导、redirect_uri 不在白名单。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_security_negative_paths() {
    let ctx = sso_ctx().await;
    let (cid, secret) = add_client(&ctx, "0", "it_sso_neg").await;
    let cookie = format!("Admin-Token={}", ctx.token);

    // 1. PKCE verifier 与 challenge 不匹配 → 400 invalid_grant
    let (status, headers, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &authorize_url(&cid, PKCE_CHALLENGE, REDIRECT_URI_ENC),
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let code = query_param(&location_of(&headers), "code").expect("应含 code");
    let (status, _, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &token_form(
            &code,
            &cid,
            &secret,
            "wrong-verifier-value-00000000000000000000000000x",
        ),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "PKCE 不匹配应 400");
    assert_eq!(json_of(&body)["error"].as_str(), Some("invalid_grant"));

    // 2. 错误 client_secret → 400 invalid_client（需重新取码，上一 code 已消耗）
    let (status, headers, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &authorize_url(&cid, PKCE_CHALLENGE, REDIRECT_URI_ENC),
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "重取授权码应 302");
    let code2 = query_param(&location_of(&headers), "code").expect("应含 code");
    let (status, _, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &token_form(&code2, &cid, "not-the-real-secret", PKCE_VERIFIER),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "错误密钥应 400");
    assert_eq!(json_of(&body)["error"].as_str(), Some("invalid_client"));

    // 3. 未登录（无 Cookie）→ 302 引导 /login
    let (status, headers, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &authorize_url(&cid, PKCE_CHALLENGE, REDIRECT_URI_ENC),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "未登录应 302");
    let loc = location_of(&headers);
    assert!(loc.starts_with("/login"), "未登录应回跳登录页，实际: {loc}");
    // redirect 参数必须是同源相对路径（%2F/sso/authorize…）：绝对 URL（含 %3A%2F%2F 即 ://）
    // 会被前端 isSafeRedirect 开放重定向守卫拒绝 → 登录后回落首页 → RP 链路断裂（E2E 审计回归）
    assert!(
        loc.starts_with("/login?redirect=%2Fsso%2Fauthorize"),
        "redirect 必须挂相对 authorize 路径，实际: {loc}"
    );
    assert!(!loc.contains("%3A%2F%2F"), "redirect 不应混入绝对 URL: {loc}");

    // 4. redirect_uri 不在白名单 → 不可回跳（硬错误 400，防开放重定向）
    let bad = "/sso/authorize?client_id=PLACEHOLDER&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fevil.test%2Fcb&code_challenge=x&code_challenge_method=S256"
        .replace("PLACEHOLDER", &urlenc(&cid));
    let (status, _, body) =
        raw_get(&ctx.app, ctx.peer_ip, &bad, &[("cookie", cookie.as_str())]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "非法 redirect_uri 应硬错误 400（不开放重定向），body={}",
        String::from_utf8_lossy(&body)
    );
}

/// consent_required='1'：authorize → NeedConsent 引导同意页 → POST /sso/consent 批准 → token。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_consent_flow() {
    let ctx = sso_ctx().await;
    let (cid, secret) = add_client(&ctx, "1", "it_sso_consent").await;
    let cookie = format!("Admin-Token={}", ctx.token);

    // 1. authorize（需同意）→ 302 到 /sso-consent，不含 code
    let (status, headers, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &authorize_url(&cid, PKCE_CHALLENGE, REDIRECT_URI_ENC),
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    let loc = location_of(&headers);
    assert!(
        loc.starts_with("/sso-consent"),
        "需同意时应引导至同意页，实际: {loc}"
    );
    assert!(
        query_param(&loc, "code").is_none(),
        "同意页阶段不应签发 code"
    );

    // 2. 同意页批准（受保护，Bearer 登录态）→ 返回 { redirect } 含 code
    let v = ctx
        .post_json(
            "/sso/consent",
            serde_json::json!({
                "clientId": cid,
                "redirectUri": REDIRECT_URI,
                "scope": "openid profile",
                "state": "st_42",
                "codeChallenge": PKCE_CHALLENGE,
                "codeChallengeMethod": "S256",
                "approved": true
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let redirect = v["data"]["redirect"]
        .as_str()
        .expect("同意批准应返回 redirect");
    assert!(
        redirect.starts_with(REDIRECT_URI),
        "回跳登记地址，实际: {redirect}"
    );
    let code = query_param(redirect, "code").expect("批准应签发 code");

    // 3. token 交换（同一 PKCE）→ 200
    let (status, _, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &token_form(&code, &cid, &secret, PKCE_VERIFIER),
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "同意后 token 应 200，body={}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        json_of(&body)["access_token"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );

    // 4. 二次 authorize：已同意且 scope 覆盖 → 直接签发 code（不再引导同意页）
    let (status, headers, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &authorize_url(&cid, PKCE_CHALLENGE, REDIRECT_URI_ENC),
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        location_of(&headers).starts_with(REDIRECT_URI),
        "已同意应直接回跳，实际: {}",
        location_of(&headers)
    );
}

/// 客户端管理 CRUD + 启停 + 列表过滤（受 RBAC 权限 system:oauth:client:* 保护）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_client_crud_and_toggle() {
    let ctx = sso_ctx().await;
    let (cid, _) = add_client(&ctx, "0", "it_sso_crud").await;
    let pk = cid_pk(&ctx, &cid).await;

    // 详情：clientSecret / idTokenSecret 均不得出现在出参
    let v = ctx.get_json(&format!("/system/oauth/client/{pk}")).await;
    assert_eq!(v["data"]["clientId"].as_str(), Some(cid.as_str()));
    assert_eq!(v["data"]["consentRequired"].as_str(), Some("0"));
    assert!(
        v["data"].get("clientSecret").is_none(),
        "详情出参不应含 clientSecret，实际: {v}"
    );
    assert!(
        v["data"].get("clientSecretHash").is_none() && v["data"].get("idTokenSecret").is_none(),
        "详情出参不应泄漏密钥，实际: {v}"
    );

    // 修改：改名 + 关掉 email scope
    let v = ctx
        .put_json(
            "/system/oauth/client",
            serde_json::json!({
                "ssoClientId": pk,
                "clientId": cid,
                "clientName": "it_sso_crud 改",
                "redirectUris": [REDIRECT_URI],
                "scopes": ["openid", "profile"],
                "consentRequired": "0",
                "enabled": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/oauth/client/{pk}")).await;
    assert_eq!(v["data"]["clientName"].as_str(), Some("it_sso_crud 改"));

    // 启停：停用后 authorize 应被拒（client_disabled → 硬错误 400）
    let v = ctx
        .put_json(
            &format!("/system/oauth/client/{pk}/status?enabled=0"),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    let cookie = format!("Admin-Token={}", ctx.token);
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &authorize_url(&cid, PKCE_CHALLENGE, REDIRECT_URI_ENC),
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "停用客户端 authorize 应 400，body={}",
        String::from_utf8_lossy(&body)
    );

    // 列表按 clientName 过滤命中
    let v = ctx
        .get_json("/system/oauth/client/list?clientName=it_sso_crud&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 数组");
    assert!(
        rows.iter()
            .any(|r| r["clientId"].as_str() == Some(cid.as_str())),
        "列表应含新建客户端，实际: {v}"
    );

    // 删除
    let v = ctx.delete_json(&format!("/system/oauth/client/{pk}")).await;
    ctx.assert_ok(&v);
}

/// 通过列表按 clientId 反查内部主键 ssoClientId。
async fn cid_pk(ctx: &TestContext, client_id: &str) -> i64 {
    let v = ctx
        .get_json(&format!(
            "/system/oauth/client/list?clientId={}&pageSize=10",
            urlenc(client_id)
        ))
        .await;
    let rows = v["rows"].as_array().expect("rows 数组");
    rows.iter()
        .find(|r| r["clientId"].as_str() == Some(client_id))
        .and_then(|r| r["ssoClientId"].as_i64())
        .unwrap_or_else(|| panic!("未能按 clientId={client_id} 反查主键，实际: {v}"))
}
