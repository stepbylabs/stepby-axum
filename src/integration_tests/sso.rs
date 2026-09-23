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
use base64::Engine as _;
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
        // v4-P1-2：enabled=true 时 validate_secrets 强制要求显式 https issuer
        //（禁止按请求 Host 推导），测试与其对齐，同时覆盖 issuer 恒定语义
        std::env::set_var("SSO_ISSUER", "https://sso.test");
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
    add_client_uris(ctx, consent_required, name, &[REDIRECT_URI]).await
}

/// 同 add_client，但可指定回调地址白名单（跨客户端拒绝用例需要互异的地址）。
async fn add_client_uris(
    ctx: &TestContext,
    consent_required: &str,
    name: &str,
    uris: &[&str],
) -> (String, String) {
    add_client_full(ctx, consent_required, name, uris, None).await
}

/// 完整参数客户端创建（v5-D3：grant_types 可指定，供 refresh_token 链路测试）。
async fn add_client_full(
    ctx: &TestContext,
    consent_required: &str,
    name: &str,
    uris: &[&str],
    grant_types: Option<&[&str]>,
) -> (String, String) {
    let mut payload = serde_json::json!({
        "clientName": name,
        "redirectUris": uris,
        "scopes": ["openid", "profile", "email"],
        "consentRequired": consent_required,
        "enabled": "1",
        "remark": "集成测试 SSO 客户端"
    });
    if let Some(g) = grant_types {
        payload["grantTypes"] = serde_json::json!(g);
    }
    let v = ctx.post_json("/system/oauth/client", payload).await;
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
    // v5-D2：RS256 为推荐算法（HS256 兼容保留）
    assert_eq!(doc["id_token_signing_alg_values_supported"][0], "RS256");
    assert!(doc["jwks_uri"].is_string(), "RS256 形态应声明 jwks_uri");
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
    assert_eq!(
        status,
        StatusCode::FOUND,
        "免同意 authorize 应 302，body={}",
        String::from_utf8_lossy(&abody)
    );
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
    assert_eq!(
        id_claims["aud"].as_str().unwrap_or_default(),
        cid,
        "id_token aud 应为 client_id"
    );
    assert!(
        !id_claims["sub"].as_str().unwrap_or_default().is_empty(),
        "id_token sub 应非空，实际: {id_claims}"
    );
    assert!(
        id_claims["exp"].as_i64().unwrap_or(0) > id_claims["iat"].as_i64().unwrap_or(0),
        "exp 应晚于 iat"
    );

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

    // 2. 错误 client_secret → 401 invalid_client + WWW-Authenticate: Basic
    //   （RFC 6749 §5.2，v2-C2；需重新取码，上一 code 已消耗）
    let (status, headers, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &authorize_url(&cid, PKCE_CHALLENGE, REDIRECT_URI_ENC),
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "重取授权码应 302");
    let code2 = query_param(&location_of(&headers), "code").expect("应含 code");
    let (status, headers, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &token_form(&code2, &cid, "not-the-real-secret", PKCE_VERIFIER),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "错误密钥应 401");
    assert_eq!(json_of(&body)["error"].as_str(), Some("invalid_client"));
    assert!(
        headers.get("www-authenticate").is_some(),
        "invalid_client 401 应带 WWW-Authenticate（v2-C2）"
    );

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
    assert!(
        !loc.contains("%3A%2F%2F"),
        "redirect 不应混入绝对 URL: {loc}"
    );

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

// ==================== v4 加固专项（P0-A / P0-B / §7 / §6 / R1 / R8） ====================

/// 带自定义 scope 的 authorize URL（email claim 用例需要）
fn authorize_url_scopes(client_id: &str, challenge: &str, scope: &str) -> String {
    format!(
        "/sso/authorize?client_id={}&response_type=code&scope={}&redirect_uri={}&state=st_42&code_challenge={}&code_challenge_method=S256",
        urlenc(client_id),
        urlenc(scope),
        REDIRECT_URI_ENC,
        urlenc(challenge)
    )
}

/// authorize（带会话 Cookie）→ 提取一次性 code
async fn obtain_code(ctx: &TestContext, cid: &str, scope: &str) -> String {
    let cookie = format!("Admin-Token={}", ctx.token);
    let (status, headers, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &authorize_url_scopes(cid, PKCE_CHALLENGE, scope),
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "authorize 应 302，body={}",
        String::from_utf8_lossy(&body)
    );
    let loc = location_of(&headers);
    query_param(&loc, "code").expect("回跳应含 code")
}

/// token 交换 → (access_token, id_token, 响应头)
async fn exchange_token(
    ctx: &TestContext,
    code: &str,
    cid: &str,
    secret: &str,
    with_redirect_uri: bool,
) -> (serde_json::Value, HeaderMap) {
    let mut form = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&code_verifier={}",
        urlenc(code),
        urlenc(cid),
        urlenc(secret),
        urlenc(PKCE_VERIFIER)
    );
    if with_redirect_uri {
        form.push_str(&format!("&redirect_uri={REDIRECT_URI_ENC}"));
    }
    let (status, headers, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &form,
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token 交换应 200，body={}",
        String::from_utf8_lossy(&body)
    );
    (json_of(&body), headers)
}

/// userinfo 请求状态码
async fn userinfo_status(ctx: &TestContext, access_token: &str) -> StatusCode {
    let bearer = format!("Bearer {access_token}");
    let (status, _, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        "/sso/userinfo",
        &[("authorization", bearer.as_str())],
    )
    .await;
    status
}

/// v4-P0-A：access_token 为不透明令牌——
/// ① 形如随机串（非三段 JWT）；② 不能访问平台业务 API（越权隔离）；
/// ③ token/userinfo 响应携带 Cache-Control: no-store（RFC 6749 §5.1）；
/// ④ id_token 携带 auth_time + at_hash；⑤ email scope 走通完整数据链路。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_v4_opaque_token_isolation_and_claims() {
    let ctx = sso_ctx().await;
    let (cid, secret) = add_client(&ctx, "0", "it_sso_v4opaque").await;

    let code = obtain_code(&ctx, &cid, "openid profile email").await;
    let (tr, token_headers) = exchange_token(&ctx, &code, &cid, &secret, true).await;
    let access_token = tr["access_token"]
        .as_str()
        .expect("应返回 access_token")
        .to_string();

    // ① 不透明令牌：不是 JWT（无 '.' 三段结构）
    assert!(
        !access_token.contains('.'),
        "SSO access_token 必须为不透明令牌（不得复用平台 JWT），实际: {access_token}"
    );

    // ③ no-store 头（RFC 6749 §5.1）
    let cache_control = token_headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cache_control.contains("no-store"),
        "token 响应必须携带 Cache-Control: no-store，实际: {cache_control}"
    );

    // ② 业务 API 越权隔离：SSO AT 调 /getInfo 必须 401
    let bearer = format!("Bearer {access_token}");
    let (status, _, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        "/getInfo",
        &[("authorization", bearer.as_str())],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "SSO 访问令牌不得访问平台业务 API（v4-P0-A 越权隔离）"
    );

    // ④ id_token 声明：auth_time 为登录认证时刻（iat 同源）、at_hash 存在
    let id_claims = decode_jwt_payload(tr["id_token"].as_str().unwrap());
    assert!(
        id_claims["auth_time"].as_i64().unwrap_or(0) > 0,
        "id_token 应携带 auth_time（v3 P1'-1），实际: {id_claims}"
    );
    assert!(
        id_claims["at_hash"].as_str().is_some_and(|s| !s.is_empty()),
        "id_token 应携带 at_hash（v4 C7），实际: {id_claims}"
    );
    // ⑤ v5-E5：认证强度声明（admin 未启用 TOTP → acr="pwd"、amr=["pwd"]）
    assert_eq!(
        id_claims["acr"].as_str(),
        Some("pwd"),
        "未启用 TOTP 用户 acr 应为 pwd，实际: {id_claims}"
    );
    assert_eq!(
        id_claims["amr"][0].as_str(),
        Some("pwd"),
        "amr 应含 pwd，实际: {id_claims}"
    );

    // ⑤ email 数据链路：scope 含 email → userinfo 返回 email + email_verified:false
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
        ui["email"].is_string(),
        "email scope 应回显 email claim（v4 §6），实际: {ui}"
    );
    assert_eq!(ui["email_verified"], serde_json::json!(false));

    // ⑥ v5-D2：JWKS 端点聚合该客户端的 RS256 公钥（kid=client_id），私钥不出库
    let (jw_status, _, jw_body) = raw_get(&ctx.app, ctx.peer_ip, "/sso/jwks", &[]).await;
    assert_eq!(jw_status, StatusCode::OK, "jwks 应 200");
    let jw = json_of(&jw_body);
    let jwk = jw["keys"]
        .as_array()
        .expect("keys 数组")
        .iter()
        .find(|k| k["kid"].as_str() == Some(cid.as_str()))
        .unwrap_or_else(|| panic!("jwks 应含该客户端公钥，实际: {jw}"));
    assert_eq!(jwk["kty"], "RSA");
    assert_eq!(jwk["alg"], "RS256");
    assert!(jwk["n"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(jwk["e"], "AQAB", "RSA 公钥指数默认 65537");
}

/// v5-D4：prompt=none 静默模式——
/// ① 未登录 + prompt=none → 302 回跳 error=login_required（redirect_uri 可信前提下）；
/// ② 未登录 + 无 prompt → 引导登录页（行为不变）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_d4_prompt_none_requires_error_redirect() {
    let ctx = sso_ctx().await;
    let (cid, _secret) = add_client(&ctx, "0", "it_sso_d4pn").await;

    // ① prompt=none（未登录）→ 302 回跳 error=login_required
    let auth_url = format!(
        "/sso/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&prompt=none&code_challenge={}&code_challenge_method=S256",
        urlenc(&cid),
        REDIRECT_URI_ENC,
        PKCE_CHALLENGE
    );
    let (status, headers, _) = raw_get(&ctx.app, ctx.peer_ip, &auth_url, &[]).await;
    assert_eq!(status, StatusCode::FOUND, "prompt=none 应 302 回跳 error");
    let loc = location_of(&headers);
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("login_required"),
        "prompt=none 未登录应回跳 login_required，实际: {loc}"
    );

    // ② 无 prompt（未登录）→ 302 登录页（行为不变）
    let auth_url2 = format!(
        "/sso/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&code_challenge={}&code_challenge_method=S256",
        urlenc(&cid),
        REDIRECT_URI_ENC,
        PKCE_CHALLENGE
    );
    let (status2, headers2, _) = raw_get(&ctx.app, ctx.peer_ip, &auth_url2, &[]).await;
    assert_eq!(status2, StatusCode::FOUND);
    let loc2 = location_of(&headers2);
    assert!(
        loc2.starts_with("/login"),
        "无 prompt 未登录应引导登录页，实际: {loc2}"
    );
}

/// v5-D3：refresh_token 轮换 + RFC 7009 吊销全链路。
/// ① 授权码兑换返回 RT（grant_types 含 refresh_token）；② refresh 得新 AT/RT（均异于旧）；
/// ③ 旧 RT 重放 → 400 invalid_grant（轮换作废）；④ 新 AT 可用；⑤ revoke AT → userinfo 401；
/// ⑥ revoke RT → refresh 400；⑦ revoke 无效 token 恒 200（防枚举）；
/// ⑧ 未声明 refresh_token 的客户端不签发 RT。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_d3_refresh_rotation_and_revoke() {
    let ctx = sso_ctx().await;
    let (cid, secret) = add_client_full(
        &ctx,
        "0",
        "it_sso_d3rt",
        &[REDIRECT_URI],
        Some(&["authorization_code", "refresh_token"]),
    )
    .await;

    // ① 授权码兑换 → AT1 + RT1
    let code = obtain_code(&ctx, &cid, "openid profile").await;
    let (tr1, _) = exchange_token(&ctx, &code, &cid, &secret, true).await;
    let at1 = tr1["access_token"].as_str().expect("AT1").to_string();
    let rt1 = tr1["refresh_token"]
        .as_str()
        .expect("应签发 RT1")
        .to_string();
    assert!(
        tr1["refresh_expires_in"].as_u64().unwrap_or(0) > 0,
        "refresh_expires_in 应为正数"
    );

    // ② refresh 轮换 → AT2 + RT2
    let refresh_form = |rt: &str| {
        format!(
            "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={}",
            urlenc(&cid),
            urlenc(&secret),
            urlenc(rt)
        )
    };
    let (r2, _, body2) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &refresh_form(&rt1),
        &[],
    )
    .await;
    assert_eq!(
        r2,
        StatusCode::OK,
        "refresh 应 200: {}",
        String::from_utf8_lossy(&body2)
    );
    let tr2 = json_of(&body2);
    let at2 = tr2["access_token"].as_str().expect("AT2").to_string();
    let rt2 = tr2["refresh_token"]
        .as_str()
        .expect("应轮换出 RT2")
        .to_string();
    assert_ne!(at1, at2, "AT 应轮换");
    assert_ne!(rt1, rt2, "RT 应轮换");

    // ③ 旧 RT1 重放 → 400 invalid_grant（轮换后作废）
    let (r3, _, _) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &refresh_form(&rt1),
        &[],
    )
    .await;
    assert_eq!(r3, StatusCode::BAD_REQUEST, "旧 RT 重放应被拒绝");

    // ④ 新 AT2 可用
    assert_eq!(
        userinfo_status(&ctx, &at2).await,
        StatusCode::OK,
        "刷新后的 AT 应可用"
    );

    // ⑤ revoke AT2 → userinfo 401
    let revoke_form = |t: &str| {
        format!(
            "token={}&client_id={}&client_secret={}",
            urlenc(t),
            urlenc(&cid),
            urlenc(&secret)
        )
    };
    let (rr1, _, _) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/revoke",
        "application/x-www-form-urlencoded",
        &revoke_form(&at2),
        &[],
    )
    .await;
    assert_eq!(rr1, StatusCode::OK, "revoke 应 200");
    assert_eq!(
        userinfo_status(&ctx, &at2).await,
        StatusCode::UNAUTHORIZED,
        "吊销后 AT 应立即失效"
    );

    // ⑥ revoke RT2 → refresh 400
    let (rr2, _, _) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/revoke",
        "application/x-www-form-urlencoded",
        &revoke_form(&rt2),
        &[],
    )
    .await;
    assert_eq!(rr2, StatusCode::OK, "revoke RT 应 200");
    let (r4, _, _) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &refresh_form(&rt2),
        &[],
    )
    .await;
    assert_eq!(r4, StatusCode::BAD_REQUEST, "吊销后的 RT 刷新应被拒绝");

    // ⑦ revoke 无效 token 恒 200（防枚举，RFC 7009 §2.2）
    let (rr3, _, _) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/revoke",
        "application/x-www-form-urlencoded",
        &revoke_form("not-a-real-token"),
        &[],
    )
    .await;
    assert_eq!(rr3, StatusCode::OK, "无效 token 吊销应恒 200");

    // ⑧ 未声明 refresh_token 的客户端不签发 RT
    let (cid2, secret2) = add_client(&ctx, "0", "it_sso_d3nort").await;
    let code2 = obtain_code(&ctx, &cid2, "openid profile").await;
    let (tr3, _) = exchange_token(&ctx, &code2, &cid2, &secret2, true).await;
    assert!(
        tr3.get("refresh_token").is_none(),
        "未声明 refresh_token grant 的客户端不应获得 RT，实际: {tr3}"
    );
}

/// v4 §7：token 请求必须携带与 authorize 完全一致的 redirect_uri（缺失 → 400 invalid_grant）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_v4_token_redirect_uri_mandatory() {
    let ctx = sso_ctx().await;
    let (cid, secret) = add_client(&ctx, "0", "it_sso_v4ru").await;
    let code = obtain_code(&ctx, &cid, "openid profile").await;

    // 缺失 redirect_uri → 拒绝（不再允许"未提供即通过"）
    let (status, _, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &format!(
            "grant_type=authorization_code&code={}&client_id={}&client_secret={}&code_verifier={}",
            urlenc(&code),
            urlenc(&cid),
            urlenc(&secret),
            urlenc(PKCE_VERIFIER)
        ),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "缺 redirect_uri 应 400");
    assert_eq!(
        json_of(&body)["error"].as_str(),
        Some("invalid_grant"),
        "缺 redirect_uri 应 invalid_grant，实际: {}",
        String::from_utf8_lossy(&body)
    );
}

/// v4-P0-B：end_session 真实登出——
/// ① 同源 Cookie 登出 → 302 回跳白名单地址；② 该用户 SSO AT 即刻 401；
/// ③ 浏览器会话 JWT 进黑名单（后续 /getInfo 401）；④ 跨站无 hint 的登出 CSRF 无副作用；
/// ⑤ hint 被篡改/跨客户端 → fail-closed 不回跳。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_v4_end_session_real_logout() {
    let ctx = sso_ctx().await;
    let (cid, secret) = add_client(&ctx, "0", "it_sso_v4logout").await;

    // 签发一枚有效 SSO AT
    let code = obtain_code(&ctx, &cid, "openid profile").await;
    let (tr, _) = exchange_token(&ctx, &code, &cid, &secret, true).await;
    let access_token = tr["access_token"].as_str().unwrap().to_string();
    assert_eq!(userinfo_status(&ctx, &access_token).await, StatusCode::OK);

    // ④ 跨站且无 hint 的登出（CSRF 模拟）→ 无副作用：不回跳、AT 仍有效
    let logout_url = format!(
        "/sso/logout?client_id={}&post_logout_redirect_uri={}",
        urlenc(&cid),
        REDIRECT_URI_ENC
    );
    let (status, headers, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &logout_url,
        &[("sec-fetch-site", "cross-site")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "跨站无 hint 登出不得回跳");
    assert_eq!(
        json_of(&body)["status"].as_str(),
        Some("logged_out"),
        "跨站无 hint 登出应返回 logged_out JSON"
    );
    assert!(
        headers.get("location").is_none(),
        "跨站无 hint 登出不应携带 Location"
    );
    assert_eq!(
        userinfo_status(&ctx, &access_token).await,
        StatusCode::OK,
        "跨站 CSRF 登出后 SSO AT 不应被吊销"
    );

    // ① 同源 Cookie 登出（无 sec-fetch-site 头 = 同源保守放行）→ 302 回跳白名单
    let cookie = format!("Admin-Token={}", ctx.token);
    let (status, headers, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &logout_url,
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "同源登出应 302 回跳白名单地址");
    assert_eq!(location_of(&headers), REDIRECT_URI);

    // ② SSO AT 即刻失效
    assert_eq!(
        userinfo_status(&ctx, &access_token).await,
        StatusCode::UNAUTHORIZED,
        "end_session 后 SSO AT 应被全量吊销（v4-P0-B）"
    );

    // ③ 浏览器会话 JWT 黑名单：携带旧 Cookie 的业务请求 401
    let (status, _, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        "/getInfo",
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "end_session 后浏览器会话应被拉黑（v4-P0-B）"
    );
}

/// v4-P0-B：id_token_hint 验签失败 / 跨客户端误用 → fail-closed（不回跳、不产生副作用）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_v4_end_session_hint_fail_closed() {
    let ctx = sso_ctx().await;
    let (cid_a, secret_a) = add_client(&ctx, "0", "it_sso_v4hintA").await;
    // 客户端 B 登记互异的回调地址，验证 A 的 hint 不得回跳到 B 的登记地址
    let (cid_b, _) = add_client_uris(&ctx, "0", "it_sso_v4hintB", &["https://b.test/cb"]).await;

    // 客户端 A 签发 id_token
    let code = obtain_code(&ctx, &cid_a, "openid profile").await;
    let (tr, _) = exchange_token(&ctx, &code, &cid_a, &secret_a, true).await;
    let id_token = tr["id_token"].as_str().unwrap().to_string();
    let access_token = tr["access_token"].as_str().unwrap().to_string();

    // 用 A 的 hint 但要求回跳到 A 的白名单 → hint 有效，应 302
    let logout_url = format!(
        "/sso/logout?id_token_hint={}&post_logout_redirect_uri={}",
        urlenc(&id_token),
        REDIRECT_URI_ENC
    );
    let (status, headers, _) = raw_get(&ctx.app, ctx.peer_ip, &logout_url, &[]).await;
    assert_eq!(
        status,
        StatusCode::FOUND,
        "有效 hint（aud=A）+ A 白名单回跳应 302"
    );
    assert_eq!(location_of(&headers), REDIRECT_URI);
    // hint 路径吊销了 A 名下该用户的全部 AT（跨端登出语义）
    assert_eq!(
        userinfo_status(&ctx, &access_token).await,
        StatusCode::UNAUTHORIZED,
        "有效 hint 登出应吊销用户全部 SSO AT"
    );

    // 跨客户端误用：A 的有效 hint + client_id=B + B 的登记回跳地址 →
    // 回跳目标以 hint 的 aud（A）为准，A 白名单不含 B 的地址 → fail-closed 不回跳
    let (status, headers, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &format!(
            "/sso/logout?id_token_hint={}&client_id={}&post_logout_redirect_uri={}",
            urlenc(&id_token),
            urlenc(&cid_b),
            "https%3A%2F%2Fb.test%2Fcb"
        ),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "跨客户端回跳地址不得放行");
    assert!(headers.get("location").is_none());

    // 篡改 hint（破坏签名）→ fail-closed：200 logged_out、不回跳
    let tampered = format!("{}tampered", &id_token[..id_token.len() - 4]);
    let (status, headers, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &format!(
            "/sso/logout?id_token_hint={}&post_logout_redirect_uri={}",
            urlenc(&tampered),
            REDIRECT_URI_ENC
        ),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "篡改 hint 不得回跳");
    assert!(headers.get("location").is_none());
}

/// v3-K3/v4：客户端禁用/删除后，已签发 SSO AT 即刻失效（不等到 TTL 过期）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_v4_disabled_client_invalidates_at() {
    let ctx = sso_ctx().await;
    let (cid, secret) = add_client(&ctx, "0", "it_sso_v4disable").await;
    let code = obtain_code(&ctx, &cid, "openid profile").await;
    let (tr, _) = exchange_token(&ctx, &code, &cid, &secret, true).await;
    let access_token = tr["access_token"].as_str().unwrap().to_string();
    assert_eq!(userinfo_status(&ctx, &access_token).await, StatusCode::OK);

    // 停用客户端 → AT 立即 401
    let pk = cid_pk(&ctx, &cid).await;
    let v = ctx
        .put_json(
            &format!("/system/oauth/client/{pk}/status?enabled=0"),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        userinfo_status(&ctx, &access_token).await,
        StatusCode::UNAUTHORIZED,
        "客户端停用后其名下 SSO AT 应立即失效（v3-K3）"
    );
}

/// v4-R8：自助授权管理——consent 批准后 grants 列表可见（client_name 快照），
/// 撤销后同意记录软删且该客户端名下 AT 级联吊销。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_v4_grants_list_and_revoke() {
    let ctx = sso_ctx().await;
    let (cid, secret) = add_client(&ctx, "1", "it_sso_v4grants").await;

    // authorize → NeedConsent → consent 批准（auth_time 由服务端 Operator.iat 权威注入）
    let cookie = format!("Admin-Token={}", ctx.token);
    let (status, headers, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &authorize_url_scopes(&cid, PKCE_CHALLENGE, "openid profile email"),
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND, "需同意客户端应 302 引导同意页");
    let loc = location_of(&headers);
    assert!(
        loc.starts_with("/sso-consent"),
        "应引导至同意页，实际: {loc}"
    );

    let v = ctx
        .post_json(
            "/sso/consent",
            serde_json::json!({
                "clientId": cid,
                "redirectUri": REDIRECT_URI,
                "scope": "openid profile email",
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
        .expect("consent 应返回 redirect");
    let code = query_param(redirect, "code").expect("consent 回跳应含 code");

    let (tr, _) = exchange_token(&ctx, &code, &cid, &secret, true).await;
    let access_token = tr["access_token"].as_str().unwrap().to_string();
    assert_eq!(userinfo_status(&ctx, &access_token).await, StatusCode::OK);

    // grants 列表可见（client_name 快照）
    let v = ctx.get_json("/system/user/profile/sso-grants").await;
    ctx.assert_ok(&v);
    let rows = v["data"].as_array().expect("grants 数组");
    let grant = rows
        .iter()
        .find(|g| g["clientId"].as_str() == Some(cid.as_str()))
        .unwrap_or_else(|| panic!("grants 应含刚授权的客户端，实际: {v}"));
    assert_eq!(grant["clientName"].as_str(), Some("it_sso_v4grants"));
    assert!(
        grant["consentedAt"].is_string(),
        "grants 应含同意时刻，实际: {grant}"
    );

    // 撤销授权 → 该客户端名下 AT 级联吊销 + 记录软删
    let v = ctx
        .delete_json(&format!("/system/user/profile/sso-grants/{}", urlenc(&cid)))
        .await;
    ctx.assert_ok(&v);
    assert_eq!(
        userinfo_status(&ctx, &access_token).await,
        StatusCode::UNAUTHORIZED,
        "撤销授权后该客户端名下 SSO AT 应级联吊销（v4-R8）"
    );
    let v = ctx.get_json("/system/user/profile/sso-grants").await;
    let rows = v["data"].as_array().expect("grants 数组");
    assert!(
        !rows
            .iter()
            .any(|g| g["clientId"].as_str() == Some(cid.as_str())),
        "撤销后 grants 不应再含该客户端，实际: {v}"
    );
}

/// v2-C2 / RFC 6749 §5.2：client 认证失败（凭据错误 / 缺失）→ 401 + `WWW-Authenticate: Basic`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_v4_invalid_client_401_www_authenticate() {
    let ctx = sso_ctx().await;
    let (cid, secret) = add_client(&ctx, "0", "it_sso_v4badcred").await;
    let code = obtain_code(&ctx, &cid, "openid").await;

    // 错误凭据 → 401 + WWW-Authenticate
    let form = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret=WRONG&code_verifier={}&redirect_uri={REDIRECT_URI_ENC}",
        urlenc(&code),
        urlenc(&cid),
        urlenc(PKCE_VERIFIER)
    );
    let (status, headers, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &form,
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "错误凭据应 401，body={}",
        String::from_utf8_lossy(&body)
    );
    let www = headers
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        www.starts_with("Basic"),
        "401 应带 WWW-Authenticate: Basic，实际: {www}"
    );
    // v5 核查（F3 补全）：协议面错误响应同样 no-store
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "错误响应应 no-store"
    );

    // 凭据完全缺失 → 同样 401 + WWW-Authenticate（invalid_client）
    let form = format!(
        "grant_type=authorization_code&code={}&code_verifier={}&redirect_uri={REDIRECT_URI_ENC}",
        urlenc(&code),
        urlenc(PKCE_VERIFIER)
    );
    let (status, headers, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &form,
        &[],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "缺失凭据应 401，body={}",
        String::from_utf8_lossy(&body)
    );
    assert!(headers.get("www-authenticate").is_some());

    // 错误凭据不得消费授权码：再用正确凭据换同一 code 应 invalid_grant（code 尚在，
    // 但此处验证的是认证失败未产生副作用 —— 正确凭据仍可换）
    let (tr, _) = exchange_token(&ctx, &code, &cid, &secret, true).await;
    assert!(
        tr["access_token"].as_str().is_some(),
        "认证失败后正确凭据仍应可换码"
    );
}

/// v3 P1'-5：`client_secret_basic`（Authorization: Basic 头，RFC 6749 §2.3.1）换 token 成功；
/// 同时验证 Basic 凭据按 form-urlencoded percent-decode 还原
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_v4_client_secret_basic_flow() {
    let ctx = sso_ctx().await;
    let (cid, secret) = add_client(&ctx, "0", "it_sso_v4basic").await;
    let code = obtain_code(&ctx, &cid, "openid").await;

    // RFC 6749 §2.3.1：凭据先按 application/x-www-form-urlencoded 编码再拼 Basic
    let cid_enc: String = url::form_urlencoded::byte_serialize(cid.as_bytes()).collect();
    let sec_enc: String = url::form_urlencoded::byte_serialize(secret.as_bytes()).collect();
    let basic_val =
        base64::engine::general_purpose::STANDARD.encode(format!("{cid_enc}:{sec_enc}").as_bytes());

    // 表单只带协议参数，凭据走 Basic 头
    let form = format!(
        "grant_type=authorization_code&code={}&code_verifier={}&redirect_uri={REDIRECT_URI_ENC}",
        urlenc(&code),
        urlenc(PKCE_VERIFIER)
    );
    let auth_header = format!("Basic {basic_val}");
    let (status, headers, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/sso/token",
        "application/x-www-form-urlencoded",
        &form,
        &[("authorization", auth_header.as_str())],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "client_secret_basic 应成功换 token，body={}",
        String::from_utf8_lossy(&body)
    );
    let tr = json_of(&body);
    assert!(tr["access_token"].as_str().is_some());
    assert!(tr["id_token"].as_str().is_some());
    // RFC 6749 §5.1
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        userinfo_status(&ctx, tr["access_token"].as_str().unwrap()).await,
        StatusCode::OK,
        "Basic 流程签发的 AT 应可通过 userinfo 校验"
    );
}

/// v4 §13-F1：历史 JWT 型 SSO 访问令牌一次性转写吊销（幂等 + blacklist 生效）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_v4_legacy_at_rewrite() {
    let ctx = sso_ctx().await;
    let mut redis = ctx.redis();

    // 清理标记，保证本测试触发一次完整转写
    let _: Result<i64, _> = redis::cmd("DEL")
        .arg("sso:v4_legacy_at_migrated")
        .query_async(&mut redis)
        .await;

    // 伪造历史形态绑定：sso:at:{hash}（A 形态上线前由旧 token 端点写入）
    let legacy_token = "legacy-jwt-style-sso-access-token";
    let hash = crate::utils::crypto::token_hash(legacy_token);
    let at_key = format!("sso:at:{hash}");
    let _: () = redis::cmd("SETEX")
        .arg(&at_key)
        .arg(3600i64)
        .arg(r#"{"client_id":"app_legacy","user_id":1}"#)
        .query_async(&mut redis)
        .await
        .expect("写入历史绑定失败");

    // 伪造 A 形态活跃绑定（含 access_token_hash）→ 精准转写必须跳过（v5 核查防误杀）
    let opaque_hash = crate::utils::crypto::token_hash("active-opaque-access-token");
    let opaque_key = format!("sso:at:{opaque_hash}");
    let _: () = redis::cmd("SETEX")
        .arg(&opaque_key)
        .arg(3600i64)
        .arg(r#"{"client_id":"app_now","user_id":1,"access_token_hash":"self","scope":["openid"]}"#)
        .query_async(&mut redis)
        .await
        .expect("写入活跃绑定失败");

    crate::initialize::revoke_legacy_sso_at_tokens(&mut redis).await;

    // 历史绑定被删 + blacklist 命中（业务路由过渡阻断/黑名单双路径立即拒绝）
    let bound: Option<String> = redis::cmd("GET")
        .arg(&at_key)
        .query_async(&mut redis)
        .await
        .expect("GET 失败");
    assert!(bound.is_none(), "历史绑定应被转写删除");
    let blacklisted: Option<String> = redis::cmd("GET")
        .arg(format!("blacklist:{hash}"))
        .query_async(&mut redis)
        .await
        .expect("GET 失败");
    assert!(blacklisted.is_some(), "历史令牌应转写为 blacklist");
    let ttl: i64 = redis::cmd("TTL")
        .arg(format!("blacklist:{hash}"))
        .query_async(&mut redis)
        .await
        .expect("TTL 失败");
    assert!(
        ttl >= 86_400,
        "blacklist TTL 应 ≥ 24h（覆盖 JWT 最长剩余寿命），实际 {ttl}"
    );

    // 活跃不透明 AT 绑定不受影响（精准识别，防误杀）
    let opaque_alive: Option<String> = redis::cmd("GET")
        .arg(&opaque_key)
        .query_async(&mut redis)
        .await
        .expect("GET 失败");
    assert!(opaque_alive.is_some(), "A 形态活跃绑定不得被转写误杀");
    let opaque_bl: Option<String> = redis::cmd("GET")
        .arg(format!("blacklist:{opaque_hash}"))
        .query_async(&mut redis)
        .await
        .expect("GET 失败");
    assert!(opaque_bl.is_none(), "活跃绑定不得写入 blacklist");

    // 清理活跃绑定（隔离 DB 内不影响其它断言）
    let _: i64 = redis::cmd("DEL")
        .arg(&opaque_key)
        .query_async(&mut redis)
        .await
        .unwrap_or(0);

    // 幂等：重复调用不报错（标记已置），且不复活任何键
    crate::initialize::revoke_legacy_sso_at_tokens(&mut redis).await;
    let blacklisted2: Option<String> = redis::cmd("GET")
        .arg(format!("blacklist:{hash}"))
        .query_async(&mut redis)
        .await
        .expect("GET 失败");
    assert!(blacklisted2.is_some());

    // 清理本测试遗留的 blacklist 与标记（隔离 DB 内不影响其它断言）
    let _: i64 = redis::cmd("DEL")
        .arg(format!("blacklist:{hash}"))
        .arg("sso:v4_legacy_at_migrated")
        .query_async(&mut redis)
        .await
        .unwrap_or(0);
}

/// v5 核查（F2 兑现）：管理员强退在线 SSO 会话 → Lua 原子化吊销
/// blacklist + online + `sso:at:` 三键（不透明 AT 的唯一吊销路径是 DEL 绑定）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sso_v5_force_logout_revokes_sso_at() {
    let ctx = sso_ctx().await;
    let mut redis = ctx.redis();

    // 伪造 SSO 在线会话（user_id=2 非 superadmin，online hash = 不透明 AT hash）
    let at_hash = crate::utils::crypto::token_hash("sso-at-under-force-logout");
    let online_json = serde_json::json!({
        "user_id": 2,
        "username": "test_force",
        "ip": "sso",
        "login_time": "2026-09-23 20:00:00",
        "browser": "SSO",
        "os": "-",
        "jti": "sso-at-app_x",
        "dept_name": "",
        "exp": chrono::Utc::now().timestamp() + 3600,
        "source": "sso"
    })
    .to_string();
    let online_key = format!("online:{at_hash}");
    let at_key = format!("sso:at:{at_hash}");
    let _: () = redis::cmd("SETEX")
        .arg(&online_key)
        .arg(3600i64)
        .arg(&online_json)
        .query_async(&mut redis)
        .await
        .expect("写 online 失败");
    let _: () = redis::cmd("SETEX")
        .arg(&at_key)
        .arg(3600i64)
        .arg(r#"{"client_id":"app_x","user_id":2,"access_token_hash":"self"}"#)
        .query_async(&mut redis)
        .await
        .expect("写绑定失败");

    // 管理员强退
    let v = ctx
        .delete_json(&format!("/monitor/online/{}", urlenc(&at_hash)))
        .await;
    ctx.assert_ok(&v);

    // 三键全清：online 消失、绑定删除（userinfo 即 401）、blacklist 生效
    let online_left: Option<String> = redis::cmd("GET")
        .arg(&online_key)
        .query_async(&mut redis)
        .await
        .expect("GET 失败");
    assert!(online_left.is_none(), "强退后 online 应删除");
    let at_left: Option<String> = redis::cmd("GET")
        .arg(&at_key)
        .query_async(&mut redis)
        .await
        .expect("GET 失败");
    assert!(at_left.is_none(), "强退 SSO 会话应联动删除 sso:at: 绑定");
    let bl: Option<String> = redis::cmd("GET")
        .arg(format!("blacklist:{at_hash}"))
        .query_async(&mut redis)
        .await
        .expect("GET 失败");
    assert!(bl.is_some(), "强退应写 blacklist");

    // 清理遗留
    let _: i64 = redis::cmd("DEL")
        .arg(format!("blacklist:{at_hash}"))
        .query_async(&mut redis)
        .await
        .unwrap_or(0);
}
