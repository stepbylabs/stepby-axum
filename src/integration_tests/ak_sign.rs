// stepby-axum/src/integration_tests/ak_sign.rs
//! AK/SK 签名开放 API 链路集成测试（HTTP 端到端）：
//! - 创建带 AK 的 PAT：access_key / secret_key 明文仅在创建响应返回一次；
//!   列表响应绝不出现 SK（对齐 PAT token 明文仅一次范式）
//! - AK 签名请求（HMAC-SHA256）：正确签名 → 200 并返回真实画像（查库）
//! - 错签 → 401 invalid_signature
//! - 同 nonce 重放 → 401 nonce_reused（SharedStore set_nx_ex 一次性抢占）
//! - 时间戳超窗（±300s 外）→ 401 timestamp_out_of_window
//! - 轮换 SK：旧 SK 即时失效、新 SK 明文仅此一次返回
//! - 吊销 AK/SK：清空后签名请求 → 401 ak_not_found
//! - 未开通 AK 的 PAT 轮换 → 404 语义错误

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tower::ServiceExt;

use super::TestContext;
use crate::middleware::ak_sign::ak_protected_routes;

/// 与 ak_sign 中间件同口径的 SHA-256 hex（请求体摘要）
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    crate::utils::crypto::hex_encode_digest(&hasher.finalize())
}

/// 当前 Unix 秒
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// 构造 AK 签名请求（可注入异常：错签 / 过期时间戳）
///
/// string_to_sign = METHOD\nPATH\nTIMESTAMP\nNONCE\nhex(SHA256(body))，
/// 签名 = hex(HMAC-SHA256(SK, string_to_sign))。
#[allow(clippy::too_many_arguments)]
fn signed_request(
    ak: &str,
    sk: &str,
    method: Method,
    uri: &str,
    body: &str,
    nonce: &str,
    ts: i64,
    sig_override: Option<String>,
) -> Request<Body> {
    let path = uri.split('?').next().unwrap_or(uri);
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        path,
        ts,
        nonce,
        sha256_hex(body.as_bytes())
    );
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(sk.as_bytes()).expect("HMAC 构造失败");
    mac.update(string_to_sign.as_bytes());
    let sig = sig_override
        .unwrap_or_else(|| crate::utils::crypto::hex_encode_digest(&mac.finalize().into_bytes()));
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-ca-key", ak)
        .header("x-ca-timestamp", ts.to_string())
        .header("x-ca-nonce", nonce)
        .header("x-ca-signature", sig)
        .body(Body::from(body.to_string()))
        .expect("构造 AK 签名请求失败")
}

/// 以 JWT bearer 构造管理端请求（创建/轮换/吊销走登录态链路）
fn bearer_request(
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

/// 执行请求并返回（HTTP 状态码, JSON body）
async fn send(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.clone().oneshot(req).await.expect("请求执行失败");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取响应体失败");
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, v)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ak_sign_chain() {
    let ctx = TestContext::new().await;

    // ---- 1. 创建带 AK 的 PAT：SK 明文仅此一次返回 ----
    let v = ctx
        .post_json(
            "/system/user/profile/tokens",
            serde_json::json!({
                "name": "it_ak_pat",
                "scopes": ["system:config:list"],
                "expireDays": 30,
                "withAk": true
            }),
        )
        .await;
    let ak = v["data"]["accessKey"]
        .as_str()
        .expect("创建响应应含 accessKey")
        .to_string();
    let sk = v["data"]["secretKey"]
        .as_str()
        .expect("创建响应应含 secretKey 明文")
        .to_string();
    let pat_id = v["data"]["pat"]["patId"]
        .as_str()
        .expect("patId")
        .to_string();
    assert!(
        ak.starts_with("ak") && ak.len() == 26,
        "AK 应为 ak + 24 hex，实际: {ak}"
    );
    assert_eq!(sk.len(), 48, "SK 应为 48 字符 base64url，实际: {sk}");

    // AK 路由独立挂载（AK 签名即鉴权，不叠加 auth 中间件——与主线程挂载语义一致）
    // with_state 注入共享状态，把 Router<Arc<AppState>> 收敛为可 oneshot 的 Router<()>
    let app: Router = ak_protected_routes(ctx.state.clone()).with_state(ctx.state.clone());

    // ---- 2. 正确签名 → 200 + 真实画像（查库）----
    let nonce1 = uuid::Uuid::new_v4().to_string();
    let (status, body) = send(
        &app,
        signed_request(
            &ak,
            &sk,
            Method::GET,
            "/open/v1/profile",
            "",
            &nonce1,
            unix_now(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "正确签名应 200，实际: {body}");
    assert_eq!(body["code"], 200, "业务码应为 200: {body}");
    assert_eq!(body["data"]["patName"], "it_ak_pat", "画像应含 PAT 名称");
    assert_eq!(body["data"]["username"], "admin", "画像应含属主用户名");
    assert!(body["data"]["tenantId"].is_i64(), "画像应含租户 ID");
    assert!(
        body["data"].get("expiresAt").is_some(),
        "画像应含 PAT 过期时间: {body}"
    );

    // ---- 3. 错签 → 401 invalid_signature（且不消耗该 nonce）----
    let nonce2 = uuid::Uuid::new_v4().to_string();
    let (status, body) = send(
        &app,
        signed_request(
            &ak,
            &sk,
            Method::GET,
            "/open/v1/profile",
            "",
            &nonce2,
            unix_now(),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "错签应 401");
    assert_eq!(body["code"], 401, "失败契约 body.code 应 401: {body}");
    assert!(
        body["msg"].as_str().unwrap_or_default().contains("签名"),
        "错签 msg 应为 invalid_signature 文案: {body}"
    );

    // ---- 4. 同 nonce 重放（正确签名）→ 401 nonce_reused ----
    let (status, body) = send(
        &app,
        signed_request(
            &ak,
            &sk,
            Method::GET,
            "/open/v1/profile",
            "",
            &nonce1,
            unix_now(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "nonce 重放应 401");
    assert!(
        body["msg"].as_str().unwrap_or_default().contains("重放"),
        "重放 msg 应为 nonce_reused 文案: {body}"
    );

    // ---- 5. 时间戳超窗（-400s）→ 401 timestamp_out_of_window ----
    let (status, body) = send(
        &app,
        signed_request(
            &ak,
            &sk,
            Method::GET,
            "/open/v1/profile",
            "",
            &uuid::Uuid::new_v4().to_string(),
            unix_now() - 400,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "超窗应 401");
    assert!(
        body["msg"].as_str().unwrap_or_default().contains("时间戳"),
        "超窗 msg 应为 timestamp_out_of_window 文案: {body}"
    );

    // ---- 6. SK 明文仅返回一次：列表响应无 accessKey/secretKey ----
    let v = ctx
        .get_json("/system/user/profile/tokens?pageSize=50")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        rows.iter().all(|r| r.get("secretKey").is_none()),
        "列表出参绝不得含 secretKey: {rows:?}"
    );
    assert!(
        rows.iter().all(|r| r.get("accessKey").is_none()),
        "列表出参不得含 accessKey"
    );
    assert!(
        rows.iter()
            .any(|r| r["patId"].as_str() == Some(pat_id.as_str())),
        "列表应包含刚创建的 PAT"
    );

    // ---- 7. 轮换 SK：新明文仅此一次；旧 SK 即时失效、新 SK 可用 ----
    let v = ctx
        .post_json(
            &format!("/system/pat/{}/rotate-ak", pat_id),
            serde_json::json!({}),
        )
        .await;
    let sk2 = v["data"]["secretKey"]
        .as_str()
        .expect("轮换响应应含新 SK 明文")
        .to_string();
    assert_eq!(
        v["data"]["accessKey"].as_str(),
        Some(ak.as_str()),
        "轮换不变更 AK"
    );
    assert_ne!(sk2, sk, "轮换后 SK 必须变化");

    // 旧 SK（新 nonce、对签）→ 401 invalid_signature
    let (status, body) = send(
        &app,
        signed_request(
            &ak,
            &sk,
            Method::GET,
            "/open/v1/profile",
            "",
            &uuid::Uuid::new_v4().to_string(),
            unix_now(),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "旧 SK 轮换后应失效: {body}"
    );
    assert!(
        body["msg"].as_str().unwrap_or_default().contains("签名"),
        "旧 SK 失败应为签名不匹配: {body}"
    );

    // 新 SK → 200
    let (status, body) = send(
        &app,
        signed_request(
            &ak,
            &sk2,
            Method::GET,
            "/open/v1/profile",
            "",
            &uuid::Uuid::new_v4().to_string(),
            unix_now(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "新 SK 应可用: {body}");

    // ---- 8. 吊销 AK/SK：清空后 → 401 ak_not_found ----
    ctx.post_json(
        &format!("/system/pat/{}/revoke-ak", pat_id),
        serde_json::json!({}),
    )
    .await;
    let (status, body) = send(
        &app,
        signed_request(
            &ak,
            &sk2,
            Method::GET,
            "/open/v1/profile",
            "",
            &uuid::Uuid::new_v4().to_string(),
            unix_now(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "吊销后应 401: {body}");
    assert!(
        body["msg"].as_str().unwrap_or_default().contains("不存在"),
        "吊销后应为 ak_not_found 文案: {body}"
    );

    // ---- 9. 未开通 AK 的 PAT 轮换 → 404 语义错误 ----
    let v = ctx
        .post_json(
            "/system/user/profile/tokens",
            serde_json::json!({
                "name": "it_ak_noak",
                "scopes": ["system:config:list"],
                "expireDays": 30
            }),
        )
        .await;
    let noak_id = v["data"]["pat"]["patId"]
        .as_str()
        .expect("patId")
        .to_string();
    let (status, body) = ctx
        .send_raw(bearer_request(
            &ctx,
            Method::POST,
            &format!("/system/pat/{}/rotate-ak", noak_id),
            Some(serde_json::json!({})),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "未开通 AK 的 PAT 轮换应 404: {body}"
    );
    assert!(
        body["msg"].as_str().unwrap_or_default().contains("AK"),
        "404 msg 应指向未开通 AK: {body}"
    );

    // ---- 10. 无签名头 → 401 ----
    let (status, _) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri("/open/v1/profile")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "无签名头应 401");
}
