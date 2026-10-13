// stepby-axum/src/integration_tests/webauthn.rs
//! WebAuthn / Passkey 集成测试（能力位 `auth.webauthn`，默认 **off**）。
//!
//! 覆盖（均为可证伪的真实断言）：
//! ① 能力位 **off**（默认）⇒ 6 条端点**全部 404**（不暴露"存在但被关"）；
//! ② 能力位 **on** ⇒ `register/start` 返回含 `challenge` 的创建选项（**契约断言**）；
//! ③ `register/finish` 传垃圾 ⇒ 400；
//! ④ `login/start` 未知用户 / 无凭据用户 ⇒ **与密码登录失败同形**（HTTP + code + msg 全等，防枚举）；
//! ⑤ 凭据列表为空 / 只能删自己的（删除他人凭据 ⇒ 404 且不生效）；
//! ⑥ **注册快乐路径**：软认证器（ES256 真签名）经 `register/start → finish` 真实落库；
//! ⑦ **登录快乐路径**：软认证器签名经 `login/start → finish` 换取**真实可用** JWT（再打通 /getInfo）；
//! ⑧ 登录负路径：断言**重放** / `signCount` **回退** / **篡改**认证器数据 ⇒ 401；
//! ⑨ 错误 `origin` / 错误 `rp_id` ⇒ 401。
//!
//! 软件认证器（见 `soft_authenticator` 模块）为**纯 Rust** 实现：p256（ES256 真签名）+
//! coset/ciborium（`COSE_Key` 与 `attestationObject` 的 CBOR 编码）。**不 mock** 任何密码学校验，
//! 全部走服务端真实验签；`origin` 取 `config/config.toml` `[server].cors_origins` 首个来源，
//! `rp_id` 由其 host 推导（与既有契约断言一致）。

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

use super::TestContext;
use crate::entity::sys_user_credential;

const FEATURE: &str = "auth.webauthn";

/// 自含 webauthn 配置的测试上下文：能力位 on + 显式 rp_id/origin。
/// 部署态 config.toml 常带 rp_id/origin 而入库模板/CI env-only 缺失 ⇒
/// 服务端 503「WebAuthn 未配置」（GitHub run 38278563900 实证）——
/// 用例前置必须自含，不得依赖部署态（批六十一）。
async fn webauthn_ctx() -> TestContext {
    TestContext::new_with(&[(FEATURE, "on")], |s| {
        s.webauthn.rp_id = "localhost".to_string();
        s.webauthn.origin = TEST_ORIGIN.to_string();
    })
    .await
}

/// 构造带鉴权头 + ConnectInfo 的请求（复用 TestContext 的隔离约定）
fn authed_request(
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

/// 构造免鉴权（公开）POST 请求
fn public_request(ctx: &TestContext, uri: &str, body: serde_json::Value) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("构造公开请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// 结构合法的注册完成请求（值无意义，仅用于让 Json 反序列化通过）
fn register_finish_body() -> serde_json::Value {
    serde_json::json!({
        "id": "x",
        "rawId": "x",
        "type": "public-key",
        "response": { "clientDataJSON": "x", "attestationObject": "x" }
    })
}

/// 结构合法的登录完成请求
fn login_finish_body(username: &str) -> serde_json::Value {
    serde_json::json!({
        "username": username,
        "id": "x",
        "rawId": "x",
        "type": "public-key",
        "response": {
            "clientDataJSON": "x",
            "authenticatorData": "x",
            "signature": "x"
        }
    })
}

/// 插入一条指定归属用户的凭据（测试夹具，绕过 WebAuthn 断言仅用于列表/越权用例）
async fn insert_credential(ctx: &TestContext, user_id: i64, credential_id: &str) -> i64 {
    let model = sys_user_credential::ActiveModel {
        cred_id: sea_orm::NotSet,
        user_id: Set(user_id),
        tenant_id: Set(0),
        credential_id: Set(credential_id.to_string()),
        public_key: Set("it-public-key".to_string()),
        name: Set(format!("it-{credential_id}")),
        sign_count: Set(0),
        last_used_at: Set(None),
        create_time: Set(Some(crate::common::datetime::now_naive())),
        del_flag: Set(Some("0".to_string())),
    }
    .insert(&ctx.state.db)
    .await
    .expect("插入凭据失败");
    model.cred_id
}

/// ① 能力位 off（默认）⇒ 6 条端点全部 404
#[tokio::test]
async fn test_webauthn_feature_off_returns_404_on_all_endpoints() {
    // 默认能力集（平台层未注入任何覆盖）= 全 off = 现状
    let ctx = TestContext::new().await;

    let self_routes = [
        (
            Method::POST,
            "/system/user/webauthn/register/start",
            Some(serde_json::json!({})),
        ),
        (
            Method::POST,
            "/system/user/webauthn/register/finish",
            Some(register_finish_body()),
        ),
        (Method::GET, "/system/user/webauthn/credentials", None),
        (Method::DELETE, "/system/user/webauthn/credentials/1", None),
    ];
    for (method, uri, body) in self_routes {
        let (status, v) = ctx.send_raw(authed_request(&ctx, method, uri, body)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{uri} 关闭态必须 404，实际 {status}: {v}"
        );
        assert_eq!(v["code"], 404, "{uri} 关闭态业务码必须 404: {v}");
    }

    let public_routes = [
        ("/login/webauthn/start", serde_json::json!({})),
        ("/login/webauthn/finish", login_finish_body("admin")),
    ];
    for (uri, body) in public_routes {
        let (status, v) = ctx.send_raw(public_request(&ctx, uri, body)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{uri} 关闭态必须 404，实际 {status}: {v}"
        );
    }
}

/// ② 能力位 on ⇒ register/start 返回含 challenge 的创建选项（契约断言）
#[tokio::test]
async fn test_register_start_returns_options_with_challenge() {
    let ctx = webauthn_ctx().await;
    let v = ctx
        .post_json(
            "/system/user/webauthn/register/start",
            serde_json::json!({}),
        )
        .await;
    assert_eq!(v["code"], 200);

    let data = &v["data"];
    let challenge = data["challenge"]
        .as_str()
        .expect("options 应含 challenge（WebAuthn 契约）");
    assert!(!challenge.is_empty(), "challenge 不得为空");
    // 32 字节随机数的 base64url 无填充编码
    assert_eq!(
        challenge.len(),
        43,
        "challenge 应为 32 字节 base64url: {challenge}"
    );
    // rp.id 从 [server].cors_origins 首个来源（http://localhost:5173）推导为 localhost
    assert_eq!(
        data["rp"]["id"], "localhost",
        "rp.id 应从 [server].cors_origins 推导: {data}"
    );
    // 用户标识与依赖方名
    assert_eq!(data["user"]["name"], "admin");
    assert!(data["rp"]["name"].as_str().is_some_and(|s| !s.is_empty()));
    // 算法族必须为 ES256（-7），类型 public-key
    assert_eq!(data["pubKeyCredParams"][0]["alg"], -7);
    assert_eq!(data["pubKeyCredParams"][0]["type"], "public-key");
}

/// ③ register/finish 传垃圾 ⇒ 400
#[tokio::test]
async fn test_register_finish_garbage_returns_400() {
    let ctx = webauthn_ctx().await;
    let (status, v) = ctx
        .send_raw(authed_request(
            &ctx,
            Method::POST,
            "/system/user/webauthn/register/finish",
            Some(register_finish_body()),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "垃圾注册响应必须 400，实际 {status}: {v}"
    );
    assert_eq!(v["code"], 400);
}

/// ④ login/start 未知用户 / 无凭据用户 ⇒ 与密码登录失败**同形**（防用户名枚举）
#[tokio::test]
async fn test_login_start_is_indistinguishable_from_login_failure() {
    let ctx = webauthn_ctx().await;

    // 基线：密码登录失败（不存在的用户）——与 C-1 反枚举口径同源
    let mut pw = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "username": "no_such_user_xyz",
                "password": "whatever-123456",
                "code": "",
                "uuid": ""
            })
            .to_string(),
        ))
        .expect("构造密码登录请求失败");
    pw.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (pw_status, pw_v) = ctx.send_raw(pw).await;
    assert_ne!(pw_v["code"], 200, "基线必须是登录失败: {pw_v}");

    // 未知用户：passkey 登录开始必须完全同形
    let (s1, v1) = ctx
        .send_raw(public_request(
            &ctx,
            "/login/webauthn/start",
            serde_json::json!({ "username": "no_such_user_xyz" }),
        ))
        .await;
    assert_eq!(s1, pw_status, "未知用户：HTTP 状态必须与密码登录失败一致");
    assert_eq!(
        v1["code"], pw_v["code"],
        "未知用户：业务码必须一致（防枚举）"
    );
    assert_eq!(v1["msg"], pw_v["msg"], "未知用户：文案必须一致（防枚举）");

    // 真实存在但无 passkey 的用户：同样同形（否则可据此枚举"哪些用户绑定了 passkey"）
    let (s2, v2) = ctx
        .send_raw(public_request(
            &ctx,
            "/login/webauthn/start",
            serde_json::json!({ "username": "admin" }),
        ))
        .await;
    assert_eq!(s2, pw_status, "无凭据用户：HTTP 状态必须与密码登录失败一致");
    assert_eq!(v2["code"], pw_v["code"], "无凭据用户：业务码必须一致");
    assert_eq!(v2["msg"], pw_v["msg"], "无凭据用户：文案必须一致");
}

/// ⑤ 凭据列表（空 → 1）与归属校验（只能删自己的；删他人 ⇒ 404 且不生效）
#[tokio::test]
async fn test_credentials_list_and_ownership_on_delete() {
    let ctx = webauthn_ctx().await;

    // 初始列表为空
    let v = ctx.get_json("/system/user/webauthn/credentials").await;
    assert_eq!(
        v["data"].as_array().map(Vec::len),
        Some(0),
        "初始凭据列表应为空: {v}"
    );

    // 他人凭据：删除必须 404 且凭据仍在（归属校验，越权保护）
    let other_cred_id = insert_credential(&ctx, 999_999, "it-other-cred").await;
    let (status, v) = ctx
        .send_raw(authed_request(
            &ctx,
            Method::DELETE,
            &format!("/system/user/webauthn/credentials/{other_cred_id}"),
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "删除他人凭据必须被拒（404）: {v}"
    );
    assert!(
        sys_user_credential::Entity::find_by_id(other_cred_id)
            .one(&ctx.state.db)
            .await
            .expect("查询凭据失败")
            .is_some(),
        "越权删除不得生效"
    );

    // 本人凭据：可见且可删
    let own_cred_id = insert_credential(&ctx, 1, "it-own-cred").await;
    let v = ctx.get_json("/system/user/webauthn/credentials").await;
    let rows = v["data"].as_array().expect("列表应为数组");
    assert_eq!(rows.len(), 1, "本人凭据应可见: {v}");
    assert_eq!(rows[0]["credId"], own_cred_id);

    let (status, v) = ctx
        .send_raw(authed_request(
            &ctx,
            Method::DELETE,
            &format!("/system/user/webauthn/credentials/{own_cred_id}"),
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "删除本人凭据应成功: {v}");
    assert_eq!(v["code"], 200);

    // 删除后列表回到空；重复删除 ⇒ 404（幂等表现为"不存在"）
    let v = ctx.get_json("/system/user/webauthn/credentials").await;
    assert_eq!(v["data"].as_array().map(Vec::len), Some(0));
    let (status, _) = ctx
        .send_raw(authed_request(
            &ctx,
            Method::DELETE,
            &format!("/system/user/webauthn/credentials/{own_cred_id}"),
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "重复删除应为 404");
}

// ==================== ⑥~⑨ 软认证器驱动的完整快乐路径 / 负路径 ====================

/// 与服务端信任锚一致（`[server].cors_origins` 首个来源）；
/// 服务端据此校验 `clientDataJSON.origin`，`rp_id` 由其 host 推导为 `localhost`。
const TEST_ORIGIN: &str = "http://localhost:5173";

use self::soft_authenticator::{Assertion, SoftAuthenticator};

/// 走完整注册流程（真实 proof of possession：真签名 + 真 COSE 公钥落库）
async fn soft_register(ctx: &TestContext, auth: &SoftAuthenticator, name: &str) {
    let v = ctx
        .post_json(
            "/system/user/webauthn/register/start",
            serde_json::json!({}),
        )
        .await;
    let data = &v["data"];
    let challenge = data["challenge"]
        .as_str()
        .expect("应含 challenge")
        .to_string();
    let rp_id = data["rp"]["id"].as_str().expect("应含 rp.id").to_string();

    let (client_data_json, attestation_object) = auth.attest(&rp_id, &challenge, TEST_ORIGIN);
    let body = serde_json::json!({
        "id": auth.credential_id_b64(),
        "rawId": auth.credential_id_b64(),
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data_json,
            "attestationObject": attestation_object,
        },
        "name": name,
    });
    let v = ctx
        .post_json("/system/user/webauthn/register/finish", body)
        .await;
    assert_eq!(v["code"], 200, "软认证器注册应成功: {v}");
}

/// 开始登录并按指定 `signCount` 产出断言；返回 `(断言, options.data)`。
async fn start_login_assertion(
    ctx: &TestContext,
    auth: &SoftAuthenticator,
    sign_count: u32,
) -> (Assertion, serde_json::Value) {
    let (status, v) = ctx
        .send_raw(public_request(
            ctx,
            "/login/webauthn/start",
            serde_json::json!({ "username": "admin" }),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "有凭据用户开始登录应成功: {v}");
    assert_eq!(v["code"], 200);
    let data = v["data"].clone();
    let challenge = data["challenge"]
        .as_str()
        .expect("应含 challenge")
        .to_string();
    let rp_id = data["rpId"].as_str().expect("应含 rpId").to_string();
    (
        auth.assert(&rp_id, &challenge, TEST_ORIGIN, sign_count),
        data,
    )
}

/// ⑥ 注册快乐路径：软认证器真签名 ⇒ 200 且凭据真实落库
#[tokio::test]
async fn test_register_happy_path_with_soft_authenticator() {
    let ctx = webauthn_ctx().await;
    let v = ctx.get_json("/system/user/webauthn/credentials").await;
    assert_eq!(
        v["data"].as_array().map(Vec::len),
        Some(0),
        "初始应为空: {v}"
    );

    let auth = SoftAuthenticator::new();
    soft_register(&ctx, &auth, "soft-key").await;

    let v = ctx.get_json("/system/user/webauthn/credentials").await;
    let rows = v["data"].as_array().expect("列表应为数组");
    assert_eq!(rows.len(), 1, "注册成功后凭据列表应出现 1 条: {v}");
    assert_eq!(rows[0]["name"], "soft-key", "凭据名应为提交的 name: {v}");
    assert_eq!(rows[0]["signCount"], 0, "注册后 signCount 应为 0: {v}");

    // 数据库确认真实落库（含非空 COSE 公钥）且归属当前登录用户
    let stored = sys_user_credential::Entity::find()
        .filter(sys_user_credential::Column::CredentialId.eq(auth.credential_id_b64()))
        .one(&ctx.state.db)
        .await
        .expect("查询凭据失败")
        .expect("凭据应已落库");
    assert_eq!(stored.user_id, 1, "凭据应归属当前登录用户 admin");
    assert!(!stored.public_key.is_empty(), "落库的 COSE 公钥不得为空");
}

/// ⑦ 登录快乐路径：软认证器签名 ⇒ 真实可用 JWT（再打通受保护接口 /getInfo）
#[tokio::test]
async fn test_login_happy_path_with_soft_authenticator() {
    let ctx = webauthn_ctx().await;
    let auth = SoftAuthenticator::new();
    soft_register(&ctx, &auth, "soft-key").await;

    let (assertion, options) = start_login_assertion(&ctx, &auth, 1).await;
    // allowCredentials 必须限定为该用户已绑定的凭据
    let allow = options["allowCredentials"]
        .as_array()
        .expect("应含 allowCredentials");
    assert!(
        allow.iter().any(|c| c["id"] == auth.credential_id_b64()),
        "allowCredentials 应含刚注册的凭据: {options}"
    );

    let (status, v) = ctx
        .send_raw(public_request(
            &ctx,
            "/login/webauthn/finish",
            assertion.login_body(&auth.credential_id_b64()),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "软认证器签名登录应成功: {v}");
    assert_eq!(v["code"], 200);
    let token = v["token"].as_str().expect("应返回 token").to_string();
    assert!(!token.is_empty(), "token 不得为空");

    // 令牌真实可用：调受保护接口 /getInfo ⇒ 200 且身份正确
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("/getInfo")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("构造 getInfo 请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let (status, v) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "passkey 登录令牌应可访问 /getInfo: {v}"
    );
    assert_eq!(v["code"], 200);
    assert_eq!(v["user"]["userName"], "admin", "令牌身份应为 admin: {v}");

    // 认证成功后 signCount 应从 0 更新为 1
    let v = ctx.get_json("/system/user/webauthn/credentials").await;
    assert_eq!(
        v["data"][0]["signCount"], 1,
        "登录后 signCount 应更新为 1: {v}"
    );
}

/// ⑧ 负路径（安全）：断言重放 / signCount 回退 / 篡改认证器数据 / 篡改 challenge ⇒ 401
#[tokio::test]
async fn test_login_replay_counter_and_tampering_rejected() {
    let ctx = webauthn_ctx().await;
    let auth = SoftAuthenticator::new();
    soft_register(&ctx, &auth, "soft-key").await;

    // 首次合法登录（signCount=2）⇒ 成功，counter 落库为 2
    let (first, _) = start_login_assertion(&ctx, &auth, 2).await;
    let first_body = first.login_body(&auth.credential_id_b64());
    let (status, v) = ctx
        .send_raw(public_request(
            &ctx,
            "/login/webauthn/finish",
            first_body.clone(),
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "首次合法登录应成功: {v}");

    // ① 重放完全相同的断言（challenge 状态已在成功后消费删除）⇒ 401
    let (status, v) = ctx
        .send_raw(public_request(&ctx, "/login/webauthn/finish", first_body))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "断言重放必须被拒: {v}");
    assert_eq!(v["code"], 401, "重放应与登录失败同形: {v}");

    // ② signCount 回退（1 < 已存 2 且非 0）⇒ 库校验拒绝 ⇒ 401
    let (regress, _) = start_login_assertion(&ctx, &auth, 1).await;
    let (status, v) = ctx
        .send_raw(public_request(
            &ctx,
            "/login/webauthn/finish",
            regress.login_body(&auth.credential_id_b64()),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "signCount 回退必须被拒: {v}"
    );
    assert_eq!(v["code"], 401);

    // ③ 篡改认证器数据（保留原签名）⇒ 验签失败 ⇒ 401
    let (tamper, _) = start_login_assertion(&ctx, &auth, 3).await;
    let mut tamper_body = tamper.login_body(&auth.credential_id_b64());
    tamper_body["response"]["authenticatorData"] =
        serde_json::Value::String(tamper.tampered_authenticator_data());
    let (status, v) = ctx
        .send_raw(public_request(&ctx, "/login/webauthn/finish", tamper_body))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "篡改认证器数据必须被拒: {v}"
    );
    assert_eq!(v["code"], 401);

    // ④ 篡改 challenge（与 options 不一致，找不到登录状态）⇒ 401
    let (_, options) = start_login_assertion(&ctx, &auth, 0).await;
    let rp_id = options["rpId"].as_str().expect("应含 rpId").to_string();
    let real_challenge = options["challenge"].as_str().expect("应含 challenge");
    let bad_challenge = auth.assert(&rp_id, &format!("{real_challenge}tampered"), TEST_ORIGIN, 1);
    let (status, v) = ctx
        .send_raw(public_request(
            &ctx,
            "/login/webauthn/finish",
            bad_challenge.login_body(&auth.credential_id_b64()),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "篡改 challenge 必须被拒: {v}"
    );
    assert_eq!(v["code"], 401);
}

/// ⑨ 反例：错误 origin / 错误 rp_id 的断言 ⇒ 被拒
#[tokio::test]
async fn test_login_wrong_origin_or_rp_id_rejected() {
    let ctx = webauthn_ctx().await;
    let auth = SoftAuthenticator::new();
    soft_register(&ctx, &auth, "soft-key").await;

    // 错误 origin：clientDataJSON.origin 与服务端信任锚不一致 ⇒ 401
    let (_, options) = start_login_assertion(&ctx, &auth, 0).await;
    let rp_id = options["rpId"].as_str().expect("应含 rpId").to_string();
    let challenge = options["challenge"]
        .as_str()
        .expect("应含 challenge")
        .to_string();
    let bad_origin = auth.assert(&rp_id, &challenge, "http://evil.example", 1);
    let (status, v) = ctx
        .send_raw(public_request(
            &ctx,
            "/login/webauthn/finish",
            bad_origin.login_body(&auth.credential_id_b64()),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "错误 origin 必须被拒: {v}"
    );
    assert_eq!(v["code"], 401);

    // 错误 rp_id：authData 的 rpIdHash 用错误域名计算 ⇒ 401
    let (_, options) = start_login_assertion(&ctx, &auth, 0).await;
    let challenge = options["challenge"]
        .as_str()
        .expect("应含 challenge")
        .to_string();
    let bad_rp = auth.assert("evil.example", &challenge, TEST_ORIGIN, 1);
    let (status, v) = ctx
        .send_raw(public_request(
            &ctx,
            "/login/webauthn/finish",
            bad_rp.login_body(&auth.credential_id_b64()),
        ))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "错误 rp_id 必须被拒: {v}");
    assert_eq!(v["code"], 401);
}

/// 软件认证器（纯 Rust 真密码学）：ES256 密钥 + COSE_Key/authData/attestationObject + 真签名。
///
/// 关键实现点（与服务端 `passkey-server` 0.1.4 的校验逐项对齐，见其 `src/protocol.rs`）：
/// - `COSE_Key`：kty=EC2、alg=-7、crv=P-256、x/y（各 32B 大端），CBOR 编码；
/// - `authData`：`sha256(rp_id)` ‖ flags ‖ signCount(4B 大端) ‖〔attestedCredentialData〕；
///   注册 flags=`AT|UP|UV`(0x45)、认证 flags=`UP|UV`(0x05)（服务端仅强校验 UP 与 AT）；
/// - `clientDataJSON`：`{type, challenge, origin, crossOrigin}`（服务端仅读取 type/challenge/origin）；
/// - `attestationObject`：CBOR `{fmt:"none", attStmt:{}, authData:<bytes>}`（服务端仅取 authData）；
/// - 认证签名：对 `authData ‖ sha256(clientDataJSON)` 做 ECDSA-P256-SHA256，DER 编码。
mod soft_authenticator {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use coset::cbor::value::Value;
    use coset::{CborSerializable, CoseKeyBuilder, iana};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::Generate;
    use sha2::{Digest, Sha256};

    /// 认证器数据标志位
    const FLAG_UP: u8 = 0x01; // 用户在场
    const FLAG_UV: u8 = 0x04; // 用户已验证
    const FLAG_AT: u8 = 0x40; // 含 attestedCredentialData（注册时置位）

    /// 一次断言（登录）产出的原始 Base64url 组件
    pub struct Assertion {
        pub client_data_json: String,
        pub authenticator_data: String,
        pub signature: String,
    }

    /// 内存软件认证器：持有一对 ES256 密钥与凭据 ID
    pub struct SoftAuthenticator {
        signing_key: SigningKey,
        credential_id: Vec<u8>,
        aaguid: [u8; 16],
    }

    impl Default for SoftAuthenticator {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SoftAuthenticator {
        pub fn new() -> Self {
            Self {
                signing_key: SigningKey::generate_from_rng(&mut {
                    use rand_os::{SeedableRng, rngs::StdRng};
                    StdRng::try_from_rng(&mut rand_os::rngs::SysRng).expect("OS RNG seed failed")
                }),
                credential_id: rand::random::<[u8; 32]>().to_vec(),
                // 全零 AAGUID ⇒ 服务端归一为 None，凭据名取显式提交的 name（便于精确断言）
                aaguid: [0u8; 16],
            }
        }

        /// 凭据 ID 的 Base64url 编码（与服务端落库/登录查库口径一致：无填充）
        pub fn credential_id_b64(&self) -> String {
            URL_SAFE_NO_PAD.encode(&self.credential_id)
        }

        /// 构造 COSE_Key（EC2 / ES256 / P-256）并 CBOR 编码
        fn cose_public_key(&self) -> Vec<u8> {
            let sec1 = self.signing_key.verifying_key().to_sec1_bytes();
            assert_eq!(sec1.len(), 65, "P-256 未压缩公钥应为 65B（0x04 ‖ x ‖ y）");
            let x = sec1[1..33].to_vec();
            let y = sec1[33..65].to_vec();
            CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
                .algorithm(iana::Algorithm::ES256)
                .build()
                .to_vec()
                .expect("COSE 公钥 CBOR 编码失败")
        }

        /// 构造 authData：`sha256(rp_id)` ‖ flags ‖ signCount(4B 大端) ‖〔attestedCredentialData〕
        fn auth_data(&self, rp_id: &str, flags: u8, sign_count: u32, attested: bool) -> Vec<u8> {
            let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
            data.push(flags);
            data.extend_from_slice(&sign_count.to_be_bytes());
            if attested {
                data.extend_from_slice(&self.aaguid);
                let id_len = u16::try_from(self.credential_id.len()).expect("credential id 过长");
                data.extend_from_slice(&id_len.to_be_bytes());
                data.extend_from_slice(&self.credential_id);
                data.extend_from_slice(&self.cose_public_key());
            }
            data
        }

        /// 产出注册证明：返回 `(clientDataJSON, attestationObject)`（Base64url）
        pub fn attest(&self, rp_id: &str, challenge: &str, origin: &str) -> (String, String) {
            let client_data = client_data_json("webauthn.create", challenge, origin);
            let auth_data = self.auth_data(rp_id, FLAG_UP | FLAG_UV | FLAG_AT, 0, true);
            let attestation = Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("none".into())),
                (Value::Text("attStmt".into()), Value::Map(Vec::new())),
                (Value::Text("authData".into()), Value::Bytes(auth_data)),
            ]);
            let mut buf = Vec::new();
            coset::cbor::into_writer(&attestation, &mut buf)
                .expect("attestationObject CBOR 编码失败");
            (
                URL_SAFE_NO_PAD.encode(client_data),
                URL_SAFE_NO_PAD.encode(buf),
            )
        }

        /// 产出一份断言：对 `authData ‖ sha256(clientDataJSON)` 做 ES256 真签名（DER 编码）
        pub fn assert(
            &self,
            rp_id: &str,
            challenge: &str,
            origin: &str,
            sign_count: u32,
        ) -> Assertion {
            let client_data = client_data_json("webauthn.get", challenge, origin);
            let auth_data = self.auth_data(rp_id, FLAG_UP | FLAG_UV, sign_count, false);
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(&client_data));
            let signature: Signature = self.signing_key.sign(&signed);
            Assertion {
                client_data_json: URL_SAFE_NO_PAD.encode(client_data),
                authenticator_data: URL_SAFE_NO_PAD.encode(auth_data),
                // WebAuthn/COSE 要求 ECDSA 签名为 ASN.1 DER 编码
                //（`Signature::to_vec()` 返回裸 r‖s，必须用 `to_der()` 取 DER 字节）
                signature: URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
            }
        }
    }

    impl Assertion {
        /// 组装为 `WebauthnLoginFinishDto` 形状的请求体（`id`/`rawId` 一致）
        pub fn login_body(&self, credential_id_b64: &str) -> serde_json::Value {
            serde_json::json!({
                "username": "admin",
                "id": credential_id_b64,
                "rawId": credential_id_b64,
                "type": "public-key",
                "response": {
                    "clientDataJSON": self.client_data_json,
                    "authenticatorData": self.authenticator_data,
                    "signature": self.signature,
                }
            })
        }

        /// 篡改 `authenticatorData`（翻转末字节 signCount 低位），签名保持原样（用于验签失败用例）
        pub fn tampered_authenticator_data(&self) -> String {
            let mut bytes = URL_SAFE_NO_PAD
                .decode(&self.authenticator_data)
                .expect("authenticatorData 解码失败");
            let last = bytes.len() - 1;
            bytes[last] ^= 0xFF;
            URL_SAFE_NO_PAD.encode(bytes)
        }
    }

    /// `clientDataJSON` 字节（字段顺序固定；服务端仅反序列化 type/challenge/origin）
    fn client_data_json(type_: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::json!({
            "type": type_,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes()
    }
}
