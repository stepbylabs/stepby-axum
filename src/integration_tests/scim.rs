// stepby-axum/src/integration_tests/scim.rs
//! v5-D12：SCIM 2.0 用户目录同步端到端链路。
//!
//! 覆盖：Bearer 鉴权（缺失/错误 401）→ provision 创建（201 + 随机不可知密码）→
//! get → list（userName eq filter）→ patch(active=false) → 登录拒绝 →
//! put（userName 不可变 400）→ delete(停用 204) → 软停用可读语义。
//! helper（raw_get/raw_post/json_of）与 sso.rs 同款（本文件自包含）。

use super::TestContext;
use axum::body::Body;
use axum::body::to_bytes;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use std::net::{IpAddr, SocketAddr};
use tower::ServiceExt;

const BEARER: &str = "Bearer scim-test-bearer-token-0123456789abcdef";

fn scim_headers() -> [(&'static str, &'static str); 2] {
    [
        ("authorization", BEARER),
        ("content-type", "application/json"),
    ]
}

async fn scim_ctx() -> TestContext {
    unsafe {
        std::env::set_var("SCIM_ENABLED", "true");
        std::env::set_var(
            "SCIM_BEARER_TOKEN",
            "scim-test-bearer-token-0123456789abcdef",
        );
    }
    // build_isolated_state 内已统一开启 SCIM（见 mod.rs），TestContext::new 即可
    TestContext::new().await
}

fn json_of(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap_or(serde_json::Value::Null)
}

async fn raw_get(
    app: &axum::Router,
    peer_ip: IpAddr,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    raw_request(app, peer_ip, Method::GET, uri, None, headers).await
}

async fn raw_post(
    app: &axum::Router,
    peer_ip: IpAddr,
    uri: &str,
    content_type: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    raw_request(
        app,
        peer_ip,
        Method::POST,
        uri,
        Some((content_type, body)),
        headers,
    )
    .await
}

async fn raw_put(
    app: &axum::Router,
    peer_ip: IpAddr,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    raw_request(
        app,
        peer_ip,
        Method::PUT,
        uri,
        Some(("application/json", body)),
        headers,
    )
    .await
}

async fn raw_delete(
    app: &axum::Router,
    peer_ip: IpAddr,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    raw_request(app, peer_ip, Method::DELETE, uri, None, headers).await
}

async fn raw_request(
    app: &axum::Router,
    peer_ip: IpAddr,
    method: Method,
    uri: &str,
    body: Option<(&str, &str)>,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Body::from(
            body.map(|(_, b)| b.to_string()).unwrap_or_default(),
        ))
        .expect("构造请求失败");
    let mut req = req;
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((peer_ip, 1234))));
    let resp = app.clone().oneshot(req).await.expect("oneshot 失败");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    (status, headers, bytes.to_vec())
}

/// SCIM 全链路：鉴权 → provision → 读取 → 过滤 → 停用 → 登录拒绝 → 删除语义
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_users_crud_and_deprovision() {
    let ctx = scim_ctx().await;

    // ① 无凭据 → 401（enabled=true，端点存在）
    let (status, _, _) = raw_get(&ctx.app, ctx.peer_ip, "/scim/v2/Users", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "无凭据应 401");

    // ② 错误凭据 → 401
    let (status, _, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users",
        &[("authorization", "Bearer wrong-token-000000000000000000")],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "错误凭据应 401");

    // ③ provision 创建（201 + 随机不可知密码）
    let create_body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "scim.user01",
        "name": {"displayName": "SCIM 同步用户"},
        "emails": [{"value": "scim.user01@example.com", "primary": true}],
        "active": true
    });
    let (status, _, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users",
        "application/json",
        &create_body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "provision 应 201: {}",
        String::from_utf8_lossy(&body)
    );
    let created = json_of(&body);
    let uid = created["id"].as_str().unwrap_or_default().to_string();
    assert!(!uid.is_empty(), "响应应含 id");
    assert_eq!(created["active"], serde_json::json!(true));
    assert_eq!(created["meta"]["resourceType"], "User");

    // ④ GET 读取
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid}"),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_of(&body)["userName"], "scim.user01");

    // ⑤ list + userName eq filter → 命中 1 条
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users?startIndex=1&count=100&filter=userName%20eq%20%22scim.user01%22",
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let list = json_of(&body);
    assert_eq!(
        list["totalResults"],
        serde_json::json!(1),
        "filter 应命中 1 条: {list}"
    );
    assert_eq!(list["Resources"][0]["id"], created["id"]);

    // ⑥ 不支持的 filter → 400
    let (status, _, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users?filter=emails%20eq%20%22x%22",
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "不支持的 filter 应 400");

    // ⑦ provision 用户本地登录：随机不可知密码 → 拒绝
    let (status, _, _) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/login",
        "application/json",
        r#"{"username":"scim.user01","password":"any-guess","code":"","uuid":""}"#,
        &[],
    )
    .await;
    assert_ne!(status, StatusCode::OK, "provision 用户随机密码不应可登录");

    // ⑧ patch active=false → 200 + active=false
    let patch_body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "active", "value": false}]
    })
    .to_string();
    let (status, _, body) = raw_request(
        &ctx.app,
        ctx.peer_ip,
        Method::PATCH,
        &format!("/scim/v2/Users/{uid}"),
        Some(("application/json", &patch_body)),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "patch 应 200: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json_of(&body)["active"], serde_json::json!(false));

    // ⑨ DELETE（deprovision=停用）→ 204；GET 仍可读且 active=false（非物理删）
    let (status, _, _) = raw_delete(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid}"),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete 应 204");
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid}"),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "软停用后 GET 应可读（非物理删）");
    assert_eq!(json_of(&body)["active"], serde_json::json!(false));

    // ⑩ PUT 改 userName → 400（不可变）
    let put_body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "renamed.user",
        "name": {"displayName": "改名"},
        "active": false
    })
    .to_string();
    let (status, _, _) = raw_put(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid}"),
        &put_body,
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "PUT 改名应 400");
}

/// v5-D12 深化：externalId 落库/回显/过滤/唯一性 + provision 事件不阻断主链
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_external_id_and_events() {
    let ctx = scim_ctx().await;

    // ① 创建带 externalId（201，回显一致）
    let create_body = serde_json::json!({
        "userName": "scim.ext01",
        "externalId": "idp-abc-001",
        "name": {"displayName": "外部同步用户"},
        "active": true
    });
    let (status, _, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users",
        "application/json",
        &create_body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let created = json_of(&body);
    assert_eq!(created["externalId"], serde_json::json!("idp-abc-001"));
    let uid = created["id"].as_str().unwrap_or_default().to_string();

    // ② GET 回显 externalId
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid}"),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json_of(&body)["externalId"],
        serde_json::json!("idp-abc-001")
    );

    // ③ externalId eq filter → 命中
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users?filter=externalId%20eq%20%22idp-abc-001%22",
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_of(&body)["totalResults"], serde_json::json!(1));

    // ④ 重复 externalId → 409
    let dup_body = serde_json::json!({
        "userName": "scim.ext02",
        "externalId": "idp-abc-001"
    });
    let (status, _, _) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users",
        "application/json",
        &dup_body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "重复 externalId 应 409");

    // ⑤ PATCH 更新 externalId → 200 回显新值
    let patch_body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "externalId", "value": "idp-abc-002"}]
    })
    .to_string();
    let (status, _, body) = raw_request(
        &ctx.app,
        ctx.peer_ip,
        Method::PATCH,
        &format!("/scim/v2/Users/{uid}"),
        Some(("application/json", &patch_body)),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        json_of(&body)["externalId"],
        serde_json::json!("idp-abc-002")
    );

    // ⑤-b 建第二个用户承载"已被占用"的 externalId，供 PUT/PATCH 冲突回归锁使用
    let (status, _, body) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users",
        "application/json",
        &serde_json::json!({"userName": "scim.ext03", "externalId": "idp-abc-003"}).to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let uid2 = json_of(&body)["id"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // ⑤-c **PUT 冲突必须 409**（b71 回归锁：PUT 原先完全不校验 externalId，
    // 同一字段 PATCH 查重、PUT 裸写 ⇒ 经 PUT 可写入重复映射，后续按 externalId
    // 反查的同步会互相覆盖）
    let (status, _, body) = raw_put(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid}"),
        &serde_json::json!({"userName": "scim.ext01", "externalId": "idp-abc-003"}).to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "PUT 写入他人已占用的 externalId 应 409：{}",
        String::from_utf8_lossy(&body)
    );

    // ⑤-d PUT 超长 externalId → 400（PATCH 早已有此校验，PUT 补齐同口径）
    let long_ext = "x".repeat(256);
    let (status, _, _) = raw_put(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid}"),
        &serde_json::json!({"userName": "scim.ext01", "externalId": long_ext}).to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "externalId 超 255 应 400");

    // ⑤-e PUT 保持**自己**的 externalId 必须放行（helper 的 self_id 排除不得误报 409）
    let (status, _, body) = raw_put(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid}"),
        &serde_json::json!({"userName": "scim.ext01", "externalId": "idp-abc-002"}).to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PUT 写回自身 externalId 不应被判重复：{}",
        String::from_utf8_lossy(&body)
    );

    // ⑤-f PATCH（无 path 的 replace，value 内含 externalId）冲突同样 409
    let patch_conflict = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "value": {"externalId": "idp-abc-003"}}]
    })
    .to_string();
    let (status, _, _) = raw_request(
        &ctx.app,
        ctx.peer_ip,
        Method::PATCH,
        &format!("/scim/v2/Users/{uid}"),
        Some(("application/json", &patch_conflict)),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "PATCH no-path 写入他人 externalId 应 409"
    );

    // ⑥ DELETE（deprovision，触发 scim_user_deactivated 事件——无订阅时火后即忘不阻断）
    let (status, _, _) = raw_delete(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid}"),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // ⑥-b 清理⑤-b 的占用承载用户（用例自清理，不留存量 externalId）
    let (status, _, _) = raw_delete(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid2}"),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}
// v5-D12 Group：原 Groups 501 显式边界测试已随真实现移除——
// Group CRUD/联动授权/删除语义的完整替代测试见 integration_tests/scim_groups.rs。
