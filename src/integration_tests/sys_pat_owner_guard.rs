// stepby-axum/src/integration_tests/sys_pat_owner_guard.rs
//! E1-a 回归：被删用户的 PAT 不可再用（HTTP 端到端）：
//! - 属主存活：PAT 访问 scope 内接口 → 200
//! - 属主被软删（DELETE /system/user/{id}）后：同一 PAT 访问 → 401
//!   （verify_token 属主回查 del_flag/status 拒绝 + delete_user 事务内物理清理双保险）
//! - 删除后：管理员 PAT 列表（/monitor/pat/list?userId=）无该用户令牌记录（孤儿清理）

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use std::net::SocketAddr;

use super::{TestContext, login};

/// 以指定 bearer 令牌构造请求。
fn bearer_request(ctx: &TestContext, bearer: &str, method: Method, uri: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pat_invalid_after_owner_deleted() {
    let ctx = TestContext::new().await;

    // 1. admin 创建普通用户并登录（普通角色 role_id=2 已关联全部菜单种子）
    let uname = "it_pat_owner";
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": uname,
                "nickName": "PAT属主守护",
                "email": "stepby@tzkj.net",
                "phonenumber": "13800007777",
                "sex": "0",
                "password": "Stepby@12345",
                "status": "0",
                "roleIds": [2]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    // add 接口只返回提示消息，经 list 查询取回 userId
    let v = ctx
        .get_json(&format!(
            "/system/user/list?userName={uname}&pageNum=1&pageSize=10"
        ))
        .await;
    ctx.assert_ok(&v);
    let uid = v["rows"][0]["userId"]
        .as_i64()
        .expect("列表应能查到新建用户 userId");
    let owner_token = login(&ctx.app, ctx.peer_ip, uname, "Stepby@12345").await;

    // 2. 属主自助签发 PAT（scope 对齐 /system/config/list）
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/system/user/profile/tokens")
        .header("authorization", format!("Bearer {owner_token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": "owner_guard",
                "scopes": ["system:config:list"],
                "expireDays": 30
            })
            .to_string(),
        ))
        .expect("构造签发请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    let v = ctx.send_json(req).await;
    ctx.assert_ok(&v);
    let pat = v["data"]["token"]
        .as_str()
        .expect("应返回明文 token")
        .to_string();

    // 3. 属主存活：PAT 访问 scope 内接口 → 200
    let (status, resp) = ctx
        .send_raw(bearer_request(
            &ctx,
            &pat,
            Method::GET,
            "/system/config/list?pageSize=5",
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "属主存活时 PAT 访问应 200，实际: {status} {resp}"
    );

    // 4. admin 软删属主用户（delete_user 事务内同步物理清理 PAT）
    let v = ctx.delete_json(&format!("/system/user/{uid}")).await;
    ctx.assert_ok(&v);

    // 5. 属主已删：同一 PAT 访问 → 401（verify_token 属主回查拒绝）
    let (status, resp) = ctx
        .send_raw(bearer_request(
            &ctx,
            &pat,
            Method::GET,
            "/system/config/list?pageSize=5",
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "属主被删后 PAT 应 401，实际: {status} {resp}"
    );

    // 6. 管理员 PAT 列表无该用户令牌记录（事务内孤儿清理生效）
    let v = ctx
        .get_json(&format!("/monitor/pat/list?userId={uid}&pageSize=50"))
        .await;
    ctx.assert_ok(&v);
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        rows.is_empty(),
        "属主删除后 PAT 记录应已清理，实际: {rows:?}"
    );
}
