// axum-backend/src/integration_tests/sys_user.rs
//! 用户模块链路集成测试：
//! - 列表 / 详情 / 部门树 / 角色下拉
//! - 新增 → 修改 → 启停 → 重置密码 → 删除 全 CRUD
//! - 分配角色 → 查询授权角色
//! - 个人中心：profile 查询/修改 → 改密 → 旧 token 失效 → 新密码重新登录

use super::TestContext;
use tower::ServiceExt;

/// 用户列表分页查询 + 详情 + 下拉树 + 角色下拉。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_list_query_and_detail() {
    let ctx = TestContext::new().await;

    // 1. 分页列表
    let v = ctx
        .get_json("/system/user/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        rows.len() >= 2,
        "种子应至少 2 个用户（admin/ry），实际: {v}"
    );
    assert!(
        v["total"].as_u64().unwrap() >= 2,
        "total 应 >= 2，实际: {v}"
    );
    assert!(
        rows.iter().any(|r| r["userName"] == "admin"),
        "列表应包含 admin，实际: {v}"
    );

    // 2. 按用户名过滤
    let v = ctx.get_json("/system/user/list?userName=admin").await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        rows.iter().all(|r| r["userName"] == "admin"),
        "按 userName=admin 过滤后应全是 admin，实际: {v}"
    );

    // 3. 详情
    let v = ctx.get_json("/system/user/1").await;
    assert_eq!(v["data"]["userId"], 1, "详情 userId 应为 1，实际: {v}");
    assert_eq!(
        v["data"]["userName"].as_str(),
        Some("admin"),
        "详情 userName 应为 admin，实际: {v}"
    );

    // 4. 部门下拉树
    let v = ctx.get_json("/system/user/deptTree").await;
    assert!(
        v["data"].as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "deptTree 应返回非空树，实际: {v}"
    );

    // 5. 角色下拉（GET /system/user/，roles 为顶层字段）
    let v = ctx.get_json("/system/user/").await;
    assert!(
        v["roles"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "用户表单角色下拉应返回角色列表，实际: {v}"
    );
}

/// 用户 CRUD 全链路：新增 → 查询 → 修改 → 启停 → 重置密码 → 删除。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_crud_chain() {
    let ctx = TestContext::new().await;

    // 1. 新增用户
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": "it_crud_user",
                "nickName": "集成测试用户",
                "email": "it.crud@yebot.dev",
                "phonenumber": "13800001111",
                "sex": "0",
                "password": "Yebot@12345",
                "status": "0",
                "postIds": [1],
                "roleIds": [2]
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 2. 查询到新用户并取 userId
    let v = ctx
        .get_json("/system/user/list?userName=it_crud_user")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 个新用户，实际: {v}");
    let user_id = rows[0]["userId"].as_i64().expect("userId 应为数字");
    assert!(user_id > 0, "新用户 userId 应 > 0");

    // 3. 修改用户（昵称）
    let v = ctx
        .put_json(
            "/system/user",
            serde_json::json!({
                "userId": user_id,
                "nickName": "集成测试用户改",
                "remark": "CRUD 链路验证"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 4. 详情确认修改生效
    let v = ctx.get_json(&format!("/system/user/{}", user_id)).await;
    assert_eq!(
        v["data"]["nickName"].as_str(),
        Some("集成测试用户改"),
        "修改后的 nickName 应生效，实际: {v}"
    );

    // 5. 启停（停用）
    let v = ctx
        .put_json(
            "/system/user/changeStatus",
            serde_json::json!({ "userId": user_id, "status": "1" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 6. 重置密码
    let v = ctx
        .put_json(
            "/system/user/resetPwd",
            serde_json::json!({ "userId": user_id, "password": "newpass123" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 7. 删除用户
    let v = ctx.delete_json(&format!("/system/user/{}", user_id)).await;
    ctx.assert_ok(&v);

    // 8. 确认删除生效
    let v = ctx
        .get_json("/system/user/list?userName=it_crud_user")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "删除后不应再查到该用户，实际: {v}");
}

/// 分配用户角色 → 查询授权角色。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_user_role_assign_chain() {
    let ctx = TestContext::new().await;

    // 1. 新增一个用户用于角色分配
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": "it_role_user",
                "nickName": "角色分配测试",
                "email": "it.role@yebot.dev",
                "phonenumber": "13800002222",
                "password": "Yebot@12345",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    let v = ctx
        .get_json("/system/user/list?userName=it_role_user")
        .await;
    let user_id = v["rows"][0]["userId"]
        .as_i64()
        .expect("应查到新用户 userId");

    // 2. 分配角色 roleIds=[2]
    let v = ctx
        .put_json(
            &format!("/system/user/authRole?userId={}&roleIds=2", user_id),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);

    // 3. 查询授权角色，确认包含 role 2（roles 为顶层字段）
    let v = ctx
        .get_json(&format!("/system/user/authRole/{}", user_id))
        .await;
    let roles = v["roles"].as_array().expect("roles 应为数组");
    assert!(
        roles.iter().any(|r| r["roleId"] == 2),
        "授权角色应包含 roleId=2，实际: {v}"
    );

    // 4. 清理：删除测试用户
    let v = ctx.delete_json(&format!("/system/user/{}", user_id)).await;
    ctx.assert_ok(&v);
}

/// 个人中心链路：profile 查询/修改 → 改密 → 旧 token 失效 → 新密码登录。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_profile_and_password_chain() {
    let ctx = TestContext::new().await;

    // 1. profile 查询（用户字段在 data 顶层，postGroup/roleGroup 在响应顶层）
    let v = ctx.get_json("/system/user/profile").await;
    assert_eq!(
        v["data"]["userName"].as_str(),
        Some("admin"),
        "profile 应返回 admin，实际: {v}"
    );
    assert!(
        v["postGroup"].as_str().is_some(),
        "profile 应返回 postGroup，实际: {v}"
    );
    assert!(
        v["roleGroup"].as_str().is_some(),
        "profile 应返回 roleGroup，实际: {v}"
    );

    // 2. 修改个人信息
    let v = ctx
        .put_json(
            "/system/user/profile",
            serde_json::json!({
                "nickName": "Yebot管理员改",
                "email": "admin@yebot.dev",
                "sex": "1"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 3. 个人改密（旧密码 → 新密码）
    let v = ctx
        .put_json(
            "/system/user/profile/updatePwd",
            serde_json::json!({
                "oldPassword": "admin123",
                "newPassword": "newpass456"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 4. 改密后旧 token 立即失效 → 401
    let (status, _) = ctx
        .send_raw(
            axum::http::Request::builder()
                .method("GET")
                .uri("/system/user/profile")
                .header("authorization", format!("Bearer {}", ctx.token))
                .body(axum::body::Body::empty())
                .expect("构造请求失败"),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "改密后旧 token 应失效"
    );

    // 5. 新密码登录 → 新 token 可用
    let new_token = super::login(&ctx.app, ctx.peer_ip, "admin", "newpass456").await;
    let app = ctx.app.clone();
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/system/user/profile")
                .header("authorization", format!("Bearer {}", new_token))
                .body(axum::body::Body::empty())
                .expect("构造请求失败"),
        )
        .await
        .expect("请求执行失败");
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "新密码登录后 profile 应返回 200"
    );
}

/// 管理员重置密码链路（P0-R81-007 版本号机制）：
/// 新增用户并登录 → 管理员重置其密码 → 用户旧 token 立即失效（401）→ 新密码重新登录可用。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_admin_reset_pwd_invalidates_token() {
    let ctx = TestContext::new().await;

    // 1. 新增目标用户（admin 操作）
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": "it_reset_pwd_user",
                "nickName": "重置密码目标",
                "email": "it.reset@yebot.dev",
                "phonenumber": "13800003333",
                "password": "Yebot@12345",
                "status": "0",
                "roleIds": [2]
            }),
        )
        .await;
    ctx.assert_ok(&v);

    let v = ctx
        .get_json("/system/user/list?userName=it_reset_pwd_user")
        .await;
    let user_id = v["rows"][0]["userId"]
        .as_i64()
        .expect("应查到目标用户 userId");

    // 2. 目标用户自行登录，拿到 token A
    let user_peer = super::next_peer_ip();
    let token_a = super::login(&ctx.app, user_peer, "it_reset_pwd_user", "Yebot@12345").await;
    let status_a = ctx
        .send_raw(
            axum::http::Request::builder()
                .method("GET")
                .uri("/system/user/profile")
                .header("authorization", format!("Bearer {}", token_a))
                .body(axum::body::Body::empty())
                .expect("构造请求失败"),
        )
        .await
        .0;
    assert_eq!(
        status_a,
        axum::http::StatusCode::OK,
        "重置前旧 token 应可用"
    );

    // 3. 管理员重置其密码
    let v = ctx
        .put_json(
            "/system/user/resetPwd",
            serde_json::json!({ "userId": user_id, "password": "Newpass789" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 4. 重置后用户旧 token A 立即失效 → 401
    let (status, _) = ctx
        .send_raw(
            axum::http::Request::builder()
                .method("GET")
                .uri("/system/user/profile")
                .header("authorization", format!("Bearer {}", token_a))
                .body(axum::body::Body::empty())
                .expect("构造请求失败"),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "管理员重置密码后用户旧 token 应失效"
    );

    // 5. 新密码重新登录 → 新 token 可用
    let token_b = super::login(&ctx.app, user_peer, "it_reset_pwd_user", "Newpass789").await;
    let (status, _) = ctx
        .send_raw(
            axum::http::Request::builder()
                .method("GET")
                .uri("/system/user/profile")
                .header("authorization", format!("Bearer {}", token_b))
                .body(axum::body::Body::empty())
                .expect("构造请求失败"),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "新密码登录后 profile 应返回 200"
    );

    // 6. 清理：删除目标用户
    let v = ctx.delete_json(&format!("/system/user/{}", user_id)).await;
    ctx.assert_ok(&v);
}

/// 停用/启用链路（P0-R81-007 版本号机制）：
/// 新增用户并登录 → 管理员停用 → 旧 token 失效（401）→ 管理员启用 → 旧 token 仍失效 → 重新登录可用。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_disable_enable_invalidates_token() {
    let ctx = TestContext::new().await;

    // 1. 新增目标用户（admin 操作）
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": "it_disable_user",
                "nickName": "停用目标",
                "email": "it.disable@yebot.dev",
                "phonenumber": "13800004444",
                "password": "Yebot@12345",
                "status": "0",
                "roleIds": [2]
            }),
        )
        .await;
    ctx.assert_ok(&v);

    let v = ctx
        .get_json("/system/user/list?userName=it_disable_user")
        .await;
    let user_id = v["rows"][0]["userId"]
        .as_i64()
        .expect("应查到目标用户 userId");

    // 2. 目标用户自行登录，拿到 token A
    let user_peer = super::next_peer_ip();
    let token_a = super::login(&ctx.app, user_peer, "it_disable_user", "Yebot@12345").await;

    // 3. 管理员停用用户
    let v = ctx
        .put_json(
            "/system/user/changeStatus",
            serde_json::json!({ "userId": user_id, "status": "1" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 4. 停用后旧 token A 立即失效 → 401
    let (status, _) = ctx
        .send_raw(
            axum::http::Request::builder()
                .method("GET")
                .uri("/system/user/profile")
                .header("authorization", format!("Bearer {}", token_a))
                .body(axum::body::Body::empty())
                .expect("构造请求失败"),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "停用后旧 token 应失效"
    );

    // 5. 管理员重新启用用户
    let v = ctx
        .put_json(
            "/system/user/changeStatus",
            serde_json::json!({ "userId": user_id, "status": "0" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 6. 启用后旧 token A 仍失效（版本号已递增，必须重新登录）
    let (status, _) = ctx
        .send_raw(
            axum::http::Request::builder()
                .method("GET")
                .uri("/system/user/profile")
                .header("authorization", format!("Bearer {}", token_a))
                .body(axum::body::Body::empty())
                .expect("构造请求失败"),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "启用后旧 token 仍应失效（需重新登录）"
    );

    // 7. 重新登录 → 新 token 可用
    let token_b = super::login(&ctx.app, user_peer, "it_disable_user", "Yebot@12345").await;
    let (status, _) = ctx
        .send_raw(
            axum::http::Request::builder()
                .method("GET")
                .uri("/system/user/profile")
                .header("authorization", format!("Bearer {}", token_b))
                .body(axum::body::Body::empty())
                .expect("构造请求失败"),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "重新登录后 profile 应返回 200"
    );

    // 8. 清理：删除目标用户
    let v = ctx.delete_json(&format!("/system/user/{}", user_id)).await;
    ctx.assert_ok(&v);
}
