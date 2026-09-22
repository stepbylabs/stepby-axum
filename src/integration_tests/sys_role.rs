// axum-backend/src/integration_tests/sys_role.rs
//! 角色模块链路集成测试：
//! - 列表 / 详情
//! - 新增 → 修改 → 启停 → 数据权限 → 删除 全 CRUD
//! - 授权用户：已授权/未授权列表 → 批量授权 → 取消授权
//! - 角色部门树

use super::TestContext;

/// 角色列表分页查询 + 详情。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_role_list_and_detail() {
    let ctx = TestContext::new().await;

    // 1. 分页列表
    let v = ctx
        .get_json("/system/role/list?pageNum=1&pageSize=10")
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.len() >= 2, "种子应至少 2 个角色，实际: {v}");
    assert!(
        rows.iter().any(|r| r["roleName"] == "超级管理员"),
        "列表应包含超级管理员，实际: {v}"
    );

    // 2. 详情
    let v = ctx.get_json("/system/role/1").await;
    assert_eq!(v["data"]["roleId"], 1, "角色详情 roleId 应为 1，实际: {v}");
    assert_eq!(
        v["data"]["roleKey"].as_str(),
        Some("admin"),
        "角色详情 roleKey 应为 admin，实际: {v}"
    );

    // 3. 角色部门树（roleId=1，depts 为顶层字段）
    let v = ctx.get_json("/system/role/deptTree/1").await;
    assert!(
        v["depts"].as_array().is_some(),
        "deptTree 应返回 depts 数组，实际: {v}"
    );
}

/// 角色 CRUD 全链路：新增 → 修改 → 启停 → 数据权限 → 删除。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_role_crud_chain() {
    let ctx = TestContext::new().await;

    // 1. 新增角色
    let v = ctx
        .post_json(
            "/system/role",
            serde_json::json!({
                "roleName": "集成测试角色",
                "roleKey": "it_role_crud",
                "roleSort": 99,
                "status": "0",
                "menuIds": [100, 101]
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 2. 按 roleKey 过滤查询到新角色
    let v = ctx.get_json("/system/role/list?roleKey=it_role_crud").await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert_eq!(rows.len(), 1, "应查到 1 个新角色，实际: {v}");
    let role_id = rows[0]["roleId"].as_i64().expect("roleId 应为数字");

    // 3. 修改角色
    let v = ctx
        .put_json(
            "/system/role",
            serde_json::json!({
                "roleId": role_id,
                "roleName": "集成测试角色改",
                "remark": "CRUD 链路验证"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 4. 详情确认修改生效
    let v = ctx.get_json(&format!("/system/role/{}", role_id)).await;
    assert_eq!(
        v["data"]["roleName"].as_str(),
        Some("集成测试角色改"),
        "修改后的 roleName 应生效，实际: {v}"
    );

    // 5. 启停（停用）
    let v = ctx
        .put_json(
            "/system/role/changeStatus",
            serde_json::json!({ "roleId": role_id, "status": "1" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 6. 数据权限（全部数据范围）
    let v = ctx
        .put_json(
            "/system/role/dataScope",
            serde_json::json!({
                "roleId": role_id,
                "dataScope": "1",
                "deptIds": []
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 7. 删除角色
    let v = ctx.delete_json(&format!("/system/role/{}", role_id)).await;
    ctx.assert_ok(&v);

    // 8. 确认删除生效
    let v = ctx.get_json("/system/role/list?roleKey=it_role_crud").await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(rows.is_empty(), "删除后不应再查到该角色，实际: {v}");
}

/// 授权用户链路：已授权/未授权列表 → 批量授权 → 取消授权。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_role_auth_user_chain() {
    let ctx = TestContext::new().await;

    // 1. 新增角色（无菜单，仅用于授权测试）
    let v = ctx
        .post_json(
            "/system/role",
            serde_json::json!({
                "roleName": "授权测试角色",
                "roleKey": "it_role_auth",
                "roleSort": 98,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json("/system/role/list?roleKey=it_role_auth").await;
    let role_id = v["rows"][0]["roleId"]
        .as_i64()
        .expect("应查到新角色 roleId");

    // 2. 新增用户（用于授权）
    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": "it_auth_user",
                "nickName": "授权测试用户",
                "email": "it.auth@yebot.dev",
                "phonenumber": "13800003333",
                "password": "Yebot@12345",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/user/list?userName=it_auth_user")
        .await;
    let user_id = v["rows"][0]["userId"]
        .as_i64()
        .expect("应查到新用户 userId");

    // 3. 初始：未授权列表应包含该用户，已授权列表不应包含
    let v = ctx
        .get_json(&format!(
            "/system/role/authUser/unallocatedList?roleId={}",
            role_id
        ))
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        rows.iter().any(|r| r["userId"] == user_id),
        "未授权列表应包含新用户，实际: {v}"
    );

    // 4. 批量授权
    let v = ctx
        .put_json(
            &format!(
                "/system/role/authUser/selectAll?roleId={}&userIds={}",
                role_id, user_id
            ),
            serde_json::json!({}),
        )
        .await;
    ctx.assert_ok(&v);

    // 5. 已授权列表应包含该用户，未授权列表不应包含
    let v = ctx
        .get_json(&format!(
            "/system/role/authUser/allocatedList?roleId={}",
            role_id
        ))
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        rows.iter().any(|r| r["userId"] == user_id),
        "授权后已授权列表应包含新用户，实际: {v}"
    );
    let v = ctx
        .get_json(&format!(
            "/system/role/authUser/unallocatedList?roleId={}",
            role_id
        ))
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        !rows.iter().any(|r| r["userId"] == user_id),
        "授权后未授权列表不应包含新用户，实际: {v}"
    );

    // 6. 取消授权
    let v = ctx
        .put_json(
            "/system/role/authUser/cancel",
            serde_json::json!({ "roleId": role_id, "userId": user_id }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!(
            "/system/role/authUser/allocatedList?roleId={}",
            role_id
        ))
        .await;
    let rows = v["rows"].as_array().expect("rows 应为数组");
    assert!(
        !rows.iter().any(|r| r["userId"] == user_id),
        "取消授权后已授权列表不应包含该用户，实际: {v}"
    );

    // 7. 清理：删除用户与角色
    let v = ctx.delete_json(&format!("/system/user/{}", user_id)).await;
    ctx.assert_ok(&v);
    let v = ctx.delete_json(&format!("/system/role/{}", role_id)).await;
    ctx.assert_ok(&v);
}
