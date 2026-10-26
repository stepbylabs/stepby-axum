// stepby-axum/src/integration_tests/sys_menu_dept.rs
//! 菜单 + 部门模块链路集成测试：
//! - 菜单：列表 / 下拉树 / 角色菜单树 / 详情 / 新增 → 修改 → 排序 → 删除
//! - 部门：列表 / 排除节点 / 下拉树 / 详情 / 新增 → 修改 → 排序 → 删除

use super::TestContext;
use axum::http::{Method, StatusCode};

/// 菜单模块全链路。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_menu_chain() {
    let ctx = TestContext::new().await;

    // 1. 菜单列表（AjaxResult<Vec>，数据在 data 字段）
    let v = ctx.get_json("/system/menu/list").await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(
        data.iter().any(|r| r["menuName"] == "系统管理"),
        "菜单列表应包含系统管理，实际: {v}"
    );

    // 2. 菜单下拉树
    let v = ctx.get_json("/system/menu/treeselect").await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(
        data.iter().any(|n| n["label"] == "系统管理"),
        "下拉树应包含系统管理，实际: {v}"
    );

    // 3. 角色菜单树（roleId=1，顶层含 menus/checkedKeys）
    let v = ctx.get_json("/system/menu/roleMenuTreeselect/1").await;
    ctx.assert_ok(&v);
    assert!(
        v["menus"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "角色菜单树 menus 不应为空，实际: {v}"
    );

    // 4. 菜单详情
    let v = ctx.get_json("/system/menu/1").await;
    assert_eq!(v["data"]["menuId"], 1, "菜单详情 menuId 应为 1，实际: {v}");

    // 5. 新增菜单
    let v = ctx
        .post_json(
            "/system/menu",
            serde_json::json!({
                "parentId": 1,
                "menuName": "集成测试菜单",
                "orderNum": 99,
                "path": "it-menu",
                "component": "system/itMenu/index",
                "menuType": "C",
                "visible": "0",
                "status": "0",
                "perms": "system:itMenu:list",
                "icon": "tool"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 6. 按 perms 过滤查到新菜单
    let v = ctx
        .get_json("/system/menu/list?menuName=集成测试菜单")
        .await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert_eq!(data.len(), 1, "应查到 1 条新菜单，实际: {v}");
    let menu_id = data[0]["menuId"].as_i64().expect("menuId 应为数字");

    // 7. 修改菜单
    let v = ctx
        .put_json(
            "/system/menu",
            serde_json::json!({
                "menuId": menu_id,
                "parentId": 1,
                "menuName": "集成测试菜单改",
                "menuType": "C"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/menu/{}", menu_id)).await;
    assert_eq!(
        v["data"]["menuName"].as_str(),
        Some("集成测试菜单改"),
        "修改后的 menuName 应生效，实际: {v}"
    );

    // 7b. 权限键格式闸：通配符会命中超管短路，必须在写面拒绝（新增与修改两条路径）。
    let wildcard_menu = serde_json::json!({
        "parentId": 1,
        "menuName": "非法通配菜单",
        "orderNum": 100,
        "path": "it-wildcard",
        "component": "system/itWildcard/index",
        "menuType": "C",
        "visible": "0",
        "status": "0",
        "perms": "*:*:*"
    });
    let (status, v) = ctx
        .send_raw(ctx.request(Method::POST, "/system/menu", Some(wildcard_menu)))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "通配权限键应 400，实际: {v}"
    );
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/menu",
            Some(serde_json::json!({
                "menuId": menu_id,
                "parentId": 1,
                "menuName": "集成测试菜单改",
                "menuType": "C",
                "perms": "*:*:*"
            })),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "修改为通配权限键应 400，实际: {v}"
    );
    let v = ctx.get_json(&format!("/system/menu/{}", menu_id)).await;
    assert_eq!(
        v["data"]["perms"].as_str(),
        Some("system:itMenu:list"),
        "被拒绝的通配写入不得改动原 perms，实际: {v}"
    );

    // 8. 菜单排序
    let v = ctx
        .put_json(
            "/system/menu/updateSort",
            serde_json::json!({ "menuIds": "100,101", "orderNums": "1,2" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 9. 删除菜单
    let v = ctx.delete_json(&format!("/system/menu/{}", menu_id)).await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/menu/list?menuName=集成测试菜单改")
        .await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(data.is_empty(), "删除后不应再查到该菜单，实际: {v}");
}

/// 部门模块全链路。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dept_chain() {
    let ctx = TestContext::new().await;

    // 1. 部门列表（data 数组）
    let v = ctx.get_json("/system/dept/list").await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(
        data.iter().any(|d| d["deptName"] == "Stepby科技"),
        "部门列表应包含 Stepby科技，实际: {v}"
    );

    // 2. 排除节点列表（排除 100 后不应包含其自身）
    let v = ctx.get_json("/system/dept/list/exclude/100").await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(
        !data.iter().any(|d| d["deptId"] == 100),
        "排除节点 100 后不应包含 deptId=100，实际: {v}"
    );

    // 3. 部门下拉树
    let v = ctx.get_json("/system/dept/treeselect").await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(
        data.iter().any(|n| n["label"] == "Stepby科技"),
        "部门树应包含 Stepby科技，实际: {v}"
    );

    // 4. 部门详情
    let v = ctx.get_json("/system/dept/100").await;
    assert_eq!(
        v["data"]["deptId"], 100,
        "部门详情 deptId 应为 100，实际: {v}"
    );

    // 5. 新增部门（挂在 103 研发部门下）
    let v = ctx
        .post_json(
            "/system/dept",
            serde_json::json!({
                "parentId": 103,
                "deptName": "集成测试部门",
                "orderNum": 99,
                "leader": "Stepby",
                "phone": "15888888888",
                "email": "stepby@tzkj.net",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);

    // 6. 查询到新部门
    let v = ctx
        .get_json("/system/dept/list?deptName=集成测试部门")
        .await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert_eq!(data.len(), 1, "应查到 1 个新部门，实际: {v}");
    let dept_id = data[0]["deptId"].as_i64().expect("deptId 应为数字");

    // 7. 修改部门
    let v = ctx
        .put_json(
            "/system/dept",
            serde_json::json!({
                "deptId": dept_id,
                "parentId": 103,
                "deptName": "集成测试部门改"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/dept/{}", dept_id)).await;
    assert_eq!(
        v["data"]["deptName"].as_str(),
        Some("集成测试部门改"),
        "修改后的 deptName 应生效，实际: {v}"
    );

    // 8. 部门排序
    let v = ctx
        .put_json(
            "/system/dept/updateSort",
            serde_json::json!({ "deptIds": "100,101", "orderNums": "1,2" }),
        )
        .await;
    ctx.assert_ok(&v);

    // 9. 删除部门
    let v = ctx.delete_json(&format!("/system/dept/{}", dept_id)).await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/dept/list?deptName=集成测试部门改")
        .await;
    let data = v["data"].as_array().expect("data 应为数组");
    assert!(data.is_empty(), "删除后不应再查到该部门，实际: {v}");
}
