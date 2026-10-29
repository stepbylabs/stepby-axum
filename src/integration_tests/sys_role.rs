// stepby-axum/src/integration_tests/sys_role.rs
//! 角色模块链路集成测试：
//! - 列表 / 详情
//! - 新增 → 修改 → 启停 → 数据权限 → 删除 全 CRUD
//! - 授权用户：已授权/未授权列表 → 批量授权 → 取消授权
//! - 角色部门树

use super::TestContext;
use axum::http::Method;

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

/// 数据范围档位白名单（批七十九）。
///
/// 改造前实测：`PUT /system/role/dataScope` 传 `dataScope="9"` 返回 `200 修改成功` 并写入
/// `sys_role`，而读取侧 `min_data_scope` 的 `_ =>` 兜底把未知档位降级成"本部门"——
/// 显示与行为分裂，且 `0` 这类档位在"取最小值"规则下会覆盖同用户其他角色的合法档。
/// 本用例钉三件事：① 三条写入路径**全部**拒非法档；② 合法档照常通过（对照组，
/// 否则实现可以是"这个入口永远 400"）；③ 被拒的那次写入**不留痕**（库里的档位不变）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_role_data_scope_rejects_unknown_tier() {
    let ctx = TestContext::new().await;

    // 非快乐路径必须走 send_raw：`post_json/put_json` 内部就断言 code==200，
    // 用它发期望被拒的请求会先在自己的断言上炸（b79 实测踩过一次，报的是"业务码应为 200"）。
    let assert_rejected = |status: axum::http::StatusCode, v: &serde_json::Value, label: &str| {
        assert_eq!(
            status.as_u16(),
            400,
            "{label} HTTP 状态码应为 400，实际 {status}，响应: {v}"
        );
        assert_eq!(
            v["code"].as_i64(),
            Some(400),
            "{label} 业务码应为 400，实际: {v}"
        );
        let msg = v["msg"].as_str().unwrap_or("");
        assert!(!msg.is_empty(), "{label} 错误文案不得为空，实际: {v}");
        assert!(
            !msg.starts_with("error."),
            "{label} 文案必须已在 zh/en 解析出文本（回显键名说明缺键），实际: {msg}"
        );
    };

    // ① 新增路径：非法档位不得建角色，也不得留下半行数据
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/role",
            Some(serde_json::json!({
                "roleName": "集成测试非法档",
                "roleKey": "it_ds_bad_add",
                "roleSort": 98,
                "status": "0",
                "dataScope": "7"
            })),
        ))
        .await;
    assert_rejected(status, &v, "POST /system/role dataScope=7");
    let v = ctx
        .get_json("/system/role/list?roleKey=it_ds_bad_add")
        .await;
    assert!(
        v["rows"].as_array().expect("rows 应为数组").is_empty(),
        "被拒的新增不得落库，实际: {v}"
    );

    // 建一个本用例专属角色（正控：合法新增必须成功，否则后面的拒绝毫无意义）
    let v = ctx
        .post_json(
            "/system/role",
            serde_json::json!({
                "roleName": "集成测试档位守卫",
                "roleKey": "it_ds_guard",
                "roleSort": 97,
                "status": "0",
                "menuIds": [100]
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json("/system/role/list?roleKey=it_ds_guard").await;
    let role_id = v["rows"][0]["roleId"]
        .as_i64()
        .unwrap_or_else(|| panic!("应能查到刚创建的角色，实际: {v}"));

    // ② 编辑路径：非法档位拒，且不影响其余字段
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/role",
            Some(serde_json::json!({ "roleId": role_id, "dataScope": "0" })),
        ))
        .await;
    assert_rejected(status, &v, "PUT /system/role dataScope=0");

    // ③ 数据权限专用路径：非法档位拒（b79 修复前正是这一条返回 200）
    let (status, v) = ctx
        .send_raw(ctx.request(
            Method::PUT,
            "/system/role/dataScope",
            Some(serde_json::json!({ "roleId": role_id, "dataScope": "9", "deptIds": [] })),
        ))
        .await;
    assert_rejected(status, &v, "PUT /system/role/dataScope dataScope=9");

    // 正控 + 不留痕：合法档位必须照常写入，且上面三次被拒的写入没有改变库内档位
    let v = ctx
        .put_json(
            "/system/role/dataScope",
            serde_json::json!({ "roleId": role_id, "dataScope": "2", "deptIds": [100] }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .put_json(
            "/system/role/dataScope",
            serde_json::json!({ "roleId": role_id, "dataScope": "4", "deptIds": [] }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json(&format!("/system/role/{}", role_id)).await;
    assert_eq!(
        v["data"]["dataScope"].as_str(),
        Some("4"),
        "档位应停留在最后一次合法写入（非法档被拒且不留痕），实际: {v}"
    );

    let v = ctx.delete_json(&format!("/system/role/{}", role_id)).await;
    ctx.assert_ok(&v);
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
                "email": "stepby@tzkj.net",
                "phonenumber": "13800003333",
                "password": "Stepby@12345",
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

/// 角色授权三条写路径的**横向越权**回归锁（b95）。
///
/// 旧实现的缺口是"人同租 ≠ 角色同租"：`selectAll/cancelAll/cancel` 只校验目标
/// 用户属于操作者租户，却没校验**角色**的归属，于是租户操作者可以把平台角色
/// （`tenant_id=0`）或他租角色挂到本租用户身上，或反向解除他租角色的授权。
/// 本用例用合成 `tid=5` 令牌（超管主体、`*:*:*`，从而 403 只可能来自租户校验）
/// 覆盖三条路径的拒绝面，并用同租角色做正控。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_role_auth_user_cross_tenant_role_is_rejected() {
    use crate::jwt::JwtUtils;
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
    use std::net::SocketAddr;

    const TID: i64 = 5;
    const OTHER_TID: i64 = 6;
    const ROLE_SAME: i64 = 99_001;
    const ROLE_PLATFORM: i64 = 99_002;
    const ROLE_OTHER: i64 = 99_003;
    const UID_SAME: i64 = 99_011;

    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    for (role_id, tenant_id) in [
        (ROLE_SAME, TID),
        (ROLE_PLATFORM, 0),
        (ROLE_OTHER, OTHER_TID),
    ] {
        crate::entity::sys_role::ActiveModel {
            role_id: Set(role_id),
            role_name: Set(format!("it_role_xtenant_{role_id}")),
            role_key: Set(format!("it_role_xtenant_key_{role_id}")),
            role_sort: Set(50),
            data_scope: Set(Some("1".to_string())),
            status: Set("0".to_string()),
            tenant_id: Set(tenant_id),
            is_system: Set(false),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        }
        .insert(db)
        .await
        .expect("插入角色失败");
    }
    crate::entity::sys_user::ActiveModel {
        user_id: Set(UID_SAME),
        user_name: Set("it_role_xtenant_user".to_string()),
        nick_name: Set("IT-ROLE-XTENANT".to_string()),
        tenant_id: Set(TID),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入租户用户失败");

    // 合成租户令牌：主体仍是超管（穿过 RBAC），Operator::tenant_id() = 5
    let (token, _claims) = JwtUtils::generate_token("1", "admin", &ctx.state.config.jwt, 0, TID)
        .expect("签发合成租户令牌失败");
    let put = |uri: &str, body: serde_json::Value| {
        let mut req = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("构造请求失败");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
        req
    };

    // ① 正控：同租角色 + 同租用户 ⇒ 授权成功，且随后可取消
    let v = ctx
        .send_json(put(
            &format!(
                "/system/role/authUser/selectAll?roleId={}&userIds={}",
                ROLE_SAME, UID_SAME
            ),
            serde_json::json!({}),
        ))
        .await;
    assert_eq!(v["code"], 200, "同租授权应成功，实际: {v}");
    let bound = crate::entity::sys_user_role::Entity::find()
        .filter(crate::entity::sys_user_role::Column::UserId.eq(UID_SAME))
        .filter(crate::entity::sys_user_role::Column::RoleId.eq(ROLE_SAME))
        .one(db)
        .await
        .unwrap();
    assert!(bound.is_some(), "正控：同租授权必须真的落库");

    // ② 三条路径 × 平台角色 / 他租角色：一律 403，且不得留下 sys_user_role 行
    for role_id in [ROLE_PLATFORM, ROLE_OTHER] {
        for (label, uri, body) in [
            (
                "selectAll",
                format!(
                    "/system/role/authUser/selectAll?roleId={}&userIds={}",
                    role_id, UID_SAME
                ),
                serde_json::json!({}),
            ),
            (
                "cancelAll",
                format!(
                    "/system/role/authUser/cancelAll?roleId={}&userIds={}",
                    role_id, UID_SAME
                ),
                serde_json::json!({}),
            ),
            (
                "cancel",
                "/system/role/authUser/cancel".to_string(),
                serde_json::json!({ "roleId": role_id, "userId": UID_SAME }),
            ),
        ] {
            let (status, v) = ctx.send_raw(put(&uri, body)).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{label} 用跨租角色 {role_id} 必须 403，实际: {status} {v}"
            );
            let leaked = crate::entity::sys_user_role::Entity::find()
                .filter(crate::entity::sys_user_role::Column::UserId.eq(UID_SAME))
                .filter(crate::entity::sys_user_role::Column::RoleId.eq(role_id))
                .one(db)
                .await
                .unwrap();
            assert!(
                leaked.is_none(),
                "{label} 被拒后不得留下 user_id={UID_SAME} role_id={role_id} 的绑定"
            );
        }
    }

    // ③ 同租角色仍可取消（证明拒绝面只在"角色跨租"，不是把功能整体关掉）
    let v = ctx
        .send_json(put(
            "/system/role/authUser/cancel",
            serde_json::json!({ "roleId": ROLE_SAME, "userId": UID_SAME }),
        ))
        .await;
    assert_eq!(v["code"], 200, "同租取消应成功，实际: {v}");

    // ④ 读面同样有租户边界：角色详情与角色菜单树不得用猜到的 role_id 读他租角色。
    //    （写面关了而读面开着，等于把"授权集合"送出去。）
    let get = |uri: &str| {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .expect("构造 GET 请求失败");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
        req
    };
    let (status, v) = ctx
        .send_raw(get(&format!(
            "/system/menu/roleMenuTreeselect/{}",
            ROLE_SAME
        )))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "同租角色的菜单树必须可读（角色授权页依赖它），实际 {status} {v}"
    );
    assert!(
        v["menus"].as_array().is_some_and(|menus| !menus.is_empty()),
        "菜单树不得为空（空树会让保存时把角色授权清掉）: {v}"
    );
    for role_id in [ROLE_PLATFORM, ROLE_OTHER] {
        for uri in [
            format!("/system/menu/roleMenuTreeselect/{role_id}"),
            format!("/system/role/{role_id}"),
        ] {
            let (status, v) = ctx.send_raw(get(&uri)).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "跨租角色读面必须 403（role_id={role_id}，{uri}），实际 {status} {v}"
            );
        }
    }
}

/// b131：角色批量删除的重复 id，与「批量授权」里重复的 userIds。
///
/// 两个形状都是**合法幂等入参**，修复前各自失败：
/// - `DELETE /system/role/9,9` ⇒ 事务内第二轮读到刚软删的行 ⇒ 整批 404 + 零删除；
/// - `PUT /system/role/authUser/selectAll?userIds=5,5` ⇒ 两个相同 ActiveModel 进
///   `insert_many` ⇒ 撞 `UNIQUE(user_id, role_id)` ⇒ 400「数据重复」。
///
/// 判据各配对照组：删除用"单 id 照常 200"，授权用"再调一次仍 200 且只绑一行"。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_role_batch_and_auth_user_dedupe_repeated_ids() {
    let ctx = TestContext::new().await;

    // ===== ① 批量删除：重复 id 必须 200 且真的删掉 =====
    let v = ctx
        .post_json(
            "/system/role",
            serde_json::json!({
                "roleName": "重复id删除角色",
                "roleKey": "it_role_dup",
                "roleSort": 95,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json("/system/role/list?roleKey=it_role_dup").await;
    let dup_role_id = v["rows"][0]["roleId"].as_i64().expect("应查到新角色");

    let v = ctx
        .delete_json(&format!("/system/role/{dup_role_id},{dup_role_id}"))
        .await;
    ctx.assert_ok(&v);
    let v = ctx.get_json("/system/role/list?roleKey=it_role_dup").await;
    assert!(
        v["rows"].as_array().map(|a| a.is_empty()).unwrap_or(false),
        "重复 id 的批量删除必须真的删掉，实际: {v}"
    );

    // 审计：恰一行 DELETE，且操作人可归因（b131 补的署名）
    let v = ctx
        .get_json(&format!(
            "/system/audit-change/list?tableName=sys_role&rowPk={dup_role_id}&action=DELETE"
        ))
        .await;
    assert_eq!(
        v["total"].as_u64(),
        Some(1),
        "重复 id 只应留一条 DELETE 审计，实际: {v}"
    );
    assert_eq!(
        v["rows"][0]["operatorName"].as_str(),
        Some("admin"),
        "角色删除留痕必须能归因到操作人（修复前为空），实际: {v}"
    );

    // ===== ② 批量授权：重复 userId 只绑一行 =====
    let v = ctx
        .post_json(
            "/system/role",
            serde_json::json!({
                "roleName": "批量授权去重角色",
                "roleKey": "it_role_selall",
                "roleSort": 94,
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/role/list?roleKey=it_role_selall")
        .await;
    let sel_role_id = v["rows"][0]["roleId"].as_i64().expect("应查到授权角色");

    let v = ctx
        .post_json(
            "/system/user",
            serde_json::json!({
                "deptId": 103,
                "userName": "it_selall_user",
                "nickName": "批量授权去重用户",
                "email": "stepby@tzkj.net",
                "phonenumber": "13800004444",
                "password": "Stepby@12345",
                "status": "0"
            }),
        )
        .await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json("/system/user/list?userName=it_selall_user")
        .await;
    let user_id = v["rows"][0]["userId"].as_i64().expect("应查到授权用户");

    let uri =
        format!("/system/role/authUser/selectAll?roleId={sel_role_id}&userIds={user_id},{user_id}");
    let v = ctx.send_json(ctx_request_put(&ctx, &uri, None)).await;
    ctx.assert_ok(&v);

    // 已授权列表：该用户恰出现一次（重复 id 不得插两行）
    let v = ctx
        .get_json(&format!(
            "/system/role/authUser/allocatedList?roleId={sel_role_id}"
        ))
        .await;
    let occurrences = v["rows"]
        .as_array()
        .map(|rows| rows.iter().filter(|r| r["userId"] == user_id).count())
        .unwrap_or(0);
    assert_eq!(
        occurrences, 1,
        "重复 userId 只应绑定一行，实际 {occurrences} 行: {v}"
    );

    // 对照组：同一请求再打一次仍 200（幂等），且仍只绑一行
    let v = ctx.send_json(ctx_request_put(&ctx, &uri, None)).await;
    ctx.assert_ok(&v);
    let v = ctx
        .get_json(&format!(
            "/system/role/authUser/allocatedList?roleId={sel_role_id}"
        ))
        .await;
    let occurrences = v["rows"]
        .as_array()
        .map(|rows| rows.iter().filter(|r| r["userId"] == user_id).count())
        .unwrap_or(0);
    assert_eq!(
        occurrences, 1,
        "重复调用后仍应只绑定一行（幂等），实际 {occurrences} 行: {v}"
    );
}

/// 构造带鉴权头 + ConnectInfo 的 PUT 请求（本文件的授权链用例需要 PUT 空体 + Query 参数）。
fn ctx_request_put(
    ctx: &TestContext,
    uri: &str,
    body: Option<serde_json::Value>,
) -> axum::http::Request<axum::body::Body> {
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::Request;
    use std::net::SocketAddr;
    let builder = Request::builder()
        .method(Method::PUT)
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
