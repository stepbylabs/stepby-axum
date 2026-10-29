// stepby-axum/src/integration_tests/scim_groups.rs
//! v5-D12 Group：SCIM 2.0 Group 资源端到端链路（组→角色集合 / 组→兼职部门）。
//!
//! 覆盖：鉴权 401 → POST 建组（201 + 成员）→ role 组绑定联动授权
//! （sys_user_role source='scim:{gid}'）→ PUT members 全量 diff 幂等（重放
//! 零副作用）→ PATCH remove members 撤销（admin 手授不动）→ GET list filter →
//! mapping_type 变更前置（有绑定 400）→ DELETE 组只撤 scim 来源授权 →
//! 用户 deprovision 清成员记录。

use super::TestContext;
use axum::body::Body;
use axum::body::to_bytes;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
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
    // 同 scim.rs：SCIM 档位与 Bearer 由 harness 统一给定，禁止进程级 `set_var`（AGENTS 开关规范⑧）。
    TestContext::new().await
}

fn json_of(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap_or(serde_json::Value::Null)
}

async fn raw_request(
    app: &axum::Router,
    peer_ip: IpAddr,
    method: Method,
    uri: &str,
    body: Option<&str>,
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
        .body(Body::from(body.unwrap_or_default().to_string()))
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
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    raw_request(app, peer_ip, Method::POST, uri, Some(body), headers).await
}

async fn raw_put(
    app: &axum::Router,
    peer_ip: IpAddr,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    raw_request(app, peer_ip, Method::PUT, uri, Some(body), headers).await
}

async fn raw_patch(
    app: &axum::Router,
    peer_ip: IpAddr,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    raw_request(app, peer_ip, Method::PATCH, uri, Some(body), headers).await
}

async fn raw_delete(
    app: &axum::Router,
    peer_ip: IpAddr,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    raw_request(app, peer_ip, Method::DELETE, uri, None, headers).await
}

/// helper：直接经 service 建一个 SCIM 组（带成员），绕过 HTTP（供绑定联动测试用）
async fn create_group_via_api(ctx: &TestContext, display_name: &str, member_ids: &[i64]) -> i64 {
    let members: Vec<serde_json::Value> = member_ids
        .iter()
        .map(|id| serde_json::json!({ "value": id.to_string() }))
        .collect();
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": display_name,
        "members": members,
    });
    let (status, _, resp) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Groups",
        &body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "建组应 201: {}",
        String::from_utf8_lossy(&resp)
    );
    let j = json_of(&resp);
    j["id"]
        .as_str()
        .unwrap_or_default()
        .parse::<i64>()
        .expect("组 id 应为数字")
}

/// helper：经管理端 API 替换组绑定（PUT /system/scimGroup/{id}，管理员 JWT）
async fn admin_put_bindings(ctx: &TestContext, group_id: i64, targets: &[i64]) -> StatusCode {
    // 管理端鉴权：复用 TestContext 的 admin token（见 mod.rs 登录 helper）
    let token = ctx.token.clone();
    let body = serde_json::json!({ "bindingTargetIds": targets });
    let (status, _, _) = raw_put(
        &ctx.app,
        ctx.peer_ip,
        &format!("/system/scimGroup/{group_id}"),
        &body.to_string(),
        &[("authorization", &format!("Bearer {token}"))],
    )
    .await;
    status
}

/// helper：直查 sys_user_role 中某用户指定来源的角色集合
async fn user_role_ids_with_source(
    db: &sea_orm::DatabaseConnection,
    user_id: i64,
    source: &str,
) -> Vec<i64> {
    use crate::entity::sys_user_role::{Column as URC, Entity as UserRole};
    UserRole::find()
        .filter(URC::UserId.eq(user_id))
        .filter(URC::Source.eq(source))
        .all(db)
        .await
        .expect("查询 sys_user_role 失败")
        .into_iter()
        .map(|m| m.role_id)
        .collect()
}

/// SCIM Group 全链路：鉴权 → 建组 → 绑定联动 → diff 幂等 → 撤销语义 → 删除
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_groups_crud_and_binding_sync() {
    let ctx = scim_ctx().await;
    let db = ctx.state.db.clone();

    // ① 无凭据 → 401
    let (status, _, _) = raw_get(&ctx.app, ctx.peer_ip, "/scim/v2/Groups", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "无凭据应 401");

    // ② 先 provision 两个用户（成员）
    async fn provision(ctx: &TestContext, name: &str) -> i64 {
        let body = serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": name,
            "name": {"displayName": name},
        });
        let (status, _, resp) = raw_post(
            &ctx.app,
            ctx.peer_ip,
            "/scim/v2/Users",
            &body.to_string(),
            &scim_headers(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "provision 应 201: {}",
            String::from_utf8_lossy(&resp)
        );
        json_of(&resp)["id"]
            .as_str()
            .unwrap_or_default()
            .parse::<i64>()
            .expect("用户 id")
    }
    let uid1 = provision(&ctx, "scim.grp.u1").await;
    let uid2 = provision(&ctx, "scim.grp.u2").await;

    // ③ POST 建组（带 1 成员）→ 201 + members 回显
    let gid = create_group_via_api(&ctx, "研发组", &[uid1]).await;
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Groups/{gid}"),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let g = json_of(&body);
    assert_eq!(g["displayName"], "研发组");
    assert_eq!(g["meta"]["resourceType"], "Group");
    assert_eq!(g["members"].as_array().map(|a| a.len()), Some(1));

    // ④ 管理端绑定角色（role 组）：绑定一个存量角色 → 成员联动获得授权
    //    取测试库任一角色（初始库有 role_id=1/2）
    let role_id: i64 = 2;
    let status = admin_put_bindings(&ctx, gid, &[role_id]).await;
    assert!(status.is_success(), "绑定应成功: {status}");
    let scim_src = format!("scim:{gid}");
    let granted = user_role_ids_with_source(&db, uid1, &scim_src).await;
    assert_eq!(granted, vec![role_id], "成员应获得组绑定角色（scim 来源）");
    // admin 来源无该行（联动只写 scim 行）
    let admin_rows = user_role_ids_with_source(&db, uid1, "admin").await;
    assert!(!admin_rows.contains(&role_id), "联动不应写 admin 行");

    // ⑤ PUT members 全量 diff：加入 uid2 → uid2 获授权；重放同列表零副作用
    let put_body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "研发组",
        "members": [
            {"value": uid1.to_string()},
            {"value": uid2.to_string()}
        ],
    });
    let (status, _, _) = raw_put(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Groups/{gid}"),
        &put_body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT 应 200");
    let granted2 = user_role_ids_with_source(&db, uid2, &scim_src).await;
    assert_eq!(granted2, vec![role_id], "新成员应自动获得授权");
    // 重放幂等
    let (status, _, _) = raw_put(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Groups/{gid}"),
        &put_body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "重放 PUT 应 200（幂等）");
    let granted1_again = user_role_ids_with_source(&db, uid1, &scim_src).await;
    assert_eq!(granted1_again, vec![role_id], "重放后 uid1 授权不变");

    // ⑥ 管理员手授同角色（走生产 upsert_admin_grants_conn：scim 行抢占为 admin 行）
    //    → PATCH remove uid1 → 只撤 scim 行（已无），admin 行保留
    let ur_repo = crate::repository::sys_user_role::SysUserRoleRepository::new(db.clone());
    ur_repo
        .upsert_admin_grants_conn(&db, uid1, vec![role_id])
        .await
        .expect("手授 upsert 失败");
    // 抢占语义断言：uid1 的 scim 行被改写为 admin 行
    let scim_after_preempt = user_role_ids_with_source(&db, uid1, &scim_src).await;
    assert!(
        scim_after_preempt.is_empty(),
        "admin 手授应抢占 scim 行（source 改写为 admin）"
    );
    let admin_preempted = user_role_ids_with_source(&db, uid1, "admin").await;
    assert_eq!(
        admin_preempted,
        vec![role_id],
        "抢占后该角色归属 admin 来源"
    );
    let patch_body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "remove", "path": "members", "value": [{"value": uid1.to_string()}]}
        ]
    });
    let (status, _, _) = raw_patch(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Groups/{gid}"),
        &patch_body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PATCH remove 应 200");
    let after = user_role_ids_with_source(&db, uid1, &scim_src).await;
    assert!(after.is_empty(), "移出组后无本组 scim 行可撤");
    let admin_kept = user_role_ids_with_source(&db, uid1, "admin").await;
    assert_eq!(
        admin_kept,
        vec![role_id],
        "管理员手授行（admin 来源）不受组撤销影响"
    );

    // ⑥b 把 uid1 加回组 → scim 授权遇 admin 已持有行不覆盖（幂等，不产生重复行）
    let patch_add_body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "add", "path": "members", "value": [{"value": uid1.to_string()}]}
        ]
    });
    let (status, _, _) = raw_patch(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Groups/{gid}"),
        &patch_add_body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PATCH add 回组应 200");
    let scim_readded = user_role_ids_with_source(&db, uid1, &scim_src).await;
    assert!(
        scim_readded.is_empty(),
        "admin 已持有的角色不应再插 scim 行（目标行已存在不覆盖）"
    );
    let admin_still = user_role_ids_with_source(&db, uid1, "admin").await;
    assert_eq!(admin_still, vec![role_id], "回组后 admin 行不受影响");

    // ⑦ list + displayName eq filter
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Groups?filter=displayName%20eq%20%22%E7%A0%94%E5%8F%91%E7%BB%84%22",
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let lr = json_of(&body);
    assert_eq!(
        lr["totalResults"],
        serde_json::json!(1),
        "filter 应命中 1 条"
    );

    // ⑧ DELETE 组 → 撤仅 scim 来源授权（uid2 的行删除），admin 行保留；组软删
    let (status, _, _) = raw_delete(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Groups/{gid}"),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "DELETE 应 204");
    let left2 = user_role_ids_with_source(&db, uid2, &scim_src).await;
    assert!(left2.is_empty(), "删组应撤销全部本组授权");
    // uid1 的角色已在 ⑥ 被抢占为 admin 来源——删组不误删
    let left1_admin = user_role_ids_with_source(&db, uid1, "admin").await;
    assert_eq!(
        left1_admin,
        vec![role_id],
        "删组不误删被抢占为 admin 来源的角色"
    );
    // 软删后 GET → 404
    let (status, _, _) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Groups/{gid}"),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "软删后 GET 应 404");
}

/// 用户 deprovision 联动：清组成员记录 + 撤 scim 来源授权
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_group_membership_cleanup_on_deprovision() {
    let ctx = scim_ctx().await;
    let db = ctx.state.db.clone();

    // provision 用户 + 建组 + 绑定角色（成员获得授权）
    let ubody = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "scim.cleanup.u1",
        "name": {"displayName": "清理用"},
    });
    let (status, _, resp) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users",
        &ubody.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let uid: i64 = json_of(&resp)["id"]
        .as_str()
        .unwrap_or_default()
        .parse()
        .expect("用户 id");

    let gid = create_group_via_api(&ctx, "清理组", &[uid]).await;
    let role_id: i64 = 2;
    let status = admin_put_bindings(&ctx, gid, &[role_id]).await;
    assert!(status.is_success(), "绑定应成功");
    let scim_src = format!("scim:{gid}");
    assert_eq!(
        user_role_ids_with_source(&db, uid, &scim_src).await,
        vec![role_id]
    );

    // deprovision（DELETE /Users/{id}）→ 成员记录清空 + scim 授权撤销
    let (status, _, _) = raw_delete(
        &ctx.app,
        ctx.peer_ip,
        &format!("/scim/v2/Users/{uid}"),
        &scim_headers(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "deprovision 应 204");

    use crate::entity::sys_scim_group_member::{Column as MC, Entity as Member};
    let member_left = Member::find()
        .filter(MC::GroupId.eq(gid))
        .filter(MC::UserId.eq(uid))
        .one(&db)
        .await
        .expect("查成员失败");
    assert!(member_left.is_none(), "deprovision 应清理组成员记录");
    let grants_left = user_role_ids_with_source(&db, uid, &scim_src).await;
    assert!(grants_left.is_empty(), "deprovision 应撤销 scim 来源授权");
}

/// 成员存在性**批查**的负路径（b71 `parse_member_ids` N+1 改造回归锁）。
///
/// 该改造把"逐个 `find_by_id` 点查"换成"一次 `is_in` 批查 + 集合判定"，必须仍然：
/// ① 拒绝不存在成员并 400；② 按**入参顺序**报告首个缺失者（detail 含具体 id）；
/// ③ 合法在前、缺失在后时整体拒绝且报的是缺失者（防"命中即放行"的实现漂移）；
/// ④ 全合法时成功（证明前两轮不是批查实现把一切判为缺失）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_group_members_reject_unknown_users_in_input_order() {
    let ctx = scim_ctx().await;

    // 先真实 provision 一个可用成员（作为"合法在前"的那个）
    let user_body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "scim.grp.neg.ok",
        "name": { "displayName": "负路径可用成员" },
    });
    let (status, _, resp) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users",
        &user_body.to_string(),
        &scim_headers(),
    )
    .await;
    assert!(
        status.is_success(),
        "provision 应成功: {status} {}",
        String::from_utf8_lossy(&resp)
    );
    let uid = json_of(&resp)["id"]
        .as_str()
        .unwrap_or_default()
        .parse::<i64>()
        .expect("用户 id");

    // ① 全部为不存在成员 → 报告**首个**缺失 id
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "负路径组A",
        "members": [{ "value": "990001" }, { "value": "990002" }],
    });
    let (status, _, resp) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Groups",
        &body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "不存在成员建组应 400: {}",
        String::from_utf8_lossy(&resp)
    );
    let detail = json_of(&resp)["detail"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        detail.contains("990001"),
        "应报告首个缺失成员 id，实际 detail={detail}"
    );

    // ② 合法在前、缺失在后 → 仍整体拒绝，且报缺失者
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "负路径组B",
        "members": [{ "value": uid.to_string() }, { "value": "990003" }],
    });
    let (status, _, resp) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Groups",
        &body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "混合成员含缺失者应整体拒绝: {}",
        String::from_utf8_lossy(&resp)
    );
    let detail = json_of(&resp)["detail"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        detail.contains("990003"),
        "应报告缺失成员 id 而非合法者，实际 detail={detail}"
    );

    // ③ 全合法 → 201
    let gid = create_group_via_api(&ctx, "负路径组C", &[uid]).await;
    assert!(gid > 0, "合法成员建组应返回有效 gid");
}

/// helper：经 SCIM API provision 一个用户并返回 user_id（管理端计数测试用）
async fn provision_user_via_api(ctx: &TestContext, name: &str) -> i64 {
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": name,
        "name": {"displayName": name},
    });
    let (status, _, resp) = raw_post(
        &ctx.app,
        ctx.peer_ip,
        "/scim/v2/Users",
        &body.to_string(),
        &scim_headers(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "provision 应 201: {}",
        String::from_utf8_lossy(&resp)
    );
    json_of(&resp)["id"]
        .as_str()
        .unwrap_or_default()
        .parse::<i64>()
        .expect("用户 id")
}

/// helper：管理端组列表（管理员 JWT），返回原始响应体
async fn admin_list_groups(ctx: &TestContext, query: &str) -> serde_json::Value {
    let token = ctx.token.clone();
    let (status, _, body) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &format!("/system/scimGroup/list?{query}"),
        &[("authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "管理端列表应 200: {}",
        String::from_utf8_lossy(&body)
    );
    json_of(&body)
}

/// b127：管理端列表的成员/绑定计数必须来自一次聚合，且零计数要显示 0 而不是缺省。
///
/// 旧实现每行 2 条 COUNT（100 行 = 200 次往返）；批量化后最容易改坏的是
/// "GROUP BY 不返回零行分组" —— 那会让没有成员/绑定的组在页面上显示空白而不是 0。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_group_admin_list_counts_are_correct_for_every_group() {
    let ctx = scim_ctx().await;
    let uid1 = provision_user_via_api(&ctx, "scim.count.u1").await;
    let uid2 = provision_user_via_api(&ctx, "scim.count.u2").await;

    // 有 2 成员 + 1 条绑定
    let with_data = create_group_via_api(&ctx, "计数组-有数据", &[uid1, uid2]).await;
    let status = admin_put_bindings(&ctx, with_data, &[2]).await;
    assert!(status.is_success(), "绑定应成功: {status}");
    // 全空组：计数必须显式是 0
    let empty = create_group_via_api(&ctx, "计数组-全空", &[]).await;

    let body = admin_list_groups(&ctx, "pageNum=1&pageSize=100").await;
    assert_eq!(body["code"], 200, "业务码应为 200: {body}");
    let rows = body["rows"].as_array().expect("rows 应为数组");
    let find = |gid: i64| {
        rows.iter()
            .find(|r| r["groupId"].as_i64() == Some(gid))
            .unwrap_or_else(|| panic!("列表应包含组 {gid}: {body}"))
            .clone()
    };
    let a = find(with_data);
    assert_eq!(a["memberCount"].as_u64(), Some(2), "成员计数: {a}");
    assert_eq!(a["bindingCount"].as_u64(), Some(1), "绑定计数: {a}");
    let b = find(empty);
    assert_eq!(b["memberCount"].as_u64(), Some(0), "零成员必须显示 0: {b}");
    assert_eq!(b["bindingCount"].as_u64(), Some(0), "零绑定必须显示 0: {b}");

    // 计数与详情同源：详情里的成员数/绑定数必须与列表一致（两处各算一遍就会漂）
    let token = ctx.token.clone();
    let (status, _, detail) = raw_get(
        &ctx.app,
        ctx.peer_ip,
        &format!("/system/scimGroup/{with_data}"),
        &[("authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let d = json_of(&detail)["data"].clone();
    assert_eq!(d["members"].as_array().map(|x| x.len()), Some(2));
    assert_eq!(d["bindingTargetIds"].as_array().map(|x| x.len()), Some(1));
}

/// b127：管理端批量删除必须**要么全删、要么一条不删**，且缺失 id 要点名。
///
/// 旧实现逐条删、首错即中断：`DELETE {g1},{g2},<不存在>` 会先把 g1/g2 真删掉，
/// 再因为第三个不存在而回 404 —— 使用者看到"失败"，而数据已经部分消失，
/// 响应里也看不出哪几个已被删。这里用"名单里混一个不存在的 id"构造该形状。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scim_group_batch_delete_is_atomic_and_names_missing_ids() {
    use crate::entity::sys_scim_group::{Entity as ScimGroup, Model as GroupModel};
    use sea_orm::EntityTrait;

    let ctx = scim_ctx().await;
    let db = ctx.state.db.clone();
    let del_flag_of = |gid: i64| {
        let db = db.clone();
        async move {
            ScimGroup::find_by_id(gid)
                .one(&db)
                .await
                .expect("查询组失败")
                .map(|m: GroupModel| m.del_flag)
                .expect("组行应保留（软删不物理删）")
        }
    };
    let g1 = create_group_via_api(&ctx, "批量组1", &[]).await;
    let g2 = create_group_via_api(&ctx, "批量组2", &[]).await;
    let missing: i64 = 9_999_999_999;
    let bearer = format!("Bearer {}", ctx.token);
    let auth: [(&str, &str); 1] = [("authorization", bearer.as_str())];

    // ① 混入不存在的 id ⇒ 整批拒绝，且前两个一条都不许少
    let uri = format!("/system/scimGroup/{g1},{g2},{missing}");
    let (status, _, body) = raw_delete(&ctx.app, ctx.peer_ip, &uri, &auth).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "含缺失 id 的整批必须拒绝: {}",
        String::from_utf8_lossy(&body)
    );
    let msg = json_of(&body)["msg"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        msg.contains(&missing.to_string()),
        "错误文案必须点名缺失 id（否则使用者只能逐个试）: {msg}"
    );
    for gid in [g1, g2] {
        assert_ne!(
            del_flag_of(gid).await.as_deref(),
            Some("2"),
            "整批被拒时组 {gid} 不得被软删（旧实现此时已把它真删掉）"
        );
    }

    // ② 对照组：同一批去掉缺失 id ⇒ 必须真的全删（证明闸不是"永远拒绝"）
    let uri = format!("/system/scimGroup/{g1},{g2}");
    let (status, _, body) = raw_delete(&ctx.app, ctx.peer_ip, &uri, &auth).await;
    assert!(
        status.is_success(),
        "合法批次应成功: {status} {}",
        String::from_utf8_lossy(&body)
    );
    for gid in [g1, g2] {
        assert_eq!(
            del_flag_of(gid).await.as_deref(),
            Some("2"),
            "组 {gid} 应已软删"
        );
    }

    // ③ 重复 id 只拆一次（去重后仍成功，且不因二次拆除报错）
    let g3 = create_group_via_api(&ctx, "批量组3", &[]).await;
    let uri = format!("/system/scimGroup/{g3},{g3}");
    let (status, _, body) = raw_delete(&ctx.app, ctx.peer_ip, &uri, &auth).await;
    assert!(
        status.is_success(),
        "重复 id 批次应成功: {status} {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        del_flag_of(g3).await.as_deref(),
        Some("2"),
        "组 {g3} 应已软删"
    );
}
