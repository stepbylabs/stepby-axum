// stepby-axum/src/integration_tests/platform_guard.rs
//! P1-1 平台专属接口请求层守卫（`/monitor/cache/*`、`/tool/gen/*`）集成测试。
//!
//! 复用全局 `TestContext` harness（隔离 sqlite + 独占 Redis DB + 真实 `build_app` 路由栈）：
//! - (a) 平台操作者（真实登录 admin，`tid=0`）→ 端点 200（**同时证明层序**：守卫内层读到的
//!   `Claims` 由外层 `auth_middleware` 注入，若层序反转则扩展缺失 → fail-closed 403）；
//! - (b) 租户操作者（`tid=5`）→ 端点 403。
//!
//! 合成租户令牌方式：`JwtUtils::generate_token(sub="1", "admin", cfg, pwd_ver=0, tid=5)`——
//! 复用超管主体（`*:*:*`，超管短路）以**通过 RBAC 权限层**，从而把 403 精确归因到本守卫
//! 而非 permission_middleware；`auth_middleware` 对 `tid=5` 查不到 `tenant:state:5` /
//! `tenant:exp:5` → 求值为 Active，正常放行至守卫层。
//! `Operator::tenant_id()` 即 `Claims.tid`（见 `middleware/auth.rs`），故守卫按 `Claims.tid`
//! 判定与按 `Operator` 判定等价。

use std::net::SocketAddr;

use super::TestContext;
use crate::jwt::JwtUtils;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};

/// 平台专属端点（harness 可端到端覆盖的最小 DB/Redis 只读端点）
///
/// `/system/menu/list` 是 b95 新纳入平台面的全局定义（`sys_menu` 无 tenant_id），
/// 与缓存/代码生成同一层守卫。**只读菜单树不在清单里**：角色授权页要用它，
/// 服务层按租户过滤可授予面（`it_tenant_menu_tree_is_scoped_not_blocked` 钉住）。
const PLATFORM_ONLY_ENDPOINTS: [&str; 3] = [
    "/monitor/cache",
    "/tool/gen/list?pageNum=1&pageSize=10",
    "/system/menu/list",
];

/// 用当前测试进程的 JWT 配置签发一份指定 `tid` 的合成令牌。
fn token_with_tid(ctx: &TestContext, tid: i64) -> String {
    let (token, _claims) = JwtUtils::generate_token("1", "admin", &ctx.state.config.jwt, 0, tid)
        .expect("签发合成租户令牌失败");
    token
}

/// 构造带指定 Bearer 令牌 + ConnectInfo 的 GET 请求（与 `TestContext::request` 同构）。
fn auth_get(ctx: &TestContext, token: &str, uri: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

/// (a) 平台操作者（tid=0）→ 平台专属端点 200。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_platform_operator_allowed_on_platform_only_endpoints() {
    let ctx = TestContext::new().await;
    for uri in PLATFORM_ONLY_ENDPOINTS {
        // ctx.get_json 断言 HTTP 200 且业务码 200（失败会 panic 并打印响应体）
        let v = ctx.get_json(uri).await;
        ctx.assert_ok(&v);
    }
}

/// (b) 租户操作者（tid != 0）→ 平台专属端点 403（不依赖 perms 的第二道防线）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_tenant_operator_forbidden_on_platform_only_endpoints() {
    let ctx = TestContext::new().await;
    let tenant_token = token_with_tid(&ctx, 5);

    // 前置校验：同一合成令牌访问非平台专属的普通受保护端点应通过鉴权与权限层
    // （证明 403 来自本守卫，而非 401 鉴权失败或权限层拒绝）。
    let (status, _v) = ctx
        .send_raw(auth_get(&ctx, &tenant_token, "/getInfo"))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "前置校验失败：合成租户令牌应能通过鉴权/权限层访问 /getInfo，实际 {status}"
    );

    for uri in PLATFORM_ONLY_ENDPOINTS {
        let (status, v) = ctx.send_raw(auth_get(&ctx, &tenant_token, uri)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "租户操作者访问 {uri} 应 403，实际 {status} {v}"
        );
        assert_eq!(
            v["code"], 403,
            "租户操作者访问 {uri} 业务码应 403，实际 {v}"
        );
    }
}

/// 展示层也必须与请求层同口径：租户的 getRouters 不得再出现菜单管理。
///
/// 否则会留下"菜单可见但请求必 403"的假入口（AGENTS 开关规范③/④）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_tenant_router_tree_prunes_menu_management() {
    let ctx = TestContext::new().await;
    let tenant_token = token_with_tid(&ctx, 5);
    let (status, v) = ctx
        .send_raw(auth_get(&ctx, &tenant_token, "/getRouters"))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "租户 getRouters 应 200，实际 {status} {v}"
    );

    fn collect_paths(nodes: &[serde_json::Value], out: &mut Vec<String>) {
        for node in nodes {
            if let Some(path) = node["path"].as_str() {
                out.push(path.to_string());
            }
            if let Some(children) = node["children"].as_array() {
                collect_paths(children, out);
            }
        }
    }
    let mut paths = Vec::new();
    collect_paths(v["data"].as_array().expect("data 应为数组"), &mut paths);
    assert!(
        !paths.iter().any(|p| p == "/system/menu" || p == "menu"),
        "租户 getRouters 不得含菜单管理（平台专属），实际路径: {paths:?}"
    );
}

/// 只读菜单树对租户**放行但要收窄**（b95）。
///
/// 角色授权页必须能读菜单树，所以这两个端点不能挂平台守卫；但保存前的门禁会拒绝
/// 平台专属 perms，因此树里也必须先不出现它们——否则就是"勾得上、存不下"的假入口。
/// 目录因子节点全被剪而变空时一并移除（菜单管理 / 缓存监控 的父目录可能随之为空）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_tenant_menu_tree_is_scoped_not_blocked() {
    const MENU_ROLE: i64 = 101; // system:role:list —— 租户可授予
    const MENU_ADMIN: i64 = 102; // system:menu:list —— b95 起平台专属
    const MENU_CACHE: i64 = 113; // monitor:cache:list —— 平台专属

    let ctx = TestContext::new().await;
    let tenant_token = token_with_tid(&ctx, 5);
    let (status, v) = ctx
        .send_raw(auth_get(&ctx, &tenant_token, "/system/menu/treeselect"))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "租户读角色授权用菜单树必须放行（403 会让角色页把授权清空），实际 {status} {v}"
    );

    fn collect_ids(nodes: &[serde_json::Value], out: &mut Vec<i64>) {
        for node in nodes {
            if let Some(id) = node["id"].as_i64() {
                out.push(id);
            }
            if let Some(children) = node["children"].as_array() {
                collect_ids(children, out);
            }
        }
    }
    let mut ids = Vec::new();
    collect_ids(v["data"].as_array().expect("data 应为数组"), &mut ids);
    assert!(
        ids.contains(&MENU_ROLE),
        "可授予的角色菜单必须在租户树里，实际: {ids:?}"
    );
    assert!(
        !ids.contains(&MENU_ADMIN),
        "菜单管理（系统:menu:*）是平台专属，不得出现在租户可勾选树里: {ids:?}"
    );
    assert!(
        !ids.contains(&MENU_CACHE),
        "缓存监控是平台专属，不得出现在租户可勾选树里: {ids:?}"
    );
}

/// 租户角色授权树必须与保存侧**同一把尺**：套餐白名单外的菜单不得出现在树里。
///
/// b95 遗留边界：树只按可授予性过滤，未按套餐白名单裁剪 ⇒ 租户管理员能看到并勾选
/// "可授予但不在套餐内"的菜单，保存时才 400（一次性交互失败，且理由不在页面上）。
/// 本用例把读侧（treeselect）与写侧（POST /system/role 的 `ensure_menus_in_package`）
/// 放在同一个夹具里对账：
/// - 读侧：树含白名单内的 `system:role:list` 及其祖先目录，不含白名单外的 `system:user:list`；
/// - 写侧：勾白名单外菜单 ⇒ 403（`ensure_menus_in_package`）；勾白名单内菜单 ⇒ 200。
///
/// 可证伪：若 `get_menu_tree_select_scoped` 忽略白名单，第一条断言会把 outside_id 读进来；
/// 若保存侧校验被摘掉，第二条的 400 会变成 200。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_role_assign_tree_respects_package_whitelist() {
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

    const TID: i64 = 9061;
    const PACKAGE_ID: i64 = 9261;
    const ROLE_KEY_IN: &str = "it_pkg_whitelist_in";
    const ROLE_KEY_OUT: &str = "it_pkg_whitelist_out";

    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    async fn menu_id_by_perms(db: &sea_orm::DatabaseConnection, perms: &str) -> i64 {
        crate::entity::sys_menu::Entity::find()
            .filter(crate::entity::sys_menu::Column::Perms.eq(perms))
            .filter(crate::entity::sys_menu::Column::DelFlag.eq("0"))
            .one(db)
            .await
            .expect("查询菜单失败")
            .unwrap_or_else(|| panic!("种子应含 perms = {perms} 的菜单"))
            .menu_id
    }
    let inside_id = menu_id_by_perms(db, "system:role:list").await;
    let outside_id = menu_id_by_perms(db, "system:user:list").await;

    // 白名单 = 目标菜单 + 其全部祖先（目录不在白名单里会让整棵子树被剪掉，夹具必须自洽）
    let mut allow = Vec::new();
    let mut cursor = Some(inside_id);
    while let Some(id) = cursor {
        allow.push(id);
        cursor = crate::entity::sys_menu::Entity::find_by_id(id)
            .one(db)
            .await
            .expect("查询祖先菜单失败")
            .and_then(|m| m.parent_id)
            .filter(|p| *p != 0);
    }
    allow.sort_unstable();
    allow.dedup();
    let menu_ids: String = allow
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");

    crate::entity::sys_tenant_package::ActiveModel {
        package_id: Set(PACKAGE_ID),
        package_name: Set(format!("IT-PKG-{PACKAGE_ID}")),
        menu_ids: Set(Some(menu_ids)),
        features: Set(None),
        default_account_count: Set(Some(0)),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_tenant_package 失败");
    crate::entity::sys_tenant::ActiveModel {
        tenant_id: Set(TID),
        tenant_code: Set(format!("it_pkg_{TID}")),
        tenant_name: Set(format!("IT-PKG-{TID}")),
        package_id: Set(Some(PACKAGE_ID)),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_tenant 失败");

    let token = token_with_tid(&ctx, TID);

    // 读侧：树 ⊆ 套餐白名单
    let (status, v) = ctx
        .send_raw(auth_get(&ctx, &token, "/system/menu/treeselect"))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "租户读授权树应 200，实际 {status} {v}"
    );
    fn collect_ids(nodes: &[serde_json::Value], out: &mut Vec<i64>) {
        for node in nodes {
            if let Some(id) = node["id"].as_i64() {
                out.push(id);
            }
            if let Some(children) = node["children"].as_array() {
                collect_ids(children, out);
            }
        }
    }
    let mut ids = Vec::new();
    collect_ids(v["data"].as_array().expect("data 应为数组"), &mut ids);
    assert!(
        ids.contains(&inside_id),
        "套餐白名单内的菜单必须在租户树里（inside={inside_id}），实际: {ids:?}"
    );
    assert!(
        !ids.contains(&outside_id),
        "套餐白名单外的菜单不得出现在租户树里（outside={outside_id}），实际: {ids:?}"
    );

    // 写侧：与读侧同一把尺
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/system/role")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "roleName": "白名单外角色",
                "roleKey": ROLE_KEY_OUT,
                "roleSort": 98,
                "status": "0",
                "menuIds": [outside_id]
            })
            .to_string(),
        ))
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4322))));
    let (status, v) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "勾选套餐白名单外的菜单必须被拒（403），实际 {status} {v}"
    );

    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/system/role")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "roleName": "白名单内角色",
                "roleKey": ROLE_KEY_IN,
                "roleSort": 99,
                "status": "0",
                "menuIds": [inside_id]
            })
            .to_string(),
        ))
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4323))));
    let (status, v) = ctx.send_raw(req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "勾选套餐白名单内的菜单必须成功（读侧与写侧同尺），实际 {status} {v}"
    );
    assert_eq!(v["code"], 200, "业务码应为 200，实际 {v}");
}
