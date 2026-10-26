// stepby-axum/src/integration_tests/menu_perm_contract.rs
//! 菜单 ↔ 后端路由权限键 契约一致性测试。
//!
//! 背景（优化方案 §3.2）：后端 `get_required_perm` 为每个受保护路由登记所需权限键，
//! 而前端通过 `sys_menu.perms`（经角色→菜单授权）授予用户。二者若发生漂移：
//! - 后端需新增权限键但菜单未登记 → 该能力永远无法被普通角色授予（越权给全部用户或不可用）；
//! - 菜单登记了非法/冗余的 perms → 前端按钮权限判断混乱。
//!
//! 本测试以生产 `PERM_ROUTE_TABLE`（单一数据源）为准，校验隔离种子数据库中的 `sys_menu`：
//! 1. `sys_menu.perms` 全部非空值格式合法（`[A-Za-z0-9_:-]+`，允许连字符以兼容
//!    `system:webhook:test-send` 这类与路由路径同名的权限键）；
//! 2. 后端 `all_required_perm_keys()` 中的每个键都必须存在于 `sys_menu.perms`，
//!    即「后端所需权限 ⊆ 菜单可授予权限」，杜绝权限键漂移。

use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use super::TestContext;
use crate::middleware::permission::all_required_perm_keys;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode};
use std::net::SocketAddr;

/// 权限标识格式合法性校验与菜单写面共用同一把尺（`common::perm_format`）：
/// 仅允许字母/数字/下划线/连字符 与 冒号（形如 `module:entity:action`；
/// 连字符用于与路由路径同名的权限键，如 `system:webhook:test-send`）。
use crate::common::perm_format::is_well_formed_perm;

/// 菜单数据卫生契约（批次十四）：C 型页面菜单**必须**携带 component——
/// 无 component 的 C 页面是"点击 404 死入口"（实证：4115 曾被污染为 C 型无
/// component 且 visible='0' 显示中）。防复发的结构化断言。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_c_type_menus_must_have_component() {
    let (state, _slot) = super::build_isolated_state().await;
    let db = &state.db;
    let rows = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT menu_id, menu_name FROM sys_menu \
             WHERE menu_type = 'C' AND del_flag = '0' \
               AND (component IS NULL OR component = '')"
                .to_string(),
        ))
        .await
        .expect("查询 C 型无 component 菜单失败");
    assert!(
        rows.is_empty(),
        "存在无 component 的 C 型页面（点击即 404 死入口）: {:?}",
        rows.iter()
            .map(|r| r.try_get::<i64>("", "menu_id"))
            .collect::<Vec<_>>()
    );
}

/// 契约一致性：后端路由所需权限 ⊆ sys_menu.perms，且菜单权限标识格式合法。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_backend_required_perms_covered_by_menu() {
    let (state, _slot) = super::build_isolated_state().await;
    let db = &state.db;

    // 读取 sys_menu 全部非空 perms（前端经角色可授予的权限全集）
    let rows = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT perms FROM sys_menu WHERE perms IS NOT NULL AND perms <> ''",
        ))
        .await
        .expect("查询 sys_menu.perms 失败");

    let mut menu_perms: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for row in &rows {
        let p: String = row
            .try_get("", "perms")
            .expect("读取 sys_menu.perms 列失败");
        assert!(
            is_well_formed_perm(&p),
            "sys_menu.perms 格式非法（仅允许 [A-Za-z0-9_:-]）: {p:?}"
        );
        menu_perms.insert(p);
    }
    assert!(
        !menu_perms.is_empty(),
        "种子数据 sys_menu.perms 不应为空（契约测试无意义）"
    );

    // 后端路由权限表的全部权限键必须能由菜单授予（单一数据源，随 PERM_ROUTE_TABLE 自动同步）
    let backend_perms: std::collections::BTreeSet<&str> =
        all_required_perm_keys().iter().copied().collect();

    let missing: Vec<&str> = backend_perms
        .iter()
        .filter(|p| !menu_perms.contains(**p))
        .copied()
        .collect();
    assert!(
        missing.is_empty(),
        "后端路由所需权限在 sys_menu.perms 中缺失 {} 个，这些能力将无法被角色授予：{missing:?}",
        missing.len()
    );

    // 兜底：确认集合并非因为"后端恰好为 0"而空转（防御性，随表增长自动失效）
    assert!(
        !backend_perms.is_empty(),
        "后端权限映射表不应为空（PERM_ROUTE_TABLE 被误删？）"
    );
}

/// RBAC 缓存旁路回归锁（§5.34 逐文件审计 F-MW-1）：
/// response_cache 曾挂在 permission **外层**，缓存命中直接返回、RBAC 从未执行——
/// 无 `system:dict:query` 权限的普通用户（stepby）也能经缓存拿到 optionselect。
/// 修复后 cache 移到 permission 内层：admin 预热缓存后，stepby 请求必须被
/// permission 拒绝（403），**不得**命中缓存。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_response_cache_does_not_bypass_rbac() {
    let ctx = TestContext::new().await;
    const URI: &str = "/system/dict/type/optionselect";

    // 1. admin（有 system:dict:query）请求 → 200，缓存写入
    let mut admin_req = Request::builder()
        .method(axum::http::Method::GET)
        .uri(URI)
        .header("authorization", format!("Bearer {}", ctx.token))
        .body(Body::empty())
        .expect("构造 admin 请求失败");
    admin_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4321))));
    let (admin_status, _) = ctx.send_raw(admin_req).await;
    assert_eq!(
        admin_status,
        StatusCode::OK,
        "admin 应正常获取字典类型下拉，实际 {admin_status}"
    );

    // 2. 建一个"空白角色"用户（role 无任何 role_menu 授权 ⇒ perms 集为空，
    //    必然不含 system:dict:query）。密码哈希直接复制 stepby 的（等价密码）。
    //    注意：seed 的 role2（stepby 所在角色）持有全量菜单，含 dict:query，
    //    不能用作反例。
    ctx.state.db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO sys_role (role_id, role_name, role_key, role_sort, data_scope, status, del_flag, create_by, create_time)
             VALUES (9001, 'IT空白角色', 'it_blank', 99, '1', '0', '0', 'it', CURRENT_TIMESTAMP)",
        ))
        .await
        .expect("插入空白角色失败");
    ctx.state.db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO sys_user (user_id, dept_id, user_name, nick_name, password, status, del_flag, create_by, create_time, tenant_id)
             SELECT 9001, dept_id, 'it_blank', 'IT空白用户', password, '0', '0', 'it', CURRENT_TIMESTAMP, tenant_id
             FROM sys_user WHERE user_name = 'stepby'",
        ))
        .await
        .expect("插入空白用户失败");
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO sys_user_role (user_id, role_id) VALUES (9001, 9001)",
        ))
        .await
        .expect("绑定空白角色失败");

    // 3. 空白用户登录 → GET optionselect 必须被 permission 拒绝 403，
    //    不得因 admin 的缓存命中而旁路（修复前此处返回 200）
    let blank_token = super::login(&ctx.app, ctx.peer_ip, "it_blank", "admin123").await;
    let mut blank_req = Request::builder()
        .method(axum::http::Method::GET)
        .uri(URI)
        .header("authorization", format!("Bearer {blank_token}"))
        .body(Body::empty())
        .expect("构造空白用户请求失败");
    blank_req
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4321))));
    let (status, _) = ctx.send_raw(blank_req).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "无任何授权的用户必须 403（RBAC 不得被缓存旁路），实际 {status}"
    );
}
