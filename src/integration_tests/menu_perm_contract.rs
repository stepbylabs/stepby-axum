// stepby-axum/src/integration_tests/menu_perm_contract.rs
//! 菜单 ↔ 后端路由权限键 契约一致性测试。
//!
//! 背景（优化方案 §3.2）：后端 `get_required_perm` 为每个受保护路由登记所需权限键，
//! 而前端通过 `sys_menu.perms`（经角色→菜单授权）授予用户。二者若发生漂移：
//! - 后端需新增权限键但菜单未登记 → 该能力永远无法被普通角色授予（越权给全部用户或不可用）；
//! - 菜单登记了非法/冗余的 perms → 前端按钮权限判断混乱。
//!
//! 本测试以生产 `PERM_ROUTE_TABLE`（单一数据源）为准，校验隔离种子数据库中的 `sys_menu`：
//! 1. `sys_menu.perms` 全部非空值格式合法（`[A-Za-z0-9_:]+`）；
//! 2. 后端 `all_required_perm_keys()` 中的每个键都必须存在于 `sys_menu.perms`，
//!    即「后端所需权限 ⊆ 菜单可授予权限」，杜绝权限键漂移。

use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use crate::middleware::permission::all_required_perm_keys;

/// 权限标识格式合法性校验：仅允许字母/数字/下划线 与 冒号（形如 `module:entity:action`）。
fn is_well_formed_perm(perm: &str) -> bool {
    !perm.is_empty()
        && perm
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_')
}

/// 契约一致性：后端路由所需权限 ⊆ sys_menu.perms，且菜单权限标识格式合法。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_backend_required_perms_covered_by_menu() {
    let (state, _slot) = super::build_isolated_state().await;
    let db = &state.db;

    // 读取 sys_menu 全部非空 perms（前端经角色可授予的权限全集）
    let rows = db
        .query_all(Statement::from_string(
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
            "sys_menu.perms 格式非法（仅允许 [A-Za-z0-9_:]）: {p:?}"
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
