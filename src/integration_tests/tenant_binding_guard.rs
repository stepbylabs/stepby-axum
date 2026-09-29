// backend-axum/src/integration_tests/tenant_binding_guard.rs
//! 第十批（MT-2 审计器候选逐条复核发现）：**关联表写入路径的父资源租户归属**回归锁。
//!
//! ## 修复前的两处真实缺口
//!
//! ① `assign_user_roles`（`PUT /system/user/authRole`）只校验"**目标用户**归属"，
//!    未校验"**被授角色**归属" ⇒ 租户操作者可把**平台角色或他租户角色**授给本租户用户；
//!    该用户随即按该角色的 `sys_role_menu` 获得授权面（**跨租户提权 / 越界可见**）。
//!    同族的 `add_user` / `edit_user` 两条路径**早已**校验（`ensure_roles_tenant_allowed`）
//!    ⇒ 本路径是唯一漏网。
//! ② `add_user` / `edit_user` 的 `post_ids` **完全没有**租户归属校验（角色 / 部门都有）
//!    ⇒ 可绑定他租户 / 平台岗位：用户详情与列表的 `postGroup` 会**回显他租户岗位名**
//!    （跨租户信息泄漏）+ 形成跨租户外键引用（数据完整性破坏）。
//!
//! `sys_user_role` / `sys_user_post` 都是**无 `tenant_id` 的关联表**，
//! 蓝本 §27.13.1 对它们"依赖父表 JOIN 即可安全"的判定**前提**正是
//! "**写入时校验父资源归属**"——`post_ids` 与 `authRole` 两条路径违反了该前提。
//!
//! ## 可证伪性
//! 移除 `assign_user_roles` 里的 `ensure_roles_tenant_allowed` 调用，用例 1/2 即从 403 变 Ok；
//! 移除 `edit_user` 里的 `ensure_posts_tenant_allowed` 调用，用例 4 即从 403 变 Ok。
//!
//! 命名空间隔离：租户用 9030/9031，user_id 用 9201+，role_id 用 9211+，post_id 用 9221+，
//! 避免与种子（admin user_id=1、role 2）及其它用例冲突。

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    Set,
};

use super::TestContext;
use crate::entity::{sys_post, sys_role, sys_user};
use crate::service::sys_user_service::UserEditDto;

/// 本租户（操作者与目标用户所属）
const TID_A: i64 = 9030;
/// 异租户（被误绑的角色 / 岗位所属）
const TID_B: i64 = 9031;
/// 平台租户（`tenant_allowed` 中 0 是"平台管理员"，作为**资源归属**时对租户操作者是异租户）
const TID_PLATFORM: i64 = 0;

const OPERATOR_USER_ID: i64 = 9201;
const TARGET_USER_ID: i64 = 9202;
const ROLE_OWN: i64 = 9211;
const ROLE_OTHER: i64 = 9212;
const ROLE_PLATFORM: i64 = 9213;
/// 操作者自身角色：`role_sort = 5`（**高于**业务角色的 10），
/// 使垂直越权校验（`target_min < op_min` 才拒）放行 ⇒ 断言精确归因**租户**维度。
const ROLE_OPERATOR: i64 = 9214;
const POST_OWN: i64 = 9221;
const POST_OTHER: i64 = 9222;
const POST_PLATFORM: i64 = 9223;

async fn insert_user(db: &DatabaseConnection, id: i64, tid: i64) {
    sys_user::ActiveModel {
        user_id: Set(id),
        user_name: Set(format!("it_tbg_{id}")),
        nick_name: Set(format!("IT-TBG-{id}")),
        tenant_id: Set(tid),
        dept_id: Set(None),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_user 失败");
}

async fn insert_role(db: &DatabaseConnection, id: i64, tid: i64, sort: i32) {
    sys_role::ActiveModel {
        role_id: Set(id),
        role_name: Set(format!("it_tbg_role_{id}")),
        role_key: Set(format!("it_tbg_key_{id}")),
        // role_sort 由调用方指定：业务角色 10（低于操作者），操作者角色 5
        // ⇒ 确保断言只由**租户**维度决定，不被垂直越权（role_sort 比较）干扰
        role_sort: Set(sort),
        data_scope: Set(Some("1".to_string())),
        status: Set("0".to_string()),
        tenant_id: Set(tid),
        is_system: Set(false),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_role 失败");
}

/// 绑定用户-角色（`source='admin'`）
async fn bind_role(db: &DatabaseConnection, user_id: i64, role_id: i64) {
    crate::entity::sys_user_role::ActiveModel {
        user_id: Set(user_id),
        role_id: Set(role_id),
        source: Set("admin".to_string()),
    }
    .insert(db)
    .await
    .expect("插入 sys_user_role 失败");
}

async fn insert_post(db: &DatabaseConnection, id: i64, tid: i64) {
    sys_post::ActiveModel {
        post_id: Set(id),
        post_code: Set(format!("it_tbg_post_{id}")),
        post_name: Set(format!("IT-TBG-POST-{id}")),
        post_sort: Set(0),
        status: Set(Some("0".to_string())),
        tenant_id: Set(tid),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_post 失败");
}

/// 建 fixture：本租户操作者（+自身角色）+ 本租户目标用户 + 三个业务角色 + 三个岗位。
///
/// 操作者绑定 `ROLE_OPERATOR`（`role_sort = 5`，高于业务角色 10）：
/// `check_vertical_auth_by_role_ids` 在"操作者无任何角色"时会**一律拒绝**分配
/// （垂直越权 safe-fail），故必须给操作者一个更高优先级角色，
/// 才能让断言精确归因到**租户**维度而非垂直越权规则。
/// 目标用户不绑角色 ⇒ `check_vertical_auth_by_user_id` 提前返回。
async fn seed(ctx: &TestContext) {
    let db = &ctx.state.db;
    insert_user(db, OPERATOR_USER_ID, TID_A).await;
    insert_user(db, TARGET_USER_ID, TID_A).await;
    insert_role(db, ROLE_OWN, TID_A, 10).await;
    insert_role(db, ROLE_OTHER, TID_B, 10).await;
    insert_role(db, ROLE_PLATFORM, TID_PLATFORM, 10).await;
    insert_role(db, ROLE_OPERATOR, TID_A, 5).await;
    bind_role(db, OPERATOR_USER_ID, ROLE_OPERATOR).await;
    insert_post(db, POST_OWN, TID_A).await;
    insert_post(db, POST_OTHER, TID_B).await;
    insert_post(db, POST_PLATFORM, TID_PLATFORM).await;
}

fn edit_dto(post_ids: Option<Vec<i64>>) -> UserEditDto {
    UserEditDto {
        user_id: TARGET_USER_ID,
        dept_id: None,
        nick_name: None,
        email: None,
        phonenumber: None,
        country_code: None,
        sex: None,
        status: None,
        role_ids: None,
        post_ids,
        dept_ids: None,
        remark: None,
    }
}

/// ① `assign_user_roles` 必须拒绝**他租户角色**与**平台角色**（跨租户提权口子）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_assign_user_roles_rejects_cross_tenant_role() {
    let ctx = TestContext::new().await;
    seed(&ctx).await;
    let svc = &ctx.state.user_service;

    let err = svc
        .assign_user_roles(TARGET_USER_ID, vec![ROLE_OTHER], OPERATOR_USER_ID, TID_A)
        .await
        .expect_err("授他租户角色必须被拒");
    assert_eq!(
        err.code, 403,
        "应为 403，实际 {}：{}",
        err.code, err.message
    );

    let err = svc
        .assign_user_roles(TARGET_USER_ID, vec![ROLE_PLATFORM], OPERATOR_USER_ID, TID_A)
        .await
        .expect_err("授平台角色必须被拒（租户操作者不得引用平台角色）");
    assert_eq!(
        err.code, 403,
        "应为 403，实际 {}：{}",
        err.code, err.message
    );
}

/// ② 对照：**同租户**角色必须放行（证明并非一律拒绝 ⇒ 断言精确归因租户维度）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_assign_user_roles_allows_same_tenant_role() {
    let ctx = TestContext::new().await;
    seed(&ctx).await;
    let svc = &ctx.state.user_service;

    svc.assign_user_roles(TARGET_USER_ID, vec![ROLE_OWN], OPERATOR_USER_ID, TID_A)
        .await
        .expect("授同租户角色应放行（对照）");

    // 落库复核：sys_user_role 确实写入
    let bound: Vec<i64> = crate::entity::sys_user_role::Entity::find()
        .filter(crate::entity::sys_user_role::Column::UserId.eq(TARGET_USER_ID))
        .all(&ctx.state.db)
        .await
        .expect("查询 sys_user_role 失败")
        .into_iter()
        .map(|r| r.role_id)
        .collect();
    assert_eq!(bound, vec![ROLE_OWN], "同租户角色应落库");
}

/// ③ `edit_user` 必须拒绝**他租户 / 平台岗位**绑定（`postGroup` 回显泄漏 + 跨租户外键引用）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_edit_user_rejects_cross_tenant_post() {
    let ctx = TestContext::new().await;
    seed(&ctx).await;
    let svc = &ctx.state.user_service;

    let err = svc
        .edit_user(
            edit_dto(Some(vec![POST_OTHER])),
            "it_tbg_op",
            OPERATOR_USER_ID,
            TID_A,
        )
        .await
        .expect_err("绑定他租户岗位必须被拒");
    assert_eq!(
        err.code, 403,
        "应为 403，实际 {}：{}",
        err.code, err.message
    );

    let err = svc
        .edit_user(
            edit_dto(Some(vec![POST_PLATFORM])),
            "it_tbg_op",
            OPERATOR_USER_ID,
            TID_A,
        )
        .await
        .expect_err("绑定平台岗位必须被拒");
    assert_eq!(
        err.code, 403,
        "应为 403，实际 {}：{}",
        err.code, err.message
    );
}

/// ④ 对照：**同租户**岗位必须放行，且落库可复核。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_edit_user_allows_same_tenant_post() {
    let ctx = TestContext::new().await;
    seed(&ctx).await;
    let svc = &ctx.state.user_service;

    svc.edit_user(
        edit_dto(Some(vec![POST_OWN])),
        "it_tbg_op",
        OPERATOR_USER_ID,
        TID_A,
    )
    .await
    .expect("绑定同租户岗位应放行（对照）");

    let bound: Vec<i64> = crate::entity::sys_user_post::Entity::find()
        .filter(crate::entity::sys_user_post::Column::UserId.eq(TARGET_USER_ID))
        .all(&ctx.state.db)
        .await
        .expect("查询 sys_user_post 失败")
        .into_iter()
        .map(|r| r.post_id)
        .collect();
    assert_eq!(bound, vec![POST_OWN], "同租户岗位应落库");
}

// ============================================================================
// 第十一批：GAP-C 根治 —— OAuth 自动建号的**默认角色**不得跨租户引用
//
// 修复前：无条件绑定平台普通角色（`role_id = 2`，`tenant_id = 0`）⇒ 供应商属租户 T 时
// 形成"租户用户 → 平台角色"的跨租户引用（第十批 MT-2 复核发现后按"登记接受 + WARN"处理）。
// 现改为 `sys_tenant_service::resolve_default_role_for_tenant`：
//   平台租户 → 平台普通角色；租户 → 该租户自己的 `{tenant_code}_common`（不存在则幂等创建，
//   菜单 = 平台普通角色菜单 ∩ 可授予 ∩ 套餐白名单）；租户不存在/创建失败 → `None`（fail-closed）。
//
// 可证伪：把 `resolve_default_role_for_tenant` 的租户分支改回返回 `COMMON_ROLE_ID`，
// 用例⑥的 `role.tenant_id == TID_COMMON` 与用例⑧的 `None` 断言即变红。
// ============================================================================

/// 本批租户命名空间（与 9030/9031 隔离）
const TID_COMMON: i64 = 9040;
const TENANT_CODE_COMMON: &str = "it_gapc";

async fn insert_tenant(db: &DatabaseConnection, id: i64, code: &str) {
    crate::entity::sys_tenant::ActiveModel {
        tenant_id: Set(id),
        tenant_code: Set(code.to_string()),
        tenant_name: Set(format!("IT-GAPC-{id}")),
        package_id: Set(None),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_tenant 失败");
}

async fn resolve(db: &DatabaseConnection, tid: i64) -> Option<i64> {
    crate::service::sys_tenant_service::resolve_default_role_for_tenant(db, tid)
        .await
        .expect("resolve_default_role_for_tenant 不应返回 Err")
}

/// ⑤ 对照：平台租户仍绑平台普通角色（行为不变）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_default_role_for_platform_tenant_is_platform_common_role() {
    let ctx = TestContext::new().await;
    assert_eq!(
        resolve(&ctx.state.db, 0).await,
        Some(2),
        "平台租户应绑平台普通角色 role_id=2"
    );
}

/// ⑥ **GAP-C 核心**：租户供应商的默认角色必须是**该租户自己的普通角色**，
///    菜单非空、⊆ 平台普通角色菜单、且**全部可授予**（不带入平台专属/tier2 权限）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_default_role_for_tenant_is_tenant_scoped_common_role() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    insert_tenant(db, TID_COMMON, TENANT_CODE_COMMON).await;

    let role_id = resolve(db, TID_COMMON).await.expect("应为租户创建普通角色");
    let role = sys_role::Entity::find_by_id(role_id)
        .one(db)
        .await
        .expect("查询角色失败")
        .expect("角色应存在");
    assert_eq!(
        role.tenant_id, TID_COMMON,
        "默认角色必须归属该租户（不得是平台角色 tenant_id=0 ⇒ 跨租户引用）"
    );
    assert_eq!(role.role_key, format!("{TENANT_CODE_COMMON}_common"));
    assert!(!role.is_system, "租户普通角色非系统角色（不享超管短路）");

    let menu_ids: Vec<i64> = crate::entity::sys_role_menu::Entity::find()
        .filter(crate::entity::sys_role_menu::Column::RoleId.eq(role_id))
        .all(db)
        .await
        .expect("查询角色菜单失败")
        .into_iter()
        .map(|r| r.menu_id)
        .collect();
    assert!(
        !menu_ids.is_empty(),
        "租户普通角色必须有菜单（否则登录后为空壳，业务链路断裂）"
    );
    let platform_menu_ids: Vec<i64> = crate::entity::sys_role_menu::Entity::find()
        .filter(crate::entity::sys_role_menu::Column::RoleId.eq(2))
        .all(db)
        .await
        .expect("查询平台普通角色菜单失败")
        .into_iter()
        .map(|r| r.menu_id)
        .collect();
    for id in &menu_ids {
        assert!(
            platform_menu_ids.contains(id),
            "菜单 {id} 超出平台普通角色菜单集（越权面）"
        );
    }
    for m in crate::entity::sys_menu::Entity::find()
        .filter(crate::entity::sys_menu::Column::MenuId.is_in(menu_ids.clone()))
        .all(db)
        .await
        .expect("查询菜单失败")
    {
        if let Some(p) = m.perms.as_deref().filter(|p| !p.is_empty()) {
            assert!(
                crate::common::tenant::is_grantable_perm(p),
                "菜单 {} 的 perms `{p}` 不可授予租户（平台专属 / tier2 混入）",
                m.menu_id
            );
        }
    }
}

/// ⑦ 幂等：重复解析返回同一角色，且该租户下同名角色只有一条。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_default_role_for_tenant_is_idempotent() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    insert_tenant(db, TID_COMMON, TENANT_CODE_COMMON).await;

    let first = resolve(db, TID_COMMON).await.expect("首次应创建");
    let second = resolve(db, TID_COMMON).await.expect("再次应复用");
    assert_eq!(first, second, "重复调用必须返回同一角色（幂等）");

    let count = sys_role::Entity::find()
        .filter(sys_role::Column::TenantId.eq(TID_COMMON))
        .filter(sys_role::Column::RoleKey.eq(format!("{TENANT_CODE_COMMON}_common")))
        .count(db)
        .await
        .expect("统计角色失败");
    assert_eq!(count, 1, "租户普通角色不得重复创建");
}

/// ⑧ fail-closed：租户不存在时返回 `None`（调用方不绑定角色），**绝不回退平台角色**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_default_role_for_missing_tenant_is_none() {
    let ctx = TestContext::new().await;
    assert_eq!(
        resolve(&ctx.state.db, 999_999).await,
        None,
        "租户不存在时必须 fail-closed（不绑定角色、不用平台角色兜底）"
    );
}
