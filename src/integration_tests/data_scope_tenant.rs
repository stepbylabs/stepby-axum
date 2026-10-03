// stepby-axum/src/integration_tests/data_scope_tenant.rs
//! 台账 P2-2：`data_scope × tenant` 组合回归（真实调用 `SysUserService::get_user_page`）。
//!
//! 现状缺口：`integration_tests/tenant_scope.rs` 只覆盖「租户隔离」（sso_client 样本），
//! `common/data_scope.rs` 只覆盖 scope 纯计算；**缺「同租户内 data_scope 收窄 +
//! 跨租户不可见」的组合用例**。本模块通过唯一入口 `get_user_page(query, operator_user_id,
//! tenant_scope)` 覆盖三层语义：
//!
//! 1. 同租户内 `data_scope` 收窄生效（scope=3 本部门：范围外同租户行不可见）；
//! 2. 跨租户不可见且与 data_scope **正交**（scope=1 全部数据也看不到它租户行 ⇒
//!    tenant 过滤是 data_scope 之外的一层硬约束）；
//! 3. 平台操作者（tid=0）**不受**租户过滤，**仍受** data_scope 影响。
//!
//! 造数：直连隔离 sqlite（`ctx.state.db`）插入 sys_user / sys_role / sys_user_role。
//! 断言全部可证伪：任一过滤层缺失（tenant 或 data_scope）都会使计数/成员集合改变。
//!
//! 命名空间隔离：测试租户用 9010/9020（种子数据均为 tid=0），部门用 9100/9200/9300/9400，
//! user_id / role_id 用 9001+，避免与迁移种子（admin user_id=1 等）冲突。

use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use super::TestContext;
use crate::common::tenant::tenant_scope;
use crate::entity::{sys_role, sys_user, sys_user_role};
use crate::service::sys_user_service::UserQueryDto;

/// 测试租户（均非 0，避免与种子 tid=0 混同）
const TID_A: i64 = 9010;
const TID_B: i64 = 9020;

fn query_all() -> UserQueryDto {
    UserQueryDto {
        page_num: 1,
        page_size: 100,
        order_by_column: None,
        is_asc: None,
        dept_id: None,
        user_name: None,
        phonenumber: None,
        status: None,
        begin_time: None,
        end_time: None,
        last_id: None,
        // 该集成测试只验证 data_scope × tenant_scope 的隔离，不叠加显式租户筛选
        tenant_id: None,
    }
}

/// 直插一条未删除、启用状态的用户。
async fn insert_user(db: &DatabaseConnection, id: i64, tid: i64, dept: Option<i64>) {
    sys_user::ActiveModel {
        user_id: Set(id),
        user_name: Set(format!("it_ds_{id}")),
        nick_name: Set(format!("IT-DS-{id}")),
        tenant_id: Set(tid),
        dept_id: Set(dept),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_user 失败");
}

/// 直插一条启用角色（含指定 data_scope，归属指定租户）。
async fn insert_role(db: &DatabaseConnection, id: i64, tid: i64, scope: &str) {
    sys_role::ActiveModel {
        role_id: Set(id),
        role_name: Set(format!("it_ds_role_{id}")),
        role_key: Set(format!("it_ds_key_{id}")),
        role_sort: Set(0),
        data_scope: Set(Some(scope.to_string())),
        status: Set("0".to_string()),
        tenant_id: Set(tid),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_role 失败");
}

/// 绑定用户 ↔ 角色（`find_by_user_id` 经 sys_user_role 关联取角色）。
async fn bind_role(db: &DatabaseConnection, user_id: i64, role_id: i64) {
    sys_user_role::ActiveModel {
        user_id: Set(user_id),
        role_id: Set(role_id),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_user_role 失败");
}

/// 从分页结果提取 user_id 集合。
fn ids(rows: &[crate::service::sys_user_service::UserVo]) -> Vec<i64> {
    rows.iter().map(|v| v.user.user_id).collect()
}

/// ① + ②：同租户内 data_scope 收窄（scope=3 本部门）+ 跨租户不可见。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_data_scope_narrows_within_tenant_and_blocks_cross_tenant() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // 租户 A（9010）：operator 与 1 名同部门用户（可见）、1 名它部门用户（范围外）；
    // 租户 B（9020）：1 名同部门用户（应被 tenant 硬约束挡住）。
    insert_user(db, 9001, TID_A, Some(9100)).await; // operator（本部门 9100）
    insert_user(db, 9002, TID_A, Some(9100)).await; // 租户 A · 本部门 → 应可见
    insert_user(db, 9003, TID_A, Some(9200)).await; // 租户 A · 它部门 → 应不可见（scope 收窄）
    insert_user(db, 9004, TID_B, Some(9100)).await; // 租户 B · 同部门 → 应不可见（tenant）
    insert_role(db, 9001, TID_A, "3").await; // data_scope=3 本部门
    bind_role(db, 9001, 9001).await;

    let (rows, total) = ctx
        .state
        .user_service
        .get_user_page(
            query_all(),
            Some(9001),
            tenant_scope(TID_A),
            &std::collections::HashSet::new(),
        )
        .await
        .expect("get_user_page 失败");

    let got = ids(&rows);
    assert_eq!(
        total, 2,
        "scope=3 应命中租户 A 本部门 2 人（operator+9002），实际 {total}：{got:?}"
    );
    assert!(
        got.contains(&9001) && got.contains(&9002),
        "本部门应可见：{got:?}"
    );
    assert!(
        !got.contains(&9003),
        "同租户·它部门行应被 data_scope=3 收窄挡住：{got:?}"
    );
    assert!(
        !got.contains(&9004),
        "它租户行应被 tenant 过滤挡住（data_scope 之外的一层硬约束）：{got:?}"
    );
}

/// ②（正交性核心）：data_scope=1「全部数据」放宽到最大，仍看不到它租户行。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_scope_all_still_cannot_see_other_tenant_rows() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // 租户 A：operator（scope=1）+ 2 名用户在两个不同部门；
    // 租户 B：1 名用户（同部门 9100）。
    insert_user(db, 9005, TID_A, Some(9100)).await; // operator
    insert_user(db, 9006, TID_A, Some(9100)).await;
    insert_user(db, 9007, TID_A, Some(9200)).await;
    insert_user(db, 9008, TID_B, Some(9100)).await; // 它租户 → 应不可见
    insert_role(db, 9005, TID_A, "1").await; // data_scope=1 全部数据
    bind_role(db, 9005, 9005).await;

    let (rows, total) = ctx
        .state
        .user_service
        .get_user_page(
            query_all(),
            Some(9005),
            tenant_scope(TID_A),
            &std::collections::HashSet::new(),
        )
        .await
        .expect("get_user_page 失败");

    let got = ids(&rows);
    assert_eq!(
        total, 3,
        "scope=1 应命中租户 A 全部 3 人（跨部门），实际 {total}：{got:?}"
    );
    assert!(
        got.contains(&9005) && got.contains(&9006) && got.contains(&9007),
        "scope=1 不应按部门收窄（跨部门全可见）：{got:?}"
    );
    assert!(
        !got.contains(&9008),
        "scope=1（全部数据）仍不得跨租户可见 ⇒ tenant 过滤是正交硬约束：{got:?}"
    );
}

/// ③：平台操作者（tid=0）不受租户过滤，但 data_scope 仍然生效。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_platform_operator_ignores_tenant_but_honors_data_scope() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // 平台 operator（tid=0, 部门 9300, scope=3 本部门）；部门 9300 下两个租户各一名用户；
    // 部门 9400 下一名租户 A 用户（应被 data_scope 挡住）。
    insert_user(db, 9009, 0, Some(9300)).await; // platform operator
    insert_user(db, 9010, TID_A, Some(9300)).await; // 租户 A · 部门 9300 → 可见
    insert_user(db, 9011, TID_B, Some(9300)).await; // 租户 B · 部门 9300 → 可见（平台不受租户过滤）
    insert_user(db, 9012, TID_A, Some(9400)).await; // 租户 A · 部门 9400 → 不可见（scope 收窄）
    insert_role(db, 9009, 0, "3").await; // platform role, data_scope=3 本部门
    bind_role(db, 9009, 9009).await;

    // tenant_scope(0) == None ⇒ 平台操作者不过滤租户
    assert_eq!(tenant_scope(0), None, "平台 tid=0 应求值为不过滤");

    let (rows, total) = ctx
        .state
        .user_service
        .get_user_page(
            query_all(),
            Some(9009),
            tenant_scope(0),
            &std::collections::HashSet::new(),
        )
        .await
        .expect("get_user_page 失败");

    let got = ids(&rows);
    assert_eq!(
        total, 3,
        "平台操作者 scope=3 应命中部门 9300 全租户 3 人（含 operator），实际 {total}：{got:?}"
    );
    assert!(
        got.contains(&9009) && got.contains(&9010) && got.contains(&9011),
        "平台操作者不受租户过滤（跨租户同部门均可见）：{got:?}"
    );
    assert!(
        !got.contains(&9012),
        "平台操作者仍受 data_scope 影响（部门 9400 超出本部门范围）：{got:?}"
    );
}
