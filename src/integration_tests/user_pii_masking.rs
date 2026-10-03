// stepby-axum/src/integration_tests/user_pii_masking.rs
//! 字段级权限 M1：sys_user 列表/详情 PII（phonenumber / email）掩码三口径回归。
//!
//! 口径（详见 `utils::masking` rustdoc 与 `sys_user_service` 的 M1 注释块）：
//! 1. 本人查自己（operator == 目标 user）→ 原值（看自己的手机号不掩码）；
//! 2. 超管（user_id==1 或拥有平台超管角色 ⇒ 权限列表含 `*:*:*`）→ 原值；
//! 3. 其它 operator 看任何用户 → 掩码（`138****5678` / `a****@example.com`）。
//!
//! 覆盖入口：
//! - `get_user_page`（列表，GET /system/user/list 的 service 出口）；
//! - `get_user_form_data`（详情/编辑回显，GET /system/user/{id} 的 service 出口）。
//!
//! 造数：直连隔离 sqlite（`ctx.state.db`）插入 sys_user / sys_role / sys_user_role，
//! 与 `data_scope_tenant.rs` 同款范式；命名空间隔离：user_id 用 9301+，role_id 用
//! 9301+，避免与种子数据及其它测试冲突。断言可证伪：任一口径失效（漏掩码或
//! 误掩码本人/超管行）都会使断言变红。

use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use super::TestContext;
use crate::entity::{sys_role, sys_user, sys_user_role};
use crate::service::sys_user_service::UserQueryDto;

/// 测试用户手机号（11 位，掩码后应为 138****5678 形态）
const PHONE: &str = "13812345678";
const PHONE_MASKED: &str = "138****5678";
/// 测试用户邮箱（掩码后应为 a****@example.com 形态）
const EMAIL: &str = "alice@example.com";
const EMAIL_MASKED: &str = "a****@example.com";

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
        tenant_id: None,
    }
}

/// 直插一条未删除、启用状态、带 PII 字段的用户（tid=0 平台租户，规避租户过滤）。
async fn insert_user_with_pii(db: &DatabaseConnection, id: i64, dept: Option<i64>) {
    sys_user::ActiveModel {
        user_id: Set(id),
        user_name: Set(format!("it_pii_{id}")),
        nick_name: Set(format!("IT-PII-{id}")),
        tenant_id: Set(0),
        dept_id: Set(dept),
        email: Set(Some(EMAIL.to_string())),
        phonenumber: Set(Some(PHONE.to_string())),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_user 失败");
}

/// 直插一条启用角色（含指定 data_scope，归属平台租户 0）。
async fn insert_role(db: &DatabaseConnection, id: i64, scope: &str, is_system: bool) {
    sys_role::ActiveModel {
        role_id: Set(id),
        role_name: Set(format!("it_pii_role_{id}")),
        role_key: Set(format!("it_pii_key_{id}")),
        role_sort: Set(0),
        data_scope: Set(Some(scope.to_string())),
        status: Set("0".to_string()),
        tenant_id: Set(0),
        is_system: Set(is_system),
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

/// 口径 3：非超管 operator 查列表 —— 他人行掩码、本人行原值（口径 1）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_list_masks_others_but_plain_for_self() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // operator 9301（普通角色 data_scope=1 全部数据）+ 目标用户 9302（同租户 0）
    insert_user_with_pii(db, 9301, Some(9400)).await;
    insert_user_with_pii(db, 9302, Some(9400)).await;
    insert_role(db, 9301, "1", false).await;
    bind_role(db, 9301, 9301).await;

    let (rows, _) = ctx
        .state
        .user_service
        .get_user_page(
            query_all(),
            Some(9301),
            None,
            &std::collections::HashSet::new(),
        )
        .await
        .expect("get_user_page 失败");

    let find = |uid: i64| {
        rows.iter()
            .find(|v| v.user.user_id == uid)
            .unwrap_or_else(|| panic!("列表应含 user {uid}"))
    };

    // 口径 3：他人行 → 掩码
    let other = find(9302);
    assert_eq!(other.user.phonenumber.as_deref(), Some(PHONE_MASKED));
    assert_eq!(other.user.email.as_deref(), Some(EMAIL_MASKED));
    // 掩码值带可识别形态（含 ****），供编辑回显识别
    assert!(other.user.phonenumber.as_deref().unwrap().contains('*'));
    assert!(other.user.email.as_deref().unwrap().contains('*'));

    // 口径 1：本人行 → 原值
    let own = find(9301);
    assert_eq!(own.user.phonenumber.as_deref(), Some(PHONE));
    assert_eq!(own.user.email.as_deref(), Some(EMAIL));
}

/// 口径 2：平台超管角色 operator（is_system && tid=0 ⇒ `*:*:*`）查列表 —— 全部原值。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_list_plain_for_super_admin_role_operator() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // operator 9303（平台超管角色）+ 两名普通用户
    insert_user_with_pii(db, 9303, Some(9400)).await;
    insert_user_with_pii(db, 9304, Some(9400)).await;
    // 口径 2 的角色来源：is_system=true 且 tenant_id=0（与 sys_menu_service
    // 授予 `*:*:*` 的超管判定同源）
    insert_role(db, 9303, "1", true).await;
    bind_role(db, 9303, 9303).await;

    let (rows, _) = ctx
        .state
        .user_service
        .get_user_page(
            query_all(),
            Some(9303),
            None,
            &std::collections::HashSet::new(),
        )
        .await
        .expect("get_user_page 失败");

    for uid in [9303, 9304] {
        let v = rows
            .iter()
            .find(|v| v.user.user_id == uid)
            .unwrap_or_else(|| panic!("列表应含 user {uid}"));
        assert_eq!(
            v.user.phonenumber.as_deref(),
            Some(PHONE),
            "超管看 user {uid} 手机号应原值"
        );
        assert_eq!(
            v.user.email.as_deref(),
            Some(EMAIL),
            "超管看 user {uid} 邮箱应原值"
        );
    }
}

/// 详情/编辑回显三口径：本人原值、超管原值、其它 operator 掩码。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn it_form_data_three_ways() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;

    // 9311 普通 operator（scope=1 可见全部）；9312 目标用户；9313 平台超管 operator
    insert_user_with_pii(db, 9311, Some(9400)).await;
    insert_user_with_pii(db, 9312, Some(9400)).await;
    insert_user_with_pii(db, 9313, Some(9400)).await;
    insert_role(db, 9311, "1", false).await;
    bind_role(db, 9311, 9311).await;
    insert_role(db, 9313, "1", true).await;
    bind_role(db, 9313, 9313).await;

    // 口径 3：普通 operator 查他人 → 掩码
    let vo = ctx
        .state
        .user_service
        .get_user_form_data(Some(9312), Some(9311), None)
        .await
        .expect("get_user_form_data（他人）失败");
    let data = vo.data.expect("详情应含 data");
    assert_eq!(data.phonenumber.as_deref(), Some(PHONE_MASKED));
    assert_eq!(data.email.as_deref(), Some(EMAIL_MASKED));

    // 口径 1：本人查自己 → 原值
    let vo = ctx
        .state
        .user_service
        .get_user_form_data(Some(9311), Some(9311), None)
        .await
        .expect("get_user_form_data（本人）失败");
    let data = vo.data.expect("详情应含 data");
    assert_eq!(data.phonenumber.as_deref(), Some(PHONE));
    assert_eq!(data.email.as_deref(), Some(EMAIL));

    // 口径 2：平台超管查他人 → 原值
    let vo = ctx
        .state
        .user_service
        .get_user_form_data(Some(9312), Some(9313), None)
        .await
        .expect("get_user_form_data（超管）失败");
    let data = vo.data.expect("详情应含 data");
    assert_eq!(data.phonenumber.as_deref(), Some(PHONE));
    assert_eq!(data.email.as_deref(), Some(EMAIL));
}
