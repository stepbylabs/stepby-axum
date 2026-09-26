// axum-backend/src/integration_tests/capability_features.rs
//! 能力位（三层开关的**中间层**）回归锁 —— `sys_tenant_package.features`。
//!
//! ## 背景
//!
//! 项目定位「大而全 + 用户可选可配置」：高危能力（如租户域名自助）**不整块砍掉**，
//! 而是收敛为三层开关：平台 `config.toml [features]`（能开什么）→ 租户套餐
//! `sys_tenant_package.features`（这个租户能开什么）→ 角色授权（这个人能用什么）。
//!
//! 本模块锁死其中**最容易被绕过的一环**：**平台层是天花板**。
//! （能力位白名单的逐条匹配语义由 `common::features` 的单元测试覆盖，此处不重复。）
//!
//! ## 可证伪性（关键）
//!
//! - 若 `effective_features_from_package` 忘了取平台天花板（直接返回套餐请求），
//!   用例① 的断言会从 `off` 变为 `full` ⇒ 变红。
//! - 若 `set_package_features` 缺任一道校验（仅平台 / 登记键 / 平台已开启），
//!   用例③ 的对应 `expect_err` 会 panic ⇒ 变红。
//! - 若 `converge_tenant_role_menus` 把两个收敛面合成"仅白名单裁剪"
//!   （`menu_ids = NULL` 时提前返回），用例④ 的菜单不会被回收 ⇒ 变红。
//!
//! 命名空间隔离：租户 9050、套餐 9250+、角色 9260，避免与其它用例冲突。

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

use super::TestContext;
use crate::common::features::FEATURE_OFF;
use crate::entity::{sys_role_menu, sys_tenant, sys_tenant_package};
use crate::service::sys_tenant_service::{
    PackageFeaturesUpdateDto, SysTenantService, effective_features_from_package,
};

const TID: i64 = 9050;
const TENANT_CODE: &str = "it_cap";
const PACKAGE_ID: i64 = 9250;
const ROLE_ID: i64 = 9260;

/// 域名管理菜单断言目标：使用**真实种子菜单**（`system:tenant:domain:list`）的 menu_id，
/// 避免本用例自造 perms 与真实平台专属前缀脱节。
async fn domain_menu_id(db: &DatabaseConnection) -> i64 {
    crate::entity::sys_menu::Entity::find()
        .filter(crate::entity::sys_menu::Column::Perms.eq("system:tenant:domain:list"))
        .filter(crate::entity::sys_menu::Column::DelFlag.eq("0"))
        .one(db)
        .await
        .expect("查询域名菜单失败")
        .expect("种子应含 perms = system:tenant:domain:list 的菜单（m20260925_000002 段 3800）")
        .menu_id
}

async fn insert_package(db: &DatabaseConnection, features: Option<&str>) {
    sys_tenant_package::ActiveModel {
        package_id: Set(PACKAGE_ID),
        package_name: Set(format!("IT-CAP-{PACKAGE_ID}")),
        menu_ids: Set(None),
        features: Set(features.map(|s| s.to_string())),
        default_account_count: Set(Some(0)),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_tenant_package 失败");
}

async fn insert_tenant_with_package(db: &DatabaseConnection) {
    sys_tenant::ActiveModel {
        tenant_id: Set(TID),
        tenant_code: Set(TENANT_CODE.to_string()),
        tenant_name: Set(format!("IT-CAP-{TID}")),
        package_id: Set(Some(PACKAGE_ID)),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_tenant 失败");
}

async fn insert_role(db: &DatabaseConnection) {
    crate::entity::sys_role::ActiveModel {
        role_id: Set(ROLE_ID),
        role_name: Set(format!("it_cap_role_{ROLE_ID}")),
        role_key: Set(format!("it_cap_key_{ROLE_ID}")),
        role_sort: Set(10),
        data_scope: Set(Some("1".to_string())),
        status: Set("0".to_string()),
        tenant_id: Set(TID),
        is_system: Set(false),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_role 失败");
}

async fn grant_menu(db: &DatabaseConnection, role_id: i64, menu_id: i64) {
    sys_role_menu::ActiveModel {
        role_id: Set(role_id),
        menu_id: Set(menu_id),
    }
    .insert(db)
    .await
    .expect("插入 sys_role_menu 失败");
}

async fn has_menu(db: &DatabaseConnection, role_id: i64, menu_id: i64) -> bool {
    sys_role_menu::Entity::find()
        .filter(sys_role_menu::Column::RoleId.eq(role_id))
        .filter(sys_role_menu::Column::MenuId.eq(menu_id))
        .one(db)
        .await
        .expect("查询 sys_role_menu 失败")
        .is_some()
}

/// ① **平台未开启 ⇒ 套餐写 `full` 也不生效**（关闭态即安全态 / 平台层是天花板）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_platform_ceiling_blocks_tenant_only_enablement() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    insert_package(db, Some(r#"{"tenant.domain_self_service":"full"}"#)).await;
    insert_tenant_with_package(db).await;

    assert!(
        !crate::common::features::platform_features().is_on("tenant.domain_self_service"),
        "本用例前提：平台层未开启该能力位（测试进程默认全 off）"
    );

    let effective = crate::service::sys_tenant_service::tenant_features_conn(db, TID)
        .await
        .expect("解析租户有效能力集失败");
    assert_eq!(
        effective.mode("tenant.domain_self_service"),
        FEATURE_OFF,
        "平台层未开启时，租户套餐写 full 必须被压回 off（否则平台开关形同虚设）"
    );
    assert!(
        !crate::common::features::is_grantable_perm_with_features(
            "system:tenant:domain:add",
            &effective
        ),
        "平台未开启时，域名新增权限不得可授予租户角色"
    );
}

/// ② 套餐 `features` 为 NULL / 空 / 非法 JSON ⇒ 回落到"全默认（关闭）"（fail-closed）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_package_features_null_or_invalid_falls_back_to_default() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    for (idx, raw) in [None, Some(""), Some("{"), Some("[]")]
        .into_iter()
        .enumerate()
    {
        let pid = PACKAGE_ID + 100 + idx as i64;
        sys_tenant_package::ActiveModel {
            package_id: Set(pid),
            package_name: Set(format!("IT-CAP-NULL-{pid}")),
            menu_ids: Set(None),
            features: Set(raw.map(|s| s.to_string())),
            default_account_count: Set(Some(0)),
            status: Set(Some("0".to_string())),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        }
        .insert(db)
        .await
        .expect("插入套餐失败");
        let package = sys_tenant_package::Entity::find_by_id(pid)
            .one(db)
            .await
            .expect("查询套餐失败")
            .expect("套餐应存在");
        let effective = effective_features_from_package(Some(&package));
        assert!(
            effective.is_default(),
            "features = {raw:?} 必须回落到全默认（关闭态），实际 {effective:?}"
        );
    }
}

/// ③ `set_package_features` 的三道校验（仅平台 / 登记键 / 平台已开启）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_package_features_validations() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    insert_package(db, None).await;
    let svc: &SysTenantService = &ctx.state.tenant_service;

    let dto = |features: std::collections::HashMap<String, String>| PackageFeaturesUpdateDto {
        package_id: PACKAGE_ID,
        features,
    };

    // 非平台操作者一律 403（即使能力位合法也不放行）
    let err = svc
        .set_package_features(dto(Default::default()), "it_cap_tid_admin", TID)
        .await
        .expect_err("租户操作者不得配置套餐能力位");
    assert_eq!(err.code, 403, "非平台操作者应被拒（403），实际 {err:?}");

    // 未登记能力位键 ⇒ 400（不静默忽略，避免"以为开了其实没开"）
    let err = svc
        .set_package_features(
            dto(std::collections::HashMap::from([(
                "not.a.feature".to_string(),
                "on".to_string(),
            )])),
            "it_cap_admin",
            0,
        )
        .await
        .expect_err("未登记能力位键应被拒绝");
    assert_eq!(err.code, 400, "未登记键应 400，实际 {err:?}");

    // 平台未开启 ⇒ 套餐不得开启（400，避免"租户开了但平台没开"的假入口）
    let err = svc
        .set_package_features(
            dto(std::collections::HashMap::from([(
                "tenant.domain_self_service".to_string(),
                "full".to_string(),
            )])),
            "it_cap_admin",
            0,
        )
        .await
        .expect_err("平台未开启的能力位不得被套餐开启");
    assert_eq!(err.code, 400, "平台未开启项应 400，实际 {err:?}");

    // 空对象（全关闭）合法：落 NULL 且不报错
    let vo = svc
        .set_package_features(dto(Default::default()), "it_cap_admin", 0)
        .await
        .expect("清空能力位应成功");
    assert!(vo.overrides.is_empty(), "空对象应落 NULL（= 全默认）");
    let row = sys_tenant_package::Entity::find_by_id(PACKAGE_ID)
        .one(db)
        .await
        .expect("查询套餐失败")
        .expect("套餐应存在");
    assert_eq!(row.features, None, "全默认应落 NULL 而非 '{{}}'");
}

/// ④ **收敛面独立于菜单白名单**：`menu_ids = NULL` 时也必须回收"已不可授予"的菜单
///
/// 可证伪：若把两个收敛面合成"仅白名单裁剪"（`menu_ids` 为 NULL 即提前返回），
/// 本用例的域名菜单不会被回收 ⇒ 变红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_convergence_revokes_ungrantable_even_without_menu_whitelist() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    // 套餐 menu_ids = NULL（不限制菜单）⇒ 唯一收敛面只能是"能力位/可授予性"
    insert_package(db, Some(r#"{"tenant.domain_self_service":"full"}"#)).await;
    insert_tenant_with_package(db).await;
    insert_role(db).await;

    let menu_id = domain_menu_id(db).await;
    grant_menu(db, ROLE_ID, menu_id).await;
    assert!(
        has_menu(db, ROLE_ID, menu_id).await,
        "前置：域名菜单已授予租户角色"
    );

    let package = sys_tenant_package::Entity::find_by_id(PACKAGE_ID)
        .one(db)
        .await
        .expect("查询套餐失败")
        .expect("套餐应存在");
    ctx.state
        .tenant_service
        .converge_tenant_role_menus(TID, &package)
        .await
        .expect("收敛应成功");

    assert!(
        !has_menu(db, ROLE_ID, menu_id).await,
        "平台未开启该能力位时，菜单白名单为 NULL 也必须回收平台专属菜单授权\
         （否则残留「菜单可见但请求 403」的假入口）"
    );
}
