// stepby-axum/src/integration_tests/capability_features.rs
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

/// ⑤ **UI 入口下发跟随能力位/展示开关，且不与端点可用性漂移**（第二十一批修复的回归锁）
///
/// # 本用例锁定的真实缺陷
///
/// `GetInfoVo` 一直**算好了** `show_tenant_column` / `show_tenant_filter`，但 handler 的
/// `GetInfoResult` **从未包含**这两个字段 ⇒ 前端 `userStore.showTenantColumn` 恒为 `false`
/// ⇒ F-6「所属租户」归属列 /「按租户筛选」入口**实际从未出现**（前端只 mock API 的单测与
/// e2e 均无此断言，故长期未被发现）。本用例断言字段**真的存在**。
///
/// 同时锁定第二十批实测到的 404 假入口：能力位 `auth.webauthn` 关闭时
/// `GET /system/user/webauthn/credentials` 为 404，故 `getInfo.showPasskey` 与
/// `captchaImage.webauthnEnabled` 必须为 `false`；开启时必须为 `true`（同一判据）。
///
/// # 可证伪性
///
/// - 把 `GetInfoResult::show_tenant_column` 字段删掉 ⇒ 第①段 `is_boolean()` 立即变红
///   （这正是修复前的状态）。
/// - 若 `showPasskey` 改成"恒 true"或改用别的判据 ⇒ 第①段与 404 的交叉断言变红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ui_entry_flags_are_delivered_and_follow_capability() {
    // ---------- ① 默认姿态：能力位全 off、[ui] 默认（auto / off） ----------
    let ctx = TestContext::new().await;
    let info = ctx.get_json("/getInfo").await;
    assert!(
        info["showTenantColumn"].is_boolean(),
        "getInfo 必须下发 showTenantColumn（修复前 handler 漏该字段 ⇒ 前端恒 false）：{info}"
    );
    assert_eq!(
        info["showTenantColumn"], true,
        "[ui].show_tenant_column=auto + 平台操作者（tid=0）⇒ 归属列可见（历史行为）"
    );
    assert!(
        info["showTenantFilter"].is_boolean(),
        "getInfo 必须下发 showTenantFilter（修复前同样漏字段）"
    );
    assert_eq!(
        info["showTenantFilter"], false,
        "[ui].tenant_filter 默认 off"
    );
    assert_eq!(
        info["showPasskey"], false,
        "能力位 auth.webauthn 默认 off ⇒ 不下发通行密钥入口"
    );
    // 本批 +3 布场（PAT / SSO Grants / 字段权限）默认姿态（测试基线已钳制为代码内建
    // 默认，不随本机 config.toml / .env 漂移，见 build_isolated_state_with）：
    // [pat].enabled 默认 true ⇒ PAT 页签下发；[sso].enabled 默认 **false**（默认关闭，
    // 与模板起步一致）⇒ SSO 页签隐藏；sys.fieldPerm.enabled 默认 false ⇒ 字段权限按钮隐藏。
    assert_eq!(
        info["showPat"], true,
        "[pat].enabled 默认 true ⇒ 下发 API 访问令牌页签入口（现状行为）"
    );
    assert_eq!(
        info["showSsoGrants"], false,
        "[sso].enabled 默认 false（默认关闭）⇒ 不下发已授权应用页签（关闭态 OIDC 端点\
         不注册，显示即假入口）；置 true 时本断言变红 ⇒ 同步核对入口显示与端点可用联动"
    );
    assert_eq!(
        info["showFieldPerm"], false,
        "sys.fieldPerm.enabled 默认 false ⇒ 不下发字段权限按钮（与矩阵接口 403 守卫同源）"
    );

    let captcha = ctx.get_json("/captchaImage").await;
    assert_eq!(
        captcha["webauthnEnabled"], false,
        "登录页 passkey 入口开关必须与同一能力位同源"
    );

    // 交叉锁（负向）：入口开关为 false ⇒ 端点必须**确实不可用**（否则即"入口可见但请求 404"或反之）
    let (status, body) = ctx
        .send_raw(ctx.request(
            axum::http::Method::GET,
            "/system/user/webauthn/credentials",
            None,
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "能力位关闭时 WebAuthn 自助端点应为 404（与 showPasskey=false 同源），实际 {status} {body}"
    );

    // ---------- ② 开启能力位 + 显式展示开关（并配好 RP 信任锚，使端点真的可用） ----------
    let ctx = TestContext::new_with(&[("auth.webauthn", "on")], |s| {
        s.ui.show_tenant_column = "never".to_string();
        s.ui.tenant_filter = "platform".to_string();
        s.webauthn.rp_id = "localhost".to_string();
        s.webauthn.origin = "http://localhost".to_string();
    })
    .await;
    let info = ctx.get_json("/getInfo").await;
    assert_eq!(
        info["showTenantColumn"], false,
        "[ui].show_tenant_column=never ⇒ 平台操作者亦不可见（证明下发值真的随配置变化）"
    );
    assert_eq!(
        info["showTenantFilter"], true,
        "[ui].tenant_filter=platform + 平台操作者 ⇒ 提供筛选入口"
    );
    assert_eq!(
        info["showPasskey"], true,
        "能力位 auth.webauthn=on ⇒ 下发通行密钥入口"
    );
    let captcha = ctx.get_json("/captchaImage").await;
    assert_eq!(captcha["webauthnEnabled"], true);

    // 交叉锁（正向）：入口开关为 true ⇒ 端点必须真的可用（200，而非仅"不是 404"）
    let (status, body) = ctx
        .send_raw(ctx.request(
            axum::http::Method::GET,
            "/system/user/webauthn/credentials",
            None,
        ))
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "能力位开启且 RP 已配置时端点应可用，实际 {status} {body}"
    );
}

/// ⑥ **启动期授权收敛核心**（§5.17）：平台层关闭时回收存量"曾经可授予"授权 + 幂等零删除。
///
/// 可证伪性：
/// - 若 `converge_tenant_role_menus_conn` 忘了带能力位判定（只做白名单裁剪），
///   `menu_ids = NULL` 时提前返回 ⇒ 第一段断言 `removed >= 1` 变红（菜单未被回收）；
/// - 若核心不幂等（无收敛面时仍执行删除/返回非零）⇒ 第二段 `removed == 0` 变红。
///
/// 测试策略：本用例直驱收敛核心（按租户 ID 收敛，命名空间隔离安全）；
/// 启动编排函数（`initialize::converge_tenant_grants_on_startup`）为薄编排
/// （查询 + 循环 + 缓存失效），不单独直测。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_startup_convergence_conn_recovers_and_is_idempotent() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    // 套餐声明 domain full，但测试进程平台层能力位默认全关 ⇒ 有效能力集 = off
    // ⇒ domain 菜单不可授予（用例① 已锁此判定）⇒ 属于启动期收敛的回收对象
    insert_package(db, Some(r#"{"tenant.domain_self_service":"full"}"#)).await;
    insert_tenant_with_package(db).await;
    insert_role(db).await;
    let menu_id = domain_menu_id(db).await;
    grant_menu(db, ROLE_ID, menu_id).await;
    assert!(has_menu(db, ROLE_ID, menu_id).await);

    let package = crate::entity::sys_tenant_package::Entity::find_by_id(PACKAGE_ID)
        .one(db)
        .await
        .expect("查询套餐失败")
        .expect("套餐应存在");

    // 第一轮：平台层关闭 ⇒ domain 授权被回收
    let removed = crate::service::sys_tenant_service::converge_tenant_role_menus_conn(
        db, TID, &package,
    )
    .await
    .expect("收敛核心执行失败");
    assert!(
        removed >= 1,
        "平台层关闭时存量不可授予授权必须被回收（实际删除 {removed} 行）"
    );
    assert!(
        !has_menu(db, ROLE_ID, menu_id).await,
        "回收后 sys_role_menu 行必须不存在"
    );

    // 第二轮：幂等——无收敛面（不可授予集合仅剩该行且已删）⇒ 零删除
    // 注意：menu_ids=NULL（不限制）⇒ 白名单面不触发；不可授予面第一轮已清空
    // ⇒ 但不可授予集合本身来自全菜单表（仍有不可授予 perms 清单），
    //   判定零删除靠"该租户角色已无可删行"路径（role_ids 仍有 ⇒ 靠 predicate 不命中）。
    let removed2 = crate::service::sys_tenant_service::converge_tenant_role_menus_conn(
        db, TID, &package,
    )
    .await
    .expect("二次收敛执行失败");
    assert_eq!(
        removed2, 0,
        "幂等约束：第一轮回收后第二轮必须零删除（实际 {removed2}）"
    );
}

/// ⑦ **单机模式（`[tenant].management = false`）租户语义面全收敛**（§5.20）。
///
/// 单机部署不存在租户语义 ⇒ 租户相关展示面整体隐藏：
/// - `getInfo` 的 `showTenantColumn` / `showTenantFilter` 强制 false
///   （归属列/筛选入口 4+1 页面全站收敛的**单一布场**）；
/// - `getRouters` 无「租户管理」菜单（`prune_tenant_management_menus`，含超管）。
///
/// 可证伪性：若 get_info 忘了带 management 门控，第①段断言 true≠false 变红；
/// 若 get_routers 剪除被绕过，第②段含 "system/tenant/index" 变红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_standalone_mode_hides_all_tenant_surfaces() {
    let ctx = TestContext::new_with(&[], |s| {
        s.tenant.management = false;
    })
    .await;

    // ① 展示布场：归属列/筛选入口强制隐藏（[ui] 保持默认 auto/off——单机模式优先级更高）
    let info = ctx.get_json("/getInfo").await;
    assert_eq!(
        info["showTenantColumn"], false,
        "单机模式下「所属租户」列必须强制隐藏（auto + 平台操作者也不例外）"
    );
    assert_eq!(
        info["showTenantFilter"], false,
        "单机模式下「按租户筛选」入口必须强制隐藏"
    );

    // ② 路由树：全部租户语义菜单被剪除（超管也生效；§5.21 全收敛——含域名/导航）。
    //    断言用 component 精确页面前缀："system/tenant/index"（租户管理页）与
    //    "system/tenant/domain/index"（我的域名）不出现。
    let routers = ctx.get_json("/getRouters").await;
    let flat = routers["data"].to_string();
    assert!(
        !flat.contains("system/tenant/index"),
        "单机模式 getRouters 不得含租户管理菜单：{flat}"
    );
    assert!(
        !flat.contains("system/tenant/domain/index"),
        "单机模式 getRouters 不得含我的域名菜单（域名绑定依赖多租户）：{flat}"
    );

    // ③ 平台侧租户语义 API 硬拒（含超管；§5.21 全收敛——含域名自助与 L3 导航端点）
    for path in [
        "/system/tenant/list?pageNum=1&pageSize=1",
        "/system/tenant/domain/list",
        "/system/tenant/menu/list",
    ] {
        let (status, _) = ctx
            .send_raw(ctx.request(axum::http::Method::GET, path, None))
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "单机模式平台侧租户语义端点应 403（含超管）: {path}，实际 {status}"
        );
    }
}
