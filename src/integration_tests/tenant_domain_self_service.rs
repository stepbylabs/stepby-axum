// axum-backend/src/integration_tests/tenant_domain_self_service.rs
//! 租户自助域名管理（批次 1c）回归锁 —— 能力位 `tenant.domain_self_service` 的**关闭态安全**。
//!
//! ## 背景
//!
//! 项目定位「大而全 + 用户可选可配置」：租户自助域名管理**不整块砍掉**，而是收敛为三层开关
//! （平台 `[features]` → 套餐 `features` → 角色授权）。本模块锁死**第一层关闭时的安全姿态**：
//! 平台层未开启（默认）时，租户操作者对域名管理 5 个端点**一律 403**，平台操作者不受影响。
//!
//! 「开启态」的行级语义（仅本租户 / 只能自定义域名 / 显式跨租户 403）由
//! `service::sys_tenant_domain_service::tests` 的纯函数单测覆盖——测试进程内平台层能力位
//! 是 `OnceLock` 单例，无法按用例翻转（翻转会污染 `capability_features` 用例①的"平台未开启"
//! 前提），故此处只做"真实 DB + 真实服务"的关闭态断言。
//!
//! ## 可证伪性（关键）
//!
//! - 若 `resolve_scope` 忘了检查能力位（直接返回 `Tenant(tid)`），本模块每条 `expect_err`
//!   都会 panic ⇒ 变红。
//! - 若把"租户操作者"误判为平台（`operator_tid == 0` 写成 `>= 0`），同样变红。
//! - 平台操作者断言提供**反向对照**：改造不得把平台侧一并锁死。
//!
//! 命名空间隔离：租户 9060、域名 `it-1c-*.yebot.test`，避免与其它用例冲突。

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

use super::TestContext;
use crate::entity::{sys_menu, sys_role_menu, sys_tenant_domain};
use crate::service::sys_tenant_domain_service::{
    SysTenantDomainService, TenantDomainAddDto, TenantDomainIdDto, TenantDomainStatusDto,
};

const TID: i64 = 9060;

/// 直插一条**归属 TID** 的域名行（不经过服务层，避免依赖平台写路径）
async fn insert_domain(db: &DatabaseConnection, domain: &str, tenant_id: i64) -> i64 {
    sys_tenant_domain::ActiveModel {
        domain_id: sea_orm::NotSet, // 自增主键，交由数据库生成
        tenant_id: Set(tenant_id),
        domain: Set(domain.to_string()),
        domain_type: Set("1".to_string()),
        is_primary: Set(Some("1".to_string())),
        verify_status: Set(Some("0".to_string())),
        verify_token: Set(Some("it-1c-token".to_string())),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        ..Default::default()
    }
    .insert(db)
    .await
    .expect("插入 sys_tenant_domain 失败")
    .domain_id
}

/// 关闭态安全：平台层未开启能力位时，租户操作者对**全部**域名端点 403
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_domain_self_service_denied_for_tenant_by_default() {
    let ctx = TestContext::new().await;
    assert!(
        !crate::common::features::platform_features().is_on("tenant.domain_self_service"),
        "本用例前提：平台层未开启该能力位（测试进程默认全 off）"
    );
    let svc: &SysTenantDomainService = &ctx.state.tenant_domain_service;

    // ① 列表：即便显式传自己的 tid 也必须 403（关闭态不降级为"只读本租户"）
    for requested in [None, Some(TID)] {
        let err = svc
            .list(requested, TID)
            .await
            .expect_err("关闭态下租户不得读取域名清单");
        assert_eq!(
            err.code, 403,
            "list(tenant_id={requested:?}) 应 403，实际 {err:?}"
        );
    }

    // ② 新增：归属自己也不行（能力位是唯一入口）
    let err = svc
        .add(
            TenantDomainAddDto {
                tenant_id: TID,
                domain: "it-1c-add.yebot.test".to_string(),
                domain_type: "1".to_string(),
                is_primary: None,
                remark: None,
            },
            "it_1c_admin",
            TID,
        )
        .await
        .expect_err("关闭态下租户不得新增域名");
    assert_eq!(err.code, 403, "add 应 403，实际 {err:?}");

    // ③ 验证 / 设主 / 启停 / 删除：均在**回查资源之前**就被拒（不泄漏"该 id 是否存在"）
    assert_eq!(
        svc.verify(1, "it_1c_admin", TID)
            .await
            .expect_err("关闭态下租户不得验证域名")
            .code,
        403
    );
    assert_eq!(
        svc.set_primary(TenantDomainIdDto { domain_id: 1 }, "it_1c_admin", TID)
            .await
            .expect_err("关闭态下租户不得设主域名")
            .code,
        403
    );
    assert_eq!(
        svc.change_status(
            TenantDomainStatusDto {
                domain_id: 1,
                status: "1".to_string(),
            },
            "it_1c_admin",
            TID
        )
        .await
        .expect_err("关闭态下租户不得启停域名")
        .code,
        403
    );
    assert_eq!(
        svc.remove(1, "it_1c_admin", TID)
            .await
            .expect_err("关闭态下租户不得删除域名")
            .code,
        403
    );
}

/// 关闭态菜单姿态：3900-3904 已登记（迁移/初始化双写生效），但**不授予任何角色**
///
/// 这是"关闭态即现状"的**可证伪**断言：若启动治理的回填步骤（①'）忽略能力位、
/// 无条件把已解锁前缀授予 role_id=2，本用例会变红。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_domain_self_service_menu_registered_but_ungranted_by_default() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    const PLATFORM_COMMON_ROLE: i64 = 2;

    for menu_id in [3900, 3901, 3902, 3903, 3904] {
        assert!(
            sys_menu::Entity::find_by_id(menu_id)
                .one(db)
                .await
                .expect("查询 sys_menu 失败")
                .is_some(),
            "菜单 {menu_id} 应已登记（迁移 m20260926_000011 / initialize 双写）"
        );
        let granted = sys_role_menu::Entity::find()
            .filter(sys_role_menu::Column::RoleId.eq(PLATFORM_COMMON_ROLE))
            .filter(sys_role_menu::Column::MenuId.eq(menu_id))
            .one(db)
            .await
            .expect("查询 sys_role_menu 失败")
            .is_some();
        assert!(
            !granted,
            "能力位默认关闭时，平台普通角色不得持有菜单 {menu_id}（关闭态即现状）"
        );
    }

    // 能力位关闭 ⇒ 域名管理菜单 perms 仍不可授予租户角色（与 ③ 层同源）
    let off = crate::common::features::FeatureSet::default();
    for perms in [
        "system:tenant:domain:list",
        "system:tenant:domain:add",
        "system:tenant:domain:verify",
        "system:tenant:domain:edit",
        "system:tenant:domain:remove",
    ] {
        assert!(
            !crate::common::features::is_grantable_perm_with_features(perms, &off),
            "{perms} 在能力位关闭态下必须不可授予"
        );
    }
}

/// 反向对照：平台操作者不受能力位影响（关闭态下仍可正常按租户过滤查询）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_domain_platform_operator_unaffected_by_capability() {
    let ctx = TestContext::new().await;
    let db = &ctx.state.db;
    let domain_id = insert_domain(db, "it-1c-platform.yebot.test", TID).await;
    assert!(domain_id > 0, "自增主键应回填");

    let svc: &SysTenantDomainService = &ctx.state.tenant_domain_service;
    // 平台操作者：可按 tid 过滤看到该行（含 verify_token，见 Vo 文档）
    let rows = svc
        .list(Some(TID), 0)
        .await
        .expect("平台操作者查询域名清单不应失败");
    let row = rows
        .iter()
        .find(|r| r.domain_id == domain_id)
        .expect("平台操作者应能看到刚插入的域名行");
    assert_eq!(row.tenant_id, TID);
    assert_eq!(row.verify_token.as_deref(), Some("it-1c-token"));
    // 平台操作者：不过滤也能查（全量视图）
    assert!(svc.list(None, 0).await.is_ok());
}
