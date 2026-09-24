// axum-backend/src/integration_tests/tenant_scope.rs
//! v5-N2 Phase 2：多租户过滤层行为验证（service 层直调，绕过 RBAC 以专测过滤）。
//!
//! 覆盖：平台管理员（tid=0）全量可见（单租户行为等价）；租户管理员（tid=5）
//! 列表隔离（仅本租户）；跨租户读/写归属校验（404 语义隐藏存在性）；
//! add 归属写入（租户管理员创建的资源自动归属本租户）。

use super::TestContext;
use crate::service::sso_service::{SsoClientQueryDto, SsoClientUpsertDto};
use sea_orm::{ConnectionTrait, Statement};

fn upsert_dto(name: &str) -> SsoClientUpsertDto {
    SsoClientUpsertDto {
        sso_client_id: 0,
        client_id: None,
        client_name: name.to_string(),
        logo_uri: None,
        redirect_uris: vec!["https://app.test/cb".to_string()],
        scopes: vec!["openid".to_string()],
        grant_types: Some(vec!["authorization_code".to_string()]),
        id_token_alg: None,
        subject_type: None,
        sector_identifier_uri: None,
        consent_required: Some("0".to_string()),
        enabled: Some("1".to_string()),
        remark: None,
    }
}

fn query_dto() -> SsoClientQueryDto {
    SsoClientQueryDto {
        page_num: None,
        page_size: None,
        client_name: None,
        client_id: None,
        enabled: None,
    }
}

/// 平台管理员全量 + 租户隔离 + 越权防护 + 归属写入
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tenant_scope_isolation() {
    let ctx = TestContext::new().await;
    let svc = &ctx.state.sso_service;

    // ① 平台管理员（tid=0）创建 client A（归属平台）
    let a = svc
        .add_client(upsert_dto("it_tenant_a"), "admin", 0)
        .await
        .unwrap();

    // ② 直改数据库：把 client A 归属租户 5（模拟租户数据）
    ctx.state
        .db
        .execute(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            format!(
                "UPDATE sys_oauth_client SET tenant_id = 5 WHERE sso_client_id = {}",
                a.client.sso_client_id
            ),
        ))
        .await
        .unwrap();
    // 平台管理员再建 client B（仍归属平台 tid=0）
    let b = svc
        .add_client(upsert_dto("it_tenant_b"), "admin", 0)
        .await
        .unwrap();

    // ③ 平台管理员（tid=0）全量可见（单租户行为等价）
    let (rows, total) = svc.get_client_page(query_dto(), 0).await.unwrap();
    assert_eq!(total, 2, "平台管理员应见全部 2 条");
    assert!(
        rows.iter()
            .any(|r| r.sso_client_id == a.client.sso_client_id)
    );
    assert!(
        rows.iter()
            .any(|r| r.sso_client_id == b.client.sso_client_id)
    );

    // ④ 租户管理员（tid=5）列表隔离：仅见本租户的 client A
    let (rows, total) = svc.get_client_page(query_dto(), 5).await.unwrap();
    assert_eq!(total, 1, "租户管理员应仅见本租户 1 条");
    assert_eq!(rows[0].sso_client_id, a.client.sso_client_id);

    // ⑤ 跨租户读 → 404（隐藏存在性）
    let err = svc
        .get_client_by_pk(b.client.sso_client_id, 5)
        .await
        .unwrap_err();
    assert_eq!(err.code, 404, "跨租户读应 404");
    // 本租户读 → 正常
    let vo = svc
        .get_client_by_pk(a.client.sso_client_id, 5)
        .await
        .unwrap();
    assert_eq!(vo.sso_client_id, a.client.sso_client_id);

    // ⑥ 跨租户写（edit/toggle/delete）→ 404
    let mut edit_dto = upsert_dto("it_tenant_b_hijack");
    edit_dto.sso_client_id = b.client.sso_client_id;
    let err = svc
        .edit_client(edit_dto, "tenant5-admin", 5)
        .await
        .unwrap_err();
    assert_eq!(err.code, 404, "跨租户改应 404");
    let err = svc
        .toggle_client(b.client.sso_client_id, "0", &mut ctx.state.redis.clone(), 5)
        .await
        .unwrap_err();
    assert_eq!(err.code, 404, "跨租户启停应 404");
    let err = svc
        .delete_clients(
            vec![b.client.sso_client_id],
            &mut ctx.state.redis.clone(),
            5,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, 404, "跨租户删应 404");

    // ⑦ 租户管理员 add → 资源自动归属本租户（tid=5）
    let c = svc
        .add_client(upsert_dto("it_tenant_c"), "tenant5-admin", 5)
        .await
        .unwrap();
    let vo = svc
        .get_client_by_pk(c.client.sso_client_id, 5)
        .await
        .unwrap();
    assert_eq!(
        vo.sso_client_id, c.client.sso_client_id,
        "本租户可见自建资源"
    );
    let err = svc
        .get_client_by_pk(c.client.sso_client_id, 7)
        .await
        .unwrap_err();
    assert_eq!(err.code, 404, "其它租户（tid=7）不可见");

    // ⑧ 平台管理员对租户资源操作放行（tid=0 全量权限）
    svc.toggle_client(a.client.sso_client_id, "0", &mut ctx.state.redis.clone(), 0)
        .await
        .unwrap();
}
