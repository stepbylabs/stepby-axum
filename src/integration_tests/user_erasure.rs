// backend-axum/src/integration_tests/user_erasure.rs
//! GDPR 被遗忘权 / 用户匿名化 集成测试（能力位 `privacy.user_erasure`）。
//!
//! 复用全局 `TestContext` harness（隔离 sqlite + 独占 Redis DB + 真实 `build_app` 路由栈），
//! 覆盖能力位三档与守卫顺序：
//! ① `off`（默认）⇒ 端点 404；② `precheck` ⇒ 预检可用（**断言不产生任何写入**），执行端点 404；
//! ③ `full` ⇒ 执行成功（字段置换 + 凭据吊销）且**重复执行幂等**；
//! ④ 非平台操作者（`tid != 0`）⇒ 404；⑤ 平台用户 / 超管（`user_id == 1`）⇒ 400。
//!
//! 平台层能力位**按实例**注入（见 `TestContext::new_with_features`）：生产由 `config.toml
//! [features]` 经 `initialize` 注入进程级 `OnceLock`（不可按用例翻转），故 harness 改为把
//! 覆盖写进 `Settings.features`，由服务层按实例读取 —— 与启动注入同源同口径。

use std::net::SocketAddr;

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

use super::TestContext;
use crate::entity::sys_oauth_user::ActiveModel as OAuthUserActiveModel;
use crate::entity::sys_pat::ActiveModel as PatActiveModel;
use crate::entity::sys_user::{ActiveModel as UserActiveModel, Entity as SysUser};
use crate::jwt::JwtUtils;
use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request, StatusCode};

const FEATURE: &str = "privacy.user_erasure";
const TID: i64 = 9070;

/// 插入一个**租户用户**（`tenant_id = TID != 0`，可被匿名化），返回 user_id。
async fn insert_tenant_user(db: &DatabaseConnection, user_name: &str) -> i64 {
    let am = UserActiveModel {
        user_name: Set(user_name.to_string()),
        nick_name: Set("被遗忘者".to_string()),
        email: Set(Some("erase-me@example.com".to_string())),
        phonenumber: Set(Some("13800000000".to_string())),
        sex: Set(Some("0".to_string())),
        avatar: Set(Some("/avatar/x.png".to_string())),
        password: Set(Some("$argon2id$fake-hash".to_string())),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        login_ip: Set(Some("10.0.0.9".to_string())),
        remark: Set(Some("PII".to_string())),
        tenant_id: Set(TID),
        create_by: Set(Some("admin".to_string())),
        ..Default::default()
    };
    am.insert(db).await.expect("插入租户用户失败").user_id
}

/// 插入一个**平台用户**（`tenant_id == 0`，不可被匿名化）。
async fn insert_platform_user(db: &DatabaseConnection, user_name: &str) -> i64 {
    let am = UserActiveModel {
        user_name: Set(user_name.to_string()),
        nick_name: Set("平台用户".to_string()),
        status: Set(Some("0".to_string())),
        del_flag: Set(Some("0".to_string())),
        tenant_id: Set(0),
        ..Default::default()
    };
    am.insert(db).await.expect("插入平台用户失败").user_id
}

/// 用当前测试进程的 JWT 配置签发一份指定 `tid` 的合成令牌（复用超管主体通过 RBAC）。
fn token_with_tid(ctx: &TestContext, tid: i64) -> String {
    let (token, _claims) = JwtUtils::generate_token("1", "admin", &ctx.state.config.jwt, 0, tid)
        .expect("签发合成租户令牌失败");
    token
}

/// 构造带指定 Bearer 令牌 + ConnectInfo 的 GET/POST 请求。
fn auth_req(ctx: &TestContext, method: Method, token: &str, uri: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("构造请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((ctx.peer_ip, 4321))));
    req
}

fn precheck_uri(uid: i64) -> String {
    format!("/system/user/{uid}/anonymize/precheck")
}

fn execute_uri(uid: i64) -> String {
    format!("/system/user/{uid}/anonymize")
}

/// ① 能力位 `off`（默认）⇒ 预检与执行端点均 404（关闭态端点表现为"不存在"）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_erasure_capability_off_returns_404() {
    let ctx = TestContext::new().await; // 默认：平台层全 off
    let uid = insert_tenant_user(&ctx.state.db, "erasure_off_u").await;

    let (status, _v) = ctx
        .send_raw(auth_req(&ctx, Method::GET, &ctx.token, &precheck_uri(uid)))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "关闭态预检应 404");

    let (status, _v) = ctx
        .send_raw(auth_req(&ctx, Method::POST, &ctx.token, &execute_uri(uid)))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "关闭态执行应 404");
}

/// ② `precheck` 档：预检可用且**不产生任何写入**；执行端点仍 404。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_erasure_precheck_only_is_readonly_and_blocks_execute() {
    let ctx = TestContext::new_with_features(&[(FEATURE, "precheck")]).await;
    let uid = insert_tenant_user(&ctx.state.db, "erasure_pre_u").await;

    // 预检：返回报告（字段清单 + 计数），HTTP 200
    let v = ctx.get_json(&precheck_uri(uid)).await;
    let report = &v["data"];
    assert_eq!(report["userId"], uid);
    assert_eq!(report["alreadyAnonymized"], false);
    assert!(
        report["fields"].as_array().is_some_and(|f| f.len() >= 10),
        "预检应返回字段清单，实际 {v}"
    );
    assert_eq!(report["patCount"], 0);
    assert_eq!(report["ssoBindingCount"], 0);

    // **无写入**：目标行完全未被改动
    let row = SysUser::find_by_id(uid)
        .one(&ctx.state.db)
        .await
        .expect("查询用户失败")
        .expect("用户应存在");
    assert_eq!(row.user_name, "erasure_pre_u", "预检不得改动 user_name");
    assert_eq!(row.nick_name, "被遗忘者", "预检不得改动 nick_name");
    assert_eq!(row.email.as_deref(), Some("erase-me@example.com"));
    assert_eq!(row.del_flag.as_deref(), Some("0"), "预检不得软删除");
    assert!(row.password.is_some(), "预检不得清空密码");

    // 执行端点：档位不足 ⇒ 404
    let (status, _v) = ctx
        .send_raw(auth_req(&ctx, Method::POST, &ctx.token, &execute_uri(uid)))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "precheck 档下执行应 404");
}

/// ③ `full` 档：执行成功（字段置换 + PAT 吊销）且重复执行**幂等**。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_erasure_full_executes_and_is_idempotent() {
    let ctx = TestContext::new_with_features(&[(FEATURE, "full")]).await;
    let uid = insert_tenant_user(&ctx.state.db, "erasure_full_u").await;

    // 造一条有效 PAT + 一条第三方绑定，供计数与吊销断言
    PatActiveModel {
        tenant_id: Set(TID),
        pat_id: Set(format!("pat-erasure-{uid}")),
        user_id: Set(uid),
        name: Set("it-token".to_string()),
        token_hash: Set(format!("hash-erasure-{uid}")),
        token_prefix: Set("ybt_it".to_string()),
        scopes: Set("[]".to_string()),
        status: Set("0".to_string()),
        create_by: Set("admin".to_string()),
        ..Default::default()
    }
    .insert(&ctx.state.db)
    .await
    .expect("插入 PAT 失败");

    OAuthUserActiveModel {
        tenant_id: Set(TID),
        user_id: Set(uid),
        provider: Set("github".to_string()),
        provider_user_id: Set(format!("gh-{uid}")),
        ..Default::default()
    }
    .insert(&ctx.state.db)
    .await
    .expect("插入第三方绑定失败");

    // 执行
    let v = ctx
        .post_json(&execute_uri(uid), serde_json::json!({}))
        .await;
    let report = &v["data"];
    assert_eq!(report["alreadyAnonymized"], false);
    assert_eq!(report["patCount"], 1, "预检计数应含 1 条有效 PAT，实际 {v}");
    assert_eq!(
        report["ssoBindingCount"], 1,
        "应含 1 条第三方绑定，实际 {v}"
    );

    // 字段置换断言
    let row = SysUser::find_by_id(uid)
        .one(&ctx.state.db)
        .await
        .expect("查询用户失败")
        .expect("用户应存在");
    assert_eq!(
        row.user_name,
        format!("deleted_{uid}"),
        "登录键应置换为 deleted_{{id}}"
    );
    assert_eq!(row.nick_name, "已注销用户");
    assert_eq!(row.email, None);
    assert_eq!(row.phonenumber, None);
    assert_eq!(row.sex, None);
    assert_eq!(row.avatar, None);
    assert_eq!(row.remark, None);
    assert_eq!(row.login_ip, None);
    assert_eq!(row.password, None, "密码应清空（不可再登录）");
    assert_eq!(row.status.as_deref(), Some("1"), "应停用");
    assert_eq!(row.del_flag.as_deref(), Some("2"), "应软删除");
    assert_eq!(row.update_by.as_deref(), Some("admin"));

    // PAT 已吊销
    let pat = crate::entity::sys_pat::Entity::find()
        .filter(crate::entity::sys_pat::Column::UserId.eq(uid))
        .one(&ctx.state.db)
        .await
        .expect("查询 PAT 失败")
        .expect("PAT 应存在");
    assert_eq!(pat.status, "1", "匿名化应即时吊销该用户全部 PAT");

    // 会话失效标记已写入（pwd_ver）
    let mut redis = ctx.redis();
    let ver: Option<String> = redis::cmd("GET")
        .arg(format!("pwd_ver:{uid}"))
        .query_async(&mut redis)
        .await
        .expect("读取 pwd_ver 失败");
    assert!(ver.is_some(), "匿名化应对 pwd_ver 递增（旧 JWT 立即失效）");

    // 幂等：重复执行 ⇒ 200、alreadyAnonymized=true、行仍为 deleted_{id}
    let v2 = ctx
        .post_json(&execute_uri(uid), serde_json::json!({}))
        .await;
    assert_eq!(
        v2["data"]["alreadyAnonymized"], true,
        "重复执行应幂等，实际 {v2}"
    );
    let row2 = SysUser::find_by_id(uid)
        .one(&ctx.state.db)
        .await
        .expect("查询用户失败")
        .expect("用户应存在");
    assert_eq!(row2.user_name, format!("deleted_{uid}"));
    assert_eq!(row2.nick_name, "已注销用户");
}

/// ④ 非平台操作者（`tid != 0`）⇒ 404（能力位已开启，证明 404 来自平台归属守卫）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_erasure_platform_only_guard_returns_404_for_tenant_operator() {
    let ctx = TestContext::new_with_features(&[(FEATURE, "full")]).await;
    let uid = insert_tenant_user(&ctx.state.db, "erasure_tid_u").await;
    let tenant_token = token_with_tid(&ctx, TID);

    // 前置：合成租户令牌可通过鉴权/权限层（超管短路）
    let (status, _v) = ctx
        .send_raw(auth_req(&ctx, Method::GET, &tenant_token, "/getInfo"))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "前置校验：合成令牌应能访问 /getInfo"
    );

    let (status, _v) = ctx
        .send_raw(auth_req(
            &ctx,
            Method::GET,
            &tenant_token,
            &precheck_uri(uid),
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "非平台操作者预检应 404");

    let (status, _v) = ctx
        .send_raw(auth_req(
            &ctx,
            Method::POST,
            &tenant_token,
            &execute_uri(uid),
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "非平台操作者执行应 404");
}

/// ⑤ 平台用户（`tenant_id == 0`）或超管（`user_id == 1`）⇒ 400（拒绝）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_erasure_rejects_platform_user_and_super_admin() {
    let ctx = TestContext::new_with_features(&[(FEATURE, "full")]).await;
    let platform_uid = insert_platform_user(&ctx.state.db, "erasure_plat_u").await;

    // 平台用户 ⇒ 400
    let (status, v) = ctx
        .send_raw(auth_req(
            &ctx,
            Method::POST,
            &ctx.token,
            &execute_uri(platform_uid),
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "平台用户不可匿名化，实际 {v}"
    );

    // 超管（user_id == 1）⇒ 400
    let (status, v) = ctx
        .send_raw(auth_req(&ctx, Method::POST, &ctx.token, &execute_uri(1)))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "超管不可匿名化，实际 {v}");

    // 超管行未被改动
    let admin = SysUser::find_by_id(1)
        .one(&ctx.state.db)
        .await
        .expect("查询超管失败")
        .expect("超管应存在");
    assert_eq!(admin.user_name, "admin", "超管登录名不得被改动");
    assert_eq!(admin.del_flag.as_deref(), Some("0"), "超管不得被软删除");
}
