// axum-backend/src/integration_tests.rs
//! 集成冒烟测试 harness —— 端到端验证 login → getInfo 链路
//!
//! 设计要点（隔离、可重复、无副作用）：
//! - 使用临时 sqlite 文件（每次运行唯一路径），由 `migrator::Migrator::up` 建表 + 种子数据，
//!   不触碰开发/生产数据库。
//! - 使用独立的 Redis DB 索引（默认 15），测试开始 `FLUSHDB` 清空，避免污染开发 Redis。
//! - 复用与生产完全一致的初始化路径（Settings → init_database → init_redis →
//!   IpLocator/IpLocationService → JobScheduler → AppState → build_app），
//!   仅替换 DB/Redis 连接目标，确保测试的是真实运行栈。
//! - 种子数据中 `sys.account.captchaEnabled` 被强制改为 `false`，使 login 跳过验证码，
//!   否则初始迁移种下的值是 `true` 会要求验证码。
//!
//! 前置依赖：本机需有可达的 Redis（默认 127.0.0.1:6379，无密码）。
//! 若 Redis 不可用，`init_redis` 会在 5s 超时后返回错误，测试将以清晰信息失败。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use tower::ServiceExt;

use migration::Migrator;
use sea_orm_migration::MigratorTrait;

use crate::config::Settings;
use crate::db::{init_database, init_redis};
use crate::scheduler::JobScheduler;
use crate::service::IpLocationService;
use crate::state::AppState;
use crate::utils::ip_location::IpLocator;

/// 集成测试专用的 Redis DB 索引（与生产 DB0 隔离）。
const TEST_REDIS_DB: &str = "15";

/// 返回 config.toml 的绝对路径（基于 CARGO_MANIFEST_DIR，避免 cwd 依赖）。
fn manifest_config_path() -> String {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    format!("{}/config/config.toml", dir)
}

/// 生成每次运行唯一的临时 sqlite 文件路径，保证隔离、不残留旧 schema/数据。
fn unique_temp_db_path() -> String {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("yebot_it_{}_{}.db", pid, nanos));
    p.to_string_lossy().to_string()
}

/// 构造隔离的 `Arc<AppState>`：
/// 1. 加载生产配置并覆盖 database.url / redis.url 为隔离目标；
/// 2. 初始化 DB 并跑全部迁移（建表 + 种子 admin/admin123）；
/// 3. 清空隔离 Redis DB，并强制关闭验证码开关；
/// 4. 按生产路径组装 IpLocator / IpLocationService / JobScheduler / AppState。
async fn build_isolated_state() -> Arc<AppState> {
    // validate_secrets 拒绝占位密钥，这里通过环境变量注入一个合法强密钥（≥32 字符），
    // apply_env_overrides 会在 from_file 内部覆盖 config.toml 的占位 secret。
    // validate_secrets 拒绝占位密钥，这里通过环境变量注入一个合法强密钥（≥32 字符），
    // apply_env_overrides 会在 from_file 内部覆盖 config.toml 的占位 secret。
    // set_var 为 unsafe（进程级环境，测试单线程阶段调用无并发竞争）。
    unsafe {
        std::env::set_var(
            "JWT_SECRET",
            "a-very-long-jwt-secret-key-for-testing-32+chars",
        );
    }

    let mut settings = Settings::from_file(&manifest_config_path())
        .expect("加载 config/config.toml 失败（请确认 cwd 或 CARGO_MANIFEST_DIR 正确）");

    let db_path = unique_temp_db_path();
    settings.database.url = format!("sqlite://{}?mode=rwc", db_path);
    settings.redis.url = format!("redis://127.0.0.1:6379/{}", TEST_REDIS_DB);
    let settings = Arc::new(settings);

    // 2. 初始化 DB + 跑迁移（建表 + 种子数据）
    let db = init_database(&settings.database, false)
        .await
        .expect("初始化测试数据库失败");
    Migrator::up(&db, None).await.expect("运行迁移建表 + 种子数据失败");

    // 3. 初始化 Redis，清空隔离 DB，并关闭验证码开关
    let redis = init_redis(&settings.redis)
        .await
        .expect("连接测试 Redis 失败（请确认本机 Redis 可达，默认 127.0.0.1:6379）");
    let mut conn = redis.clone();
    redis::cmd("FLUSHDB")
        .query_async::<()>(&mut conn)
        .await
        .expect("清空隔离 Redis DB 失败");
    // 迁移种子把 captchaEnabled 种成 'true'，这里强制关掉，避免 login 要求验证码
    db.execute(Statement::from_string(
        DatabaseBackend::Sqlite,
        "UPDATE sys_config SET config_value='false' WHERE config_key='sys.account.captchaEnabled'",
    ))
    .await
    .expect("关闭验证码开关失败");

    // 4. 按生产路径组装（IP 库文件不存在时 IpLocator 优雅降级为空字符串）
    let ip_locator = Arc::new(IpLocator::new_with_xdb(
        &settings.ip_location.mmdb_path,
        &settings.ip_location.xdb_path,
        settings.ip_location.xdb_enabled,
    ));
    let ip_location_service =
        IpLocationService::new(db.clone(), settings.clone(), ip_locator.clone());
    let job_scheduler = Arc::new(
        JobScheduler::new(db.clone(), redis.clone(), ip_location_service.clone())
            .await
            .expect("创建调度器失败"),
    );
    let state = Arc::new(AppState::new(
        db,
        redis,
        settings,
        job_scheduler,
        ip_locator,
        ip_location_service,
    ));

    state
}

/// 构造一个带 ConnectInfo 的 POST /login 请求（login handler 需要 peer addr）。
fn login_request(body: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("构造 login 请求失败");
    // login handler 需要 ConnectInfo<SocketAddr>，oneshot 不会自动注入，这里手动补
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))));
    req
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_login_then_getinfo_smoke() {
    let state = build_isolated_state().await;
    let app = crate::router::build_app(state);

    // ---------- 1. 登录（admin / admin123，MD5 种子哈希，登录时自动升级为 Argon2）----------
    let login_body = serde_json::json!({
        "username": "admin",
        "password": "admin123",
        "code": "",
        "uuid": ""
    })
    .to_string();

    let resp = app
        .clone()
        .oneshot(login_request(&login_body))
        .await
        .expect("login 请求执行失败");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "登录应返回 HTTP 200"
    );

    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取 login 响应体失败");
    let v: serde_json::Value = serde_json::from_slice(&body).expect("login 响应 JSON 解析失败");
    assert_eq!(v["code"], 200, "login 业务码应为 200，实际: {:?}", v);
    let token = v["token"]
        .as_str()
        .expect("login 响应应包含 token")
        .to_string();
    assert!(!token.is_empty(), "token 不应为空");

    // ---------- 2. 携带 token 获取用户信息 ----------
    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/getInfo")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .expect("构造 getInfo 请求失败"),
        )
        .await
        .expect("getInfo 请求执行失败");
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "getInfo（带有效 token）应返回 HTTP 200"
    );

    let body2 = to_bytes(resp2.into_body(), usize::MAX)
        .await
        .expect("读取 getInfo 响应体失败");
    let v2: serde_json::Value =
        serde_json::from_slice(&body2).expect("getInfo 响应 JSON 解析失败");
    assert_eq!(v2["code"], 200, "getInfo 业务码应为 200，实际: {:?}", v2);
    assert_eq!(
        v2["user"]["userName"].as_str(),
        Some("admin"),
        "getInfo 应返回 admin 用户，实际: {:?}",
        v2
    );

    let roles = v2["roles"].as_array().expect("roles 应为数组");
    assert!(
        roles.iter().any(|r| r.as_str() == Some("admin")),
        "admin 用户的 roles 应包含 'admin'，实际: {:?}",
        v2
    );
    let perms = v2["permissions"].as_array().expect("permissions 应为数组");
    assert!(
        perms.iter().any(|p| p.as_str() == Some("*:*:*")),
        "admin 用户的 permissions 应包含 '*:*:*'，实际: {:?}",
        v2
    );

    // ---------- 3. 无 token 访问受保护接口 → 401 ----------
    let resp3 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/getInfo")
                .body(Body::empty())
                .expect("构造无 token getInfo 请求失败"),
        )
        .await
        .expect("无 token getInfo 请求执行失败");
    assert_eq!(
        resp3.status(),
        StatusCode::UNAUTHORIZED,
        "无 token 访问受保护接口应返回 401"
    );

    // ---------- 4. 伪造 token 访问受保护接口 → 401 ----------
    let resp4 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/getInfo")
                .header("authorization", "Bearer not.a.real.token")
                .body(Body::empty())
                .expect("构造伪造 token getInfo 请求失败"),
        )
        .await
        .expect("伪造 token getInfo 请求执行失败");
    assert_eq!(
        resp4.status(),
        StatusCode::UNAUTHORIZED,
        "伪造 token 访问受保护接口应返回 401"
    );
}
