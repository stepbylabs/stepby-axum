// stepby-axum/src/integration_tests/mod.rs
//! 集成测试（端到端验证核心业务链路）
//!
//! 设计要点（隔离、可重复、无副作用、可并行）：
//! - 每个测试使用独立的临时 sqlite 文件（唯一路径），由 `migrator::Migrator::up` 建表 + 种子数据，
//!   不触碰开发/生产数据库。
//! - 每个测试使用独立的 Redis DB 索引（1..=15，跨进程文件锁仲裁独占），`FLUSHDB` 清空，
//!   避免并行测试/并行测试进程互相干扰。
//! - 每个测试使用独立的 peer IP（10.77.x.y），隔离全局内存限流令牌桶，避免并行测试触发 429。
//! - 测试库中将限流 `*` 默认配置放大到 1,000,000 容量，进一步规避限流对测试的干扰。
//! - 复用与生产完全一致的初始化路径（Settings → init_database → init_redis →
//!   IpLocator/IpLocationService → JobScheduler → AppState → build_app），
//!   仅替换 DB/Redis 连接目标，确保测试的是真实运行栈。
//! - 种子数据中 `sys.account.captchaEnabled` 被强制改为 `false`，使 login 跳过验证码。
//!
//! 前置依赖：本机需有可达的 Redis（默认 127.0.0.1:6379，无密码）。
//! 若 Redis 不可用，`init_redis` 会在超时后返回错误，测试将以清晰信息失败。

mod ak_sign;
mod auth;
mod capability_features;
mod clear_fields;
mod common_handler;
mod common_search;
mod data_scope_tenant;
mod file_common;
mod flow;
mod i18n_keys;
mod ip_location;
mod menu_perm_contract;
mod monitor;
mod monitor_extra;
mod platform_guard;
mod response_cache;
mod scim;
mod scim_groups;
mod sso;
mod sys_backup;
mod sys_config_dict;
mod sys_frontend_error;
mod sys_http_debug;
mod sys_job;
mod sys_log_clean_export;
mod sys_logininfor;
mod sys_menu_dept;
mod sys_misc_extra;
mod sys_msg;
mod sys_notice;
mod sys_oauth;
mod sys_oper_log;
mod sys_pat;
mod sys_pat_owner_guard;
mod sys_post;
mod sys_rate_limit;
mod sys_report;
mod sys_report_board;
mod sys_role;
mod sys_task;
mod sys_user;
mod sys_user_extra;
mod sys_user_pref;
mod sys_web_hook;
mod tenant_binding_guard;
mod tenant_domain_self_service;
mod tenant_index_plan;
mod tenant_scope;
mod tool_gen;
mod totp;
mod user_erasure;
mod user_pii_masking;
mod webauthn;
mod webhook_tenant;
mod webhook_unify;
mod ws;

use std::fs::OpenOptions;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request};
use migration::Migrator;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::MigratorTrait;
use tower::ServiceExt;

use crate::config::Settings;
use crate::db::{init_database, init_redis};
use crate::scheduler::JobScheduler;
use crate::service::IpLocationService;
use crate::state::AppState;
use crate::utils::ip_location::IpLocator;

/// 测试专用 peer IP 分配器（轮询 10.77.x.y）。
/// 全局内存限流令牌桶按 IP 分桶，独立 IP 避免并行测试共享桶而触发 429。
static PEER_IP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// 幂等初始化测试日志订阅器（仅测试进程生效，用 `with_test_writer` 输出到测试捕获器）。
/// 级别由 `RUST_LOG` 控制（默认 warn），便于排查集成测试中的底层错误（如 DbErr）。
static TRACING_INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();

fn init_test_tracing() {
    TRACING_INIT.get_or_init(|| {
        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string());
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_new(&filter)
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_test_writer()
            .try_init();
    });
}

/// 测试专用临时 sqlite 文件序号（保证同进程内路径唯一，规避 Windows 时钟粒度下
/// `SystemTime::now().as_nanos()` 并发返回相同值导致两个测试共用同一 DB 文件）。
static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_peer_ip() -> IpAddr {
    let n = PEER_IP_COUNTER.fetch_add(1, Ordering::Relaxed);
    IpAddr::V4(Ipv4Addr::new(
        10,
        77,
        ((n >> 8) & 0xff) as u8,
        (n & 0xff) as u8,
    ))
}

/// 返回 config.toml 的绝对路径（基于 CARGO_MANIFEST_DIR，避免 cwd 依赖）。
fn manifest_config_path() -> String {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    format!("{}/config/config.toml", dir)
}

/// 集成测试可用 Redis DB 数（Redis 默认 16 个 DB，0 保留给 dev/8080 实例，1..=15 供测试独占）。
/// 槽位仲裁用**跨进程文件锁**：同进程并行用例与同时运行的多个全量测试进程
/// 各自独占一个 DB 索引，从根上杜绝「两个测试进程重叠时 freelist 各自为政 →
/// FLUSHDB 清掉对方正在使用的 DB」的互踩假失败。
const TEST_REDIS_DB_COUNT: u64 = 15;

/// 等待 Redis DB 槽位的总上限。
///
/// 正常情况下槽位随测试结束持续释放，排队用例很快就能拿到；只有当某个测试进程
/// 整体卡死（槽位永不释放）时才会触顶。这里刻意给足 10 分钟（远超单轮全量的
/// 2-3 分钟），宁可多等也不让排队用例假失败——与旧信号量设计的「无限排队」语义
/// 等价，仅保留一个防永久挂死的兜底。
const REDIS_SLOT_WAIT_TIMEOUT: Duration = Duration::from_secs(600);

/// 等待期间打 WARN 的间隔（便于诊断「谁占着槽位」）。
const REDIS_SLOT_WARN_INTERVAL: Duration = Duration::from_secs(30);

/// 尝试独占槽位 `i`：打开（或创建）锁文件 `%TEMP%/stepby_it_redis_db_{i}.lock`
/// 并尝试加跨进程排他文件锁（`std::fs::File::try_lock`，Rust ≥1.89 稳定）。
/// 加锁成功返回持有锁的 `File`（File 存活即持有锁，close/drop 自动释放）；
/// 被其它进程/用例占用（WouldBlock）或打开失败时返回 `None` 让路。
///
/// 为什么选文件锁而不是 Redis SETNX 租约：
/// - 进程被 kill / panic 时 OS 自动释放锁，无 TTL 续租与僵死租约问题；
/// - 锁文件从不删除（只留空文件），避免「A 解锁删除 → C 新建同名文件 → B 仍持旧
///   inode/fd」的经典删除竞争；
/// - 同进程内不同 `File` 句柄同样互斥（Windows LockFileEx 按句柄、Unix flock 按
///   open file description），进程内并行用例与跨进程天然同一套仲裁。
fn try_lock_slot(i: u64) -> Option<std::fs::File> {
    let path = std::env::temp_dir().join(format!("stepby_it_redis_db_{i}.lock"));
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .read(true)
        .open(&path)
        .ok()?;
    match file.try_lock() {
        Ok(()) => Some(file),
        Err(_) => None,
    }
}

/// 持有 Redis DB 占用权的守卫：字段 `db_index` 为本测试独占的 DB 索引，
/// `_lock` 是对锁文件 `%TEMP%/stepby_it_redis_db_{n}.lock` 的跨进程排他文件锁，
/// 结构体 drop（测试结束/panic）时 File 关闭、OS 自动释放锁。
pub struct RedisSlot {
    pub db_index: u64,
    _lock: std::fs::File,
}

/// 分配一个独占的 Redis DB 槽位（跨进程文件锁仲裁）。
/// 按序扫描 1..=15，全部被占则每 250ms 重扫一轮（持续等待，槽位随测试结束释放）；
/// 每 30s 打一条 WARN 便于诊断，总等待超过 10 分钟才 panic（防永久挂死兜底）。
async fn acquire_redis_slot() -> RedisSlot {
    let start = tokio::time::Instant::now();
    let mut last_warn = start;
    loop {
        for i in 1..=TEST_REDIS_DB_COUNT {
            if let Some(lock) = try_lock_slot(i) {
                return RedisSlot {
                    db_index: i,
                    _lock: lock,
                };
            }
        }
        let now = tokio::time::Instant::now();
        if now.duration_since(last_warn) >= REDIS_SLOT_WARN_INTERVAL {
            tracing::warn!(
                waited_secs = now.duration_since(start).as_secs(),
                "测试 Redis DB 槽位（1..=15）全部被占用，继续排队等待……\
                 （通常因多个测试进程并行或个别用例耗时较长）"
            );
            last_warn = now;
        }
        assert!(
            now.duration_since(start) < REDIS_SLOT_WAIT_TIMEOUT,
            "等待测试 Redis DB 槽位超时（>10 分钟）：1..=15 全部被占用且持续未释放，\
             请确认是否有卡死的 cargo test 进程未退出"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// 生成同进程内必然唯一的临时 sqlite 文件路径（pid + 单调序号），
/// 保证隔离、不残留旧 schema/数据、并行测试不撞文件。
fn unique_temp_db_path() -> String {
    let pid = std::process::id();
    let seq = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("stepby_it_{}_{}.db", pid, seq));
    p.to_string_lossy().to_string()
}

/// 构造隔离的 `(Arc<AppState>, RedisSlot)`：
/// 1. 加载生产配置并覆盖 database.url / redis.url 为隔离目标（独占 Redis DB 槽位）；
/// 2. 初始化 DB 并跑全部迁移（建表 + 种子 admin/admin123）；
/// 3. 清空隔离 Redis DB、强制关闭验证码开关、放大限流默认容量；
/// 4. 按生产路径组装 IpLocator / IpLocationService / JobScheduler / AppState。
///
/// 返回的 `RedisSlot` 必须由调用方持有至测试结束，以独占 Redis DB（drop 释放文件锁）。
async fn build_isolated_state() -> (Arc<AppState>, RedisSlot) {
    build_isolated_state_with_features(&[]).await
}

/// 与 [`build_isolated_state`] 相同，但允许注入**平台层能力位覆盖**（`[features]`）。
///
/// 为何需要：平台层能力位在生产由 `config.toml [features]` 提供并经 `initialize`
/// 注入进程级 `OnceLock`（不可按用例翻转）；本函数改为**按实例**把覆盖写进
/// `Settings.features`，使服务层读取的 `FeatureSet` 可按测试独立配置
/// （`UserErasureService` 即从 `config.features` 净化解析，与启动注入同口径）。
async fn build_isolated_state_with_features(
    features: &[(&str, &str)],
) -> (Arc<AppState>, RedisSlot) {
    build_isolated_state_with(features, |_| {}).await
}

/// 与 [`build_isolated_state_with_features`] 相同，但额外允许调用方对**本实例**的 `Settings`
/// 做任意调整（如 `[sso].consent_ticket = "required"`）。
///
/// 为什么需要：部分开关（如 `[sso].consent_ticket`）由 `settings.sso.*` 直读、**不经**
/// `FeatureSet`，既要按用例翻档、又**不能**污染并行测试 ⇒ 只能落在实例级 `Settings` 上
/// （进程级环境变量是全局的，会串档）。`configure` 在能力位覆盖之后、构建 `Arc<Settings>` 之前执行。
async fn build_isolated_state_with(
    features: &[(&str, &str)],
    configure: impl FnOnce(&mut Settings),
) -> (Arc<AppState>, RedisSlot) {
    // 幂等初始化测试日志，便于并行测试中查看底层错误（DbErr 等）
    init_test_tracing();

    // validate_secrets 拒绝占位密钥，这里通过环境变量注入一个合法强密钥（≥32 字符）。
    // set_var 为 unsafe（进程级环境，所有测试写入同一常量值，无实际竞争）。
    unsafe {
        std::env::set_var(
            "JWT_SECRET",
            "a-very-long-jwt-secret-key-for-testing-32+chars",
        );
    }

    let mut settings = Settings::from_file(&manifest_config_path())
        .expect("加载 config/config.toml 失败（请确认 cwd 或 CARGO_MANIFEST_DIR 正确）");

    // v5-D12：测试环境统一开启 SCIM（Bearer 固定测试值）——其它测试不请求 /scim/*
    // 故无干扰；SCIM 用例依赖此配置。
    settings.scim.enabled = true;
    settings.scim.bearer_token = "scim-test-bearer-token-0123456789abcdef".to_string();

    // 平台层能力位覆盖（集成测试专用）：写入 `Settings.features`，由服务层按实例读取。
    for (key, mode) in features {
        settings
            .features
            .0
            .insert((*key).to_string(), (*mode).to_string());
    }

    // 调用方的实例级调整（不影响其它并行测试）
    configure(&mut settings);

    let slot = acquire_redis_slot().await;
    let db_path = unique_temp_db_path();
    settings.database.url = format!("sqlite://{}?mode=rwc", db_path);
    // 测试 harness 不经过 main.rs，dotenvy 未加载——显式加载（CWD = workspace root，.env 可达）
    let _ = dotenvy::dotenv();
    // redis 密码从环境注入（.env 的 REDIS_PASSWORD；docker --requirepass 展开），
    // 无密码环境（REDIS_PASSWORD 未设）保持原行为
    let redis_auth = match std::env::var("REDIS_PASSWORD") {
        Ok(p) if !p.is_empty() => format!(":{}@", p),
        _ => String::new(),
    };
    settings.redis.url = format!("redis://{}127.0.0.1:6379/{}", redis_auth, slot.db_index);
    let settings = Arc::new(settings);

    // 2. 初始化 DB + 跑迁移（建表 + 种子数据）
    let db = init_database(&settings.database, false)
        .await
        .expect("初始化测试数据库失败");
    Migrator::up(&db, None)
        .await
        .expect("运行迁移建表 + 种子数据失败");
    // 存量库兜底：测试隔离库若由旧迁移建表，可能缺 sys_user.password_version 列
    // （pwd_ver 双写 DB 会 WARN 失败 → 重登签发 claim 读列为 0 → 新 token 被
    // Redis 中的 pwd_ver 拒绝 401）。与生产启动路径同口径补列。
    crate::initialize::ensure_user_password_version_column(&db)
        .await
        .expect("补建 sys_user.password_version 列失败");
    // 字段级权限 M2 兜底（幂等）：测试库与生产启动路径同口径补齐
    // sys_role_field_perm 表 / 菜单 4120-4121 / sys.fieldPerm.enabled 种子，
    // 保证菜单权限契约测试（PERM_ROUTE_TABLE ⊆ sys_menu.perms）覆盖新权限键。
    crate::initialize::ensure_role_field_perm_tables(&db)
        .await
        .expect("字段级权限 M2 兜底失败");

    // 3. 初始化 Redis，清空隔离 DB，关闭验证码开关，放大限流容量
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
    // 放大全局限流默认容量：并行测试共享全局内存令牌桶，默认 100/10s 易触发 429
    db.execute(Statement::from_string(
        DatabaseBackend::Sqlite,
        "UPDATE sys_rate_limit SET capacity=1000000, refill_per_second=1000000.0 WHERE route_pattern='*'",
    ))
    .await
    .expect("放大限流容量失败");

    // 4. 按生产路径组装（IP 库文件不存在时 IpLocator 优雅降级为空字符串）
    let ip_locator = Arc::new(IpLocator::new_with_xdb(
        &settings.ip_location.mmdb_path,
        &settings.ip_location.xdb_path,
        settings.ip_location.xdb_enabled,
    ));
    let ip_location_service =
        IpLocationService::new(db.clone(), settings.clone(), ip_locator.clone());
    // SharedStore 双档改造：集成测试固定走 redis 档（RedisStore = 生产 redis 档同实现），
    // 保证原有裸 redis::cmd 断言与业务写入落在同一 Redis DB，测试语义与迁移前一致。
    let store: Arc<dyn crate::shared_store::SharedStore> =
        Arc::new(crate::shared_store::RedisStore::new(redis.clone(), db.clone()));
    let job_scheduler = Arc::new(
        JobScheduler::new(
            db.clone(),
            store.clone(),
            ip_location_service.clone(),
            settings.clone(),
        )
        .await
        .expect("创建调度器失败"),
    );
    // 构建文件存储后端（按 upload.backend 切换 local/s3，测试默认 local）
    let storage: Arc<dyn crate::storage::StorageBackend> =
        crate::storage::new_backend(&settings.upload).expect("构建存储后端失败");

    (
        Arc::new(AppState::new(
            db,
            store,
            // redis 档测试：原生连接注入 rate_limit Lua 令牌桶使用
            Some(redis.clone()),
            settings,
            job_scheduler,
            ip_locator,
            ip_location_service,
            storage,
        )),
        slot,
    )
}

/// 构造一个带 ConnectInfo 的 POST /login 请求（login handler 需要 peer addr）。
fn login_request(peer_ip: IpAddr, body: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("构造 login 请求失败");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((peer_ip, 1234))));
    req
}

/// 以指定账号登录并返回 token。登录失败会 panic（带响应体便于定位）。
pub async fn login(app: &Router, peer_ip: IpAddr, username: &str, password: &str) -> String {
    let login_body = serde_json::json!({
        "username": username,
        "password": password,
        "code": "",
        "uuid": ""
    })
    .to_string();
    let resp = app
        .clone()
        .oneshot(login_request(peer_ip, &login_body))
        .await
        .expect("login 请求执行失败");
    let status = resp.status();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("读取 login 响应体失败");
    let v: serde_json::Value = serde_json::from_slice(&body).expect("login 响应 JSON 解析失败");
    assert_eq!(
        v["code"], 200,
        "login 业务码应为 200（HTTP {status}），实际: {v}"
    );
    v["token"]
        .as_str()
        .expect("login 响应应包含 token")
        .to_string()
}

/// 端到端测试客户端：持有完整应用 + admin token + 唯一 peer IP + 独占 Redis DB 槽位。
///
/// 提供 get_json / post_json / put_json / delete_json 便捷方法，
/// 自动附加 Authorization 头与 ConnectInfo（确保限流/审计按测试隔离），
/// 并统一断言业务码 code == 200（快乐路径）。
pub struct TestContext {
    pub app: Router,
    pub token: String,
    pub peer_ip: IpAddr,
    /// 应用状态句柄（测试直查 Redis / DB 用，与 app 共享同一实例）
    pub state: Arc<AppState>,
    /// 测试断言专用的原生 Redis 连接（与 app 共享同一隔离 DB）。
    /// SharedStore 迁移收尾：裸 `redis::cmd` 断言统一取自本字段（redis 档测试语义不变）。
    pub redis: redis::aio::ConnectionManager,
    /// 独占的 Redis DB 槽位（drop 时自动归还，保证并行测试 DB 索引唯一）
    _slot: RedisSlot,
}

impl TestContext {
    /// 构建隔离状态 + 完整应用，并以 admin/admin123 登录。
    pub async fn new() -> Self {
        Self::new_with_features(&[]).await
    }

    /// 同上，但注入平台层能力位覆盖（供 `privacy.user_erasure` 等能力位用例按档位验证）。
    pub async fn new_with_features(features: &[(&str, &str)]) -> Self {
        Self::new_with(features, |_| {}).await
    }

    /// 同上，但额外允许对**本实例**的 `Settings` 做任意调整（如 `[sso].consent_ticket`）。
    ///
    /// 与 `new_with_features` 一样是**实例级**（写入 `Arc<Settings>`），因此不影响并行测试。
    pub async fn new_with(
        features: &[(&str, &str)],
        configure: impl FnOnce(&mut Settings),
    ) -> Self {
        let (state, slot) = build_isolated_state_with(features, configure).await;
        // redis 档测试：从 AppState 取回原生 Redis 连接，供各测试文件裸 redis::cmd 断言使用
        let redis = state
            .redis_conn
            .clone()
            .expect("集成测试固定走 redis 档，redis_conn 必为 Some");
        let app = crate::router::build_app(state.clone());
        let peer_ip = next_peer_ip();
        let token = login(&app, peer_ip, "admin", "admin123").await;
        Self {
            app,
            token,
            peer_ip,
            state,
            redis,
            _slot: slot,
        }
    }

    /// 测试专属的 Redis 连接（与 app 共享同一隔离 DB）
    pub fn redis(&self) -> redis::aio::ConnectionManager {
        self.redis.clone()
    }

    /// 构造带鉴权头 + ConnectInfo 的请求。
    fn request(&self, method: Method, uri: &str, body: Option<serde_json::Value>) -> Request<Body> {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.token));
        let mut req = match body {
            Some(b) => builder
                .header("content-type", "application/json")
                .body(Body::from(b.to_string()))
                .expect("构造请求失败"),
            None => builder.body(Body::empty()).expect("构造请求失败"),
        };
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((self.peer_ip, 4321))));
        req
    }

    /// 执行请求并解析 JSON，断言 HTTP 200 且业务码 code == 200。
    pub async fn send_json(&self, req: Request<Body>) -> serde_json::Value {
        let resp = self.app.clone().oneshot(req).await.expect("请求执行失败");
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("读取响应体失败");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_else(|e| {
            panic!(
                "响应不是合法 JSON（HTTP {status}）: {e}\nbody={}",
                String::from_utf8_lossy(&body)
            )
        });
        assert_eq!(v["code"], 200, "业务码应为 200（HTTP {status}），实际: {v}");
        v
    }

    /// 执行请求并返回原始 HTTP 状态码 + JSON（用于 401/404/400 等非快乐路径断言）。
    pub async fn send_raw(
        &self,
        req: Request<Body>,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        let resp = self.app.clone().oneshot(req).await.expect("请求执行失败");
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("读取响应体失败");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    pub async fn get_json(&self, uri: &str) -> serde_json::Value {
        self.send_json(self.request(Method::GET, uri, None)).await
    }

    pub async fn post_json(&self, uri: &str, body: serde_json::Value) -> serde_json::Value {
        self.send_json(self.request(Method::POST, uri, Some(body)))
            .await
    }

    pub async fn put_json(&self, uri: &str, body: serde_json::Value) -> serde_json::Value {
        self.send_json(self.request(Method::PUT, uri, Some(body)))
            .await
    }

    pub async fn delete_json(&self, uri: &str) -> serde_json::Value {
        self.send_json(self.request(Method::DELETE, uri, None))
            .await
    }

    /// 断言 code == 200（对 send_raw 结果使用，避免二次断言重复）。
    pub fn assert_ok(&self, v: &serde_json::Value) {
        assert_eq!(v["code"], 200, "业务码应为 200，实际: {v}");
    }
}
