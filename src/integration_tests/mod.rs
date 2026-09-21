// axum-backend/src/integration_tests/mod.rs
//! 集成测试（端到端验证核心业务链路）
//!
//! 设计要点（隔离、可重复、无副作用、可并行）：
//! - 每个测试使用独立的临时 sqlite 文件（唯一路径），由 `migrator::Migrator::up` 建表 + 种子数据，
//!   不触碰开发/生产数据库。
//! - 每个测试使用独立的 Redis DB 索引（1..=15 轮询分配），`FLUSHDB` 清空，避免并行测试互相干扰。
//! - 每个测试使用独立的 peer IP（10.77.x.y），隔离全局内存限流令牌桶，避免并行测试触发 429。
//! - 测试库中将限流 `*` 默认配置放大到 1,000,000 容量，进一步规避限流对测试的干扰。
//! - 复用与生产完全一致的初始化路径（Settings → init_database → init_redis →
//!   IpLocator/IpLocationService → JobScheduler → AppState → build_app），
//!   仅替换 DB/Redis 连接目标，确保测试的是真实运行栈。
//! - 种子数据中 `sys.account.captchaEnabled` 被强制改为 `false`，使 login 跳过验证码。
//!
//! 前置依赖：本机需有可达的 Redis（默认 127.0.0.1:6379，无密码）。
//! 若 Redis 不可用，`init_redis` 会在超时后返回错误，测试将以清晰信息失败。

mod auth;
mod common_handler;
mod file_common;
mod ip_location;
mod monitor;
mod monitor_extra;
mod sys_backup;
mod sys_config_dict;
mod sys_http_debug;
mod sys_job;
mod sys_logininfor;
mod sys_log_clean_export;
mod sys_menu_dept;
mod sys_misc_extra;
mod sys_msg;
mod sys_notice;
mod sys_oauth;
mod sys_oper_log;
mod sys_post;
mod sys_rate_limit;
mod sys_report;
mod sys_role;
mod sys_task;
mod sys_user;
mod sys_user_extra;
mod sys_user_pref;
mod sys_web_hook;
mod menu_perm_contract;
mod response_cache;
mod tool_gen;
mod totp;
mod ws;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Method, Request};
use migration::Migrator;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sea_orm_migration::MigratorTrait;
use tokio::sync::{Semaphore, SemaphorePermit};
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
        let filter = std::env::var("RUST_LOG")
            .unwrap_or_else(|_| "warn".to_string());
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
    IpAddr::V4(Ipv4Addr::new(10, 77, ((n >> 8) & 0xff) as u8, (n & 0xff) as u8))
}

/// 返回 config.toml 的绝对路径（基于 CARGO_MANIFEST_DIR，避免 cwd 依赖）。
fn manifest_config_path() -> String {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    format!("{}/config/config.toml", dir)
}

/// 集成测试可用 Redis DB 数（Redis 默认 16 个 DB，0 保留给生产，1..=15 供测试独占）。
/// 并发测试总数超过该值时，由信号量排队，保证每个测试独占一个 DB 且互不 FLUSHDB 污染。
const TEST_REDIS_DB_COUNT: usize = 15;

/// 空闲 Redis DB 索引池（自由列表）：
/// - `acquire` 弹出一个空闲索引，测试结束 drop 时归还；
/// - 配合信号量，保证同时最多 `TEST_REDIS_DB_COUNT` 个测试各占一个唯一 DB。
static REDIS_DB_FREELIST: LazyLock<Mutex<Vec<u64>>> = LazyLock::new(|| {
    Mutex::new((1..=TEST_REDIS_DB_COUNT as u64).collect())
});
static REDIS_DB_SEMAPHORE: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(TEST_REDIS_DB_COUNT));

/// 持有 Redis DB 占用权的守卫：字段 `db_index` 为本测试独占的 DB 索引，
/// `_permit` 持有信号量许可；结构体 drop 时先归还空闲索引，随后释放许可。
pub struct RedisSlot {
    pub db_index: u64,
    _permit: SemaphorePermit<'static>,
}

impl Drop for RedisSlot {
    fn drop(&mut self) {
        REDIS_DB_FREELIST.lock().expect("DB 池锁中毒").push(self.db_index);
    }
}

/// 分配一个独占的 Redis DB 槽位（信号量排队 + 自由列表取唯一索引）。
async fn acquire_redis_slot() -> RedisSlot {
    let permit = REDIS_DB_SEMAPHORE
        .acquire()
        .await
        .expect("获取测试 Redis DB 许可失败（信号量关闭）");
    let db_index = REDIS_DB_FREELIST
        .lock()
        .expect("DB 池锁中毒")
        .pop()
        .expect("信号量保证池非空");
    RedisSlot {
        db_index,
        _permit: permit,
    }
}

/// 生成同进程内必然唯一的临时 sqlite 文件路径（pid + 单调序号），
/// 保证隔离、不残留旧 schema/数据、并行测试不撞文件。
fn unique_temp_db_path() -> String {
    let pid = std::process::id();
    let seq = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("yebot_it_{}_{}.db", pid, seq));
    p.to_string_lossy().to_string()
}

/// 构造隔离的 `(Arc<AppState>, RedisSlot)`：
/// 1. 加载生产配置并覆盖 database.url / redis.url 为隔离目标（独占 Redis DB 槽位）；
/// 2. 初始化 DB 并跑全部迁移（建表 + 种子 admin/admin123）；
/// 3. 清空隔离 Redis DB、强制关闭验证码开关、放大限流默认容量；
/// 4. 按生产路径组装 IpLocator / IpLocationService / JobScheduler / AppState。
///
/// 返回的 `RedisSlot` 必须由调用方持有至测试结束，以独占 Redis DB（drop 自动归还）。
async fn build_isolated_state() -> (Arc<AppState>, RedisSlot) {
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

    let slot = acquire_redis_slot().await;
    let db_path = unique_temp_db_path();
    settings.database.url = format!("sqlite://{}?mode=rwc", db_path);
    settings.redis.url = format!("redis://127.0.0.1:6379/{}", slot.db_index);
    let settings = Arc::new(settings);

    // 2. 初始化 DB + 跑迁移（建表 + 种子数据）
    let db = init_database(&settings.database, false)
        .await
        .expect("初始化测试数据库失败");
    Migrator::up(&db, None)
        .await
        .expect("运行迁移建表 + 种子数据失败");

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
    let job_scheduler = Arc::new(
        JobScheduler::new(
            db.clone(),
            redis.clone(),
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
            redis,
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
    /// 独占的 Redis DB 槽位（drop 时自动归还，保证并行测试 DB 索引唯一）
    _slot: RedisSlot,
}

impl TestContext {
    /// 构建隔离状态 + 完整应用，并以 admin/admin123 登录。
    pub async fn new() -> Self {
        let (state, slot) = build_isolated_state().await;
        let app = crate::router::build_app(state);
        let peer_ip = next_peer_ip();
        let token = login(&app, peer_ip, "admin", "admin123").await;
        Self {
            app,
            token,
            peer_ip,
            _slot: slot,
        }
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
        let resp = self
            .app
            .clone()
            .oneshot(req)
            .await
            .expect("请求执行失败");
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
        assert_eq!(
            v["code"], 200,
            "业务码应为 200（HTTP {status}），实际: {v}"
        );
        v
    }

    /// 执行请求并返回原始 HTTP 状态码 + JSON（用于 401/404/400 等非快乐路径断言）。
    pub async fn send_raw(&self, req: Request<Body>) -> (axum::http::StatusCode, serde_json::Value) {
        let resp = self
            .app
            .clone()
            .oneshot(req)
            .await
            .expect("请求执行失败");
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
