// axum-backend/src/main.rs
//! axum-backend 应用入口
//! 1. 加载 .env 环境变量
//! 2. 安装 panic hook（将 panic 转入 tracing 结构化日志）
//! 3. 构建 8MB 栈大小的 Tokio runtime（项目硬约束）
//! 4. 调用 AppInitializer 完成初始化（配置/日志/DB/Redis/AppState）
//! 5. 构建 Router 并启动 axum HTTP 服务
//! 6. 监听 SIGTERM 优雅关闭（含调度器关闭，超时 10 秒保护）

use std::time::Duration;

use axum_backend::{initialize::AppInitializer, router};
use tokio::net::TcpListener;

/// 优雅关闭调度器的超时时间（秒）。
///
/// 超时后强制退出，避免 shutdown 流程卡死导致进程无法退出。
const GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 10;

fn main() -> anyhow::Result<()> {
    // 1. 加载 .env 环境变量（失败不阻断，生产环境可能无 .env）
    let _ = dotenvy::dotenv();

    // 2. 安装 panic hook：将 panic 转入 tracing 结构化日志（P0-New-4）
    init_panic_hook();

    // 3. 构建 Tokio runtime，手动指定 8MB 线程栈大小（项目硬约束，P0-New-10）
    //    默认 2MB 在递归序列化（如 OpenAPI 递归类型）或深层调用栈下可能栈溢出
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024) // 8MB
        .build()?;

    runtime.block_on(async_main())
}

/// 异步主逻辑
async fn async_main() -> anyhow::Result<()> {
    // 初始化编排：加载配置 -> 日志 -> DB -> Redis -> AppState
    let state = AppInitializer::run("config/config.toml").await?;

    // 提取监听地址（在 state 被路由消费前取出）
    let host = state.config.server.host.clone();
    let port = state.config.server.port;
    let addr = format!("{}:{}", host, port);

    // 提取调度器引用（在 state 被 router 消费前 clone 出来，用于优雅关闭时调用 shutdown）
    // 修复 P0-R81-020：原 main.rs 无调度器关闭流程，导致关闭时定时任务仍在执行
    let job_scheduler = state.job_scheduler.clone();

    // 构建应用路由（叠加全局中间件）
    let app = router::build_app(state);

    // 启动 HTTP 服务
    // BUILD_TIMESTAMP / GIT_HASH / GIT_DIRTY 由 build.rs 注入，便于日志溯源构建版本
    let listener = TcpListener::bind(&addr).await?;

    // 启动日志在 bind 成功之后输出（反映"端口已真正开始监听"，而非仅准备就绪）
    tracing::info!(
        "服务启动于 http://{} (build_ts={}, git={}{})",
        addr,
        env!("BUILD_TIMESTAMP"),
        env!("GIT_HASH"),
        env!("GIT_DIRTY"),
    );

    // Slowloris 防护说明：
    // axum 0.8 重构后 Serve 不再暴露 http1_header_read_timeout / tcp_nodelay 方法，
    // 改为在 router 层通过 tower_http::timeout::TimeoutLayer 设置请求级超时（见 build_app），
    // 防止慢速请求耗尽连接池。生产环境建议同时在反向代理（Nginx）层配置
    // client_header_timeout / client_body_timeout 实现纵深防御。
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("HTTP 服务已停止，正在关闭调度器...");

    // 优雅关闭调度器（P0-R81-020）
    // 使用 GRACEFUL_SHUTDOWN_TIMEOUT_SECS 超时保护，避免 shutdown 流程卡死导致进程无法退出
    match tokio::time::timeout(Duration::from_secs(GRACEFUL_SHUTDOWN_TIMEOUT_SECS), job_scheduler.shutdown()).await {
        Ok(Ok(_)) => tracing::info!("调度器已正常关闭"),
        Ok(Err(e)) => tracing::warn!("调度器关闭失败（不阻断退出）: {}", e),
        Err(_) => tracing::warn!("调度器关闭超时（>{}s），强制退出", GRACEFUL_SHUTDOWN_TIMEOUT_SECS),
    }

    tracing::info!("服务已优雅关闭");
    Ok(())
}

/// 安装 panic hook，将 panic 信息写入 tracing 结构化日志（P0-New-4）
///
/// 保留默认 hook 的行为（打印到 stderr），额外通过 tracing::error 记录，
/// 便于日志采集系统（如 ELK / Loki）统一收集 panic 事件。
fn init_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());
        tracing::error!(
            target: "panic",
            location = %location,
            payload = %payload,
            "panic occurred"
        );
        default_hook(info);
    }));
}

/// 监听 Ctrl+C 信号实现优雅关闭
async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::warn!("Ctrl+C 信号处理器安装失败");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                if sig.recv().await.is_none() {
                    tracing::warn!("SIGTERM 信号处理器异常");
                }
            }
            Err(_) => tracing::warn!("SIGTERM 信号处理器安装失败"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
