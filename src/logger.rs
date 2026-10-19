// stepby-axum/src/logger.rs

use std::sync::OnceLock;

use crate::config::LogConfig;
use crate::observability::error_log::ErrorCaptureLayer;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// 全局保活 WorkerGuard（P0-67 未修复项）
///
/// tracing-appender 的 non_blocking writer 在 guard 被 drop 时会停止刷写日志，
/// 必须在程序整个生命周期内保活。使用 OnceLock 静态变量保存，
/// 进程退出时 drop 即可保证剩余日志刷新到磁盘。
static LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// stdout 写句柄生产者（`MakeWriter` 靠 `Fn() -> W` 的 blanket impl 生效；
/// 用 fn item 而非 `Stdout` 值，因为 `Stdout` 本身不实现 `MakeWriter`/`Clone`）
fn stdout_handle() -> std::io::Stdout {
    std::io::stdout()
}

/// 初始化日志体系（tracing + tracing-subscriber）
///
/// 输出层（**注册顺序有意义，见下**）：
/// - 文件层（按日轮转，路径从 `log_config.file_path` 读取，默认 "logs"）
///   文件层使用 non_blocking writer 提升性能，WorkerGuard 通过 OnceLock 全局保活
///   文件层始终使用纯文本格式（grep 友好），且**必须先于 stdout 层注册**
/// - stdout 层（保留，容器环境需要；ANSI 仅在真终端开启）
///   - `json_stdout = true` 时使用 JSON 结构化格式（P2-9，生产环境推荐，便于 ELK/Loki 采集）
///   - `json_stdout = false` 时使用纯文本格式（开发环境友好）
pub fn init_logger(log_config: &LogConfig) {
    // 文件层：按日轮转
    // tracing_appender::rolling::daily 在目录下生成 `app.log.YYYY-MM-DD` 文件
    // file_appender 返回 (non_blocking_writer, WorkerGuard)，guard 必须 keep-alive
    let file_appender = tracing_appender::rolling::daily(&log_config.file_path, "app.log");
    let (non_blocking_file_writer, guard) = tracing_appender::non_blocking(file_appender);

    // guard 存入 OnceLock 保活（已存在则跳过，避免重复 init 时覆盖丢失 guard）
    if LOG_GUARD.set(guard).is_err() {
        tracing::warn!("日志 WorkerGuard 已存在，本次 init 未覆盖（可能是重复初始化）");
    }

    // b73 轮 9 修复的两个叠加快因（原实现文件层写了 `.with_ansi(false)`，但磁盘日志**仍有**
    // ESC 转义码——`<ESC>[3mrequest_id<ESC>[0m<ESC>[2m=<ESC>[0m<uuid>`）：
    // ① **层顺序**：tracing-subscriber 0.3 把"span 的字段串"缓存在 registry 扩展里，由
    //    **第一个**执行 `on_new_span` 的层生成，后续层直接复用该字符串
    //    （`fmt_layer.rs:878` 的 `if extensions.get_mut::<FormattedFields<N>>().is_none()`；
    //    层分发顺序是"先 `.with()` 的先跑"，见 `layered.rs:286` 先 `self.inner` 再 `self.layer`）。
    //    旧代码 stdout 层（ANSI 开）先注册 ⇒ 它先生成**带色**字段串 ⇒ 文件层写的就是这个串，
    //    文件层自己的 `with_ansi(false)` 只影响 level/target，拦不住字段串。
    //    ⇒ 后果：日志文件不可 grep、`/monitor/logtail` 页面显示乱码、
    //      测试侧按 `request_id=` 归一聚合完全失效（实测 438 行裂成 751 型）。
    //    ⇒ 现在文件层先注册，字段串以"无色"版本落定，两层共用。
    // ② **ANSI 只给真终端**：stdout 被重定向（systemd/容器/CI/e2e 起进程）时打颜色
    //    只会污染捕获文件，故按 `IsTerminal` 判定。
    let stdout_ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let (subscriber, otlp_enabled) = build_subscriber(
        non_blocking_file_writer,
        stdout_handle,
        log_config,
        stdout_ansi,
    );
    subscriber.init();

    tracing::info!(
        level = %log_config.level,
        file_path = %log_config.file_path,
        json_stdout = log_config.json_stdout,
        otlp = otlp_enabled,
        "日志系统初始化完成（stdout + 按日轮转文件）"
    );
}

/// 组装订阅栈。**文件层必须先于 stdout 层**——顺序即 b73 轮 9 修复的契约，
/// 缘由见 [`init_logger`] 内注释（span 字段串由第一个 `on_new_span` 的层生成并缓存复用）。
///
/// 单独成函数是为了让"顺序"可被单测直接验证：`init_logger` 走 `.init()` 全局安装且绑定
/// `WorkerGuard`，测试无法复用；本函数只接收 writer，两层在函数内构造，链式类型保持具体。
/// 第二返回值告知调用方 OTLP 层是否真的装了（避免为打启动日志再构造一个 exporter）。
fn build_subscriber<W1, W2>(
    file_writer: W1,
    stdout_writer: W2,
    log_config: &LogConfig,
    stdout_ansi: bool,
) -> (impl tracing::Subscriber + Send + Sync, bool)
where
    W1: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
    W2: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_config.level));

    let file_layer = fmt::layer()
        .with_writer(file_writer)
        .with_target(true)
        .with_ansi(false) // 文件中关闭 ANSI 颜色，便于 grep
        .with_file(true)
        .with_line_number(true);

    // P2-9：生产环境可配置 json_stdout = true 使用 JSON 结构化格式（JSON 侧恒关 ANSI）
    let stdout_layer: Box<dyn tracing_subscriber::Layer<_> + Send + Sync> =
        if log_config.json_stdout {
            Box::new(
                fmt::layer()
                    .json()
                    .with_writer(stdout_writer)
                    .with_target(true)
                    .with_ansi(false)
                    .with_file(true)
                    .with_line_number(true),
            )
        } else {
            Box::new(
                fmt::layer()
                    .with_writer(stdout_writer)
                    .with_target(true)
                    .with_ansi(stdout_ansi)
                    .with_file(true)
                    .with_line_number(true),
            )
        };

    // G-13b：OTLP 追踪导出层（可选编译特性；未启用/未配置 endpoint 时为 None，零影响）
    let otlp_layer = build_otlp_layer();
    let otlp_enabled = otlp_layer.is_some();

    (
        tracing_subscriber::registry()
            .with(env_filter)
            .with(file_layer)
            .with(stdout_layer)
            .with(otlp_layer)
            // ErrorCaptureLayer：采集 ERROR 级别日志事件到进程内错误总线（供 /monitor/error-log/* 查询）。
            // 需 registry 提供 LookupSpan，以读取当前 request span 上的 request_id/path 进行关联。
            .with(ErrorCaptureLayer::new()),
        otlp_enabled,
    )
}

/// G-13b：OTLP 追踪导出层构建
///
/// - 未启用 `otlp` feature → 恒 `None`（零依赖、零出站）；
/// - 已启用但 `OTEL_EXPORTER_OTLP_ENDPOINT` 未配置/为空 → `None`（零出站，
///   与 upload_scan 默认 off 同款"未配置即不存在"哲学）；
/// - 已配置 → OTLP gRPC（tonic）batch exporter + OpenTelemetryLayer，
///   服务名标签取 `OTEL_SERVICE_NAME`（缺省 `stepby-axum`）。
#[cfg(feature = "otlp")]
fn build_otlp_layer<S>() -> Option<Box<dyn tracing_subscriber::Layer<S> + Send + Sync>>
where
    S: tracing::Subscriber + Send + Sync + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    // opentelemetry 0.28：with_endpoint 在 WithExportConfig trait、tracer() 在
    // TracerProvider trait——均需显式引入作用域
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())?;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
        .map_err(|e| {
            tracing::warn!("OTLP exporter 构建失败（追踪层跳过）: {e}");
            e
        })
        .ok()?;

    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "stepby-axum".to_string());
    let resource = opentelemetry_sdk::Resource::builder()
        .with_attribute(opentelemetry::KeyValue::new("service.name", service_name))
        .build();

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    let tracer = provider.tracer("stepby-axum");
    tracing::info!(endpoint = %endpoint, "OTLP 追踪导出已启用（G-13b）");
    Some(Box::new(tracing_opentelemetry::layer().with_tracer(tracer)))
}

/// G-13b：未启用 `otlp` feature 时恒 None（零依赖路径）
#[cfg(not(feature = "otlp"))]
fn build_otlp_layer<S>() -> Option<Box<dyn tracing_subscriber::Layer<S> + Send + Sync>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// 内存 MakeWriter：clone 后共享同一缓冲，供多层各写各的
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    fn take_text(buf: &SharedBuf) -> String {
        String::from_utf8(buf.0.lock().unwrap().clone()).expect("日志缓冲应为 UTF-8")
    }

    fn log_config(json_stdout: bool) -> LogConfig {
        LogConfig {
            // "info" 而非 "warn"：`info_span!` 建的 span 会被 warn 级 EnvFilter 整体关掉，
            // 关掉后 span 字段根本不进事件行，测不到想测的东西。
            level: "info".to_string(),
            sql_logging: false,
            file_path: "logs".to_string(),
            json_stdout,
        }
    }

    /// b73 轮 9 回归锁：文件层必须先于 stdout 层注册。
    ///
    /// 机制（tracing-subscriber 0.3.23 `fmt_layer.rs:878`）：一个 span 的字段串只格式化**一次**，
    /// 结果缓存在 registry 扩展里供后续层复用，"谁先 `on_new_span` 谁定调"。
    /// 旧顺序（stdout 带 ANSI 在前）会让文件层复用**带 ESC 转义码**的字段串 ⇒
    /// 磁盘日志不可 grep、`/monitor/logtail` 显示乱码、按 `request_id=` 归一聚合全废
    /// （实测 438 行裂成 751 型）。
    #[test]
    fn file_layer_registered_first_keeps_disk_log_free_of_ansi() {
        let file_buf = SharedBuf::default();
        let stdout_buf = SharedBuf::default();

        let (subscriber, otlp_enabled) = build_subscriber(
            file_buf.clone(),
            stdout_buf.clone(),
            &log_config(false),
            true, // stdout 在真终端（模拟开发机交互式启动）
        );
        assert!(!otlp_enabled, "未配置 OTLP endpoint 时不应装追踪层");
        let _guard = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("request", request_id = %"cafe1234-0000");
        {
            let _enter = span.enter();
            tracing::warn!("日志层级回归锁消息");
        }
        drop(_guard);

        let file_text = take_text(&file_buf);
        let stdout_text = take_text(&stdout_buf);

        // 前置条件：带色层确实产出了 ANSI（否则整测空跑，证伪不了任何东西）
        assert!(
            stdout_text.contains('\u{1b}'),
            "stdout 层 with_ansi(true) 应产生 ESC（依赖 ansi feature）; 实际: {stdout_text:?}"
        );
        assert!(
            file_text.contains("request_id=cafe1234-0000"),
            "span 字段应写入文件层: {file_text:?}"
        );
        assert!(
            !file_text.contains('\u{1b}'),
            "文件层日志不得含 ANSI 转义码（层顺序回归）: {file_text:?}"
        );
    }

    /// 反证（变异证伪）：把顺序写反——带色层先入栈——应当复现 ESC 泄漏到"文件"侧。
    /// 这条用例证明上面那条锁**真的受顺序约束**，而不是恒真的空断言。
    #[test]
    fn reversed_layer_order_leaks_ansi_into_the_plain_sink() {
        let plain_buf = SharedBuf::default();
        let colored_buf = SharedBuf::default();

        let colored = fmt::layer()
            .with_writer(colored_buf.clone())
            .with_ansi(true)
            .with_target(true);
        let plain = fmt::layer()
            .with_writer(plain_buf.clone())
            .with_ansi(false)
            .with_target(true);

        // 故意反序：先 with(colored) ⇒ colored 先跑 on_new_span
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new("info"))
            .with(colored)
            .with(plain)
            .with(ErrorCaptureLayer::new());
        let _guard = tracing::subscriber::set_default(subscriber);

        let span = tracing::info_span!("request", request_id = %"deadbeef-1111");
        {
            let _enter = span.enter();
            tracing::warn!("顺序反证消息");
        }
        drop(_guard);

        let plain_text = take_text(&plain_buf);
        let colored_text = take_text(&colored_buf);
        assert!(
            colored_text.contains('\u{1b}'),
            "带色侧应有 ESC: {colored_text:?}"
        );
        assert!(
            plain_text.contains('\u{1b}'),
            "反序时无色侧应被污染（复现缺陷; 若此断言失败说明机制理解有误）: {plain_text:?}"
        );
    }

    /// json_stdout 档：stdout 走 JSON（恒无 ANSI），文件仍为纯文本
    #[test]
    fn json_stdout_mode_keeps_file_layer_plain_text() {
        let file_buf = SharedBuf::default();
        let stdout_buf = SharedBuf::default();

        let (subscriber, _) = build_subscriber(
            file_buf.clone(),
            stdout_buf.clone(),
            &log_config(true),
            true,
        );
        let _guard = tracing::subscriber::set_default(subscriber);
        let span = tracing::info_span!("request", request_id = %"json0001");
        {
            let _enter = span.enter();
            tracing::warn!("json 档位消息");
        }
        drop(_guard);

        let file_text = take_text(&file_buf);
        let stdout_text = take_text(&stdout_buf);
        assert!(
            stdout_text.contains("\"fields\"") || stdout_text.trim_start().starts_with('{'),
            "stdout 应为 JSON 行: {stdout_text:?}"
        );
        assert!(
            file_text.contains("request_id=json0001") && !file_text.contains('\u{1b}'),
            "文件侧应为无 ANSI 纯文本: {file_text:?}"
        );
    }

    /// ANSI 判定必须来自"是否真终端"而非恒 true（重定向捕获文件时不得打颜色）
    #[test]
    fn stdout_ansi_flag_is_respected_for_redirected_stdout() {
        let file_buf = SharedBuf::default();
        let stdout_buf = SharedBuf::default();

        // stdout_ansi = false ⇒ 等价于 systemd/容器/e2e 里 stdout 被重定向的场景
        let (subscriber, _) = build_subscriber(
            file_buf.clone(),
            stdout_buf.clone(),
            &log_config(false),
            false,
        );
        let _guard = tracing::subscriber::set_default(subscriber);
        let span = tracing::info_span!("request", request_id = %"pipe0001");
        {
            let _enter = span.enter();
            tracing::warn!("重定向 stdout 消息");
        }
        drop(_guard);

        let stdout_text = take_text(&stdout_buf);
        assert!(
            stdout_text.contains("request_id=pipe0001"),
            "stdout 仍应收到日志: {stdout_text:?}"
        );
        assert!(
            !stdout_text.contains('\u{1b}'),
            "stdout 被重定向时不得输出 ANSI: {stdout_text:?}"
        );
        assert!(
            !take_text(&file_buf).contains('\u{1b}'),
            "文件侧同样不得含 ANSI"
        );
    }
}
