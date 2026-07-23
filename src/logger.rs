// axum-backend/src/logger.rs

use std::sync::OnceLock;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, EnvFilter, prelude::*};
use crate::config::LogConfig;

/// 全局保活 WorkerGuard（P0-67 未修复项）
///
/// tracing-appender 的 non_blocking writer 在 guard 被 drop 时会停止刷写日志，
/// 必须在程序整个生命周期内保活。使用 OnceLock 静态变量保存，
/// 进程退出时 drop 即可保证剩余日志刷新到磁盘。
static LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// 初始化日志体系（tracing + tracing-subscriber）
///
/// 输出层：
/// - stdout 层（保留，容器环境需要）
///   - `json_stdout = true` 时使用 JSON 结构化格式（P2-9，生产环境推荐，便于 ELK/Loki 采集）
///   - `json_stdout = false` 时使用纯文本格式（开发环境友好）
/// - 文件层（按日轮转，路径从 `log_config.file_path` 读取，默认 "logs"）
///   文件层使用 non_blocking writer 提升性能，WorkerGuard 通过 OnceLock 全局保活
///   文件层始终使用纯文本格式（grep 友好）
pub fn init_logger(log_config: &LogConfig) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&log_config.level));

    // stdout 层（容器环境需要，保留）
    // P2-9：生产环境可配置 json_stdout = true 使用 JSON 结构化格式
    let stdout_layer: Box<dyn tracing_subscriber::Layer<_> + Send + Sync> = if log_config.json_stdout {
        Box::new(
            fmt::layer()
                .json()
                .with_target(true)
                .with_ansi(false) // JSON 输出关闭 ANSI 颜色
                .with_file(true)
                .with_line_number(true),
        )
    } else {
        Box::new(
            fmt::layer()
                .with_target(true)
                .with_ansi(true)
                .with_file(true)
                .with_line_number(true),
        )
    };

    // 文件层：按日轮转
    // tracing_appender::rolling::daily 在目录下生成 `app.YYYY-MM-DD.log` 文件
    // file_appender 返回 (non_blocking_writer, WorkerGuard)，guard 必须 keep-alive
    let file_appender = tracing_appender::rolling::daily(&log_config.file_path, "app.log");
    let (non_blocking_file_writer, guard) = tracing_appender::non_blocking(file_appender);

    // guard 存入 OnceLock 保活（已存在则跳过，避免重复 init 时覆盖丢失 guard）
    if LOG_GUARD.set(guard).is_err() {
        tracing::warn!("日志 WorkerGuard 已存在，本次 init 未覆盖（可能是重复初始化）");
    }

    let file_layer = fmt::layer()
        .with_writer(non_blocking_file_writer)
        .with_target(true)
        .with_ansi(false) // 文件中关闭 ANSI 颜色，便于 grep
        .with_file(true)
        .with_line_number(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    tracing::info!(
        level = %log_config.level,
        file_path = %log_config.file_path,
        json_stdout = log_config.json_stdout,
        "日志系统初始化完成（stdout + 按日轮转文件）"
    );
}
