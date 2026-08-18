//! 实时系统日志查看 Handler（Log Tail）
//!
//! 设计要点：
//! - 定位：系统监控预留的「实时日志」能力，读取 tracing 按日轮转的应用日志文件
//!   （<log.file_path>/app.log.YYYY-MM-DD，见 initialize 中 tracing_appender::rolling::daily("app.log")），
//!   供运维无需登入服务器即可排查问题。
//! - `files`：列出日志目录下所有应用日志文件（名称、大小、修改时间）。
//! - `tail`：读取指定日志文件的**尾部**（默认最近 500 行，上限 2000 行），
//!   支持级别（TRACE/DEBUG/INFO/WARN/ERROR）与关键字过滤，适合配合前端自动刷新做实时追踪。
//! - 安全（L-1）：文件名经白名单规则 `app.log.YYYY-MM-DD` 校验（前缀 + 日期三段 4-2-2），
//!   杜绝路径穿越（`../`、`/`、绝对路径）；目录解析限定在日志根目录内。
//! - 性能：文件 IO（读取尾部）在 `spawn_blocking` 中执行，异步上下文中一次性最多读取
//!   尾部 4MB（超过则仅取尾 4MB），从尾部解析出行后只返回末尾 `lines` 行，避免整文件
//!   读入内存导致 OOM。

use std::sync::Arc;

use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::{AjaxResult, AppError};
use crate::state::AppState;

/// 一次最多读取的日志尾部字节数（4MB），防止超大日志文件整读内存
const TAIL_READ_LIMIT_BYTES: u64 = 4 * 1024 * 1024;
/// 返回的最大行数（默认 500，上限 2000）
const DEFAULT_TAIL_LINES: u64 = 500;
const MAX_TAIL_LINES: u64 = 2000;

/// 日志文件名白名单（tracing_appender::rolling::daily("app.log") 按日轮转格式：app.log.YYYY-MM-DD）
fn is_valid_log_file_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.len() != name.len()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
    {
        return false;
    }
    // 固定前缀 "app.log."，其后必须恰好是 YYYY-MM-DD（三段、长度 4-2-2、纯数字）
    let prefix = "app.log.";
    if !name.starts_with(prefix) {
        return false;
    }
    let mid = &name[prefix.len()..];
    let parts: Vec<&str> = mid.split('-').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
}

/// 解析日志根目录为绝对路径（与日志写入使用同一 `log.file_path` 配置）
fn resolve_log_root(log_dir: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(log_dir);
    if dir.is_absolute() {
        return dir;
    }
    // 相对路径：与 tracing_appender::rolling::daily 相同地基于进程 CWD 写入/读取
    std::env::current_dir()
        .map(|cwd| cwd.join(&dir))
        .unwrap_or_else(|_| dir)
}

/// 从一行 tracing 纯文本日志中提取日志级别（找不到视为 INFO）
fn extract_level(line: &str) -> String {
    // tracing 文本格式：`2026-08-18T10:00:00.123Z  INFO target: msg`
    for token in line.split_whitespace() {
        if matches!(token, "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR") {
            return token.to_string();
        }
    }
    "INFO".to_string()
}

/// 按级别过滤（level 为空表示不过滤）
fn level_matches(level_filter: &str, row_level: &str) -> bool {
    let f = level_filter.to_uppercase();
    if f.is_empty() || f == "ALL" {
        return true;
    }
    // 支持等级语义：取 >= 该级别的日志（如 ERROR 只显示 ERROR；WARN 显示 WARN+ERROR）
    let rank = |l: &str| match l {
        "TRACE" => 0,
        "DEBUG" => 1,
        "INFO" => 2,
        "WARN" => 3,
        "ERROR" => 4,
        _ => 2,
    };
    rank(row_level) >= rank(&f)
}

// ==================== DTO ====================

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogFileInfo {
    pub file_name: String,
    pub file_size: u64,
    /// 文件大小（人类可读，如 1.5MB）
    pub file_size_str: String,
    pub last_modified: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogFilesResponse {
    pub rows: Vec<LogFileInfo>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct LogTailQuery {
    /// 日志文件名，如 app.log.2026-08-18
    pub file_name: String,
    /// 级别过滤（TRACE/DEBUG/INFO/WARN/ERROR，空=全部）
    pub level: Option<String>,
    /// 关键字过滤（子串匹配，空=不过滤）
    pub keyword: Option<String>,
    /// 返回最近的行数（默认 500，上限 2000，0=返回全部读取到的行）
    pub lines: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogLine {
    /// 顺序号（本次返回批次内 1..n）
    pub no: u64,
    /// 日志级别
    pub level: String,
    /// 原始日志文本
    pub text: String,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogTailResponse {
    pub file_name: String,
    /// 过滤后的总行数
    pub total: u64,
    pub rows: Vec<LogLine>,
}

// ==================== Handler ====================

/// GET /monitor/log/files
/// 列出日志目录下的应用日志文件
pub async fn files(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<LogFilesResponse>, AppError> {
    let log_dir = resolve_log_root(&state.config.log.file_path);

    // 目录存在性检查 + 读取目录条目 + 元数据全部在 spawn_blocking 中完成，避免阻塞 Tokio worker
    let entries: Vec<LogFileInfo> = tokio::task::spawn_blocking({
        let dir = log_dir;
        move || -> std::io::Result<Vec<LogFileInfo>> {
            if !dir.exists() {
                return Ok(Vec::new());
            }
            let mut result = Vec::new();
            let entries = std::fs::read_dir(&dir)?;
            for entry in entries {
                let Ok(entry) = entry else { continue };
                let Ok(meta) = entry.metadata() else { continue };
                if !meta.is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                if !is_valid_log_file_name(&name) {
                    continue;
                }
                let size = meta.len();
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                    .unwrap_or(0);
                let modified_str = chrono::DateTime::<chrono::Local>::from(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(modified as u64),
                )
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();
                result.push(LogFileInfo {
                    file_name: name,
                    file_size: size,
                    file_size_str: format_file_size(size),
                    last_modified: modified_str,
                });
            }
            // 按修改时间倒序（最新日志在前）
            result.sort_by(|a, b| b.last_modified.cmp(&a.last_modified));
            Ok(result)
        }
    })
    .await
    .map_err(|_| AppError::internal(&crate::tr!("error.log.list_task_failed")))?
    .map_err(|_| AppError::internal(&crate::tr!("error.log.list_failed")))?;

    Ok(AjaxResult::success(LogFilesResponse { rows: entries }))
}

/// GET /monitor/log/tail
/// 读取指定日志文件尾部并过滤
pub async fn tail(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LogTailQuery>,
) -> Result<AjaxResult<LogTailResponse>, AppError> {
    let file_name = params.file_name.trim().to_string();
    if file_name.is_empty() || !is_valid_log_file_name(&file_name) {
        return Err(AppError::bad_request(&crate::tr!("error.log.invalid_name")));
    }

    let level_filter = params.level.unwrap_or_default().to_uppercase();
    let keyword = params.keyword.unwrap_or_default();
    let lines_req = params
        .lines
        .unwrap_or(DEFAULT_TAIL_LINES)
        .min(MAX_TAIL_LINES);

    let log_dir = resolve_log_root(&state.config.log.file_path);

    // 读取尾部 + 过滤移入 spawn_blocking（文件 IO 阻塞工作移出 async 上下文）
    let (rows, size) = tokio::task::spawn_blocking({
        let dir = log_dir.clone();
        let file_name = file_name.clone();
        let level_filter = level_filter.clone();
        let keyword = keyword.clone();
        move || -> std::io::Result<(Vec<LogLine>, u64)> {
            let path = dir.join(&file_name);
            // 双保险：拼接后仍须位于日志根目录内（白名单正则已排除路径穿越）
            if !path.starts_with(&dir) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "invalid path",
                ));
            }
            if !path.exists() || !path.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "not found",
                ));
            }
            let size = std::fs::metadata(&path)?.len();

            let mut file = std::fs::File::open(&path)?;
            use std::io::{Read, Seek, SeekFrom};
            // 只读取尾部 TAIL_READ_LIMIT_BYTES，防止超大文件整读内存
            let read_bytes = if size > TAIL_READ_LIMIT_BYTES {
                file.seek(SeekFrom::End(-(TAIL_READ_LIMIT_BYTES as i64)))?;
                TAIL_READ_LIMIT_BYTES as usize
            } else {
                size as usize
            };
            let mut buf = vec![0u8; read_bytes];
            file.read_exact(&mut buf)?;

            // 切分成行（跳过尾部空行）
            let content = String::from_utf8_lossy(&buf);
            let mut lines: Vec<&str> = content.split('\n').collect();
            while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
                lines.pop();
            }

            // 先过滤，再取末尾 lines_req 行（返回的都是较新的）
            let mut matched: Vec<(String, String)> = Vec::new();
            for line in lines {
                if !keyword.is_empty() && !line.contains(&keyword) {
                    continue;
                }
                let level = extract_level(line);
                if !level_matches(&level_filter, &level) {
                    continue;
                }
                matched.push((level, line.trim_end().to_string()));
            }

            let take = if lines_req == 0 {
                matched.len()
            } else {
                (lines_req as usize).min(matched.len())
            };
            let start = matched.len().saturating_sub(take);
            let rows: Vec<LogLine> = matched[start..]
                .iter()
                .enumerate()
                .map(|(i, (level, text))| LogLine {
                    no: (i + 1) as u64,
                    level: level.clone(),
                    text: text.clone(),
                })
                .collect();

            Ok((rows, size))
        }
    })
    .await
    .map_err(|_| AppError::internal(&crate::tr!("error.log.tail_task_failed")))?
    .map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::bad_request(&crate::tr!("error.log.file_not_found"))
        } else {
            AppError::internal(&crate::tr!("error.log.tail_failed"))
        }
    })?;

    let _ = size;
    Ok(AjaxResult::success(LogTailResponse {
        file_name,
        total: rows.len() as u64,
        rows,
    }))
}

/// 格式化文件大小（人类可读）
fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if size == 0 {
        return "0 B".to_string();
    }
    let mut s = size as f64;
    let mut i = 0;
    while s >= 1024.0 && i < UNITS.len() - 1 {
        s /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", size, UNITS[i])
    } else {
        format!("{:.2} {}", s, UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_log_file_name() {
        assert!(is_valid_log_file_name("app.log.2026-08-18"));
        assert!(is_valid_log_file_name("app.log.2026-08-18"));
        assert!(!is_valid_log_file_name("app.log.2026-8-18"));
        assert!(!is_valid_log_file_name("app.log.2026-08-18.txt"));
        assert!(!is_valid_log_file_name("../app.log.2026-08-18"));
        assert!(!is_valid_log_file_name("app.log.20260818"));
        assert!(!is_valid_log_file_name("x.log"));
        // 旧格式（app.YYYY-MM-DD.log）与 daily("app.log") 实际产物（app.log.YYYY-MM-DD）不同
        assert!(!is_valid_log_file_name("app.2026-08-18.log"));
        assert!(!is_valid_log_file_name("app.log.2026-08-18.log"));
    }

    #[test]
    fn test_extract_level() {
        assert_eq!(
            extract_level("2026-08-18T10:00:00.123Z  INFO handler: ok"),
            "INFO"
        );
        assert_eq!(
            extract_level("2026-08-18T10:00:00.123Z  ERROR handler: bad"),
            "ERROR"
        );
        assert_eq!(
            extract_level("2026-08-18T10:00:00.123Z  WARN handler: w"),
            "WARN"
        );
        assert_eq!(extract_level("some non-standard line"), "INFO");
    }

    #[test]
    fn test_level_matches() {
        assert!(level_matches("", "INFO"));
        assert!(level_matches("ALL", "ERROR"));
        assert!(!level_matches("ERROR", "INFO"));
        assert!(level_matches("ERROR", "ERROR"));
        assert!(level_matches("WARN", "ERROR"));
        assert!(!level_matches("WARN", "INFO"));
    }
}
