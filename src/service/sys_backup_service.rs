//! 数据备份/恢复 Service 层
//!
//! 职责：
//! - 创建数据库备份（通过 pg_dump / mysqldump / sqlite3 子进程）
//! - 恢复数据库备份（通过 psql / mysql / sqlite3 子进程）
//! - 备份日志分页查询 / 详情 / 批量删除
//! - 备份文件下载
//!
//! 安全要点：
//! - 备份目录通过 UploadConfig 配置，禁止写入任意路径
//! - 备份文件名采用 `{timestamp}_{uuid}.dump` 格式，禁用用户输入
//! - 子进程执行设置 5 分钟超时，避免恶意大库阻塞
//! - 恢复操作前校验文件路径穿越，必须位于备份目录内
//! - 备份目录通过路径规范化（canonicalize）二次校验

use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, FromQueryResult, Set, Statement,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::config::Settings;
use crate::entity::sys_backup_log::{
    ActiveModel as SysBackupLogActiveModel, Column as BackupLogColumn, Model as SysBackupLogModel,
};
use crate::repository::sys_backup_log::SysBackupLogRepository;

// ==================== 常量 ====================

/// 子进程超时时间（5 分钟），避免恶意大库阻塞后端
const BACKUP_TIMEOUT_SECS: u64 = 300;

/// 备份文件存储子目录（相对工作目录）
const BACKUP_DIR: &str = "backups";

/// 「租户数据包」附加导出表（除 `initialize::TENANT_CARRYING_TABLES` 之外）：
/// 三张租户表族本体均以 `tenant_id` 为归属列，需随包导出（否则包内缺租户身份与域名/菜单）
const TENANT_PACKAGE_EXTRA_TABLES: &[&str] =
    &["sys_tenant", "sys_tenant_domain", "sys_tenant_menu"];

/// 备份日志的 `backup_type`：租户数据包导出
pub const BACKUP_TYPE_TENANT_EXPORT: &str = "tenant_export";

/// 整库备份自动轮转保留数量（默认安全：保留最近 10 份成功备份）
///
/// 背景：备份功能上线后每次 e2e / 手动备份均真实落盘且无自动清理，
/// 曾堆积 130+ 份（峰值单份 3.3GB，累计 15GB+）。每次成功备份后自动清理
/// 超出保留数的最旧整库备份（manual / auto）；`tenant_export` 租户留档与
/// `restore` 恢复记录（无落盘文件）不参与轮转；手动删除接口不受影响。
const RETAIN_SUCCESS_BACKUPS: usize = 10;

/// 恢复失败原因的落库上限（字符）。
///
/// psql/mysql 的 stderr 是"每条失败语句一行"，大库恢复失败时可达几十 KB；
/// 无上限会把 `error_msg` 撑大并随列表接口回显。按字符截断（不是字节）以免
/// 在 UTF-8 中间切断。
const RESTORE_ERROR_MAX_CHARS: usize = 4000;

/// SQLite 恢复临时库文件名前缀（与业务文件隔离；陈旧清理只认这个前缀）。
const SQLITE_RESTORE_TEMP_PREFIX: &str = ".stepby-restore-";

/// SQLite 恢复校验的核心表：重建后的临时库必须全部含有。
///
/// 这一条挡的是"看起来成功、其实什么都没有"的三类备份：截断的 dump
/// （`BEGIN` 未 `COMMIT` ⇒ CLI 静默回滚、退出码 0）、空文件、以及别的系统的
/// SQLite 备份。只做 `integrity_check` 不够——空库同样 `ok`。
const SQLITE_RESTORE_REQUIRED_TABLES: &[&str] = &["sys_user", "sys_menu"];

/// 陈旧 SQLite 恢复临时文件的年龄阈值（秒）。
///
/// 恢复中途进程被杀会留下完整临时库（可能数百 MB）。下次恢复开头只清理
/// 超过该阈值的文件：正在进行的另一实例（多副本共库）不会被误删。
const SQLITE_RESTORE_TEMP_STALE_SECS: u64 = 2 * 60 * 60;

// ==================== DTO ====================

/// 备份日志分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupLogQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    pub backup_type: Option<String>,
    pub status: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 `params[beginTime]`）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 `params[endTime]`）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&BackupLogQueryDto> for PageDomain {
    fn from(dto: &BackupLogQueryDto) -> Self {
        // 动态排序透传：先 sanitize（格式白名单），列级白名单在 service 查询时解析
        let mut page = PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: dto.order_by_column.clone(),
            is_asc: dto.is_asc.clone(),
        };
        page.sanitize_order_fields();
        page
    }
}

/// 备份创建响应
#[derive(Debug, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupCreateVo {
    pub backup_id: i64,
    pub file_name: String,
    pub file_path: String,
    pub file_size: i64,
}

/// 已打开的备份文件（下载处理器的入参输出）。
///
/// 除文件句柄与体积外，一并带出**归属事实**（`tenant_id` / `backup_type`）：b137 起
/// 下载要在 `sys_oper_log` 留痕，平台代管他租户数据包时必须记下目标租户——
/// 只返回 `(File, size, name)` 会让处理器拿不到这条归属，再查一次库等于同一事实读两遍。
pub struct OpenedBackupFile {
    pub file: tokio::fs::File,
    pub size: u64,
    pub file_name: String,
    pub tenant_id: i64,
    pub backup_type: String,
}

// ==================== 辅助函数 ====================

/// 根据数据库 URL 判断数据库类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbKind {
    Postgres,
    Mysql,
    Sqlite,
}

/// 从 database.url 解析数据库类型
///
/// - `postgres://` 或 `postgresql://` → Postgres
/// - `mysql://` → Mysql
/// - `sqlite://` 或 `sqlite://./data/stepby.db` → Sqlite
fn parse_db_kind(url: &str) -> Result<DbKind, ServiceError> {
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        Ok(DbKind::Postgres)
    } else if url.starts_with("mysql://") {
        Ok(DbKind::Mysql)
    } else if url.starts_with("sqlite://") || url.starts_with("sqlite:") {
        Ok(DbKind::Sqlite)
    } else {
        Err(ServiceError::bad_request(&crate::tr!(
            "error.backup.unsupported_db_type",
            url = url.split("://").next().unwrap_or("")
        )))
    }
}

/// 解析 SQLite 数据库文件路径
///
/// 支持 `sqlite://./data/stepby.db?mode=rwc` 和 `sqlite:./data/stepby.db` 两种格式
fn parse_sqlite_file_path(url: &str) -> Result<PathBuf, ServiceError> {
    let stripped = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
        .unwrap_or(url);
    // 去掉 query 参数
    let path_str = stripped.split('?').next().unwrap_or(stripped);
    Ok(PathBuf::from(path_str))
}

/// 解析 PG/MySQL 连接信息
///
/// 返回 (host, port, username, password, database)
fn parse_db_conn_info(url: &str) -> Result<(String, String, String, String, String), ServiceError> {
    // url 格式: postgres://user:password@host:port/database
    //          mysql://user:password@host:port/database
    let no_scheme = url
        .split("://")
        .nth(1)
        .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.backup.db_url_invalid")))?;
    // 拆分 user:password 和 host:port/database
    let (auth_host, db) = match no_scheme.rsplit_once('/') {
        Some((x, y)) => (x, y.to_string()),
        None => (no_scheme, String::new()),
    };
    let (user_pass, host_port) = match auth_host.rsplit_once('@') {
        Some((x, y)) => (x, y),
        None => ("", auth_host),
    };
    let (user, pass) = match user_pass.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (user_pass.to_string(), String::new()),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.to_string()),
        None => (host_port.to_string(), String::new()),
    };
    Ok((host, port, user, pass, db))
}

// ==================== 子进程参数与备份可恢复性判据 ====================

/// `pg_dump` 参数（纯函数：可恢复性契约由单测钉住）。
///
/// `--clean --if-exists` 是**可恢复性**的一半：默认 dump 只有 `CREATE TABLE`，
/// 回放到非空库会在第一条 `relation "x" already exists` 失败；带上 DROP 后
/// 新备份才能恢复到既有库，对空库则是一串无害 no-op。
fn pg_dump_args(host: &str, port: &str, user: &str, db: &str, file: &str) -> Vec<String> {
    vec![
        "--host".into(),
        host.into(),
        "--port".into(),
        port.into(),
        "--username".into(),
        user.into(),
        "--dbname".into(),
        db.into(),
        "--clean".into(),
        "--if-exists".into(),
        "--file".into(),
        file.into(),
    ]
}

/// `psql` 恢复参数（纯函数）。
///
/// `--single-transaction` + `ON_ERROR_STOP=1` 是**原子性**的两半：
/// psql 默认遇错继续执行、**退出码仍为 0** ⇒ 旧实现会把"前一半语句失败、
/// 后一半数据照常写入"记成恢复成功；两个开关合起来保证整份 dump 要么全部
/// 生效、要么全部回滚，失败时退出码非零。
fn pg_restore_args(host: &str, port: &str, user: &str, db: &str, file: &str) -> Vec<String> {
    vec![
        "--host".into(),
        host.into(),
        "--port".into(),
        port.into(),
        "--username".into(),
        user.into(),
        "--dbname".into(),
        db.into(),
        "--single-transaction".into(),
        "--set=ON_ERROR_STOP=1".into(),
        "--file".into(),
        file.into(),
    ]
}

/// `mysqldump` 参数（纯函数）。
///
/// - `--add-drop-table`：mysqldump 默认开启，但**显式写出**才能让"恢复可重放"
///   这件事在源码里可读、可测（判据不依赖客户端版本的默认值）；
/// - `--default-character-set=utf8mb4`：备份与恢复必须同字符集，否则中文数据
///   在客户端默认 latin1 的机器上静默乱码。
fn mysqldump_args(host: &str, port: &str, user: &str, db: &str, file: &str) -> Vec<String> {
    vec![
        "--host".into(),
        host.into(),
        "--port".into(),
        port.into(),
        "--user".into(),
        user.into(),
        "--single-transaction".into(),
        "--routines".into(),
        "--triggers".into(),
        "--add-drop-table".into(),
        "--default-character-set=utf8mb4".into(),
        db.into(),
        "--result-file".into(),
        file.into(),
    ]
}

/// `mysql` 恢复参数（纯函数）：字符集必须与 `mysqldump_args` 同源。
fn mysql_restore_args(host: &str, port: &str, user: &str, db: &str) -> Vec<String> {
    vec![
        "--host".into(),
        host.into(),
        "--port".into(),
        port.into(),
        "--user".into(),
        user.into(),
        "--default-character-set=utf8mb4".into(),
        db.into(),
    ]
}

/// 备份文件大小校验：空文件与"与登记大小不一致"一律拒绝。
///
/// 两类都是真实事故形状：备份进程被杀留下半份、磁盘写满截断、文件被人替换。
/// 恢复是**破坏性**操作，必须在触碰在线库之前拦住；下载同样要拦——把截断的
/// 备份当成功件带离现场，等于把唯一可用的恢复材料也弄没了。
///
/// `recorded <= 0` 表示历史行没有可用的登记大小（早期 restore 记录），此时
/// 只判空文件，不误杀。
fn validate_backup_file_size(recorded: i64, actual: u64) -> Result<(), &'static str> {
    if actual == 0 {
        return Err("error.backup.dump_empty");
    }
    if recorded > 0 && actual != recorded as u64 {
        return Err("error.backup.dump_size_mismatch");
    }
    Ok(())
}

/// 把校验失败翻译成用户可见错误（参数化文案由 i18n 负责）。
fn backup_size_error(key: &str, recorded: i64, actual: u64) -> ServiceError {
    if key == "error.backup.dump_empty" {
        ServiceError::bad_request(&crate::tr!("error.backup.dump_empty"))
    } else {
        ServiceError::bad_request(&crate::tr!(
            "error.backup.dump_size_mismatch",
            expected = recorded,
            actual = actual
        ))
    }
}

/// 按字符截断恢复错误信息（保留可读性，避免 UTF-8 中间截断）。
fn truncate_restore_error(msg: &str) -> String {
    let mut out: String = msg.chars().take(RESTORE_ERROR_MAX_CHARS).collect();
    if msg.chars().count() > RESTORE_ERROR_MAX_CHARS {
        out.push('…');
    }
    out
}

/// sqlite3 **点命令**的路径引用。
///
/// 点命令按空白切分参数：`.backup C:\a b\c.db` 会把路径截成两段、静默备份到
/// 错误位置。双引号内可保留单引号（Windows 路径常见），路径含双引号时改用
/// 单引号；两种引号同时出现（Unix 合法文件名）拒绝执行，而不是拼一个可疑命令。
///
/// **反斜杠必须先归一**（b99 实证）：sqlite3 的引号解析器**在引号内仍处理
/// 反斜杠转义**，`"C:\Users\..."` 会被读成 `C:Users...`（`\t` 之类变成控制字符），
/// `.backup` 于是一个字节都没写进在线库却**退出码 0** —— 上层据此报"恢复成功"。
/// Windows 接受正斜杠，统一转换；Unix 文件名允许反斜杠但点命令会吃掉它，
/// 直接拒绝而不是猜一个目标路径。
fn sqlite_dot_arg(path: &Path) -> Result<String, ServiceError> {
    let mut raw = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        raw = raw.replace('\\', "/");
    } else if raw.contains('\\') {
        return Err(ServiceError::internal(&crate::tr!(
            "error.backup.sqlite_path_unsupported"
        )));
    }
    if !raw.contains('"') {
        Ok(format!("\"{raw}\""))
    } else if !raw.contains('\'') {
        Ok(format!("'{raw}'"))
    } else {
        Err(ServiceError::internal(&crate::tr!(
            "error.backup.sqlite_path_unsupported"
        )))
    }
}

/// 读取数据库的 `PRAGMA user_version`（替换的落地指纹）。
///
/// 为什么不用 `schema_version/page_count`：两者都不是内容指纹——b99 实测
/// "写到别处"的那一轮直播库与临时库 `page_count` 完全相同，而 `schema_version`
/// 会因连接活动正常漂移。`user_version` 是 DB 头里的一个 32 位字段，`.backup`
/// 会逐页复制（已实测），且**合并式写入（WAL）下只有真正替换成功才会出现**。
async fn sqlite_user_version(db: &Path) -> Result<i64, ServiceError> {
    let out = run_sqlite_step(db, &["PRAGMA user_version;".to_string()], true, None).await?;
    if !out.status.success() {
        return Err(ServiceError::internal(&crate::tr!(
            "error.backup.sqlite_restore_swap_failed",
            err = truncate_restore_error(String::from_utf8_lossy(&out.stderr).trim())
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim().parse().map_err(|_| {
        ServiceError::internal(&crate::tr!(
            "error.backup.sqlite_restore_swap_failed",
            err = truncate_restore_error(&format!("user_version 输出不可解析: {text:?}"))
        ))
    })
}

/// 写回 `PRAGMA user_version`（替换完成后把指纹还原成恢复前的值）。
async fn sqlite_set_user_version(db: &Path, value: i64) -> Result<(), ServiceError> {
    let out = run_sqlite_step(db, &[format!("PRAGMA user_version = {value};")], true, None).await?;
    if !out.status.success() {
        return Err(ServiceError::internal(&crate::tr!(
            "error.backup.sqlite_restore_swap_failed",
            err = truncate_restore_error(String::from_utf8_lossy(&out.stderr).trim())
        )));
    }
    Ok(())
}

/// 获取备份目录绝对路径（不存在则创建）
///
/// 注：此函数执行同步 IO，调用方需在 spawn_blocking 中使用
fn ensure_backup_dir() -> Result<PathBuf, ServiceError> {
    let dir = PathBuf::from(BACKUP_DIR);
    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.mkdir_failed")))?;
    }
    Ok(dir)
}

/// 异步版本：在 spawn_blocking 中执行 ensure_backup_dir
async fn ensure_backup_dir_async() -> Result<PathBuf, ServiceError> {
    tokio::task::spawn_blocking(ensure_backup_dir)
        .await
        .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.mkdir_task_join_failed")))?
}

/// 校验备份文件路径必须位于备份目录内（防路径穿越）
///
/// 使用 canonicalize 二次校验规范化后路径仍以备份目录开头
async fn validate_backup_path(file_name: &str) -> Result<PathBuf, ServiceError> {
    if file_name.is_empty()
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name.contains("..")
        || file_name.contains('\0')
    {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.backup.filename_invalid"
        )));
    }
    let dir = ensure_backup_dir_async().await?;
    // Defense-in-depth: canonicalize the directory to resolve any symlinks
    let canonical_dir = tokio::fs::canonicalize(&dir)
        .await
        .map_err(|_| ServiceError::bad_request(&crate::tr!("error.backup.filename_invalid")))?;
    let file_path = canonical_dir.join(file_name);
    Ok(file_path)
}

// ==================== SQLite 恢复：临时库重建 + 校验 + 原子替换 ====================

/// 运行一次 sqlite3 子进程（stdout/stderr 捕获，5 分钟超时，kill_on_drop）。
///
/// `safe=true` 时带 `-safe -bail`：**dump 是从磁盘读入的完整脚本，可能被人替换**，
/// `-safe` 禁掉 `.shell` / `.system` 等点命令（否则一条伪造的备份文件就是一次
/// 任意命令执行），`-bail` 让首个错误立即停止而不是继续执行后续语句。
async fn run_sqlite_step(
    db: &Path,
    args: &[String],
    safe: bool,
    stdin: Option<std::process::Stdio>,
) -> Result<std::process::Output, ServiceError> {
    let mut cmd = Command::new("sqlite3");
    if safe {
        cmd.arg("-safe").arg("-bail");
    }
    cmd.arg(db)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(stdin) = stdin {
        cmd.stdin(stdin);
    }
    let child = cmd
        .spawn()
        .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.sqlite3_failed")))?;
    tokio::time::timeout(
        Duration::from_secs(BACKUP_TIMEOUT_SECS),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| {
        ServiceError::internal(&crate::tr!(
            "error.backup.restore_process_timeout",
            secs = BACKUP_TIMEOUT_SECS
        ))
    })?
    .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.restore_process_exec_failed")))
}

/// 删除临时库三件套（主文件 + `-wal` + `-shm`），NotFound 视为已清理。
async fn cleanup_sqlite_temp(temp: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut os = temp.as_os_str().to_os_string();
        os.push(suffix);
        let path = PathBuf::from(os);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                file = %path.file_name().unwrap_or_default().to_string_lossy(),
                error = %e,
                "{}",
                crate::tr!("error.backup.restore_sqlite_tmp_cleanup_failed")
            ),
        }
    }
}

/// 备份失败后删除半份产物：失败文件既不可下载也不可恢复（status=failed），
/// 留在盘上只会占空间，并在"登记大小 vs 实际大小"的校验里制造后续噪声。
async fn remove_partial_backup(path: &Path) {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            file = %path.file_name().unwrap_or_default().to_string_lossy(),
            error = %e,
            "备份失败后清理半份产物失败"
        ),
    }
}

/// 清理超过 [`SQLITE_RESTORE_TEMP_STALE_SECS`] 的陈旧恢复临时库。
///
/// 只认固定前缀与三种后缀，且只删"够旧"的：多副本部署下另一实例正在进行的
/// 恢复不会被误删（它的临时库刚刚创建）。目录不可枚举只 WARN 不阻断——
/// 这是卫生动作，不是判据。
async fn sweep_stale_restore_temps(dir: &Path) {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(error = %e, "SQLite 恢复临时文件清理：目录不可枚举，跳过");
            return;
        }
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0usize;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(SQLITE_RESTORE_TEMP_PREFIX)
            || !(name.ends_with(".db") || name.ends_with(".db-wal") || name.ends_with(".db-shm"))
        {
            continue;
        }
        let stale = entry
            .metadata()
            .await
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age.as_secs() >= SQLITE_RESTORE_TEMP_STALE_SECS);
        if !stale {
            continue;
        }
        match tokio::fs::remove_file(entry.path()).await {
            Ok(()) => removed += 1,
            Err(e) => {
                tracing::warn!(file = %name, error = %e, "陈旧 SQLite 恢复临时文件删除失败")
            }
        }
    }
    if removed > 0 {
        tracing::info!(count = removed, "已清理陈旧 SQLite 恢复临时文件");
    }
}

/// 用 SQL 文本备份重建在线 SQLite 库（临时库 → 校验 → Backup API 原子替换）。
///
/// 为什么不能直接 `.read` 回放（旧实现）：
/// 1. `.dump` 产物是 `CREATE TABLE`（无 `IF NOT EXISTS`/`DROP`）⇒ 对非空库第一条
///    `table already exists` 就失败，**任何真实数据库的恢复都跑不通**（b99 实证）；
/// 2. SQLite CLI 遇错默认继续执行 ⇒ 表不存在时先建、再写一半数据，留下半恢复状态；
/// 3. `.read <path>` 还依赖点命令的空白切分，目录含空格时路径被截断。
///
/// 现方案：dump 经 **stdin** 喂给临时库（不经点命令解析、`-safe` 禁点命令），
/// 校验 `integrity_check=ok` 且核心表齐全后，用 SQLite Backup API（`.backup`）
/// 把临时库**原子替换**进在线库——目标库上的写事务保证读者要么看到旧内容、
/// 要么看到新内容，不会看到半成品；任何一步失败在线库都未被改动。
async fn restore_sqlite_from_dump(live_db: &Path, dump: &Path) -> Result<(), ServiceError> {
    let dir = live_db.parent().unwrap_or_else(|| Path::new("."));
    sweep_stale_restore_temps(dir).await;
    let temp = dir.join(format!(
        "{SQLITE_RESTORE_TEMP_PREFIX}{}.db",
        uuid::Uuid::new_v4().simple()
    ));

    let outcome: Result<(), ServiceError> = async {
        // 1) 重建临时库。stdin 直接接文件句柄：dump 多大都不进内存。
        let dump_file = std::fs::File::open(dump).map_err(|_| {
            ServiceError::internal(&crate::tr!("error.backup.read_backup_file_failed"))
        })?;
        let build = run_sqlite_step(
            &temp,
            &[],
            true,
            Some(std::process::Stdio::from(dump_file)),
        )
        .await?;
        if !build.status.success() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.backup.sqlite_dump_invalid",
                err = truncate_restore_error(
                    String::from_utf8_lossy(&build.stderr).trim()
                )
            )));
        }

        // 2) 校验：完整 + 核心表齐全。
        //    截断的 dump（BEGIN 未 COMMIT）会被 SQLite 静默回滚、退出码 0，
        //    所以"命令成功"不等于"库建对了"——必须查事实。
        let names = SQLITE_RESTORE_REQUIRED_TABLES
            .iter()
            .map(|t| format!("'{t}'"))
            .collect::<Vec<_>>()
            .join(",");
        let check_sql = format!(
            "PRAGMA integrity_check;\nSELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ({names});"
        );
        let check = run_sqlite_step(&temp, &[check_sql], true, None).await?;
        let stdout = String::from_utf8_lossy(&check.stdout);
        let mut lines = stdout.lines();
        let integrity = lines.next().unwrap_or("").trim().to_string();
        let table_count: i64 = lines
            .next()
            .and_then(|l| l.trim().parse().ok())
            .unwrap_or(-1);
        if !check.status.success() || integrity != "ok" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.backup.sqlite_dump_corrupt",
                detail = truncate_restore_error(&format!(
                    "integrity_check={integrity}; stderr={}",
                    String::from_utf8_lossy(&check.stderr).trim()
                ))
            )));
        }
        if table_count != SQLITE_RESTORE_REQUIRED_TABLES.len() as i64 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.backup.sqlite_dump_incomplete",
                tables = SQLITE_RESTORE_REQUIRED_TABLES.join(", ")
            )));
        }

        // 3) 原子替换。`.backup` 必须在非 safe 模式执行（safe 模式禁用它），
        //    输入只有下方这一条自造点命令，不含 dump 内容。
        //    退出码 0 **不足以**证明替换落在在线库上（b99 实证：点命令把路径里的
        //    反斜杠当转义吃掉时，它写到了别处仍返回 0）⇒ 在临时库写一枚
        //    user_version 指纹，替换成功后在在线库读回，读不到就是没落地。
        let original_uv = sqlite_user_version(live_db).await?;
        let mut canary = (uuid::Uuid::new_v4().as_u128() & 0x7fff_ffff) as i64;
        if canary == 0 || canary == original_uv {
            canary = if original_uv == 1 { 2 } else { 1 };
        }
        let mark = run_sqlite_step(
            &temp,
            &[format!("PRAGMA user_version = {canary};")],
            true,
            None,
        )
        .await?;
        if !mark.status.success() {
            return Err(ServiceError::internal(&crate::tr!(
                "error.backup.sqlite_restore_swap_failed",
                err = truncate_restore_error(String::from_utf8_lossy(&mark.stderr).trim())
            )));
        }
        let live_arg = sqlite_dot_arg(live_db)?;
        let swap = run_sqlite_step(
            &temp,
            &[".timeout 10000".to_string(), format!(".backup {live_arg}")],
            false,
            None,
        )
        .await?;
        if !swap.status.success() {
            return Err(ServiceError::internal(&crate::tr!(
                "error.backup.sqlite_restore_swap_failed",
                err = truncate_restore_error(
                    String::from_utf8_lossy(&swap.stderr).trim()
                )
            )));
        }
        let landed = sqlite_user_version(live_db).await?;
        if landed != canary {
            return Err(ServiceError::internal(&crate::tr!(
                "error.backup.sqlite_restore_swap_failed",
                err = format!(
                    "在线库未出现备份指纹（期望 user_version={canary}，实际 {landed}）——                     备份可能写到了别的路径"
                )
            )));
        }
        // 指纹还原（不影响恢复结论：user_version 不参与业务）。
        if let Err(e) = sqlite_set_user_version(live_db, original_uv).await {
            tracing::warn!(error = %e, "SQLite 恢复：user_version 还原失败（不影响数据）");
        }
        Ok(())
    }
    .await;

    cleanup_sqlite_temp(&temp).await;
    outcome
}

// ==================== Service 实现 ====================

/// 备份日志允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖备份日志业务展示列（主键、文件名、大小、类型、状态、时间）；
/// `file_path`（文件系统路径）、`error_msg`、`tenant_id` 等内部/敏感列不开放动态排序。
const BACKUP_LOG_SORTABLE_COLUMNS: &[(&str, BackupLogColumn)] = &[
    ("backup_id", BackupLogColumn::BackupId),
    ("file_name", BackupLogColumn::FileName),
    ("file_size", BackupLogColumn::FileSize),
    ("backup_type", BackupLogColumn::BackupType),
    ("status", BackupLogColumn::Status),
    ("create_time", BackupLogColumn::CreateTime),
];

/// 数据备份/恢复 Service
pub struct SysBackupService {
    backup_repo: SysBackupLogRepository,
    config: std::sync::Arc<Settings>,
}

impl SysBackupService {
    pub fn new(db: DatabaseConnection, config: std::sync::Arc<Settings>) -> Self {
        Self {
            backup_repo: SysBackupLogRepository::new(db),
            config,
        }
    }

    /// 启动期收敛「卡在 running」的备份日志（b73，AGENTS B.6「失败审计」的数据面收口）。
    ///
    /// 形态：`create_backup` / 租户自导出先插 `status='running'` 占位行，子进程结束后写终态。
    /// 进程在子进程运行期间被杀（发布重启 / OOM / 会话回收）⇒ 该行**永久停留 running**：
    /// 备份列表页显示一个永远在跑的备份，运维无从判断结局，`find_excess_success_ids` 轮转也绕开它。
    ///
    /// 阈值取 `BACKUP_TIMEOUT_SECS` 的两倍再加一分钟：子进程自身已有 5 分钟超时，
    /// 超过 2×超时 + 余量仍为 running 的行**不可能是本进程的合法在途任务**。
    /// **多副本共库的口径**：另一实例真在跑的备份理论上可能落在此窗口内，故阈值必须远大于单次备份
    /// 预算（不得调小），且只写 `error_msg` 说明是"启动期收敛"，不删行——保留可追溯性。
    ///
    /// 幂等：只处理 `status='running'`，二次调用零命中；失败上抛（由调用方 best-effort 留痕）。
    pub async fn reconcile_interrupted_backups(&self) -> Result<u64, ServiceError> {
        let stale_before = crate::common::datetime::now_naive()
            - chrono::Duration::seconds((BACKUP_TIMEOUT_SECS * 2 + 60) as i64);
        let rows = self
            .backup_repo
            .find_stale_running(stale_before)
            .await
            .map_err(|e| ServiceError::internal(&format!("查询中断备份日志失败: {e}")))?;
        let total = rows.len() as u64;
        for row in rows {
            let backup_id = row.backup_id;
            let mut am: SysBackupLogActiveModel = row.into();
            am.status = Set("failed".to_string());
            am.error_msg = Set(Some(format!(
                "备份进程未回写终态（超 {} 分钟仍为 running），已由启动期收敛判为失败；\
                 若产物文件存在可手动校验后登记",
                (BACKUP_TIMEOUT_SECS * 2 + 60) / 60
            )));
            self.backup_repo.update(am).await.map_err(|e| {
                ServiceError::internal(&format!(
                    "收敛中断备份日志失败 (backup_id={backup_id}): {e}"
                ))
            })?;
        }
        if total > 0 {
            tracing::warn!(
                count = total,
                "启动期收敛：{} 条备份日志卡在 running，已判为 failed（进程中断导致结局未知）",
                total
            );
        }
        Ok(total)
    }

    /// 创建数据库备份
    ///
    /// 流程：
    /// 1. 解析数据库类型
    /// 2. 生成唯一备份文件名 `{timestamp}_{uuid}.{ext}`
    /// 3. 调用对应工具子进程（pg_dump/mysqldump/sqlite3 .dump）
    /// 4. 5 分钟超时保护
    /// 5. 记录备份日志（成功/失败均记录）
    pub async fn create_backup(&self, operator: &str) -> Result<BackupCreateVo, ServiceError> {
        let db_url = self.config.database.url.clone();
        let kind = parse_db_kind(&db_url)?;

        let ts = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let uuid_str = uuid::Uuid::new_v4().simple().to_string();
        let ext = match kind {
            DbKind::Postgres => "sql",
            DbKind::Mysql => "sql",
            DbKind::Sqlite => "db",
        };
        let file_name = format!("{}_{}.{}", ts, uuid_str, ext);
        let file_path = validate_backup_path(&file_name).await?;
        let file_path_str = file_path.to_string_lossy().to_string();

        let now = crate::common::datetime::now_naive();
        // 预创建一条 pending 日志（status=failed 占位，执行成功后更新为 success）
        let pending_am = SysBackupLogActiveModel {
            file_name: Set(file_name.clone()),
            file_path: Set(file_path_str.clone()),
            file_size: Set(0_i64),
            backup_type: Set("manual".to_string()),
            status: Set("running".to_string()),
            error_msg: Set(None),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            ..Default::default()
        };
        let log_model = self.backup_repo.insert(pending_am).await?;
        let backup_id = log_model.backup_id;

        // 执行备份子进程
        let result = self.run_backup_process(kind, &db_url, &file_path).await;

        // 异步获取文件大小，避免阻塞 worker
        let file_size = {
            let fp = file_path.clone();
            match tokio::task::spawn_blocking(move || std::fs::metadata(fp)).await {
                Ok(Ok(m)) => m.len() as i64,
                _ => 0,
            }
        };

        let (status, error_msg) = match result {
            // 退出码 0 但产物为空 ⇒ 不能记成功：这样的"备份"既不可恢复也不可下载，
            // 却会占掉一个保留位并把最旧的可用备份轮转掉。
            Ok(()) if file_size <= 0 => {
                remove_partial_backup(&file_path).await;
                tracing::error!(
                    "备份产物为空 (backup_id={})，按失败处理（子进程退出码为 0）",
                    backup_id
                );
                (
                    "failed".to_string(),
                    Some(crate::tr!("error.backup.dump_empty")),
                )
            }
            Ok(()) => ("success".to_string(), None),
            Err(e) => {
                tracing::error!("备份失败 (backup_id={}): {}", backup_id, e);
                (
                    "failed".to_string(),
                    Some(truncate_restore_error(&e.to_string())),
                )
            }
        };

        // 更新日志状态
        let mut update_am: SysBackupLogActiveModel = log_model.into();
        update_am.status = Set(status.clone());
        update_am.error_msg = Set(error_msg);
        update_am.file_size = Set(file_size);
        let updated = self.backup_repo.update(update_am).await?;

        if status == "failed" {
            return Err(ServiceError::internal(
                updated
                    .error_msg
                    .as_deref()
                    .unwrap_or(&crate::tr!("error.backup.db_backup_failed")),
            ));
        }

        // 成功备份后自动轮转（fail-open：清理异常只记警告，不影响本次备份结果）
        if let Err(e) = self.cleanup_excess_backups().await {
            tracing::warn!(
                "备份轮转清理失败（不影响本次备份 backup_id={}）: {}",
                updated.backup_id,
                e
            );
        }

        Ok(BackupCreateVo {
            backup_id: updated.backup_id,
            file_name: updated.file_name,
            file_path: updated.file_path,
            file_size: updated.file_size,
        })
    }

    /// 自动轮转：删除超出 `RETAIN_SUCCESS_BACKUPS` 的最旧整库备份（文件 + 日志记录）
    ///
    /// 复用 `delete_backups` 链路（含 canonicalize 路径二次校验、spawn_blocking 异步删文件），
    /// 保证与手动删除同级别的安全语义。
    async fn cleanup_excess_backups(&self) -> Result<(), ServiceError> {
        let excess_ids = self
            .backup_repo
            .find_excess_success_ids(RETAIN_SUCCESS_BACKUPS)
            .await?;
        if excess_ids.is_empty() {
            return Ok(());
        }
        tracing::info!(
            "备份轮转：保留最近 {} 份整库备份，清理 {} 份过期备份（ids 前缀 {:?}...）",
            RETAIN_SUCCESS_BACKUPS,
            excess_ids.len(),
            &excess_ids[..excess_ids.len().min(3)]
        );
        self.delete_backups(excess_ids).await
    }

    /// 导出「租户数据包」（台账 F-2 定案：整库备份保留 + 新增租户数据包导出；**不做**租户级恢复）
    ///
    /// 语义：把该租户在全部「承载租户归属」表（`initialize::TENANT_CARRYING_TABLES`，33 张，
    /// 逐表探测表/列存在性后按 `tenant_id = ?` 精确收窄）+ 租户表族本体
    /// （`sys_tenant` / `sys_tenant_domain` / `sys_tenant_menu`）的行导出为**单个 JSON 文件**
    /// 落盘到备份目录，并登记一条 `backup_type = "tenant_export"` 的备份日志
    /// ⇒ 直接复用既有备份列表 / 下载 / 删除链路（无需新增存储与清理逻辑）。
    ///
    /// 安全：
    /// - 本方法只服务平台专属能力（路由 `platform_only_guard` + `system:backup:*` 不在租户
    ///   可授集合），租户操作者一律 403；
    /// - 导出范围按 `tenant_id = ?` 精确过滤，不含其它租户数据；`tenant_id = 0`（平台租户）
    ///   同样允许导出（平台代管数据的自留包）；
    /// - 只导出不导入：租户级恢复需处理跨租户外键/依赖顺序，成本高收益低，明确不做。
    pub async fn export_tenant_package(
        &self,
        tenant_id: i64,
        operator: &str,
    ) -> Result<BackupCreateVo, ServiceError> {
        let db = self.backup_repo.base().db();
        let backend = db.get_database_backend();
        // PG 用 $n 占位符，SQLite/MySQL 用 ?
        let ph = |i: usize| -> String {
            if backend == DatabaseBackend::Postgres {
                format!("${i}")
            } else {
                "?".to_string()
            }
        };

        // 1. 租户存在性校验（不过滤 del_flag：回收站租户同样允许导出留档）
        let tenant_row = db
            .query_one_raw(Statement::from_sql_and_values(
                backend,
                format!(
                    "SELECT tenant_code, tenant_name FROM sys_tenant WHERE tenant_id = {}",
                    ph(1)
                ),
                [tenant_id.into()],
            ))
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.backup.tenant_not_found")))?;
        let tenant_code: String = tenant_row.try_get("", "tenant_code").unwrap_or_default();
        let tenant_name: String = tenant_row.try_get("", "tenant_name").unwrap_or_default();

        // 2. 逐表导出（表 / 列缺失则跳过并登记，兼容历史库）
        let mut tables = serde_json::Map::new();
        let mut table_counts = serde_json::Map::new();
        let mut skipped_tables: Vec<String> = Vec::new();
        for table in crate::initialize::TENANT_CARRYING_TABLES
            .iter()
            .chain(TENANT_PACKAGE_EXTRA_TABLES.iter())
        {
            if !crate::initialize::sso_table_exists(db, table).await? {
                skipped_tables.push((*table).to_string());
                continue;
            }
            if !crate::initialize::sso_has_column(db, table, "tenant_id").await? {
                skipped_tables.push((*table).to_string());
                continue;
            }
            let rows = db
                .query_all_raw(Statement::from_sql_and_values(
                    backend,
                    format!("SELECT * FROM {} WHERE tenant_id = {}", table, ph(1)),
                    [tenant_id.into()],
                ))
                .await?;
            // 行 → JSON：sea-orm 的 `JsonValue`（= serde_json::Value）已实现 FromQueryResult，
            // 按各表实际列类型解码（三方言 sqlx 后端分支齐备），无需逐表维护实体映射。
            let mut json_rows: Vec<serde_json::Value> = Vec::with_capacity(rows.len());
            for row in &rows {
                json_rows.push(serde_json::Value::from_query_result(row, "")?);
            }
            table_counts.insert(
                (*table).to_string(),
                serde_json::Value::from(json_rows.len()),
            );
            tables.insert((*table).to_string(), serde_json::Value::Array(json_rows));
        }

        // 3. 组装包体（含包格式/版本与租户身份，便于离线识别与后续版本演进）
        let package = serde_json::json!({
            "format": "stepby-tenant-package",
            "version": 1,
            "exportedAt": crate::common::datetime::now_naive(),
            "tenantId": tenant_id,
            "tenantCode": tenant_code,
            "tenantName": tenant_name,
            "tableCounts": table_counts,
            "skippedTables": skipped_tables,
            "tables": tables,
        });

        // 4. 落盘 + 登记备份日志
        let ts = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let uuid_str = uuid::Uuid::new_v4().simple().to_string();
        let file_name = format!("tenant_{}_{}_{}.json", tenant_id, ts, uuid_str);
        let file_path = validate_backup_path(&file_name).await?;
        let bytes = serde_json::to_vec_pretty(&package).map_err(|e| {
            tracing::error!("租户数据包序列化失败 (tenant_id={}): {}", tenant_id, e);
            ServiceError::internal(&crate::tr!("error.backup.tenant_export_serialize_failed"))
        })?;
        let file_size = bytes.len() as i64;
        let file_path_for_write = file_path.clone();
        tokio::task::spawn_blocking(move || std::fs::write(&file_path_for_write, &bytes))
            .await
            .map_err(|_| {
                ServiceError::internal(&crate::tr!("error.backup.write_task_join_failed"))
            })?
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.write_failed")))?;

        let file_path_str = file_path.to_string_lossy().to_string();
        let am = SysBackupLogActiveModel {
            tenant_id: Set(tenant_id),
            file_name: Set(file_name.clone()),
            file_path: Set(file_path_str.clone()),
            file_size: Set(file_size),
            backup_type: Set(BACKUP_TYPE_TENANT_EXPORT.to_string()),
            status: Set("success".to_string()),
            error_msg: Set(None),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(crate::common::datetime::now_naive())),
            ..Default::default()
        };
        let log_model = self.backup_repo.insert(am).await?;

        Ok(BackupCreateVo {
            backup_id: log_model.backup_id,
            file_name,
            file_path: file_path_str,
            file_size,
        })
    }

    /// 执行备份子进程
    async fn run_backup_process(
        &self,
        kind: DbKind,
        db_url: &str,
        file_path: &Path,
    ) -> Result<(), ServiceError> {
        let file_path_str = file_path.to_string_lossy().to_string();

        // SQLite 单独处理：`.dump` 的 stdout **直接重定向到备份文件**。
        // 旧实现把整个 dump 收进 `output.stdout`（Vec<u8>）再写盘——100MB 级库
        // 每次备份都要先占一份等量内存。
        if kind == DbKind::Sqlite {
            let db_file = parse_sqlite_file_path(db_url)?;
            let stdout_file = std::fs::File::create(file_path)
                .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.write_failed")))?;
            let child = tokio::process::Command::new("sqlite3")
                .arg(db_file)
                .arg(".dump")
                .stdout(std::process::Stdio::from(stdout_file))
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.sqlite3_failed")))?;
            let output = tokio::time::timeout(
                Duration::from_secs(BACKUP_TIMEOUT_SECS),
                child.wait_with_output(),
            )
            .await
            .map_err(|_| {
                ServiceError::internal(&crate::tr!(
                    "error.backup.process_timeout",
                    secs = BACKUP_TIMEOUT_SECS
                ))
            })?
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.process_exec_failed")))?;
            if !output.status.success() {
                remove_partial_backup(file_path).await;
                let err = String::from_utf8_lossy(&output.stderr).to_string();
                return Err(ServiceError::internal(&crate::tr!(
                    "error.backup.sqlite3_backup_failed",
                    err = truncate_restore_error(&err)
                )));
            }
            return Ok(());
        }

        // Postgres / MySQL 使用 --file/--result-file 直接写文件
        let mut cmd = match kind {
            DbKind::Postgres => {
                let (host, port, user, pass, db) = parse_db_conn_info(db_url)?;
                let mut c = Command::new("pg_dump");
                c.args(pg_dump_args(&host, &port, &user, &db, &file_path_str));
                c.env("PGPASSWORD", pass);
                c
            }
            DbKind::Mysql => {
                let (host, port, user, pass, db) = parse_db_conn_info(db_url)?;
                let mut c = Command::new("mysqldump");
                c.args(mysqldump_args(&host, &port, &user, &db, &file_path_str));
                // B7：将密码经 MYSQL_PWD 环境变量传递，避免明文出现在进程命令行
                // （`ps` / `/proc` 可见，属中危泄漏）。与下方 restore 分支及 Postgres
                // 的 PGPASSWORD 同构。MySQL 8.0 客户端会打印一条
                // "using password in environment variable" 提示，无害。
                c.env("MYSQL_PWD", pass);
                c
            }
            DbKind::Sqlite => {
                return Err(ServiceError::internal(&crate::tr!(
                    "error.backup.sqlite3_branch_unreachable"
                )));
            }
        };

        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        // 5 分钟超时
        let child = cmd.spawn().map_err(|_| {
            ServiceError::internal(&crate::tr!("error.backup.process_start_failed"))
        })?;

        let output = tokio::time::timeout(
            Duration::from_secs(BACKUP_TIMEOUT_SECS),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| {
            ServiceError::internal(&crate::tr!(
                "error.backup.process_timeout",
                secs = BACKUP_TIMEOUT_SECS
            ))
        })?
        .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.process_exec_failed")))?;

        if !output.status.success() {
            remove_partial_backup(file_path).await;
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(ServiceError::internal(&crate::tr!(
                "error.backup.process_nonzero_exit",
                err = truncate_restore_error(&err)
            )));
        }
        Ok(())
    }

    /// 恢复数据库备份
    ///
    /// 流程：
    /// 1. 校验备份记录存在、状态成功、不是租户数据包
    /// 2. 校验文件路径穿越（必须位于备份目录内）
    /// 3. **校验文件非空且与登记大小一致**（截断/替换的备份在触碰在线库之前拦住）
    /// 4. 调用对应工具子进程（psql 原子事务 / mysql 流式 / sqlite3 临时库重建+原子替换）
    /// 5. 5 分钟超时保护
    /// 6. 记录恢复日志（backup_type=restore，含真实文件大小与截断后的错误原因）
    pub async fn restore_backup(&self, backup_id: i64, operator: &str) -> Result<(), ServiceError> {
        let log = self
            .backup_repo
            .find_by_id(backup_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.backup.record_not_found")))?;

        if log.status != "success" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.backup.restore_status_invalid"
            )));
        }

        // 仅整库备份（manual/auto）可恢复：租户数据包（tenant_export）是 JSON 导出件，
        // 不承载整库结构，且 F-2 已定案「不做租户级恢复」（跨租户外键/依赖顺序成本高收益低）
        if log.backup_type == BACKUP_TYPE_TENANT_EXPORT {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.backup.tenant_export_restore_unsupported"
            )));
        }

        // 校验文件路径穿越（取 basename 重新拼接）
        let base_name = std::path::Path::new(&log.file_name)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                ServiceError::bad_request(&crate::tr!("error.backup.filename_invalid_restore"))
            })?
            .to_string();
        let file_path = validate_backup_path(&base_name).await?;
        let file_path_for_meta = file_path.clone();
        let actual_size = tokio::task::spawn_blocking(move || {
            std::fs::metadata(&file_path_for_meta).map(|m| m.len())
        })
        .await
        .map_err(|_| {
            ServiceError::internal(&crate::tr!("error.backup.file_exist_check_join_failed"))
        })?
        .map_err(|_| ServiceError::not_found(&crate::tr!("error.backup.file_not_found")))?;

        let db_url = self.config.database.url.clone();
        let kind = parse_db_kind(&db_url)?;
        // 文件大小校验也走"记录恢复日志"的统一出口：恢复失败必须留痕，
        // 否则运维只能从 oper_log 猜这次点的是哪份备份、为什么被拒。
        let result = match validate_backup_file_size(log.file_size, actual_size) {
            Ok(()) => self.run_restore_process(kind, &db_url, &file_path).await,
            Err(key) => Err(backup_size_error(key, log.file_size, actual_size)),
        };

        let now = crate::common::datetime::now_naive();
        // 失败时保留**原始错误码**回给客户端：早前这里统一包成 internal(500)，
        // 于是"备份被截断/内容非法"这类 400 级可修正错误在界面上变成 500，
        // 运维只能看到一串 `ServiceError(code=400, ...)` 的字符串化消息。
        let (status, error_msg, failure) = match result {
            Ok(()) => ("success".to_string(), None, None),
            Err(e) => {
                let message = truncate_restore_error(&e.message);
                tracing::error!("恢复失败 (backup_id={}): {}", backup_id, message);
                let returned = ServiceError {
                    code: e.code,
                    message: message.clone(),
                    retry_after: e.retry_after,
                };
                ("failed".to_string(), Some(message), Some(returned))
            }
        };

        // 记录恢复日志（独立记录，保留原备份记录不变）
        let am = SysBackupLogActiveModel {
            file_name: Set(log.file_name.clone()),
            file_path: Set(log.file_path.clone()),
            // 恢复行此前记的是"被恢复备份的登记大小"（早期版本为 0），
            // 现统一记**本次实际读取的文件大小**：它与 decision 使用的元数据同源。
            file_size: Set(actual_size as i64),
            backup_type: Set("restore".to_string()),
            status: Set(status.clone()),
            error_msg: Set(error_msg.clone()),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            ..Default::default()
        };
        self.backup_repo.insert(am).await?;

        if let Some(err) = failure {
            return Err(err);
        }

        Ok(())
    }

    /// 执行恢复子进程
    ///
    /// 三种方言的可恢复性/原子性口径（b99 收口）：
    /// - **SQLite**：dump 是 SQL 文本，不能直接回放到非空库 ⇒ 临时库重建 + 校验
    ///   + Backup API 原子替换（见 [`restore_sqlite_from_dump`]）；
    /// - **PostgreSQL**：`--single-transaction` + `ON_ERROR_STOP=1` ⇒ 要么全生效、
    ///   要么全回滚（psql 默认遇错继续且退出码 0，会把半写记成成功）；
    /// - **MySQL**：`mysql` 客户端默认遇错中止，dump 自带 `DROP TABLE IF EXISTS`
    ///   （`mysqldump --add-drop-table` 默认开启）⇒ 可重放；输入流式喂入。
    async fn run_restore_process(
        &self,
        kind: DbKind,
        db_url: &str,
        file_path: &Path,
    ) -> Result<(), ServiceError> {
        let file_path_str = file_path.to_string_lossy().to_string();

        // MySQL 单独处理：需要通过 stdin 喂入 SQL 文件内容（避免 shell 重定向带来的命令注入）
        if kind == DbKind::Mysql {
            return self.run_mysql_restore(db_url, file_path).await;
        }

        let mut cmd = match kind {
            DbKind::Postgres => {
                let (host, port, user, pass, db) = parse_db_conn_info(db_url)?;
                let mut c = Command::new("psql");
                c.args(pg_restore_args(&host, &port, &user, &db, &file_path_str));
                c.env("PGPASSWORD", pass);
                c
            }
            DbKind::Mysql => {
                // P3 修复: 使用 i18n key 替代硬编码中文
                return Err(ServiceError::internal(&crate::tr!(
                    "error.backup.mysql_restore_branch_unreachable"
                )));
            }
            DbKind::Sqlite => {
                let db_file = parse_sqlite_file_path(db_url)?;
                return restore_sqlite_from_dump(&db_file, file_path).await;
            }
        };

        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let child = cmd.spawn().map_err(|_| {
            ServiceError::internal(&crate::tr!("error.backup.restore_process_start_failed"))
        })?;

        let output = tokio::time::timeout(
            Duration::from_secs(BACKUP_TIMEOUT_SECS),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| {
            ServiceError::internal(&crate::tr!(
                "error.backup.restore_process_timeout",
                secs = BACKUP_TIMEOUT_SECS
            ))
        })?
        .map_err(|_| {
            ServiceError::internal(&crate::tr!("error.backup.restore_process_exec_failed"))
        })?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(ServiceError::internal(&crate::tr!(
                "error.backup.restore_process_nonzero_exit",
                err = truncate_restore_error(&err)
            )));
        }
        Ok(())
    }

    /// MySQL 恢复子进程：把 dump 文件**流式**喂入 stdin。
    ///
    /// 安全设计（修复 C-1 命令注入）：
    /// - 不使用 `sh -c "mysql ... < file"` 拼接 shell 命令
    /// - 直接 `Command::new("mysql")` + 参数化传参，完全绕过 shell
    /// - SQL 文件内容通过 stdin pipe 传入，等价于 `< file` 重定向但无注入风险
    ///
    /// 内存口径（b99）：旧实现先 `std::fs::read` 整个 dump，注释却写着"分块写入，
    /// 避免一次性占用过多内存"——**与事实相反**，峰值等于文件大小。现改为
    /// `tokio::io::copy` 从文件读到 stdin，进程内存与 dump 大小无关。
    async fn run_mysql_restore(&self, db_url: &str, file_path: &Path) -> Result<(), ServiceError> {
        let (host, port, user, pass, db) = parse_db_conn_info(db_url)?;

        let mut cmd = Command::new("mysql");
        cmd.args(mysql_restore_args(&host, &port, &user, &db))
            // 安全：通过 MYSQL_PWD 环境变量传递密码，避免通过命令行参数泄漏到进程列表
            .env("MYSQL_PWD", &pass)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|_| {
            ServiceError::internal(&crate::tr!("error.backup.restore_process_start_failed"))
        })?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            ServiceError::internal(&crate::tr!("error.backup.restore_process_start_failed"))
        })?;
        let mut file = tokio::fs::File::open(file_path).await.map_err(|_| {
            ServiceError::internal(&crate::tr!("error.backup.read_backup_file_failed"))
        })?;

        // 写侧独立任务：子进程提前退出（SQL 错误）时 copy 会拿到 EPIPE，
        // 结论以子进程退出码为准；写侧错误只在"子进程成功但没读完"时上报。
        //
        // panic 隔离（AGENTS B.6）：写侧只做 IO，理论上不会 panic，但任务一旦 panic，
        // `JoinHandle` 只剩 `JoinError`（原因丢失）且"子进程还没读完"这一事实也会被
        // 误读成执行失败。用 catch_unwind 把 panic 收敛成一条 io 错误，与 EPIPE 同路。
        // 超时由上方的 `wait_with_output` 统一兜住，超时/异常时 `abort()` 掉本任务。
        let writer = tokio::spawn(async move {
            let copied = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
                let copied = tokio::io::copy(&mut file, &mut stdin).await;
                drop(stdin);
                copied
            }))
            .await;
            copied.unwrap_or_else(|_| Err(std::io::Error::other("mysql restore writer panicked")))
        });

        let waited = tokio::time::timeout(
            Duration::from_secs(BACKUP_TIMEOUT_SECS),
            child.wait_with_output(),
        )
        .await;
        let output = match waited {
            Err(_) => {
                writer.abort();
                return Err(ServiceError::internal(&crate::tr!(
                    "error.backup.restore_process_timeout",
                    secs = BACKUP_TIMEOUT_SECS
                )));
            }
            Ok(Ok(output)) => output,
            Ok(Err(_)) => {
                writer.abort();
                return Err(ServiceError::internal(&crate::tr!(
                    "error.backup.restore_process_exec_failed"
                )));
            }
        };
        let copied = writer.await.map_err(|_| {
            ServiceError::internal(&crate::tr!("error.backup.restore_process_exec_failed"))
        })?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(ServiceError::internal(&crate::tr!(
                "error.backup.restore_process_nonzero_exit",
                err = truncate_restore_error(&err)
            )));
        }
        if copied.is_err() {
            // 子进程成功但 dump 没读完 ⇒ 数据不完整，不能记成功
            return Err(ServiceError::internal(&crate::tr!(
                "error.backup.read_backup_file_failed"
            )));
        }
        Ok(())
    }

    /// 分页查询备份日志（**租户自助只读**：`operator_tid != 0` 时结构性收窄）
    ///
    /// 批次 2（能力位 `backup.visibility`）：租户操作者**只能**看到本租户的
    /// `tenant_export` 数据包行——同时施加 `tenant_id = 自己` 与
    /// `backup_type = 'tenant_export'` 两道条件：
    /// - 前者防跨租户读取；
    /// - 后者防读到整库备份行（其 `file_name` / `file_path` / `file_size` 即宿主库元数据）。
    ///
    /// 平台操作者（`operator_tid == 0`）行为不变（全量 + 原有筛选条件）。
    pub async fn get_backup_log_page(
        &self,
        query: BackupLogQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<SysBackupLogModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_backup_log::Entity>(
                prop,
                BACKUP_LOG_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        let is_tenant = crate::common::tenant::tenant_scope(operator_tid).is_some();
        let (rows, total) = self
            .backup_repo
            .find_page_filtered(
                offset,
                limit,
                query.backup_type.as_deref(),
                query.status.as_deref(),
                begin,
                end,
                crate::common::tenant::tenant_scope(operator_tid),
                is_tenant,
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询备份日志详情（**租户自助只读**：`operator_tid != 0` 时行级校验）
    ///
    /// 租户只能读取本租户的 `tenant_export` 行；其余一律 403（含"记录不存在"以外的
    /// 他租户行——不区分 404/403 会让租户可枚举 backup_id 的归属）。
    pub async fn get_backup_by_id(
        &self,
        backup_id: i64,
        operator_tid: i64,
    ) -> Result<SysBackupLogModel, ServiceError> {
        let model = self
            .backup_repo
            .find_by_id(backup_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.backup.record_not_found")))?;
        Self::ensure_backup_visible(&model, operator_tid)?;
        Ok(model)
    }

    /// 备份行的**租户可见性**守卫（纯函数，便于单测）
    ///
    /// - 平台操作者（`operator_tid == 0`）⇒ 放行；
    /// - 租户操作者 ⇒ 必须 `backup_type == 'tenant_export'` **且** `tenant_id == 自己`。
    pub(crate) fn ensure_backup_visible(
        model: &SysBackupLogModel,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if operator_tid == 0 {
            return Ok(());
        }
        if model.backup_type == BACKUP_TYPE_TENANT_EXPORT
            && crate::common::tenant::tenant_allowed(operator_tid, model.tenant_id)
        {
            return Ok(());
        }
        Err(ServiceError::forbidden(&crate::tr!(
            "error.backup.tenant_scope_denied"
        )))
    }

    /// 批量删除备份日志（批量查询 + 异步删除文件，避免 N+1 与阻塞 IO）
    pub async fn delete_backups(&self, ids: Vec<i64>) -> Result<(), ServiceError> {
        // 批量查询所有备份记录（避免循环内 N+1 查询）
        let logs = self.backup_repo.find_by_ids(&ids).await?;

        // 收集需要删除的原始文件路径（manual/auto/tenant_export 有落盘文件，
        // restore 类型只是恢复记录、无自有文件，不删）
        let mut raw_paths: Vec<PathBuf> = Vec::new();
        for log in &logs {
            if (log.backup_type == "manual"
                || log.backup_type == "auto"
                || log.backup_type == BACKUP_TYPE_TENANT_EXPORT)
                && !log.file_path.is_empty()
            {
                raw_paths.push(PathBuf::from(&log.file_path));
            }
        }

        // 在 spawn_blocking 中完成 canonicalize + 路径校验 + 删除，
        // 避免 canonicalize 同步 IO 阻塞 Tokio worker
        if !raw_paths.is_empty() {
            let backup_dir = PathBuf::from(BACKUP_DIR);
            tokio::task::spawn_blocking(move || {
                let dir_canonical = match backup_dir.canonicalize() {
                    Ok(p) => Some(p),
                    Err(e) => {
                        // 目录不可解析时**一个文件都删不掉**，而记录仍会被清理（见下方 delete_by_ids）
                        // ⇒ 必须留痕，否则磁盘上留下的是一批无人知晓的孤儿文件（b97）。
                        tracing::warn!(
                            error = %e,
                            "备份目录不可解析：本轮跳过全部文件删除（数据库记录仍会被清理）"
                        );
                        None
                    }
                };
                for path in &raw_paths {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("<非 UTF-8 文件名>");
                    // 二次校验路径在备份目录内（canonicalize 在阻塞线程中执行）
                    match path.canonicalize() {
                        Ok(canonical) => {
                            if !dir_canonical
                                .as_ref()
                                .is_some_and(|d| canonical.starts_with(d))
                            {
                                tracing::warn!(
                                    file = %name,
                                    "备份文件不在备份目录内，拒绝删除（记录仍会被清理）"
                                );
                            } else if let Err(e) = std::fs::remove_file(&canonical) {
                                tracing::warn!(file = %name, error = %e, "删除备份文件失败");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                file = %name,
                                error = %e,
                                "备份文件不存在或不可解析，跳过删除"
                            );
                        }
                    }
                }
            })
            .await
            .map_err(|_| {
                ServiceError::internal(&crate::tr!("error.backup.delete_file_task_failed"))
            })?;
        }

        self.backup_repo.delete_by_ids(ids).await?;
        Ok(())
    }

    /// 打开备份文件用于**流式下载**（返回文件句柄、实际大小、原始文件名）
    ///
    /// 批次 2：`operator_tid != 0`（租户操作者）时先做行级可见性校验——只能下载
    /// **本租户的 `tenant_export` 数据包**，整库备份（manual/auto/restore）一律 403。
    /// 请求层另需 `backup.visibility` 达 `full` 档（`view_only` 不放行下载面）。
    ///
    /// b99：返回句柄而不是 `Vec<u8>`——备份是整库快照（可达 GB 级），
    /// 旧实现每次下载都把整个文件读进内存再交给响应体，内存峰值等于文件大小。
    /// 与恢复同口径校验"非空 + 与登记大小一致"：把被截断的备份当成功件带走，
    /// 等于把唯一可用的恢复材料也弄没了。
    pub async fn open_backup_file(
        &self,
        backup_id: i64,
        operator_tid: i64,
    ) -> Result<OpenedBackupFile, ServiceError> {
        let log = self.get_backup_by_id(backup_id, operator_tid).await?;
        if log.status != "success" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.backup.download_status_invalid"
            )));
        }
        let base_name = std::path::Path::new(&log.file_name)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                ServiceError::bad_request(&crate::tr!("error.backup.filename_invalid_restore"))
            })?
            .to_string();
        let file_path = validate_backup_path(&base_name).await?;
        let meta = tokio::fs::metadata(&file_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ServiceError::not_found(&crate::tr!("error.backup.file_not_found"))
            } else {
                ServiceError::internal(&crate::tr!("error.backup.read_backup_file_failed"))
            }
        })?;
        let actual_size = meta.len();
        if let Err(key) = validate_backup_file_size(log.file_size, actual_size) {
            return Err(backup_size_error(key, log.file_size, actual_size));
        }
        let file = tokio::fs::File::open(&file_path).await.map_err(|_| {
            ServiceError::internal(&crate::tr!("error.backup.read_backup_file_failed"))
        })?;
        Ok(OpenedBackupFile {
            file,
            size: actual_size,
            file_name: log.file_name,
            tenant_id: log.tenant_id,
            backup_type: log.backup_type,
        })
    }
}

#[cfg(test)]
mod tenant_visibility_tests {
    use super::*;

    /// 构造一条仅用于可见性判定的备份行（不需要真实文件）
    fn row(tenant_id: i64, backup_type: &str) -> SysBackupLogModel {
        SysBackupLogModel {
            tenant_id,
            backup_id: 1,
            file_name: "x.sql".to_string(),
            file_path: "/tmp/x.sql".to_string(),
            file_size: 1,
            backup_type: backup_type.to_string(),
            status: "success".to_string(),
            error_msg: None,
            create_by: None,
            create_time: None,
        }
    }

    /// 批次 2 回归锁：租户只能读**本租户的 tenant_export**，整库备份与他租户行一律 403
    ///
    /// 可证伪性：若删掉 `backup_type == BACKUP_TYPE_TENANT_EXPORT` 这一半条件，
    /// "租户读自己的整库备份"断言会从 Err(403) 变成 Ok ⇒ 变红（那等于把宿主库元数据
    /// 与整库文件下载面下放给租户）。
    #[test]
    fn test_ensure_backup_visible_tenant_scope() {
        const TID: i64 = 9100;
        // 平台操作者：全量放行
        for bt in ["manual", "auto", BACKUP_TYPE_TENANT_EXPORT, "restore"] {
            assert!(
                SysBackupService::ensure_backup_visible(&row(TID, bt), 0).is_ok(),
                "平台操作者应可读 {bt} 行"
            );
        }
        // 租户操作者：只有本租户的 tenant_export 可读
        assert!(
            SysBackupService::ensure_backup_visible(&row(TID, BACKUP_TYPE_TENANT_EXPORT), TID)
                .is_ok(),
            "租户应可读本租户的数据包导出行"
        );
        for bt in ["manual", "auto", "restore"] {
            let err = SysBackupService::ensure_backup_visible(&row(TID, bt), TID)
                .expect_err("租户不得读整库/恢复类备份行");
            assert_eq!(err.code, 403, "{bt} 应 403，实际 {err:?}");
        }
        // 跨租户：他租户的 tenant_export 亦不可读
        let err =
            SysBackupService::ensure_backup_visible(&row(TID + 1, BACKUP_TYPE_TENANT_EXPORT), TID)
                .expect_err("租户不得读他租户的数据包行");
        assert_eq!(err.code, 403);
        // 平台租户行（tenant_id = 0）对租户同样不可见
        let err = SysBackupService::ensure_backup_visible(&row(0, BACKUP_TYPE_TENANT_EXPORT), TID)
            .expect_err("租户不得读平台租户的数据包行");
        assert_eq!(err.code, 403);
    }
}

#[cfg(test)]
mod backup_restore_contract_tests {
    use super::*;

    /// PG 备份必须自带 DROP：否则新备份无法恢复到既有库（b99 实证 SQLite 同族缺陷）。
    #[test]
    fn pg_dump_args_make_backup_restorable_on_non_empty_db() {
        let args = pg_dump_args("db", "5432", "u", "app", "/b/x.sql");
        assert!(args.contains(&"--clean".to_string()), "必须带 --clean");
        assert!(
            args.contains(&"--if-exists".to_string()),
            "必须带 --if-exists"
        );
        assert_eq!(
            args[args.len() - 2..],
            ["--file".to_string(), "/b/x.sql".to_string()],
            "文件参数必须成对且位置不变"
        );
    }

    /// psql 默认遇错继续执行且退出码 0 ⇒ 旧实现会把半写记成成功。
    #[test]
    fn pg_restore_args_are_atomic_and_fail_closed() {
        let args = pg_restore_args("db", "5432", "u", "app", "/b/x.sql");
        assert!(
            args.contains(&"--single-transaction".to_string()),
            "恢复必须整份一个事务"
        );
        assert!(
            args.contains(&"--set=ON_ERROR_STOP=1".to_string()),
            "首个错误必须中止并返回非零"
        );
    }

    /// MySQL 备份/恢复两端字符集必须同源，且 dump 必须能重放（DROP + CREATE）。
    #[test]
    fn mysql_args_align_charset_and_are_replayable() {
        let dump = mysqldump_args("db", "3306", "u", "app", "/b/x.sql");
        assert!(dump.contains(&"--add-drop-table".to_string()));
        assert!(dump.contains(&"--default-character-set=utf8mb4".to_string()));
        let restore = mysql_restore_args("db", "3306", "u", "app");
        assert!(
            restore.contains(&"--default-character-set=utf8mb4".to_string()),
            "恢复侧漏掉字符集 ⇒ 中文静默乱码"
        );
    }

    #[test]
    fn backup_size_guard_rejects_empty_and_mismatch() {
        assert_eq!(
            validate_backup_file_size(100, 0),
            Err("error.backup.dump_empty")
        );
        assert_eq!(
            validate_backup_file_size(100, 99),
            Err("error.backup.dump_size_mismatch")
        );
        assert_eq!(
            validate_backup_file_size(100, 101),
            Err("error.backup.dump_size_mismatch")
        );
        assert_eq!(validate_backup_file_size(100, 100), Ok(()));
        // 历史行没有登记大小（0）时只判空文件，不误杀
        assert_eq!(validate_backup_file_size(0, 5), Ok(()));
    }

    #[test]
    fn restore_error_truncation_is_char_safe() {
        let long: String = "错".repeat(RESTORE_ERROR_MAX_CHARS + 10);
        let out = truncate_restore_error(&long);
        assert_eq!(out.chars().count(), RESTORE_ERROR_MAX_CHARS + 1);
        assert!(out.ends_with('…'));
        let short = "普通错误";
        assert_eq!(truncate_restore_error(short), short);
    }

    #[test]
    fn sqlite_dot_arg_quotes_paths_with_spaces_and_quotes() {
        assert_eq!(
            sqlite_dot_arg(Path::new("C:/data/stepby.db")).unwrap(),
            "\"C:/data/stepby.db\""
        );
        assert_eq!(
            sqlite_dot_arg(Path::new("D:/a b/c.db")).unwrap(),
            "\"D:/a b/c.db\""
        );
        // 含单引号：双引号包裹可保留单引号
        assert_eq!(
            sqlite_dot_arg(Path::new("D:/o'brien/db")).unwrap(),
            "\"D:/o'brien/db\""
        );
        // 含双引号：改用单引号
        assert_eq!(
            sqlite_dot_arg(Path::new("D:/a\"b/db")).unwrap(),
            "'D:/a\"b/db'"
        );
        // Windows 反斜杠必须归一为正斜杠：点命令解析器会在引号内把 `\` 当转义，
        // `"C:\Users\..."` 会被读成 `C:Users...` 并静默写到别处（b99 实证）。
        #[cfg(windows)]
        assert_eq!(
            sqlite_dot_arg(Path::new(r"D:\data\stepby.db")).unwrap(),
            "\"D:/data/stepby.db\""
        );
        // 两种引号同时出现：拒绝而不是拼一个可疑命令
        assert!(sqlite_dot_arg(Path::new("D:/a'b\"c/db")).is_err());
    }
}
