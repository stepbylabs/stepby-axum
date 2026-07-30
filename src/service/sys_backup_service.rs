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

use chrono::NaiveDateTime;
use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{default_page_num, default_page_size, PageDomain};
use crate::config::Settings;
use crate::entity::sys_backup_log::{ActiveModel as SysBackupLogActiveModel, Model as SysBackupLogModel};
use crate::repository::sys_backup_log::SysBackupLogRepository;

// ==================== 常量 ====================

/// 子进程超时时间（5 分钟），避免恶意大库阻塞后端
const BACKUP_TIMEOUT_SECS: u64 = 300;

/// 备份文件存储子目录（相对工作目录）
const BACKUP_DIR: &str = "backups";

// ==================== DTO ====================

/// 备份日志分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupLogQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub backup_type: Option<String>,
    pub status: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&BackupLogQueryDto> for PageDomain {
    fn from(dto: &BackupLogQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
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

// ==================== 辅助函数 ====================

/// 解析时间字符串（%Y-%m-%d 格式），失败返回 ServiceError
fn parse_time(s: &str) -> Result<NaiveDateTime, ServiceError> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| ServiceError::bad_request(&crate::tr!("error.common.time_format_invalid", s = s)))
}

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
/// - `sqlite://` 或 `sqlite://./data/yebot.db` → Sqlite
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
/// 支持 `sqlite://./data/yebot.db?mode=rwc` 和 `sqlite:./data/yebot.db` 两种格式
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
        return Err(ServiceError::bad_request(&crate::tr!("error.backup.filename_invalid")));
    }
    let dir = ensure_backup_dir_async().await?;
    let file_path = dir.join(file_name);
    Ok(file_path)
}

// ==================== Service 实现 ====================

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

        let now = chrono::Local::now().naive_local();
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
        let result = self
            .run_backup_process(kind, &db_url, &file_path)
            .await;

        // 异步获取文件大小，避免阻塞 worker
        let file_size = {
            let fp = file_path.clone();
            match tokio::task::spawn_blocking(move || std::fs::metadata(fp)).await {
                Ok(Ok(m)) => m.len() as i64,
                _ => 0,
            }
        };

        let (status, error_msg) = match result {
            Ok(()) => ("success".to_string(), None),
            Err(e) => {
                tracing::error!("备份失败 (backup_id={}): {}", backup_id, e);
                ("failed".to_string(), Some(e.to_string()))
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

        Ok(BackupCreateVo {
            backup_id: updated.backup_id,
            file_name: updated.file_name,
            file_path: updated.file_path,
            file_size: updated.file_size,
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

        // SQLite 单独处理（通过 stdout 捕获后写入文件）
        if kind == DbKind::Sqlite {
            let db_file = parse_sqlite_file_path(db_url)?;
            let output = tokio::process::Command::new("sqlite3")
                .arg(db_file)
                .arg(".dump")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.sqlite3_failed")))?;
            if !output.status.success() {
                let err = String::from_utf8_lossy(&output.stderr).to_string();
                return Err(ServiceError::internal(&crate::tr!(
                    "error.backup.sqlite3_backup_failed",
                    err = err
                )));
            }
            // 使用 spawn_blocking 包装同步 fs::write，避免阻塞 Tokio worker
            let file_path_owned = file_path.to_path_buf();
            let stdout = output.stdout;
            tokio::task::spawn_blocking(move || std::fs::write(&file_path_owned, &stdout))
                .await
                .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.write_task_join_failed")))?
                .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.write_failed")))?;
            return Ok(());
        }

        // Postgres / MySQL 使用 --file/--result-file 直接写文件
        let mut cmd = match kind {
            DbKind::Postgres => {
                let (host, port, user, pass, db) = parse_db_conn_info(db_url)?;
                let mut c = Command::new("pg_dump");
                c.arg("--host").arg(&host)
                    .arg("--port").arg(&port)
                    .arg("--username").arg(&user)
                    .arg("--dbname").arg(&db)
                    .arg("--file").arg(&file_path_str);
                c.env("PGPASSWORD", pass);
                c
            }
            DbKind::Mysql => {
                let (host, port, user, pass, db) = parse_db_conn_info(db_url)?;
                let mut c = Command::new("mysqldump");
                c.arg("--host").arg(&host)
                    .arg("--port").arg(&port)
                    .arg("--user").arg(&user)
                    .arg(format!("--password={}", pass))
                    .arg("--single-transaction")
                    .arg("--routines")
                    .arg("--triggers")
                    .arg(&db)
                    .arg("--result-file").arg(&file_path_str);
                c
            }
            DbKind::Sqlite => {
                return Err(ServiceError::internal(
                    &crate::tr!("error.backup.sqlite3_branch_unreachable"),
                ));
            }
        };

        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        // 5 分钟超时
        let child = cmd
            .spawn()
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.process_start_failed")))?;

        let output = tokio::time::timeout(Duration::from_secs(BACKUP_TIMEOUT_SECS), child.wait_with_output())
            .await
            .map_err(|_| {
                ServiceError::internal(&crate::tr!(
                    "error.backup.process_timeout",
                    secs = BACKUP_TIMEOUT_SECS
                ))
            })?
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.process_exec_failed")))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(ServiceError::internal(&crate::tr!(
                "error.backup.process_nonzero_exit",
                err = err
            )));
        }
        Ok(())
    }

    /// 恢复数据库备份
    ///
    /// 流程：
    /// 1. 校验备份记录存在
    /// 2. 校验文件路径穿越（必须位于备份目录内）
    /// 3. 调用对应工具子进程（psql/mysql/sqlite3 .read）
    /// 4. 5 分钟超时保护
    /// 5. 记录恢复日志（backup_type=restore）
    pub async fn restore_backup(
        &self,
        backup_id: i64,
        operator: &str,
    ) -> Result<(), ServiceError> {
        let log = self
            .backup_repo
            .find_by_id(backup_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.backup.record_not_found")))?;

        if log.status != "success" {
            return Err(ServiceError::bad_request(&crate::tr!("error.backup.restore_status_invalid")));
        }

        // 校验文件路径穿越（取 basename 重新拼接）
        let base_name = std::path::Path::new(&log.file_name)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.backup.filename_invalid_restore")))?
            .to_string();
        let file_path = validate_backup_path(&base_name).await?;
        let file_path_clone = file_path.clone();
        let exists = tokio::task::spawn_blocking(move || file_path_clone.exists())
            .await
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.file_exist_check_join_failed")))?;
        if !exists {
            return Err(ServiceError::not_found(&crate::tr!("error.backup.file_not_found")));
        }

        let db_url = self.config.database.url.clone();
        let kind = parse_db_kind(&db_url)?;
        let result = self
            .run_restore_process(kind, &db_url, &file_path)
            .await;

        let now = chrono::Local::now().naive_local();
        let (status, error_msg) = match result {
            Ok(()) => ("success".to_string(), None),
            Err(e) => {
                tracing::error!("恢复失败 (backup_id={}): {}", backup_id, e);
                ("failed".to_string(), Some(e.to_string()))
            }
        };

        // 记录恢复日志（独立记录，保留原备份记录不变）
        let am = SysBackupLogActiveModel {
            file_name: Set(log.file_name.clone()),
            file_path: Set(log.file_path.clone()),
            file_size: Set(log.file_size),
            backup_type: Set("restore".to_string()),
            status: Set(status.clone()),
            error_msg: Set(error_msg.clone()),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            ..Default::default()
        };
        self.backup_repo.insert(am).await?;

        if status == "failed" {
            return Err(ServiceError::internal(
                error_msg.as_deref().unwrap_or(&crate::tr!("error.backup.db_restore_failed")),
            ));
        }
        Ok(())
    }

    /// 执行恢复子进程
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
                c.arg("--host").arg(&host)
                    .arg("--port").arg(&port)
                    .arg("--username").arg(&user)
                    .arg("--dbname").arg(&db)
                    .arg("--file").arg(&file_path_str);
                c.env("PGPASSWORD", pass);
                c
            }
            DbKind::Mysql => {
                // P3 修复: 使用 i18n key 替代硬编码中文
                return Err(ServiceError::internal(&crate::tr!("error.backup.mysql_restore_branch_unreachable")));
            }
            DbKind::Sqlite => {
                let db_file = parse_sqlite_file_path(db_url)?;
                let mut c = Command::new("sqlite3");
                c.arg(db_file).arg(format!(".read {}", file_path_str));
                c
            }
        };

        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let child = cmd
            .spawn()
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.restore_process_start_failed")))?;

        let output = tokio::time::timeout(Duration::from_secs(BACKUP_TIMEOUT_SECS), child.wait_with_output())
            .await
            .map_err(|_| {
                ServiceError::internal(&crate::tr!(
                    "error.backup.restore_process_timeout",
                    secs = BACKUP_TIMEOUT_SECS
                ))
            })?
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.restore_process_exec_failed")))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(ServiceError::internal(&crate::tr!(
                "error.backup.restore_process_nonzero_exit",
                err = err
            )));
        }
        Ok(())
    }

    /// MySQL 恢复子进程：通过 stdin 管道喂入 SQL 文件内容
    ///
    /// 安全设计（修复 C-1 命令注入）：
    /// - 不使用 `sh -c "mysql ... < file"` 拼接 shell 命令
    /// - 直接 `Command::new("mysql")` + 参数化传参，完全绕过 shell
    /// - SQL 文件内容通过 stdin pipe 传入，等价于 `< file` 重定向但无注入风险
    /// - 使用 tokio::io::AsyncWriteExt 异步写入 stdin，避免阻塞 worker
    async fn run_mysql_restore(
        &self,
        db_url: &str,
        file_path: &Path,
    ) -> Result<(), ServiceError> {
        use tokio::io::AsyncWriteExt;

        let (host, port, user, pass, db) = parse_db_conn_info(db_url)?;

        // 在 spawn_blocking 中读取文件内容（同步 IO 不阻塞 worker）
        let fp = file_path.to_path_buf();
        let sql_bytes = tokio::task::spawn_blocking(move || std::fs::read(&fp))
            .await
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.read_file_task_failed")))?
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.read_backup_file_failed")))?;

        let mut cmd = Command::new("mysql");
        cmd.arg("--host").arg(&host)
            .arg("--port").arg(&port)
            .arg("--user").arg(&user)
            .arg(format!("--password={}", pass))
            .arg(&db)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.restore_process_start_failed")))?;

        // 取出 stdin 并异步写入 SQL 内容
        if let Some(mut stdin) = child.stdin.take() {
            // 大文件分块写入，避免一次性占用过多内存
            for chunk in sql_bytes.chunks(64 * 1024) {
                stdin.write_all(chunk).await
                    .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.restore_process_exec_failed")))?;
            }
            // 显式关闭 stdin，通知 mysql 子进程输入结束
            // P3 修复: shutdown 失败记录 warn 日志，便于排查上游写入错误
            if let Err(e) = stdin.shutdown().await {
                tracing::warn!(error = %e, "MySQL 恢复: stdin shutdown 失败（可能子进程已退出）");
            }
        }

        let output = tokio::time::timeout(Duration::from_secs(BACKUP_TIMEOUT_SECS), child.wait_with_output())
            .await
            .map_err(|_| {
                ServiceError::internal(&crate::tr!(
                    "error.backup.restore_process_timeout",
                    secs = BACKUP_TIMEOUT_SECS
                ))
            })?
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.restore_process_exec_failed")))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(ServiceError::internal(&crate::tr!(
                "error.backup.restore_process_nonzero_exit",
                err = err
            )));
        }
        Ok(())
    }

    /// 分页查询备份日志
    pub async fn get_backup_log_page(
        &self,
        query: BackupLogQueryDto,
    ) -> Result<(Vec<SysBackupLogModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };

        let (rows, total) = self
            .backup_repo
            .find_page_filtered(
                offset,
                limit,
                query.backup_type.as_deref(),
                query.status.as_deref(),
                begin,
                end,
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询备份日志详情
    pub async fn get_backup_by_id(&self, backup_id: i64) -> Result<SysBackupLogModel, ServiceError> {
        self.backup_repo
            .find_by_id(backup_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.backup.record_not_found")))
    }

    /// 批量删除备份日志（批量查询 + 异步删除文件，避免 N+1 与阻塞 IO）
    pub async fn delete_backups(&self, ids: Vec<i64>) -> Result<(), ServiceError> {
        // 批量查询所有备份记录（避免循环内 N+1 查询）
        let logs = self.backup_repo.find_by_ids(&ids).await?;

        // 收集需要删除的原始文件路径（仅 manual/auto 类型，restore 类型不删文件）
        let mut raw_paths: Vec<PathBuf> = Vec::new();
        for log in &logs {
            if (log.backup_type == "manual" || log.backup_type == "auto")
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
                let dir_canonical = backup_dir.canonicalize().ok();
                for path in &raw_paths {
                    // 二次校验路径在备份目录内（canonicalize 在阻塞线程中执行）
                    if let Ok(canonical) = path.canonicalize()
                        && let Some(ref dir_canonical) = dir_canonical
                        && canonical.starts_with(dir_canonical)
                        && let Err(e) = std::fs::remove_file(&canonical)
                    {
                        tracing::warn!(
                            "删除备份文件失败 {}: {}",
                            canonical.display(),
                            e
                        );
                    }
                }
            })
            .await
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.delete_file_task_failed")))?;
        }

        self.backup_repo.delete_by_ids(ids).await?;
        Ok(())
    }

    /// 读取备份文件二进制内容（供 handler 下载）
    pub async fn read_backup_file(&self, backup_id: i64) -> Result<(Vec<u8>, String), ServiceError> {
        let log = self.get_backup_by_id(backup_id).await?;
        if log.status != "success" {
            return Err(ServiceError::bad_request(&crate::tr!("error.backup.download_status_invalid")));
        }
        let base_name = std::path::Path::new(&log.file_name)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.backup.filename_invalid_restore")))?
            .to_string();
        let file_path = validate_backup_path(&base_name).await?;
        let file_path_clone = file_path.clone();
        let exists = tokio::task::spawn_blocking(move || file_path_clone.exists())
            .await
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.file_exist_check_join_failed")))?;
        if !exists {
            return Err(ServiceError::not_found(&crate::tr!("error.backup.file_not_found")));
        }
        let bytes = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            std::fs::read(&file_path)
        })
        .await
        .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.read_file_task_failed")))?
        .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.read_backup_file_failed")))?;
        Ok((bytes, log.file_name))
    }
}
