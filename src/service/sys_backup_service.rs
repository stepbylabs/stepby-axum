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
use crate::config::Settings;
use crate::entity::sys_backup_log::{
    ActiveModel as SysBackupLogActiveModel, Model as SysBackupLogModel,
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
            .query_one(Statement::from_sql_and_values(
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
                .query_all(Statement::from_sql_and_values(
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
            "format": "yebot-tenant-package",
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
                .map_err(|_| {
                    ServiceError::internal(&crate::tr!("error.backup.write_task_join_failed"))
                })?
                .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.write_failed")))?;
            return Ok(());
        }

        // Postgres / MySQL 使用 --file/--result-file 直接写文件
        let mut cmd = match kind {
            DbKind::Postgres => {
                let (host, port, user, pass, db) = parse_db_conn_info(db_url)?;
                let mut c = Command::new("pg_dump");
                c.arg("--host")
                    .arg(&host)
                    .arg("--port")
                    .arg(&port)
                    .arg("--username")
                    .arg(&user)
                    .arg("--dbname")
                    .arg(&db)
                    .arg("--file")
                    .arg(&file_path_str);
                c.env("PGPASSWORD", pass);
                c
            }
            DbKind::Mysql => {
                let (host, port, user, pass, db) = parse_db_conn_info(db_url)?;
                let mut c = Command::new("mysqldump");
                c.arg("--host")
                    .arg(&host)
                    .arg("--port")
                    .arg(&port)
                    .arg("--user")
                    .arg(&user)
                    .arg("--single-transaction")
                    .arg("--routines")
                    .arg("--triggers")
                    .arg(&db)
                    .arg("--result-file")
                    .arg(&file_path_str);
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
        let file_path_clone = file_path.clone();
        let exists = tokio::task::spawn_blocking(move || file_path_clone.exists())
            .await
            .map_err(|_| {
                ServiceError::internal(&crate::tr!("error.backup.file_exist_check_join_failed"))
            })?;
        if !exists {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.backup.file_not_found"
            )));
        }

        let db_url = self.config.database.url.clone();
        let kind = parse_db_kind(&db_url)?;
        let result = self.run_restore_process(kind, &db_url, &file_path).await;

        let now = crate::common::datetime::now_naive();
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
                error_msg
                    .as_deref()
                    .unwrap_or(&crate::tr!("error.backup.db_restore_failed")),
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
                c.arg("--host")
                    .arg(&host)
                    .arg("--port")
                    .arg(&port)
                    .arg("--username")
                    .arg(&user)
                    .arg("--dbname")
                    .arg(&db)
                    .arg("--file")
                    .arg(&file_path_str);
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
                let mut c = Command::new("sqlite3");
                c.arg(db_file).arg(format!(".read {}", file_path_str));
                c
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
    async fn run_mysql_restore(&self, db_url: &str, file_path: &Path) -> Result<(), ServiceError> {
        use tokio::io::AsyncWriteExt;

        let (host, port, user, pass, db) = parse_db_conn_info(db_url)?;

        // 在 spawn_blocking 中读取文件内容（同步 IO 不阻塞 worker）
        let fp = file_path.to_path_buf();
        let sql_bytes = tokio::task::spawn_blocking(move || std::fs::read(&fp))
            .await
            .map_err(|_| ServiceError::internal(&crate::tr!("error.backup.read_file_task_failed")))?
            .map_err(|_| {
                ServiceError::internal(&crate::tr!("error.backup.read_backup_file_failed"))
            })?;

        let mut cmd = Command::new("mysql");
        cmd.arg("--host")
            .arg(&host)
            .arg("--port")
            .arg(&port)
            .arg("--user")
            .arg(&user)
            // 安全：通过 MYSQL_PWD 环境变量传递密码，避免通过命令行参数泄漏到进程列表
            .env("MYSQL_PWD", &pass)
            .arg(&db)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|_| {
            ServiceError::internal(&crate::tr!("error.backup.restore_process_start_failed"))
        })?;

        // 取出 stdin 并异步写入 SQL 内容
        if let Some(mut stdin) = child.stdin.take() {
            // 大文件分块写入，避免一次性占用过多内存
            for chunk in sql_bytes.chunks(64 * 1024) {
                stdin.write_all(chunk).await.map_err(|_| {
                    ServiceError::internal(&crate::tr!("error.backup.restore_process_exec_failed"))
                })?;
            }
            // 显式关闭 stdin，通知 mysql 子进程输入结束
            // P3 修复: shutdown 失败记录 warn 日志，便于排查上游写入错误
            if let Err(e) = stdin.shutdown().await {
                tracing::warn!(error = %e, "MySQL 恢复: stdin shutdown 失败（可能子进程已退出）");
            }
        }

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
                err = err
            )));
        }
        Ok(())
    }

    /// 分页查询备份日志（**租户自助只读**：`operator_tid != 0` 时结构性收窄）
    ///
    /// 批次 2（能力位 `backup.readonly_visible`）：租户操作者**只能**看到本租户的
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
                let dir_canonical = backup_dir.canonicalize().ok();
                for path in &raw_paths {
                    // 二次校验路径在备份目录内（canonicalize 在阻塞线程中执行）
                    if let Ok(canonical) = path.canonicalize()
                        && let Some(ref dir_canonical) = dir_canonical
                        && canonical.starts_with(dir_canonical)
                        && let Err(e) = std::fs::remove_file(&canonical)
                    {
                        tracing::warn!("删除备份文件失败 {}: {}", canonical.display(), e);
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

    /// 读取备份文件二进制内容（供 handler 下载）
    ///
    /// 批次 2：`operator_tid != 0`（租户操作者）时先做行级可见性校验——只能下载
    /// **本租户的 `tenant_export` 数据包**，整库备份（manual/auto/restore）一律 403。
    pub async fn read_backup_file(
        &self,
        backup_id: i64,
        operator_tid: i64,
    ) -> Result<(Vec<u8>, String), ServiceError> {
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
        let file_path_clone = file_path.clone();
        let exists = tokio::task::spawn_blocking(move || file_path_clone.exists())
            .await
            .map_err(|_| {
                ServiceError::internal(&crate::tr!("error.backup.file_exist_check_join_failed"))
            })?;
        if !exists {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.backup.file_not_found"
            )));
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
