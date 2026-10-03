//! 服务器监控 Handler（Axum 原生实现）
//!
//! 接口路径对齐前端调用规范：
//! - GET /monitor/server — 获取服务器信息（CPU、内存、JVM/运行时、磁盘、系统信息）
//!
//! 使用 sysinfo crate 采集 CPU/内存/磁盘信息，
//! JVM 信息映射为 Rust 运行时进程信息（语言差异，字段名保持对齐前端）。

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use serde::Serialize;
use sysinfo::{Disks, System};
use utoipa::ToSchema;

use crate::common::constants::{SECS_PER_DAY, SECS_PER_HOUR, SECS_PER_MIN};
use crate::common::{AjaxResult, AppError};
use crate::state::AppState;

/// sysinfo CPU 使用率采样间隔（毫秒）。
///
/// sysinfo 需要两次 refresh_cpu_usage + 间隔才能拿到非零使用率；
/// 间隔过短会使使用率偏低，过长会阻塞 spawn_blocking 任务。
const CPU_SAMPLING_INTERVAL_MS: u64 = 200;

// ==================== 响应结构体 ====================

/// 服务器信息（对齐前端 server 对象结构）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub cpu: CpuInfo,
    pub mem: MemInfo,
    pub jvm: JvmInfo,
    pub sys: SysInfo,
    pub sys_files: Vec<SysFileInfo>,
}

/// CPU 信息
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CpuInfo {
    /// 核心数
    pub cpu_num: usize,
    /// 用户使用率
    pub used: f32,
    /// 系统使用率
    pub sys: f32,
    /// 空闲率
    pub free: f32,
}

/// 内存信息（单位：G）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MemInfo {
    pub total: f64,
    pub used: f64,
    pub free: f64,
    /// 使用率
    pub usage: f64,
}

/// 运行时信息（对齐前端 JVM 字段，单位：M）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JvmInfo {
    pub total: f64,
    pub used: f64,
    pub free: f64,
    pub usage: f64,
    /// 运行时名称
    pub name: String,
    /// 运行时版本
    pub version: String,
    /// 启动时间
    pub start_time: String,
    /// 运行时长
    pub run_time: String,
    /// 安装路径
    pub home: String,
    /// 运行参数
    pub input_args: String,
}

/// 系统信息
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SysInfo {
    /// 服务器名称
    pub computer_name: String,
    /// 操作系统
    pub os_name: String,
    /// 服务器 IP
    pub computer_ip: String,
    /// 系统架构
    pub os_arch: String,
    /// 项目路径
    pub user_dir: String,
}

/// 磁盘信息
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SysFileInfo {
    /// 盘符路径
    pub dir_name: String,
    /// 文件系统
    pub sys_type_name: String,
    /// 盘符类型
    pub type_name: String,
    /// 总大小（G）
    pub total: f64,
    /// 可用大小（G）
    pub free: f64,
    /// 已用大小（G）
    pub used: f64,
    /// 已用百分比
    pub usage: f64,
}

// ==================== Handler 实现 ====================

/// GET /monitor/server
/// 获取服务器信息
#[utoipa::path(
    get,
    path = "/monitor/server",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<ServerInfo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-server"
)]
pub async fn get_server(
    State(_state): State<Arc<AppState>>,
) -> Result<AjaxResult<ServerInfo>, AppError> {
    // sysinfo 的 CPU/内存/磁盘查询是同步阻塞操作，使用 spawn_blocking 包裹
    // 避免阻塞 async runtime 的工作线程
    let server_info = tokio::task::spawn_blocking(move || {
        // 1. CPU 信息（需两次刷新 + 间隔以获取非零使用率）
        //    使用 new_all() 同时刷新进程信息，供 JVM 字段使用
        let mut sys = System::new_all();
        sys.refresh_cpu_usage();
        std::thread::sleep(Duration::from_millis(CPU_SAMPLING_INTERVAL_MS));
        sys.refresh_cpu_usage();

        let cpu_num = sys.cpus().len();
        let used = sys.global_cpu_usage();
        let cpu = CpuInfo {
            cpu_num,
            used: round1(used),
            // sysinfo 不区分用户/系统使用率，系统部分简化为 0
            sys: 0.0,
            free: round1(100.0 - used),
        };

        // 2. 内存信息（单位 G）
        sys.refresh_memory();
        let mem_total = sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0;
        let mem_used = sys.used_memory() as f64 / 1024.0 / 1024.0 / 1024.0;
        let mem_free = mem_total - mem_used;
        let mem_usage = if mem_total > 0.0 {
            mem_used / mem_total * 100.0
        } else {
            0.0
        };
        let mem = MemInfo {
            total: round2(mem_total),
            used: round2(mem_used),
            free: round2(mem_free),
            usage: round2(mem_usage),
        };

        // 3. 运行时（JVM）信息
        let jvm = build_jvm_info(&sys);

        // 4. 系统信息
        let computer_name = System::host_name().unwrap_or_default();
        let os_name = format!(
            "{} {}",
            System::name().unwrap_or_default(),
            System::os_version().unwrap_or_default()
        );
        let sys_info = SysInfo {
            computer_name,
            os_name,
            computer_ip: get_local_ip(),
            os_arch: std::env::consts::ARCH.to_string(),
            user_dir: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        };

        // 5. 磁盘信息
        let disks = Disks::new_with_refreshed_list();
        let sys_files: Vec<SysFileInfo> = disks
            .list()
            .iter()
            .map(|disk| {
                let total = disk.total_space() as f64 / 1024.0 / 1024.0 / 1024.0;
                let available = disk.available_space() as f64 / 1024.0 / 1024.0 / 1024.0;
                let used = total - available;
                let usage = if total > 0.0 {
                    used / total * 100.0
                } else {
                    0.0
                };
                SysFileInfo {
                    dir_name: disk.mount_point().display().to_string(),
                    sys_type_name: disk.file_system().to_string_lossy().to_string(),
                    type_name: disk.name().to_string_lossy().to_string(),
                    total: round2(total),
                    free: round2(available),
                    used: round2(used),
                    usage: round2(usage),
                }
            })
            .collect();

        ServerInfo {
            cpu,
            mem,
            jvm,
            sys: sys_info,
            sys_files,
        }
    })
    .await
    .map_err(|e| {
        tracing::error!("spawn_blocking sysinfo 查询失败: {}", e);
        AppError::internal(&crate::tr!("error.server.info_fetch_failed"))
    })?;

    Ok(AjaxResult::success(server_info))
}

// ==================== 数据库连接池监控 ====================

/// 数据库连接池信息（对齐前端 db-pool 对象结构）
///
/// 字段语义：
/// - dbKind：数据库方言（sqlite | mysql | postgres）
/// - poolSize：当前池内连接总数（sqlx `Pool::size()`）
/// - numIdle：空闲连接数（sqlx `Pool::num_idle()`）
/// - busy：繁忙连接数 = poolSize - numIdle（下溢保护为 0）
/// - maxConn：配置的最大连接数（来源 `config.settings.database.max_connections`）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DbPoolInfo {
    /// 数据库方言（sqlite | mysql | postgres；连接不可用时为 unknown）
    pub db_kind: String,
    /// 当前池内连接总数
    pub pool_size: u64,
    /// 空闲连接数
    pub num_idle: u64,
    /// 繁忙连接数（poolSize - numIdle）
    pub busy: u64,
    /// 配置的最大连接数
    pub max_conn: u64,
}

/// GET /monitor/db-pool
/// 获取数据库连接池统计信息
///
/// 实现（sea-orm 1.x 真实 API）：
/// - 底层 sqlx 池仅能通过 [`DatabaseConnection`] 的公开 getter 取得
///   （`get_sqlite_connection_pool` / `get_mysql_connection_pool` / `get_postgres_connection_pool`，
///   方言不匹配时会 panic，且 `pool` 字段为 pub(crate) 无法直接访问）；
/// - 故先按枚举变体 match 判定方言（不调用任何 panic 路径），**变体匹配时**才调用对应
///   getter —— 同方言下 getter 不会 panic，杜绝风险；
/// - 池统计取 sqlx 原生指标：`Pool::size()`（总连接）、`Pool::num_idle()`（空闲），
///   busy 为二者差值（saturating，不造假）；
/// - 若连接类型不可得（Disconnected / Mock / Proxy 等无 sqlx 池的变体），按约定诚实降级：
///   dbKind 返回 "unknown"，其余统计字段置 0。
#[utoipa::path(
    get,
    path = "/monitor/db-pool",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<DbPoolInfo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "monitor-server"
)]
pub async fn get_db_pool(State(state): State<Arc<AppState>>) -> AjaxResult<DbPoolInfo> {
    use sea_orm::DatabaseConnection;

    // 先按连接枚举变体判定方言（安全，无 panic 路径），再调用同方言的池 getter
    let (db_kind, pool_size, num_idle) = match &state.db {
        DatabaseConnection::SqlxSqlitePoolConnection(_) => {
            let pool = state.db.get_sqlite_connection_pool();
            ("sqlite", pool.size() as u64, pool.num_idle() as u64)
        }
        DatabaseConnection::SqlxMySqlPoolConnection(_) => {
            let pool = state.db.get_mysql_connection_pool();
            ("mysql", pool.size() as u64, pool.num_idle() as u64)
        }
        DatabaseConnection::SqlxPostgresPoolConnection(_) => {
            let pool = state.db.get_postgres_connection_pool();
            ("postgres", pool.size() as u64, pool.num_idle() as u64)
        }
        // 无 sqlx 池的变体（Disconnected / Mock / Proxy）：真实不可得，诚实降级为 0
        _ => ("unknown", 0, 0),
    };

    let info = DbPoolInfo {
        db_kind: db_kind.to_string(),
        pool_size,
        num_idle,
        // saturating_sub：理论上 num_idle ≤ size，防御异常数据下溢
        busy: pool_size.saturating_sub(num_idle),
        // maxConn 从 settings 的 database 段读取（真实字段名 max_connections）
        max_conn: state.config.database.max_connections as u64,
    };
    AjaxResult::success(info)
}

// ==================== 辅助函数 ====================

/// 构建运行时（JVM）信息
///
/// sys 已通过 new_all() 刷新过进程信息，此处直接读取。
fn build_jvm_info(sys: &System) -> JvmInfo {
    let pid = sysinfo::get_current_pid().unwrap_or(sysinfo::Pid::from(0usize));

    let process_mem_mb = sys
        .process(pid)
        .map(|p| p.memory() as f64 / 1024.0 / 1024.0)
        .unwrap_or(0.0);

    // JVM total 映射为系统总内存（M），进程可寻址全部系统内存
    let total_mb = sys.total_memory() as f64 / 1024.0 / 1024.0;
    let used_mb = process_mem_mb;
    let free_mb = (total_mb - used_mb).max(0.0);
    let usage = if total_mb > 0.0 {
        used_mb / total_mb * 100.0
    } else {
        0.0
    };

    // 启动时间与运行时长
    let start_time_epoch = sys.process(pid).map(|p| p.start_time()).unwrap_or(0);
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let start_time_str = format_epoch(start_time_epoch);
    let run_time_str = format_duration(now_epoch.saturating_sub(start_time_epoch));

    // 运行时名称与版本
    let name = "Rust".to_string();
    let version = format!(
        "{} (cargo {})",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_NAME")
    );

    // 安装路径（可执行文件路径）
    let home = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    // 运行参数（命令行参数）
    let input_args = std::env::args().collect::<Vec<_>>().join(" ");

    JvmInfo {
        total: round2(total_mb),
        used: round2(used_mb),
        free: round2(free_mb),
        usage: round2(usage),
        name,
        version,
        start_time: start_time_str,
        run_time: run_time_str,
        home,
        input_args,
    }
}

/// 获取本机 IP（通过 UDP socket 探测，失败回退 127.0.0.1）
fn get_local_ip() -> String {
    use std::net::UdpSocket;
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0")
        && socket.connect("8.8.8.8:80").is_ok()
        && let Ok(addr) = socket.local_addr()
    {
        return addr.ip().to_string();
    }
    "127.0.0.1".to_string()
}

/// 格式化 epoch 时间戳为可读字符串
fn format_epoch(epoch: u64) -> String {
    use chrono::TimeZone;
    // R11：防 u64→i64 溢出（epoch > i64::MAX 时回绕为负数导致时间错误）
    let epoch_i64 = i64::try_from(epoch).unwrap_or(i64::MAX);
    match chrono::Local.timestamp_opt(epoch_i64, 0) {
        chrono::LocalResult::Single(t) => t.format("%Y-%m-%d %H:%M:%S").to_string(),
        _ => String::new(),
    }
}

/// 格式化秒数时长为 "X天X小时X分钟"
fn format_duration(secs: u64) -> String {
    // R11：防 u64→i64 溢出
    let secs = i64::try_from(secs).unwrap_or(i64::MAX);
    let days = secs / SECS_PER_DAY;
    let hours = (secs % SECS_PER_DAY) / SECS_PER_HOUR;
    let minutes = (secs % SECS_PER_HOUR) / SECS_PER_MIN;
    crate::tr!(
        "error.monitor_server.duration_format",
        days = days,
        hours = hours,
        minutes = minutes
    )
    .to_string()
}

/// 保留一位小数
fn round1(v: f32) -> f32 {
    (v * 10.0).round() / 10.0
}

/// 保留两位小数
fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}
