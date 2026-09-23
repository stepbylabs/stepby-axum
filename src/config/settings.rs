// axum-backend/src/config/settings.rs

use serde::Deserialize;
use std::fmt;

/// 全局配置根结构体
///
/// 注意：不 derive(Debug)，改用手动实现以脱敏 config_enc_key
#[derive(Clone, Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
    pub log: LogConfig,
    #[serde(default)]
    pub upload: UploadConfig,
    /// IP 归属地查询配置（可选，未配置时使用默认 mmdb 路径）
    #[serde(default)]
    pub ip_location: IpLocationConfig,
    /// 邮件 SMTP 配置（可选，未配置时邮件相关功能降级为仅 sys_notice）
    #[serde(default)]
    pub mail: MailConfig,
    /// 配置加密主密钥（用于 sys_config 表中敏感字段 AES-256-GCM 加解密）
    ///
    /// 通过 CONFIG_ENC_KEY 环境变量注入，不入配置文件。
    /// 启用 IP 库管理（License Key 加密存储）时必须配置，否则相关功能降级。
    #[serde(default)]
    pub config_enc_key: String,
    /// 权限未映射路由的默认处置策略（权限 fail-open 加固，B3）
    ///
    /// - false（默认，开发/兼容）：未登记权限映射且不在"仅登录白名单"的路由**放行**
    ///   （保持现有默认行为，零破坏性）。
    /// - true（生产推荐）：此类路由**拒绝（403）**并审计，实现 fail-closed，
    ///   防止新增路由漏登记权限导致越权。
    ///
    /// 注意：permission_middleware 仅作用于 protected 路由子树的 route_layer，
    /// 公开路由（/login /health /ws /swagger-ui / 等）不受影响。
    #[serde(default)]
    pub permission_deny_by_default: bool,
    /// 可观测性监控配置（慢请求阈值 / 缓冲容量 / Prometheus 指标 token）
    #[serde(default)]
    pub monitor: MonitorConfig,
    /// 系统日志保留策略配置（操作日志 / 登录日志的定期归档清理）
    #[serde(default)]
    pub sys_log: SysLogConfig,
    /// 个人访问令牌（PAT）配置（Tier-S #3）
    #[serde(default)]
    pub pat: PatConfig,
    /// 单点登录 / OIDC Provider 配置（Tier B，默认关闭）
    #[serde(default)]
    pub sso: SsoConfig,
    /// 审批工作流配置（m20260923_000002；cron 为空 = 禁用超时扫描）
    #[serde(default)]
    pub flow: FlowConfig,
}

/// 手动实现 Debug 以脱敏 config_enc_key
impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("server", &self.server)
            .field("database", &self.database)
            .field("redis", &self.redis)
            .field("jwt", &self.jwt)
            .field("log", &self.log)
            .field("upload", &self.upload)
            .field("ip_location", &self.ip_location)
            .field("mail", &self.mail)
            .field("config_enc_key", &"<redacted>")
            .field(
                "permission_deny_by_default",
                &self.permission_deny_by_default,
            )
            .field("monitor", &self.monitor)
            .field("sys_log", &self.sys_log)
            .field("pat", &self.pat)
            .field("sso", &self.sso)
            .field("flow", &self.flow)
            .finish()
    }
}

/// 系统日志保留策略配置（M2：操作日志 / 登录日志定期归档清理）
///
/// 保留天数由 `retention_days` 控制（默认 `LOG_RETENTION_DAYS`=90 天），
/// 供每日归档任务 `cleanup_expired_logs` 读取（cron: "0 0 3 * * *"）。
#[derive(Clone, Deserialize)]
pub struct SysLogConfig {
    /// 操作日志 / 登录日志保留天数（默认 90 天）
    ///
    /// 每日定时清理早于（当前时间 - retention_days）的日志，避免日志表无限增长。
    #[serde(default = "default_sys_log_retention_days")]
    pub retention_days: i64,
}

impl fmt::Debug for SysLogConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SysLogConfig")
            .field("retention_days", &self.retention_days)
            .finish()
    }
}

impl Default for SysLogConfig {
    fn default() -> Self {
        Self {
            retention_days: default_sys_log_retention_days(),
        }
    }
}

fn default_sys_log_retention_days() -> i64 {
    crate::common::constants::LOG_RETENTION_DAYS
}

/// 个人访问令牌（PAT）配置（Tier-S #3）
#[derive(Clone, Debug, Deserialize)]
pub struct PatConfig {
    /// 是否启用 PAT 鉴权（关闭时携带 ybt_ 前缀的令牌一律 401）
    #[serde(default = "default_pat_enabled")]
    pub enabled: bool,
    /// 令牌前缀（用于在 auth 中间件区分 JWT 与 PAT；真实 JWT 以 "eyJ" 开头，不会冲突）
    #[serde(default = "default_pat_prefix")]
    pub prefix: String,
    /// 创建令牌时的默认有效期（天），用户未指定时使用；NULL 语义由前端显式传 0/不传控制
    #[serde(default = "default_pat_default_expire_days")]
    pub default_expire_days: i64,
    /// 有效期上限（天）：请求的过期天数超过则裁剪至此值；0 表示允许永不过期
    #[serde(default = "default_pat_max_expire_days")]
    pub max_expire_days: i64,
    /// 每用户最多有效令牌数（防令牌泛滥）
    #[serde(default = "default_pat_max_per_user")]
    pub max_per_user: i64,
}

impl Default for PatConfig {
    fn default() -> Self {
        Self {
            enabled: default_pat_enabled(),
            prefix: default_pat_prefix(),
            default_expire_days: default_pat_default_expire_days(),
            max_expire_days: default_pat_max_expire_days(),
            max_per_user: default_pat_max_per_user(),
        }
    }
}

fn default_pat_enabled() -> bool {
    true
}
fn default_pat_prefix() -> String {
    "ybt_".to_string()
}
fn default_pat_default_expire_days() -> i64 {
    90
}
fn default_pat_max_expire_days() -> i64 {
    365
}
fn default_pat_max_per_user() -> i64 {
    20
}

/// 单点登录 / OIDC Provider 配置（Tier B：本系统作为授权服务器）
#[derive(Clone, Debug, Deserialize)]
pub struct SsoConfig {
    /// 是否启用 SSO（OIDC Provider）端点。默认关闭，需显式开启（生产按需）
    #[serde(default = "default_sso_disabled")]
    pub enabled: bool,
    /// OIDC issuer（发现文档 iss 与端点绝对前缀）。
    /// enabled=true 时必须显式配置且为 https（localhost/127.0.0.1 例外）——
    /// v4-P1-2：不再允许按请求 Host 推导（Host 头可被伪造，issuer 可被诱导）。
    #[serde(default)]
    pub issuer: String,
    /// 授权码有效期（秒，默认 60，短 TTL 一次性使用）
    #[serde(default = "default_sso_code_ttl_secs")]
    pub code_ttl_secs: u64,
    /// ID Token 有效期（秒，默认 3600）
    #[serde(default = "default_sso_id_token_ttl_secs")]
    pub id_token_ttl_secs: u64,
    /// access_token（不透明令牌）有效期（秒，默认 3600）。
    /// v4-P0-A：access_token 与 ID Token 生命周期分离——不再错用 id_token_ttl_secs。
    #[serde(default = "default_sso_access_token_ttl_secs")]
    pub access_token_ttl_secs: u64,
    /// v5-D3：refresh_token 有效期（秒，默认 30 天）。
    /// RT 为不透明令牌（与 AT 同构：SHA-256 → `sso:rt:{hash}` 绑定），轮换式使用——
    /// 每次刷新旧 RT 立即作废并签发新 RT；登出/强退/改密全量吊销。
    #[serde(default = "default_sso_refresh_token_ttl_secs")]
    pub refresh_token_ttl_secs: u64,
}

impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            enabled: default_sso_disabled(),
            issuer: String::new(),
            code_ttl_secs: default_sso_code_ttl_secs(),
            id_token_ttl_secs: default_sso_id_token_ttl_secs(),
            access_token_ttl_secs: default_sso_access_token_ttl_secs(),
            refresh_token_ttl_secs: default_sso_refresh_token_ttl_secs(),
        }
    }
}

fn default_sso_disabled() -> bool {
    false
}
fn default_sso_code_ttl_secs() -> u64 {
    60
}
fn default_sso_id_token_ttl_secs() -> u64 {
    3600
}
fn default_sso_access_token_ttl_secs() -> u64 {
    3600
}
fn default_sso_refresh_token_ttl_secs() -> u64 {
    30 * 24 * 3600
}

/// 可观测性监控配置（慢请求 / 错误聚合 / Prometheus 指标）
#[derive(Clone, Deserialize)]
pub struct MonitorConfig {
    /// /metrics 端点 Bearer token（脱敏）。
    ///
    /// 留空表示 /metrics 匿名可访问（本地 curl / 无鉴权抓取）。
    /// 生产环境强烈建议设置（可通过 MONITOR_METRICS_TOKEN 环境变量注入）。
    #[serde(default)]
    pub metrics_token: String,
    /// 慢请求阈值（毫秒），超过才记录到慢请求缓冲（默认 300ms）
    #[serde(default = "default_slow_request_ms")]
    pub slow_request_ms: u64,
    /// 慢请求缓冲容量（默认 200）
    #[serde(default = "default_slow_capacity")]
    pub slow_capacity: usize,
    /// 错误聚合缓冲容量（默认 500）
    #[serde(default = "default_error_capacity")]
    pub error_capacity: usize,
}

/// 手动实现 Debug 以脱敏 metrics_token
impl fmt::Debug for MonitorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MonitorConfig")
            .field("metrics_token", &"<redacted>")
            .field("slow_request_ms", &self.slow_request_ms)
            .field("slow_capacity", &self.slow_capacity)
            .field("error_capacity", &self.error_capacity)
            .finish()
    }
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            metrics_token: String::new(),
            slow_request_ms: default_slow_request_ms(),
            slow_capacity: default_slow_capacity(),
            error_capacity: default_error_capacity(),
        }
    }
}

fn default_slow_request_ms() -> u64 {
    300
}

fn default_slow_capacity() -> usize {
    200
}

fn default_error_capacity() -> usize {
    500
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// CORS 允许的 Origin 白名单（生产环境必须显式配置）
    pub cors_origins: Vec<String>,
    /// 可信代理 IP 白名单（CIDR 或精确 IP）
    ///
    /// 仅当直连客户端 IP 在此列表内时，才信任 X-Forwarded-For / X-Real-IP。
    /// 空列表表示不信任任何代理头，直接使用 TCP 对端 IP。
    /// 生产环境应配置为反向代理的真实 IP（如 nginx 所在机器）。
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// 是否启用 API 文档（Swagger UI / OpenAPI JSON），生产环境建议关闭
    #[serde(default = "default_docs_enabled")]
    pub docs_enabled: bool,
}

#[derive(Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: u64,
    pub idle_timeout: u64,
    /// 连接最大生命周期（秒，默认 1800=30 分钟）
    ///
    /// 避免长连接因 MySQL wait_timeout / 网络中间件探活失效而出现静默断开。
    #[serde(default = "default_db_max_lifetime_secs")]
    pub max_lifetime_secs: u64,
    /// 从池中获取连接的等待超时（秒，默认 10）
    ///
    /// 超时返回错误（业务层转为 503），而非无限阻塞协程。
    #[serde(default = "default_db_acquire_timeout_secs")]
    pub acquire_timeout_secs: u64,
}

/// 手动实现 Debug 以脱敏 url（含数据库密码）
impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &"<redacted>")
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("connect_timeout", &self.connect_timeout)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_lifetime_secs", &self.max_lifetime_secs)
            .field("acquire_timeout_secs", &self.acquire_timeout_secs)
            .finish()
    }
}

fn default_db_max_lifetime_secs() -> u64 {
    1800
}

fn default_db_acquire_timeout_secs() -> u64 {
    10
}

#[derive(Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

/// 手动实现 Debug 以脱敏 url（含 Redis 密码）
impl fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisConfig")
            .field("url", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expire_hours: i64,
    pub issuer: String,
    /// JWT 受众（aud claim），用于防止 token 跨服务复用（SEC-001）
    /// 默认 "yebot"，生产环境应通过配置显式指定
    #[serde(default = "default_jwt_audience")]
    pub audience: String,
}

/// 手动实现 Debug 以脱敏 secret
impl fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtConfig")
            .field("secret", &"<redacted>")
            .field("expire_hours", &self.expire_hours)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    pub level: String,
    pub sql_logging: bool,
    /// 日志文件输出目录（相对路径，默认 "logs"）
    /// 配置后日志会同时输出到 stdout 和文件（按日轮转）
    #[serde(default = "default_log_file_path")]
    pub file_path: String,
    /// stdout 是否使用 JSON 结构化格式（P2-9，生产环境推荐 true，便于 ELK/Loki 采集）
    /// 文件层始终使用纯文本（grep 友好）
    #[serde(default)]
    pub json_stdout: bool,
}

/// 文件上传配置
#[derive(Debug, Clone, Deserialize)]
pub struct UploadConfig {
    /// 头像存储目录（相对路径，如 "uploads/avatar"）
    #[serde(default = "default_avatar_dir")]
    pub avatar_dir: String,
    /// 头像访问 URL 前缀（如 "/uploads/avatar"）
    #[serde(default = "default_avatar_url_prefix")]
    pub avatar_url_prefix: String,
    /// 允许的头像扩展名白名单（小写，不含点）
    #[serde(default = "default_avatar_allowed_exts")]
    pub avatar_allowed_exts: Vec<String>,
    /// 头像最大字节数
    #[serde(default = "default_avatar_max_size")]
    pub avatar_max_size: usize,
    /// 通用上传文件存储目录（相对路径，如 "uploads/file"）
    #[serde(default = "default_common_dir")]
    pub common_dir: String,
    /// 通用上传文件访问 URL 前缀（如 "/uploads/file"）
    #[serde(default = "default_common_url_prefix")]
    pub common_url_prefix: String,
    /// 通用上传允许的扩展名白名单（小写，不含点）
    #[serde(default = "default_common_allowed_exts")]
    pub common_allowed_exts: Vec<String>,
    /// 通用上传最大字节数
    #[serde(default = "default_common_max_size")]
    pub common_max_size: usize,
    /// 存储后端类型（`local` 或 `s3`），默认 local（F1）
    ///
    /// - `local`：本地文件系统（现有默认行为，配合 `/uploads/*` 静态托管）
    /// - `s3`：S3 兼容对象存储（MinIO / AWS S3 / 阿里云 OSS / 腾讯 COS），
    ///   文件保存到 `s3.bucket` 的 `uploads/...` 前缀下，并通过 `s3.public_endpoint`
    ///   生成可访问 URL（前端无需任何改动）
    #[serde(default = "default_upload_backend")]
    pub backend: String,
    /// S3 兼容对象存储配置（backend=s3 时使用）
    #[serde(default)]
    pub s3: S3StorageConfig,
}

impl Default for UploadConfig {
    fn default() -> Self {
        Self {
            avatar_dir: default_avatar_dir(),
            avatar_url_prefix: default_avatar_url_prefix(),
            avatar_allowed_exts: default_avatar_allowed_exts(),
            avatar_max_size: default_avatar_max_size(),
            common_dir: default_common_dir(),
            common_url_prefix: default_common_url_prefix(),
            common_allowed_exts: default_common_allowed_exts(),
            common_max_size: default_common_max_size(),
            backend: default_upload_backend(),
            s3: S3StorageConfig::default(),
        }
    }
}

fn default_avatar_dir() -> String {
    "uploads/avatar".to_string()
}

/// S3 兼容对象存储配置（F1）
///
/// 支持 MinIO / AWS S3 / 阿里云 OSS / 腾讯 COS 等一切 S3 兼容端点。
/// 存储时对象 key 使用 `uploads/{dir}/{uuid}.{ext}` 前缀，路径风格（path-style）统一，
/// 便于从 `public_endpoint` 直接返回可访问 URL。
#[derive(Clone, Deserialize)]
pub struct S3StorageConfig {
    /// 访问密钥 ID（AK）
    #[serde(default)]
    pub access_key: String,
    /// 访问密钥 Secret（SK，生产环境建议通过 S3_SECRET_KEY 环境变量注入）
    #[serde(default)]
    pub secret_key: String,
    /// S3 端点（如 `https://minio.example.com:9000` 或 `https://s3.cn-north-1.amazonaws.com.cn`）
    #[serde(default)]
    pub endpoint: String,
    /// 区域（如 `us-east-1`、`cn-north-1`）
    #[serde(default = "default_s3_region")]
    pub region: String,
    /// 桶名（Bucket）
    #[serde(default)]
    pub bucket: String,
    /// 寻址风格：`true` 路径风格（MinIO / 阿里云 OSS / 腾讯 COS 默认），
    /// 对象 URI 为 `/{bucket}/{key}`；`false` 虚拟主机风格（AWS S3 推荐），
    /// bucket 作为 endpoint 的子域（`{bucket}.{host}/{key}`），并将 endpoint 设为
    /// `https://s3.{region}.amazonaws.com`。可通过环境变量 `S3_PATH_STYLE=false` 覆盖。
    #[serde(default = "default_s3_path_style")]
    pub path_style: bool,
    /// 对象访问公开 URL 前缀（用于前端拼接访问地址，如 `https://cdn.example.com`）。
    /// 为空时回退使用 `endpoint`。
    #[serde(default)]
    pub public_endpoint: String,
}

/// 手动实现 Debug 以脱敏 secret_key
impl fmt::Debug for S3StorageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3StorageConfig")
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("path_style", &self.path_style)
            .field("public_endpoint", &self.public_endpoint)
            .finish()
    }
}

impl Default for S3StorageConfig {
    fn default() -> Self {
        Self {
            access_key: String::new(),
            secret_key: String::new(),
            endpoint: String::new(),
            region: default_s3_region(),
            bucket: String::new(),
            path_style: default_s3_path_style(),
            public_endpoint: String::new(),
        }
    }
}

fn default_upload_backend() -> String {
    "local".to_string()
}

fn default_s3_region() -> String {
    "us-east-1".to_string()
}

fn default_s3_path_style() -> bool {
    true
}

/// 日志文件输出目录默认值（P0-67 未修复项）
fn default_log_file_path() -> String {
    "logs".to_string()
}

fn default_avatar_url_prefix() -> String {
    "/uploads/avatar".to_string()
}

fn default_avatar_allowed_exts() -> Vec<String> {
    vec![
        "jpg".to_string(),
        "jpeg".to_string(),
        "png".to_string(),
        "gif".to_string(),
    ]
}

fn default_avatar_max_size() -> usize {
    crate::common::constants::AVATAR_MAX_SIZE
}

fn default_common_dir() -> String {
    "uploads/file".to_string()
}

fn default_common_url_prefix() -> String {
    "/uploads/file".to_string()
}

fn default_common_allowed_exts() -> Vec<String> {
    vec![
        "jpg".to_string(),
        "jpeg".to_string(),
        "png".to_string(),
        "gif".to_string(),
        "pdf".to_string(),
        "doc".to_string(),
        "docx".to_string(),
        "xls".to_string(),
        "xlsx".to_string(),
        "txt".to_string(),
        "zip".to_string(),
    ]
}

fn default_common_max_size() -> usize {
    crate::common::constants::UPLOAD_MAX_SIZE
}

/// 审批工作流配置（m20260923_000002 flow_module）
///
/// - `timeout_scan_cron` 为空 = 禁用超时扫描任务（mmdb_auto_update 同款约定）
/// - `enabled` 为第二开关（运行配置级），两个条件同时满足才注册任务
#[derive(Debug, Clone, Deserialize)]
pub struct FlowConfig {
    /// 超时扫描 cron（6 字段含秒，默认每 10 分钟）；空字符串 = 禁用
    #[serde(default = "default_flow_scan_cron")]
    pub timeout_scan_cron: String,
    /// 是否启用审批超时扫描（第二开关，默认 true）
    #[serde(default = "default_flow_scan_enabled")]
    pub enabled: bool,
    /// 待办 SLA 时长（小时，超过即触发提醒；默认 48h）
    #[serde(default = "default_flow_timeout_hours")]
    pub timeout_hours: i64,
    /// 同一任务的重复提醒间隔（秒，Redis SETNX TTL；默认 3600）
    #[serde(default = "default_flow_remind_interval")]
    pub remind_interval_secs: u64,
    /// 单次扫描最多处理的任务数（分页限量，防止超出任务超时上限）
    #[serde(default = "default_flow_scan_batch")]
    pub scan_batch_limit: u64,
}

fn default_flow_scan_cron() -> String {
    "0 */10 * * * *".to_string()
}
fn default_flow_scan_enabled() -> bool {
    true
}
fn default_flow_timeout_hours() -> i64 {
    48
}
fn default_flow_remind_interval() -> u64 {
    3600
}
fn default_flow_scan_batch() -> u64 {
    200
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            timeout_scan_cron: default_flow_scan_cron(),
            enabled: default_flow_scan_enabled(),
            timeout_hours: default_flow_timeout_hours(),
            remind_interval_secs: default_flow_remind_interval(),
            scan_batch_limit: default_flow_scan_batch(),
        }
    }
}

/// IP 归属地查询配置
#[derive(Debug, Clone, Deserialize)]
pub struct IpLocationConfig {
    /// MaxMindDB 离线数据库文件路径（相对路径，默认 "data/GeoLite2-City.mmdb"）
    /// 文件不存在时所有查询返回空字符串，不影响业务流程
    #[serde(default = "default_mmdb_path")]
    pub mmdb_path: String,
    /// ip2region xdb 数据库文件路径（相对路径，可选）
    /// 启用后国内 IP 优先查 xdb（精度到县级行政区划），未命中再查 mmdb
    #[serde(default = "default_xdb_path")]
    pub xdb_path: String,
    /// 是否启用 ip2region 双库混合模式
    #[serde(default = "default_xdb_enabled")]
    pub xdb_enabled: bool,
    /// mmdb 自动更新 cron 表达式（6 字段含秒，默认每周二凌晨 4:00）
    /// 设为空字符串则禁用自动更新
    #[serde(default = "default_mmdb_update_cron")]
    pub auto_update_cron: String,
}

impl Default for IpLocationConfig {
    fn default() -> Self {
        Self {
            mmdb_path: default_mmdb_path(),
            xdb_path: default_xdb_path(),
            xdb_enabled: default_xdb_enabled(),
            auto_update_cron: default_mmdb_update_cron(),
        }
    }
}

fn default_mmdb_path() -> String {
    "data/GeoLite2-City.mmdb".to_string()
}

fn default_xdb_path() -> String {
    "data/ip2region.xdb".to_string()
}

fn default_xdb_enabled() -> bool {
    false
}

fn default_mmdb_update_cron() -> String {
    // 每周二凌晨 4:00（6 字段含秒）
    "0 0 4 * * 2".to_string()
}

/// 邮件 SMTP 配置
///
/// 未配置（enabled=false）时邮件功能优雅降级为仅 sys_notice 入库，不发送实际邮件。
/// 生产环境建议通过环境变量 MAIL_PASSWORD 注入 SMTP 密码，避免明文写入配置文件。
#[derive(Clone, Deserialize)]
pub struct MailConfig {
    /// 是否启用 SMTP 邮件发送（false 时所有邮件操作降级为仅记录 sys_notice）
    #[serde(default)]
    pub enabled: bool,
    /// SMTP 服务器主机（如 smtp.qq.com、smtp.gmail.com）
    #[serde(default)]
    pub host: String,
    /// SMTP 服务器端口（SSL 直连 465，STARTTLS 587）
    #[serde(default = "default_mail_port")]
    pub port: u16,
    /// SMTP 登录用户名（通常为发件邮箱地址）
    #[serde(default)]
    pub username: String,
    /// SMTP 登录密码或授权码（生产环境建议通过 MAIL_PASSWORD 环境变量注入）
    #[serde(default)]
    pub password: String,
    /// 发件人邮箱地址（通常与 username 相同）
    #[serde(default)]
    pub from_email: String,
    /// 发件人显示名称
    #[serde(default = "default_mail_from_name")]
    pub from_name: String,
    /// 是否使用 STARTTLS（端口 587 时通常为 true，端口 465 SSL 直连时为 false）
    #[serde(default = "default_mail_starttls")]
    pub starttls: bool,
}

/// 手动实现 Debug 以脱敏 password
impl fmt::Debug for MailConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailConfig")
            .field("enabled", &self.enabled)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("from_email", &self.from_email)
            .field("from_name", &self.from_name)
            .field("starttls", &self.starttls)
            .finish()
    }
}

impl Default for MailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: default_mail_port(),
            username: String::new(),
            password: String::new(),
            from_email: String::new(),
            from_name: default_mail_from_name(),
            starttls: default_mail_starttls(),
        }
    }
}

fn default_mail_port() -> u16 {
    465
}

fn default_mail_from_name() -> String {
    "yebot System".to_string()
}

fn default_mail_starttls() -> bool {
    false
}

fn default_docs_enabled() -> bool {
    // 生产环境 fail-closed：默认关闭 Swagger UI，开发环境在 config.toml 显式设 docs_enabled = true
    false
}

fn default_jwt_audience() -> String {
    "yebot".to_string()
}

impl Settings {
    /// 从 toml 配置文件加载，随后用环境变量覆盖敏感字段
    /// 环境变量优先级：DATABASE_URL > REDIS_URL > JWT_SECRET > SERVER_HOST > SERVER_PORT > config.toml
    ///
    /// 配置文件查找链：`path` → 同目录 `config.toml.prod` → 仅环境变量模式。
    /// 这样容器镜像只需注入环境变量（DATABASE_URL/REDIS_URL/JWT_SECRET/...）即可启动，
    /// 无需挂载 `config/config.toml`（该文件已被 .dockerignore 排除，否则会导致启动崩溃）。
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let candidates = [path, "config/config.toml.prod"];
        for (idx, cand) in candidates.iter().enumerate() {
            match std::fs::read_to_string(cand) {
                Ok(content) => {
                    let mut settings: Settings = toml::from_str(&content)
                        .map_err(|e| anyhow::anyhow!("解析配置文件 {} 失败: {}", cand, e))?;
                    settings.apply_env_overrides();
                    settings.validate_secrets()?;
                    if idx != 0 {
                        tracing::warn!("配置文件 {} 不存在，已回退使用 {}", path, cand);
                    }
                    return Ok(settings);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(anyhow::anyhow!("读取配置文件 {} 失败: {}", cand, e));
                }
            }
        }

        // 配置文件全部缺失：回退到仅环境变量模式（容器/无配置文件部署场景）
        tracing::warn!(
            "未找到任何配置文件（{} / config/config.toml.prod），回退到仅环境变量模式",
            path
        );
        Self::from_env_only()
    }

    /// 用环境变量覆盖可注入字段（敏感配置与部署相关参数）
    ///
    /// 覆盖项：DATABASE_URL / REDIS_URL / JWT_SECRET / JWT_EXPIRE_HOURS /
    /// SERVER_HOST / SERVER_PORT / CORS_ORIGINS（可选，逗号分隔）/
    /// MAIL_PASSWORD / CONFIG_ENC_KEY
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("DATABASE_URL") {
            self.database.url = v;
        }
        if let Ok(v) = std::env::var("REDIS_URL") {
            self.redis.url = v;
        }
        if let Ok(v) = std::env::var("JWT_SECRET") {
            self.jwt.secret = v;
        }
        if let Ok(v) = std::env::var("JWT_EXPIRE_HOURS")
            && let Ok(hours) = v.parse::<i64>()
        {
            if hours > 0 {
                self.jwt.expire_hours = hours;
            } else {
                // P2：拒绝 0/负值（会导致 token 立即过期或签发异常），回退默认 24h
                tracing::warn!("JWT_EXPIRE_HOURS={hours} 无效（必须 > 0），回退默认 24 小时");
                self.jwt.expire_hours = 24;
            }
        }
        if let Ok(v) = std::env::var("SERVER_HOST") {
            self.server.host = v;
        }
        if let Ok(v) = std::env::var("SERVER_PORT")
            && let Ok(port) = v.parse::<u16>()
        {
            self.server.port = port;
        }
        if let Ok(v) = std::env::var("CORS_ORIGINS") {
            let origins: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !origins.is_empty() {
                self.server.cors_origins = origins;
            }
        }
        // 邮件 SMTP 密码通过环境变量注入（避免明文写入配置文件）
        if let Ok(v) = std::env::var("MAIL_PASSWORD") {
            self.mail.password = v;
        }
        // 配置加密主密钥（用于 sys_config 表中敏感字段 AES-256-GCM 加解密）
        // 启用 IP 库管理功能时必须配置，否则 License Key 加密功能失效
        if let Ok(v) = std::env::var("CONFIG_ENC_KEY") {
            self.config_enc_key = v;
        }
        // 权限 fail-open 加固开关（B3）：未映射路由是否默认拒绝
        // PERMISSION_DENY_BY_DEFAULT=true 时，受保护路由中未登记权限映射且不在"仅登录白名单"的
        // 路径将被拒绝（403），实现 fail-closed，防止新增路由漏登记权限导致越权。
        // 缺省不设置则保持 false（fail-open 放行，兼容现有默认行为，零破坏性）。
        if let Ok(v) = std::env::var("PERMISSION_DENY_BY_DEFAULT") {
            self.permission_deny_by_default = v == "true" || v == "1";
        }
        // 存储后端类型（F1）：UPLOAD_BACKEND=local|s3
        if let Ok(v) = std::env::var("UPLOAD_BACKEND") {
            self.upload.backend = v;
        }
        // S3 兼容对象存储敏感字段通过环境变量注入（避免明文写入配置文件）
        if let Ok(v) = std::env::var("S3_ACCESS_KEY") {
            self.upload.s3.access_key = v;
        }
        if let Ok(v) = std::env::var("S3_SECRET_KEY") {
            self.upload.s3.secret_key = v;
        }
        if let Ok(v) = std::env::var("S3_ENDPOINT") {
            self.upload.s3.endpoint = v;
        }
        if let Ok(v) = std::env::var("S3_REGION") {
            self.upload.s3.region = v;
        }
        if let Ok(v) = std::env::var("S3_BUCKET") {
            self.upload.s3.bucket = v;
        }
        if let Ok(v) = std::env::var("S3_PUBLIC_ENDPOINT") {
            self.upload.s3.public_endpoint = v;
        }
        // 寻址风格开关（F1）：S3_PATH_STYLE=false 切换为虚拟主机风格，缺省保持路径风格
        if let Ok(v) = std::env::var("S3_PATH_STYLE") {
            self.upload.s3.path_style = !(v.eq_ignore_ascii_case("false") || v == "0");
        }
        // 可观测性监控配置（Prometheus 指标 token 脱敏注入，避免明文写入配置文件）
        if let Ok(v) = std::env::var("MONITOR_METRICS_TOKEN") {
            self.monitor.metrics_token = v;
        }
        // 系统日志保留天数（M2）：LOG_RETENTION_DAYS 环境变量覆盖默认 90 天
        if let Ok(v) = std::env::var("LOG_RETENTION_DAYS")
            && let Ok(days) = v.parse::<i64>()
            && days > 0
        {
            self.sys_log.retention_days = days;
        }
        // 单点登录 / OIDC Provider（Tier B）：默认关闭，SSO_ENABLED=true 显式开启
        if let Ok(v) = std::env::var("SSO_ENABLED") {
            self.sso.enabled = v == "true" || v == "1";
        }
        // OIDC issuer（发现文档 iss 与端点绝对前缀），enabled=true 时必须显式配置（v4-P1-2）
        if let Ok(v) = std::env::var("SSO_ISSUER") {
            self.sso.issuer = v;
        }
        // v4-P1-3：TTL 三项支持 env 覆盖（容器场景无法改配置文件）
        if let Ok(v) = std::env::var("SSO_CODE_TTL_SECS")
            && let Ok(n) = v.parse::<u64>()
            && n > 0
        {
            self.sso.code_ttl_secs = n;
        }
        if let Ok(v) = std::env::var("SSO_ID_TOKEN_TTL_SECS")
            && let Ok(n) = v.parse::<u64>()
            && n > 0
        {
            self.sso.id_token_ttl_secs = n;
        }
        if let Ok(v) = std::env::var("SSO_ACCESS_TOKEN_TTL_SECS")
            && let Ok(n) = v.parse::<u64>()
            && n > 0
        {
            self.sso.access_token_ttl_secs = n;
        }
    }

    /// 仅从环境变量构建配置（无配置文件场景，如容器通过环境变量注入）
    ///
    /// 必需环境变量：DATABASE_URL、REDIS_URL、JWT_SECRET、SERVER_HOST、SERVER_PORT
    /// 可选环境变量：JWT_EXPIRE_HOURS（默认 24）、CORS_ORIGINS（逗号分隔）、
    ///                MAIL_PASSWORD、CONFIG_ENC_KEY、RUST_LOG（默认 info）
    /// 其余字段使用与结构体一致的内置默认值。
    fn from_env_only() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL").map_err(|_| {
            anyhow::anyhow!("环境变量 DATABASE_URL 未设置（容器部署需通过 -e/compose 注入）")
        })?;
        let redis_url =
            std::env::var("REDIS_URL").map_err(|_| anyhow::anyhow!("环境变量 REDIS_URL 未设置"))?;
        let jwt_secret = std::env::var("JWT_SECRET")
            .map_err(|_| anyhow::anyhow!("环境变量 JWT_SECRET 未设置"))?;
        let server_host = std::env::var("SERVER_HOST")
            .map_err(|_| anyhow::anyhow!("环境变量 SERVER_HOST 未设置"))?;
        let server_port = std::env::var("SERVER_PORT")
            .map_err(|_| anyhow::anyhow!("环境变量 SERVER_PORT 未设置"))?
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("SERVER_PORT 解析失败: {}", e))?;
        let jwt_expire_hours = std::env::var("JWT_EXPIRE_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse::<i64>()
            .map_err(|e| anyhow::anyhow!("JWT_EXPIRE_HOURS 解析失败: {}", e))?;

        let mut settings = Settings {
            pat: PatConfig::default(),
            sso: SsoConfig::default(),
            flow: FlowConfig::default(),
            server: ServerConfig {
                host: server_host,
                port: server_port,
                cors_origins: vec![],
                trusted_proxies: vec![],
                docs_enabled: false,
            },
            database: DatabaseConfig {
                url: database_url,
                max_connections: 20,
                min_connections: 5,
                connect_timeout: 8,
                idle_timeout: 600,
                max_lifetime_secs: 1800,
                acquire_timeout_secs: 10,
            },
            redis: RedisConfig { url: redis_url },
            jwt: JwtConfig {
                secret: jwt_secret,
                expire_hours: jwt_expire_hours,
                issuer: "yebot".to_string(),
                audience: "yebot".to_string(),
            },
            log: LogConfig {
                level: std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
                sql_logging: false,
                file_path: "logs".to_string(),
                json_stdout: true,
            },
            upload: UploadConfig::default(),
            ip_location: IpLocationConfig::default(),
            mail: MailConfig::default(),
            config_enc_key: std::env::var("CONFIG_ENC_KEY").unwrap_or_default(),
            monitor: MonitorConfig::default(),
            permission_deny_by_default: true,
            sys_log: SysLogConfig::default(),
        };

        settings.apply_env_overrides();
        settings.validate_secrets()?;
        Ok(settings)
    }

    /// 校验敏感配置不使用默认占位符
    ///
    /// 若 jwt.secret 或 database.url 包含占位符（CHANGE_ME），
    /// 启动时直接报错拒绝，防止生产环境使用不安全配置。
    fn validate_secrets(&self) -> anyhow::Result<()> {
        // B10：显式拒绝弱/占位密钥（大小写不敏感 deny-list），覆盖 CHANGE_ME（旧逻辑）、
        // 测试前缀 yebot_local_test_*、example/password/test_ 等常见弱密钥模式。
        // 使用 deny-list 而非激进熵评分，避免误杀合法开发密钥（向后兼容）。
        let weak_patterns: &[&str] = &[
            "changeme",
            "change_me",
            "test_",
            "yebot_local_test_",
            "example",
            "password",
        ];
        let secret_lower = self.jwt.secret.to_lowercase();
        if weak_patterns.iter().any(|p| secret_lower.contains(p)) {
            anyhow::bail!(
                "jwt.secret 不能使用弱/占位密钥（命中禁止模式），请通过环境变量 JWT_SECRET 设置真实强密钥（至少 32 字符）"
            );
        }
        let db_lower = self.database.url.to_lowercase();
        if db_lower.contains("changeme") || db_lower.contains("change_me") {
            anyhow::bail!(
                "database.url 不能使用默认占位符，请通过环境变量 DATABASE_URL 设置真实数据库连接"
            );
        }
        if self.jwt.secret.len() < 32 {
            anyhow::bail!(
                "jwt.secret 长度不足 32 字符，当前 {} 字符，请设置更强的密钥",
                self.jwt.secret.len()
            );
        }
        // B8：CONFIG_ENC_KEY 用于派生 AES-256-GCM 密钥（crypto.rs 以 SHA256(master_key) 作 KDF）。
        // 若显式配置但熵不足（<32 字符），派生出的密钥可被离线暴力枚举，故强制长度下限。
        // 空值（未配置）保持宽容：系统以明文 fail-open 存储（见 ip_location_service），不在此拦截，
        // 以免破坏依赖空密钥的开发/测试环境。
        if !self.config_enc_key.is_empty() && self.config_enc_key.len() < 32 {
            anyhow::bail!(
                "CONFIG_ENC_KEY 长度不足 32 字符（当前 {} 字符），低熵密钥无法保证 AES-256-GCM 安全，请使用 ≥32 随机字符",
                self.config_enc_key.len()
            );
        }
        // v4-P1-2：SSO 启用时强制显式 issuer（https，localhost/127.0.0.1 例外）。
        // 不再允许按请求 Host 推导 issuer——Host 头可被攻击者伪造，issuer 可被诱导错配。
        if self.sso.enabled {
            let issuer = self.sso.issuer.trim();
            if issuer.is_empty() {
                anyhow::bail!(
                    "SSO_ENABLED=true 时必须显式配置 SSO_ISSUER（https URL），禁止按请求 Host 动态推导（可被伪造）"
                );
            }
            let is_local =
                issuer.starts_with("http://localhost") || issuer.starts_with("http://127.0.0.1");
            if !issuer.starts_with("https://") && !is_local {
                anyhow::bail!(
                    "SSO_ISSUER 必须为 https URL（OIDC 规范要求），当前: {issuer}（本地开发可用 http://localhost 或 http://127.0.0.1）"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个通过校验的基准 Settings（jwt.secret 为合法强密钥），供测试复用
    fn make_test_settings() -> Settings {
        Settings {
            pat: PatConfig::default(),
            sso: SsoConfig::default(),
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                cors_origins: vec![],
                trusted_proxies: vec![],
                docs_enabled: false,
            },
            database: DatabaseConfig {
                url: "postgres://user:pass@host:5432/db".to_string(),
                max_connections: 10,
                min_connections: 1,
                connect_timeout: 8,
                idle_timeout: 600,
                max_lifetime_secs: 1800,
                acquire_timeout_secs: 10,
            },
            redis: RedisConfig {
                url: "redis://localhost:6379".to_string(),
            },
            jwt: JwtConfig {
                secret: "placeholder-strong-secret-0123456789abcdef".to_string(),
                expire_hours: 24,
                issuer: "yebot".to_string(),
                audience: "yebot".to_string(),
            },
            log: LogConfig {
                level: "info".to_string(),
                sql_logging: false,
                file_path: "logs".to_string(),
                json_stdout: false,
            },
            upload: UploadConfig::default(),
            ip_location: IpLocationConfig::default(),
            mail: MailConfig::default(),
            config_enc_key: String::new(),
            monitor: MonitorConfig::default(),
            permission_deny_by_default: true,
            flow: FlowConfig::default(),
            sys_log: SysLogConfig::default(),
        }
    }

    /// 验证 Settings Debug 输出不泄漏 config_enc_key
    #[test]
    fn test_settings_debug_redacts_config_enc_key() {
        let settings = Settings {
            pat: PatConfig::default(),
            sso: SsoConfig::default(),
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                cors_origins: vec![],
                trusted_proxies: vec![],
                docs_enabled: false,
            },
            database: DatabaseConfig {
                url: "postgres://user:supersecret@host:5432/db".to_string(),
                max_connections: 10,
                min_connections: 1,
                connect_timeout: 8,
                idle_timeout: 600,
                max_lifetime_secs: 1800,
                acquire_timeout_secs: 10,
            },
            redis: RedisConfig {
                url: "redis://:redispass@host:6379".to_string(),
            },
            jwt: JwtConfig {
                secret: "a-very-long-jwt-secret-key-for-testing-32+chars".to_string(),
                expire_hours: 24,
                issuer: "yebot".to_string(),
                audience: "yebot".to_string(),
            },
            log: LogConfig {
                level: "info".to_string(),
                sql_logging: false,
                file_path: "logs".to_string(),
                json_stdout: false,
            },
            upload: UploadConfig::default(),
            ip_location: IpLocationConfig::default(),
            mail: MailConfig {
                enabled: true,
                host: "smtp.example.com".to_string(),
                port: 465,
                username: "user@example.com".to_string(),
                password: "smtp_password_123".to_string(),
                from_email: "noreply@example.com".to_string(),
                from_name: "Test".to_string(),
                starttls: false,
            },
            config_enc_key: "encryption-key-should-not-leak".to_string(),
            monitor: MonitorConfig::default(),
            permission_deny_by_default: true,
            flow: FlowConfig::default(),
            sys_log: SysLogConfig::default(),
        };

        let debug_str = format!("{:?}", settings);

        // 敏感字段不应出现在 Debug 输出中
        assert!(
            !debug_str.contains("supersecret"),
            "database URL password leaked"
        );
        assert!(
            !debug_str.contains("redispass"),
            "Redis URL password leaked"
        );
        assert!(
            !debug_str.contains("a-very-long-jwt-secret"),
            "JWT secret leaked"
        );
        assert!(
            !debug_str.contains("smtp_password_123"),
            "Mail password leaked"
        );
        assert!(
            !debug_str.contains("encryption-key-should-not-leak"),
            "config_enc_key leaked"
        );

        // 脱敏标记应存在
        assert!(debug_str.contains("<redacted>"), "Redacted marker missing");
    }

    /// 验证 DatabaseConfig Debug 不泄漏 url
    #[test]
    fn test_database_config_debug_redacts_url() {
        let db_config = DatabaseConfig {
            url: "mysql://root:password123@localhost:3306/yebot".to_string(),
            max_connections: 20,
            min_connections: 5,
            connect_timeout: 8,
            idle_timeout: 600,
            max_lifetime_secs: 1800,
            acquire_timeout_secs: 10,
        };
        let debug_str = format!("{:?}", db_config);
        assert!(
            !debug_str.contains("password123"),
            "Database URL password leaked in Debug"
        );
        assert!(debug_str.contains("<redacted>"));
    }

    /// 验证 JwtConfig Debug 不泄漏 secret
    #[test]
    fn test_jwt_config_debug_redacts_secret() {
        let jwt_config = JwtConfig {
            secret: "my-super-secret-jwt-key-1234567890123456".to_string(),
            expire_hours: 24,
            issuer: "yebot".to_string(),
            audience: "yebot".to_string(),
        };
        let debug_str = format!("{:?}", jwt_config);
        assert!(
            !debug_str.contains("my-super-secret-jwt-key"),
            "JWT secret leaked in Debug"
        );
        assert!(debug_str.contains("<redacted>"));
    }

    /// 验证 MailConfig Debug 不泄漏 password
    #[test]
    fn test_mail_config_debug_redacts_password() {
        let mail_config = MailConfig {
            enabled: true,
            host: "smtp.qq.com".to_string(),
            port: 465,
            username: "test@qq.com".to_string(),
            password: "qq_auth_code_secret".to_string(),
            from_email: "test@qq.com".to_string(),
            from_name: "Test".to_string(),
            starttls: false,
        };
        let debug_str = format!("{:?}", mail_config);
        assert!(
            !debug_str.contains("qq_auth_code_secret"),
            "Mail password leaked in Debug"
        );
        assert!(debug_str.contains("<redacted>"));
    }

    /// 验证 RedisConfig Debug 不泄漏 url
    #[test]
    fn test_redis_config_debug_redacts_url() {
        let redis_config = RedisConfig {
            url: "redis://:mypassword@localhost:6379/0".to_string(),
        };
        let debug_str = format!("{:?}", redis_config);
        assert!(
            !debug_str.contains("mypassword"),
            "Redis URL password leaked in Debug"
        );
        assert!(debug_str.contains("<redacted>"));
    }

    /// B10：validate_secrets 应拒绝弱/占位密钥，放行合法强密钥（deny-list 向后兼容）
    #[test]
    fn test_validate_secrets_rejects_weak_keys() {
        // 合法强密钥应通过
        let mut s = make_test_settings();
        s.jwt.secret = "a-valid-strong-jwt-secret-key-0123456789abcdef".to_string();
        assert!(s.validate_secrets().is_ok(), "合法强密钥应被接受");

        // 测试前缀 yebot_local_test_* 应被拒
        let mut s2 = make_test_settings();
        s2.jwt.secret = "yebot_local_test_abc1234567890123456789".to_string();
        assert!(s2.validate_secrets().is_err(), "测试前缀密钥应被拒绝");

        // CHANGE_ME 占位（大小写不敏感）应被拒
        let mut s3 = make_test_settings();
        s3.jwt.secret = "CHANGE_ME_please_set_a_real_strong_secret_xx".to_string();
        assert!(s3.validate_secrets().is_err(), "CHANGE_ME 占位密钥应被拒绝");

        // password 弱模式应被拒
        let mut s4 = make_test_settings();
        s4.jwt.secret = "password_12345678901234567890123456789".to_string();
        assert!(s4.validate_secrets().is_err(), "password 弱模式应被拒绝");

        // example 弱模式应被拒
        let mut s5 = make_test_settings();
        s5.jwt.secret = "example_secret_key_012345678901234567890".to_string();
        assert!(s5.validate_secrets().is_err(), "example 弱模式应被拒绝");
    }
}
