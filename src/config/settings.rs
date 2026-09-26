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
    /// 权限未映射路由的默认处置策略（权限 fail-closed 加固，B3 / W-1）
    ///
    /// - true（**默认**，fail-closed）：未登记权限映射且不在"仅登录白名单"的受保护路由
    ///   **拒绝（403）**并审计，防止新增路由漏登记权限导致越权。
    /// - false（**显式** opt-out，开发/兼容）：此类路由**放行**（fail-open，安全假设被削弱）。
    ///
    /// 默认值与 `from_env_only()`（配置文件全缺失时的回退路径）及集成测试夹具保持一致，
    /// 避免"换配置来源即换安全姿态"的环境漂移。
    ///
    /// 注意：①permission_middleware 仅作用于 protected 路由子树的 route_layer，
    /// 公开路由（/login /health /ws /swagger-ui / 等）不受影响；
    /// ②在 TOML 中本键位于**顶层**，必须写在任何 `[table]` 段之前，
    /// 否则会被解析进上一张表（如 `[log]`）而被静默忽略（曾发生，见单测
    /// `test_shipped_config_template_is_fail_closed`）。
    #[serde(default = "default_deny_by_default")]
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
    /// v5-D12：SCIM 2.0 用户目录同步配置（供外部 IdP provisioning 调用，默认关闭）
    #[serde(default)]
    pub scim: ScimConfig,
    /// 审批工作流配置（m20260923_000002；cron 为空 = 禁用超时扫描）
    #[serde(default)]
    pub flow: FlowConfig,
    /// 平台层**能力位**默认值（三层开关的最外层：能开什么）。
    ///
    /// 键 = `crate::common::features::KNOWN_FEATURES` 登记的能力位键，值 = 模式串
    /// （如 `off` / `view_only` / `full`）。未登记键与非法模式在启动时被剔除并告警。
    /// **缺省 `{}` = 全关闭**（默认值 = 现状 = 关闭态即安全态）。
    #[serde(default)]
    pub features: FeaturesConfig,
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
            .field("features", &self.features)
            .finish()
    }
}

/// 平台层能力位默认值（`config.toml` 的 `[features]` 段）。
///
/// `#[serde(transparent)]` + `BTreeMap`：TOML 里就是一个扁平表
/// （`nav.l3 = "off"`），无嵌套层级；`BTreeMap` 保证序列化顺序稳定。
///
/// 单一事实源仍是 `crate::common::features::KNOWN_FEATURES`——本结构只承载
/// **平台层的显式覆盖**，未写在此处的能力位一律走注册表默认（`off`）。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(transparent)]
pub struct FeaturesConfig(pub std::collections::BTreeMap<String, String>);

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

/// `permission_deny_by_default` 的缺省值：`true`（fail-closed，W-1）
///
/// 与 `from_env_only()`、集成测试夹具保持一致；只有显式写 `false` 才降级为 fail-open。
fn default_deny_by_default() -> bool {
    true
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

/// v5-D12：SCIM 2.0 用户目录同步配置（RFC 7644 最小可用子集）
#[derive(Clone, Deserialize)]
pub struct ScimConfig {
    /// 是否启用 /scim/v2 端点。默认关闭，需显式开启（SCIM_ENABLED=true）
    #[serde(default = "default_scim_disabled")]
    pub enabled: bool,
    /// SCIM Bearer Token（IdP 服务器对服务器调用的专用凭据，与用户 JWT 无关）。
    /// enabled=true 时必须非空且 ≥32 字符（SCIM_BEARER_TOKEN 环境变量注入）。
    #[serde(default)]
    pub bearer_token: String,
    /// SCIM 凭据归属租户（v5-N2 Phase 3 收口）：该凭据 provisioning 出的用户/组
    /// 归属此租户，读路径亦按此租户过滤。0 = 平台租户（全局 provisioning，不过滤）。
    /// 通过 SCIM_TENANT_ID 环境变量注入。
    #[serde(default)]
    pub tenant_id: i64,
}

impl Default for ScimConfig {
    fn default() -> Self {
        Self {
            enabled: default_scim_disabled(),
            bearer_token: String::new(),
            tenant_id: 0,
        }
    }
}

fn default_scim_disabled() -> bool {
    false
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
    ///
    /// W-7 起语义收窄为"**首次提醒**的多实例互斥窗口"：提醒只发一次
    /// （DB `last_reminded_at` 为事实源），后续不再重复打扰（待办红点常驻由列表承担）。
    #[serde(default = "default_flow_remind_interval")]
    pub remind_interval_secs: u64,
    /// 升级提醒阈值（小时；默认 72；**0 = 关闭升级**）
    ///
    /// 待办超时超过该时长仍 pending 时，额外提醒一次**申请人部门主管**（不可用时回退 admin），
    /// 形成"首次提醒本人 → 超 N 天升级主管"的闭环（W-7 推荐策略）。
    #[serde(default = "default_flow_escalate_after_hours")]
    pub escalate_after_hours: i64,
    /// 单次扫描最多处理的任务数（分页限量，防止超出任务超时上限）
    #[serde(default = "default_flow_scan_batch")]
    pub scan_batch_limit: u64,
    /// 是否启用**分布式扫描锁**（S-1；默认 `false` = 接受单实例部署假设）
    ///
    /// 单实例部署下无需锁：逐任务 `SET NX` 已能防止重复提醒。多实例部署时须置 `true`，
    /// 否则多实例会**同时**执行整轮扫描（逐任务去重只能收窄不能消除重复提醒/巡检开销）。
    /// 锁 key 为 `lock:scheduler:flow_timeout_scan`，释放走 Lua CAS（防误删他实例的锁）。
    #[serde(default = "default_flow_scan_lock_enabled")]
    pub scan_lock_enabled: bool,
    /// 分布式扫描锁 TTL（秒；默认 300 = 5 分钟）
    ///
    /// 必须**大于**单轮扫描的最坏耗时（`scan_batch_limit` 条任务的提醒 + 巡检），
    /// 否则锁提前过期会导致并发窗口重现；同理过大会在实例崩溃后延长恢复窗口。
    #[serde(default = "default_flow_scan_lock_ttl")]
    pub scan_lock_ttl_secs: u64,
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
fn default_flow_escalate_after_hours() -> i64 {
    72
}
fn default_flow_scan_batch() -> u64 {
    200
}
fn default_flow_scan_lock_enabled() -> bool {
    false
}
fn default_flow_scan_lock_ttl() -> u64 {
    300
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            timeout_scan_cron: default_flow_scan_cron(),
            enabled: default_flow_scan_enabled(),
            timeout_hours: default_flow_timeout_hours(),
            remind_interval_secs: default_flow_remind_interval(),
            escalate_after_hours: default_flow_escalate_after_hours(),
            scan_batch_limit: default_flow_scan_batch(),
            scan_lock_enabled: default_flow_scan_lock_enabled(),
            scan_lock_ttl_secs: default_flow_scan_lock_ttl(),
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
        // 权限 fail-closed 开关（B3 / W-1）：未映射路由是否默认拒绝
        // PERMISSION_DENY_BY_DEFAULT=true 时，受保护路由中未登记权限映射且不在"仅登录白名单"的
        // 路径将被拒绝（403），实现 fail-closed，防止新增路由漏登记权限导致越权。
        // 缺省（不设置且配置文件未写）即 true（fail-closed）；显式设 false/0 才降级为 fail-open。
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
        // v5-D12：SCIM（SCIM_ENABLED=true 显式开启；SCIM_BEARER_TOKEN 为 IdP 调用凭据）
        if let Ok(v) = std::env::var("SCIM_ENABLED") {
            self.scim.enabled = v == "true" || v == "1";
        }
        if let Ok(v) = std::env::var("SCIM_BEARER_TOKEN") {
            self.scim.bearer_token = v;
        }
        // v5-N2 Phase 3：SCIM 凭据归属租户（0=平台租户；非 0 时 provisioning 归属该租户）
        if let Ok(v) = std::env::var("SCIM_TENANT_ID")
            && let Ok(n) = v.parse::<i64>()
        {
            self.scim.tenant_id = n;
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
            scim: ScimConfig::default(),
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
            features: FeaturesConfig::default(),
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
        // v5-D12：SCIM 启用时强制显式 Bearer Token（服务器对服务器凭据，低熵即拒绝）
        if self.scim.enabled {
            let bt = self.scim.bearer_token.trim();
            if bt.is_empty() {
                anyhow::bail!("SCIM_ENABLED=true 时必须显式配置 SCIM_BEARER_TOKEN（≥32 随机字符）");
            }
            if bt.len() < 32 {
                anyhow::bail!(
                    "SCIM_BEARER_TOKEN 长度不足 32 字符（当前 {} 字符），低熵令牌无法抵御枚举攻击",
                    bt.len()
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
            scim: ScimConfig::default(),
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
            features: FeaturesConfig::default(),
        }
    }

    /// W-1 回归：`permission_deny_by_default` 缺键时缺省即 fail-closed（true）
    ///
    /// 防止"换配置来源即换安全姿态"：此前结构体缺省为 false（fail-open），
    /// 而 `from_env_only()` / 集成测试夹具为 true，造成环境漂移。
    /// 以入库模板为基底去掉该键，既覆盖全部必填字段，又直接验证"缺键 == true"。
    #[test]
    fn test_deny_by_default_defaults_to_true() {
        let template = std::fs::read_to_string("config/config.toml.example")
            .expect("config/config.toml.example 应存在");
        let without_key = template
            .lines()
            .filter(|l| !l.trim_start().starts_with("permission_deny_by_default"))
            .collect::<Vec<_>>()
            .join("\n");
        let s: Settings = toml::from_str(&without_key).expect("模板（去掉该键）应可解析");
        assert!(
            s.permission_deny_by_default,
            "permission_deny_by_default 缺省必须为 true（fail-closed）"
        );
    }

    /// W-1 回归：入库配置模板必须在**顶层**显式 fail-closed
    ///
    /// 曾发生：该键被误写在 `[log]` 段之后，被 TOML 解析进 `log` 表而被**静默忽略**，
    /// 实际生效的是结构体缺省值 —— 安全开关形同虚设。本断言锁住"顶层 + true"两个要点。
    #[test]
    fn test_shipped_config_template_is_fail_closed() {
        // config.toml.example 为唯一入库模板；config.toml / config.toml.prod 均被 .gitignore 排除，
        // 若本机存在则一并校验（缺失时跳过，不算失败）。
        let mut checked = 0usize;
        for path in ["config/config.toml.example", "config/config.toml.prod"] {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) if path.ends_with(".example") => panic!("{path} 缺失（入库模板必须存在）"),
                Err(_) => continue,
            };
            let value: toml::Value =
                toml::from_str(&content).unwrap_or_else(|e| panic!("{path} TOML 解析失败: {e}"));
            assert_eq!(
                value
                    .get("permission_deny_by_default")
                    .and_then(|v| v.as_bool()),
                Some(true),
                "{path} 必须在**顶层**显式 permission_deny_by_default = true；\
                 写在 [table] 段之后会被解析进该表而静默忽略"
            );
            checked += 1;
        }
        assert!(checked >= 1, "至少应校验 config/config.toml.example");
    }

    /// S-1：分布式扫描锁缺省必须**关闭**（明确接受单实例部署假设）
    ///
    /// 与 W-1 相反方向：扫描锁开启时对 Redis 采用 fail-closed，若缺省就开启，
    /// 单实例部署遇到 Redis 抖动会**停止**超时提醒（业务可见的功能倒退）。
    /// 故缺省 false；多实例部署须显式置 true。同时锁 TTL 必须为正数。
    #[test]
    fn test_flow_scan_lock_defaults_to_disabled() {
        let cfg = FlowConfig::default();
        assert!(
            !cfg.scan_lock_enabled,
            "scan_lock_enabled 缺省必须为 false（单实例部署假设；多实例须显式开启）"
        );
        assert!(
            cfg.scan_lock_ttl_secs > 0,
            "scan_lock_ttl_secs 缺省必须为正数（0 会导致锁立即过期，形同无锁）"
        );
        // 缺键解析同样走缺省（老配置文件不写该键不得改变行为）
        let s: Settings = toml::from_str(
            &std::fs::read_to_string("config/config.toml.example")
                .expect("config/config.toml.example 应存在"),
        )
        .expect("模板应可解析");
        assert!(
            !s.flow.scan_lock_enabled,
            "入库模板不得隐式开启扫描锁（保持单实例默认）"
        );
    }

    /// 能力位缺省必须"全关闭"（**关闭态即安全态**）
    ///
    /// 三层开关的最外层（平台 `config`）是"能开什么"的唯一入口：一旦入库模板里
    /// 预置了能力位，所有租户的默认姿态就被悄悄抬高了。故锁死两点：
    /// ① 结构体缺省 = 空覆盖表 ⇒ 全部走注册表默认（`off`）；
    /// ② 入库模板（`config.toml.example` 及本机存在的 `config.toml.prod`）不得预置任何
    ///    非 `off` 的能力位。
    #[test]
    fn test_features_default_to_all_off() {
        use crate::common::features::{FEATURE_OFF, FeatureSet, KNOWN_FEATURES};

        let cfg = FeaturesConfig::default();
        assert!(
            cfg.0.is_empty(),
            "FeaturesConfig 缺省必须为空表（全走注册表默认 off）"
        );
        let set = FeatureSet::sanitized(cfg.0.clone());
        for def in KNOWN_FEATURES {
            assert_eq!(
                set.mode(def.key),
                FEATURE_OFF,
                "{} 在平台层缺省下必须为 off",
                def.key
            );
        }

        for path in ["config/config.toml.example", "config/config.toml.prod"] {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) if path.ends_with(".example") => panic!("{path} 缺失（入库模板必须存在）"),
                Err(_) => continue,
            };
            let s: Settings =
                toml::from_str(&content).unwrap_or_else(|e| panic!("{path} TOML 解析失败: {e}"));
            let set = FeatureSet::sanitized(s.features.0.clone());
            for def in KNOWN_FEATURES {
                assert_eq!(
                    set.mode(def.key),
                    FEATURE_OFF,
                    "{path} 不得预置能力位 {}（默认必须为 off）",
                    def.key
                );
            }
        }
    }

    /// 验证 Settings Debug 输出不泄漏 config_enc_key
    #[test]
    fn test_settings_debug_redacts_config_enc_key() {
        let settings = Settings {
            pat: PatConfig::default(),
            sso: SsoConfig::default(),
            scim: ScimConfig::default(),
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
            features: FeaturesConfig::default(),
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
