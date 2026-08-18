// axum-backend/src/config/settings.rs

use std::fmt;
use serde::Deserialize;

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
            .field("permission_deny_by_default", &self.permission_deny_by_default)
            .finish()
    }
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
        }
    }
}

fn default_avatar_dir() -> String {
    "uploads/avatar".to_string()
}

/// 日志文件输出目录默认值（P0-67 未修复项）
fn default_log_file_path() -> String {
    "logs".to_string()
}

fn default_avatar_url_prefix() -> String {
    "/uploads/avatar".to_string()
}

fn default_avatar_allowed_exts() -> Vec<String> {
    vec!["jpg".to_string(), "jpeg".to_string(), "png".to_string(), "gif".to_string()]
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
                        tracing::warn!(
                            "配置文件 {} 不存在，已回退使用 {}",
                            path,
                            cand
                        );
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
    }

    /// 仅从环境变量构建配置（无配置文件场景，如容器通过环境变量注入）
    ///
    /// 必需环境变量：DATABASE_URL、REDIS_URL、JWT_SECRET、SERVER_HOST、SERVER_PORT
    /// 可选环境变量：JWT_EXPIRE_HOURS（默认 24）、CORS_ORIGINS（逗号分隔）、
    ///                MAIL_PASSWORD、CONFIG_ENC_KEY、RUST_LOG（默认 info）
    /// 其余字段使用与结构体一致的内置默认值。
    fn from_env_only() -> anyhow::Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("环境变量 DATABASE_URL 未设置（容器部署需通过 -e/compose 注入）"))?;
        let redis_url = std::env::var("REDIS_URL")
            .map_err(|_| anyhow::anyhow!("环境变量 REDIS_URL 未设置"))?;
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
            permission_deny_by_default: true,
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个通过校验的基准 Settings（jwt.secret 为合法强密钥），供测试复用
    fn make_test_settings() -> Settings {
        Settings {
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
            redis: RedisConfig { url: "redis://localhost:6379".to_string() },
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
            permission_deny_by_default: true,
        }
    }

    /// 验证 Settings Debug 输出不泄漏 config_enc_key
    #[test]
    fn test_settings_debug_redacts_config_enc_key() {
        let settings = Settings {
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
            permission_deny_by_default: true,
        };

        let debug_str = format!("{:?}", settings);

        // 敏感字段不应出现在 Debug 输出中
        assert!(!debug_str.contains("supersecret"), "database URL password leaked");
        assert!(!debug_str.contains("redispass"), "Redis URL password leaked");
        assert!(!debug_str.contains("a-very-long-jwt-secret"), "JWT secret leaked");
        assert!(!debug_str.contains("smtp_password_123"), "Mail password leaked");
        assert!(!debug_str.contains("encryption-key-should-not-leak"), "config_enc_key leaked");

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
        assert!(!debug_str.contains("password123"), "Database URL password leaked in Debug");
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
        assert!(!debug_str.contains("my-super-secret-jwt-key"), "JWT secret leaked in Debug");
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
        assert!(!debug_str.contains("qq_auth_code_secret"), "Mail password leaked in Debug");
        assert!(debug_str.contains("<redacted>"));
    }

    /// 验证 RedisConfig Debug 不泄漏 url
    #[test]
    fn test_redis_config_debug_redacts_url() {
        let redis_config = RedisConfig {
            url: "redis://:mypassword@localhost:6379/0".to_string(),
        };
        let debug_str = format!("{:?}", redis_config);
        assert!(!debug_str.contains("mypassword"), "Redis URL password leaked in Debug");
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
