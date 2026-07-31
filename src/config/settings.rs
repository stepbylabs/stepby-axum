// axum-backend/src/config/settings.rs

use serde::Deserialize;

/// 全局配置根结构体
#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

fn default_db_max_lifetime_secs() -> u64 {
    1800
}

fn default_db_acquire_timeout_secs() -> u64 {
    10
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expire_hours: i64,
    pub issuer: String,
    /// JWT 受众（aud claim），用于防止 token 跨服务复用（SEC-001）
    /// 默认 "yebot"，生产环境应通过配置显式指定
    #[serde(default = "default_jwt_audience")]
    pub audience: String,
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
    5 * 1024 * 1024
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
    10 * 1024 * 1024
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
#[derive(Debug, Clone, Deserialize)]
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
            self.jwt.expire_hours = hours;
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
        if self.jwt.secret.contains("CHANGE_ME") {
            anyhow::bail!(
                "jwt.secret 不能使用默认占位符，请通过环境变量 JWT_SECRET 设置真实密钥（至少 32 字符）"
            );
        }
        if self.database.url.contains("CHANGE_ME") {
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
        Ok(())
    }
}
