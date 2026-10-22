// stepby-axum/src/config/mod.rs

/// 未知配置条目识别（启动 WARN 的判据本体，见模块文档头）
pub mod config_paths;
/// 生成物：结构体派生的已知配置路径表（勿手工编辑，
/// `python scripts/config_parity_scan.py --emit-schema`）
pub mod config_schema;
pub mod settings;

pub use settings::{
    DatabaseConfig, JwtConfig, LogConfig, MailConfig, PatConfig, RedisConfig, ResolvedWebauthn,
    S3StorageConfig, ServerConfig, Settings, SsoConfig, TenantColumnMode, TenantConfig,
    TenantFilterMode, UiConfig, UploadConfig, WebauthnConfig,
};
