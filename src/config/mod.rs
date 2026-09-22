// axum-backend/src/config/mod.rs

pub mod settings;

pub use settings::{
    DatabaseConfig, JwtConfig, LogConfig, MailConfig, PatConfig, RedisConfig, S3StorageConfig,
    ServerConfig, Settings, UploadConfig,
};
