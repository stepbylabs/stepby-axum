// axum-backend/src/config/mod.rs

pub mod settings;

pub use settings::{
    DatabaseConfig, JwtConfig, LogConfig, MailConfig, RedisConfig, ServerConfig, Settings,
    UploadConfig,
};
