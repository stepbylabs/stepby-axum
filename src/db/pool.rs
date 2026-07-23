// axum-backend/src/db/pool.rs

use std::time::Duration;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use crate::config::DatabaseConfig;
use crate::db::db_type::DbType;

/// 初始化数据库连接池
/// sql_logging 从 LogConfig 传入（避免 DatabaseConfig 与 LogConfig 耦合）
///
/// 安全：连接失败时详情写 tracing 日志，对外返回通用文案，
/// 避免连接串（可能含密码）经 anyhow 传播到 stderr。
pub async fn init_database(config: &DatabaseConfig, sql_logging: bool) -> anyhow::Result<DatabaseConnection> {
    let db_type = DbType::from_url(&config.url);
    tracing::info!("数据库类型: {}", db_type.name());

    let mut opt = ConnectOptions::new(&config.url);
    opt.max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .connect_timeout(Duration::from_secs(config.connect_timeout))
        .idle_timeout(Duration::from_secs(config.idle_timeout))
        // 连接最大生命周期（配置驱动，默认 1800s），避免长连接因 MySQL wait_timeout / 网络中间件探活失效
        .max_lifetime(Duration::from_secs(config.max_lifetime_secs))
        // 从池中获取连接的等待超时（配置驱动，默认 10s），超时返回错误而非无限阻塞
        .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
        .sqlx_logging(sql_logging);

    let db = Database::connect(opt).await.map_err(|e| {
        tracing::error!("数据库连接失败: {}", e);
        anyhow::anyhow!("数据库连接失败，请检查 DATABASE_URL 配置与网络")
    })?;
    tracing::info!("数据库连接成功");
    Ok(db)
}
