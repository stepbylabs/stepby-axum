// axum-backend/src/db/pool.rs

use crate::config::DatabaseConfig;
use crate::db::db_type::DbType;
use sea_orm::sqlx::sqlite::SqliteJournalMode;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::time::Duration;

/// 初始化数据库连接池
/// sql_logging 从 LogConfig 传入（避免 DatabaseConfig 与 LogConfig 耦合）
///
/// 安全：连接失败时详情写 tracing 日志，对外返回通用文案，
/// 避免连接串（可能含密码）经 anyhow 传播到 stderr。
pub async fn init_database(
    config: &DatabaseConfig,
    sql_logging: bool,
) -> anyhow::Result<DatabaseConnection> {
    let db_type = DbType::from_url(&config.url).map_err(|e| {
        tracing::error!("数据库 URL 解析失败: {}", e);
        anyhow::anyhow!("{}", e)
    })?;
    tracing::info!("数据库类型: {}", db_type.name());

    // SQLite 并发优化（关键）：
    // 1. max_connections=1 — SQLite 本质是单写者，池 >1 连接会造成 WAL 模式下
    //    deferred BEGIN 事务读后写时与另一连接提交冲突，产生 SQLITE_BUSY_SNAPSHOT (517)。
    //    单连接池 + WAL 模式：读不阻塞写，写序列化，无 517 风险。
    // 2. WAL 模式 — 允许单连接内读并发，reader 永不阻塞 writer。
    // 3. busy_timeout=5s — 外部进程或罕见锁争用时安全兜底。
    let max_conn = if db_type == DbType::Sqlite {
        1
    } else {
        config.max_connections
    };

    let mut opt = ConnectOptions::new(&config.url);
    opt.max_connections(max_conn)
        .min_connections(config.min_connections.min(max_conn))
        .connect_timeout(Duration::from_secs(config.connect_timeout))
        .idle_timeout(Duration::from_secs(config.idle_timeout))
        // 连接最大生命周期（配置驱动，默认 1800s），避免长连接因 MySQL wait_timeout / 网络中间件探活失效
        .max_lifetime(Duration::from_secs(config.max_lifetime_secs))
        // 从池中获取连接的等待超时（配置驱动，默认 10s），超时返回错误而非无限阻塞
        .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
        .sqlx_logging(sql_logging);

    if db_type == DbType::Sqlite {
        opt.map_sqlx_sqlite_opts(|opts| {
            opts.journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(5))
        });
    }

    let db = Database::connect(opt).await.map_err(|e| {
        tracing::error!("数据库连接失败: {}", e);
        anyhow::anyhow!("数据库连接失败，请检查 DATABASE_URL 配置与网络")
    })?;
    tracing::info!("数据库连接成功");
    Ok(db)
}
