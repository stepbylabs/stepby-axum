// backend-axum/src/db/pool.rs

use crate::config::DatabaseConfig;
use crate::db::db_type::DbType;
use crate::db::limits;
use sea_orm::sqlx::sqlite::SqliteJournalMode;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::time::Duration;

/// 初始化数据库连接池
/// sql_logging 从 LogConfig 传入（避免 DatabaseConfig 与 LogConfig 耦合）
///
/// 安全：连接失败时详情写 tracing 日志，对外返回通用文案，
/// 避免连接串（可能含密码）经 anyhow 传播到 stderr。
///
/// 语句级超时（R9-ERR-004）：防止单条 SQL 无限占用连接，按方言落地
/// （PostgreSQL 连接参数 / MySQL after_connect 会话变量 / SQLite 不适用）。
pub async fn init_database(
    config: &DatabaseConfig,
    sql_logging: bool,
) -> anyhow::Result<DatabaseConnection> {
    let db_type = DbType::from_url(&config.url).map_err(|e| {
        tracing::error!("数据库 URL 解析失败: {}", e);
        anyhow::anyhow!("{}", e)
    })?;
    tracing::info!("数据库类型: {}", db_type.name());

    // 进程级限制快照（语句超时 / 递归 CTE 深度），仓库层经 db::limits 读取
    limits::init(config);

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
    } else if db_type == DbType::Mysql {
        // MySQL：max_execution_time 是会话变量而非连接参数，sea-orm 未暴露
        // sqlx after_connect 钩子 → 走原生 MySqlPoolOptions 建池后包装回 sea-orm
        return connect_mysql_with_statement_timeout(&opt, config.statement_timeout_secs).await;
    } else if db_type == DbType::Postgres && config.statement_timeout_secs > 0 {
        apply_postgres_statement_timeout(&mut opt, config.statement_timeout_secs);
    }

    let db = Database::connect(opt).await.map_err(|e| {
        tracing::error!("数据库连接失败: {}", e);
        anyhow::anyhow!("数据库连接失败，请检查 DATABASE_URL 配置与网络")
    })?;
    tracing::info!("数据库连接成功");
    Ok(db)
}

/// PostgreSQL 语句级超时（R9-ERR-004）：
/// - `statement_timeout`：覆盖全部语句（毫秒）；
/// - `idle_in_transaction_session_timeout`：同值，防止"开事务后挂起"的连接
///   被无限占用（statement_timeout 不覆盖事务间空闲）。
///
/// 配置 `statement_timeout_secs = 0` 表示显式关闭（不进入本函数）。
fn apply_postgres_statement_timeout(opt: &mut ConnectOptions, timeout_secs: u64) {
    let timeout_ms = timeout_secs.saturating_mul(1000);
    let stmt_ms = timeout_ms.to_string();
    let idle_txn_ms = timeout_ms.to_string();
    opt.map_sqlx_postgres_opts(move |pg_opts| {
        pg_opts.options([
            ("statement_timeout", stmt_ms.as_str()),
            ("idle_in_transaction_session_timeout", idle_txn_ms.as_str()),
        ])
    });
    tracing::info!(
        timeout_secs,
        "PostgreSQL 语句级超时已启用（statement_timeout + idle_in_transaction_session_timeout）"
    );
}

/// MySQL 语句级超时（R9-ERR-004）：
/// 连接建立后执行 `SET SESSION max_execution_time = <ms>`（after_connect 钩子）。
///
/// ⚠️ 引擎限制：`max_execution_time` 仅覆盖 SELECT；写语句无服务端语句超时，
/// 路由层 120s 兜底超时仍生效。配置 `statement_timeout_secs = 0` 表示显式关闭。
///
/// 池参数（max/min connections、connect/idle timeout、max_lifetime、
/// test_before_acquire）经 sea-orm `ConnectOptions::sqlx_pool_options()`
/// 原样复用；SQL 日志行为（log/disable statement logging、慢语句日志）
/// 与 sea-orm `SqlxMySqlConnector::connect` 的接线保持一致。
async fn connect_mysql_with_statement_timeout(
    opt: &ConnectOptions,
    timeout_secs: u64,
) -> anyhow::Result<DatabaseConnection> {
    use sea_orm::SqlxMySqlConnector;
    use sea_orm::sqlx::ConnectOptions as _;
    use sea_orm::sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};

    let pool_opts: MySqlPoolOptions = opt.clone().sqlx_pool_options();
    let mut sqlx_opts = opt
        .get_url()
        .parse::<MySqlConnectOptions>()
        .map_err(|e| anyhow::anyhow!("MySQL 连接串解析失败: {}", e))?;
    if !opt.get_sqlx_logging() {
        sqlx_opts = sqlx_opts.disable_statement_logging();
    } else {
        sqlx_opts = sqlx_opts.log_statements(opt.get_sqlx_logging_level());
        let (slow_level, slow_threshold) = opt.get_sqlx_slow_statements_logging_settings();
        if slow_level != log::LevelFilter::Off {
            sqlx_opts = sqlx_opts.log_slow_statements(slow_level, slow_threshold);
        }
    }

    let pool = if timeout_secs == 0 {
        tracing::info!("语句级超时已通过配置显式关闭（statement_timeout_secs=0）");
        pool_opts.connect_with(sqlx_opts).await
    } else {
        let timeout_ms = timeout_secs.saturating_mul(1000);
        let set_sql = format!("SET SESSION max_execution_time = {}", timeout_ms);
        tracing::info!(
            timeout_secs,
            "MySQL 语句级超时已启用（max_execution_time，仅覆盖 SELECT）"
        );
        pool_opts
            .after_connect(move |conn, _meta| {
                let set_sql = set_sql.clone();
                Box::pin(async move {
                    sea_orm::sqlx::query(&set_sql).execute(conn).await?;
                    Ok(())
                })
            })
            .connect_with(sqlx_opts)
            .await
    }
    .map_err(|e| {
        tracing::error!("数据库连接失败: {}", e);
        anyhow::anyhow!("数据库连接失败，请检查 DATABASE_URL 配置与网络")
    })?;

    tracing::info!("数据库连接成功");
    Ok(SqlxMySqlConnector::from_sqlx_mysql_pool(pool))
}
