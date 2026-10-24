// stepby-axum/src/db/pool.rs

use crate::config::DatabaseConfig;
use crate::db::db_type::DbType;
use crate::db::limits;
use sea_orm::sqlx::sqlite::SqliteJournalMode;
// G-12：log_slow_statements / log_statements 定义在 sqlx::ConnectOptions trait 上
// （MySQL 原生路径同款引入），SQLite/PostgreSQL 的 map_sqlx_*_opts 闭包内调用需要 trait 在作用域
use sea_orm::sqlx::ConnectOptions as _;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::time::Duration;

/// 慢 SQL 日志设置解析（G-12，三后端统一口径）
///
/// `threshold_ms > 0` → `Some((Warn, 阈值))`；`0` → `None`（显式关闭）。
/// WARN 级：慢查询属"需关注但不致命"，与 sqlx 默认 `LogSettings::slow_statements_level` 一致。
fn slow_sql_logging_settings(threshold_ms: u64) -> Option<(log::LevelFilter, Duration)> {
    (threshold_ms > 0).then(|| (log::LevelFilter::Warn, Duration::from_millis(threshold_ms)))
}

/// 初始化数据库连接池
/// sql_logging 从 LogConfig 传入（避免 DatabaseConfig 与 LogConfig 耦合）
///
/// 安全：连接失败时详情写 tracing 日志，对外返回通用文案，
/// 避免连接串（可能含密码）经 anyhow 传播到 stderr。
///
/// 语句级超时（R9-ERR-004）：防止单条 SQL 无限占用连接，按方言落地
/// （PostgreSQL 连接参数 / MySQL after_connect 会话变量 / SQLite 不适用）。
///
/// 慢 SQL 日志（G-12）：`slow_sql_threshold_ms > 0` 时三后端统一以 WARN 级
/// 记录超阈值语句——**独立于 `sql_logging` 开关**（sqlx `LogSettings` 中
/// `slow_statements_level` 与 `statements_level` 是独立字段）。
pub async fn init_database(
    config: &DatabaseConfig,
    sql_logging: bool,
) -> anyhow::Result<DatabaseConnection> {
    let db_type = DbType::from_url(&config.url).map_err(|e| {
        tracing::error!("数据库 URL 解析失败: {}", e);
        anyhow::anyhow!("{}", e)
    })?;
    tracing::info!("数据库类型: {}", db_type.name());

    // 进程级限制快照（递归 CTE 深度），仓库层经 db::limits 读取；
    // 语句级超时不经本通道——它按方言在下方直接落到连接参数（PG 连接参数 / MySQL after_connect）
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
        // G-12：sea-orm 主流程在 sql_logging=false 时会 disable_statement_logging()
        // （连慢语句一并关闭），其 opts_fn 在主流程之后执行，此处覆盖为最终态：
        // 慢语句日志按配置独立开关，普通语句日志维持 sql_logging 语义。
        let slow = slow_sql_logging_settings(config.slow_sql_threshold_ms);
        opt.map_sqlx_sqlite_opts(move |mut o| {
            match slow {
                Some((level, dur)) => o = o.log_slow_statements(level, dur),
                None => o = o.log_slow_statements(log::LevelFilter::Off, Duration::ZERO),
            }
            o.journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(5))
        });
    } else if db_type == DbType::Mysql {
        // MySQL：max_execution_time 是会话变量而非连接参数，sea-orm 未暴露
        // sqlx after_connect 钩子 → 走原生 MySqlPoolOptions 建池后包装回 sea-orm
        return connect_mysql_with_statement_timeout(
            &opt,
            config.statement_timeout_ms(),
            config.slow_sql_threshold_ms,
        )
        .await;
    } else if db_type == DbType::Postgres {
        apply_postgres_options(&mut opt, config);
    }

    let db = Database::connect(opt).await.map_err(|e| {
        tracing::error!("数据库连接失败: {}", e);
        anyhow::anyhow!("数据库连接失败，请检查 DATABASE_URL 配置与网络")
    })?;
    tracing::info!("数据库连接成功");
    Ok(db)
}

/// PostgreSQL 连接选项（R9-ERR-004 语句级超时 + G-12 慢 SQL 日志）
///
/// - `statement_timeout`：覆盖全部语句（毫秒）；
/// - `idle_in_transaction_session_timeout`：同值，防止"开事务后挂起"的连接
///   被无限占用（statement_timeout 不覆盖事务间空闲）；
/// - 慢 SQL 日志：按 `slow_sql_threshold_ms` 独立接线（同 SQLite 语义）。
///
/// 注意：`map_sqlx_postgres_opts` 的 opts_fn 是**覆盖式存储**（单槽），
/// 语句超时与慢日志必须合并在同一个闭包内，否则后设者顶掉先设者。
///
/// 配置 `statement_timeout_secs = 0` / `slow_sql_threshold_ms = 0` 分别显式关闭对应能力。
/// 毫秒数一律取 `DatabaseConfig::statement_timeout_ms()`（已按上限夹取，唯一换算出口）。
fn apply_postgres_options(opt: &mut ConnectOptions, config: &DatabaseConfig) {
    let timeout_ms = config.statement_timeout_ms();
    let slow = slow_sql_logging_settings(config.slow_sql_threshold_ms);
    let stmt_ms = timeout_ms.to_string();
    let idle_txn_ms = timeout_ms.to_string();
    opt.map_sqlx_postgres_opts(move |mut pg_opts| {
        // PgConnectOptions 的 options/log_slow_statements 均为消耗式 builder（self → Self）
        if timeout_ms > 0 {
            pg_opts = pg_opts.options([
                ("statement_timeout", stmt_ms.as_str()),
                ("idle_in_transaction_session_timeout", idle_txn_ms.as_str()),
            ]);
        }
        match slow {
            Some((level, dur)) => pg_opts = pg_opts.log_slow_statements(level, dur),
            None => pg_opts = pg_opts.log_slow_statements(log::LevelFilter::Off, Duration::ZERO),
        }
        pg_opts
    });
    if timeout_ms > 0 {
        tracing::info!(
            timeout_ms,
            "PostgreSQL 语句级超时已启用（statement_timeout + idle_in_transaction_session_timeout）"
        );
    } else {
        tracing::info!("PostgreSQL 语句级超时已通过配置显式关闭（statement_timeout_secs=0）");
    }
}

/// MySQL 语句级超时（R9-ERR-004）：
/// 连接建立后执行 `SET SESSION max_execution_time = <ms>`（after_connect 钩子）。
///
/// ⚠️ 引擎限制：`max_execution_time` 仅覆盖 SELECT；写语句无服务端语句超时，
/// 路由层 120s 兜底超时仍生效。`timeout_ms = 0` 表示显式关闭（配置里写 `statement_timeout_secs = 0`）。
/// 该毫秒数由 `DatabaseConfig::statement_timeout_ms()` 给出——**上限夹取在这个唯一出口里做**，
/// 本函数不再自行换算：脏值（如 `u64::MAX`）越过的不是启动期，而是每一次 `SET SESSION`。
///
/// G-12：慢 SQL 日志经 `MySqlConnectOptions::log_slow_statements` 接线，
/// 独立于 `sql_logging` 开关（与 SQLite/PostgreSQL 统一口径）。
///
/// 池参数（max/min connections、connect/idle timeout、max_lifetime、
/// test_before_acquire）经 sea-orm `ConnectOptions::sqlx_pool_options()`
/// 原样复用。
async fn connect_mysql_with_statement_timeout(
    opt: &ConnectOptions,
    timeout_ms: u64,
    slow_sql_threshold_ms: u64,
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
    }
    // G-12：慢语句日志独立于语句日志（LogSettings 两字段独立），按配置显式驱动
    match slow_sql_logging_settings(slow_sql_threshold_ms) {
        Some((level, dur)) => sqlx_opts = sqlx_opts.log_slow_statements(level, dur),
        None => sqlx_opts = sqlx_opts.log_slow_statements(log::LevelFilter::Off, Duration::ZERO),
    }

    let pool = if timeout_ms == 0 {
        tracing::info!("语句级超时已通过配置显式关闭（statement_timeout_secs=0）");
        pool_opts.connect_with(sqlx_opts).await
    } else {
        let set_sql = format!("SET SESSION max_execution_time = {}", timeout_ms);
        tracing::info!(
            timeout_ms,
            "MySQL 语句级超时已启用（max_execution_time，仅覆盖 SELECT）"
        );
        pool_opts
            .after_connect(move |conn, _meta| {
                let set_sql = set_sql.clone();
                Box::pin(async move {
                    // SAFETY §5.52（sea-orm 2.0/sqlx 0.9 SqlSafeStr 审计）：set_sql 由
                    // timeout_ms（配置解析的 u64）经 format! 构造，无外部输入参与——
                    // AssertSqlSafe 为官方人工审计豁免通道。
                    sqlx::query(sqlx::AssertSqlSafe(set_sql))
                        .execute(conn)
                        .await?;
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

#[cfg(test)]
mod tests {
    use crate::common::prod_scan::{Scan, prod_file, require_volume};

    /// 判"两条方言路径是否都经唯一出口取毫秒数"的**纯函数**：真实树与合成夹具共用同一份实现
    /// （两份实现必漂，AGENTS 前言 ㉘）。
    ///
    /// 入参应是**已按生产口径归一**的行集（`prod_scan` 负责：注释行置空、`#[cfg(test)]` 之后截断），
    /// 否则本判据的字面量会匹配到自己这一行而恒绿（前言 ㉙ 的"反查判据读整份文件"同一课）。
    fn conversion_sites(lines: &[String]) -> (usize, usize, Vec<usize>) {
        let mut via_getter = 0;
        let mut raw_field = 0;
        let mut local_mul: Vec<usize> = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            via_getter += line.matches("config.statement_timeout_ms()").count();
            raw_field += line.matches("config.statement_timeout_secs").count();
            if line.contains(".saturating_mul(1000)") {
                local_mul.push(i + 1);
            }
        }
        (via_getter, raw_field, local_mul)
    }

    /// 接线锁：秒→毫秒的换算只准住在 `DatabaseConfig::statement_timeout_ms()` 里。
    /// 上限夹取一旦能被绕过，脏配置炸的就是"每一次建连接"，而不是启动期一句拒绝。
    #[test]
    fn statement_timeout_flows_only_through_the_single_getter() {
        let file = prod_file("src/db/pool.rs", &Scan::default());
        require_volume(std::slice::from_ref(&file), 1, 50, "db/pool 的生产视图");
        let (via_getter, raw_field, local_mul) = conversion_sites(&file.lines);
        assert!(
            via_getter >= 2,
            "MySQL after_connect 与 PG 连接参数两处都必须经 statement_timeout_ms() 取毫秒数，实测 {via_getter} 处"
        );
        assert_eq!(
            raw_field, 0,
            "生产码不得再直接读 config.statement_timeout_secs（绕过上限夹取的那条路就是本锁的洞）"
        );
        assert!(
            local_mul.is_empty(),
            "不得再有本地秒→毫秒换算（会漂成两份口径）：行号 {local_mul:?}"
        );
    }

    /// 刀口活性：坏形状必须被抓、合规形状必须不报（只期望抛错等于没测，前言 ⑥）。
    #[test]
    fn wiring_judge_is_falsifiable() {
        let bad: Vec<String> = [
            "    let timeout_ms = timeout_secs.saturating_mul(1000);",
            "        connect_mysql_with_statement_timeout(&opt, config.statement_timeout_secs,",
            "    let timeout_ms = config.statement_timeout_ms();",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let (via_getter, raw_field, local_mul) = conversion_sites(&bad);
        assert_eq!(raw_field, 1, "裸读配置字段必须数到一条");
        assert_eq!(local_mul, vec![1], "本地换算必须数到，且上报的行号对得上");
        assert_eq!(via_getter, 1, "合规出口本身不该被算成违规");

        let good: Vec<String> = [
            "    let timeout_ms = config.statement_timeout_ms();",
            "            config.statement_timeout_ms(),",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let (g, r, m) = conversion_sites(&good);
        assert_eq!(
            (g, r, m.len()),
            (2, 0, 0),
            "两处都经唯一出口 ⇒ 不得报任何东西"
        );
    }
}
