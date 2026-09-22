//! Repository 层单元测试共享工具。
//!
//! 提供创建带完整迁移 schema 的隔离 SQLite 数据库，供各 repo 的 keyset/分页测试使用。
//! 使用临时文件（而非 `sqlite:memory:`），避免 SQLite 内存库多连接隔离导致的
//! "no such table"；每次调用路径唯一，互不干扰，用完即随临时目录清理。

use sea_orm::{Database, DatabaseConnection, DbErr};
use sea_orm_migration::MigratorTrait;
use std::sync::atomic::{AtomicU64, Ordering};

/// 进程内自增序号：确保每次 `migrated_db()` 拿到唯一临时库路径。
/// 仅靠 `pid + nanos` 在 Windows 上不够——`SystemTime` 粒度约 100ns，
/// 并行测试可能取到相同纳秒值 → 同一文件 → 两个 `Migrator::up` 并发抢插
/// 同一 `seaql_migrations.version` 触发 UNIQUE 冲突。原子自增保证严格唯一。
static DB_SEQ: AtomicU64 = AtomicU64::new(0);

/// 创建一个跑完全部迁移（建表）的临时 SQLite，返回连接。
pub async fn migrated_db() -> Result<DatabaseConnection, DbErr> {
    let pid = std::process::id();
    let seq = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let p = std::env::temp_dir().join(format!("yebot_repo_test_{}_{}_{}.db", pid, seq, nanos));
    let url = format!("sqlite://{}?mode=rwc", p.to_string_lossy());
    let db = Database::connect(&url).await?;
    migration::Migrator::up(&db, None).await?;
    Ok(db)
}
