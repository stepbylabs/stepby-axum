//! Repository 层单元测试共享工具（**也是全仓测试临时库的文件卫生单一事实源**）。
//!
//! 提供创建带完整迁移 schema 的隔离 SQLite 数据库，供各 repo 的 keyset/分页测试使用。
//! 使用临时文件（而非 `sqlite:-memory:`），避免 SQLite 内存库多连接隔离导致的
//! "no such table"。
//!
//! ⚠ 本文件原先写着"每次调用路径唯一……**用完即随临时目录清理**"，两句都不成立
//! （b88 实测：`stepby_repo_test_*` 遗留 **10,499 个文件 / 11.15 GB**，`stepby_it_*` 遗留
//! 66,515 个 / 66.84 GB，而**全仓没有任何删除通道**）。"随临时目录清理"是一种很常见的
//! 错觉——Windows 不会自己清 `%TEMP%` 里应用创建的文件。现在回收通道真的存在：
//! [`sweep_stale_harness_dbs`]；隔离性也真的由磁盘作证：[`claim_harness_db_path`]。
//! 事故现场与四条卫生锁见 `src/integration_tests/it_hygiene.rs` 与台账 b88 §13。

use sea_orm::{Database, DatabaseConnection, DbErr};
use sea_orm_migration::MigratorTrait;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// 集成测试（`integration_tests`）自己的临时库前缀。
pub const IT_DB_PREFIX: &str = "stepby_it_";
/// 本文件 `migrated_db()` 的临时库前缀。
pub const REPO_DB_PREFIX: &str = "stepby_repo_test_";

/// **本仓测试自己创建**的临时 SQLite 家族。回收器只认这里列出的前缀——
/// 作用面必须由"谁产生的"界定，不能由"看起来像垃圾"界定。
pub const HARNESS_DB_FAMILIES: &[&str] = &[IT_DB_PREFIX, REPO_DB_PREFIX];

/// SQLite 为一个库文件产生的三种名字（主文件 + WAL + SHM）。
///
/// 后缀白名单**故意窄**而不是黑名单：`IT_DB_PREFIX` 下面还住着
/// `stepby_it_redis_db_{n}.lock`，那是 Redis DB 槽位的跨进程**独占仲裁文件本身**、
/// 按设计跨轮复用，回收它等于拆掉并行测试的仲裁通道（比丢几个库严重得多）。
/// 取白名单的另一个理由是失败方向：SQLite 将来若新增边车名，白名单只会"漏删"（还能再收），
/// 黑名单会"误删"（正在用的文件被拆）。
pub const HARNESS_DB_SUFFIXES: &[&str] = &[".db", ".db-wal", ".db-shm"];

/// 判定"这是历史遗留"的年龄阈值。一轮全量 `cargo test --lib` 实测最长 360.75s（b88），
/// 两小时是**数量级以上**的余量 ⇒ 被回收的不可能是仍在用的库。
pub const HARNESS_DB_STALE_SECS: u64 = 2 * 60 * 60;

/// 进程内自增序号：确保每次 `migrated_db()` 拿到唯一临时库路径。
/// 仅靠 `pid + nanos` 在 Windows 上不够——`SystemTime` 粒度约 100ns，
/// 并行测试可能取到相同纳秒值 → 同一文件 → 两个 `Migrator::up` 并发抢插
/// 同一 `seaql_migrations.version` 触发 UNIQUE 冲突。原子自增保证严格唯一。
///
/// ⚠ 但"同进程内唯一"**不**等于"跨轮唯一"：pid 会被回收，而 `?mode=rwc` 存在即原样打开。
/// 真正的唯一性由 [`claim_harness_db_path`] 向磁盘认领来保证。
static DB_SEQ: AtomicU64 = AtomicU64::new(0);

/// 向磁盘**认领**一个隔离库路径：文件必须是"我刚创建的"。
///
/// 返回 `None` 表示该序号上已有文件（上一轮遗留 / 别的进程正在用），调用方换下一个序号。
/// 抽成函数而不是把 `open` 写在调用点的循环里：同进程内计数器单调递增，调用点永远
/// 拿不到一个"已存在"的序号 ⇒ "已存在必须跳过"这一支结构上打不中，测不到 b88 那个真缺陷。
/// 有了这个签名，自检可以在**私有目录**里把同一个序号用两次。
///
/// 其它 I/O 错误一律 panic（不是"跳过"）：临时目录不可写时不能假装拿到了隔离库。
pub fn claim_harness_db_path(family: &str, seq: u64, dir: &std::path::Path) -> Option<PathBuf> {
    let p = dir.join(format!("{family}{}_{seq}.db", std::process::id()));
    match std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&p)
    {
        // 认领后立刻关闭句柄：调用方（sea-orm / 集成 harness）按 URL 自己打开。
        Ok(f) => {
            drop(f);
            Some(p)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => None,
        Err(err) => panic!("认领隔离测试库失败（{}）：{err}", p.display()),
    }
}

/// 在共享临时目录里按"家族 + 进程内计数"认领，直到成功（最多 10000 次）。
///
/// `counter` 由调用方持有（各家族各自一个 `AtomicU64`），返回路径的序号总是单调递增的。
/// 10000 次全撞名 ⇒ panic：**带着可疑隔离性跑完 1600 条比少跑几条危险得多**，
/// 且这一形状本身说明临时目录状态异常。
pub fn claim_harness_db_path_loop(family: &str, counter: &AtomicU64) -> PathBuf {
    let dir = std::env::temp_dir();
    for _ in 0..10_000_u32 {
        let seq = counter.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = claim_harness_db_path(family, seq, &dir) {
            return p;
        }
    }
    panic!(
        "隔离测试库连续 10000 个序号都撞名 ⇒ 临时目录状态异常，\
         不得带着可疑隔离性继续跑测试（家族 {family}）"
    )
}

/// 只依据"名字 + 距今秒数"判断该不该回收——抽成纯函数是为了能被双向自检
/// （判据读不到事实就等于没判，见 AGENTS 测试门禁全景 前言 ⑥）。
///
/// 时刻取不到（`None`）一律**不回收**：宁可留一个文件，也不能把"定不了位"读成"够旧了"
/// （与 `NaN > 容差` 恒 false、`Number(null) === 0` 同族，前言 ⑧）。
pub fn is_stale_harness_file(file_name: &str, age_secs: Option<u64>) -> bool {
    match age_secs {
        Some(secs) => {
            secs > HARNESS_DB_STALE_SECS
                && HARNESS_DB_FAMILIES.iter().any(|f| file_name.starts_with(f))
                && HARNESS_DB_SUFFIXES.iter().any(|s| file_name.ends_with(s))
        }
        None => false,
    }
}

/// 回收历史遗留的隔离库文件（两个家族一起）。
///
/// 实测泄漏量级（b88，回收前）：`stepby_it_` **66,515 个 / 66.84 GB**、
/// `stepby_repo_test_` **10,499 个 / 11.15 GB**；第一次回收净删 65,201 个文件。
/// 磁盘压力不是抽象风险：同一台机器上 `libtest` 178.5s → 360.75s、
/// `action-inventory` 最慢一页 3.4s → 12.2s（都由轮内自证）。
///
/// 在集成 harness 的第一个用例里经 `Once` 执行一次；失败只 WARN 不影响用例
/// （回收是卫生，不是判据——把它变成硬失败会让"临时目录不可枚举"这类环境问题伪装成产品缺陷）。
/// 本轮自己创建的库**不删**（要等满阈值后由下一轮回收）：删掉失败现场等于把
/// "这一轮留下了什么"变成不可复盘，登记为台账 b88 N-I 的取舍。
pub fn sweep_stale_harness_dbs() {
    let dir = std::env::temp_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!(
                "跳过测试临时库回收：临时目录不可枚举 {}（{err}）",
                dir.display()
            );
            return;
        }
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0_u64;
    let mut failures = 0_u64;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let age = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| now.duration_since(t).ok())
            .map(|d| d.as_secs());
        if !is_stale_harness_file(&name, age) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            // 仍被别的进程占用（并行跑测试，纪律上禁止但不该假设）⇒ 留着，下一轮再收
            Err(_) => failures += 1,
        }
    }
    tracing::info!(
        "测试临时库回收：删除 {} 个超过 {} 分钟的遗留文件，{} 个因占用未删（目录 {}，家族 {:?}）",
        removed,
        HARNESS_DB_STALE_SECS / 60,
        failures,
        dir.display(),
        HARNESS_DB_FAMILIES
    );
}

/// 创建一个跑完全部迁移（建表）的临时 SQLite，返回连接。
///
/// 路径由 [`claim_harness_db_path_loop`] 向磁盘认领（0 字节新文件），再交给
/// `sqlite://…?mode=rwc`——`rwc` 在这里只承担"文件已存在但我刚建的是空库"的正常语义，
/// 不再有"打开上一轮同名旧库"这一支。
pub async fn migrated_db() -> Result<DatabaseConnection, DbErr> {
    let p = claim_harness_db_path_loop(REPO_DB_PREFIX, &DB_SEQ);
    let url = format!("sqlite://{}?mode=rwc", p.to_string_lossy());
    let db = Database::connect(&url).await?;
    migration::Migrator::up(&db, None).await?;
    Ok(db)
}
