//! migration 独立二进制入口（批次六十一补齐——`cargo run -p migration` 契约落地）。
//!
//! 背景：docs/checklist.md / docs/testing-guide.md / docs/deployment.md 多处引用
//! `cargo run -p migration` 执行数据库迁移，但本 crate 此前从未实现 bin target
//! （ed93647 目录重组后仅有 lib），命令实际不可用（CI migration-matrix 三库全挂
//! 实证：`a bin target must be available`）。本入口补齐该契约：读 DATABASE_URL
//! → Migrator::up 全量前向迁移 → 输出「迁移完成」。
//!
//! 用法：
//! - 前向：`DATABASE_URL=<连接串> cargo run -p migration [步数]`
//! - 回滚：`DATABASE_URL=<连接串> cargo run -p migration --down [步数]`（批七十六 R-10 新增）
//!
//! 多库支持由 sea-orm-migration 特性矩阵（mysql/postgres/sqlite）承载，与主服务一致。
//!
//! 可选的 `[步数]`（≥1）只前推/回退 N 条迁移，并在结束时打印剩余待执行数：
//! 存量库（"兜底先建过对象、版本号却没登记"）逐条试跑时，全量 `up` 只会报第一个失败，
//! 定位一条要跑一整趟；有限步数让"哪一条不幂等"变成可机械二判的证据（本轮实测就是靠它
//! 把 chain_hash / sys_data_rule / prompt_tokens 这类撞库点一条条钉出来的）。
//!
//! ## 为什么补 `--down`（批七十六 R-10）
//!
//! 本仓 121 条迁移每条都写了 `down()`，但**没有任何一条被执行过**：既没有 CLI 回滚入口，
//! 也没有测试调用 `Migrator::down`（`grep -rn "Migrator::down" src/ migration/ tests/`
//! 实测零命中）。也就是说"可回滚"一直只是注释里的承诺——`down()` 里写错一个表名、
//! 漏一个方言分支，只有在真正出事的那天才第一次被发现。`--down` 把这条路变成可实测的：
//! 全新库 `up 全量 → down 全量 → 再 up 全量` 三趟跑通，才算"回滚契约成立"。

use migration::{Migrator, MigratorTrait};
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{Database, DatabaseConnection};

async fn pending(db: &DatabaseConnection) -> usize {
    Migrator::get_pending_migrations(db)
        .await
        .map(|m| m.len())
        .unwrap_or(usize::MAX)
}

async fn applied(db: &DatabaseConnection) -> usize {
    Migrator::get_applied_migrations(db)
        .await
        .map(|m| m.len())
        .unwrap_or(usize::MAX)
}

/// 最近一条已应用迁移的名字（回滚失败时用来指出"卡在谁身上"）。
async fn newest_applied(db: &DatabaseConnection) -> String {
    Migrator::get_applied_migrations(db)
        .await
        .map(|v| v.last().map(|m| m.name().to_string()).unwrap_or_default())
        .unwrap_or_else(|e| format!("<读取已应用列表失败: {e}>"))
}

/// 下一条待执行迁移的名字（前滚失败时用来指出"卡在谁身上"）。
async fn next_pending(db: &DatabaseConnection) -> String {
    Migrator::get_pending_migrations(db)
        .await
        .map(|v| v.first().map(|m| m.name().to_string()).unwrap_or_default())
        .unwrap_or_else(|e| format!("<读取待执行列表失败: {e}>"))
}

/// 解析 `[步数]`：缺省 = 全量；`0`/非整数 = 退出码 2（不 panic、也不静默当成"全量"）。
fn parse_steps(arg: &str, usage: &str) -> Option<u32> {
    match arg.parse::<u32>() {
        Ok(0) | Err(_) => {
            eprintln!("参数 {arg:?} 不是 ≥1 的整数步数；用法：{usage}");
            std::process::exit(2);
        }
        Ok(n) => Some(n),
    }
}

const USAGE: &str = "用法：DATABASE_URL=<连接串> cargo run -p migration [--down] [步数]";

#[tokio::main]
async fn main() -> Result<(), DbErr> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        // 与主服务一致的零配置回退：SQLite 单文件（含 mode=rwc 允许全新库创建）
        "sqlite://./data/stepby.db?mode=rwc".to_string()
    });

    // argv[1] 决定方向（`--down` 为回滚档，其余位置参数是步数）；不认识的 flag 一律拒绝，
    // 免得把"拼错了的回滚命令"当成前向迁移执行——那会把一次演练变成一次真实升级。
    let mut down = false;
    let mut steps: Option<u32> = None;
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut idx = 0usize;
    if let Some(first) = argv.first() {
        if first == "--down" {
            down = true;
            idx = 1;
        } else if first.starts_with('-') {
            eprintln!("未知参数 {first:?}；{USAGE}");
            std::process::exit(2);
        }
    }
    if let Some(arg) = argv.get(idx) {
        steps = parse_steps(arg, USAGE);
    }
    if argv.len() > idx + 1 {
        eprintln!("多余参数 {:?}；{USAGE}", &argv[idx + 1..]);
        std::process::exit(2);
    }

    let db = Database::connect(&database_url)
        .await
        .expect("数据库连接失败，请检查 DATABASE_URL 配置与网络");

    if down {
        // 逐条回滚而不是"一次 down 全量"：全量失败时 sea-orm 只给一个不带迁移名的错误，
        // 回滚现场拿到那种报错等于什么都没拿到（批七十六 R-10 在 MySQL 实测：第 70 条起
        // 中断，日志只有"回滚执行失败"）。逐条走还能报出"卡在谁身上 + 已退几条"。
        let mut done = 0u32;
        loop {
            // 步数上限（migration crate 是 edition 2021，这里用不了 let-chain 语法）
            let reached_limit = match steps {
                Some(n) => done >= n,
                None => false,
            };
            if reached_limit {
                break;
            }
            let left = applied(&db).await;
            if left == 0 {
                break;
            }
            let head = newest_applied(&db).await;
            if let Err(e) = Migrator::down(&db, Some(1)).await {
                eprintln!(
                    "[migration] 回滚失败：卡在 {head}（本次已回滚 {done} 条，库内仍有 {left} 条已应用）\
                     \n错误: {e}\n{USAGE}"
                );
                return Err(e);
            }
            done += 1;
        }
        let after = applied(&db).await;
        match steps {
            Some(n) => println!("回滚完成（本次限 {n} 步，实退 {done} 条）：已应用余 {after}"),
            None => println!("回滚完成（全量，实退 {done} 条）：已应用余 {after}"),
        }
        return Ok(());
    }

    let mut done_up = 0u32;
    loop {
        let reached_limit = match steps {
            Some(n) => done_up >= n,
            None => false,
        };
        let left = pending(&db).await;
        if reached_limit || left == 0 {
            break;
        }
        let head = next_pending(&db).await;
        if let Err(e) = Migrator::up(&db, Some(1)).await {
            // 与 down 档同口径：报错必须带迁移名。只说"迁移执行失败"等于让运维在最忙的时刻
            // 再去猜是哪一条（本仓第一次三库回滚演练实测就是靠这句定位到 PG 的第 64 条）。
            eprintln!(
                "[migration] 迁移失败：卡在 {head}（本次已前滚 {done_up} 条，仍有 {left} 条待执行）\
                 \n错误: {e}\n{USAGE}"
            );
            return Err(e);
        }
        done_up += 1;
    }
    let after = pending(&db).await;

    match steps {
        Some(n) => println!("迁移完成（本次限 {n} 步，实进 {done_up} 条）：待执行 {after}"),
        None => println!("迁移完成（实进 {done_up} 条）：待执行 {after}"),
    }
    Ok(())
}
