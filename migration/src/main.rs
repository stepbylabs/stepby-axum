//! migration 独立二进制入口（批次六十一补齐——`cargo run -p migration` 契约落地）。
//!
//! 背景：docs/checklist.md / docs/testing-guide.md / docs/deployment.md 多处引用
//! `cargo run -p migration` 执行数据库迁移，但本 crate 此前从未实现 bin target
//! （ed93647 目录重组后仅有 lib），命令实际不可用（CI migration-matrix 三库全挂
//! 实证：`a bin target must be available`）。本入口补齐该契约：读 DATABASE_URL
//! → Migrator::up 全量前向迁移 → 输出「迁移完成」。
//!
//! 用法：`DATABASE_URL=<连接串> cargo run -p migration`
//! 多库支持由 sea-orm-migration 特性矩阵（mysql/postgres/sqlite）承载，与主服务一致。

use migration::{Migrator, MigratorTrait};
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::Database;

#[tokio::main]
async fn main() -> Result<(), DbErr> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        // 与主服务一致的零配置回退：SQLite 单文件（含 mode=rwc 允许全新库创建）
        "sqlite://./data/stepby.db?mode=rwc".to_string()
    });

    let db = Database::connect(&database_url)
        .await
        .expect("数据库连接失败，请检查 DATABASE_URL 配置与网络");

    Migrator::up(&db, None).await.expect("迁移执行失败");

    println!("迁移完成");
    Ok(())
}
