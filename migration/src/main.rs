// axum-backend/migration/src/main.rs
//! migration 命令行入口
//! 从 DATABASE_URL 环境变量读取连接串，执行迁移

use migration::Migrator;
use sea_orm_migration::sea_orm::Database;
use sea_orm_migration::MigratorTrait;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 加载 .env 文件（从当前目录或父目录查找）
    let _ = dotenvy::dotenv();

    // 从环境变量读取连接串（运行前请设置 DATABASE_URL）
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://./data/stepby.db?mode=rwc".to_string());

    println!("正在连接数据库: {}", database_url);
    let connection = Database::connect(&database_url).await?;

    println!("开始执行数据库迁移...");
    Migrator::up(&connection, None).await?;

    println!("迁移完成");
    Ok(())
}
