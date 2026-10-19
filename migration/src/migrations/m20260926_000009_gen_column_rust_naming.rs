// stepby-axum/migration/src/migrations/m20260926_000009_gen_column_rust_naming.rs
//! 台账（第八批）：代码生成列元数据的 **Java 遗留命名 → Rust 命名**。
//!
//! ## 背景
//!
//! `gen_table_column` 的两列 `java_type` / `java_field` 是早期 Java 版本的遗留命名，
//! 但本仓是 **Rust 后端**，且这两列存的**本来就是 Rust 语义**：
//! - `java_type`  实际存 `i64` / `String` / `chrono::NaiveDateTime`（Rust 类型）；
//! - `java_field` 实际存 `user_id` 等 snake_case（Rust 字段名）。
//!
//! 实体注释（`entity/gen_table_column.rs:25/27`）早已写"Rust 类型 / Rust 字段名"，
//! 仅**列名**未同步 ⇒ 命名与语义长期不一致。本迁移把两列重命名为
//! `rust_type` / `rust_field`。
//!
//! ## 口径
//!
//! - **迁移只进不退**：`m20250716_000001`（建表，含旧列名）已发布并被执行过，
//!   故**不改旧迁移**，新增本迁移做 `RENAME COLUMN`（新库 = 建表 + 重命名，结果一致）。
//! - **双写**：`initialize::ensure_gen_column_rust_naming` 同步补同款幂等兜底，
//!   覆盖"存量库直接启动服务（按架构约定不跑迁移）"路径，见 `initialize/mod.rs`。
//! - 幂等：仅当**旧列存在且新列不存在**时才重命名（`has_column` 守卫），
//!   故重复执行/新库执行均安全。
//! - `RENAME COLUMN` 三方言均支持（SQLite ≥ 3.25 / PostgreSQL / MySQL 8.0+）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000009_gen_column_rust_naming"
    }
}

/// 重命名映射：`(旧列名, 新列名)`
const RENAMES: [(&str, &str); 2] = [("java_type", "rust_type"), ("java_field", "rust_field")];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_table("gen_table_column").await? {
            return Ok(());
        }
        for (old, new) in RENAMES {
            // 幂等：旧列不存在（已重命名过 / 新库已是新列名）或新列已存在 ⇒ 跳过
            if !manager.has_column("gen_table_column", old).await?
                || manager.has_column("gen_table_column", new).await?
            {
                continue;
            }
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    "ALTER TABLE gen_table_column RENAME COLUMN {old} TO {new}"
                ))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_table("gen_table_column").await? {
            return Ok(());
        }
        for (old, new) in RENAMES {
            if !manager.has_column("gen_table_column", new).await?
                || manager.has_column("gen_table_column", old).await?
            {
                continue;
            }
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    "ALTER TABLE gen_table_column RENAME COLUMN {new} TO {old}"
                ))
                .await?;
        }
        Ok(())
    }
}
