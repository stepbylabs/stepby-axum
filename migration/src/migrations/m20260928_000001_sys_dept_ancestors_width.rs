// stepby-axum/migration/src/migrations/m20260928_000001_sys_dept_ancestors_width.rs
//! R5-DB-26：`sys_dept.ancestors` 宽度修正（VARCHAR(50) → VARCHAR(500)）。
//!
//! 缺陷：`ancestors` 存储以逗号拼接的祖先 ID 链（形如 `0,100,101,102,...`，
//! 见 `src/service/sys_dept_service.rs` 的维护逻辑与 data_scope 过滤）。初始迁移
//! 建表时定为 `VARCHAR(50)`：部门树较深或 ID 较大时该 CSV 必然超过 50 字符——
//! **SQLite 不强制 VARCHAR 长度**（静默放行，故单测测不出来），但
//! **PostgreSQL / MySQL 会强制**，导致新增/移动部门时插入失败或数据截断。
//!
//! 分工：全新库由 init 迁移直接建为 `VARCHAR(500)`（见 `m20250711_000001_init.rs`）；
//! 本迁移负责**存量库**（存量库启动不自动跑 `Migrator::up`，由迁移命令行补齐）。
//!
//! 与既有迁移的关系：`m20260719_000001_adjust_field_length` 已对存量库把
//! `ancestors` 放宽到 500（同为宽松化）。本迁移把 R5-DB-26 的保证**显式化并与该
//! 迁移中的 `cron_expression` 收缩解耦**（收缩属有风险的破坏性变更，不应与放宽
//! 绑定在同一迁移里）；对已是 500 的列重复执行同一 ALTER 是无害 no-op，故存量库
//! 重复覆盖安全。
//!
//! 方言说明：
//! - PostgreSQL：`ALTER TABLE ... ALTER COLUMN ... TYPE VARCHAR(500)`，保留 DEFAULT/NULL 属性。
//! - MySQL：`MODIFY COLUMN` 会重置列的全部属性，故显式重申 `DEFAULT ''`（与建表一致）。
//! - SQLite：不强制 VARCHAR 长度（存储类型统一 TEXT），且不支持 `ALTER COLUMN TYPE` /
//!   `MODIFY COLUMN`；本 crate 无 SQLite 表重建辅助，故 **no-op + 告警**（与 m20260719 同策略）。
//!
//! `down()` 有意为 no-op：把已放宽的列收回 50 会截断既有长路径（静默数据损坏），
//! 故不提供自动回滚；如需回退请人工评估数据长度后执行。

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DatabaseBackend;

/// PostgreSQL：放宽 ancestors 到 VARCHAR(500)（保留 DEFAULT/NULL）。
const PG_WIDEN_ANCESTORS: &str = "ALTER TABLE sys_dept ALTER COLUMN ancestors TYPE VARCHAR(500)";

/// MySQL：放宽 ancestors 到 VARCHAR(500)；MODIFY COLUMN 重置列属性故重申 DEFAULT ''。
const MYSQL_WIDEN_ANCESTORS: &str =
    "ALTER TABLE sys_dept MODIFY COLUMN ancestors VARCHAR(500) DEFAULT ''";

/// 目标方言对应的放宽 DDL；SQLite 无实际语义（不强制长度）故返回 None = 不执行。
fn widen_ancestors_sql(backend: DatabaseBackend) -> Option<&'static str> {
    match backend {
        DatabaseBackend::Postgres => Some(PG_WIDEN_ANCESTORS),
        DatabaseBackend::MySql => Some(MYSQL_WIDEN_ANCESTORS),
        DatabaseBackend::Sqlite => None,
        _ => None,
    }
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260928_000001_sys_dept_ancestors_width"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        match widen_ancestors_sql(backend) {
            Some(sql) => {
                manager.get_connection().execute_unprepared(sql).await?;
            }
            None => {
                // SQLite：无 ALTER COLUMN TYPE 语法且长度不被强制，跳过并告警
                eprintln!(
                    "[migration][warn] m20260928_000001: SQLite 不强制 VARCHAR 长度，\
                     跳过 sys_dept.ancestors 宽度修正（存储类型统一为 TEXT）"
                );
            }
        }
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // 有意 no-op（理由见文件头）：收回宽度可能截断存量数据。
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 可证伪：DDL 必须精确指向 `sys_dept.ancestors` 且目标宽度为 VARCHAR(500)。
    #[test]
    fn ddl_targets_sys_dept_ancestors_varchar_500() {
        for (backend, expected) in [
            (
                DatabaseBackend::Postgres,
                "ALTER TABLE sys_dept ALTER COLUMN ancestors TYPE VARCHAR(500)",
            ),
            (
                DatabaseBackend::MySql,
                "ALTER TABLE sys_dept MODIFY COLUMN ancestors VARCHAR(500) DEFAULT ''",
            ),
        ] {
            let sql = widen_ancestors_sql(backend).expect("PG/MySQL 必须产出放宽 DDL");
            assert_eq!(sql, expected, "backing={backend:?}");
            assert!(sql.contains("TABLE sys_dept"), "目标表错误: {sql}");
            assert!(sql.contains("ancestors"), "目标列错误: {sql}");
            assert!(sql.contains("VARCHAR(500)"), "目标类型错误: {sql}");
        }
    }

    /// 可证伪：SQLite 不产生 ALTER（长度不被强制，且无该方言语法）。
    #[test]
    fn sqlite_is_noop() {
        assert!(widen_ancestors_sql(DatabaseBackend::Sqlite).is_none());
    }
}
