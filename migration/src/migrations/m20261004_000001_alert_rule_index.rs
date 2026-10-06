// stepby-axum/migration/src/migrations/m20261004_000001_alert_rule_index.rs
//! 全链路核查补录（2026-10-04）：sys_alert_rule 的 enabled 条件索引
//!
//! 评估调度（alertEvalTask 每分钟）经 `find_enabled`（repository/sys_alert_rule.rs:41）
//! 以 `enabled = '1'` 全量拉取启用规则；该表除主键外无任何二级索引，
//! 每分钟一次全表扫描（数据量小危害低，但对齐项目其它表的索引纪律）。
//!
//! ## 口径
//!
//! 与 m20261002_000001_perf_indexes 同款：迁移只进不退；
//! `initialize/mod.rs` 的 `ensure_perf_indexes` 兜底函数同步补同款幂等语句
//! （存量库不跑 Migrator::up）；幂等：`IF NOT EXISTS`（PG/SQLite），
//! MySQL 经 `IndexDdlExt` 容错"索引已存在"。

use crate::IndexDdlExt;
use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261004_000001_alert_rule_index"
    }
}

/// (索引名, 表名 (列清单)) —— down 与 up 共用
const INDEX_TARGETS: &[(&str, &str)] = &[("idx_alert_rule_enabled", "sys_alert_rule (enabled)")];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let ine = match conn.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "",
            _ => "IF NOT EXISTS ",
        };
        for (idx_name, target) in INDEX_TARGETS {
            conn.execute_index_ddl_ic(&format!("CREATE INDEX {ine}{idx_name} ON {target}"))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for (idx_name, target) in INDEX_TARGETS {
            let sql = match conn.get_database_backend() {
                sea_orm::DatabaseBackend::MySql => {
                    let table = target.split(" (").next().unwrap_or(target);
                    format!("DROP INDEX {idx_name} ON {table}")
                }
                _ => format!("DROP INDEX IF EXISTS {idx_name}"),
            };
            conn.execute_unprepared(&sql).await?;
        }
        Ok(())
    }
}
