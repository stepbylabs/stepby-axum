// stepby-axum/migration/src/migrations/m20261002_000001_perf_indexes.rs
//! E2-a 性能索引补齐（两个表三个索引）：
//!
//! 1. `idx_flow_doc_tenant ON flow_demo_doc (tenant_id)`
//!    多租户 Phase 2 铺开 `tenant_id` 列后，flow_demo_doc 既有索引只有
//!    `idx_flow_doc_applicant (applicant_id, status)`；按租户维度过滤/统计的
//!    管理端查询（列表分页、租户维度 count）全表扫描。
//!
//! 2. `idx_web_hook_log_status ON sys_web_hook_log (status)`
//!    推送记录分页 `find_page_filtered`（repository/sys_web_hook_log.rs）的
//!    等值过滤列（status）；既有索引只有 `idx_web_hook_log_hook_id` 与
//!    `idx_web_hook_log_created`，status 过滤全表扫描。
//!
//! 3. `idx_web_hook_log_event_type ON sys_web_hook_log (event_type)`
//!    按事件类型过滤列（列表/导出路径；LIKE 含前导通配时作回退覆盖）。
//!
//! ## 口径
//!
//! 与 m20260926_000008 同款：迁移只进不退（不改动原建表迁移）；
//! `initialize/mod.rs` 兜底函数同步补同款幂等语句（存量库不跑 Migrator::up），
//! 表不存在（如 web_hook 模块未建表的库）时兜底自动跳过。
//! 幂等：`IF NOT EXISTS`（PG/SQLite）；MySQL 经 `IndexDdlExt` 容错"索引已存在"。

use crate::IndexDdlExt;
use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261002_000001_perf_indexes"
    }
}

/// (索引名, 表名 (列清单)) —— down 与 up 共用
const INDEX_TARGETS: &[(&str, &str)] = &[
    ("idx_flow_doc_tenant", "flow_demo_doc (tenant_id)"),
    ("idx_web_hook_log_status", "sys_web_hook_log (status)"),
    ("idx_web_hook_log_event_type", "sys_web_hook_log (event_type)"),
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // MySQL 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属），留空交由
        // execute_index_ddl_ic 容错"索引已存在"实现幂等；PG/SQLite 直接 INE。
        let ine = match conn.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "",
            _ => "IF NOT EXISTS ",
        };
        for (idx_name, target) in INDEX_TARGETS {
            conn.execute_index_ddl_ic(&format!(
                "CREATE INDEX {ine}{idx_name} ON {target}"
            ))
            .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // MySQL 的 DROP INDEX 需要 ON <table>，PG/SQLite 不需要
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
