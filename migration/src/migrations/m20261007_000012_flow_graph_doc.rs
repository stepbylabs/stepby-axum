//! 批次十六：图驱动单据表（flow_graph_doc）——G-02「按图推进」闭环的最后一块
//!
//! 设计：设计器画的图（flow_definition.graph_json）此前对推进内核零消费（demo 单据
//! 走 `demo_nodes(flow_mode)` 硬编码链）。本表承接"任意图驱动审批"：提交时绑定
//! 已发布流程定义行（版本快照）+ 冻结字段快照（条件边求值池），推进时由适配层
//! `route_graph(fields)` 重放同路径 ⇒ 确定性路由，引擎（线性链 + 节点内四模式 +
//! 加减签）零改动。
//!
//! 存量库兜底：`initialize::ensure_flow_graph_doc_table`（与迁移逐列一致，双写）。

use sea_orm_migration::prelude::*;

use crate::IndexDdlExt;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000012_flow_graph_doc"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        let auto = match backend {
            sea_orm::DatabaseBackend::Sqlite => "INTEGER PRIMARY KEY AUTOINCREMENT",
            sea_orm::DatabaseBackend::Postgres => "BIGSERIAL PRIMARY KEY",
            _ => "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        };
        // 方言映射（run 38328469439/本地 MySQL8+PG 实证）：
        // - TEXT 列在 MySQL 8 严格模式下禁 DEFAULT 值 ⇒ fields_json 改可空（应用层恒写值）
        // - PG 无 DATETIME 类型 ⇒ 统一 TIMESTAMP（MySQL/SQLite 兼容）
        let (fields_json_col, ts_type) = match backend {
            sea_orm::DatabaseBackend::MySql => ("fields_json TEXT NULL,", "DATETIME"),
            sea_orm::DatabaseBackend::Postgres => {
                ("fields_json TEXT NOT NULL DEFAULT '{}',", "TIMESTAMP")
            }
            _ => ("fields_json TEXT NOT NULL DEFAULT '{}',", "DATETIME"),
        };
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "CREATE TABLE IF NOT EXISTS flow_graph_doc (\
                 doc_id {auto},\
                 tenant_id BIGINT NOT NULL DEFAULT 0,\
                 dept_id BIGINT NULL,\
                 flow_id BIGINT NOT NULL,\
                 flow_code VARCHAR(64) NOT NULL,\
                 title VARCHAR(200) NOT NULL,\
                 {fields_json_col}\
                 status VARCHAR(16) NOT NULL DEFAULT 'pending',\
                 current_round INT NOT NULL DEFAULT 1,\
                 current_node_seq INT NULL,\
                 submitted_at {ts_type} NULL,\
                 finished_at {ts_type} NULL,\
                 create_by VARCHAR(64) DEFAULT '',\
                 create_time {ts_type} NULL,\
                 update_by VARCHAR(64) DEFAULT '',\
                 update_time {ts_type} NULL,\
                 del_flag VARCHAR(1) DEFAULT '0'\
                 )"
            ))
            .await?;
        // MySQL 不支持 CREATE INDEX IF NOT EXISTS（run 38328469439 实证）——方言分支同上。
        let ine = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "",
            _ => "IF NOT EXISTS ",
        };
        manager
            .get_connection()
            .execute_index_ddl_ic(&format!(
                "CREATE INDEX {ine}idx_flow_graph_doc_tenant \
                 ON flow_graph_doc (tenant_id, status)"
            ))
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS flow_graph_doc")
            .await?;
        Ok(())
    }
}
