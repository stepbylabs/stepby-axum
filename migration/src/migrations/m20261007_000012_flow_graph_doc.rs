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
                 fields_json TEXT NOT NULL DEFAULT '{{}}',\
                 status VARCHAR(16) NOT NULL DEFAULT 'pending',\
                 current_round INT NOT NULL DEFAULT 1,\
                 current_node_seq INT NULL,\
                 submitted_at DATETIME NULL,\
                 finished_at DATETIME NULL,\
                 create_by VARCHAR(64) DEFAULT '',\
                 create_time DATETIME NULL,\
                 update_by VARCHAR(64) DEFAULT '',\
                 update_time DATETIME NULL,\
                 del_flag VARCHAR(1) DEFAULT '0'\
                 )"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX IF NOT EXISTS idx_flow_graph_doc_tenant \
                 ON flow_graph_doc (tenant_id, status)",
            )
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
