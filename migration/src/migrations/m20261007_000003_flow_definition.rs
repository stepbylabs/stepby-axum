//! G-02 M1：可视化流程定义存储（flow_definition 表）
//!
//! - 审计项 G-02（P1）M1 阶段：把审批链从"代码内注册"（`sys_flow_service::demo_nodes`）
//!   扩展出**DB 定义的流程图**（BPMN-lite 节点/边 JSON）；
//! - 同 `flow_code` 多 **version**（实例绑定 version，防定义变更污染在途实例）；
//! - `is_latest` 标记每 code 的最新已发布版；
//! - graph_json 校验由 `common/flow_graph.rs` 白名单校验器承担（M2 推进函数接入）；
//! - 存量库兜底：`initialize::ensure_flow_definition_table`（同构 CREATE TABLE IF NOT EXISTS）。

use sea_orm_migration::prelude::*;

use crate::IndexDdlExt;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000003_flow_definition"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        // 方言映射：PG 无 DATETIME 类型（run 38328469439/本地 PG 实证）⇒ TIMESTAMP
        let ts_type = match backend {
            sea_orm::DatabaseBackend::Postgres => "TIMESTAMP",
            _ => "DATETIME",
        };
        // TEXT 列方言：SQLite/PG = TEXT；MySQL = LONGTEXT
        let text_type = match backend {
            sea_orm::DatabaseBackend::MySql => "LONGTEXT",
            _ => "TEXT",
        };
        let now_expr = match backend {
            sea_orm::DatabaseBackend::Sqlite => {
                format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
            }
            _ => "NOW()".to_string(),
        };
        let create_sql = format!(
            "CREATE TABLE IF NOT EXISTS flow_definition (\
             flow_id {pk},\
             tenant_id BIGINT NOT NULL DEFAULT 0,\
             flow_code VARCHAR(64) NOT NULL,\
             flow_name VARCHAR(128) NOT NULL,\
             graph_json {text_type} NOT NULL,\
             version INT NOT NULL DEFAULT 1,\
             is_latest CHAR(1) NOT NULL DEFAULT '1',\
             status CHAR(1) NOT NULL DEFAULT '0',\
             create_by VARCHAR(64),\
             create_time {ts_type},\
             update_by VARCHAR(64),\
             update_time {ts_type},\
             remark VARCHAR(500),\
             del_flag CHAR(1) DEFAULT '0')",
            pk = match backend {
                sea_orm::DatabaseBackend::Sqlite => "INTEGER PRIMARY KEY AUTOINCREMENT",
                sea_orm::DatabaseBackend::Postgres => "BIGSERIAL PRIMARY KEY",
                _ => "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            },
        );
        manager
            .get_connection()
            .execute_unprepared(&create_sql)
            .await?;
        // 唯一索引：(tenant_id, flow_code, version) 与 (tenant_id, flow_code, is_latest) 唯一
        //（is_latest 同 code 只允许一条 '1'；SQLite 无部分唯一索引差异——用唯一索引 + '0' 填充策略）
        // MySQL 不支持 CREATE INDEX IF NOT EXISTS（run 38328469439 实证）——
        // 方言分支：MySQL 发裸语句，重复场景由迁移一次性语义 + "已存在"容错兜底。
        let ine = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "",
            _ => "IF NOT EXISTS ",
        };
        let idx_sqls = [
            format!("CREATE UNIQUE INDEX {ine}uq_flow_def_code_ver ON flow_definition (tenant_id, flow_code, version)"),
        ];
        for idx in idx_sqls {
            manager.get_connection().execute_index_ddl_ic(&idx).await?;
        }
        // 幂等 seed：一条演示定义（draft 状态，version=1，is_latest='1'）
        let graph = r#"{"nodes":[{"id":"start","type":"start"},{"id":"a1","type":"approve","name":"部门主管审批","assignees":["dept_leader"],"quorum":"any"},{"id":"a2","type":"approve","name":"管理员审批","assignees":["role:admin"],"quorum":"any"},{"id":"end","type":"end"}],"edges":[{"from":"start","to":"a1"},{"from":"a1","to":"a2"},{"from":"a2","to":"end"}]}"#;
        let seed_sql = format!(
            "INSERT INTO flow_definition (tenant_id, flow_code, flow_name, graph_json, version, is_latest, status, create_by, create_time, remark, del_flag) \
             SELECT 0, 'demo_v2', '可配置演示审批流', '{graph}', 1, '1', '0', 'admin', {now_expr}, 'G-02 M1 种子：两级单审（对齐 demo single 模式）', '0' \
             WHERE NOT EXISTS (SELECT 1 FROM flow_definition WHERE tenant_id = 0 AND flow_code = 'demo_v2')",
        );
        manager
            .get_connection()
            .execute_unprepared(&seed_sql)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS flow_definition")
            .await?;
        Ok(())
    }
}
