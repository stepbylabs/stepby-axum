//! G-02 M2：审批引擎动作矩阵扩展列（sys_flow_task）
//!
//! - `weight`（INT NOT NULL DEFAULT 1）：加权票节点（task_type=weighted）按审批人
//!   **提交时快照**的权重（D2：运行期不重算）；single/countersign/or_sign 行恒 1；
//! - `threshold`（INT NULL）：weighted 行的节点门槛快照（权重和 ≥ threshold 即节点通过）；
//!   非 weighted 行恒 NULL（fail-closed：weighted 行缺快照时不判定完成）；
//! - `delegate_from`（BIGINT NULL）：委派动作记录转出审批人（委派语义：处理完回不到 A，
//!   行保持 pending 且 assignee 换为受托人）。
//!
//! 幂等：has_column 守卫逐列判定（对齐 m20260926_000009 gen_column 模式）；
//! 存量库兜底：`initialize::ensure_flow_task_action_columns`（同构 ALTER ADD）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000006_flow_task_action"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 三方言统一走 ALTER TABLE ADD COLUMN；has_column 守卫保证重放/异构库幂等
        let adds: [(&str, &str); 3] = [
            ("weight", "INT NOT NULL DEFAULT 1"),
            ("threshold", "INT NULL"),
            ("delegate_from", "BIGINT NULL"),
        ];
        for (col, ddl) in adds {
            if !manager.has_column("sys_flow_task", col).await? {
                conn.execute_unprepared(&format!(
                    "ALTER TABLE sys_flow_task ADD COLUMN {col} {ddl}"
                ))
                .await?;
            }
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 列级回滚：三方言 DROP COLUMN（SQLite 3.35+ 支持；测试/开发库可回滚）
        let conn = manager.get_connection();
        for col in ["weight", "threshold", "delegate_from"] {
            if manager.has_column("sys_flow_task", col).await? {
                conn.execute_unprepared(&format!("ALTER TABLE sys_flow_task DROP COLUMN {col}"))
                    .await?;
            }
        }
        Ok(())
    }
}
