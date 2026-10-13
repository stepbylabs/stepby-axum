//! 批次十七：节点高级动作白名单快照（sys_flow_task.actions_json）
//!
//! 语义：task 行的 `actions_json` 快照该节点开放的高级动作（delegate /
//! countersign_add / countersign_del）；**NULL = 存量行向后兼容（全开放）**，
//! 非 NULL = 白名单严格匹配（校验在 delegate/countersign_add/countersign_del
//! 三入口，批次十七收窄 M2 遗留 TODO「demo 链默认开放」）。
//! 存量库兜底：`initialize::ensure_flow_task_actions_json_column`（双写）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000013_flow_task_actions_json"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_flow_task ADD COLUMN actions_json TEXT NULL")
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_flow_task DROP COLUMN actions_json")
            .await?;
        Ok(())
    }
}
