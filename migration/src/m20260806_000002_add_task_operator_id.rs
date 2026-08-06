// axum-backend/migration/src/m20260806_000002_add_task_operator_id.rs
//! 迁移：sys_task 表增加 operator_id 列（P0-2 越权广播修复）
//!
//! 背景：taskProgress 消息原通过全局 WS 广播推送给所有在线客户端，存在跨用户
//! 信息泄漏。修复方案：task 记录增加 operator_id（任务创建者 user_id），
//! taskProgress 定向推送给创建者。本迁移为 sys_task 增加该列（可空，兼容历史数据）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260806_000002_add_task_operator_id"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Alias::new("sys_task"))
                    .add_column(
                        ColumnDef::new(Alias::new("operator_id"))
                            .big_integer()
                            .null()
                            .comment("操作人 user_id（P0-2：taskProgress 定向推送目标，None 为系统任务）"),
                    )
                    .to_owned(),
            )
            .await
    }
}
