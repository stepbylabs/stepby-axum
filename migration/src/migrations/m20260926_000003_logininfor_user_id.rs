// stepby-axum/migration/src/migrations/m20260926_000003_logininfor_user_id.rs
//! 台账 F-8（§2.4 建议采纳）：sys_logininfor 增 `user_id` 列 + 索引 + 存量回填。
//!
//! 背景：登录日志表原只有 `user_name`（可变、可重名于历史数据），审计域"强关联"要求
//! 以不可变主键关联用户。`user_name` 全局唯一（§27 原则 A）⇒ 回填无歧义；
//! 未匹配（失败登录的用户名不存在等）回填 0，语义为"无对应用户"。
//!
//! 列定义为 `BIGINT NOT NULL DEFAULT 0`（与同表 `tenant_id` 同款约定）：语义上
//! "0 = 无对应用户"是**唯一**的缺省表示，避免 NULL/0 双语义并存导致查询与索引失效。
//!
//! 写入链路：登录审计服务在同一事务/调用点补写 user_id（`service/sys_logininfor_service.rs`）。
//! 存量库兜底：`initialize::ensure_logininfor_user_id_column`。

use sea_orm_migration::prelude::*;

use crate::IndexDdlExt;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000003_logininfor_user_id"
    }
}

/// 登录日志 user_id 索引名（审计按用户检索）
pub const IDX_LOGININFOR_USER: &str = "idx_sys_logininfor_user";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(
            "ALTER TABLE sys_logininfor ADD COLUMN user_id BIGINT NOT NULL DEFAULT 0",
        )
        .await?;
        conn.execute_index_ddl_ic(&format!(
            "CREATE INDEX {IDX_LOGININFOR_USER} ON sys_logininfor (user_id)"
        ))
        .await?;
        // 存量回填：按 user_name 精确匹配（MIN 兜底历史上可能存在的重名脏数据）；未匹配 = 0
        conn.execute_unprepared(
            "UPDATE sys_logininfor SET user_id = COALESCE(\
               (SELECT MIN(u.user_id) FROM sys_user u WHERE u.user_name = sys_logininfor.user_name)\
               , 0) WHERE user_name IS NOT NULL",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // R-10 回滚演练修（MySQL 1064）：`DROP INDEX IF EXISTS` 只有 PG/SQLite 认，
        // MySQL 要 `DROP INDEX <idx> ON <table>`。up() 侧本来就走三方言分支，
        // down() 却写成了单方言——回滚链正是在这里断的。
        let drop_idx = match conn.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => {
                format!("DROP INDEX {IDX_LOGININFOR_USER} ON sys_logininfor")
            }
            _ => format!("DROP INDEX IF EXISTS {IDX_LOGININFOR_USER}"),
        };
        conn.execute_unprepared(&drop_idx).await?;
        conn.execute_unprepared("ALTER TABLE sys_logininfor DROP COLUMN user_id")
            .await?;
        Ok(())
    }
}
