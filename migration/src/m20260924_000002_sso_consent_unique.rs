// axum-backend/migration/src/m20260924_000002_sso_consent_unique.rs
//! v5-E1：sys_oauth_consent 组合唯一索引 (user_id, client_id)。
//!
//! 背景：授权同意依赖代码层判重（find_by_user_client 后插入），无 DB 级约束——
//! 并发的两次 authorize 可插入两行同 (user_id, client_id) 记录，导致 grants 列表
//! 重复与撤销语义混乱。注释原称"user_id + client_id 唯一"实为代码约定。
//!
//! 前置：v5-E1 将撤销语义由软删改为物理删（repository::revoke），使 (user_id,
//! client_id) 在有效记录内天然唯一。本迁移：
//! 1. 物理删除历史软删行（del_flag='2'，撤销语义变更后为脏数据）；
//! 2. 同 (user_id, client_id) 重复行仅保留最早 consent_id（防御存量并发脏数据）；
//! 3. 建组合唯一索引 uq_sso_consent_user_client。
//!
//! 存量库兜底：AppInitializer::ensure_sso_consent_unique 以等价 SQL 幂等执行。

use crate::IndexDdlExt;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DatabaseBackend;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260924_000002_sso_consent_unique"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // 1. 清理软删行（撤销语义已改物理删，软删行为脏数据）
        conn.execute_unprepared("DELETE FROM sys_oauth_consent WHERE del_flag = '2'")
            .await?;
        // 2. 去重：同 (user_id, client_id) 保留最早 consent_id
        //    MySQL 不允许 DELETE 目标表同时出现在子查询 FROM（1093），
        //    派生表包裹（物化）后三方言等价
        conn.execute_unprepared(
            "DELETE FROM sys_oauth_consent WHERE consent_id NOT IN (\
             SELECT keep_id FROM (\
             SELECT MIN(consent_id) AS keep_id FROM sys_oauth_consent GROUP BY user_id, client_id\
             ) keep_rows)",
        )
        .await?;
        // 3. 组合唯一索引
        conn.execute_index_ddl_ic(
            "CREATE UNIQUE INDEX uq_sso_consent_user_client \
             ON sys_oauth_consent (user_id, client_id)",
        )
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        // MySQL 语法为 DROP INDEX <name> ON <table>，且不支持 IF EXISTS
        match manager.get_database_backend() {
            DatabaseBackend::MySql => {
                conn.execute_unprepared(
                    "DROP INDEX uq_sso_consent_user_client ON sys_oauth_consent",
                )
                .await?;
            }
            _ => {
                conn.execute_unprepared("DROP INDEX IF EXISTS uq_sso_consent_user_client")
                    .await?;
            }
        }
        Ok(())
    }
}
