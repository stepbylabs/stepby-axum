//! G-01 M1：通用报表数据集与大屏存储（report_dataset / report_dashboard）
//!
//! - 审计项 G-01（P1）M1 阶段：受控数据集（SQL 模板白名单校验）+ 大屏画布配置存储；
//! - dataset.sql_template 为**管理员预注册**的参数化模板：`common/dataset_sql.rs`
//!   白名单校验器 fail-closed（仅 SELECT 单语句 / 禁 DML DDL / 禁注释 / 禁多语句）；
//! - columns_meta：试跑采样得到的列元数据（设计器列选择用）；
//! - dashboard.layout_json 存 schemaVersion 增量（echarts option 不存全量）；
//! - 存量库兜底：`initialize::ensure_report_tables`（同构 CREATE TABLE IF NOT EXISTS）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000004_report_dataset"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        let text_type = match backend {
            sea_orm::DatabaseBackend::MySql => "LONGTEXT",
            _ => "TEXT",
        };
        let pk = match backend {
            sea_orm::DatabaseBackend::Sqlite => "INTEGER PRIMARY KEY AUTOINCREMENT",
            sea_orm::DatabaseBackend::Postgres => "BIGSERIAL PRIMARY KEY",
            _ => "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        };

        let dataset_sql = format!(
            "CREATE TABLE IF NOT EXISTS report_dataset (\
             dataset_id {pk},\
             tenant_id BIGINT NOT NULL DEFAULT 0,\
             dataset_code VARCHAR(64) NOT NULL,\
             dataset_name VARCHAR(128) NOT NULL,\
             sql_template {text_type} NOT NULL,\
             params_schema {text_type},\
             columns_meta {text_type},\
             status CHAR(1) NOT NULL DEFAULT '0',\
             remark VARCHAR(500),\
             create_by VARCHAR(64),\
             create_time DATETIME,\
             update_by VARCHAR(64),\
             update_time DATETIME,\
             del_flag CHAR(1) DEFAULT '0')"
        );
        manager
            .get_connection()
            .execute_unprepared(&dataset_sql)
            .await?;

        let dashboard_sql = format!(
            "CREATE TABLE IF NOT EXISTS report_dashboard (\
             dashboard_id {pk},\
             tenant_id BIGINT NOT NULL DEFAULT 0,\
             dashboard_code VARCHAR(64) NOT NULL,\
             dashboard_name VARCHAR(128) NOT NULL,\
             layout_json {text_type} NOT NULL,\
             schema_version INT NOT NULL DEFAULT 1,\
             status CHAR(1) NOT NULL DEFAULT '0',\
             remark VARCHAR(500),\
             create_by VARCHAR(64),\
             create_time DATETIME,\
             update_by VARCHAR(64),\
             update_time DATETIME,\
             del_flag CHAR(1) DEFAULT '0')"
        );
        manager
            .get_connection()
            .execute_unprepared(&dashboard_sql)
            .await?;

        let idx_sqls = [
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_report_dataset_code ON report_dataset (tenant_id, dataset_code)",
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_report_dashboard_code ON report_dashboard (tenant_id, dashboard_code)",
        ];
        for idx in idx_sqls {
            manager.get_connection().execute_unprepared(idx).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS report_dashboard")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS report_dataset")
            .await?;
        Ok(())
    }
}
