// stepby-axum/migration/src/migrations/m20250716_000001_gen_and_notice_read.rs
//! 第二次迁移：新增代码生成模块表 + 通知公告已读记录表
//!
//! 新增表：
//! 1. gen_table         - 代码生成业务表
//! 2. gen_table_column  - 代码生成业务表字段
//! 3. sys_notice_read   - 通知公告已读记录表

use crate::IndexDdlExt;
use sea_orm_migration::prelude::*;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(backend, sea_orm_migration::sea_orm::DatabaseBackend::Sqlite)
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    let backend = manager.get_connection().get_database_backend();
    matches!(
        backend,
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

impl sea_orm_migration::MigrationName for Migration {
    fn name(&self) -> &str {
        "m20250716_000001_gen_and_notice_read"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_gen_table(manager).await?;
        create_gen_table_column(manager).await?;
        create_sys_notice_read(manager).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 回滚顺序与创建顺序相反
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_notice_read")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS gen_table_column")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS gen_table")
            .await?;
        Ok(())
    }
}

// ========== gen_table 建表 ==========

/// 创建 gen_table 表（代码生成业务表）
async fn create_gen_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // SQLite 与 PostgreSQL/MySQL 的主键自增语法不同，统一使用 raw SQL 保证兼容
    let sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS gen_table (
            table_id          INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name        VARCHAR(200) NOT NULL,
            table_comment     VARCHAR(500),
            sub_table_name    VARCHAR(64),
            sub_table_fk_name VARCHAR(64),
            class_name        VARCHAR(100),
            tpl_category      VARCHAR(200) DEFAULT 'crud',
            tpl_web_type      VARCHAR(30)  DEFAULT 'element-plus',
            package_name      VARCHAR(100),
            module_name       VARCHAR(30),
            business_name     VARCHAR(30),
            function_name     VARCHAR(50),
            function_author   VARCHAR(50),
            gen_type          CHAR(1)      DEFAULT '0',
            gen_path          VARCHAR(200),
            options           VARCHAR(1000),
            create_by         VARCHAR(64)  DEFAULT '',
            create_time       DATETIME,
            update_by         VARCHAR(64)  DEFAULT '',
            update_time       DATETIME,
            remark            VARCHAR(500)
        )"#
        .to_string()
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS gen_table (
            table_id          BIGSERIAL PRIMARY KEY,
            table_name        VARCHAR(200) NOT NULL,
            table_comment     VARCHAR(500),
            sub_table_name    VARCHAR(64),
            sub_table_fk_name VARCHAR(64),
            class_name        VARCHAR(100),
            tpl_category      VARCHAR(200) DEFAULT 'crud',
            tpl_web_type      VARCHAR(30)  DEFAULT 'element-plus',
            package_name      VARCHAR(100),
            module_name       VARCHAR(30),
            business_name     VARCHAR(30),
            function_name     VARCHAR(50),
            function_author   VARCHAR(50),
            gen_type          CHAR(1)      DEFAULT '0',
            gen_path          VARCHAR(200),
            options           VARCHAR(1000),
            create_by         VARCHAR(64)  DEFAULT '',
            create_time       TIMESTAMP,
            update_by         VARCHAR(64)  DEFAULT '',
            update_time       TIMESTAMP,
            remark            VARCHAR(500)
        )"#
        .to_string()
    } else {
        // MySQL
        r#"CREATE TABLE IF NOT EXISTS gen_table (
            table_id          BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            table_name        VARCHAR(200) NOT NULL,
            table_comment     VARCHAR(500),
            sub_table_name    VARCHAR(64),
            sub_table_fk_name VARCHAR(64),
            class_name        VARCHAR(100),
            tpl_category      VARCHAR(200) DEFAULT 'crud',
            tpl_web_type      VARCHAR(30)  DEFAULT 'element-plus',
            package_name      VARCHAR(100),
            module_name       VARCHAR(30),
            business_name     VARCHAR(30),
            function_name     VARCHAR(50),
            function_author   VARCHAR(50),
            gen_type          CHAR(1)      DEFAULT '0',
            gen_path          VARCHAR(200),
            options           VARCHAR(1000),
            create_by         VARCHAR(64)  DEFAULT '',
            create_time       DATETIME,
            update_by         VARCHAR(64)  DEFAULT '',
            update_time       DATETIME,
            remark            VARCHAR(500)
        )"#
        .to_string()
    };

    manager.get_connection().execute_unprepared(&sql).await?;

    // 唯一索引：table_name
    manager
        .get_connection()
        .execute_index_ddl_ic("CREATE UNIQUE INDEX idx_gen_table_name ON gen_table (table_name)")
        .await?;
    Ok(())
}

// ========== gen_table_column 建表 ==========

/// 创建 gen_table_column 表（代码生成业务表字段）
async fn create_gen_table_column(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS gen_table_column (
            column_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            table_id       INTEGER NOT NULL,
            column_name    VARCHAR(200),
            column_comment VARCHAR(500),
            column_type    VARCHAR(100),
            java_type      VARCHAR(500),
            java_field     VARCHAR(200),
            is_pk          CHAR(1) DEFAULT '0',
            is_increment   CHAR(1) DEFAULT '0',
            is_required    CHAR(1) DEFAULT '0',
            is_insert      CHAR(1) DEFAULT '0',
            is_edit        CHAR(1) DEFAULT '0',
            is_list        CHAR(1) DEFAULT '0',
            is_query       CHAR(1) DEFAULT '0',
            query_type     VARCHAR(200) DEFAULT 'EQ',
            html_type      VARCHAR(200),
            dict_type      VARCHAR(200) DEFAULT '',
            sort           INTEGER DEFAULT 0,
            create_by      VARCHAR(64) DEFAULT '',
            create_time    DATETIME,
            update_by      VARCHAR(64) DEFAULT '',
            update_time    DATETIME
        )"#
        .to_string()
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS gen_table_column (
            column_id      BIGSERIAL PRIMARY KEY,
            table_id       BIGINT NOT NULL,
            column_name    VARCHAR(200),
            column_comment VARCHAR(500),
            column_type    VARCHAR(100),
            java_type      VARCHAR(500),
            java_field     VARCHAR(200),
            is_pk          CHAR(1) DEFAULT '0',
            is_increment   CHAR(1) DEFAULT '0',
            is_required    CHAR(1) DEFAULT '0',
            is_insert      CHAR(1) DEFAULT '0',
            is_edit        CHAR(1) DEFAULT '0',
            is_list        CHAR(1) DEFAULT '0',
            is_query       CHAR(1) DEFAULT '0',
            query_type     VARCHAR(200) DEFAULT 'EQ',
            html_type      VARCHAR(200),
            dict_type      VARCHAR(200) DEFAULT '',
            sort           INTEGER DEFAULT 0,
            create_by      VARCHAR(64) DEFAULT '',
            create_time    TIMESTAMP,
            update_by      VARCHAR(64) DEFAULT '',
            update_time    TIMESTAMP
        )"#
        .to_string()
    } else {
        r#"CREATE TABLE IF NOT EXISTS gen_table_column (
            column_id      BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            table_id       BIGINT NOT NULL,
            column_name    VARCHAR(200),
            column_comment VARCHAR(500),
            column_type    VARCHAR(100),
            java_type      VARCHAR(500),
            java_field     VARCHAR(200),
            is_pk          CHAR(1) DEFAULT '0',
            is_increment   CHAR(1) DEFAULT '0',
            is_required    CHAR(1) DEFAULT '0',
            is_insert      CHAR(1) DEFAULT '0',
            is_edit        CHAR(1) DEFAULT '0',
            is_list        CHAR(1) DEFAULT '0',
            is_query       CHAR(1) DEFAULT '0',
            query_type     VARCHAR(200) DEFAULT 'EQ',
            html_type      VARCHAR(200),
            dict_type      VARCHAR(200) DEFAULT '',
            sort           INTEGER DEFAULT 0,
            create_by      VARCHAR(64) DEFAULT '',
            create_time    DATETIME,
            update_by      VARCHAR(64) DEFAULT '',
            update_time    DATETIME
        )"#
        .to_string()
    };

    manager.get_connection().execute_unprepared(&sql).await?;

    // 普通索引：table_id
    manager
        .get_connection()
        .execute_index_ddl_ic(
            "CREATE INDEX idx_gen_table_column_table_id ON gen_table_column (table_id)",
        )
        .await?;
    Ok(())
}

// ========== sys_notice_read 建表 ==========

/// 创建 sys_notice_read 表（通知公告已读记录）
async fn create_sys_notice_read(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_notice_read (
            read_id    INTEGER PRIMARY KEY AUTOINCREMENT,
            notice_id  INTEGER NOT NULL,
            user_id    INTEGER NOT NULL,
            read_time  DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(notice_id, user_id)
        )"#
        .to_string()
    } else if is_postgres(manager) {
        r#"CREATE TABLE IF NOT EXISTS sys_notice_read (
            read_id    BIGSERIAL PRIMARY KEY,
            notice_id  BIGINT NOT NULL,
            user_id    BIGINT NOT NULL,
            read_time  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(notice_id, user_id)
        )"#
        .to_string()
    } else {
        r#"CREATE TABLE IF NOT EXISTS sys_notice_read (
            read_id    BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            notice_id  BIGINT NOT NULL,
            user_id    BIGINT NOT NULL,
            read_time  DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(notice_id, user_id)
        )"#
        .to_string()
    };

    manager.get_connection().execute_unprepared(&sql).await?;

    // 普通索引：notice_id
    manager
        .get_connection()
        .execute_index_ddl_ic(
            "CREATE INDEX idx_notice_read_notice_id ON sys_notice_read (notice_id)",
        )
        .await?;
    Ok(())
}
