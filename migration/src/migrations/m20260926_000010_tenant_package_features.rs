// stepby-axum/migration/src/migrations/m20260926_000010_tenant_package_features.rs
//! 租户套餐能力位（Feature Flags）列：三层开关的**中间层**落地。
//!
//! 对应项目定位「大而全 + 用户可选可配置」的落地准则 ②：
//! 平台 `config`（能开什么）→ **租户套餐能力位**（这个租户能开什么）→ 角色授权（这个人能
//! 用什么）。缺中间层时，任何"平台专属能力按租户放开"的需求都只能靠改代码实现。
//!
//! 内容：
//!   1. `sys_tenant_package` 增 `features TEXT NULL`（JSON 对象，key = 能力位键，
//!      value = 模式串；NULL / `{}` = 全默认，即**全部关闭**）。
//!
//! 语义（`src/common/features.rs` 为单一事实源）：
//!   - 能力位键与合法模式由 `KNOWN_FEATURES` 注册表定义；未登记键与非法模式
//!     在读取时被剔除并告警（fail-closed）。
//!   - **默认值 = 现状 = 关闭态即安全态**：存量套餐行全为 NULL，行为与迁移前完全一致。
//!
//! 幂等：列存在性探测后 ALTER（sqlite pragma / pg·mysql information_schema）。
//! 本迁移**只建列，不写数据**——避免用 DDL 迁移做业务数据回填。

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::Statement;

pub struct Migration;

/// 判断当前数据库是否为 SQLite
fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite
    )
}

/// 判断当前数据库是否为 PostgreSQL
fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

/// 幂等加列：存在性探测后 `ALTER TABLE ADD COLUMN`（三方言）。
async fn ensure_column(
    manager: &SchemaManager<'_>,
    table: &str,
    column: &str,
    column_def: &str,
) -> Result<(), DbErr> {
    let conn = manager.get_connection();
    let exists_sql = if is_sqlite(manager) {
        format!("SELECT COUNT(*) AS n FROM pragma_table_info('{table}') WHERE name = '{column}'")
    } else if is_postgres(manager) {
        format!(
            "SELECT COUNT(*) AS n FROM information_schema.columns \
             WHERE table_name = '{table}' AND column_name = '{column}'"
        )
    } else {
        format!(
            "SELECT COUNT(*) AS n FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = '{table}' AND column_name = '{column}'"
        )
    };
    let row = conn
        .query_one_raw(Statement::from_string(
            conn.get_database_backend(),
            exists_sql,
        ))
        .await?;
    let exists = row
        .map(|r| {
            r.try_get::<i64>("", "n")
                .or_else(|_| r.try_get::<i32>("", "n").map(i64::from))
                .unwrap_or(0)
        })
        .unwrap_or(0)
        > 0;
    if exists {
        return Ok(());
    }
    conn.execute_unprepared(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {column_def}"
    ))
    .await?;
    Ok(())
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260926_000010_tenant_package_features"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 列名/类型须与 AppInitializer 的 `ensure_tenant_package_features` 兜底逐列一致
        ensure_column(manager, "sys_tenant_package", "features", "TEXT NULL").await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared("ALTER TABLE sys_tenant_package DROP COLUMN features")
            .await?;
        Ok(())
    }
}
