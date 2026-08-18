// axum-backend/migration/src/m20260818_000003_audit_alarm_config.rs
//! 异常操作告警阈值初始配置（sys_config）
//!
//! 审计大屏「异常操作告警」功能依赖以下配置项（不配置时后端回退内置默认值）：
//!   - sys.audit.alarm.window_minutes      时间窗口（分钟，默认 5）
//!   - sys.audit.alarm.fail_threshold      同一对象（操作人/模块）失败次数阈值（默认 5）
//!   - sys.audit.alarm.fail_rate_threshold 失败率百分比阈值（默认 30）
//!
//! 幂等：全部走 execute_idempotent_insert（INSERT OR IGNORE / ON CONFLICT DO NOTHING）。

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

/// 当前时间表达式（跨数据库兼容）
fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        format!("'{}'", now)
    } else {
        "NOW()".to_string()
    }
}

/// 幂等 INSERT
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = if is_sqlite(manager) {
        format!("INSERT OR IGNORE INTO {}", body)
    } else if is_postgres(manager) {
        format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
    } else {
        format!("INSERT IGNORE INTO {}", body)
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260818_000003_audit_alarm_config"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = now_expr(manager);
        // 复用首迁移 config_id 序列：从 100 开始，避开前置迁移已占用的 1-6
        let sql = format!(
            "sys_config (config_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
            (100, '异常操作告警-时间窗口(分钟)', 'sys.audit.alarm.window_minutes', '5', 'Y', 'admin', {now}, '统计操作失败的时间窗口，单位分钟，范围 1-1440'), \
            (101, '异常操作告警-失败次数阈值', 'sys.audit.alarm.fail_threshold', '5', 'Y', 'admin', {now}, '同一操作人或模块在窗口内失败次数达到该值即告警，最小 1'), \
            (102, '异常操作告警-失败率阈值(%)', 'sys.audit.alarm.fail_rate_threshold', '30', 'Y', 'admin', {now}, '窗口内失败操作占比达到该百分比即触发失败率告警，范围 0-100')",
        );
        execute_idempotent_insert(manager, &sql).await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
