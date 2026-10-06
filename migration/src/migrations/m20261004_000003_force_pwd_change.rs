// stepby-axum/migration/src/migrations/m20261004_000003_force_pwd_change.rs
//! B4 强制首登改密机制（开关式，默认关闭 = 现有行为零变化）：
//!
//! 1. `sys_user.must_change_pwd CHAR(1) DEFAULT '0'`：'1' = 初始密码未修改
//!    （本轮建列时对 admin 种子标记 '1'，其余用户默认 '0'）；
//!    个人中心改密成功即清除（`update_user_password` 统一路径）。
//! 2. `sys_config` 种子 `sys.user.forceFirstLoginChangePwd = 'false'`：
//!    开关开启后 `/getInfo` 下发 `mustChangePassword=true`（服务端判定，对齐
//!    `showTenantColumn` 的"单点判定"范式），前端据此强制跳转改密页并拦截其它路由；
//!    开关关闭（默认）时标志恒 false，前端零行为变化（e2e/演示不受影响）。
//!
//! ## 口径
//!
//! - 加列幂等（`has_column` 判存在），**仅本次新建列时**回填 admin 标记——
//!   存量库重跑不重复标记（已改密用户不得被误标回待改状态）；
//! - config 种子仅 `INSERT OR IGNORE`（不 UPDATE，尊重管理员已改值）；
//! - `pub fn` 供 `initialize/mod.rs` 兜底引用（单一事实源）。

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::Statement;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261004_000003_force_pwd_change"
    }
}

/// 强改开关的 config 键与默认值（迁移与兜底共用）
pub const FORCE_PWD_CHANGE_CONFIG_KEY: &str = "sys.user.forceFirstLoginChangePwd";
pub const FORCE_PWD_CHANGE_CONFIG_DEFAULT: &str = "false";

/// 幂等检查列是否存在（三方言；与 m20261003_000002 has_column 同口径。
/// 注意 SQLite 的 PRAGMA table_info 返回**全部列**，必须按 name 过滤判定——
/// 直接以"行非空"判定会导致恒 true、ALTER 永不执行（本迁移首版曾踩此坑，
/// 测试以 no such column 实证暴露后修正））
async fn has_column(manager: &SchemaManager<'_>, table: &str, column: &str) -> Result<bool, DbErr> {
    let conn = manager.get_connection();
    let backend = conn.get_database_backend();
    match backend {
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite => {
            let rows = conn
                .query_all_raw(Statement::from_string(
                    backend,
                    format!("PRAGMA table_info({table})"),
                ))
                .await?;
            Ok(rows.iter().any(|row| {
                row.try_get::<String>("", "name")
                    .map(|n| n.eq_ignore_ascii_case(column))
                    .unwrap_or(false)
            }))
        }
        _ => {
            let schema = if backend == sea_orm::DatabaseBackend::Postgres {
                "table_schema=current_schema()"
            } else {
                "table_schema=DATABASE()"
            };
            let rows = conn
                .query_all_raw(Statement::from_string(
                    backend,
                    format!(
                        "SELECT 1 FROM information_schema.columns WHERE table_name='{table}' AND column_name='{column}' AND {schema} LIMIT 1"
                    ),
                ))
                .await?;
            Ok(!rows.is_empty())
        }
    }
}

/// 幂等 INSERT（种子数据按唯一约束去重；与 m20261003_000002 同款口径）
async fn execute_idempotent_insert(manager: &SchemaManager<'_>, body: &str) -> Result<(), DbErr> {
    let sql = match manager.get_connection().get_database_backend() {
        sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {}", body),
        sea_orm::DatabaseBackend::Postgres => {
            format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
        }
        _ => format!("INSERT IGNORE INTO {}", body),
    };
    manager.get_connection().execute_unprepared(&sql).await?;
    Ok(())
}

/// sys_user 加列 + admin 标记 + config 种子的 INSERT 体（迁移与兜底共用）
///
/// 返回 `(must_seed_admin, config_bodies)`：
/// - `must_seed_admin = true` 表示本次新加了 `must_change_pwd` 列（调用方应回填 admin 标记）；
/// - `config_bodies` 为强改开关的幂等 INSERT 语句体。
pub async fn upsert_force_pwd_change_columns(
    manager: &SchemaManager<'_>,
    now_expr: &str,
) -> Result<(bool, Vec<String>), DbErr> {
    // 1. sys_user.must_change_pwd（幂等加列）
    let newly_added = !has_column(manager, "sys_user", "must_change_pwd").await?;
    if newly_added {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE sys_user ADD COLUMN must_change_pwd CHAR(1) DEFAULT '0'",
            )
            .await?;
    }

    // 2. sys_config 强改开关（幂等种子，不 UPDATE——尊重管理员已改值）
    let config_body = format!(
        "sys_config (config_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
        (9010, '用户首登强制改密开关', '{FORCE_PWD_CHANGE_CONFIG_KEY}', '{FORCE_PWD_CHANGE_CONFIG_DEFAULT}', 'Y', 'admin', {now_expr}, '开启后初始密码/过期密码用户登录时被强制引导改密')"
    );

    Ok((newly_added, vec![config_body]))
}

/// admin 标记回填语句体（仅建列时执行）
pub fn admin_marker_bodies() -> Vec<String> {
    vec![
        "UPDATE sys_user SET must_change_pwd = '1' WHERE user_id = 1 AND must_change_pwd = '0'"
            .to_string(),
    ]
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "NOW()".to_string(),
            _ => "CURRENT_TIMESTAMP".to_string(),
        };
        let (newly_added, config_bodies) = upsert_force_pwd_change_columns(manager, &now).await?;

        if newly_added {
            for body in admin_marker_bodies() {
                manager.get_connection().execute_unprepared(&body).await?;
            }
        }
        for body in config_bodies {
            execute_idempotent_insert(manager, &body).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "DELETE FROM sys_config WHERE config_key = 'sys.user.forceFirstLoginChangePwd'",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared("ALTER TABLE sys_user DROP COLUMN must_change_pwd")
            .await?;
        Ok(())
    }
}
