// stepby-axum/migration/src/migrations/m20260925_000001_multitenant_phase2.rs
//! 多租户 Phase 2（立项实施）：存量 27 张业务/审计表统一铺开 tenant_id。
//!
//! 立项定案（2026-09-25 福哥拍板"现在立项"，按文档 §5.3 推荐方案落定）：
//!   1. 租户模型 = 共享菜单 + 数据隔离（不独立 realm）；
//!   2. tid 载体 = JWT claim `tid`（已实现）+ **dept 树根 = 租户**（不建独立 sys_tenant 表）；
//!   3. 本迁移 = 27 张表加列 + tid 索引；存量数据全部归 tid=0（平台租户）；
//!   4. 过滤语义 = common::tenant（tid=0 平台不过滤；tid≠0 仅本租户）；
//!   5. tid=0 = 平台租户（跨租户运营）。
//!
//! 逐表甄别（加列 / 不加列）：
//!   【加列 27 张】业务域：sys_dept/sys_role/sys_post/sys_config/sys_dict_type/
//!     sys_dict_data/sys_notice/sys_notice_read/sys_pat/sys_user_pref；
//!     SSO 域：sys_oauth_consent/sys_oauth_provider/sys_oauth_user；
//!     消息域：sys_msg_channel/sys_msg_template/sys_msg_send_log；
//!     业务功能：sys_web_hook/sys_web_hook_log/sys_report/sys_report_sub/
//!     sys_job/sys_job_log/sys_task/sys_backup_log；
//!     审计域：sys_oper_log/sys_logininfor/sys_frontend_error。
//!   【不加列，甄别理由】sys_menu（推荐：全租户共享功能目录，避免 3600+ 段位
//!     每租户复制）；sys_rate_limit（全局基础设施配置）；gen_table/gen_table_column
//!     （开发期工具不隔离）；sys_user_role/sys_role_menu/sys_role_dept/
//!     sys_user_post/sys_user_dept（纯关联表依赖父表 JOIN，加冗余列反而引入
//!     双写漂移风险）；已有 tid：sys_user/sys_oauth_client/sys_flow_task/
//!     sys_flow_log/sys_scim_group(+binding/member)。
//!
//! 幂等：列存在性检查（sqlite pragma / pg·mysql information_schema）+
//! `execute_index_ddl_ic` 幂等索引——存量库与全新库均可安全执行。
//! 跨 sqlite/postgres/mysql 三方言。

use crate::IndexDdlExt;
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

/// 幂等加列：列已存在则跳过（防存量库经 AppInitializer 兜底补列后迁移重放报
/// duplicate column）。
async fn ensure_tenant_column(manager: &SchemaManager<'_>, table: &str) -> Result<(), DbErr> {
    let conn = manager.get_connection();
    let exists_sql = if is_sqlite(manager) {
        format!("SELECT COUNT(*) AS n FROM pragma_table_info('{table}') WHERE name = 'tenant_id'")
    } else if is_postgres(manager) {
        format!(
            "SELECT COUNT(*) AS n FROM information_schema.columns \
             WHERE table_name = '{table}' AND column_name = 'tenant_id'"
        )
    } else {
        format!(
            "SELECT COUNT(*) AS n FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = '{table}' AND column_name = 'tenant_id'"
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
        // 列已存在（存量库经 AppInitializer 兜底补列）：静默跳过
        return Ok(());
    }
    conn.execute_unprepared(&format!(
        "ALTER TABLE {table} ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 0"
    ))
    .await?;
    Ok(())
}

/// Phase 2 覆盖的 27 张表（甄别理由见文件头）。
const TABLES: &[&str] = &[
    "sys_dept",
    "sys_role",
    "sys_post",
    "sys_config",
    "sys_dict_type",
    "sys_dict_data",
    "sys_notice",
    "sys_notice_read",
    "sys_pat",
    "sys_user_pref",
    "sys_oauth_consent",
    "sys_oauth_provider",
    "sys_oauth_user",
    "sys_msg_channel",
    "sys_msg_template",
    "sys_msg_send_log",
    "sys_web_hook",
    "sys_web_hook_log",
    "sys_report",
    "sys_report_sub",
    "sys_job",
    "sys_job_log",
    "sys_task",
    "sys_backup_log",
    "sys_oper_log",
    "sys_logininfor",
    "sys_frontend_error",
];

/// 大表追加 (tenant_id, <时间列>) 组合索引（租户内按时间检索的高频路径）。
/// 注意各表时间列名不同：sys_oper_log=oper_time、sys_logininfor=login_time、
/// sys_msg_send_log=create_time（列名与实体对齐）。
const BIG_TABLES: &[(&str, &str)] = &[
    ("sys_oper_log", "oper_time"),
    ("sys_logininfor", "login_time"),
    ("sys_msg_send_log", "create_time"),
];

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260925_000001_multitenant_phase2"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. 幂等加列（27 张）
        for table in TABLES {
            ensure_tenant_column(manager, table).await?;
        }

        // 2. 幂等索引：每表单列 tid 索引（租户内数据隔离查询的主路径）
        for table in TABLES {
            manager
                .get_connection()
                .execute_index_ddl_ic(&format!(
                    "CREATE INDEX idx_{table}_tid ON {table} (tenant_id)"
                ))
                .await?;
        }

        // 3. 大表组合索引（租户内时间序检索）
        for (table, time_col) in BIG_TABLES {
            manager
                .get_connection()
                .execute_index_ddl_ic(&format!(
                    "CREATE INDEX idx_{table}_tid_time ON {table} (tenant_id, {time_col})"
                ))
                .await?;
        }

        Ok(())
        // 存量数据迁移：无需回填——所有行 ADD COLUMN 时 DEFAULT 0，
        // 语义即"归平台租户"（立项定案第 3 条）。
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let sqlite_or_pg = is_sqlite(manager) || is_postgres(manager);
        // R-10 首次全量回滚实测（MySQL 1091 Can't DROP 'idx_sys_dept_tid_time'）：
        // 组合索引 `idx_<表>_tid_time` 只在 up() 第 3 段的 BIG_TABLES 三张表上建过，
        // 旧 down() 却对全部 27 张 TABLES 无条件删它 ⇒ 回滚链在 sys_dept 当场中断。
        // 现在删除动作与 up() 的三个分段一一对应：单列 tid 索引↔TABLES、
        // 组合索引↔BIG_TABLES、DROP COLUMN↔TABLES。
        for (table, _time_col) in BIG_TABLES {
            if sqlite_or_pg {
                conn.execute_unprepared(&format!("DROP INDEX IF EXISTS idx_{table}_tid_time"))
                    .await?;
            } else {
                conn.execute_unprepared(&format!("DROP INDEX idx_{table}_tid_time ON {table}"))
                    .await?;
            }
        }
        for table in TABLES {
            // MySQL 无 DROP INDEX IF EXISTS，语法为 DROP INDEX <idx> ON <table>
            if sqlite_or_pg {
                conn.execute_unprepared(&format!("DROP INDEX IF EXISTS idx_{table}_tid"))
                    .await?;
            } else {
                conn.execute_unprepared(&format!("DROP INDEX idx_{table}_tid ON {table}"))
                    .await?;
            }
            conn.execute_unprepared(&format!("ALTER TABLE {table} DROP COLUMN tenant_id"))
                .await?;
        }
        Ok(())
    }
}
