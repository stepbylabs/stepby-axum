// stepby-axum/migration/src/migrations/m20261006_000001_ai_config_and_history.rs
//! AI-01/AI-02（§5.39 设计文档 ai01-02-design-2026-10-06.md，福哥已拍板四项）：
//!
//! 1. `sys_config` 种子 `sys.ai.*` 6 键（幂等 INSERT，不 UPDATE——尊重管理员已改值）：
//!    enabled(false) / provider(openai) / base_url('') / api_key('') /
//!    model(gpt-4o-mini) / allowed_tables(内置 7 表)。
//!    **双源语义**：config.toml `[ai]` 段为出厂缺省；`sys.ai.*` 键存在即覆盖
//!    （启动后以管理页/sys_config 为准，改 [ai] 需先清空对应键——运维口径见
//!    config.toml.example [ai] 段注释）。
//! 2. `ai_chat_history` 建表（AI-02 查询历史持久化；SchemaManager 自动三方言）。
//!
//! ## 口径
//!
//! - config 种子仅幂等 INSERT（`INSERT OR IGNORE` 三方言）；
//! - `pub fn` 供 `initialize/mod.rs` 兜底引用（单一事实源，对齐 B4 迁移先例）。

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::Statement;
use sea_orm_migration::sea_orm::DatabaseConnection;

/// initialize/mod.rs 存量库兜底入口（包装 SchemaManager，主 crate 无需直接依赖
/// sea-orm-migration）：建 ai_chat_history 表 + `sys.ai.*` 六键幂等种子。
pub async fn init_ai_config_and_history(db: &DatabaseConnection) -> Result<(), DbErr> {
    let manager = SchemaManager::new(db);
    create_ai_chat_history(&manager).await?;
    let now = match manager.get_connection().get_database_backend() {
        sea_orm::DatabaseBackend::MySql => "NOW()",
        _ => "CURRENT_TIMESTAMP",
    };
    for body in ai_config_seed_bodies(now) {
        let sql = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {}", body),
            sea_orm::DatabaseBackend::Postgres => format!("INSERT INTO {} ON CONFLICT DO NOTHING", body),
            _ => format!("INSERT IGNORE INTO {}", body),
        };
        manager.get_connection().execute_unprepared(&sql).await?;
    }
    Ok(())
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261006_000001_ai_config_and_history"
    }
}

/// `sys.ai.*` 六键（迁移与 initialize 兜底共用单一事实源）
pub const AI_CONFIG_SEEDS: &[(&str, &str, &str)] = &[
    (
        "sys.ai.enabled",
        "false",
        "AI 助手总开关（平台层；关闭时 /ai/* 一律 403）",
    ),
    (
        "sys.ai.provider",
        "openai",
        "LLM 提供方（OpenAI 兼容协议：OpenAI/DeepSeek/Ollama/vLLM）",
    ),
    ("sys.ai.base_url", "", "OpenAI 兼容 base_url"),
    ("sys.ai.api_key", "", "API Key（管理页保存时信封加密存储）"),
    ("sys.ai.model", "gpt-4o-mini", "模型名"),
    (
        "sys.ai.allowed_tables",
        "sys_user,sys_dept,sys_role,sys_post,sys_config,sys_dict_type,sys_dict_data",
        "AI 可查询表白名单（逗号分隔）",
    ),
];

/// 幂等检查表是否存在（三方言；对齐 has_column 同款口径）
async fn has_table(manager: &SchemaManager<'_>, table: &str) -> Result<bool, DbErr> {
    let conn = manager.get_connection();
    let backend = conn.get_database_backend();
    match backend {
        sea_orm::DatabaseBackend::Sqlite => {
            let rows = conn
                .query_all(Statement::from_string(
                    backend,
                    format!("SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'"),
                ))
                .await?;
            Ok(!rows.is_empty())
        }
        _ => {
            let schema = if backend == sea_orm::DatabaseBackend::Postgres {
                "table_schema=current_schema()"
            } else {
                "table_schema=DATABASE()"
            };
            let rows = conn
                .query_all(Statement::from_string(
                    backend,
                    format!(
                        "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND {schema} LIMIT 1"
                    ),
                ))
                .await?;
            Ok(!rows.is_empty())
        }
    }
}

/// ai_chat_history 建表语句体（迁移与 initialize 兜底共用；三方言由
/// SchemaManager create_table 自动适配，勿手写 AUTOINCREMENT 差异）
pub async fn create_ai_chat_history(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // §5.45 修复：兜底段在存量库执行时表已存在（迁移建过）——幂等跳过，
    // 否则 CREATE TABLE 报 already exists 导致启动失败
    if has_table(manager, "ai_chat_history").await? {
        return Ok(());
    }
    manager
        .create_table(
            Table::create()
                .table(Alias::new("ai_chat_history"))
                .col(
                    ColumnDef::new(Alias::new("id"))
                        .big_integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(ColumnDef::new(Alias::new("tenant_id")).big_integer().not_null())
                .col(ColumnDef::new(Alias::new("user_id")).big_integer().not_null())
                .col(
                    ColumnDef::new(Alias::new("question"))
                        .string_len(1000)
                        .not_null(),
                )
                .col(ColumnDef::new(Alias::new("sql_text")).text().not_null())
                .col(
                    ColumnDef::new(Alias::new("tables_used"))
                        .string_len(500)
                        .not_null(),
                )
                .col(ColumnDef::new(Alias::new("columns_json")).text())
                .col(
                    ColumnDef::new(Alias::new("rows_count"))
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Alias::new("duration_ms"))
                        .big_integer()
                        .not_null(),
                )
                .col(ColumnDef::new(Alias::new("success")).char_len(1).not_null())
                .col(ColumnDef::new(Alias::new("error_msg")).string_len(500))
                .col(ColumnDef::new(Alias::new("create_time")).date_time().not_null())
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx_ai_hist_tenant_user")
                .table(Alias::new("ai_chat_history"))
                .col(Alias::new("tenant_id"))
                .col(Alias::new("user_id"))
                .col(Alias::new("id"))
                .to_owned(),
        )
        .await
}

/// `sys.ai.*` 六键的幂等 INSERT 语句体（迁移与 initialize 兜底共用）。
/// config_id 从 9030 起（9010 已被 B4 强改开关占用）。
pub fn ai_config_seed_bodies(now_expr: &str) -> Vec<String> {
    let specs: [(i64, &str, &str, &str); 6] = [
        (9030, "AI 助手总开关", "sys.ai.enabled", "false"),
        (9031, "AI LLM 提供方", "sys.ai.provider", "openai"),
        (9032, "AI base_url", "sys.ai.base_url", ""),
        (9033, "AI API Key", "sys.ai.api_key", ""),
        (9034, "AI 模型名", "sys.ai.model", "gpt-4o-mini"),
        (9035, "AI 可查询表白名单", "sys.ai.allowed_tables", "sys_user,sys_dept,sys_role,sys_post,sys_config,sys_dict_type,sys_dict_data"),
    ];
    specs
        .iter()
        .map(|(id, name, key, value)| {
            format!(
                "sys_config (config_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
                ({id}, '{name}', '{key}', '{value}', 'Y', 'admin', {now_expr}, 'AI 助手配置（管理页可改，热生效）')"
            )
        })
        .collect()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "NOW()".to_string(),
            _ => "CURRENT_TIMESTAMP".to_string(),
        };
        create_ai_chat_history(manager).await?;
        for body in ai_config_seed_bodies(&now) {
            let sql = match manager.get_connection().get_database_backend() {
                sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {}", body),
                sea_orm::DatabaseBackend::Postgres => {
                    format!("INSERT INTO {} ON CONFLICT DO NOTHING", body)
                }
                _ => format!("INSERT IGNORE INTO {}", body),
            };
            manager.get_connection().execute_unprepared(&sql).await?;
        }
        // AI-01 管理页菜单（platform-only；perms 契约测试要求后端 perms ⊆ sys_menu.perms）
        // 超管（role_id=1）经 isAdmin 特判拥有全部 perms，无需 role_menu 授权行
        let menus_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
            (4102, 'AI 助手配置', 1, 14, 'aiConfig', 'system/aiConfig/index', '', '', '1', '0', 'C', '0', '0', 'system:aiConfig:edit', 'ai', 'admin', {now}, 'AI 助手 LLM 接入配置（平台专属）', '0'), \
            (4115, 'AI 历史查询', 120, 2, '#', '', '', '', '1', '0', 'F', '0', '0', 'monitor:aiHistory:list', '#', 'admin', {now}, 'AI 问数历史管理视图（审计大屏域）', '0'), \
            (4116, 'AI 问数历史', 120, 3, 'aiHistory', 'monitor/aiHistory/index', '', '', '1', '0', 'C', '0', '0', 'monitor:aiHistory:list', 'history', 'admin', {now}, 'AI 问数历史管理视图（平台跨租户/租户管理员本租户）', '0')"
        );
        let menu_sql = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {}", menus_sql),
            sea_orm::DatabaseBackend::Postgres => format!("INSERT INTO {} ON CONFLICT DO NOTHING", menus_sql),
            _ => format!("INSERT IGNORE INTO {}", menus_sql),
        };
        manager
            .get_connection()
            .execute_unprepared(&menu_sql)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (_, key, _) in AI_CONFIG_SEEDS {
            manager
                .get_connection()
                .execute_unprepared(&format!("DELETE FROM sys_config WHERE config_key = '{key}'"))
                .await?;
        }
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS ai_chat_history")
            .await?;
        Ok(())
    }
}

// 让 AI_CONFIG_SEEDS 不产生 dead_code 警告（down 未引用它，引用的是字面量循环）
#[allow(dead_code)]
fn _seed_reference() {
    let _ = AI_CONFIG_SEEDS;
}
