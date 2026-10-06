// stepby-axum/migration/src/migrations/m20261003_000004_webhook_unify.rs
//! WebHook 订阅双轨合并（方案 C）——数据收敛迁移：
//!
//! 将存量 `sys_web_hook.event_types`（逗号分隔事件串；空串 = 订阅全部）转换为
//! 新口径 `subscribed_events`（JSON 数组字符串；NULL/空 = 订阅全部）：
//! - 仅处理 `subscribed_events IS NULL` 且 `event_types` 非空的行（幂等：重复执行无害）；
//! - 逗号拆分为数组元素，并应用**存量事件名映射表**（见 [`LEGACY_EVENT_KEY_MAP`]）：
//!   `login_success` / `login` → `login.success`、`login_failure` / `login_fail` /
//!   `login_failed` → `login.failed`；不在映射表中的元素（如 `scim_user_provisioned`
//!   或用户自定义串）**原样保留**（匹配大小写不敏感，行为与旧口径等价）；
//! - `event_types` 为空串/全空白 → 保持 `subscribed_events` NULL（= 订阅全部，
//!   与旧口径「空 = 全部」语义一致，零行为变化）；
//! - 整串先 `LOWER` 后映射（事件名均为 ASCII；新口径匹配大小写不敏感，小写化无损）。
//!
//! ## 转换算法（三方言同构）
//!
//! 1. `base   = TRIM(LOWER(COALESCE(event_types, '')))`
//! 2. `base   = REPLACE(REPLACE(base, ', ', ','), ' ,', ',')`（SQLite 无多参 TRIM，
//!    用嵌套 REPLACE 处理元素两侧空格；MySQL/PG 同式，语义与逐元素 TRIM 等价）
//! 3. `wrapped = ',' || base || ','`（MySQL 用 CONCAT；首尾加逗号形成「整段边界」，
//!    保证后续按 `,key,` 整段替换不会误伤含 `login` 子串的自定义事件名如 `my_login`）
//! 4. 对映射表逐项 `REPLACE(wrapped, ',key,', ',value,')`
//! 5. `inner  = SUBSTR(mapped, 2, LENGTH(mapped) - 2)`（MySQL 用 SUBSTRING/CHAR_LENGTH）
//! 6. `subscribed_events = '["' || REPLACE(inner, ',', '","') || '"]'`
//!
//! 例：`event_types = ' login , my_event '` → `["login.success","my_event"]`。
//!
//! ## 口径
//!
//! 与既有迁移同款：幂等（只 UPDATE `subscribed_events IS NULL` 的行；表/列存在性检查）。
//! `initialize/mod.rs` 兜底片段（存量库不跑 Migrator::up）由集成方追加，见交付报告：
//! 兜底直接复用本文件 [`build_unify_update_sql`] 产出的同款 SQL（单一事实源）。

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::{DatabaseBackend, Statement};

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261003_000004_webhook_unify"
    }
}

/// 存量事件名 → 事件目录 event_key 映射表（单一事实源之一）。
///
/// 与 `src/service/sys_web_hook_service.rs` 的 `LEGACY_EVENT_KEY_MAP` **必须保持一致**
///（集成测试 `webhook_unify.rs` 双向断言两份表相等，防漂移）。
///
/// 盘点来源（dispatch_event 全部调用点）：
/// - auth_handler（登录成功/失败，方案 C 已删除双发）→ `login_success` / `login_failure`；
/// - webauthn_handler（WebAuthn 登录成功/失败）→ 同上两个常量；
/// - scim_handler（provision/deactivate/group）→ `scim_*` 四常量，**不在目录**，不映射
///   （原样保留，按原事件名在新列上匹配，语义与旧口径等价）。
/// - 另宽容收录存量用户可能手写的变体：`login` / `login_fail` / `login_failed`。
pub const LEGACY_EVENT_KEY_MAP: &[(&str, &str)] = &[
    ("login", "login.success"),
    ("login_success", "login.success"),
    ("login_failure", "login.failed"),
    ("login_fail", "login.failed"),
    ("login_failed", "login.failed"),
];

/// 生成「存量 event_types → subscribed_events JSON 数组」的幂等 UPDATE SQL。
///
/// 三方言适配点：字符串连接（MySQL 无 `||`，用 CONCAT）、子串/长度（MySQL TEXT 用
/// CHAR_LENGTH，其余 LENGTH）、其余（TRIM/LOWER/COALESCE/REPLACE）三方言同构。
/// 供本迁移与集成测试（webhook_unify.rs）共用，保证兜底片段与迁移 SQL 单一事实源。
pub fn build_unify_update_sql(backend: DatabaseBackend) -> String {
    let is_mysql = backend == DatabaseBackend::MySql;
    // 方言适配：字符串拼接与字符长度（事件名 ASCII，LENGTH 与 CHAR_LENGTH 等价；
    // 自定义元素可能含多字节，MySQL 统一用 CHAR_LENGTH 保险）
    let concat = |parts: &[&str]| -> String {
        if is_mysql {
            format!("CONCAT({})", parts.join(", "))
        } else {
            parts.join(" || ")
        }
    };
    let char_len = |expr: &str| -> String {
        if is_mysql {
            format!("CHAR_LENGTH({expr})")
        } else {
            format!("LENGTH({expr})")
        }
    };
    let substr2 = |expr: &str| -> String {
        if is_mysql {
            format!("SUBSTRING({expr}, 2, {} - 2)", char_len(expr))
        } else {
            format!("SUBSTR({expr}, 2, {} - 2)", char_len(expr))
        }
    };

    // 1-2. 归一化：小写 + 去首尾空白 + 去元素两侧空格（SQLite 无多参 TRIM，嵌套 REPLACE）
    let base = "TRIM(LOWER(COALESCE(event_types, '')))";
    let normalized = format!("REPLACE(REPLACE({base}, ', ', ','), ' ,', ',')");
    // 3. 首尾加逗号形成整段边界（防 `,login,` 误伤 `my_login` 等含子串的自定义名）
    let wrapped = concat(&["','", &normalized, "','"]);
    // 4. 逐项整段替换映射（长键在前保险；各模式整段互斥，顺序实际无影响）
    let mut mapped = wrapped;
    for (legacy, canonical) in LEGACY_EVENT_KEY_MAP {
        mapped = format!("REPLACE({mapped}, ',{legacy},', ',{canonical},')");
    }
    // 5-6. 去包裹逗号 → 逗号串转 JSON 数组字符串（'["' + REPLACE(inner, ',', '","') + '"]'）
    let inner = substr2(&mapped);
    let json = concat(&["'[\"'", &format!("REPLACE({inner}, ',', '\",\"')"), "'\"]'"]);

    format!(
        "UPDATE sys_web_hook SET subscribed_events = {json} \
         WHERE subscribed_events IS NULL \
           AND TRIM(COALESCE(event_types, '')) <> ''"
    )
}

/// 幂等检查表是否存在（三方言）
async fn table_exists(manager: &SchemaManager<'_>, table: &str) -> Result<bool, DbErr> {
    let conn = manager.get_connection();
    let backend = conn.get_database_backend();
    let sql = match backend {
        DatabaseBackend::Sqlite => {
            format!("SELECT 1 FROM sqlite_master WHERE type='table' AND name='{table}'")
        }
        DatabaseBackend::Postgres => format!(
            "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema=current_schema() LIMIT 1"
        ),
        DatabaseBackend::MySql => format!(
            "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema=DATABASE() LIMIT 1"
        ),
        _ => unreachable!("unknown backend"),
    };
    Ok(!conn
        .query_all_raw(Statement::from_string(backend, sql))
        .await?
        .is_empty())
}

/// 幂等检查列是否存在（三方言）
async fn has_column(
    manager: &SchemaManager<'_>,
    table: &str,
    column: &str,
) -> Result<bool, DbErr> {
    let conn = manager.get_connection();
    let backend = conn.get_database_backend();
    let rows = match backend {
        DatabaseBackend::Sqlite => {
            conn.query_all_raw(Statement::from_string(
                backend,
                format!("PRAGMA table_info({table})"),
            ))
            .await?
        }
        _ => {
            let schema = if backend == DatabaseBackend::Postgres {
                "table_schema=current_schema()"
            } else {
                "table_schema=DATABASE()"
            };
            conn.query_all_raw(Statement::from_string(
                backend,
                format!(
                    "SELECT 1 FROM information_schema.columns WHERE table_name='{table}' AND column_name='{column}' AND {schema} LIMIT 1"
                ),
            ))
            .await?
        }
    };
    if backend == DatabaseBackend::Sqlite {
        Ok(rows.iter().any(|row| {
            row.try_get::<String>("", "name")
                .map(|n| n.eq_ignore_ascii_case(column))
                .unwrap_or(false)
        }))
    } else {
        Ok(!rows.is_empty())
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 前置：sys_web_hook 表 + subscribed_events / event_types 两列齐备才收敛
        //（缺列说明订阅双轨特性尚未落地，无存量数据可收敛，跳过保持幂等）
        if !table_exists(manager, "sys_web_hook").await? {
            return Ok(());
        }
        if !has_column(manager, "sys_web_hook", "subscribed_events").await?
            || !has_column(manager, "sys_web_hook", "event_types").await?
        {
            return Ok(());
        }
        let backend = manager.get_connection().get_database_backend();
        let sql = build_unify_update_sql(backend);
        manager.get_connection().execute_unprepared(&sql).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 数据收敛不可逆（原逗号串已小写化 + 映射改写）；event_types 影子列原值仍在，
        // 这里仅清空新列回退到「NULL = 订阅全部」的兼容态，行为无损。
        if !table_exists(manager, "sys_web_hook").await? {
            return Ok(());
        }
        manager
            .get_connection()
            .execute_unprepared("UPDATE sys_web_hook SET subscribed_events = NULL")
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SQLite 方言 SQL 应命中典型形态（文本断言，真实行为由集成测试覆盖）
    #[test]
    fn build_sql_sqlite_contains_mapping_chain() {
        let sql = build_unify_update_sql(DatabaseBackend::Sqlite);
        assert!(sql.contains("UPDATE sys_web_hook SET subscribed_events"));
        assert!(sql.contains("subscribed_events IS NULL"));
        // 映射链：每个映射键都应出现整段替换模式
        for (legacy, canonical) in LEGACY_EVENT_KEY_MAP {
            assert!(
                sql.contains(&format!("',{legacy},'")),
                "SQL 应包含 {legacy} 映射模式: {sql}"
            );
            assert!(
                sql.contains(&format!("',{canonical},'")),
                "SQL 应包含 {canonical} 目标模式: {sql}"
            );
        }
    }

    /// MySQL 方言应使用 CONCAT/CHAR_LENGTH/SUBSTRING（无 `||` 拼接）
    #[test]
    fn build_sql_mysql_uses_concat() {
        let sql = build_unify_update_sql(DatabaseBackend::MySql);
        assert!(sql.contains("CONCAT("));
        assert!(sql.contains("CHAR_LENGTH("));
        assert!(sql.contains("SUBSTRING("));
        assert!(!sql.contains(" || "), "MySQL 不应使用 || 拼接: {sql}");
    }
}
