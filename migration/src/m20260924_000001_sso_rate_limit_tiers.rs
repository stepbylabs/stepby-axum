// stepby-axum/migration/src/m20260924_000001_sso_rate_limit_tiers.rs
//! v5-S1：SSO/OIDC 公开端点限流分档（docs/optimization/topic-sso-multitenant-final-audit-2026-09-23.md §8.1-S1）
//!
//! 背景：SSO 公开端点此前仅由 route_pattern='*' 全局默认档（100 突发 / 10 rps）覆盖，
//! 与业务面共用一档——token 兑换（机器对机器）与 userinfo（RP 每次会话校验都调用）
//! 的流量画像完全不同，分档才能既防滥用又不误伤正常 RP。
//!
//! 初始档位（上线后按 429 率与 RP 实际调用量调整，压测验证属运维动作）：
//! - /sso/token                           30 / 0.5 rps   机器对机器低频兑换，严档防暴力试 secret
//! - /sso/authorize                       60 / 1.0 rps   浏览器整页导航（302 链），中档
//! - /sso/logout                          30 / 0.5 rps   登出低频，严档
//! - /sso/userinfo                       120 / 2.0 rps   RP 高频会话校验，宽于默认
//! - /.well-known/openid-configuration    60 / 1.0 rps   RP 启动期拉取一次，中档
//!
//! 与 '*' 全局档的关系：rate_limit 中间件先按 route_pattern 精确匹配（oper_url 为
//! 纯路径，不含 query），未命中回退 '*'。启用/禁用由 sys_rate_limit.enabled 控制，
//! 运维可在管理页直接调整，无需改代码。
//!
//! 幂等：route_pattern 有唯一索引，INSERT ... WHERE NOT EXISTS 可重复执行；
//! 存量库（启动不跑 Migrator::up）由 AppInitializer::ensure_sso_rate_limit_tiers
//! 以等价 SQL 兜底（见 initialize/mod.rs）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260924_000001_sso_rate_limit_tiers"
    }
}

/// (route_pattern, capacity, refill_per_second, description)
const TIERS: &[(&str, u32, f64, &str)] = &[
    (
        "/sso/token",
        30,
        0.5,
        "SSO 令牌兑换（机器对机器，严档防暴力试 secret）",
    ),
    (
        "/sso/authorize",
        60,
        1.0,
        "SSO 授权端点（浏览器导航，中档）",
    ),
    ("/sso/logout", 30, 0.5, "SSO 登出（低频严档）"),
    (
        "/sso/userinfo",
        120,
        2.0,
        "SSO 用户信息（RP 高频会话校验，宽档）",
    ),
    (
        "/.well-known/openid-configuration",
        60,
        1.0,
        "OIDC 发现文档（RP 启动期拉取，中档）",
    ),
];

fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite
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

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let now = now_expr(manager);
        for (pattern, capacity, refill, description) in TIERS {
            let sql = format!(
                "INSERT INTO sys_rate_limit (route_pattern, capacity, refill_per_second, enabled, description, create_by, create_time, update_by, update_time) \
                 SELECT '{pattern}', {capacity}, {refill}, TRUE, '{description}', 'admin', {now}, 'admin', {now} \
                 WHERE NOT EXISTS (SELECT 1 FROM sys_rate_limit WHERE route_pattern = '{pattern}')"
            );
            conn.execute_unprepared(&sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for (pattern, _, _, _) in TIERS {
            conn.execute_unprepared(&format!(
                "DELETE FROM sys_rate_limit WHERE route_pattern = '{pattern}'"
            ))
            .await?;
        }
        Ok(())
    }
}
