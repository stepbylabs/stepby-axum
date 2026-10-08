// stepby-axum/migration/src/migrations/m20261008_000001_log_archive_anchor.rs
//! 批次十九：oper_log 链感知保留策略（P0 正确性修复 + 归档能力，福哥拍板立项）
//!
//! 背景：防篡改 HMAC 链恒开（state.rs `with_chain`），而 `cleanup_expired_logs`
//! 物理删除 90 天前日志——首次真删即把 verify-chain 打成恒 broken（幸存首行的
//! stored hash 用被删尾行 hash 作前驱计算，verify 起点空种子必不匹配；
//! `find_chained_ascending` 注释自认"任何子集校验都会因缺失前驱而误报断裂"）。
//!
//! 方案：**删除锚点登记**——任何物理删除路径（cleanup job / 手动 clean）删除前，
//! 把被删区间内"最后一个链行"（chain_hash 非 NULL）的边界与 hash 写入锚点表；
//! verify-chain 重算时遇幸存行前驱缺失，用锚点链作 prev 种子续接，链校验语义
//! 从"链首起验"升级为"锚点链 + 幸存链整体重算"，结果分级 valid /
//! valid_with_gap（有清理缺口，锚点续接成功）/ broken（真篡改）。
//!
//! 表 `sys_log_archive_anchor`：
//! - `first_oper_id` / `last_oper_id`：被删区间内**链行**（chain_hash 非 NULL）的
//!   oper_id 边界（verify 只关心链行序列；NULL 行不在链中，删除不影响链）；
//! - `last_chain_hash`：被删段内最后一个链行的 chain_hash（= 幸存续接行的真实前驱）；
//! - `deleted_count`：全行数（含 NULL 行，统计口径）；
//! - `mode`：delete / archive（retention_mode 三档，本批次 P2）；
//! - `archive_object_key`：archive 档导出对象在存储后端的 key（平台租户 0 归属）；
//! - `deleted_at`：删除执行时刻——verify 种子判定需区分"行在删除前已存在（前驱
//!   是被删尾行）"vs"行在删除后写入（写侧续接幸存前驱）"。
//!
//! 多租户与权限（全局铁律第一问）：
//! - 链跨租户全局串联（write 侧不区分租户），锚点即全局链缺口登记——**无租户维度**；
//!   删除路径本身平台视角（cleanup）或带 tenant_scope（手动 clean），行为不变；
//! - 归档数据含全租户日志 = 平台合规数据 → 归档下载端点用新平台专属前缀
//!   `monitor:operlogArchive:`（PLATFORM_ONLY_PERM_PREFIXES 登记，租户授权剔除
//!   机制自动收口），F 按钮 9180/9181（高位段，规避 e2e 动态菜单自增撞号——4180/4181 曾被 e2e 菜单用例占用致 INSERT OR IGNORE 静默失效） 挂操作日志菜单（parent 500）。
//!
//! 存量库兜底：`init_log_archive_anchor`（单一事实源，up() 与 initialize 共用——
//! 建表 IF NOT EXISTS + 种按钮 INSERT IGNORE 三方言幂等）。

use sea_orm_migration::prelude::*;

/// 与 `common::tenant::PLATFORM_ONLY_PERM_PREFIXES` **逐项一致**（12 项，含本批新增的
/// `monitor:operlogArchive:`——审计归档下载，平台专属合规数据）。迁移 crate 无法引用
/// `src` 常量，故显式列出并由单测 `platform_only_prefixes_match_migration_lists`
/// 锁双向一致（LATEST_SRC 指向本迁移）。
const PLATFORM_ONLY_PERM_PREFIXES: &[&str] = &[
    "system:tenant:domain:",
    "system:tenantMenu:",
    "tool:gen:",
    "tool:httpDebug:",
    "monitor:cache:",
    "monitor:log:",
    "monitor:slowSql:",
    "monitor:health:",
    "monitor:operlogArchive:",
    "system:backup:",
    "system:rateLimit:",
    "system:aiConfig:",
];

/// 构造 `perms LIKE '<prefix>%' OR ...` 的条件片段（前缀均来自本文件常量，无注入面）
fn perms_like_clause() -> String {
    PLATFORM_ONLY_PERM_PREFIXES
        .iter()
        .map(|p| format!("perms LIKE '{p}%'"))
        .collect::<Vec<_>>()
        .join(" OR ")
}

/// 建表 + 种按钮 + 平台专属前缀存量剔除（幂等，单一事实源：Migration::up 与
/// initialize 存量库兜底共用）
///
/// 自增主键三方言 DDL 各异（SQLite 要求 INTEGER PRIMARY KEY AUTOINCREMENT、
/// MySQL 用 AUTO_INCREMENT、PG 用 BIGSERIAL），按 backend 分支；索引
/// （idx_log_anchor_last_oper）仅由 Migration::up 创建：锚点表行数 ≈ 清理执行
/// 次数（每次清理 1 行），存量库兜底路径跳过索引无性能影响（MySQL 无 CREATE INDEX
/// IF NOT EXISTS，避免为可忽略的收益引入 information_schema 判存逻辑）。
pub async fn init_log_archive_anchor<C: ConnectionTrait>(db: &C) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let ddl = match backend {
        sea_orm::DatabaseBackend::Sqlite => {
            "CREATE TABLE IF NOT EXISTS sys_log_archive_anchor (
                anchor_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                first_oper_id INTEGER NOT NULL,
                last_oper_id INTEGER NOT NULL,
                last_chain_hash VARCHAR(64) NOT NULL,
                deleted_count INTEGER NOT NULL,
                mode VARCHAR(16) NOT NULL,
                archive_object_key VARCHAR(255) NULL,
                deleted_at TIMESTAMP NOT NULL
            )"
        }
        sea_orm::DatabaseBackend::MySql => {
            "CREATE TABLE IF NOT EXISTS sys_log_archive_anchor (
                anchor_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
                first_oper_id BIGINT NOT NULL,
                last_oper_id BIGINT NOT NULL,
                last_chain_hash VARCHAR(64) NOT NULL,
                deleted_count BIGINT NOT NULL,
                mode VARCHAR(16) NOT NULL,
                archive_object_key VARCHAR(255) NULL,
                deleted_at TIMESTAMP NOT NULL
            )"
        }
        sea_orm::DatabaseBackend::Postgres => {
            "CREATE TABLE IF NOT EXISTS sys_log_archive_anchor (
                anchor_id BIGSERIAL NOT NULL PRIMARY KEY,
                first_oper_id BIGINT NOT NULL,
                last_oper_id BIGINT NOT NULL,
                last_chain_hash VARCHAR(64) NOT NULL,
                deleted_count BIGINT NOT NULL,
                mode VARCHAR(16) NOT NULL,
                archive_object_key VARCHAR(255) NULL,
                deleted_at TIMESTAMP NOT NULL
            )"
        }
        _ => return Err(DbErr::Custom("unsupported database backend".into())),
    };
    db.execute_unprepared(ddl).await?;

    let now = match backend {
        sea_orm::DatabaseBackend::MySql => "NOW()",
        _ => "CURRENT_TIMESTAMP",
    };
    let menus_sql = format!(
        "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
        (9180, '审计归档下载', 500, 4, '#', '', '', '', '1', '0', 'F', '0', '0', 'monitor:operlogArchive:download', '#', 'admin', {now}, '链感知保留：归档对象下载（平台专属，monitor:operlogArchive: 前缀）', '0'), \
        (9181, '链完整性校验', 500, 5, '#', '', '', '', '1', '0', 'F', '0', '0', 'monitor:operlogArchive:verify', '#', 'admin', {now}, '批次十九收尾：verify-chain 收紧平台专属（原复用 monitor:operlog:query，租户可见即泄漏全平台链统计）', '0')"
    );
    let menu_sql = match backend {
        sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {}", menus_sql),
        sea_orm::DatabaseBackend::Postgres => {
            format!("INSERT INTO {} ON CONFLICT DO NOTHING", menus_sql)
        }
        _ => format!("INSERT IGNORE INTO {}", menus_sql),
    };
    db.execute_unprepared(&menu_sql).await?;

    // 平台专属前缀存量剔除（模式对齐 m20260926_000013，幂等 DELETE）：新增前缀
    // `monitor:operlogArchive:` 若曾被误授权给租户角色，启动/迁移期即回收。
    // 对全新库（按钮刚种、无任何角色授权行）为 no-op。
    let clause = perms_like_clause();
    db.execute_unprepared(&format!(
        "DELETE FROM sys_role_menu WHERE role_id = 2 AND menu_id IN \
         (SELECT menu_id FROM sys_menu WHERE del_flag = '0' AND ({clause}))"
    ))
    .await?;
    db.execute_unprepared(&format!(
        "DELETE FROM sys_role_menu WHERE menu_id IN \
         (SELECT menu_id FROM sys_menu WHERE del_flag = '0' AND ({clause})) \
         AND role_id IN (SELECT role_id FROM sys_role WHERE tenant_id <> 0)"
    ))
    .await?;
    Ok(())
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261008_000001_log_archive_anchor"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        init_log_archive_anchor(manager.get_connection()).await?;

        // 清理查询索引（新库迁移路径创建；兜底路径行数极少可跳过，见函数文档）
        manager
            .create_index(
                Index::create()
                    .name("idx_log_anchor_last_oper")
                    .table(Alias::new("sys_log_archive_anchor"))
                    .col(Alias::new("last_oper_id"))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id IN (9180, 9181)")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_log_archive_anchor")
            .await?;
        Ok(())
    }
}
