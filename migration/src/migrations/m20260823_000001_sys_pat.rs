// stepby-axum/migration/src/m20260823_000001_sys_pat.rs
//! Tier-S #3：个人访问令牌（PAT）模块迁移
//!
//! 1. 建表 sys_pat（跨 sqlite/postgres/mysql 兼容，幂等 CREATE TABLE IF NOT EXISTS）：
//!    - pat_id        令牌 ID（应用生成 uuid hex，主键，非自增）
//!    - user_id       属主用户 ID
//!    - name          令牌名称
//!    - token_hash    令牌明文 SHA-256 hex（唯一，鉴权查库）
//!    - token_prefix  展示前缀
//!    - scopes        权限范围 JSON 数组
//!    - status        '0' 有效 / '1' 已吊销
//!    - expires_at    过期时间（NULL=永不过期）
//!    - last_used_at  最近使用时间
//!    - create_by / create_time / update_time
//! 2. 索引：user_id（列表）、token_hash（鉴权，唯一）。
//! 3. 菜单：C 页面「API 令牌」(monitor/pat/index, perms=monitor:pat:list) + F 按钮「吊销」
//!    (perms=monitor:pat:revoke)，挂系统监控目录（parent_id=2），授予 role_id=2（超管 role_key=admin
//!    由 get_menu_tree_by_user_id 短路可见全部菜单，无需显式授权）。

use sea_orm_migration::prelude::*;

pub struct Migration;

fn is_sqlite(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Sqlite
    )
}

fn is_postgres(manager: &SchemaManager<'_>) -> bool {
    matches!(
        manager.get_connection().get_database_backend(),
        sea_orm_migration::sea_orm::DatabaseBackend::Postgres
    )
}

fn now_expr(manager: &SchemaManager<'_>) -> String {
    if is_sqlite(manager) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        format!("'{}'", now)
    } else {
        "NOW()".to_string()
    }
}

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
        "m20260823_000001_sys_pat"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. 建表（pat_id 用 VARCHAR/TEXT 主键，跨方言可移植，避免自增差异）
        let (dt, text) = if is_postgres(manager) {
            ("TIMESTAMP", "TEXT")
        } else {
            ("DATETIME", "TEXT")
        };
        let create_sql = format!(
            "CREATE TABLE IF NOT EXISTS sys_pat (
                pat_id       VARCHAR(64) NOT NULL PRIMARY KEY,
                user_id      BIGINT NOT NULL,
                name         VARCHAR(100) NOT NULL,
                token_hash   VARCHAR(64) NOT NULL,
                token_prefix VARCHAR(24) NOT NULL,
                scopes       {text} NOT NULL,
                status       VARCHAR(1) NOT NULL DEFAULT '0',
                expires_at   {dt} NULL,
                last_used_at {dt} NULL,
                create_by    VARCHAR(64) DEFAULT '',
                create_time  {dt} NULL,
                update_time  {dt} NULL
            )"
        );
        manager
            .get_connection()
            .execute_unprepared(&create_sql)
            .await?;

        // 2. 索引（token_hash 唯一用于鉴权；user_id 用于列表）
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("uk_sys_pat_token_hash")
                    .unique()
                    .table(Alias::new("sys_pat"))
                    .col(Alias::new("token_hash"))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_sys_pat_user_id")
                    .table(Alias::new("sys_pat"))
                    .col(Alias::new("user_id"))
                    .to_owned(),
            )
            .await?;

        // 3. 菜单：C 页面 + F 吊销按钮
        const PAGE_MENU_ID: i64 = 3560;
        const BTN_MENU_ID: i64 = 3561;
        const PARENT_DIR_ID: i64 = 2; // 系统监控目录
        let now = now_expr(manager);

        let page_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES \
            ({PAGE_MENU_ID}, 'API 令牌', {PARENT_DIR_ID}, 11, 'pat', 'monitor/pat/index', '', '', '1', '0', 'C', '0', '0', 'monitor:pat:list', 'key', 'admin', {now}, '个人访问令牌统一管理（查看 / 吊销）', '0', 'menu.pat')"
        );
        execute_idempotent_insert(manager, &page_sql).await?;
        execute_idempotent_insert(
            manager,
            &format!("sys_role_menu (role_id, menu_id) VALUES (2, {PAGE_MENU_ID})"),
        )
        .await?;

        let btn_sql = format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES \
            ({BTN_MENU_ID}, '吊销', {PAGE_MENU_ID}, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'monitor:pat:revoke', 'delete', 'admin', {now}, '吊销指定用户的访问令牌', '0', '')"
        );
        execute_idempotent_insert(manager, &btn_sql).await?;
        execute_idempotent_insert(
            manager,
            &format!("sys_role_menu (role_id, menu_id) VALUES (2, {BTN_MENU_ID})"),
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        const PAGE_MENU_ID: i64 = 3560;
        const BTN_MENU_ID: i64 = 3561;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_role_menu WHERE menu_id IN ({PAGE_MENU_ID}, {BTN_MENU_ID})"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared(&format!(
                "DELETE FROM sys_menu WHERE menu_id IN ({PAGE_MENU_ID}, {BTN_MENU_ID})"
            ))
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS sys_pat")
            .await?;
        Ok(())
    }
}
