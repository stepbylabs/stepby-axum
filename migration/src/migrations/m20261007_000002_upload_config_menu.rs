//! G-11 OSS 存储配置管理页菜单（P3 审计项，方案深审 2026-10-06）
//!
//! - menu_id 4103：`uploadConfig` 平台专属管理页（对齐 4102 AI 助手配置范式）；
//! - perms `system:uploadConfig:edit` 与 `middleware/permission.rs` 的
//!   fail-closed 映射逐条对应（GET/PUT/test 三端点共用单权限模型）；
//! - 超管（role_id=1）经 isAdmin 特判拥有全部 perms，无需 role_menu 授权行；
//! - 存量库兜底：initialize 侧幂等 seed（同构 SQL）。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000002_upload_config_menu"
    }
}

/// 幂等 INSERT（方言感知 IGNORE 前后缀，与 m20261006_000001 同构）
fn idempotent_insert(backend: sea_orm::DatabaseBackend, body: &str) -> String {
    match backend {
        sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {body}"),
        sea_orm::DatabaseBackend::Postgres => format!("INSERT INTO {body} ON CONFLICT DO NOTHING"),
        _ => format!("INSERT IGNORE INTO {body}"),
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let now_expr = match manager.get_connection().get_database_backend() {
            sea_orm::DatabaseBackend::Sqlite => {
                format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
            }
            _ => "NOW()".to_string(),
        };
        let backend = manager.get_connection().get_database_backend();
        let menu_sql = idempotent_insert(
            backend,
            &format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                (4103, 'OSS 存储配置', 1, 15, 'uploadConfig', 'system/uploadConfig/index', '', '', '1', '0', 'C', '0', '0', 'system:uploadConfig:edit', 'upload', 'admin', {now_expr}, 'OSS 凭据动态化管理（平台专属；仅 backend=s3 档生效）', '0')"
            ),
        );
        manager
            .get_connection()
            .execute_unprepared(&menu_sql)
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_menu WHERE menu_id = 4103")
            .await?;
        Ok(())
    }
}
