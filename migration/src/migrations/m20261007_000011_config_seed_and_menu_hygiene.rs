//! 批次十四：RBAC 全景审计修复——治理参数项 seed + 菜单数据卫生
//!
//! 三项（均经存量库真值实证）：
//! 1. **`sys.upload.*` 八键 seed**：G-11 注册了治理键但从未在任何迁移 INSERT，
//!    且 `UploadConfigService` 写入是纯 UPDATE ⇒ 所有库缺行、OSS 管理页保存
//!    静默失效（0 行更新不报错，重启回落 config.toml）。本迁移补 seed（值=空串
//!    即"跟随 config.toml 出厂缺省"；治理列 = Locked 三元组）；
//!    存量库由 `initialize::ensure_governance_config_rows` 双写兜底（同值）。
//! 2. **软删域名按钮重复组 3800-3804**：同一能力两套菜单并存（3800-3804 挂租户
//!    管理目录 3700 下、3900-3904 挂平台专属区 3950 下）——域名管理是平台专属
//!    能力，正确位置是 3900 组；3800 组授权已被 3.5h/`m20260926_000006` 剔除
//!    （零 role_menu/零子菜单），软删消除"授权歧义 + 假入口"。
//! 3. **软删 4115（AI 历史查询）**：与 4116 同 perms 冗余按钮行（查询动作=进页面，
//!    无需独立按钮），且存量库该行已被污染为 C 型无 component（visible='0' 显示中
//!    = 点击 404 死入口）。连同清理其 role_menu 残留（role 2）。
//!
//! 幂等：INSERT OR IGNORE / 条件 UPDATE（del_flag 已 '1' 零影响），可重复执行。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000011_config_seed_and_menu_hygiene"
    }
}

/// 幂等 INSERT（方言感知 IGNORE 前后缀，与 m20261007_000002 同构）
fn idempotent_insert(backend: sea_orm::DatabaseBackend, body: &str) -> String {
    match backend {
        sea_orm::DatabaseBackend::Sqlite => format!("INSERT OR IGNORE INTO {body}"),
        sea_orm::DatabaseBackend::Postgres => format!("INSERT INTO {body} ON CONFLICT DO NOTHING"),
        _ => format!("INSERT IGNORE INTO {body}"),
    }
}

/// `sys.upload.*` 八键（键, 显示名）——config_value 恒空串 = 跟随 config.toml 出厂缺省
const UPLOAD_KEYS: &[(&str, &str)] = &[
    (
        "sys.upload.backend",
        "上传存储后端（local/s3 热切换，空=跟随 config.toml）",
    ),
    ("sys.upload.s3.access_key", "S3 AccessKey"),
    ("sys.upload.s3.bucket", "S3 Bucket"),
    ("sys.upload.s3.endpoint", "S3 Endpoint"),
    (
        "sys.upload.s3.path_style",
        "S3 路径风格寻址（true/false，空=跟随 config.toml）",
    ),
    ("sys.upload.s3.public_endpoint", "S3 公开访问前缀"),
    ("sys.upload.s3.region", "S3 Region"),
    ("sys.upload.s3.secret_key", "S3 SecretKey"),
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_connection().get_database_backend();
        let now = match backend {
            sea_orm::DatabaseBackend::Sqlite => {
                format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
            }
            _ => "NOW()".to_string(),
        };

        // 1. sys.upload.* 八键（治理列 = Coverage::Locked 三元组，对齐 governance 注册表）
        for (key, name) in UPLOAD_KEYS {
            let sql = idempotent_insert(
                backend,
                &format!(
                    "sys_config (config_name, config_key, config_value, config_type, create_by, \
                     create_time, remark, scope, tenant_editable, visible_to_tenant) VALUES \
                     ('{name}', '{key}', '', 'Y', 'admin', {now}, \
                     'G-11 OSS 凭据动态化（治理注册表 seed）', 'platform_only', '0', '0')"
                ),
            );
            manager.get_connection().execute_unprepared(&sql).await?;
        }

        // 2. 软删域名按钮重复组 3800-3804（正确位置 = 平台专属区 3900-3904）
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET del_flag = '1' \
                 WHERE menu_id BETWEEN 3800 AND 3804 AND del_flag = '0'",
            )
            .await?;

        // 3. 软删 4115 冗余死页面 + 清理 role_menu 残留
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET del_flag = '1' \
                 WHERE menu_id = 4115 AND del_flag = '0'",
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_role_menu WHERE menu_id = 4115")
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM sys_config WHERE config_key LIKE 'sys.upload.%'")
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET del_flag = '0' \
                 WHERE menu_id BETWEEN 3800 AND 3804 OR menu_id = 4115",
            )
            .await?;
        Ok(())
    }
}
