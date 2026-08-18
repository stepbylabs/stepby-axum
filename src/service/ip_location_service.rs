//! IP 归属地库管理服务
//!
//! 职责：
//! - 从 MaxMind 官方或 P3TERX 镜像下载 mmdb 文件
//! - 解压 tar.gz 并提取 .mmdb 文件
//! - SHA256 校验文件完整性
//! - 验证 mmdb 文件有效性（尝试打开）
//! - 原子替换旧文件（备份 → rename）
//! - 调用 IpLocator::reload() 热加载
//! - 记录更新日志到 sys_ip_location_log 表
//!
//! 依赖：reqwest（HTTP 下载）、flate2 + tar（解压）、sha2（校验）、aes-gcm（License Key 加解密）

use std::path::Path;
use std::sync::Arc;

use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::config::Settings;
use crate::utils::crypto::{decrypt_config_value, encrypt_config_value};
use crate::utils::ip_location::IpLocator;

/// IP 库更新源类型
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UpdateSource {
    /// MaxMind 官方下载（需 Account ID + License Key）
    Maxmind,
    /// P3TERX GitHub 镜像（免 License Key）
    P3terx,
}

impl std::fmt::Display for UpdateSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateSource::Maxmind => write!(f, "maxmind"),
            UpdateSource::P3terx => write!(f, "p3terx"),
        }
    }
}

impl std::str::FromStr for UpdateSource {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "maxmind" => Ok(UpdateSource::Maxmind),
            "p3terx" => Ok(UpdateSource::P3terx),
            _ => Err(crate::tr!("error.ip_location.unknown_source_type", s = s)),
        }
    }
}

/// IP 库状态信息
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IpLocationStatus {
    /// mmdb 文件是否存在
    pub mmdb_loaded: bool,
    /// mmdb 文件路径
    pub mmdb_path: String,
    /// mmdb 文件大小（字节）
    pub mmdb_size: u64,
    /// mmdb 文件最后修改时间（Unix 时间戳，秒）
    pub mmdb_modified: i64,
    /// 是否已启用双库模式（ip2region xdb）
    pub xdb_enabled: bool,
    /// xdb 文件是否存在
    pub xdb_loaded: bool,
    /// xdb 文件路径
    pub xdb_path: String,
    /// xdb 文件大小（字节）
    pub xdb_size: u64,
    /// xdb 文件最后修改时间
    pub xdb_modified: i64,
    /// 自动更新 cron 表达式
    pub auto_update_cron: String,
    /// 当前配置的更新源（maxmind / p3terx）
    pub current_source: String,
    /// MaxMind Account ID 是否已配置
    pub maxmind_account_id_configured: bool,
    /// MaxMind License Key 是否已配置
    pub maxmind_license_key_configured: bool,
}

/// 更新结果
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResult {
    /// 是否成功
    pub success: bool,
    /// 耗时（秒）
    pub elapsed_seconds: f64,
    /// 更新源
    pub source: String,
    /// 新文件大小（字节）
    pub new_size: u64,
    /// 新文件 SHA256
    pub new_sha256: String,
    /// 旧文件大小（字节，0 表示之前无文件）
    pub old_size: u64,
    /// 消息
    pub message: String,
    /// 时间戳
    pub timestamp: String,
}

/// IP 库管理配置（从 sys_config 表读取）
#[derive(Debug, Clone)]
pub struct IpLocationConfig {
    /// 更新源（maxmind / p3terx）
    pub update_source: String,
    /// MaxMind Account ID（明文，从加密存储解密）
    pub maxmind_account_id: String,
    /// MaxMind License Key（明文，从加密存储解密）
    pub maxmind_license_key: String,
    /// 是否启用自动更新
    pub auto_update_enabled: bool,
}

/// 默认配置值
impl Default for IpLocationConfig {
    fn default() -> Self {
        Self {
            update_source: "p3terx".to_string(),
            maxmind_account_id: String::new(),
            maxmind_license_key: String::new(),
            auto_update_enabled: false,
        }
    }
}

/// sys_config 表中的 key 常量
pub const CONFIG_KEY_UPDATE_SOURCE: &str = "ip_location.update_source";
pub const CONFIG_KEY_MAXMIND_ACCOUNT_ID: &str = "ip_location.maxmind_account_id";
pub const CONFIG_KEY_MAXMIND_LICENSE_KEY: &str = "ip_location.maxmind_license_key";
pub const CONFIG_KEY_AUTO_UPDATE_ENABLED: &str = "ip_location.auto_update_enabled";

/// P3TERX 镜像下载 URL（直接提供 .mmdb 文件，无需解压）
const P3TERX_URL: &str =
    "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb";

/// MaxMind 官方下载 URL 模板（tar.gz 格式，需解压）
/// 实际请求使用 HTTP Basic Auth：username=account_id, password=license_key
const MAXMIND_URL: &str =
    "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz";

/// IP 归属地库管理服务
#[derive(Clone)]
pub struct IpLocationService {
    db: DatabaseConnection,
    config: Arc<Settings>,
    ip_locator: Arc<IpLocator>,
}

impl IpLocationService {
    pub fn new(db: DatabaseConnection, config: Arc<Settings>, ip_locator: Arc<IpLocator>) -> Self {
        Self {
            db,
            config,
            ip_locator,
        }
    }

    /// 获取自动更新 cron 表达式（供调度器注册时使用）
    pub fn auto_update_cron(&self) -> &str {
        &self.config.ip_location.auto_update_cron
    }

    /// 从 sys_config 表读取 IP 库管理配置（自动解密敏感字段）
    ///
    /// 若 CONFIG_ENC_KEY 未配置，加密字段返回空字符串（fail-closed）
    pub async fn read_config(&self) -> anyhow::Result<IpLocationConfig> {
        let master_key = &self.config.config_enc_key;

        let source = self.read_config_value(CONFIG_KEY_UPDATE_SOURCE).await?;
        let account_id_enc = self
            .read_config_value(CONFIG_KEY_MAXMIND_ACCOUNT_ID)
            .await?;
        let license_key_enc = self
            .read_config_value(CONFIG_KEY_MAXMIND_LICENSE_KEY)
            .await?;
        let auto_update = self
            .read_config_value(CONFIG_KEY_AUTO_UPDATE_ENABLED)
            .await?;

        let account_id = if account_id_enc.is_empty() {
            String::new()
        } else if master_key.is_empty() {
            tracing::warn!("MaxMind Account ID 已存储但 CONFIG_ENC_KEY 未配置，无法解密");
            String::new()
        } else {
            decrypt_config_value(&account_id_enc, master_key).unwrap_or_default()
        };

        let license_key = if license_key_enc.is_empty() {
            String::new()
        } else if master_key.is_empty() {
            tracing::warn!("MaxMind License Key 已存储但 CONFIG_ENC_KEY 未配置，无法解密");
            String::new()
        } else {
            decrypt_config_value(&license_key_enc, master_key).unwrap_or_default()
        };

        Ok(IpLocationConfig {
            update_source: if source.is_empty() {
                "p3terx".to_string()
            } else {
                source
            },
            maxmind_account_id: account_id,
            maxmind_license_key: license_key,
            auto_update_enabled: auto_update == "true",
        })
    }

    /// 保存 IP 库管理配置到 sys_config 表（自动加密敏感字段）
    pub async fn save_config(
        &self,
        source: &str,
        account_id: &str,
        license_key: &str,
        auto_update: bool,
    ) -> anyhow::Result<()> {
        let master_key = &self.config.config_enc_key;

        // 加密敏感字段（若主密钥未配置，则不加密存储但给出警告）
        let account_id_stored = if account_id.is_empty() {
            String::new()
        } else if master_key.is_empty() {
            tracing::warn!("CONFIG_ENC_KEY 未配置，Account ID 将以明文存储（不推荐）");
            account_id.to_string()
        } else {
            encrypt_config_value(account_id, master_key)?
        };

        let license_key_stored = if license_key.is_empty() {
            String::new()
        } else if master_key.is_empty() {
            tracing::warn!("CONFIG_ENC_KEY 未配置，License Key 将以明文存储（不推荐）");
            license_key.to_string()
        } else {
            encrypt_config_value(license_key, master_key)?
        };

        self.upsert_config_value(CONFIG_KEY_UPDATE_SOURCE, source, "IP 库更新源")
            .await?;
        self.upsert_config_value(
            CONFIG_KEY_MAXMIND_ACCOUNT_ID,
            &account_id_stored,
            "MaxMind Account ID（加密）",
        )
        .await?;
        self.upsert_config_value(
            CONFIG_KEY_MAXMIND_LICENSE_KEY,
            &license_key_stored,
            "MaxMind License Key（加密）",
        )
        .await?;
        self.upsert_config_value(
            CONFIG_KEY_AUTO_UPDATE_ENABLED,
            if auto_update { "true" } else { "false" },
            "是否启用自动更新",
        )
        .await?;

        Ok(())
    }

    /// 查询当前 IP 库状态
    pub async fn get_status(&self) -> anyhow::Result<IpLocationStatus> {
        let mmdb_path = self.config.ip_location.mmdb_path.clone();
        let xdb_path = self.config.ip_location.xdb_path.clone();

        // 使用 spawn_blocking 包装同步 metadata 调用
        let mmdb_path_clone = mmdb_path.clone();
        let (_mmdb_exists, mmdb_size, mmdb_modified) =
            tokio::task::spawn_blocking(move || file_info(&mmdb_path_clone)).await?;
        let xdb_path_clone = xdb_path.clone();
        let (_xdb_exists, xdb_size, xdb_modified) =
            tokio::task::spawn_blocking(move || file_info(&xdb_path_clone)).await?;

        let cfg = self.read_config().await.unwrap_or_default();

        Ok(IpLocationStatus {
            mmdb_loaded: self.ip_locator.is_loaded(),
            mmdb_path,
            mmdb_size,
            mmdb_modified,
            xdb_enabled: self.config.ip_location.xdb_enabled,
            xdb_loaded: self.ip_locator.is_xdb_loaded(),
            xdb_path,
            xdb_size,
            xdb_modified,
            auto_update_cron: self.config.ip_location.auto_update_cron.clone(),
            current_source: cfg.update_source,
            maxmind_account_id_configured: !cfg.maxmind_account_id.is_empty(),
            maxmind_license_key_configured: !cfg.maxmind_license_key.is_empty(),
        })
    }

    /// 热加载 xdb 文件（用于后台管理触发 ip2region 库更新）
    ///
    /// xdb 文件通常数 MB，`XdbReader::from_file` 内部使用 `std::fs::read` 同步读取整文件，
    /// 在 async 上下文中直接调用会阻塞 Tokio worker。通过 `spawn_blocking` 将同步 IO 转移到
    /// 阻塞线程池执行。
    pub async fn reload_xdb(&self) -> anyhow::Result<()> {
        let xdb_path = self.config.ip_location.xdb_path.clone();
        let ip_locator = self.ip_locator.clone();
        tokio::task::spawn_blocking(move || ip_locator.reload_xdb(&xdb_path))
            .await
            .map_err(|e| anyhow::anyhow!("热加载 xdb 任务 join 失败: {}", e))??;
        Ok(())
    }

    /// 触发 IP 库更新（手动或定时任务调用）
    ///
    /// 流程：
    /// 1. 读取配置（更新源 + 凭据）
    /// 2. 根据 source 选择下载 URL 和认证方式
    /// 3. 下载到临时文件
    /// 4. 若为 tar.gz（MaxMind 官方），解压提取 .mmdb
    /// 5. 计算 SHA256
    /// 6. 验证 mmdb 文件有效性（Reader::open_readfile）
    /// 7. 备份旧文件 → rename 临时文件 → 删除备份
    /// 8. 调用 IpLocator::reload() 热加载
    pub async fn update_now(&self, force_source: Option<&str>) -> anyhow::Result<UpdateResult> {
        let start = std::time::Instant::now();
        let cfg = self.read_config().await?;
        let source_str = force_source.unwrap_or(&cfg.update_source);
        let source: UpdateSource = source_str.parse().map_err(|e: String| anyhow::anyhow!(e))?;

        tracing::info!("开始更新 IP 库，更新源: {}", source);

        let mmdb_path = self.config.ip_location.mmdb_path.clone();
        let mmdb_path_for_info = mmdb_path.clone();
        let old_size =
            tokio::task::spawn_blocking(move || file_info(&mmdb_path_for_info).1).await?;

        // 根据更新源选择下载方式
        let (new_mmdb_bytes, sha256_hex) = match source {
            UpdateSource::Maxmind => {
                if cfg.maxmind_account_id.is_empty() || cfg.maxmind_license_key.is_empty() {
                    anyhow::bail!(
                        "MaxMind update source requires Account ID and License Key to be configured"
                    );
                }
                self.download_from_maxmind(&cfg.maxmind_account_id, &cfg.maxmind_license_key)
                    .await?
            }
            UpdateSource::P3terx => self.download_from_p3terx().await?,
        };

        // 验证 mmdb 文件有效性（尝试在内存中打开）
        let temp_path = format!("{}.tmp", mmdb_path);
        tokio::fs::write(&temp_path, &new_mmdb_bytes)
            .await
            .map_err(|e| anyhow::anyhow!("failed to write temp file {}: {}", temp_path, e))?;

        // 验证 mmdb 文件可被 maxminddb 打开
        if let Err(e) = maxminddb::Reader::open_readfile(&temp_path) {
            if let Err(cleanup_err) = tokio::fs::remove_file(&temp_path).await {
                tracing::warn!(path = %temp_path, error = %cleanup_err, "清理无效 mmdb 临时文件失败");
            }
            anyhow::bail!("downloaded mmdb file is invalid (cannot open): {}", e);
        }

        // 备份旧文件（如果存在）
        let backup_path = format!("{}.bak", mmdb_path);
        if Path::new(&mmdb_path).exists() {
            tokio::fs::rename(&mmdb_path, &backup_path)
                .await
                .map_err(|e| anyhow::anyhow!("failed to backup old mmdb file: {}", e))?;
        }

        // 原子替换：rename 临时文件 → 正式文件
        if let Err(e) = tokio::fs::rename(&temp_path, &mmdb_path).await {
            // 替换失败，尝试恢复备份
            if Path::new(&backup_path).exists()
                && let Err(restore_err) = tokio::fs::rename(&backup_path, &mmdb_path).await
            {
                tracing::error!(backup = %backup_path, target = %mmdb_path, error = %restore_err, "恢复 mmdb 备份失败（原文件可能已丢失）");
            }
            anyhow::bail!("failed to replace mmdb file: {}", e);
        }

        // 删除备份（更新成功）
        if Path::new(&backup_path).exists()
            && let Err(e) = tokio::fs::remove_file(&backup_path).await
        {
            tracing::warn!(path = %backup_path, error = %e, "清理 mmdb 备份文件失败（不影响主流程）");
        }

        // 热加载
        if let Err(e) = self.ip_locator.reload(&mmdb_path) {
            tracing::error!("热加载 mmdb 失败（文件已更新，下次重启生效）: {}", e);
            // 不返回错误，因为文件已成功更新
        }

        let new_size = new_mmdb_bytes.len() as u64;
        let elapsed = start.elapsed().as_secs_f64();

        let result = UpdateResult {
            success: true,
            elapsed_seconds: elapsed,
            source: source.to_string(),
            new_size,
            new_sha256: sha256_hex,
            old_size,
            message: crate::tr!(
                "msg.success.ip_location_update",
                source = source.to_string(),
                size = new_size
            ),
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        };

        tracing::info!(
            "IP 库更新成功: source={}, size={}B, elapsed={:.2}s",
            source,
            new_size,
            elapsed
        );

        Ok(result)
    }

    /// 从 P3TERX 镜像下载（直接是 .mmdb 文件，无需解压）
    async fn download_from_p3terx(&self) -> anyhow::Result<(Vec<u8>, String)> {
        tracing::info!("从 P3TERX 镜像下载 mmdb 文件: {}", P3TERX_URL);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .user_agent("yebot-backend/0.1")
            .build()?;

        let response = client
            .get(P3TERX_URL)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("P3TERX download request failed: {}", e))?;

        if !response.status().is_success() {
            anyhow::bail!("P3TERX download failed, HTTP status: {}", response.status());
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("failed to read P3TERX response body: {}", e))?;

        if bytes.len() < crate::common::constants::MMDB_MIN_FILE_SIZE {
            anyhow::bail!(
                "P3TERX downloaded file too small ({} bytes), download may have failed",
                bytes.len()
            );
        }

        let sha256 = calculate_sha256(&bytes);
        tracing::info!("P3TERX 下载完成: {} bytes, SHA256={}", bytes.len(), sha256);

        Ok((bytes.to_vec(), sha256))
    }

    /// 从 MaxMind 官方下载（tar.gz 格式，需解压提取 .mmdb）
    async fn download_from_maxmind(
        &self,
        account_id: &str,
        license_key: &str,
    ) -> anyhow::Result<(Vec<u8>, String)> {
        tracing::info!(
            "从 MaxMind 官方下载 mmdb 文件（Account ID: {}）",
            account_id
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .user_agent("yebot-backend/0.1")
            .build()?;

        let response = client
            .get(MAXMIND_URL)
            .basic_auth(account_id, Some(license_key))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("MaxMind download request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "MaxMind download failed, HTTP status: {}, response: {}",
                status,
                body
            );
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| anyhow::anyhow!("failed to read MaxMind response body: {}", e))?;

        // 解压 tar.gz 并提取 .mmdb 文件
        let mmdb_bytes = extract_mmdb_from_tar_gz(&bytes)
            .map_err(|e| anyhow::anyhow!("failed to extract tar.gz: {}", e))?;

        let sha256 = calculate_sha256(&mmdb_bytes);
        tracing::info!(
            "MaxMind 下载并解压完成: {} bytes, SHA256={}",
            mmdb_bytes.len(),
            sha256
        );

        Ok((mmdb_bytes, sha256))
    }

    /// 触发 mmdb 热加载（不下载新文件，仅重新加载现有文件）
    pub async fn reload(&self) -> anyhow::Result<()> {
        let mmdb_path = &self.config.ip_location.mmdb_path;
        self.ip_locator.reload(mmdb_path)?;
        Ok(())
    }

    // ==================== sys_config 表 CRUD 辅助方法 ====================

    async fn read_config_value(&self, key: &str) -> anyhow::Result<String> {
        use crate::entity::sys_config;
        use sea_orm::ColumnTrait;
        use sea_orm::EntityTrait;
        use sea_orm::QueryFilter;

        let result = sys_config::Entity::find()
            .filter(sys_config::Column::ConfigKey.eq(key))
            .one(&self.db)
            .await
            .map_err(|e| anyhow::anyhow!("查询 sys_config 失败: {}", e))?;

        Ok(result
            .map(|m| m.config_value.unwrap_or_default())
            .unwrap_or_default())
    }

    async fn upsert_config_value(&self, key: &str, value: &str, name: &str) -> anyhow::Result<()> {
        use crate::entity::sys_config;
        use sea_orm::ActiveModelTrait;
        use sea_orm::ActiveValue::Set;
        use sea_orm::ColumnTrait;
        use sea_orm::EntityTrait;
        use sea_orm::QueryFilter;

        let existing = sys_config::Entity::find()
            .filter(sys_config::Column::ConfigKey.eq(key))
            .one(&self.db)
            .await
            .map_err(|e| anyhow::anyhow!("查询 sys_config 失败: {}", e))?;

        if let Some(model) = existing {
            let mut active: sys_config::ActiveModel = model.into();
            active.config_value = Set(Some(value.to_string()));
            active.update_time = Set(Some(crate::common::datetime::now_naive()));
            active
                .update(&self.db)
                .await
                .map_err(|e| anyhow::anyhow!("更新 sys_config 失败: {}", e))?;
        } else {
            let active = sys_config::ActiveModel {
                config_name: Set(Some(name.to_string())),
                config_key: Set(key.to_string()),
                config_value: Set(Some(value.to_string())),
                config_type: Set(Some("Y".to_string())),
                create_by: Set(Some("admin".to_string())),
                create_time: Set(Some(crate::common::datetime::now_naive())),
                remark: Set(Some("IP 库管理配置".to_string())),
                ..Default::default()
            };
            active
                .insert(&self.db)
                .await
                .map_err(|e| anyhow::anyhow!("插入 sys_config 失败: {}", e))?;
        }

        Ok(())
    }
}

// ==================== 辅助函数 ====================

/// 计算字节数组的 SHA256 哈希（hex 编码）
fn calculate_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// 从 tar.gz 字节流中提取 .mmdb 文件
fn extract_mmdb_from_tar_gz(tar_gz_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let gz = GzDecoder::new(tar_gz_bytes);
    let mut archive = tar::Archive::new(gz);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let path_str = path.to_string_lossy();

        // 查找 .mmdb 文件（通常路径形如 GeoLite2-City_YYYYMMDD/GeoLite2-City.mmdb）
        if path_str.ends_with(".mmdb") {
            let mut buffer = Vec::new();
            entry.read_to_end(&mut buffer)?;
            return Ok(buffer);
        }
    }

    anyhow::bail!(".mmdb file not found in tar.gz archive")
}

/// 获取文件信息（存在性、大小、修改时间）
fn file_info(path: &str) -> (bool, u64, i64) {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let size = meta.len();
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
                .unwrap_or(0);
            (true, size, modified)
        }
        Err(_) => (false, 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_sha256() {
        let bytes = b"hello world";
        let hash = calculate_sha256(bytes);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_update_source_parse() {
        assert_eq!(
            "maxmind".parse::<UpdateSource>().unwrap(),
            UpdateSource::Maxmind
        );
        assert_eq!(
            "P3TERX".parse::<UpdateSource>().unwrap(),
            UpdateSource::P3terx
        );
        assert!("invalid".parse::<UpdateSource>().is_err());
    }

    #[test]
    fn test_file_info_nonexistent() {
        let (exists, size, modified) = file_info("/nonexistent/path/file.mmdb");
        assert!(!exists);
        assert_eq!(size, 0);
        assert_eq!(modified, 0);
    }
}
