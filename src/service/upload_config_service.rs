// stepby-axum/src/service/upload_config_service.rs
//! OSS 存储配置运行时服务（G-11 第一档，方案深审 2026-10-06）
//!
//! **双源语义**（对齐 `ai/config_service.rs` 的 sys.ai.* 范式）：
//! config.toml `[upload.s3]` 段为出厂缺省（startup 快照）；`sys.upload.s3.*`
//! 七键（sys_config，管理页可改热生效）存在且非空即覆盖。
//!
//! 生效边界（第一档：**凭据/参数动态化，backend 档位重启生效**）：
//! - `config.toml [upload].backend = "s3"` 且运行时覆盖齐全时，上传/删除链路
//!   经 `Self::resolve_s3_backend` 按运行时配置构建（指纹缓存复用）；
//! - `backend = "local"` 无凭据概念，不受影响；
//! - 档位本身（local ↔ s3）仍以 config.toml 为准（重启生效）——档位切换属
//!   低频运维动作，不为此引入热切换复杂度（第二档 ArcSwap 另行评估）。
//!
//! 安全：
//! - secret_key 信封加密存储（v3 信封，`encrypt_config_value`），读取 unseal，
//!   管理页只回显掩码（oper_log 侧 is_sensitive_key 自动脱敏请求体）；
//! - endpoint 变更走 `common::ssrf` 校验（防 DNS rebinding/私网穿透，对齐 ai base_url）；
//! - 平台专属（handler 层 `tenant_id == 0` 门控，对齐 sys.ai.*）。

use sea_orm::DatabaseConnection;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::ServiceError;
use crate::config::settings::S3StorageConfig;
use crate::service::sys_config_service::SysConfigService;
use crate::storage::{S3Backend, StorageBackend};
use crate::utils::crypto::{encrypt_config_value, unseal_sensitive_value};

const KEY_ACCESS_KEY: &str = "sys.upload.s3.access_key";
const KEY_SECRET_KEY: &str = "sys.upload.s3.secret_key";
const KEY_ENDPOINT: &str = "sys.upload.s3.endpoint";
const KEY_REGION: &str = "sys.upload.s3.region";
const KEY_BUCKET: &str = "sys.upload.s3.bucket";
const KEY_PATH_STYLE: &str = "sys.upload.s3.path_style";
const KEY_PUBLIC_ENDPOINT: &str = "sys.upload.s3.public_endpoint";

pub struct UploadConfigService {
    pub db: Arc<DatabaseConnection>,
    pub config_service: SysConfigService,
    /// config.toml `[upload.s3]` 段出厂缺省快照（sys.upload.s3.* 键为空时回落）
    pub startup: S3StorageConfig,
    pub enc_key: String,
    /// config.toml `[upload].backend` 档位快照（"local" | "s3"）——出厂档；
    /// 热切换后的运行档位持久化于 `sys.upload.backend`（见 [`Self::effective_backend_mode`]）
    pub startup_backend_mode: String,
    /// 运行时覆盖构建的 S3 后端缓存：`(配置指纹, backend)`——配置未变时复用
    /// 连接池（reqwest Client 内含连接复用），变更后整实例替换（旧实例由
    /// Arc 存活到最后一个使用者，无在途请求撕裂）。
    cached_backend: RwLock<Option<(String, Arc<S3Backend>)>>,
}

/// 档位持久化键（sys.upload.backend，Locked；空 = 跟随 config.toml 出厂档）
pub const KEY_BACKEND_MODE: &str = "sys.upload.backend";

/// 管理页回显 VO（secret_key 掩码，永不回显明文）
#[derive(Debug, Clone, Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename_all = "camelCase")]
pub struct UploadConfigMaskedVo {
    pub access_key_masked: String,
    pub has_access_key: bool,
    pub secret_key_masked: String,
    pub has_secret_key: bool,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub path_style: bool,
    pub public_endpoint: String,
    /// **当前生效档位**（local/s3）：`sys.upload.backend` 覆盖优先，缺省回落 config.toml 出厂档。
    ///
    /// 必须与写路径/探针用的档位同源（[`UploadConfigService::effective_backend_mode`]）——回显出厂档
    /// 会让管理页显示与实际行为分裂（C.7）。
    pub backend_mode: String,
}

/// 管理页更新入参（secret_key 为 None/空串 = 保留原值）
#[derive(Debug, Clone, serde::Deserialize, garde::Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UploadConfigUpdateDto {
    #[garde(length(max = 200))]
    pub access_key: Option<String>,
    /// None/空串 = 保留原值；有值 = 更新（服务端 seal 后落库，请求体由
    /// oper_log is_sensitive_key 自动脱敏）
    #[garde(length(max = 200))]
    pub secret_key: Option<String>,
    #[garde(length(max = 300))]
    pub endpoint: Option<String>,
    #[garde(length(max = 64))]
    pub region: Option<String>,
    #[garde(length(max = 200))]
    pub bucket: Option<String>,
    #[garde(skip)]
    pub path_style: Option<bool>,
    #[garde(length(max = 300))]
    pub public_endpoint: Option<String>,
}

impl UploadConfigService {
    pub fn new(
        db: Arc<DatabaseConnection>,
        config_service: SysConfigService,
        startup: S3StorageConfig,
        backend_mode: String,
        enc_key: String,
    ) -> Self {
        Self {
            db,
            config_service,
            startup,
            startup_backend_mode: backend_mode,
            enc_key,
            cached_backend: RwLock::new(None),
        }
    }

    /// 读单个 `sys.upload.s3.*` 键（cache-aside）
    async fn raw(&self, key: &str) -> Result<Option<String>, ServiceError> {
        self.config_service
            .get_config_value_by_key_cached(key, None)
            .await
    }

    /// 非空覆盖，否则回落 startup 缺省
    async fn effective_string(&self, key: &str, fallback: &str) -> Result<String, ServiceError> {
        match self.raw(key).await? {
            Some(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
            _ => Ok(fallback.to_string()),
        }
    }

    /// **运行时有效 S3 配置**（resolve 每次调用，cache-aside O(1)）
    pub async fn get_effective(&self) -> Result<S3StorageConfig, ServiceError> {
        let access_key = self
            .effective_string(KEY_ACCESS_KEY, &self.startup.access_key)
            .await?;
        let endpoint = self
            .effective_string(KEY_ENDPOINT, &self.startup.endpoint)
            .await?;
        let region = self
            .effective_string(KEY_REGION, &self.startup.region)
            .await?;
        let bucket = self
            .effective_string(KEY_BUCKET, &self.startup.bucket)
            .await?;
        let path_style = match self.raw(KEY_PATH_STYLE).await? {
            Some(v) if !v.trim().is_empty() => v.trim().eq_ignore_ascii_case("true"),
            _ => self.startup.path_style,
        };
        let public_endpoint = self
            .effective_string(KEY_PUBLIC_ENDPOINT, &self.startup.public_endpoint)
            .await?;
        // secret_key：sys.upload.s3.secret_key 存的是信封密文——unseal 回明文；
        // 键缺失/空回落 startup（env/config.toml 注入）
        let secret_key = match self.raw(KEY_SECRET_KEY).await? {
            Some(stored) if !stored.trim().is_empty() => {
                unseal_sensitive_value(&stored, &self.enc_key)
            }
            _ => self.startup.secret_key.clone(),
        };
        Ok(S3StorageConfig {
            access_key,
            secret_key,
            endpoint,
            region,
            bucket,
            path_style,
            public_endpoint,
        })
    }

    /// 管理页回显（access_key / secret_key 掩码，永不回显明文）
    pub async fn masked(&self) -> Result<UploadConfigMaskedVo, ServiceError> {
        let effective = self.get_effective().await?;
        let raw_access = self.raw(KEY_ACCESS_KEY).await?.unwrap_or_default();
        let has_access_key = !raw_access.trim().is_empty() && !effective.access_key.is_empty();
        let raw_secret = self.raw(KEY_SECRET_KEY).await?.unwrap_or_default();
        let has_secret_key = !raw_secret.trim().is_empty() && !effective.secret_key.is_empty();
        Ok(UploadConfigMaskedVo {
            access_key_masked: mask_keep(&effective.access_key),
            has_access_key,
            secret_key_masked: mask_keep(&effective.secret_key),
            has_secret_key,
            endpoint: effective.endpoint.clone(),
            region: effective.region.clone(),
            bucket: effective.bucket.clone(),
            path_style: effective.path_style,
            public_endpoint: effective.public_endpoint.clone(),
            // C.7 回显与生效同源（b74 §一.6）：此前回显 `startup_backend_mode`（出厂档快照），
            // 而写路径与 `/health` 探针用 `effective_backend_mode()` ⇒ 管理员热切换 s3↔local 后
            // "页面显示出厂档、实际跑覆盖档"，与 AGENTS 点名的"显示 8、实际 4"是同一种行为分裂。
            backend_mode: self.effective_backend_mode().await?,
        })
    }

    /// 七键 UPDATE（直接 SQL——键固定且平台专属；写后 refreshCache 热生效）
    ///
    /// 方言注意：`Statement::from_sql_and_values` 的占位符风格随 backend 变化
    /// （PG 为 `$n`），SQL 必须按 backend 分支——不能照抄 ai/config_service 的
    /// Sqlite 固定标注（该处在 PG 下会因占位符风格错配而失败，本处一并修正口径）。
    ///
    /// b83 订正：本文件原按 backend 手写 `$1`/`?` 两支、`ai/config_service` 写死 Sqlite，
    /// 两份还都把 `update_time` 交给 `CURRENT_TIMESTAMP`（三库落不同时区）。现已统一走
    /// `SysConfigService::set_platform_value`——方言占位符与时间口径各只有一处事实源。
    async fn write_key(&self, key: &str, value: &str) -> Result<(), ServiceError> {
        self.config_service.set_platform_value(key, value).await
    }

    /// 管理页更新：SSRF 校验 endpoint + secret_key/access_key seal + 七键写入 +
    /// 缓存失效 + 后端缓存重置（下次 resolve 按新配置重建）
    pub async fn update(&self, dto: &UploadConfigUpdateDto) -> Result<(), ServiceError> {
        // endpoint 非空 → SSRF 校验（防 DNS rebinding/私网穿透；对齐既有出站防护）
        if let Some(ep) = dto.endpoint.as_deref()
            && !ep.trim().is_empty()
        {
            let url = crate::common::ssrf::validate_url(ep.trim())
                .map_err(|e| ServiceError::bad_request(&format!("endpoint 不被允许: {e}")))?;
            let port = url.port_or_known_default().unwrap_or(443);
            crate::common::ssrf::validate_host_resolution(url.host_str().unwrap_or_default(), port)
                .await
                .map_err(|e| ServiceError::bad_request(&format!("endpoint 主机不可用: {e}")))?;
        }
        if let Some(v) = dto.access_key.as_deref() {
            self.write_key(KEY_ACCESS_KEY, v.trim()).await?;
        }
        if let Some(k) = dto.secret_key.as_deref()
            && !k.trim().is_empty()
        {
            let sealed = encrypt_config_value(k.trim(), &self.enc_key)
                .map_err(|e| ServiceError::internal(&format!("secret_key 加密失败: {e}")))?;
            self.write_key(KEY_SECRET_KEY, &sealed).await?;
        }
        if let Some(v) = dto.endpoint.as_deref() {
            self.write_key(KEY_ENDPOINT, v.trim()).await?;
        }
        if let Some(v) = dto.region.as_deref() {
            self.write_key(KEY_REGION, v.trim()).await?;
        }
        if let Some(v) = dto.bucket.as_deref() {
            self.write_key(KEY_BUCKET, v.trim()).await?;
        }
        if let Some(v) = dto.path_style {
            self.write_key(KEY_PATH_STYLE, if v { "true" } else { "false" })
                .await?;
        }
        if let Some(v) = dto.public_endpoint.as_deref() {
            self.write_key(KEY_PUBLIC_ENDPOINT, v.trim()).await?;
        }
        // 热生效：失效 sys_config 缓存（cache-aside 下次读新值）+ 重置后端缓存
        // （下次 resolve_s3_backend 按新指纹重建，旧实例 Arc 存活至在途请求结束）。
        // 旁路语义：七键已写库，刷新失败不把"保存成功"变成 5xx。
        self.config_service
            .refresh_cache_best_effort("upload.config")
            .await;
        *self.cached_backend.write().await = None;
        tracing::info!(
            operator_manual = true,
            "OSS 存储配置已更新（sys.upload.s3.* 七键，热生效）"
        );
        Ok(())
    }

    /// 连通性测试：按当前有效配置 ListObjectsV2（max-keys=1，独立 10s 超时语义）
    pub async fn test_connectivity(&self) -> Result<String, ServiceError> {
        let effective = self.get_effective().await?;
        let started = std::time::Instant::now();
        let backend =
            S3Backend::try_new(&effective).map_err(|e| ServiceError::bad_request(&e.message))?;
        // list 空前缀 = ListObjectsV2（bucket 级探活）；路径/寻址/签名错误都会在此暴露
        let _ = backend
            .list("", 0, &effective.public_endpoint)
            .await
            .map_err(|e| ServiceError::bad_request(&format!("连通失败: {}", e.message)))?;
        Ok(format!(
            "连通正常（bucket {}，{}ms）",
            effective.bucket,
            started.elapsed().as_millis()
        ))
    }

    /// **生效档位**（G-11 第二档）：`sys.upload.backend` 非空（local/s3）即覆盖
    /// config.toml 出厂档；非法值视为空（回落出厂档，与治理注册表 fail-safe 口径一致）
    pub async fn effective_backend_mode(&self) -> Result<String, ServiceError> {
        let stored = self.raw(KEY_BACKEND_MODE).await?.unwrap_or_default();
        let stored = stored.trim().to_lowercase();
        if stored == "local" || stored == "s3" {
            Ok(stored)
        } else {
            Ok(self.startup_backend_mode.clone())
        }
    }

    /// backend 档位热切换（G-11 第二档核心）：构建新档后端 → 持久化键 →
    /// 由调用方 store 进 `AppState.hot_storage`（ArcSwap 整指针替换，读侧无锁）
    ///
    /// - `local`：恒可构建；
    /// - `s3`：按当前**有效 S3 配置**构建（config.toml 缺省 + sys.upload.s3.* 覆盖），
    ///   配置不完整则 400（fail-closed——不切到不可用的档）。
    pub async fn build_backend_for_mode(
        &self,
        mode: &str,
    ) -> Result<Arc<dyn crate::storage::StorageBackend>, ServiceError> {
        match mode {
            "local" => Ok(Arc::new(crate::storage::LocalBackend {})
                as Arc<dyn crate::storage::StorageBackend>),
            "s3" => {
                let cfg = self.get_effective().await?;
                let backend = crate::storage::S3Backend::try_new(&cfg).map_err(|e| {
                    ServiceError::bad_request(&format!("s3 档配置不可用: {}", e.message))
                })?;
                Ok(Arc::new(backend) as Arc<dyn crate::storage::StorageBackend>)
            }
            other => Err(ServiceError::bad_request(&format!(
                "不支持的存储档位: {other}（可选 local / s3）"
            ))),
        }
    }

    /// 档位持久化（写 sys.upload.backend + refreshCache）
    pub async fn persist_backend_mode(&self, mode: &str) -> Result<(), ServiceError> {
        self.config_service
            .set_platform_value(KEY_BACKEND_MODE, mode)
            .await?;
        // 旁路语义同上方写路径：档位已落库，缓存失效失败只留痕（TTL 300s 内自愈）
        self.config_service
            .refresh_cache_best_effort("upload.backend_mode")
            .await;
        Ok(())
    }

    /// 启动恢复（G-11 第二档）：`sys.upload.backend` 与出厂档不同 → 返回应装载的
    /// 运行档后端（调用方 store 进 hot_storage；失败仅告警不阻断启动——回落出厂档）
    pub async fn restore_backend_if_switched(
        &self,
    ) -> Option<Arc<dyn crate::storage::StorageBackend>> {
        // b71 吞错治理：回落出厂档的取舍不变（启动不因读档失败而中断），但读库失败必须留痕
        // ——原 `.ok()?` 让"配置表读不出来"与"档位就是出厂档"在日志里完全同形。
        let effective = match self.effective_backend_mode().await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "G-11 启动恢复：读取有效档位失败，回落出厂档 {}（非档位本身问题）",
                    self.startup_backend_mode
                );
                return None;
            }
        };
        if effective == self.startup_backend_mode {
            return None;
        }
        match self.build_backend_for_mode(&effective).await {
            Ok(b) => {
                tracing::info!(
                    "G-11 启动恢复：热切换档位 {effective} 已重新装载（出厂档 {}）",
                    self.startup_backend_mode
                );
                Some(b)
            }
            Err(e) => {
                tracing::warn!(
                    "G-11 启动恢复失败（回落出厂档 {}）: {}",
                    self.startup_backend_mode,
                    e.message
                );
                None
            }
        }
    }

    /// 上传链路运行时解析（G-11 核心接线点）
    ///
    /// 仅当 config.toml 档位为 `s3` 时尝试运行时覆盖：
    /// - 有效配置与 startup 快照**有差异** → 按有效配置构建/复用缓存后端；
    /// - 无差异（用户未做运行时覆盖）→ 回落 `AppState.storage`（启动时构建），
    ///   行为与改造前逐字节一致；
    /// - 档位为 `local` → 恒回落 `AppState.storage`。
    pub async fn resolve_s3_backend(
        &self,
        startup_storage: &Arc<dyn StorageBackend>,
    ) -> Result<Arc<dyn StorageBackend>, ServiceError> {
        if self.startup_backend_mode != "s3" {
            return Ok(startup_storage.clone());
        }
        let effective = self.get_effective().await?;
        let fingerprint = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            effective.access_key,
            // 指纹含明文 secret——仅用于内存比对，不落盘不日志
            effective.secret_key,
            effective.endpoint,
            effective.region,
            effective.bucket,
            effective.path_style,
            effective.public_endpoint,
        );
        if let Some((cached_fp, backend)) = self.cached_backend.read().await.as_ref()
            && cached_fp == &fingerprint
        {
            return Ok(backend.clone() as Arc<dyn StorageBackend>);
        }
        // 与 startup 快照一致（无运行时覆盖）→ 回落启动后端（零行为变化）
        if effective.access_key == self.startup.access_key
            && effective.secret_key == self.startup.secret_key
            && effective.endpoint == self.startup.endpoint
            && effective.region == self.startup.region
            && effective.bucket == self.startup.bucket
            && effective.path_style == self.startup.path_style
            && effective.public_endpoint == self.startup.public_endpoint
        {
            return Ok(startup_storage.clone());
        }
        let backend =
            Arc::new(S3Backend::try_new(&effective).map_err(|e| {
                ServiceError::bad_request(&format!("OSS 配置不可用: {}", e.message))
            })?);
        *self.cached_backend.write().await = Some((fingerprint, backend.clone()));
        Ok(backend as Arc<dyn StorageBackend>)
    }
}

/// 掩码（保留前 2 后 2，中段 `****`；≤6 字符全掩码）——对齐 masking::mask_keep 风格
fn mask_keep(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    if chars.len() <= 6 {
        return "*".repeat(chars.len());
    }
    format!(
        "{}****{}",
        chars[..2].iter().collect::<String>(),
        chars[chars.len() - 2..].iter().collect::<String>()
    )
}
