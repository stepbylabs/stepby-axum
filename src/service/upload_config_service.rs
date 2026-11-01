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

/// 「存在且非空即覆盖，否则回落缺省」的**唯一**实现（本模块双源语义的单一事实源）。
///
/// `get_effective`（已存配置 → 有效配置）与 `merge_draft`（屏上草稿 → 保存后将生效的
/// 配置）都必须经它。两处各写一遍时，漂开的不是编译错误而是**一句假话**：「测试按钮
/// 测的就是屏上这份表单」——草稿侧若把空串读成"沿用有效值"，而写库侧的空串经
/// `effective_string` 实际回落到出厂值，测试通过、保存后立刻换了一份配置。
/// 空串在两侧必须是同一个决定。
fn resolve_stored(stored: Option<&str>, fallback: &str) -> String {
    match stored {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => fallback.to_string(),
    }
}

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
        Ok(resolve_stored(self.raw(key).await?.as_deref(), fallback))
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

    /// 把管理页草稿叠到"当前有效配置"上，得到**保存之后会生效**的那份配置。
    ///
    /// 回落规则不再另写一遍：非空/空的判定与 `get_effective` 共用
    /// [`resolve_stored`]，因此"测的就是屏上这份"这句话由代码结构保证，
    /// 而不是靠注释声明"两边口径一致"（AGENTS 铁律：派生结论的成立前提要么由
    /// 代码路径保证，要么由锁钉住）。`update` 的写路径仍是另一处事实，其形状由
    /// 本模块单测 `draft_merge_matches_effective_rule` 逐字段对账。
    /// - 字段缺省（`None`）⇒ `update` 根本不写这一列 ⇒ 沿用有效值；
    /// - 字段带上但值为空串 ⇒ `update` 写入空串 ⇒ `effective_string` 视空为"未覆盖"
    ///   ⇒ 回落到出厂值（`startup`），**不是**沿用有效值；
    /// - `secret_key` 例外：`update` 对空串直接跳过（空=保留原凭据），所以空串沿用有效值；
    /// - `path_style` 是布尔，无"空串"态：带上即覆盖。
    fn merge_draft(
        base: &S3StorageConfig,
        startup: &S3StorageConfig,
        draft: &UploadConfigUpdateDto,
    ) -> S3StorageConfig {
        /// 除 secret_key 之外的字符串字段：缺省=沿用有效值，空串=回落出厂值，其它=取草稿值
        fn pick(current: &str, factory: &str, incoming: Option<&str>) -> String {
            match incoming {
                None => current.to_string(),
                Some(v) => resolve_stored(Some(v), factory),
            }
        }
        S3StorageConfig {
            access_key: pick(
                &base.access_key,
                &startup.access_key,
                draft.access_key.as_deref(),
            ),
            // 空串 = 保留原凭据（与 update 的 `&& !k.trim().is_empty()` 同一条件）
            secret_key: match draft.secret_key.as_deref() {
                Some(v) if !v.trim().is_empty() => v.trim().to_string(),
                _ => base.secret_key.clone(),
            },
            endpoint: pick(&base.endpoint, &startup.endpoint, draft.endpoint.as_deref()),
            region: pick(&base.region, &startup.region, draft.region.as_deref()),
            bucket: pick(&base.bucket, &startup.bucket, draft.bucket.as_deref()),
            public_endpoint: pick(
                &base.public_endpoint,
                &startup.public_endpoint,
                draft.public_endpoint.as_deref(),
            ),
            path_style: draft.path_style.unwrap_or(base.path_style),
        }
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
        Self::probe(&effective).await
    }

    /// **草稿**连通性测试：以屏上这份表单为准，叠加到有效配置之上后再探活。
    ///
    /// 立项原因：管理页的「测试」按钮原先只能测**已保存**的配置——管理员改了 endpoint /
    /// bucket 后点测试，拿到的是旧值的结果，于是出现"测通了，保存后上传全挂"与"测失败，
    /// 但改的其实是对的"两种误导（AGENTS 67(a) 同族：屏上那句话没有判据支撑）。
    ///
    /// 叠加口径与 `update` 逐字一致：**空串/缺省 = 沿用原值**（凭据尤其——掩码回显的
    /// secretKey 提交时是空的，若把空串当真值就是"测试必然失败"的假信号）。
    ///
    /// SSRF 校验只判**草稿里填的** endpoint（与 `update` 同一条件），不给已存的配置
    /// 新增一条拒绝理由：出厂 config.toml 注入的 endpoint 历史上不经校验，测试时突然
    /// 判它违规等于把"配置坏了"换成"测试工具坏了"（⑯(c)：前置条件不成立的判据是噪声）。
    pub async fn test_connectivity_draft(
        &self,
        draft: &UploadConfigUpdateDto,
    ) -> Result<String, ServiceError> {
        if let Some(ep) = draft.endpoint.as_deref()
            && !ep.trim().is_empty()
        {
            Self::guard_endpoint(ep).await?;
        }
        let effective = self.get_effective().await?;
        Self::probe(&Self::merge_draft(&effective, &self.startup, draft)).await
    }

    /// endpoint 的 SSRF 校验（`update` 与草稿测试共用同一把尺，禁止两处各写一遍）
    async fn guard_endpoint(ep: &str) -> Result<(), ServiceError> {
        let url = crate::common::ssrf::validate_url(ep.trim())
            .map_err(|e| ServiceError::bad_request(&format!("endpoint 不被允许: {e}")))?;
        let port = url.port_or_known_default().unwrap_or(443);
        crate::common::ssrf::validate_host_resolution(url.host_str().unwrap_or_default(), port)
            .await
            .map_err(|e| ServiceError::bad_request(&format!("endpoint 主机不可用: {e}")))?;
        Ok(())
    }

    /// 实际探活（ListObjectsV2 max-keys=1）——已存配置与草稿两条入口共用
    async fn probe(cfg: &S3StorageConfig) -> Result<String, ServiceError> {
        let started = std::time::Instant::now();
        let backend = S3Backend::try_new(cfg).map_err(|e| ServiceError::bad_request(&e.message))?;
        // list 空前缀 = ListObjectsV2（bucket 级探活）；路径/寻址/签名错误都会在此暴露
        let _ = backend
            .list("", 0, &cfg.public_endpoint)
            .await
            .map_err(|e| ServiceError::bad_request(&format!("连通失败: {}", e.message)))?;
        Ok(format!(
            "连通正常（bucket {}，{}ms）",
            cfg.bucket,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::prod_scan::{self, Scan};

    /// 已生效的配置（= `get_effective()` 的产物形状）：每字段都取自"库里存的那份"
    fn effective() -> S3StorageConfig {
        S3StorageConfig {
            access_key: "stored-ak".to_string(),
            secret_key: "stored-sk".to_string(),
            endpoint: "https://stored.example".to_string(),
            region: "stored-region".to_string(),
            bucket: "stored-bucket".to_string(),
            path_style: true,
            public_endpoint: "https://cdn.stored.example".to_string(),
        }
    }

    /// 出厂缺省（config.toml `[upload.s3]` 快照）
    fn factory() -> S3StorageConfig {
        S3StorageConfig {
            access_key: "factory-ak".to_string(),
            secret_key: String::new(),
            endpoint: "https://factory.example".to_string(),
            region: "factory-region".to_string(),
            bucket: "factory-bucket".to_string(),
            path_style: false,
            public_endpoint: String::new(),
        }
    }

    fn draft(
        access_key: Option<&str>,
        secret_key: Option<&str>,
        endpoint: Option<&str>,
        region: Option<&str>,
        bucket: Option<&str>,
        path_style: Option<bool>,
        public_endpoint: Option<&str>,
    ) -> UploadConfigUpdateDto {
        UploadConfigUpdateDto {
            access_key: access_key.map(str::to_string),
            secret_key: secret_key.map(str::to_string),
            endpoint: endpoint.map(str::to_string),
            region: region.map(str::to_string),
            bucket: bucket.map(str::to_string),
            path_style,
            public_endpoint: public_endpoint.map(str::to_string),
        }
    }

    /// 七个字段全缺省 = 前端发的 `{}` = `update` 一条都不写。
    ///
    /// 这条是"向后兼容"那句话的**判据**：改造成接收草稿之后，不带字段的请求必须
    /// 与改造前逐字段等价（否则 `/health` 探针与任何旧调用点会被静默换成另一份配置）。
    #[test]
    fn all_absent_draft_is_the_effective_config_itself() {
        let base = effective();
        let merged = UploadConfigService::merge_draft(
            &base,
            &factory(),
            &draft(None, None, None, None, None, None, None),
        );
        for (name, got, want) in [
            ("access_key", &merged.access_key, &base.access_key),
            ("secret_key", &merged.secret_key, &base.secret_key),
            ("endpoint", &merged.endpoint, &base.endpoint),
            ("region", &merged.region, &base.region),
            ("bucket", &merged.bucket, &base.bucket),
            (
                "public_endpoint",
                &merged.public_endpoint,
                &base.public_endpoint,
            ),
        ] {
            assert_eq!(got, want, "字段 {name}：全缺省的草稿必须原样沿用有效值");
        }
        assert_eq!(merged.path_style, base.path_style, "path_style 同理");
    }

    /// **「不带」与「带空串」是两种指令**——这一族在本仓已立过三次案（b145 IP 库凭据、
    /// b133 读成功标记、本批 uploadConfig）。空串是"用户把这个字段清空了"，
    /// 于是回落到出厂值；不带才是"这个字段我没动"。合并成一种就是缺陷。
    ///
    /// 期望值取自**手写的对账表**而不是取自 `resolve_stored`：实现与期望同时改才可能
    /// 一起错，用被测函数给自己当期望值等于没判（AGENTS ⑥）。
    #[test]
    fn blank_field_and_absent_field_are_different_decisions() {
        let cases: [(Option<&str>, &str); 4] = [
            (None, "https://stored.example"),
            (Some(""), "https://factory.example"),
            (Some("   "), "https://factory.example"),
            (Some(" https://typed.example "), "https://typed.example"),
        ];
        for (incoming, want) in cases {
            let d = draft(None, None, incoming, None, None, None, None);
            let merged = UploadConfigService::merge_draft(&effective(), &factory(), &d);
            assert_eq!(
                merged.endpoint, want,
                "endpoint 入参 {incoming:?} ⇒ 期望 {want:?}"
            );
            // 共用一把尺的对账**只在 Some 那三支做**：草稿侧的 None 根本不走 `resolve_stored`
            // （由 `pick` 的第一支拦下），拿它去要求两侧同答等于问两个不同的问题。
            // 读取侧的 None = "这个键在库里不存在" ⇒ 回落出厂；草稿侧的 None = "这个字段没发"
            // ⇒ 不动那一列。两个 None 语义相反，因此这里把它也钉成一条断言。
            if incoming.is_some() {
                assert_eq!(
                    resolve_stored(incoming, &factory().endpoint),
                    want,
                    "endpoint 入参 {incoming:?}：读取侧与草稿侧对空串/有值的决定必须逐字相同"
                );
            } else {
                assert_eq!(
                    resolve_stored(None, &factory().endpoint),
                    "https://factory.example",
                    "读取侧的 None 回落出厂值（键缺失）"
                );
                assert_eq!(
                    merged.endpoint, "https://stored.example",
                    "草稿侧的 None 沿用有效值（字段没发）——与上一行刻意相反，不得'统一'"
                );
            }
        }
    }

    /// `secret_key` 是这一族里**刻意不同**的一支：`update` 对空串直接跳过（留空=保留原
    /// 凭据，管理页的 `留空保留已保存的值` 就靠这句成立）。把它"统一"成别的字段的
    /// 空串语义，症状是留空保存一次就把已存密文换成出厂值（出厂 SK 通常是空 ⇒ 上传全挂）。
    #[test]
    fn secret_key_blank_keeps_the_stored_credential_not_the_factory_one() {
        let kept = UploadConfigService::merge_draft(
            &effective(),
            &factory(),
            &draft(None, Some("   "), None, None, None, None, None),
        );
        assert_eq!(kept.secret_key, "stored-sk", "留空必须保留已存凭据");
        assert_ne!(
            kept.secret_key,
            factory().secret_key,
            "出厂 SK 是空串：把它当结果就是「留空 = 清掉凭据」那个缺陷"
        );
        let rotated = UploadConfigService::merge_draft(
            &effective(),
            &factory(),
            &draft(None, Some("new-sk"), None, None, None, None, None),
        );
        assert_eq!(rotated.secret_key, "new-sk");
        // ⚠ 这里**不**再对照 endpoint 的空串语义：那条由
        // `blank_field_and_absent_field_are_different_decisions` 独占判据。两条腿各自
        // 只被自己的变异打红才叫独立（AGENTS ㉖②"验独立"）；在这里重复一遍，
        // 一个只改 `pick` 的退化会同时红两条，反而看不出哪条在起作用。
    }

    /// `path_style` 是布尔，没有"空串"态：带上即覆盖（含显式 `false`）。
    #[test]
    fn path_style_is_overwritten_whenever_it_is_present() {
        let off = UploadConfigService::merge_draft(
            &effective(),
            &factory(),
            &draft(None, None, None, None, None, Some(false), None),
        );
        assert!(
            !off.path_style,
            "显式 false 必须生效（'带上即覆盖'不是'非空才覆盖'）"
        );
        let untouched = UploadConfigService::merge_draft(
            &effective(),
            &factory(),
            &draft(None, None, None, None, None, None, None),
        );
        assert!(untouched.path_style);
    }

    /// 采集口径探针：`prod_scan` 的视图确实把注释剔掉了（否则下面那条"注释里提到不算"
    /// 的反证只是我以为）。这条不是业务判据，是**判据的输入形状**证明（AGENTS ⑬）。
    #[test]
    fn prod_scan_view_drops_comment_lines() {
        let text = "// .test_connectivity_draft(\nlet _ = 1;\n";
        let lines = prod_scan::normalize(text, &Scan::default());
        assert!(
            !lines
                .iter()
                .any(|l| l.contains(".test_connectivity_draft(")),
            "注释行必须被剔掉，实测视图={lines:?}"
        );
    }

    /// 接线守恒：**两条入口的调用点集合必须逐字等于登记表**，一条不多一条不少。
    ///
    /// 立项形状（AGENTS 67(c)/㉔）：只判"handler 里出现了 draft"这种存在性锁，有人整段
    /// 删掉接线、或把 `/health` 探针换成测草稿，都能让判据保持绿。所以这里数**调用点集合**。
    ///
    /// `.test_connectivity(` 有两个同名不同服务的合法站点（`ai_config_service` 与
    /// `upload_config_service` 各一条），期望集因此含 `src/ai/handler.rs`——把它**写进**
    /// 期望而不是排除，是为了让"删掉任一接线"必然改变集合；把它当噪声剔掉就等于
    /// 给自己留了一条"扫到了但判不准"的路（AGENTS ⑯(c)）。
    #[test]
    fn draft_and_stored_entries_each_have_a_registered_consumer_set() {
        let files = prod_scan::prod_files(&Scan::default());
        prod_scan::require_volume(&files, 190, 20_000, "uploadConfig 接线守恒");
        let mut draft_sites = Vec::new();
        let mut stored_sites = Vec::new();
        for f in &files {
            let text = f.text();
            // `.test_connectivity(` 不是 `.test_connectivity_draft(` 的子串（y 后面是 `_`）
            if text.contains(".test_connectivity_draft(") {
                draft_sites.push(f.rel.clone());
            }
            if text.contains(".test_connectivity(") {
                stored_sites.push(f.rel.clone());
            }
        }
        draft_sites.sort();
        stored_sites.sort();
        assert_eq!(
            draft_sites,
            vec!["src/handler/upload_config_handler.rs".to_string()],
            "草稿入口的唯一消费者必须是管理页 handler（没有消费者=功能没接上；多一个=两份实现必漂）"
        );
        assert_eq!(
            stored_sites,
            vec![
                "src/ai/handler.rs".to_string(),
                "src/handler/health_probes.rs".to_string()
            ],
            "已存配置入口：`src/handler/health_probes.rs` 是 /health 存储探针（探针测部署态，\
             给它喂草稿等于让一次表单输入改变 /health 的结论）；`src/ai/handler.rs` 是\
             **同名不同服务**的 `ai_config_service::test_connectivity`。两者都必须在册"
        );
    }

    /// `test_config` 的**函数体**必须消费草稿、且不得回落到只读已存配置的那条入口。
    ///
    /// 收窄到函数体而不是整份文件（AGENTS ㊴：`switch_backend` 那里也有
    /// `upload_config_service` 的调用，整份文件级 needle 会被别处的合法字面量洗绿）。
    /// 三条合成用例各挡一种退化：整段删接线 / 换回旧入口 / 只在注释里提到草稿。
    #[test]
    fn test_config_handler_body_consumes_the_draft() {
        let handler =
            prod_scan::prod_file("src/handler/upload_config_handler.rs", &Scan::default());
        let body = fn_body(&handler.lines, DECL).unwrap_or_else(|| {
            panic!(
                "test_config 的函数体取不到（采集面坏了，不是\"没有违规\"）：{}",
                handler.rel
            )
        });
        assert!(
            body.contains(".test_connectivity_draft("),
            "test_config 必须按草稿探活，实测函数体={body}"
        );
        assert!(
            !body.contains(".test_connectivity("),
            "test_config 不得再走只读已存配置的那条入口（那样「测的是屏上这份」又是假话）"
        );

        // 合成双向：三种坏形状必须判否，合规形状必须判是。
        // 一律先过 `view()`（= 真实管道 prod_scan::normalize），否则"注释里提到不算"
        // 这条只是我自己写的字符串比较，没有证明任何东西（AGENTS ⑬）。
        assert!(
            fn_body(
                &view("pub async fn test_config(\n    a: u8,\n) -> R {\n    let _ = svc.test_connectivity_draft(&d);\n}\n"),
                DECL
            )
            .unwrap()
            .contains(".test_connectivity_draft("),
            "合规形状必须被判是（否则上面的断言可以是'永远为假'实现的另一种写法）"
        );
        assert!(
            !fn_body(
                &view("pub async fn test_config(\n    a: u8,\n) -> R {\n    ensure_platform(&op)?;\n    Ok(AjaxResult::success(String::new()))\n}\n"),
                DECL
            )
            .unwrap()
            .contains(".test_connectivity_draft("),
            "整段删掉接线必须被判否（存在性锁在这里会照常绿）"
        );
        let body_old = fn_body(
            &view("pub async fn test_config(\n    a: u8,\n) -> R {\n    let _ = svc.test_connectivity();\n}\n"),
            DECL,
        )
        .unwrap();
        assert!(
            !body_old.contains(".test_connectivity_draft(")
                && body_old.contains(".test_connectivity("),
            "换回旧入口必须被两条断言同时抓到"
        );
        assert!(
            !fn_body(
                &view("pub async fn test_config(\n    a: u8,\n) -> R {\n    // svc.test_connectivity_draft(&d);\n    let _ = svc.test_connectivity();\n}\n"),
                DECL
            )
            .unwrap()
            .contains(".test_connectivity_draft("),
            "注释里提到草稿不算接线"
        );
        // 区间终点：下一个顶格声明必须截断区间，否则隔壁函数的调用点会被算进本函数体
        let two_fns = view(concat!(
            "pub async fn test_config(\n    a: u8,\n) -> R {\n    ok();\n}\n",
            "pub async fn other() -> R {\n    let _ = svc.test_connectivity_draft(&d);\n    Ok(1)\n}\n"
        ));
        let body_two = fn_body(&two_fns, DECL).unwrap();
        assert!(
            !body_two.contains(".test_connectivity_draft("),
            "隔壁函数里的草稿调用不得算进 test_config 的函数体，实测={body_two}"
        );
    }

    /// 判据要找的声明行（用 `concat!` 拼：本文件里的字面量若与 needle 同形，
    /// 反查型判据就会匹配到自己那一行而恒真——AGENTS ㊴ 的同一条）。
    const DECL: &str = concat!("pub async fn test_", "config(");

    /// 真实采集管道：把源码文本按"生产码视图"归一（注释置空、`#[cfg(test)]` 截断）。
    fn view(text: &str) -> Vec<String> {
        prod_scan::normalize(text, &Scan::default())
    }

    /// 从顶格函数声明起做**花括号配平**取函数体（含声明行）。
    ///
    /// 三个各自踩过的坑：① 声明行**自己**也以 `pub async fn ` 开头 ⇒ 终止条件必须写成
    /// `i > start && (A || B || C)`；不写括号时 `&&` 先于 `||` 结合，第一个顶格声明就把
    /// 区间掐成空串（本批第一版就是这么红的——而红的仍是判据自己，不是产品）；
    /// ② 签名是多行的 ⇒ 只有**见过开括号之后** depth 归零才算结束，否则取到空体；
    /// ③ 硬终点取"下一个顶格 `fn `"：找不到闭包时不得一路吃到文件末尾。
    fn fn_body(lines: &[String], decl: &str) -> Option<String> {
        let start = lines
            .iter()
            .position(|l| l.trim_start().starts_with(decl))?;
        let mut depth = 0i32;
        let mut seen_open = false;
        let mut out = String::new();
        for (i, line) in lines.iter().enumerate().skip(start) {
            if i > start
                && (line.starts_with("fn ")
                    || line.starts_with("pub fn ")
                    || line.starts_with("pub async fn "))
            {
                break;
            }
            out.push_str(line);
            out.push('\n');
            depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
            if line.contains('{') {
                seen_open = true;
            }
            if seen_open && depth <= 0 {
                break;
            }
        }
        Some(out)
    }
}
