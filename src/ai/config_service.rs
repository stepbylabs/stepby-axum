// stepby-axum/src/ai/config_service.rs
//! AI 助手运行时配置服务（AI-01，§5.39 设计文档 ai01-02-design-2026-10-06.md）
//!
//! **双源语义**：config.toml `[ai]` 段为出厂缺省（startup 快照）；`sys.ai.*`
//! 六键（sys_config，管理页可改热生效）存在且非空即覆盖。
//!
//! 安全：
//! - api_key 信封加密存储（`seal_sensitive_value`，enc2: 前缀），读取时
//!   `unseal_sensitive_value` 解密喂给 provider，管理页只回显掩码；
//! - base_url 变更时走 `common::ssrf` 校验（防 DNS rebinding/私网穿透）；
//! - 平台专属（handler 层 `tenant_id == 0` 门控）。

use serde::Serialize;
use std::sync::Arc;
use ts_rs::TS;

use crate::common::ServiceError;
use crate::config::settings::AiConfig;
use crate::service::sys_config_service::SysConfigService;
use crate::utils::crypto::{seal_sensitive_value, unseal_sensitive_value};

const KEY_ENABLED: &str = "sys.ai.enabled";
const KEY_PROVIDER: &str = "sys.ai.provider";
const KEY_BASE_URL: &str = "sys.ai.base_url";
const KEY_API_KEY: &str = "sys.ai.api_key";
const KEY_MODEL: &str = "sys.ai.model";
const KEY_ALLOWED_TABLES: &str = "sys.ai.allowed_tables";

pub struct AiConfigService {
    pub db: Arc<sea_orm::DatabaseConnection>,
    pub config_service: SysConfigService,
    /// config.toml `[ai]` 段出厂缺省快照（sys.ai.* 键为空时回落）
    pub startup: AiConfig,
    pub enc_key: String,
}

/// 管理页回显 VO（api_key 掩码，永不回显明文）
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename_all = "camelCase")]
pub struct AiConfigMaskedVo {
    pub enabled: bool,
    pub provider: String,
    pub base_url: String,
    pub api_key_masked: String,
    pub has_api_key: bool,
    pub model: String,
    pub allowed_tables: Vec<String>,
}

/// 管理页更新入参（api_key 为 None/空串 = 保留原值）
#[derive(Debug, Clone, serde::Deserialize, garde::Validate)]
#[serde(rename_all = "camelCase")]
pub struct AiConfigUpdateDto {
    #[garde(skip)]
    pub enabled: bool,
    #[garde(length(min = 1, max = 64))]
    pub provider: String,
    #[garde(length(max = 300))]
    pub base_url: String,
    /// None/空串 = 保留原值；有值 = 更新（服务端 seal 后落库，请求体由
    /// oper_log is_sensitive_key 自动脱敏）
    #[garde(length(max = 200))]
    pub api_key: Option<String>,
    #[garde(length(min = 1, max = 100))]
    pub model: String,
    #[garde(length(max = 2000))]
    pub allowed_tables: Vec<String>,
}

impl AiConfigService {
    pub fn new(
        db: Arc<sea_orm::DatabaseConnection>,
        config_service: SysConfigService,
        startup: AiConfig,
        enc_key: String,
    ) -> Self {
        Self {
            db,
            config_service,
            startup,
            enc_key,
        }
    }

    /// 读单个 `sys.ai.*` 键（cache-aside）
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

    /// **运行时有效配置**（chat/tables 每次调用 resolve，方案 Y：cache-aside O(1)）
    pub async fn get_effective(&self) -> Result<AiConfig, ServiceError> {
        let enabled = match self.raw(KEY_ENABLED).await? {
            Some(v) if !v.trim().is_empty() => v.trim().eq_ignore_ascii_case("true"),
            _ => self.startup.enabled,
        };
        let provider = self
            .effective_string(KEY_PROVIDER, &self.startup.provider)
            .await?;
        let base_url = self
            .effective_string(KEY_BASE_URL, &self.startup.base_url)
            .await?;
        let model = self
            .effective_string(KEY_MODEL, &self.startup.model)
            .await?;
        let allowed_tables_raw = self
            .effective_string(KEY_ALLOWED_TABLES, &self.startup.allowed_tables.join(","))
            .await?;
        // 白名单表名会被拼进 `PRAGMA table_info(...)` / information_schema 语句
        // （SQLite 的 PRAGMA 不支持绑定参数）⇒ 这里按标识符形状过滤。非法条目
        // 直接剔除（收窄可查询面是安全方向），但必须留痕——否则"面板里少了一张
        // 表"将无从归因。管理端保存路径另有 400 拒绝（见 `update`）。
        let mut allowed_tables: Vec<String> = Vec::new();
        let mut invalid_tables: Vec<&str> = Vec::new();
        for s in allowed_tables_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if crate::common::sql_dialect::is_valid_identifier(s) {
                allowed_tables.push(s.to_string());
            } else {
                invalid_tables.push(s);
            }
        }
        if !invalid_tables.is_empty() {
            tracing::warn!(
                invalid = ?invalid_tables,
                "AI 配置 allowed_tables 含非法标识符，已忽略这些条目"
            );
        }
        // api_key：sys.ai.api_key 存的是信封密文（enc2: 前缀）——unseal 回明文；
        // 键缺失/空回落 startup（env/config.toml 注入）
        let api_key = match self.raw(KEY_API_KEY).await? {
            Some(stored) if !stored.trim().is_empty() => {
                unseal_sensitive_value(&stored, &self.enc_key)
            }
            _ => self.startup.api_key.clone(),
        };
        Ok(AiConfig {
            enabled,
            provider,
            base_url,
            api_key,
            model,
            max_rows: self.startup.max_rows,
            timeout_secs: self.startup.timeout_secs,
            // b72：并发上限**不透传 sys.ai.* 热更值**（本字段无对应热键，恒为启动配置），
            // 与 `ai::gate` 的"闸门上限启动只读"口径保持一致，避免管理端出现改不动的假入口
            max_concurrency: self.startup.max_concurrency,
            allowed_tables,
        })
    }

    /// 管理页回显（api_key 掩码）
    pub async fn masked(&self) -> Result<AiConfigMaskedVo, ServiceError> {
        let effective = self.get_effective().await?;
        let stored = self.raw(KEY_API_KEY).await?.unwrap_or_default();
        let has_api_key = !stored.trim().is_empty() && !effective.api_key.is_empty();
        let api_key_masked = if effective.api_key.is_empty() {
            String::new()
        } else {
            crate::utils::masking::mask_keep(&effective.api_key, 3, 4)
        };
        Ok(AiConfigMaskedVo {
            enabled: effective.enabled,
            provider: effective.provider,
            base_url: effective.base_url,
            api_key_masked,
            has_api_key,
            model: effective.model,
            allowed_tables: effective.allowed_tables,
        })
    }

    /// 六键 UPDATE（写后 refreshCache 热生效）。
    ///
    /// SQL 本体收敛到 `SysConfigService::set_platform_value`（b83）：本处原写死
    /// `DatabaseBackend::Sqlite` 并把 `update_time` 交给 `CURRENT_TIMESTAMP`，
    /// 前者在 PG 部署下语法失败、后者在 SQLite/MySQL/PG 三库落不同时区。
    async fn write_key(&self, key: &str, value: &str) -> Result<(), ServiceError> {
        self.config_service.set_platform_value(key, value).await
    }

    /// 管理页更新：SSRF 校验 base_url + api_key seal + 六键写入 + 缓存失效
    pub async fn update(&self, dto: &AiConfigUpdateDto) -> Result<(), ServiceError> {
        // base_url 非空 → SSRF 校验（防 DNS rebinding/私网穿透；对齐既有出站防护）
        if !dto.base_url.trim().is_empty() {
            let url = crate::common::ssrf::validate_url(dto.base_url.trim())
                .map_err(|e| ServiceError::bad_request(&format!("base_url 不被允许: {e}")))?;
            let port = url.port_or_known_default().unwrap_or(443);
            crate::common::ssrf::validate_host_resolution(url.host_str().unwrap_or_default(), port)
                .await
                .map_err(|e| ServiceError::bad_request(&format!("base_url 主机不可用: {e}")))?;
        }
        // 表名要拼进语句，保存时就把非法形状挡在门外——且必须排在任何 `write_key`
        // **之前**：六键是逐条写的，校验放在写了一半之后就会留下半应用配置。
        if let Some(bad) = dto
            .allowed_tables
            .iter()
            .map(|s| s.trim())
            .find(|s| !s.is_empty() && !crate::common::sql_dialect::is_valid_identifier(s))
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.ai.allowed_table_invalid",
                name = bad
            )));
        }
        self.write_key(KEY_ENABLED, if dto.enabled { "true" } else { "false" })
            .await?;
        self.write_key(KEY_PROVIDER, dto.provider.trim()).await?;
        self.write_key(KEY_BASE_URL, dto.base_url.trim()).await?;
        if let Some(k) = dto.api_key.as_deref()
            && !k.trim().is_empty()
        {
            let sealed = seal_sensitive_value(k.trim(), &self.enc_key)
                .map_err(|e| ServiceError::internal(&format!("api_key 加密失败: {e}")))?;
            self.write_key(KEY_API_KEY, &sealed).await?;
        }
        self.write_key(KEY_MODEL, dto.model.trim()).await?;
        self.write_key(
            KEY_ALLOWED_TABLES,
            &dto.allowed_tables
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(","),
        )
        .await?;
        // 热生效：失效 sys_config 缓存（cache-aside 下次读新值）。
        // 旁路语义：六键已写库，刷新失败不把"保存成功"变成 5xx（b105 收口假成功时拆出的两档）。
        self.config_service
            .refresh_cache_best_effort("ai.config")
            .await;
        tracing::info!(
            operator_manual = true,
            "AI 助手配置已更新（sys.ai.* 六键，热生效）"
        );
        Ok(())
    }

    /// 连通性测试：最小 completions 请求（独立 10s 超时，不消耗业务超时预算）
    pub async fn test_connectivity(&self) -> Result<String, ServiceError> {
        let effective = self.get_effective().await?;
        if effective.base_url.is_empty() || effective.api_key.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.ai.config_missing"
            )));
        }
        // b144：走 `outbound_client::build_with` ⇒ 宿主缺系统信任库时仍能用内嵌根证书出站
        // （裸构造在这种宿主上必然失败，于是"测试连接"报的是"client 构建失败"，
        // 而真正缺的是 ca-certificates——把人支使去查 AI 配置）。
        let client = crate::common::outbound_client::build_with("ai_config_test", |b| {
            b.timeout(std::time::Duration::from_secs(10))
        })
        .map_err(|e| ServiceError::internal(&format!("client 构建失败: {e}")))?;
        let url = format!(
            "{}/chat/completions",
            effective.base_url.trim_end_matches('/')
        );
        // b74（AGENTS B.4）：管理端"测试连接"是**独立故障面**（显式动作、会产生 token 费用），
        // 与业务推理（component="ai"）、探针（component="probe:ai"）分开计数，
        // 否则"探针慢/推理拒签"会被这个低频动作平均掉。
        let mut outbound = crate::observability::metrics::OutboundGuard::start("ai_config_test");
        let started = std::time::Instant::now();
        let resp = client
            .post(&url)
            .bearer_auth(&effective.api_key)
            .json(&serde_json::json!({
                "model": effective.model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1
            }))
            .send()
            .await
            .map_err(|e| ServiceError::bad_request(&format!("连通失败: {e}")))?;
        let ms = started.elapsed().as_millis();
        let status = resp.status().as_u16();
        if status == 200 {
            outbound.succeeded();
            Ok(format!("连通正常（模型 {}，{ms}ms）", effective.model))
        } else {
            // b145：上游给的理由（配额 / 无效凭据 / 地区限制）就在响应体里。
            // 旧写法 `text().unwrap_or_default()` 把"读不到"折成空串，消息只剩 `status=403: `。
            let body =
                crate::common::outbound_error_body::read_error_body(resp, "ai:config_test").await;
            Err(ServiceError::bad_request(&format!(
                "连通异常 status={status}: {body}"
            )))
        }
    }

    /// 外部依赖探活（AGENTS #5，接入 `/health`）：**零 token 成本**的可达性判定。
    ///
    /// 与 [`Self::test_connectivity`] 的分工必须清楚：后者是管理端"保存并测试"的显式
    /// 动作，会发一次最小 completion（**产生 token 费用**），不能接进周期探针；本方法
    /// 只 `GET {base_url}/models`（OpenAI 兼容端点的标准元数据接口，与本项目硬编码
    /// `{base_url}/chat/completions` 的同一档位假设），2xx 即判可达。
    ///
    /// 返回 `Ok(None)` = 依赖未启用/未配置 ⇒ 探针语义为 SKIPPED（可选依赖没配不是故障）。
    /// 失败信息只带状态码与耗时：供应商响应体可能含其内部信息，不进公开端点。
    pub async fn probe_reachability(&self) -> Result<Option<String>, ServiceError> {
        let effective = self.get_effective().await?;
        if !effective.enabled
            || effective.base_url.trim().is_empty()
            || effective.api_key.trim().is_empty()
        {
            return Ok(None);
        }
        let url = format!("{}/models", effective.base_url.trim_end_matches('/'));
        // b144：与 chat/completions 那一支同口径（内嵌根证书回落），label 单独成桶——
        // "列模型"与"测试连接"是两个动作，故障时运维需要知道是哪一条。
        let client = crate::common::outbound_client::build_with("ai_config_models", |b| {
            b.timeout(std::time::Duration::from_secs(10))
        })
        .map_err(|e| ServiceError::internal(&format!("client 构建失败: {e}")))?;
        let started = std::time::Instant::now();
        let resp = client
            .get(&url)
            .bearer_auth(&effective.api_key)
            .send()
            .await
            .map_err(|e| ServiceError::bad_request(&format!("AI provider 不可达: {e}")))?;
        let ms = started.elapsed().as_millis();
        let code = resp.status().as_u16();
        if resp.status().is_success() {
            Ok(Some(format!("连通正常（HTTP {code}，{ms}ms）")))
        } else {
            Err(ServiceError::bad_request(&format!(
                "AI provider 返回 HTTP {code}（{ms}ms）"
            )))
        }
    }
}
