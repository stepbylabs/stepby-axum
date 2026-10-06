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

use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
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
        let base_url = self.effective_string(KEY_BASE_URL, &self.startup.base_url).await?;
        let model = self.effective_string(KEY_MODEL, &self.startup.model).await?;
        let allowed_tables_raw = self
            .effective_string(KEY_ALLOWED_TABLES, &self.startup.allowed_tables.join(","))
            .await?;
        let allowed_tables: Vec<String> = allowed_tables_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
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

    /// 六键 UPDATE（直接 SQL——键固定且平台专属；写后 refreshCache 热生效）
    async fn write_key(&self, key: &str, value: &str) -> Result<(), ServiceError> {
        self.db
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE sys_config SET config_value = ?, update_time = CURRENT_TIMESTAMP WHERE config_key = ?",
                [value.into(), key.into()],
            ))
            .await
            .map_err(|e| ServiceError::internal(&format!("写入 {key} 失败: {e}")))?;
        Ok(())
    }

    /// 管理页更新：SSRF 校验 base_url + api_key seal + 六键写入 + 缓存失效
    pub async fn update(&self, dto: &AiConfigUpdateDto) -> Result<(), ServiceError> {
        // base_url 非空 → SSRF 校验（防 DNS rebinding/私网穿透；对齐既有出站防护）
        if !dto.base_url.trim().is_empty() {
            let url = crate::common::ssrf::validate_url(dto.base_url.trim())
                .map_err(|e| ServiceError::bad_request(&format!("base_url 不被允许: {e}")))?;
            let port = url.port_or_known_default().unwrap_or(443);
            crate::common::ssrf::validate_host_resolution(
                url.host_str().unwrap_or_default(),
                port,
            )
            .await
            .map_err(|e| ServiceError::bad_request(&format!("base_url 主机不可用: {e}")))?;
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
        // 热生效：失效 sys_config 缓存（cache-aside 下次读新值）
        self.config_service.refresh_cache().await?;
        tracing::info!(operator_manual = true, "AI 助手配置已更新（sys.ai.* 六键，热生效）");
        Ok(())
    }

    /// 连通性测试：最小 completions 请求（独立 10s 超时，不消耗业务超时预算）
    pub async fn test_connectivity(&self) -> Result<String, ServiceError> {
        let effective = self.get_effective().await?;
        if effective.base_url.is_empty() || effective.api_key.is_empty() {
            return Err(ServiceError::bad_request(
                "请先填写 base_url 与 api_key",
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| ServiceError::internal(&format!("client 构建失败: {e}")))?;
        let url = format!(
            "{}/chat/completions",
            effective.base_url.trim_end_matches('/')
        );
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
            Ok(format!("连通正常（模型 {}，{ms}ms）", effective.model))
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(ServiceError::bad_request(&format!(
                "连通异常 status={status}: {}",
                body.chars().take(120).collect::<String>()
            )))
        }
    }
}
