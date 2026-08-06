//! 参数配置模块 Service 层
//!
//! 职责：
//! - 参数配置 CRUD、config_key 唯一性校验
//! - 按 config_key 查询参数值（前端读取配置用）
//! - 批量物理删除（config 表无 del_flag）
//! - Excel 导出全量查询
//! - 刷新缓存（当前无缓存层，直接返回成功）
//!
//! 不依赖任何 Web 框架类型（axum / tower / tower-http）

use std::time::Duration;

use redis::aio::ConnectionManager;
use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use garde::Validate;

use crate::common::error::ServiceError;
use crate::common::page::{default_page_num, default_page_size, PageDomain};
use crate::db::redis::REDIS_CMD_TIMEOUT_SECS;
use crate::entity::sys_config::{
    ActiveModel as SysConfigActiveModel, Model as SysConfigModel,
};
use crate::repository::sys_config::SysConfigRepository;

/// 配置缓存 key 前缀（H-4：cache-aside）
const CONFIG_CACHE_PREFIX: &str = "config:";

/// 缓存穿透防护：None 值的 sentinel（P2 修复：原实现不缓存 None，恶意请求不存在的 key 每次穿透 DB）
const CONFIG_NULL_MARKER: &str = "__NULL__";
/// 配置缓存 TTL（秒，5 分钟，H-4）
const CONFIG_CACHE_TTL: i64 = 300;

// ==================== DTO ====================

/// 参数配置分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub config_name: Option<String>,
    pub config_key: Option<String>,
    pub config_type: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&ConfigQueryDto> for PageDomain {
    fn from(dto: &ConfigQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 新增参数配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigAddDto {
    #[garde(length(min = 1, max = 100))]
    pub config_name: Option<String>,
    #[garde(length(min = 1, max = 100))]
    pub config_key: String,
    #[garde(skip)]
    pub config_value: Option<String>,
    #[garde(skip)]
    pub config_type: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 修改参数配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigEditDto {
    #[garde(skip)]
    pub config_id: i64,
    #[garde(length(min = 1, max = 100))]
    pub config_name: Option<String>,
    #[garde(length(min = 1, max = 100))]
    pub config_key: String,
    #[garde(skip)]
    pub config_value: Option<String>,
    #[garde(skip)]
    pub config_type: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

// ==================== 辅助函数 ====================

// ==================== Service 实现 ====================

/// 参数配置模块 Service
///
/// H-4：持有 Redis ConnectionManager 用于 cache-aside 缓存配置值，
/// 减少登录/注册流程对 sys_config 表的频繁查询（每次登录原本 2 次 DB 查询：
/// captchaEnabled + registerUser）。
#[derive(Clone)]
pub struct SysConfigService {
    config_repo: SysConfigRepository,
    redis: ConnectionManager,
}

impl SysConfigService {
    pub fn new(db: DatabaseConnection, redis: ConnectionManager) -> Self {
        Self {
            config_repo: SysConfigRepository::new(db),
            redis,
        }
    }

    /// H-4：按 config_key 查询参数值，带 Redis cache-aside 缓存
    ///
    /// 缓存策略：
    /// - key: `config:{config_key}`
    /// - TTL: 300 秒（5 分钟）
    /// - 命中：直接返回缓存的 config_value
    /// - 未命中：查 DB，缓存结果（仅缓存 Some 值；None 不缓存会导致缓存穿透，后续按需补充 sentinel）
    /// - Redis 错误：fail-open 降级到 DB（配置查询非安全敏感场景，可用性优先）
    ///
    /// 返回 `Option<String>`：
    /// - Some(value): 配置存在
    /// - None: 配置不存在或 DB 错误（调用方按业务默认值处理）
    ///
    /// 调用方：AuthService::is_captcha_enabled / is_register_enabled
    pub async fn get_config_value_by_key_cached(
        &self,
        config_key: &str,
    ) -> Result<Option<String>, ServiceError> {
        let cache_key = format!("{}{}", CONFIG_CACHE_PREFIX, config_key);
        let mut conn = self.redis.clone();

        // 1. 尝试从 Redis 缓存读取（fail-open：超时/错误降级到 DB）
        let cached: Option<String> = tokio::time::timeout(
            Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("GET").arg(&cache_key).query_async(&mut conn),
        )
        .await
        .ok()                  // 超时 → None（降级到 DB）
        .and_then(|r| r.ok())  // Redis 错误 → None
        .flatten();            // Option<Option<String>> → Option<String>

        if let Some(val) = cached {
            // P2：识别 None sentinel，避免缓存穿透
            if val == CONFIG_NULL_MARKER {
                return Ok(None);
            }
            return Ok(Some(val));
        }

        // 2. 缓存未命中 → 查 DB
        let model = self.config_repo.find_by_config_key(config_key).await?;
        let value = model.and_then(|m| m.config_value);

        // 3. 缓存结果（best-effort）：Some 值按正常 TTL 缓存；
        //    None 缓存 sentinel（P2：60s 短 TTL，既防穿透又避免长期陈旧）
        let cache_ttl = if value.is_some() { CONFIG_CACHE_TTL } else { 60i64 };
        let cache_value = value.clone().unwrap_or_else(|| CONFIG_NULL_MARKER.to_string());
        let _ = tokio::time::timeout(
            Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("SETEX")
                .arg(&cache_key)
                .arg(cache_ttl)
                .arg(&cache_value)
                .query_async::<()>(&mut conn),
        )
        .await;

        Ok(value)
    }

    /// H-4：失效指定 config_key 的缓存（修改/删除配置时调用）
    /// P2 修复: DEL 失败或超时时记录 warn 日志，便于排查脏读风险
    async fn invalidate_config_cache(&self, config_key: &str) {
        let cache_key = format!("{}{}", CONFIG_CACHE_PREFIX, config_key);
        let mut conn = self.redis.clone();
        let result = tokio::time::timeout(
            Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("DEL").arg(&cache_key).query_async::<()>(&mut conn),
        )
        .await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::warn!(
                    config_key = %config_key,
                    error = %e,
                    "配置缓存 DEL 失败，可能产生脏读直至 TTL 过期"
                );
            }
            Err(_) => {
                tracing::warn!(
                    config_key = %config_key,
                    "配置缓存 DEL 超时（{}s），可能产生脏读直至 TTL 过期",
                    REDIS_CMD_TIMEOUT_SECS
                );
            }
        }
    }

    /// 分页查询参数配置
    ///
    /// 支持 config_name 模糊、config_key 模糊、config_type 精确、时间范围筛选
    pub async fn get_config_page(
        &self,
        query: ConfigQueryDto,
    ) -> Result<(Vec<SysConfigModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        let (rows, total) = self
            .config_repo
            .find_page_filtered(
                offset,
                limit,
                query.config_name.as_deref(),
                query.config_key.as_deref(),
                query.config_type.as_deref(),
                begin,
                end,
            )
            .await?;
        Ok((rows, total))
    }

    /// 根据 config_id 查询参数配置详情
    pub async fn get_config_by_id(
        &self,
        config_id: i64,
    ) -> Result<SysConfigModel, ServiceError> {
        let model = self
            .config_repo
            .find_by_id(config_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.config.not_found")))?;
        Ok(model)
    }

    /// 按 config_key 查询参数值（前端读取配置用）
    ///
    /// 返回 config_value 字符串；若配置不存在返回 not_found。
    /// 安全：密钥类配置（key 含 secret/password/passwd/token/key/私钥/口令 等）返回值脱敏为 `***`，
    /// 避免通过 /system/config/configKey/{key} 接口泄露敏感明文（SEC-信息泄露面）。
    pub async fn get_config_by_key(
        &self,
        config_key: &str,
    ) -> Result<String, ServiceError> {
        let model = self
            .config_repo
            .find_by_config_key(config_key)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.config.not_found")))?;
        let value = model.config_value.unwrap_or_default();
        if Self::is_sensitive_key(config_key) {
            Ok("***".to_string())
        } else {
            Ok(value)
        }
    }

    /// 判断配置键是否可能为敏感密钥类（用于 configKey 查询脱敏）
    fn is_sensitive_key(key: &str) -> bool {
        let lower = key.to_ascii_lowercase();
        lower.contains("secret")
            || lower.contains("password")
            || lower.contains("passwd")
            || lower.contains("token")
            || lower.contains("apikey")
            || lower.contains("api_key")
            || lower.contains("privatekey")
            || lower.contains("private_key")
            || lower.contains("凭据")
            || lower.contains("密钥")
            || lower.contains("口令")
    }

    /// 新增参数配置
    ///
    /// 业务校验：config_key 唯一性
    pub async fn add_config(
        &self,
        dto: ConfigAddDto,
        operator: &str,
    ) -> Result<SysConfigModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // config_key 唯一性校验
        let existing = self.config_repo.find_by_config_key(&dto.config_key).await?;
        if existing.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!("error.config.key_exists")));
        }

        let now = crate::common::datetime::now_naive();
        let am = SysConfigActiveModel {
            config_name: Set(dto.config_name),
            config_key: Set(dto.config_key),
            config_value: Set(dto.config_value),
            config_type: Set(dto.config_type),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(dto.remark),
            ..Default::default()
        };

        let model = self.config_repo.insert(am).await?;
        // H-4：新增配置后失效该 key 的缓存（best-effort）
        self.invalidate_config_cache(&model.config_key).await;
        Ok(model)
    }

    /// 修改参数配置
    ///
    /// 业务校验：config_key 唯一性（排除自身）
    pub async fn edit_config(
        &self,
        dto: ConfigEditDto,
        operator: &str,
    ) -> Result<SysConfigModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let existing = self.get_config_by_id(dto.config_id).await?;

        // config_key 变更时校验唯一性（排除自身）
        let old_key = existing.config_key.clone();
        if dto.config_key != old_key {
            let conflict = self.config_repo.find_by_config_key(&dto.config_key).await?;
            if conflict.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!("error.config.key_exists")));
            }
        }

        let now = crate::common::datetime::now_naive();
        let mut am: SysConfigActiveModel = existing.into();
        am.config_name = Set(dto.config_name);
        am.config_key = Set(dto.config_key.clone());
        am.config_value = Set(dto.config_value);
        am.config_type = Set(dto.config_type);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.remark = Set(dto.remark);

        let model = self.config_repo.update(am).await?;
        // H-4：修改配置后失效缓存。若 config_key 变更，old_key 和 new_key 都需失效
        // （old_key 缓存的旧值已过时，new_key 可能存在 None 占位缓存）
        self.invalidate_config_cache(&old_key).await;
        self.invalidate_config_cache(&model.config_key).await;
        Ok(model)
    }

    /// 批量删除参数配置（物理删除，config 表无 del_flag）
    pub async fn delete_configs(&self, config_ids: Vec<i64>) -> Result<(), ServiceError> {
        if config_ids.is_empty() {
            return Ok(());
        }
        // H-4：删除前先查询 config_key（单次批量查询，避免 N+1），用于失效缓存
        let models = self.config_repo.find_by_ids(config_ids.clone()).await?;
        self.config_repo.delete_by_ids(config_ids).await?;
        // P2 优化: 批量失效 Redis 缓存使用 pipeline，避免循环单条 DEL 的 N 次 RTT
        // 与 refresh_cache() 方法保持一致
        if !models.is_empty() {
            let mut conn = self.redis.clone();
            let mut pipe = redis::pipe();
            for m in &models {
                pipe.cmd("DEL").arg(format!("{}{}", CONFIG_CACHE_PREFIX, m.config_key));
            }
            if let Err(e) = pipe.query_async::<Vec<i64>>(&mut conn).await {
                tracing::warn!("批量失效配置缓存失败: {}", e);
            }
        }
        Ok(())
    }

    /// 刷新缓存
    ///
    /// H-4：扫描并清除所有 `config:*` 缓存键。best-effort，Redis 错误仅记日志不影响业务。
    pub async fn refresh_cache(&self) -> Result<(), ServiceError> {
        let mut conn = self.redis.clone();
        let pattern = format!("{}*", CONFIG_CACHE_PREFIX);
        let keys = match crate::utils::redis::scan_keys(&mut conn, &pattern, 5000).await {
            Ok(ks) => ks,
            Err(e) => {
                tracing::warn!("刷新配置缓存时扫描键失败: {}", e);
                return Ok(());
            }
        };
        if keys.is_empty() {
            return Ok(());
        }
        let mut pipe = redis::pipe();
        for key in &keys {
            pipe.cmd("DEL").arg(key);
        }
        if let Err(e) = pipe.query_async::<Vec<i64>>(&mut conn).await {
            tracing::warn!("刷新配置缓存时批量删除失败: {}", e);
        }
        Ok(())
    }

    /// 导出参数配置（全量查询不分页）
    ///
    /// 支持与分页查询相同的筛选条件，返回全部匹配记录
    pub async fn export_configs(
        &self,
        query: ConfigQueryDto,
    ) -> Result<Vec<SysConfigModel>, ServiceError> {
        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        let rows = self
            .config_repo
            .find_all_filtered(
                query.config_name.as_deref(),
                query.config_key.as_deref(),
                query.config_type.as_deref(),
                begin,
                end,
            )
            .await?;
        Ok(rows)
    }
}
