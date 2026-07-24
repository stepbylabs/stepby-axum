//! API 限流配置 Service 层
//!
//! 职责：
//! - 限流配置 CRUD、route_pattern 唯一性校验
//! - 按 route 获取限流配置（中间件调用，带 Redis 缓存）
//! - 修改/删除时失效缓存
//! - Excel 导出全量查询
//!
//! 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! 但依赖 middleware::rate_limit::RateLimitConfig（仅数据结构，无循环依赖）

use std::time::Duration;

use redis::aio::ConnectionManager;
use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::common::error::ServiceError;
use crate::common::page::{default_page_num, default_page_size, PageDomain};
use crate::db::redis::REDIS_CMD_TIMEOUT_SECS;
use crate::entity::sys_rate_limit::{
    ActiveModel as SysRateLimitActiveModel, Model as SysRateLimitModel,
};
use crate::middleware::rate_limit::RateLimitConfig;
use crate::repository::sys_rate_limit::SysRateLimitRepository;

/// 限流缓存 key 前缀（格式：rate_limit:config:{route}）
const RATE_LIMIT_CACHE_PREFIX: &str = "rate_limit:config:";
/// 限流缓存 TTL（秒，5 分钟）
const RATE_LIMIT_CACHE_TTL: i64 = 300;
/// 全局默认 route_pattern
const GLOBAL_DEFAULT_PATTERN: &str = "*";

// ==================== DTO ====================

/// 限流配置分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub route_pattern: Option<String>,
    pub enabled: Option<bool>,
}

impl From<&RateLimitQueryDto> for PageDomain {
    fn from(dto: &RateLimitQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 新增限流配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitAddDto {
    #[validate(length(min = 1, max = 200, message = "路由前缀不能为空且不超过200字符"))]
    pub route_pattern: String,
    #[validate(range(min = 1, max = 10000, message = "桶容量范围为 1-10000"))]
    pub capacity: i32,
    #[validate(range(min = 0.1, max = 1000.0, message = "补充速率范围为 0.1-1000"))]
    pub refill_per_second: f64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[validate(length(max = 500, message = "描述长度不能超过500"))]
    pub description: Option<String>,
}

/// 修改限流配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitEditDto {
    pub id: i64,
    #[validate(length(min = 1, max = 200, message = "路由前缀不能为空且不超过200字符"))]
    pub route_pattern: String,
    #[validate(range(min = 1, max = 10000, message = "桶容量范围为 1-10000"))]
    pub capacity: i32,
    #[validate(range(min = 0.1, max = 1000.0, message = "补充速率范围为 0.1-1000"))]
    pub refill_per_second: f64,
    pub enabled: bool,
    #[validate(length(max = 500, message = "描述长度不能超过500"))]
    pub description: Option<String>,
}

/// serde 默认值函数：true
fn default_true() -> bool {
    true
}

// ==================== Service 实现 ====================

/// API 限流配置 Service
///
/// 数据访问通过 Repository 层委托：
/// - rate_limit_repo: sys_rate_limit 表 CRUD
/// - redis: Redis 连接管理器，用于限流配置缓存（cache-aside 模式）
pub struct SysRateLimitService {
    rate_limit_repo: SysRateLimitRepository,
    redis: ConnectionManager,
}

impl SysRateLimitService {
    pub fn new(db: DatabaseConnection, redis: ConnectionManager) -> Self {
        Self {
            rate_limit_repo: SysRateLimitRepository::new(db),
            redis,
        }
    }

    /// 构造限流缓存 key
    fn cache_key(route: &str) -> String {
        format!("{}{}", RATE_LIMIT_CACHE_PREFIX, route)
    }

    /// 失效所有限流缓存（best-effort，扫描并删除所有 rate_limit:config:* 键）
    ///
    /// 缓存以输入 route 为 key，单个 route_pattern 的变更可能影响多个缓存条目
    /// （例如修改 "*" 全局默认会影响所有未精确匹配的 route 缓存），
    /// 因此采用 SCAN + DEL 批量清除所有相关键。
    async fn invalidate_all_cache(&self) {
        let mut conn = self.redis.clone();
        let pattern = format!("{}*", RATE_LIMIT_CACHE_PREFIX);
        let mut cursor: u64 = 0;
        loop {
            let scan_result: Result<(u64, Vec<String>), _> = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await;
            let (next_cursor, keys) = match scan_result {
                Ok(result) => result,
                Err(e) => {
                    tracing::warn!("扫描限流缓存键失败: {}", e);
                    return;
                }
            };
            if !keys.is_empty() {
                let mut pipe = redis::pipe();
                for key in &keys {
                    pipe.cmd("DEL").arg(key);
                }
                if let Err(e) = pipe.query_async::<Vec<i64>>(&mut conn).await {
                    tracing::warn!("批量删除限流缓存失败: {}", e);
                }
            }
            if next_cursor == 0 {
                break;
            }
            cursor = next_cursor;
        }
    }

    /// 失效指定 route_pattern 的缓存（修改/删除时调用）
    ///
    /// 由于缓存以输入 route 为 key，单个 route_pattern 的变更可能影响多个缓存条目，
    /// 因此实际采用扫描清除所有 rate_limit:config:* 键的方式。
    pub async fn invalidate_cache(&self, _route_pattern: &str) {
        self.invalidate_all_cache().await;
    }

    /// 分页查询限流配置
    ///
    /// 支持 route_pattern 模糊、enabled 精确筛选
    pub async fn list(
        &self,
        query: RateLimitQueryDto,
    ) -> Result<(Vec<SysRateLimitModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let (rows, total) = self
            .rate_limit_repo
            .find_page_filtered(
                offset,
                limit,
                query.route_pattern.as_deref(),
                query.enabled,
            )
            .await?;
        Ok((rows, total))
    }

    /// 根据 id 查询限流配置详情
    pub async fn get_by_id(&self, id: i64) -> Result<SysRateLimitModel, ServiceError> {
        self.rate_limit_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| ServiceError::not_found("限流配置不存在"))
    }

    /// 新增限流配置
    ///
    /// 业务校验：route_pattern 唯一性
    pub async fn add(
        &self,
        dto: RateLimitAddDto,
        operator: &str,
    ) -> Result<SysRateLimitModel, ServiceError> {
        dto.validate()?;

        // route_pattern 唯一性校验
        let existing = self
            .rate_limit_repo
            .find_by_route_pattern(&dto.route_pattern)
            .await?;
        if existing.is_some() {
            return Err(ServiceError::bad_request("路由前缀已存在"));
        }

        let route_pattern_for_cache = dto.route_pattern.clone();
        let now = chrono::Local::now().naive_local();
        let am = SysRateLimitActiveModel {
            route_pattern: Set(dto.route_pattern),
            capacity: Set(dto.capacity),
            refill_per_second: Set(dto.refill_per_second),
            enabled: Set(dto.enabled),
            description: Set(dto.description),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            ..Default::default()
        };

        let model = self.rate_limit_repo.insert(am).await?;
        self.invalidate_cache(&route_pattern_for_cache).await;
        Ok(model)
    }

    /// 修改限流配置
    ///
    /// 业务校验：route_pattern 唯一性（排除自身）
    pub async fn edit(
        &self,
        dto: RateLimitEditDto,
        operator: &str,
    ) -> Result<SysRateLimitModel, ServiceError> {
        dto.validate()?;

        let existing = self.get_by_id(dto.id).await?;

        // route_pattern 变更时校验唯一性（排除自身）
        let old_pattern = existing.route_pattern.clone();
        if dto.route_pattern != old_pattern {
            let conflict = self
                .rate_limit_repo
                .find_by_route_pattern(&dto.route_pattern)
                .await?;
            if conflict.is_some() {
                return Err(ServiceError::bad_request("路由前缀已存在"));
            }
        }

        let route_pattern_for_cache = dto.route_pattern.clone();
        let now = chrono::Local::now().naive_local();
        let mut am: SysRateLimitActiveModel = existing.into();
        am.route_pattern = Set(dto.route_pattern);
        am.capacity = Set(dto.capacity);
        am.refill_per_second = Set(dto.refill_per_second);
        am.enabled = Set(dto.enabled);
        am.description = Set(dto.description);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));

        let model = self.rate_limit_repo.update(am).await?;
        self.invalidate_cache(&route_pattern_for_cache).await;
        Ok(model)
    }

    /// 批量删除限流配置（物理删除）
    pub async fn remove(&self, ids: Vec<i64>) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Ok(());
        }
        // 批量查询要删除的记录（单次查询替代 N 次 find_by_id）
        let models = self.rate_limit_repo.find_by_ids(ids.clone()).await?;

        self.rate_limit_repo.delete_by_ids(ids).await?;

        // 失效缓存：invalidate_cache 实际调用 invalidate_all_cache（扫描全量 key），
        // 原实现按 pattern 循环调用会触发 N 次 SCAN，这里降为单次全量失效。
        if !models.is_empty() {
            self.invalidate_all_cache().await;
        }
        Ok(())
    }

    /// 获取指定路由的限流配置（中间件调用）
    ///
    /// 流程：
    /// 1. 从 Redis 缓存读取（key: rate_limit:config:{route}）
    /// 2. 缓存未命中则查 DB：先精确匹配 route_pattern=route，未命中则用 "*" 全局默认
    /// 3. 将结果缓存到 Redis（TTL 300 秒）
    /// 4. 缓存或 DB 查询失败时返回默认值 (capacity=100, refill_per_second=10.0)
    ///
    /// 注意：本方法不会返回错误（中间件无法处理错误），任何异常都降级到默认配置。
    /// 中间件调用方应使用 `unwrap_or_default()` 或 `.unwrap_or(RateLimitConfig::default())`。
    pub async fn get_config_for_route(
        &self,
        route: &str,
    ) -> Result<RateLimitConfig, ServiceError> {
        let key = Self::cache_key(route);

        // 1. 尝试从 Redis 读取（R8-CONC-013：包裹 3s 超时，防止 Redis 挂起导致请求阻塞）
        let mut conn = self.redis.clone();
        let cached: Option<String> = tokio::time::timeout(
            Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("GET").arg(&key).query_async(&mut conn),
        )
        .await
        .ok()                  // 超时 → None（缓存未命中，降级到 DB）
        .and_then(|r| r.ok())  // Redis 错误 → None
        .flatten();            // Option<Option<String>> → Option<String>

        if let Some(val) = cached
            && let Ok(cached_config) = serde_json::from_str::<RateLimitConfigCached>(&val)
        {
            return Ok(cached_config.into());
        }
        // 反序列化失败或缓存未命中，继续查 DB（缓存损坏时后续会覆盖）

        // 2. 查 DB：先精确匹配 route_pattern=route（且 enabled=true），未命中则用 "*"
        let model = self
            .rate_limit_repo
            .find_by_route_pattern(route)
            .await?
            .filter(|m| m.enabled);

        let model = match model {
            Some(m) => Some(m),
            None => self
                .rate_limit_repo
                .find_by_route_pattern(GLOBAL_DEFAULT_PATTERN)
                .await?
                .filter(|m| m.enabled),
        };

        let config = match model {
            Some(m) => RateLimitConfig {
                capacity: m.capacity.max(0) as u32,
                refill_per_second: m.refill_per_second,
            },
            None => RateLimitConfig::default(),
        };

        // 3. 缓存到 Redis（best-effort，失败仅记日志不影响业务）
        //    R8-CONC-013：包裹 3s 超时，防止 SETEX 挂起（Redis 不可用时快速降级）
        let cached_config = RateLimitConfigCached::from(&config);
        if let Ok(val) = serde_json::to_string(&cached_config) {
            let cache_result = tokio::time::timeout(
                Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
                redis::cmd("SETEX")
                    .arg(&key)
                    .arg(RATE_LIMIT_CACHE_TTL)
                    .arg(val)
                    .query_async::<()>(&mut conn),
            )
            .await;
            match cache_result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("缓存限流配置到 Redis 失败 (key={}): {}", key, e),
                Err(e) => tracing::warn!("缓存限流配置到 Redis 超时 (key={}): {}", key, e),
            }
        }

        Ok(config)
    }

    /// 导出限流配置（全量查询不分页）
    pub async fn export(
        &self,
        query: RateLimitQueryDto,
    ) -> Result<Vec<SysRateLimitModel>, ServiceError> {
        let rows = self
            .rate_limit_repo
            .find_all_filtered(query.route_pattern.as_deref(), query.enabled)
            .await?;
        Ok(rows)
    }
}

/// 缓存序列化结构（与 RateLimitConfig 字段一致，用于 Redis JSON 存储）
///
/// 不直接序列化 RateLimitConfig 是因为该结构定义在 middleware 模块，
/// 未派生 Serialize/Deserialize，此处保持解耦。
#[derive(serde::Serialize, serde::Deserialize)]
struct RateLimitConfigCached {
    capacity: u32,
    refill_per_second: f64,
}

impl From<&RateLimitConfig> for RateLimitConfigCached {
    fn from(config: &RateLimitConfig) -> Self {
        Self {
            capacity: config.capacity,
            refill_per_second: config.refill_per_second,
        }
    }
}

impl From<RateLimitConfigCached> for RateLimitConfig {
    fn from(c: RateLimitConfigCached) -> Self {
        Self {
            capacity: c.capacity,
            refill_per_second: c.refill_per_second,
        }
    }
}
