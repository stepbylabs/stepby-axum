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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use garde::Validate;
use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_rate_limit::{
    ActiveModel as SysRateLimitActiveModel, Column as RateLimitColumn, Model as SysRateLimitModel,
};
use crate::middleware::rate_limit::RateLimitConfig;
use crate::repository::sys_rate_limit::SysRateLimitRepository;
use crate::shared_store::SharedStore;

/// 限流缓存 key 前缀（格式：rate_limit:config:{route}）
const RATE_LIMIT_CACHE_PREFIX: &str = "rate_limit:config:";
/// 限流缓存 TTL（秒，5 分钟）
const RATE_LIMIT_CACHE_TTL: i64 = 300;
/// 全局默认 route_pattern
const GLOBAL_DEFAULT_PATTERN: &str = "*";
/// M-2：进程内缓存 TTL（秒）
///
/// 限流中间件每个请求都会调用 get_config_for_route，若每次都走共享存储 GET 会引入
/// 额外往返开销。进程内缓存以短 TTL（10s）缓存最近配置，命中时直接返回，避免该往返。
/// 10s 窗口足以平滑突发请求，配置变更后最长 10s 生效（invalidate 时立即清空）。
const LOCAL_CACHE_TTL_SECS: u64 = 10;

/// R-2：进程内缓存最大条目数，超过时触发惰性清理（移除已过期条目）
///
/// route_pattern 集合通常有界（与 API 路由数量相当），此上限用于防御异常场景下的内存增长。
const LOCAL_CACHE_MAX_ENTRIES: usize = 1024;

// ==================== DTO ====================

/// 限流配置分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    pub route_pattern: Option<String>,
    pub enabled: Option<bool>,
}

impl From<&RateLimitQueryDto> for PageDomain {
    fn from(dto: &RateLimitQueryDto) -> Self {
        // 动态排序透传：先 sanitize（格式白名单），列级白名单在 service 查询时解析
        let mut page = PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: dto.order_by_column.clone(),
            is_asc: dto.is_asc.clone(),
        };
        page.sanitize_order_fields();
        page
    }
}

/// 新增限流配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitAddDto {
    #[garde(length(min = 1, max = 200))]
    pub route_pattern: String,
    #[garde(range(min = 1, max = 10000))]
    pub capacity: i32,
    #[garde(range(min = 0.1, max = 1000.0))]
    pub refill_per_second: f64,
    #[serde(default = "default_true")]
    #[garde(skip)]
    pub enabled: bool,
    #[garde(length(max = 500))]
    pub description: Option<String>,
}

/// 修改限流配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitEditDto {
    #[garde(skip)]
    pub id: i64,
    #[garde(length(min = 1, max = 200))]
    pub route_pattern: String,
    #[garde(range(min = 1, max = 10000))]
    pub capacity: i32,
    #[garde(range(min = 0.1, max = 1000.0))]
    pub refill_per_second: f64,
    #[garde(skip)]
    pub enabled: bool,
    #[garde(length(max = 500))]
    pub description: Option<String>,
}

/// serde 默认值函数：true
fn default_true() -> bool {
    true
}

// ==================== Service 实现 ====================

/// 允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖限流配置业务展示列（路由 pattern、容量/速率、启停、时间）；
/// `create_by` / `update_by` 等内部审计列不开放动态排序。
const SORTABLE_COLUMNS: &[(&str, RateLimitColumn)] = &[
    ("id", RateLimitColumn::Id),
    ("route_pattern", RateLimitColumn::RoutePattern),
    ("capacity", RateLimitColumn::Capacity),
    ("refill_per_second", RateLimitColumn::RefillPerSecond),
    ("enabled", RateLimitColumn::Enabled),
    ("create_time", RateLimitColumn::CreateTime),
    ("update_time", RateLimitColumn::UpdateTime),
];

/// 某路由解析出的**限流档位**（配置 + 分桶口径）。
///
/// `own_tier` 语义：`true` = DB 中存在 `route_pattern == 本路由` 且启用的行（该接口有
/// 自己的档位）；`false` = 回落 `*` 全局默认。中间件据此选择桶：
/// - `true` ⇒ 桶键含路由模板（各档位彼此隔离）；
/// - `false` ⇒ 沿用 `rate_limit:{tid}:{ip}` 共享桶（与改造前**逐字节等价**）。
///
/// 为什么必须分流：本表此前所有档位共用同一个 (租户,IP) 桶，桶参数取"当前这一次请求
/// 命中的行"——于是 5 次/20s 的敏感操作档位会把同客户端的无关接口一起掐断（b72 实证）。
#[derive(Debug, Clone, Copy)]
pub struct RateLimitTier {
    pub config: RateLimitConfig,
    pub own_tier: bool,
}

/// API 限流配置 Service
///
/// 数据访问通过 Repository 层委托：
/// - rate_limit_repo: sys_rate_limit 表 CRUD
/// - store: 共享态存储（SharedStore），用于限流配置缓存（cache-aside 模式）
///
/// M-2：增加进程内短 TTL 缓存（local_cache），减少限流中间件每请求一次的共享存储往返。
/// 缓存层次：local_cache (10s) → 共享存储 (300s) → DB。配置变更时 invalidate 同时清空 local_cache。
pub struct SysRateLimitService {
    rate_limit_repo: SysRateLimitRepository,
    store: Arc<dyn SharedStore>,
    /// M-2：进程内缓存（route → (config, fetched_at)），短 TTL 减少共享存储往返
    local_cache: Mutex<HashMap<String, (RateLimitTier, Instant)>>,
}

impl SysRateLimitService {
    pub fn new(db: DatabaseConnection, store: Arc<dyn SharedStore>) -> Self {
        Self {
            rate_limit_repo: SysRateLimitRepository::new(db),
            store,
            local_cache: Mutex::new(HashMap::new()),
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
    ///
    /// M-2：同时清空进程内 local_cache，确保配置变更后立即生效（最长延迟 0s）。
    pub async fn invalidate_all_cache(&self) {
        // M-2：先清空进程内缓存（同步、立即生效）
        // H-1：Mutex 中毒时恢复 Guard 而非忽略（避免中毒后缓存永久失效）
        {
            let mut cache = self.local_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.clear();
        }
        let pattern = format!("{}*", RATE_LIMIT_CACHE_PREFIX);
        // 全量扫描（原 cursor 循环至游标归零的语义）；失败仅 warn 后返回
        let keys = match self.store.scan(&pattern, None).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!("扫描限流缓存键失败: {}", e);
                return;
            }
        };
        if !keys.is_empty() {
            // 批量删除（原 pipeline 语义——非事务允许部分成功，del 多键等价）
            if let Err(e) = self.store.del(&keys).await {
                tracing::warn!("批量删除限流缓存失败: {}", e);
            }
        }
    }

    /// 失效指定 route_pattern 的缓存（修改/删除时调用）
    ///
    /// 由于缓存以输入 route 为 key，单个 route_pattern 的变更可能影响多个缓存条目，
    /// 因此实际采用扫描清除所有 rate_limit:config:* 键的方式。
    pub async fn invalidate_cache(&self, _route_pattern: &str) {
        self.invalidate_all_cache().await;
    }

    /// R-2：惰性清理进程内缓存（移除已过期条目，防止内存无限增长）
    ///
    /// 在 local_cache 条目数超过 LOCAL_CACHE_MAX_ENTRIES 时触发，移除所有已过 TTL 的条目。
    /// 采用 `retain` 保留未过期条目，O(n) 遍历。H-1：Mutex 中毒时恢复 Guard。
    fn cleanup_local_cache(&self) {
        let mut cache = self.local_cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() <= LOCAL_CACHE_MAX_ENTRIES {
            return;
        }
        let now = Instant::now();
        let ttl = Duration::from_secs(LOCAL_CACHE_TTL_SECS);
        cache.retain(|_, (_, fetched_at)| now.duration_since(*fetched_at) <= ttl);
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
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_rate_limit::Entity>(prop, SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let (rows, total) = self
            .rate_limit_repo
            .find_page_filtered(
                offset,
                limit,
                query.route_pattern.as_deref(),
                query.enabled,
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 根据 id 查询限流配置详情
    pub async fn get_by_id(&self, id: i64) -> Result<SysRateLimitModel, ServiceError> {
        self.rate_limit_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.rate_limit.not_found")))
    }

    /// 新增限流配置
    ///
    /// 业务校验：route_pattern 唯一性
    pub async fn add(
        &self,
        dto: RateLimitAddDto,
        operator: &str,
    ) -> Result<SysRateLimitModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // route_pattern 唯一性校验
        let existing = self
            .rate_limit_repo
            .find_by_route_pattern(&dto.route_pattern)
            .await?;
        if existing.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.rate_limit.pattern_exists"
            )));
        }

        let route_pattern_for_cache = dto.route_pattern.clone();
        let now = crate::common::datetime::now_naive();
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
        crate::common::i18n::validate(&dto)?;

        let existing = self.get_by_id(dto.id).await?;

        // route_pattern 变更时校验唯一性（排除自身）
        let old_pattern = existing.route_pattern.clone();
        if dto.route_pattern != old_pattern {
            let conflict = self
                .rate_limit_repo
                .find_by_route_pattern(&dto.route_pattern)
                .await?;
            if conflict.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.rate_limit.pattern_exists"
                )));
            }
        }

        let route_pattern_for_cache = dto.route_pattern.clone();
        let now = crate::common::datetime::now_naive();
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

    /// 获取指定路由的限流配置（中间件调用；只需参数时用本方法，需要分桶口径用
    /// [`Self::resolve_tier_for_route`]）。
    pub async fn get_config_for_route(&self, route: &str) -> Result<RateLimitConfig, ServiceError> {
        Ok(self.resolve_tier_for_route(route).await?.config)
    }

    /// 解析指定路由的**限流档位**（配置 + 该路由是否拥有独立档位）。
    ///
    /// `has_own_tier` 是分桶口径的关键：限流桶必须按档位隔离，否则"敏感操作 5 次/20s"
    /// 这类紧档位会把同客户端的无关接口一起掐断（b72 e2e 实证：租户恢复(桶 5)之后
    /// 的域名 verify 直接 429）。见 `middleware::rate_limit` 的分桶说明。
    ///
    /// M-2 缓存层次：local_cache (10s) → Redis (300s) → DB
    /// 流程：
    /// 0. M-2：先查进程内 local_cache（短 TTL 10s），命中则直接返回，避免 Redis 往返
    /// 1. 从 Redis 缓存读取（key: rate_limit:config:{route}）
    /// 2. 缓存未命中则查 DB：先精确匹配 route_pattern=route，未命中则用 "*" 全局默认
    /// 3. 将结果缓存到 Redis（TTL 300 秒）+ local_cache（TTL 10s）
    /// 4. 缓存或 DB 查询失败时返回默认值 (capacity=100, refill_per_second=10.0)
    ///
    /// 注意：本方法不会返回错误（中间件无法处理错误），任何异常都降级到默认配置。
    /// 中间件调用方应使用 `unwrap_or_default()` 或 `.unwrap_or(RateLimitConfig::default())`。
    pub async fn resolve_tier_for_route(&self, route: &str) -> Result<RateLimitTier, ServiceError> {
        let key = Self::cache_key(route);

        // 0. M-2：先查进程内 local_cache（短 TTL，命中则直接返回，避免 Redis 往返）
        //    限流中间件每个请求都调用本方法，local_cache 命中可显著降低 Redis 压力。
        //    H-1：Mutex 中毒时恢复 Guard 而非忽略（避免中毒后 local_cache 永久失效）。
        //    用块作用域限定 MutexGuard 生命周期，确保其在 await 点前 drop（future 满足 Send）。
        let now = Instant::now();
        {
            let cache = self.local_cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((cfg, fetched_at)) = cache.get(route)
                && now.duration_since(*fetched_at) <= Duration::from_secs(LOCAL_CACHE_TTL_SECS)
            {
                return Ok(*cfg);
            }
        }

        // 1. 尝试从共享存储读取（R8-CONC-013：命令级超时已内建于 store 实现层，
        //    防止存储挂起导致请求阻塞；错误/超时 → 未命中，降级到 DB）
        let cached: Option<String> = self.store.get(&key).await.ok().flatten();

        if let Some(val) = cached
            && let Ok(cached_config) = serde_json::from_str::<RateLimitConfigCached>(&val)
        {
            let tier: RateLimitTier = cached_config.into();
            // M-2：回填 local_cache（best-effort）
            // H-1：Mutex 中毒时恢复 Guard，块作用域确保 await 前 drop
            {
                let mut cache = self.local_cache.lock().unwrap_or_else(|e| e.into_inner());
                cache.insert(route.to_string(), (tier, Instant::now()));
            }
            // R-2：惰性清理已过期的 local_cache 条目
            self.cleanup_local_cache();
            return Ok(tier);
        }
        // 反序列化失败或缓存未命中，继续查 DB（缓存损坏时后续会覆盖）

        // 2. 查 DB：先精确匹配 route_pattern=route（且 enabled=true），未命中则用 "*"
        //    `own_tier` 记录**是否命中了本路由自己的档位**——中间件据此决定分桶口径：
        //    独立档位必须独立成桶，否则"敏感操作 5 次/20s"这类紧档位会与同客户端的
        //    无关接口共用一个桶并互相掐断（b72 e2e 实证：租户恢复后域名 verify 429）。
        let own = self
            .rate_limit_repo
            .find_by_route_pattern(route)
            .await?
            .filter(|m| m.enabled);

        let (model, own_tier) = match own {
            Some(m) => (Some(m), true),
            None => (
                self.rate_limit_repo
                    .find_by_route_pattern(GLOBAL_DEFAULT_PATTERN)
                    .await?
                    .filter(|m| m.enabled),
                false,
            ),
        };

        let config = match model {
            Some(m) => RateLimitConfig {
                capacity: u32::try_from(m.capacity.max(0)).unwrap_or(u32::MAX),
                refill_per_second: m.refill_per_second,
            },
            None => RateLimitConfig::default(),
        };
        let tier = RateLimitTier { config, own_tier };

        // 3. 缓存到共享存储（best-effort，失败仅记日志不影响业务）
        //    R8-CONC-013：命令级超时已内建于 store 实现层（快速降级，不挂起请求）
        let cached_config = RateLimitConfigCached::from(&tier);
        if let Ok(val) = serde_json::to_string(&cached_config)
            && let Err(e) = self
                .store
                .set_ex(&key, &val, RATE_LIMIT_CACHE_TTL as u64)
                .await
        {
            tracing::warn!("缓存限流配置到 Redis 失败 (key={}): {}", key, e);
        }

        // M-2：回填 local_cache（best-effort，即使 Redis 写入失败也回填本地，下次请求仍可命中）
        // H-1：Mutex 中毒时恢复 Guard，块作用域确保无跨 await 持有
        {
            let mut cache = self.local_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(route.to_string(), (tier, Instant::now()));
        }
        // R-2：惰性清理已过期的 local_cache 条目
        self.cleanup_local_cache();

        Ok(tier)
    }

    /// 导出限流配置（全量查询不分页）
    pub async fn export(
        &self,
        query: RateLimitQueryDto,
    ) -> Result<Vec<SysRateLimitModel>, ServiceError> {
        // 导出与页面列表同序：动态排序白名单解析口径一致
        let page = PageDomain::from(&query);
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_rate_limit::Entity>(prop, SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let rows = self
            .rate_limit_repo
            .find_all_filtered(query.route_pattern.as_deref(), query.enabled, sort)
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
    /// b72：该路由是否拥有独立档位（分桶口径）。`#[serde(default)]` 保证升级期
    /// 存量缓存条目（无此字段）按 `false` 解读 = 沿用共享桶 = 与升级前行为一致，
    /// 最长 300s（Redis TTL）后自愈为正确口径。
    #[serde(default)]
    own_tier: bool,
}

impl From<&RateLimitTier> for RateLimitConfigCached {
    fn from(tier: &RateLimitTier) -> Self {
        Self {
            capacity: tier.config.capacity,
            refill_per_second: tier.config.refill_per_second,
            own_tier: tier.own_tier,
        }
    }
}

impl From<RateLimitConfigCached> for RateLimitTier {
    fn from(c: RateLimitConfigCached) -> Self {
        Self {
            config: RateLimitConfig {
                capacity: c.capacity,
                refill_per_second: c.refill_per_second,
            },
            own_tier: c.own_tier,
        }
    }
}
