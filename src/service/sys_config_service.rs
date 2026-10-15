//! 参数配置模块 Service 层
//!
//! 职责：
//! - 参数配置 CRUD、config_key 唯一性校验（复合唯一域 `(tenant_id, config_key)`）
//! - 按 config_key 查询生效参数值（租户覆盖行优先，回落平台默认行）
//! - 批量物理删除（config 表无 del_flag）
//! - Excel 导出（平台全量 / 租户生效视图）
//! - **两层缓存**（§27.8）：平台默认层 `config:def:{key}` + 租户覆盖层 `config:{tid}:{key}`，
//!   读时合并、不缓存合并结果 → 平台改默认值只失效 def 层即可全局即时生效
//! - **治理列读写**（§27.8）：`scope` / `tenant_editable` / `visible_to_tenant`
//!
//! ## config 治理（§27.8 四条硬规则）
//! ① `platform_only`（平台安全项）集合由零依赖共享 crate `governance` 锁死
//!    界面**不允许**下放（`tenant_editable='0'`、`visible_to_tenant='0'`）；
//! ② 治理元数据（scope/editable/visible）的变更走本 Service 的写路径，
//!    而 `/system/config` 的写操作已被 `oper_log_middleware` 覆盖审计（actor + 前后值），
//!    故此处**无需**额外实现审计（元数据变更留痕由中间件保证）；
//! ③ 默认策略由注册表声明（`governance::CONFIGS` 的 `Coverage`）：迁移
//!    `m20260925_000004` 与启动兜底 `ensure_tenant_saas_governance` 都从**同一份数据**
//!    按覆盖策略分组 seed（此前是"同值本地副本 + 人工两处同步"），平台在允许范围内覆写；
//! ④ 敏感项由 `visible_to_tenant='0'` **显式声明**——`is_sensitive_key` 由"主判据"
//!    降级为"治理列缺省时的兜底"（见 `get_config_by_key`）。
//!
//! 不依赖任何 Web 框架类型（axum / tower / tower-http）

use futures::future::FutureExt;
use garde::Validate;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_config::{
    ActiveModel as SysConfigActiveModel, Column as ConfigColumn, Model as SysConfigModel,
};
use crate::repository::sys_config::SysConfigRepository;
use crate::shared_store::SharedStore;

// ==================== 治理常量（§27.8 硬规则① / ③，单一事实源）====================

/// `platform_only`（平台安全项）config key 集合——**注册表锁死，界面不允许下放**。
///
/// 安全底线：密码策略、验证码/注册开关、登录锁定、IP 库凭据、审计告警阈值等。
///
/// **单一事实源已上移到零依赖共享 crate `governance`**（`CONFIGS` 中
/// `Coverage::Locked` 的项）。迁移 `m20260925_000004` 与启动兜底
/// `ensure_tenant_saas_governance` 现在都引用同一份数据，不再需要
/// 「同值本地副本 + 修改时人工两处同步」。
pub use governance::locked_keys as platform_locked_keys;

/// `platform_default`（平台默认值，租户可见且可覆盖）config key 集合。
///
/// 单一事实源为共享 crate `governance`（`Coverage::Free` / `Coverage::Ceiling` 的项）。
pub use governance::default_keys as platform_default_keys;

/// 治理域取值：平台锁定（租户不可见、不可改）
const SCOPE_PLATFORM_ONLY: &str = "platform_only";
/// 治理域取值：平台默认（租户可见、可覆盖）
const SCOPE_PLATFORM_DEFAULT: &str = "platform_default";
/// 治理域取值：租户私有（仅本租户可见/可改）
const SCOPE_TENANT_PRIVATE: &str = "tenant_private";

// ==================== 缓存常量 ====================

/// 平台默认层缓存 key 前缀（§27.8：平台默认 `config:def:{key}`，无租户维度）
const CONFIG_DEFAULT_CACHE_PREFIX: &str = "config:def:";
/// 租户覆盖层缓存 key 前缀（§27.8：租户覆盖 `config:{tid}:{key}`）
const CONFIG_CACHE_PREFIX: &str = "config:";

/// 缓存穿透防护：None 值的 sentinel（原实现不缓存 None，恶意请求不存在的 key 每次穿透 DB）
const CONFIG_NULL_MARKER: &str = "__NULL__";
/// 配置值缓存 TTL（秒，5 分钟，H-4）
const CONFIG_CACHE_TTL: i64 = 300;
/// 空值（sentinel）缓存短 TTL（秒）：既防穿透又避免长期陈旧
const CONFIG_NULL_CACHE_TTL: i64 = 60;

/// 租户覆盖层缓存 key：`config:{tid}:{key}`
fn tenant_cache_key(tid: i64, config_key: &str) -> String {
    format!("{CONFIG_CACHE_PREFIX}{tid}:{config_key}")
}

/// 平台默认层缓存 key：`config:def:{key}`
fn default_cache_key(config_key: &str) -> String {
    format!("{CONFIG_DEFAULT_CACHE_PREFIX}{config_key}")
}

// ==================== DTO ====================

/// 参数配置分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigQueryDto {
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
    pub config_name: Option<String>,
    pub config_key: Option<String>,
    pub config_type: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 `params[beginTime]`）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 `params[endTime]`）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&ConfigQueryDto> for PageDomain {
    fn from(dto: &ConfigQueryDto) -> Self {
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
    /// 治理域（仅平台操作者可设置；租户写入被忽略并强制为 tenant_private）。
    /// 缺省/非法值 → 默认 `platform_only`（fail-closed）。
    #[garde(skip)]
    pub scope: Option<String>,
    /// 租户是否可覆盖（仅平台操作者可设置，'0'/'1'）。
    #[garde(skip)]
    pub tenant_editable: Option<String>,
    /// 租户是否可见（仅平台操作者可设置，'0'/'1'）。
    #[garde(skip)]
    pub visible_to_tenant: Option<String>,
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
    /// 治理域（仅平台操作者可设置；租户写入被忽略并保持 tenant_private）。
    #[garde(skip)]
    pub scope: Option<String>,
    /// 租户是否可覆盖（仅平台操作者可设置，'0'/'1'）。
    #[garde(skip)]
    pub tenant_editable: Option<String>,
    /// 租户是否可见（仅平台操作者可设置，'0'/'1'）。
    #[garde(skip)]
    pub visible_to_tenant: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

// ==================== 辅助函数 ====================

// ==================== Service 实现 ====================

/// 允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖参数配置业务展示列；`config_value`（值大字段，可能含密钥明文）、
/// `scope` / `tenant_editable` / `visible_to_tenant`（治理内部列）与
/// `tenant_id` / `create_by` / `update_by` / `remark` 不开放动态排序。
const SORTABLE_COLUMNS: &[(&str, ConfigColumn)] = &[
    ("config_id", ConfigColumn::ConfigId),
    ("config_name", ConfigColumn::ConfigName),
    ("config_key", ConfigColumn::ConfigKey),
    ("config_type", ConfigColumn::ConfigType),
    ("create_time", ConfigColumn::CreateTime),
    ("update_time", ConfigColumn::UpdateTime),
];

/// 参数配置模块 Service
///
/// H-4：持有共享态存储（SharedStore）用于 cache-aside 缓存配置值，
/// 减少登录/注册流程对 sys_config 表的频繁查询（每次登录原本 2 次 DB 查询：
/// captchaEnabled + registerUser）。
#[derive(Clone)]
pub struct SysConfigService {
    config_repo: SysConfigRepository,
    store: Arc<dyn SharedStore>,
}

impl SysConfigService {
    pub fn new(db: DatabaseConnection, store: Arc<dyn SharedStore>) -> Self {
        Self {
            config_repo: SysConfigRepository::new(db),
            store,
        }
    }

    // ==================== 缓存层（两层）====================

    /// 读单层缓存：`Some(Some(v))` = 命中值；`Some(None)` = 命中 None sentinel（该层无行）；
    /// `None` = 未命中或共享存储异常（fail-open 降级到 DB）。
    async fn read_cache_layer(&self, cache_key: &str) -> Option<Option<String>> {
        // 命令级超时/错误 → 未命中（降级到 DB）——由 store 实现层内建
        let cached: Option<String> = self.store.get(cache_key).await.ok().flatten();
        cached.map(|val| {
            if val == CONFIG_NULL_MARKER {
                None
            } else {
                Some(val)
            }
        })
    }

    /// 写单层缓存（best-effort）：Some 值按正常 TTL；None 写 sentinel 并按短 TTL 防穿透。
    async fn write_cache_layer(&self, cache_key: &str, value: Option<&str>) {
        let ttl = if value.is_some() {
            CONFIG_CACHE_TTL
        } else {
            CONFIG_NULL_CACHE_TTL
        };
        let cache_value = value.unwrap_or(CONFIG_NULL_MARKER);
        if let Err(e) = self.store.set_ex(cache_key, cache_value, ttl as u64).await {
            tracing::warn!(
                cache_key = %cache_key,
                error = %e,
                "配置缓存写失败，本次读将回落查库（与 del_cache_key 的 best-effort 口径一致）"
            )
        }
    }

    /// DEL 单个缓存 key（best-effort，失败仅 warn）。
    async fn del_cache_key(&self, cache_key: &str) {
        if let Err(e) = self.store.del(&[cache_key.to_string()]).await {
            tracing::warn!(cache_key = %cache_key, error = %e, "配置缓存 DEL 失败，可能产生脏读直至 TTL 过期")
        }
    }

    /// 失效**平台默认层**：只删 `config:def:{key}`。
    ///
    /// 两层缓存「读时合并、不缓存合并结果」→ 平台改默认值只失效本层即可全局即时生效，
    /// 无需扫描删除各租户的覆盖层 key（租户层只缓存各自的覆盖值，不受平台默认值影响）。
    async fn invalidate_default_cache(&self, config_key: &str) {
        self.del_cache_key(&default_cache_key(config_key)).await;
    }

    /// 失效**指定租户覆盖层**：只删 `config:{tid}:{key}`（租户行写/删时调用）。
    async fn invalidate_tenant_cache(&self, tid: i64, config_key: &str) {
        if tid == 0 {
            // 平台行写入 → 失效平台默认层
            self.invalidate_default_cache(config_key).await;
        } else {
            self.del_cache_key(&tenant_cache_key(tid, config_key)).await;
        }
    }

    /// H-4：按 config_key 查询**生效参数值**，带两层 Redis cache-aside 缓存（§27.8）
    ///
    /// 调用方**必须显式传入** `tenant_id`：
    /// - `None`（或 `Some(0)`）：只读平台默认层 `config:def:{key}`；
    /// - `Some(tid)`（tid≠0）：先读租户覆盖层 `config:{tid}:{key}`，无覆盖（sentinel）则回落平台默认层；
    ///   `tenant_private` 行只在 tid 匹配时可见（覆盖层 key 已按 tid 隔离）。
    ///
    /// 读时合并、不缓存合并结果 → 平台改默认值只失效 def 层；租户改覆盖只失效自己那把 key。
    /// 运行时读取（登录开关/默认密码等）允许读取 platform_only 的平台值（例如租户必须遵循
    /// 平台下发的 captchaEnabled）；`visible_to_tenant` 治理的是**运维界面可见性**（见列表视图）。
    ///
    /// 返回 `Option<String>`：Some(value) 存在；None 不存在或 Redis/DB 错误（调用方按业务默认值处理）。
    pub async fn get_config_value_by_key_cached(
        &self,
        config_key: &str,
        tenant_id: Option<i64>,
    ) -> Result<Option<String>, ServiceError> {
        let tid = tenant_id.unwrap_or(0);

        // 1. 租户覆盖层（仅 tid != 0）
        if tid != 0 {
            let tkey = tenant_cache_key(tid, config_key);
            match self.read_cache_layer(&tkey).await {
                Some(Some(v)) => return Ok(Some(v)), // 命中租户覆盖值
                Some(None) => {}                     // 命中 sentinel：无覆盖 → 回落平台层
                None => {
                    // 未命中 → 查本租户覆盖行
                    let row = self.config_repo.find_by_tenant_key(tid, config_key).await?;
                    let val = row.and_then(|m| m.config_value);
                    self.write_cache_layer(&tkey, val.as_deref()).await;
                    if let Some(v) = val {
                        return Ok(Some(v));
                    }
                    // 无覆盖 → 继续回落平台默认层
                }
            }
        }

        // 2. 平台默认层
        let dkey = default_cache_key(config_key);
        if let Some(hit) = self.read_cache_layer(&dkey).await {
            return Ok(hit);
        }
        let row = self.config_repo.find_platform_by_key(config_key).await?;
        let val = row.and_then(|m| m.config_value);
        self.write_cache_layer(&dkey, val.as_deref()).await;
        Ok(val)
    }

    // ==================== 治理辅助 ====================

    /// key 是否为平台锁定安全项（§27.8 硬规则①：注册表锁死，界面不允许下放）。
    ///
    /// 判据来自共享注册表的 `Coverage::Locked`。未登记 key 一律**非**锁定
    /// （交由调用方的其它门禁处理），与旧 `PLATFORM_LOCKED_KEYS.contains` 逐条等价。
    fn is_platform_locked(config_key: &str) -> bool {
        governance::item(config_key)
            .map(|i| i.coverage == governance::Coverage::Locked)
            .unwrap_or(false)
    }

    /// 归一化治理标志位（'0'/'1'），非法值显式报错（不静默降级）。
    fn normalize_flag(field: &str, value: &str) -> Result<String, ServiceError> {
        match value {
            "0" | "1" => Ok(value.to_string()),
            _ => Err(ServiceError::bad_request(&crate::tr!(
                "error.config.flag_invalid",
                field = field
            ))),
        }
    }

    /// 解析平台操作者提交的治理列（§27.8）：
    /// - platform_only 常量集合 → 强制 fail-closed（`platform_only` / '0' / '0'），界面不允许下放；
    /// - 其余项：scope 缺省 = `platform_only`（fail-closed）；editable/visible 缺省按 scope 推导
    ///   （platform_only → '0'/'0'，其余 → '1'/'1'），非法 scope/标志位 → 400。
    fn resolve_governance(
        config_key: &str,
        scope: Option<&str>,
        tenant_editable: Option<&str>,
        visible_to_tenant: Option<&str>,
    ) -> Result<(String, String, String), ServiceError> {
        if Self::is_platform_locked(config_key) {
            // 硬规则①：安全底线在代码常量中锁死，忽略任何提交值
            return Ok((
                SCOPE_PLATFORM_ONLY.to_string(),
                "0".to_string(),
                "0".to_string(),
            ));
        }
        let scope = scope.unwrap_or(SCOPE_PLATFORM_ONLY);
        let (def_editable, def_visible) = match scope {
            SCOPE_PLATFORM_ONLY => ("0", "0"),
            SCOPE_PLATFORM_DEFAULT | SCOPE_TENANT_PRIVATE => ("1", "1"),
            _ => {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.config.scope_invalid"
                )));
            }
        };
        let editable = match tenant_editable {
            Some(v) => Self::normalize_flag("tenantEditable", v)?,
            None => def_editable.to_string(),
        };
        let visible = match visible_to_tenant {
            Some(v) => Self::normalize_flag("visibleToTenant", v)?,
            None => def_visible.to_string(),
        };
        Ok((scope.to_string(), editable, visible))
    }

    /// 租户可写性校验（§27.8 治理表）：
    ///
    /// - **平台已有该 key 的行**（`tenant_id=0`）：仅当 `tenant_editable='1' AND
    ///   visible_to_tenant='1'`（即 `platform_default`）才可写入（写租户覆盖行）；
    ///   不可编辑 / 不可见 → **403**（fail-closed，用 forbidden 而非 400）；
    /// - **平台无该 key 的行**：允许租户**自建** `tenant_private` 新键（租户业务配置，
    ///   行 `tenant_id=tid` 仅本租户可见，不污染平台默认层）；
    /// - `platform_only` 锁定集合（注册表 `Coverage::Locked`）一律 **403**，不可自建。
    async fn ensure_tenant_can_write(
        &self,
        tid: i64,
        config_key: &str,
    ) -> Result<(), ServiceError> {
        if Self::is_platform_locked(config_key) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.config.governance_forbidden"
            )));
        }
        let platform = self.config_repo.find_platform_by_key(config_key).await?;
        // 平台无该 key 的行 → 租户自建 tenant_private 新键（§27.8），故仅 Some 分支需拦截
        if let Some(m) = platform {
            let writable = m.tenant_editable.as_deref() == Some("1")
                && m.visible_to_tenant.as_deref() == Some("1");
            if !writable {
                // 平台行不可编辑 / 不可见 → 租户不得写入
                tracing::debug!(
                    tid,
                    config_key,
                    "租户尝试写入不可下放的 config key，已拒绝（403）"
                );
                return Err(ServiceError::forbidden(&crate::tr!(
                    "error.config.governance_forbidden"
                )));
            }
        }
        Ok(())
    }

    /// 校验租户操作者是否可见某平台行（列表/详情读取用于 fail-closed 拦截）。
    fn platform_row_visible_to_tenant(row: &SysConfigModel) -> bool {
        row.tenant_id == 0 && row.visible_to_tenant.as_deref() == Some("1")
    }

    /// 分页查询参数配置（治理视图，§27.8）
    ///
    /// - `tenant_id = None / Some(0)`：平台操作者 → **平台全量视图**（现状保留，不过滤）；
    /// - `tenant_id = Some(tid)`（tid≠0）：租户操作者 → **生效视图**（本租户自己的行 +
    ///   平台 `visible_to_tenant='1'` 的行；同 key 以租户行覆盖平台行），
    ///   **绝不返回 platform_only 行**（见 `SysConfigRepository::find_effective_page`）。
    ///
    /// 支持 config_name 模糊、config_key 模糊、config_type 精确、时间范围筛选。
    pub async fn get_config_page(
        &self,
        query: ConfigQueryDto,
        tenant_id: Option<i64>,
    ) -> Result<(Vec<SysConfigModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_config::Entity>(prop, SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        let (rows, total) = match tenant_id.filter(|t| *t != 0) {
            Some(tid) => {
                self.config_repo
                    .find_effective_page(
                        tid,
                        offset,
                        limit,
                        query.config_name.as_deref(),
                        query.config_key.as_deref(),
                        query.config_type.as_deref(),
                        begin,
                        end,
                        sort,
                    )
                    .await?
            }
            None => {
                self.config_repo
                    .find_page_filtered(
                        offset,
                        limit,
                        query.config_name.as_deref(),
                        query.config_key.as_deref(),
                        query.config_type.as_deref(),
                        begin,
                        end,
                        sort,
                    )
                    .await?
            }
        };
        Ok((rows, total))
    }

    /// 根据 config_id 查询参数配置详情（治理视图）
    ///
    /// - 平台操作者（None / Some(0)）：全量可见；
    /// - 租户操作者（Some(tid)）：仅本租户行或平台 `visible_to_tenant='1'` 的行可见，
    ///   否则 **403**（不泄露 platform_only / 其它租户行；fail-closed）。
    pub async fn get_config_by_id(
        &self,
        config_id: i64,
        tenant_id: Option<i64>,
    ) -> Result<SysConfigModel, ServiceError> {
        let model = self
            .config_repo
            .find_by_id(config_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.config.not_found")))?;
        if let Some(tid) = tenant_id.filter(|t| *t != 0)
            && model.tenant_id != tid
            && !Self::platform_row_visible_to_tenant(&model)
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.config.governance_forbidden"
            )));
        }
        Ok(model)
    }

    /// 按 config_key 查询**生效参数值**（前端读取配置用，§27.8）
    ///
    /// 生效行解析：租户覆盖行优先，回落平台默认行（`find_effective_by_key`）。
    /// 脱敏规则（治理列为准、`is_sensitive_key` 降级为兜底）：
    /// - 租户操作者读取平台 `visible_to_tenant != '1'` 的行（含全部 platform_only）→ 脱敏 `***`；
    /// - 其余情况走 `is_sensitive_key` 兜底（密钥类 key 名启发式，兼容历史数据）。
    pub async fn get_config_by_key(
        &self,
        config_key: &str,
        tenant_id: Option<i64>,
    ) -> Result<String, ServiceError> {
        let model = self
            .config_repo
            .find_effective_by_key(config_key, tenant_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.config.not_found")))?;
        // 治理列显式声明「租户不可见」→ 对租户调用一律脱敏；
        // 治理列缺省（历史行/非平台行）时由 is_sensitive_key 兜底。
        let masked = match tenant_id.filter(|t| *t != 0) {
            Some(_) => {
                model.tenant_id == 0 && model.visible_to_tenant.as_deref() != Some("1")
                    || Self::is_sensitive_key(config_key)
            }
            None => Self::is_sensitive_key(config_key),
        };
        if masked {
            Ok("***".to_string())
        } else {
            Ok(model.config_value.unwrap_or_default())
        }
    }

    /// 判断配置键是否可能为敏感密钥类（脱敏**兜底**判据，§27.8 硬规则④）
    ///
    /// 主判据已改为治理列 `visible_to_tenant='0'` 的显式声明（见 `get_config_by_key`）；
    /// 本函数仅在治理列缺省（历史数据 / 非平台行）时兜底，
    /// 避免通过 `/system/config/configKey/{key}` 泄露密钥类明文（SEC-信息泄露面）。
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

    /// 新增参数配置（写治理，§27.8）
    ///
    /// - **平台操作者（operator_tid=0）**：全权，可管理治理列（`scope`/`editable`/`visible`）；
    ///   `platform_only` 常量集合强制锁定，唯一性限于平台层（`tenant_id=0`）。
    /// - **租户操作者（operator_tid≠0）**：可写「平台行 `tenant_editable='1' AND
    ///   visible_to_tenant='1'`」的 key（覆盖），也可自建平台**不存在**的新键；
    ///   写入行 `tenant_id = operator_tid`，治理列固定为
    ///   `tenant_private`（**不得篡改**）；命中 platform_only / 平台行不可编辑 / 不可见 → **403**。
    ///   唯一性限于本租户层。
    pub async fn add_config(
        &self,
        dto: ConfigAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysConfigModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // 唯一性校验：复合唯一域 (tenant_id, config_key)，同租户内键名唯一
        let existing = self
            .config_repo
            .find_by_tenant_key(operator_tid, &dto.config_key)
            .await?;
        if existing.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.config.key_exists"
            )));
        }

        // 治理列解析：平台操作者可管理；租户操作者仅可覆盖平台可下放项，治理列固定
        let (scope, tenant_editable, visible_to_tenant) = if operator_tid == 0 {
            Self::resolve_governance(
                &dto.config_key,
                dto.scope.as_deref(),
                dto.tenant_editable.as_deref(),
                dto.visible_to_tenant.as_deref(),
            )?
        } else {
            // 租户：先做可写性校验（403），再写固定治理列
            self.ensure_tenant_can_write(operator_tid, &dto.config_key)
                .await?;
            (
                SCOPE_TENANT_PRIVATE.to_string(),
                "1".to_string(),
                "1".to_string(),
            )
        };

        let now = crate::common::datetime::now_naive();
        let am = SysConfigActiveModel {
            // 多租户：参数归属操作者租户（平台管理员=0）
            tenant_id: Set(operator_tid),
            config_name: Set(dto.config_name),
            config_key: Set(dto.config_key),
            config_value: Set(dto.config_value),
            config_type: Set(dto.config_type),
            scope: Set(Some(scope)),
            tenant_editable: Set(Some(tenant_editable)),
            visible_to_tenant: Set(Some(visible_to_tenant)),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(dto.remark),
            ..Default::default()
        };

        let model = self.config_repo.insert(am).await?;
        // 失效对应缓存层：平台行 → def 层；租户行 → 该租户覆盖层
        self.invalidate_tenant_cache(model.tenant_id, &model.config_key)
            .await;
        Ok(model)
    }

    /// 修改参数配置（写治理，§27.8）
    ///
    /// 越权防护：仅本租户行可改（平台操作者全权）。租户不得改平台行（`tenant_allowed` 拦截）。
    /// 治理列：平台操作者可管理；租户操作者保持 `tenant_private` 且不得篡改。
    pub async fn edit_config(
        &self,
        dto: ConfigEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysConfigModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let existing = self
            .get_config_by_id(dto.config_id, Some(operator_tid))
            .await?;
        // 多租户越权防护：只能修改本租户参数（平台操作者放行；租户不得改平台行）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        // config_key 变更时校验唯一性（排除自身，限于同一租户层）
        let old_key = existing.config_key.clone();
        let row_tid = existing.tenant_id;
        if dto.config_key != old_key {
            if operator_tid != 0 {
                // 租户改 key：新 key 必须仍是可覆盖的平台可下放项，否则 403
                self.ensure_tenant_can_write(operator_tid, &dto.config_key)
                    .await?;
            }
            let conflict = self
                .config_repo
                .find_by_tenant_key(row_tid, &dto.config_key)
                .await?;
            if conflict.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.config.key_exists"
                )));
            }
        }

        // 治理列现值快照（`existing` 随即被 `into()` 转移；供治理列的"部分更新语义"兜底）
        let (existing_scope, existing_editable, existing_visible) = (
            existing.scope.clone(),
            existing.tenant_editable.clone(),
            existing.visible_to_tenant.clone(),
        );

        // 审计合规域：变更前快照（必须在 existing 被 move 进 ActiveModel 之前计算）
        let before_snapshot = serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);

        let now = crate::common::datetime::now_naive();
        let mut am: SysConfigActiveModel = existing.into();
        // 部分更新语义（批五十六扩展，对齐治理列 2026-09-26 修复）：Option 未提交（None）
        // = 保留现值，显式 Some("")= 清空。此前无条件 Set 使"只改 remark 的常规编辑"
        // 抹掉 config_name / config_value / config_type —— e2e F10 实证
        // sys.index.skinName 的 config_name 被清空（编辑表单不含该列）。
        if let Some(v) = dto.config_name.clone() {
            am.config_name = Set(Some(v));
        }
        am.config_key = Set(dto.config_key.clone());
        if let Some(v) = dto.config_value.clone() {
            am.config_value = Set(Some(v));
        }
        if let Some(v) = dto.config_type.clone() {
            am.config_type = Set(Some(v));
        }
        if operator_tid == 0 {
            // 平台操作者可管理治理列。
            //
            // **部分更新语义（2026-09-26 缺陷修复）**：治理列未传时保持**现有值**，而非回落
            // `platform_only`。否则"只改 remark / 只改值"的常规编辑会把 `platform_default`
            // 键**静默降级**为 `platform_only`，租户随即失去覆盖能力且无任何提示。
            // 实测路径：e2e 功能 27 的 `PUT /system/config`（仅改 remark）把
            // `sys.index.skinName` 降级为 platform_only ⇒ 功能 72 的"租户覆盖 platform_default
            // 键"断言由 200 变 403。fail-closed 缺省只适用于**新增**（未声明治理的新键），
            // 不适用于更新（更新时"未传"应表示"不改"）。
            //
            // 语义细节：显式改 `scope` 而未传标志位时，仍按新 scope 推导（保持治理一致性）；
            // 未改 scope 时标志位缺省保持现有值。
            let scope_in = dto.scope.as_deref().or(existing_scope.as_deref());
            let (editable_in, visible_in) = if dto.scope.is_some() {
                (
                    dto.tenant_editable.as_deref(),
                    dto.visible_to_tenant.as_deref(),
                )
            } else {
                (
                    dto.tenant_editable
                        .as_deref()
                        .or(existing_editable.as_deref()),
                    dto.visible_to_tenant
                        .as_deref()
                        .or(existing_visible.as_deref()),
                )
            };
            let (scope, editable, visible) =
                Self::resolve_governance(&dto.config_key, scope_in, editable_in, visible_in)?;
            am.scope = Set(Some(scope));
            am.tenant_editable = Set(Some(editable));
            am.visible_to_tenant = Set(Some(visible));
        } else {
            // 租户操作者不得篡改治理列：固定 tenant_private 且可见可覆盖
            am.scope = Set(Some(SCOPE_TENANT_PRIVATE.to_string()));
            am.tenant_editable = Set(Some("1".to_string()));
            am.visible_to_tenant = Set(Some("1".to_string()));
        }
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        // remark 同部分更新语义（None=保留）——F10 只改 remark 的 PUT 此前会连带
        // 抹掉未提交的 config_name；本行原无条件 Set 是remark/config_name 双漂移根因
        if let Some(v) = dto.remark.clone() {
            am.remark = Set(Some(v));
        }

        // 参数变更 + 审计留痕同事务：edit_config 原为无事务直更，接入变更留痕后
        // 引入事务保证「变更与留痕」原子性——record_change 失败令业务一并回滚，
        // 杜绝"参数已改但无痕"的合规缺口。
        let config_repo = self.config_repo.clone();
        let model = self
            .config_repo
            .base()
            .db()
            .transaction::<_, SysConfigModel, sea_orm::DbErr>(|txn| {
                let am = am.clone();
                let before_snapshot = before_snapshot.clone();
                // 审计留痕块为 boxed()（需 'static），operator 为 &str 引用生命周期不足，
                // 克隆为 owned String 移入 async move 块
                let operator_owned = operator.to_string();
                async move {
                    let model = config_repo.base().update_conn(txn, am).await?;

                    // 审计合规域：UPDATE 变更留痕（敏感列由 record_change 内部统一打码）
                    let after = serde_json::to_value(&model).unwrap_or(serde_json::Value::Null);
                    let audit_operator =
                        crate::service::sys_audit_change_service::resolve_operator(
                            txn,
                            None, // edit_config 签名仅携带操作人用户名，ID 由回查补齐
                            Some(operator_owned.as_str()),
                        )
                        .await;
                    crate::service::sys_audit_change_service::record_change(
                        txn,
                        "sys_config",
                        &model.config_id.to_string(),
                        crate::service::sys_audit_change_service::ACTION_UPDATE,
                        Some(before_snapshot),
                        Some(after),
                        audit_operator,
                    )
                    .await?;
                    Ok(model)
                }
                .boxed()
            })
            .await
            .map_err(ServiceError::from)?;

        // 若 config_key 变更，old_key 与 new_key 都需失效（旧层 + 新层）
        if model.config_key != old_key {
            self.invalidate_tenant_cache(row_tid, &old_key).await;
        }
        self.invalidate_tenant_cache(model.tenant_id, &model.config_key)
            .await;
        Ok(model)
    }

    /// 批量删除参数配置（物理删除，config 表无 del_flag；写治理，§27.8）
    ///
    /// - 平台操作者全权；
    /// - 租户操作者不得删除平台行（`tenant_id=0`）→ **403**；跨租户行 → 403。
    pub async fn delete_configs(
        &self,
        config_ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if config_ids.is_empty() {
            return Ok(());
        }
        // H-4：删除前先查询 config_key（单次批量查询，避免 N+1），用于失效缓存
        let models = self.config_repo.find_by_ids(config_ids.clone()).await?;
        // 写治理：租户不得删除平台行（fail-closed 403，先于通用越权检查给出明确语义）
        if operator_tid != 0 && models.iter().any(|m| m.tenant_id == 0) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.config.platform_row_forbidden"
            )));
        }
        // 多租户越权防护：任一所选参数跨越操作者租户即整体拒绝（平台操作者放行）
        if models
            .iter()
            .any(|m| !crate::common::tenant::tenant_allowed(operator_tid, m.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        self.config_repo.delete_by_ids(config_ids).await?;
        // 批量失效对应层的缓存：平台行 → def 层；租户行 → 该租户覆盖层
        // （原 pipeline 逐键 DEL 语义——非事务允许部分成功，del 多键等价）
        if !models.is_empty() {
            let keys: Vec<String> = models
                .iter()
                .map(|m| {
                    if m.tenant_id == 0 {
                        default_cache_key(&m.config_key)
                    } else {
                        tenant_cache_key(m.tenant_id, &m.config_key)
                    }
                })
                .collect();
            if let Err(e) = self.store.del(&keys).await {
                tracing::warn!("批量失效配置缓存失败: {}", e);
            }
        }
        Ok(())
    }

    /// 刷新缓存
    ///
    /// H-4：扫描并清除所有 config 缓存键。best-effort，Redis 错误仅记日志不影响业务。
    ///
    /// §27.8 两层缓存：前缀 `CONFIG_CACHE_PREFIX`（`config:`）是**两层共同前缀**，
    /// 既可命中租户覆盖层（`config:{tid}:{key}`），也可命中平台默认层（`config:def:{key}`，
    /// 由 `CONFIG_DEFAULT_CACHE_PREFIX` 构造），故一次 `config:*` 扫描即覆盖两层。
    pub async fn refresh_cache(&self) -> Result<(), ServiceError> {
        let pattern = format!("{}*", CONFIG_CACHE_PREFIX);
        // 第九批：改用 **不截断** 扫描。本函数语义是"清除**所有** config 缓存键"，
        // 原 `scan_keys(.., 5000)` 超限即静默截断 ⇒ 超 5000 键时残留陈旧缓存，
        // 配置更新后部分键仍返回旧值（与"刷新缓存"的意图直接冲突）。
        // pattern 为固定前缀 `config:*`（非通配 `*`），无海量键 OOM 风险。
        let keys = match self.store.scan(&pattern, None).await {
            Ok(ks) => ks,
            Err(e) => {
                tracing::warn!("刷新配置缓存时扫描键失败: {}", e);
                return Ok(());
            }
        };
        if keys.is_empty() {
            return Ok(());
        }
        // 批量删除（原分批 pipeline 语义——del 单次多键等价；local 档逐键删除天然部分成功）
        if let Err(e) = self.store.del(&keys).await {
            tracing::warn!("刷新配置缓存时批量删除失败: {}", e);
        }
        Ok(())
    }

    /// 导出参数配置（全量查询不分页；治理视图，§27.8）
    ///
    /// 视图与 [`Self::get_config_page`] 一致：
    /// - `tenant_id = None / Some(0)`：平台操作者 → **平台全量视图**；
    /// - `tenant_id = Some(tid)`（tid≠0）：租户操作者 → **生效视图**（本租户行 +
    ///   平台 `visible_to_tenant='1'` 行，同 key 租户行覆盖平台行），**绝不导出 platform_only**。
    pub async fn export_configs(
        &self,
        query: ConfigQueryDto,
        tenant_id: Option<i64>,
    ) -> Result<Vec<SysConfigModel>, ServiceError> {
        // 导出与页面列表同序：动态排序白名单解析口径一致
        let page = PageDomain::from(&query);
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_config::Entity>(prop, SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        let rows = match tenant_id.filter(|t| *t != 0) {
            Some(tid) => {
                self.config_repo
                    .find_effective_all(
                        tid,
                        query.config_name.as_deref(),
                        query.config_key.as_deref(),
                        query.config_type.as_deref(),
                        begin,
                        end,
                        sort,
                    )
                    .await?
            }
            None => {
                self.config_repo
                    .find_all_filtered(
                        query.config_name.as_deref(),
                        query.config_key.as_deref(),
                        query.config_type.as_deref(),
                        begin,
                        end,
                        sort,
                    )
                    .await?
            }
        };
        Ok(rows)
    }
}
