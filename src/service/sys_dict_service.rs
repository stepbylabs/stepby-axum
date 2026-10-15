//! 字典模块 Service 层
//!
//! 职责：
//! - 字典类型 CRUD、字典类型查重、按 dict_type 查询字典数据
//! - 字典数据 CRUD、按 dict_type 查询列表（前端下拉用）
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 数据访问通过 Repository 层委托
//! - 多表操作（字典类型变更级联、字典类型删除级联）使用事务保证一致性

use futures::future::FutureExt;
use garde::Validate;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_dict_data::{
    ActiveModel as SysDictDataActiveModel, Column as DictDataColumn, Model as SysDictDataModel,
};
use crate::entity::sys_dict_type::{
    ActiveModel as SysDictTypeActiveModel, Column as DictTypeColumn, Model as SysDictTypeModel,
};
use crate::repository::sys_dict_data::SysDictDataRepository;
use crate::repository::sys_dict_type::SysDictTypeRepository;
use crate::shared_store::SharedStore;

/// 字典缓存 key 前缀（格式：dict:{dict_type}）
const DICT_CACHE_PREFIX: &str = "dict:";
/// 字典缓存 TTL（秒，30 分钟）
const DICT_CACHE_TTL: i64 = 1800;

/// 空值缓存标记（R9-FLW-009：防穿透）
///
/// 当 dict_type 不存在时缓存此标记，避免恶意请求不存在的 dict_type 反复打 DB。
/// 空值缓存 TTL 较短（60 秒），平衡穿透防护与新增字典后及时生效。
const DICT_NULL_MARKER: &str = "__NULL__";
const DICT_NULL_TTL: i64 = 60;

// ==================== 字典类型 DTO ====================

/// 字典类型分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DictTypeQueryDto {
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
    pub dict_name: Option<String>,
    pub dict_type: Option<String>,
    pub status: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 `params[beginTime]`）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 `params[endTime]`）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&DictTypeQueryDto> for PageDomain {
    fn from(dto: &DictTypeQueryDto) -> Self {
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

/// 新增字典类型 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DictTypeAddDto {
    #[garde(length(min = 1, max = 100))]
    pub dict_name: String,
    #[garde(length(min = 1, max = 100))]
    pub dict_type: String,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 修改字典类型 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DictTypeEditDto {
    #[garde(skip)]
    pub dict_id: i64,
    #[garde(length(min = 1, max = 100))]
    pub dict_name: String,
    #[garde(length(min = 1, max = 100))]
    pub dict_type: String,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

// ==================== 字典数据 DTO ====================

/// 字典数据分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DictDataQueryDto {
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
    pub dict_type: Option<String>,
    pub dict_label: Option<String>,
    pub status: Option<String>,
}

impl From<&DictDataQueryDto> for PageDomain {
    fn from(dto: &DictDataQueryDto) -> Self {
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

/// 新增字典数据 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DictDataAddDto {
    #[garde(range(min = 0))]
    pub dict_sort: Option<i32>,
    #[garde(length(min = 1, max = 100))]
    pub dict_label: String,
    /// 英文标签（国际化）
    #[garde(skip)]
    pub dict_label_en: Option<String>,
    #[garde(length(min = 1, max = 100))]
    pub dict_value: String,
    #[garde(length(min = 1, max = 100))]
    pub dict_type: String,
    #[garde(skip)]
    pub css_class: Option<String>,
    #[garde(skip)]
    pub list_class: Option<String>,
    #[garde(skip)]
    pub is_default: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 修改字典数据 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DictDataEditDto {
    #[garde(skip)]
    pub dict_code: i64,
    #[garde(range(min = 0))]
    pub dict_sort: Option<i32>,
    #[garde(length(min = 1, max = 100))]
    pub dict_label: String,
    /// 英文标签（国际化）
    #[garde(skip)]
    pub dict_label_en: Option<String>,
    #[garde(length(min = 1, max = 100))]
    pub dict_value: String,
    #[garde(length(min = 1, max = 100))]
    pub dict_type: String,
    #[garde(skip)]
    pub css_class: Option<String>,
    #[garde(skip)]
    pub list_class: Option<String>,
    #[garde(skip)]
    pub is_default: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

// ==================== 辅助函数 ====================

// ==================== Service 实现 ====================

/// 允许排序的字典类型列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖字典类型业务展示列；`create_by` / `update_by` / `remark` / `del_flag` / `tenant_id`
/// 等内部列不开放动态排序。
const DICT_TYPE_SORTABLE_COLUMNS: &[(&str, DictTypeColumn)] = &[
    ("dict_id", DictTypeColumn::DictId),
    ("dict_name", DictTypeColumn::DictName),
    ("dict_type", DictTypeColumn::DictType),
    ("status", DictTypeColumn::Status),
    ("create_time", DictTypeColumn::CreateTime),
    ("update_time", DictTypeColumn::UpdateTime),
];

/// 允许排序的字典数据列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖字典数据业务展示列；`css_class` / `list_class` / `create_by` / `update_by` /
/// `remark` / `del_flag` / `tenant_id` 等内部列不开放动态排序。
const DICT_DATA_SORTABLE_COLUMNS: &[(&str, DictDataColumn)] = &[
    ("dict_code", DictDataColumn::DictCode),
    ("dict_sort", DictDataColumn::DictSort),
    ("dict_label", DictDataColumn::DictLabel),
    ("dict_value", DictDataColumn::DictValue),
    ("dict_type", DictDataColumn::DictType),
    ("is_default", DictDataColumn::IsDefault),
    ("status", DictDataColumn::Status),
    ("create_time", DictDataColumn::CreateTime),
    ("update_time", DictDataColumn::UpdateTime),
];

/// 字典模块 Service（字典类型 + 字典数据）
///
/// 数据访问通过 Repository 层委托：
/// - dict_type_repo: sys_dict_type 表 CRUD
/// - dict_data_repo: sys_dict_data 表 CRUD
/// - store: 共享态存储（SharedStore），用于字典数据缓存（cache-aside 模式）
///
/// R9-FLW-009：缓存穿透防护（空值缓存）+ 击穿防护（singleflight）
pub struct SysDictService {
    dict_type_repo: SysDictTypeRepository,
    dict_data_repo: SysDictDataRepository,
    store: Arc<dyn SharedStore>,
    /// singleflight 锁表：同 dict_type 的并发查询只允许一个查 DB，其他等待复用结果
    ///
    /// 防止热点 key 失效瞬间 N 个请求同时打 DB（缓存击穿）。
    /// 锁粒度为 dict_type 字符串，不同 dict_type 互不阻塞。
    inflight: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl SysDictService {
    pub fn new(db: DatabaseConnection, store: Arc<dyn SharedStore>) -> Self {
        Self {
            dict_type_repo: SysDictTypeRepository::new(db.clone()),
            dict_data_repo: SysDictDataRepository::new(db),
            store,
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn db(&self) -> &DatabaseConnection {
        self.dict_type_repo.base().db()
    }

    // ==================== 缓存辅助方法 ====================

    /// 构造字典数据缓存 key（两层：平台层 `dict:0:{dict_type}` / 租户层 `dict:{tid}:{dict_type}`）
    ///
    /// 多租户隔离：字典数据按**类型归属层**分缓存，`tid` 即数据归属层
    /// （平台类型数据=0 / 租户自建类型数据=租户 ID），杜绝跨租户串读。
    fn cache_key(tid: i64, dict_type: &str) -> String {
        format!("{}{}:{}", DICT_CACHE_PREFIX, tid, dict_type)
    }

    /// 失效指定层 + dict_type 的缓存（best-effort，失败仅记日志不阻断业务）
    async fn invalidate_cache(&self, tid: i64, dict_type: &str) {
        let key = Self::cache_key(tid, dict_type);
        if let Err(e) = self.store.del(std::slice::from_ref(&key)).await {
            tracing::warn!("失效字典缓存 {} 失败: {}", key, e);
        }
    }

    /// 失效指定层多个 dict_type 的缓存（P2-6：批量 DEL，一次往返）
    ///
    /// 原 Redis pipeline 语义保持：非事务，允许部分成功
    /// （local 档逐键 DELETE 天然部分成功；redis 档单条 DEL 多键等价）。
    /// 保持 best-effort 语义：失败仅 warn 不阻断业务。
    async fn invalidate_caches(&self, tid: i64, dict_types: &[String]) {
        if dict_types.is_empty() {
            return;
        }
        let keys: Vec<String> = dict_types
            .iter()
            .map(|dt| Self::cache_key(tid, dt))
            .collect();
        if let Err(e) = self.store.del(&keys).await {
            tracing::warn!(
                "批量失效字典缓存失败（{} 个 dict_type）: {}",
                dict_types.len(),
                e
            );
        }
    }

    // ==================== 字典类型 ====================

    /// 归一化租户过滤域：`Some(0)`/`None`（平台操作者）→ None（不过滤）；其余 → Some(tid)。
    fn tenant_scope_of(tenant_id: Option<i64>) -> Option<i64> {
        tenant_id.filter(|t| *t != 0)
    }

    /// 分页查询字典类型
    ///
    /// 多租户（§27.8）：`tenant_id = None / Some(0)` → 平台全量；`Some(tid)` →
    /// 本租户自建类型 + 平台类型（`tenant_id IN (0, tid)`）。
    /// 支持 dict_name 模糊、dict_type 模糊、status 精确、时间范围筛选
    pub async fn get_dict_type_page(
        &self,
        query: DictTypeQueryDto,
        tenant_id: Option<i64>,
    ) -> Result<(Vec<SysDictTypeModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_dict_type::Entity>(
                prop,
                DICT_TYPE_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let begin = match query.begin_time.as_deref() {
            Some(s) => Some(crate::common::datetime::parse_query_date(s)?),
            None => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) => Some(crate::common::datetime::parse_query_date(s)?),
            None => None,
        };

        let (rows, total) = self
            .dict_type_repo
            .find_page_filtered(
                offset,
                limit,
                Self::tenant_scope_of(tenant_id),
                query.dict_name.as_deref(),
                query.dict_type.as_deref(),
                query.status.as_deref(),
                begin,
                end,
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 导出字典类型列表（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    ///
    /// 多租户视图同 [`Self::get_dict_type_page`]。
    pub async fn export_dict_types(
        &self,
        query: DictTypeQueryDto,
        tenant_id: Option<i64>,
    ) -> Result<Vec<SysDictTypeModel>, ServiceError> {
        let offset = 0u64;
        let limit = crate::common::page::EXPORT_MAX_ROWS;
        // 导出与页面列表同序：动态排序白名单解析口径一致
        let page = PageDomain::from(&query);
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_dict_type::Entity>(
                prop,
                DICT_TYPE_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let begin = match query.begin_time.as_deref() {
            Some(s) => Some(crate::common::datetime::parse_query_date(s)?),
            None => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) => Some(crate::common::datetime::parse_query_date(s)?),
            None => None,
        };

        let (rows, _) = self
            .dict_type_repo
            .find_page_filtered(
                offset,
                limit,
                Self::tenant_scope_of(tenant_id),
                query.dict_name.as_deref(),
                query.dict_type.as_deref(),
                query.status.as_deref(),
                begin,
                end,
                sort,
            )
            .await?;
        Ok(rows)
    }

    /// 查询可用的字典类型（前端下拉选择用）
    ///
    /// 多租户：`tenant_id = None / Some(0)` → 平台全量；`Some(tid)` → 本租户自建类型 + 平台类型。
    pub async fn get_all_dict_types(
        &self,
        tenant_id: Option<i64>,
    ) -> Result<Vec<SysDictTypeModel>, ServiceError> {
        let rows = self
            .dict_type_repo
            .find_active_all(Self::tenant_scope_of(tenant_id))
            .await?;
        Ok(rows)
    }

    /// 根据 dict_id 查询字典类型详情（治理视图）
    ///
    /// - 平台操作者（None / Some(0)）：全量可见；
    /// - 租户操作者（Some(tid)）：仅本租户行或平台行可见，否则 **403**（fail-closed）。
    pub async fn get_dict_type_by_id(
        &self,
        dict_id: i64,
        tenant_id: Option<i64>,
    ) -> Result<SysDictTypeModel, ServiceError> {
        let model = self
            .dict_type_repo
            .find_active_by_id(dict_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.dict.type_not_found")))?;
        if let Some(tid) = Self::tenant_scope_of(tenant_id)
            && model.tenant_id != 0
            && model.tenant_id != tid
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.dict.platform_row_forbidden"
            )));
        }
        Ok(model)
    }

    /// 新增字典类型（写治理，§27.8）
    ///
    /// - **平台操作者（operator_tid=0）**：全权，唯一性限于平台层（`tenant_id=0`）。
    /// - **租户操作者（operator_tid≠0）**：可创建自建类型（`tenant_id=operator_tid`）；
    ///   但与**平台既有类型同名** → **403**（显式检查，禁止覆盖平台类型；
    ///   不依赖唯一索引报错，避免 500/400 语义混淆）；与本租户既有类型同名 → 400。
    pub async fn add_dict_type(
        &self,
        dto: DictTypeAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysDictTypeModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // 平台层同名校验（复合唯一域 (tenant_id, dict_type)）
        let platform_existing = self
            .dict_type_repo
            .find_platform_by_dict_type(&dto.dict_type)
            .await?;
        if platform_existing.is_some() {
            if operator_tid != 0 {
                // 租户不得创建与平台同名类型（显式 403，不覆盖平台类型）
                return Err(ServiceError::forbidden(&crate::tr!(
                    "error.dict.platform_type_exists"
                )));
            }
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.dict.type_exists"
            )));
        }
        // 本租户层同名校验（平台操作者 operator_tid=0 时上面已覆盖该层）
        if operator_tid != 0 {
            let own_existing = self
                .dict_type_repo
                .find_by_tenant_dict_type(operator_tid, &dto.dict_type)
                .await?;
            if own_existing.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.dict.type_exists"
                )));
            }
        }

        // 提前克隆 dict_type，避免后续 move 后无法用于缓存失效
        let dict_type_for_cache = dto.dict_type.clone();

        let now = crate::common::datetime::now_naive();
        let am = SysDictTypeActiveModel {
            // 多租户：字典类型归属操作者租户（平台管理员=0），租户自建类型打租户 ID
            tenant_id: Set(operator_tid),
            dict_name: Set(Some(dto.dict_name)),
            dict_type: Set(Some(dto.dict_type)),
            status: Set(dto.status),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(dto.remark),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        };

        let dict_type_repo = self.dict_type_repo.clone();
        let txn_result = self
            .db()
            .transaction::<_, SysDictTypeModel, sea_orm::DbErr>(|txn| {
                let am = am;
                let operator = operator.to_string();
                Box::pin(async move {
                    let model = dict_type_repo.base().insert_conn(txn, am).await?;
                    // 审计合规域：INSERT 变更留痕（同事务提交/回滚，失败令业务一并回滚）
                    crate::service::sys_audit_change_service::audit_insert(
                        txn,
                        "sys_dict_type",
                        &model.dict_id.to_string(),
                        &model,
                        None, // add_dict_type 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator.as_str()),
                    )
                    .await?;
                    Ok(model)
                })
            })
            .await;
        let model = txn_result.map_err(ServiceError::from)?;
        // 新增字典类型后失效对应层缓存（防御性清理，正常情况下无数据）
        self.invalidate_cache(operator_tid, &dict_type_for_cache)
            .await;
        Ok(model)
    }

    /// 修改字典类型（事务：字典类型变更时同步更新 sys_dict_data.dict_type）
    ///
    /// 业务校验：
    /// - 目标存在且未删除
    /// - **租户不得改平台类型**（`tenant_id=0`）→ **403**
    /// - dict_type 若变更，校验新值在同层唯一；租户改名撞平台既有类型 → **403**
    /// - 若 dict_type 变更，事务内同步更新 sys_dict_data.dict_type
    pub async fn edit_dict_type(
        &self,
        dto: DictTypeEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysDictTypeModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let existing = self
            .get_dict_type_by_id(dto.dict_id, Some(operator_tid))
            .await?;
        // 多租户越权防护：只能修改本租户字典类型（平台操作者放行；租户不得改平台类型）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.dict.platform_row_forbidden"
            )));
        }

        // dict_type 变更时校验唯一性（限于本行归属层，避免撞唯一索引报 500）
        let old_dict_type = existing.dict_type.clone().unwrap_or_default();
        let dict_type_changed = dto.dict_type != old_dict_type;
        if dict_type_changed {
            if operator_tid != 0 {
                // 租户改名撞平台既有类型 → 403（禁止覆盖平台类型）
                let platform_conflict = self
                    .dict_type_repo
                    .find_platform_by_dict_type(&dto.dict_type)
                    .await?;
                if platform_conflict.is_some() {
                    return Err(ServiceError::forbidden(&crate::tr!(
                        "error.dict.platform_type_exists"
                    )));
                }
            }
            let conflict = self
                .dict_type_repo
                .find_by_tenant_dict_type(existing.tenant_id, &dto.dict_type)
                .await?;
            if conflict.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.dict.type_exists"
                )));
            }
        }

        let now = crate::common::datetime::now_naive();
        // 级联更新的归属层 = 该类型所属租户（平台类型=0 / 租户自建类型=租户 ID）
        // 必须在 `existing` 被消费进 ActiveModel 之前取出
        let row_tid = existing.tenant_id;
        // 部分更新语义快照（2026-09-26 缺陷修复）：status 未传时保持现值，避免字典类型被静默置 NULL 失效
        let existing_status = existing.status.clone();
        // 审计合规域：变更前快照（必须在 existing 被 move 进 ActiveModel 之前计算）
        let before_snapshot = serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);
        let mut am: SysDictTypeActiveModel = existing.into();
        am.dict_name = Set(Some(dto.dict_name));
        am.dict_type = Set(Some(dto.dict_type.clone()));
        am.status = Set(dto.status.or(existing_status));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.remark = Set(dto.remark);

        // 事务：dict_type 变更时同步字典数据 + 更新字典类型
        let dict_type_repo = self.dict_type_repo.clone();
        let dict_data_repo = self.dict_data_repo.clone();

        let model = self
            .db()
            .transaction::<_, SysDictTypeModel, sea_orm::DbErr>(|txn| {
                let dict_type_repo = dict_type_repo.clone();
                let dict_data_repo = dict_data_repo.clone();
                let old_dict_type = old_dict_type.clone();
                let new_dict_type = dto.dict_type.clone();
                let before_snapshot = before_snapshot.clone();
                let operator = operator.to_string();
                async move {
                    // 若 dict_type 变更，同步更新 sys_dict_data.dict_type（限本归属层，防跨租户误改）
                    if dict_type_changed {
                        dict_data_repo
                            .update_dict_type_conn(txn, row_tid, &old_dict_type, &new_dict_type)
                            .await?;
                    }
                    // 更新字典类型
                    let model = dict_type_repo.base().update_conn(txn, am).await?;
                    // 审计合规域：UPDATE 变更留痕（同事务提交/回滚）
                    crate::service::sys_audit_change_service::audit_update(
                        txn,
                        "sys_dict_type",
                        &model.dict_id.to_string(),
                        &before_snapshot,
                        &model,
                        None, // edit_dict_type 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator.as_str()),
                    )
                    .await?;
                    Ok(model)
                }
                .boxed()
            })
            .await?;
        // 字典类型变更后失效新旧 dict_type 缓存（限本归属层）
        let mut to_invalidate = vec![dto.dict_type.clone()];
        if dict_type_changed {
            to_invalidate.push(old_dict_type);
        }
        self.invalidate_caches(row_tid, &to_invalidate).await;
        Ok(model)
    }

    /// 批量删除字典类型（事务：级联软删除关联字典数据）
    ///
    /// REGRESS-003：软删除时重命名 dict_type 为 `{original}_deleted_{dict_id}`，
    /// 释放 `uk_sys_dict_type_tenant (tenant_id, dict_type)` 唯一索引，避免无法重新创建同名字典类型。
    ///
    /// 多租户：租户不得删除平台类型（`tenant_id=0`）→ **403**；级联删除限本归属层。
    pub async fn delete_dict_types(
        &self,
        dict_ids: Vec<i64>,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        // 预查询所有 dict_type 字符串（事务外查询，事务内仅写）
        // 批量查询（单次 SELECT 替代 N 次），并校验全部存在
        let models = self.dict_type_repo.find_active_by_ids(&dict_ids).await?;
        if models.len() != dict_ids.len() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.dict.type_not_found"
            )));
        }
        // 租户不得删除平台类型（fail-closed 403，先给出明确语义）
        if operator_tid != 0 && models.iter().any(|m| m.tenant_id == 0) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.dict.platform_row_forbidden"
            )));
        }
        // 多租户越权防护：任一所选字典类型跨越操作者租户即整体拒绝（平台操作者放行）
        if models
            .iter()
            .any(|m| !crate::common::tenant::tenant_allowed(operator_tid, m.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        // 保持按 dict_ids 输入顺序构建 (dict_id, dict_type, tenant_id)，便于事务内重命名与级联限层
        let mut dict_types: Vec<(i64, String, i64)> = Vec::with_capacity(dict_ids.len());
        for dict_id in &dict_ids {
            let m = models.iter().find(|m| m.dict_id == *dict_id);
            let dt = m.and_then(|m| m.dict_type.clone()).unwrap_or_default();
            let owner = m.map(|m| m.tenant_id).unwrap_or(0);
            dict_types.push((*dict_id, dt, owner));
        }

        let dict_type_repo = self.dict_type_repo.clone();
        let dict_data_repo = self.dict_data_repo.clone();
        let operator = operator.to_string();

        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let dict_type_repo = dict_type_repo.clone();
                let dict_data_repo = dict_data_repo.clone();
                let dict_types = dict_types.clone();
                let models = models.clone();
                let operator = operator.clone();
                async move {
                    for (dict_id, dict_type, owner_tid) in &dict_types {
                        // 软删除字典类型并重命名 dict_type（REGRESS-003）
                        // P0-H1 修复：dict_type 列为 VARCHAR(100)，重命名后缀可能超长导致 UPDATE 失败
                        // 截断原始 dict_type 到安全长度，确保 {truncated}_deleted_{dict_id} ≤ 100
                        // P0-8 修复：按字节切片可能落在 UTF-8 字符中间 panic，改为字符边界安全截断
                        let suffix = format!("_deleted_{}", dict_id);
                        let max_original_len = 100usize.saturating_sub(suffix.len());
                        let mut truncated_original = dict_type.clone();
                        if truncated_original.len() > max_original_len {
                            let mut end = max_original_len;
                            while end > 0 && !dict_type.is_char_boundary(end) {
                                end -= 1;
                            }
                            truncated_original.truncate(end);
                        }
                        let renamed = format!("{}{}", truncated_original, suffix);
                        dict_type_repo
                            .soft_delete_with_rename_conn(txn, *dict_id, renamed)
                            .await?;
                        // 级联软删除关联字典数据（限本归属层，dict_data 表无外键约束）
                        dict_data_repo
                            .soft_delete_by_dict_type_conn(txn, *owner_tid, dict_type)
                            .await?;
                        // 审计合规域：DELETE 变更留痕（同事务提交/回滚）
                        if let Some(m) = models.iter().find(|m| m.dict_id == *dict_id) {
                            crate::service::sys_audit_change_service::audit_delete(
                                txn,
                                "sys_dict_type",
                                &dict_id.to_string(),
                                m,
                                None, // delete_dict_types 签名仅携带操作人用户名，ID 由回查补齐
                                Some(operator.as_str()),
                            )
                            .await?;
                        }
                    }
                    Ok(())
                }
                .boxed()
            })
            .await?;
        // 删除字典类型后失效所有相关 dict_type 缓存（按各类型归属层逐层失效）
        let mut invalidations: std::collections::HashMap<i64, Vec<String>> =
            std::collections::HashMap::new();
        for (_, dt, owner_tid) in &dict_types {
            invalidations
                .entry(*owner_tid)
                .or_default()
                .push(dt.clone());
        }
        for (owner_tid, dts) in invalidations {
            self.invalidate_caches(owner_tid, &dts).await;
        }
        Ok(())
    }

    // ==================== 字典数据 ====================

    /// 分页查询字典数据
    ///
    /// 多租户：`tenant_id = None / Some(0)` → 平台全量；`Some(tid)` → `tenant_id IN (0, tid)`
    /// （平台类型数据 + 本租户自建类型数据）。
    /// 支持 dict_type 精确、dict_label 模糊、status 精确筛选
    pub async fn get_dict_data_page(
        &self,
        query: DictDataQueryDto,
        tenant_id: Option<i64>,
    ) -> Result<(Vec<SysDictDataModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_dict_data::Entity>(
                prop,
                DICT_DATA_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let (rows, total) = self
            .dict_data_repo
            .find_page_filtered(
                offset,
                limit,
                Self::tenant_scope_of(tenant_id),
                query.dict_type.as_deref(),
                query.dict_label.as_deref(),
                query.status.as_deref(),
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 导出字典数据（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    ///
    /// 多租户视图同 [`Self::get_dict_data_page`]。
    pub async fn export_dict_data(
        &self,
        query: DictDataQueryDto,
        tenant_id: Option<i64>,
    ) -> Result<Vec<SysDictDataModel>, ServiceError> {
        let offset = 0u64;
        let limit = crate::common::page::EXPORT_MAX_ROWS;
        // 导出与页面列表同序：动态排序白名单解析口径一致
        let page = PageDomain::from(&query);
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_dict_data::Entity>(
                prop,
                DICT_DATA_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let (rows, _) = self
            .dict_data_repo
            .find_page_filtered(
                offset,
                limit,
                Self::tenant_scope_of(tenant_id),
                query.dict_type.as_deref(),
                query.dict_label.as_deref(),
                query.status.as_deref(),
                sort,
            )
            .await?;
        Ok(rows)
    }

    /// 读单层字典数据缓存：
    /// - `Some(Some(rows))` = 命中数据；`Some(None)` = 命中空值 sentinel（该层无数据）；
    /// - `None` = 未命中 / 共享存储异常 / 反序列化失败（fail-open 降级 DB）。
    async fn read_dict_cache_layer(
        store: &Arc<dyn SharedStore>,
        key: &str,
    ) -> Option<Option<Vec<SysDictDataModel>>> {
        let cached: Option<String> = store.get(key).await.ok().flatten();
        match cached {
            None => None,
            Some(json_str) if json_str == DICT_NULL_MARKER => Some(None),
            Some(json_str) => match serde_json::from_str::<Vec<SysDictDataModel>>(&json_str) {
                Ok(rows) => Some(Some(rows)),
                Err(e) => {
                    // 缓存数据损坏 → 视为未命中，回退查 DB
                    tracing::warn!("字典缓存 {} 反序列化失败，回退查 DB: {}", key, e);
                    None
                }
            },
        }
    }

    /// 读取**某一归属层**的字典数据（cache-aside + singleflight）。
    ///
    /// 返回 `Some(rows)` 表示该层有数据；`None` 表示该层无数据（空值 sentinel）→ 调用方回落下一层。
    ///
    /// 缓存 key = `dict:{layer_tid}:{dict_type}`（两层缓存：平台层 0 / 租户层 tid）。
    /// R9-FLW-009 缓存防护：穿透（空值标记）+ 击穿（singleflight，锁粒度=缓存 key）。
    async fn load_dict_data_layer(
        &self,
        layer_tid: i64,
        dict_type: &str,
    ) -> Result<Option<Vec<SysDictDataModel>>, ServiceError> {
        let key = Self::cache_key(layer_tid, dict_type);

        // 1. 读缓存
        match Self::read_dict_cache_layer(&self.store, &key).await {
            Some(Some(rows)) => return Ok(Some(rows)),
            Some(None) => return Ok(None),
            None => {}
        }

        // 2. 未命中 → singleflight（锁粒度=缓存 key，层间不互相阻塞）
        let inflight_lock = {
            let mut map = self.inflight.lock().await;
            map.entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };

        let result: Result<Option<Vec<SysDictDataModel>>, ServiceError> = async {
            let _guard = inflight_lock.lock().await;

            // double-check：持有锁后再次读缓存，可能已被前一个持锁请求填充
            match Self::read_dict_cache_layer(&self.store, &key).await {
                Some(Some(rows)) => return Ok(Some(rows)),
                Some(None) => return Ok(None),
                None => {}
            }

            // 3. 查 DB（限本归属层，避免跨层/跨租户混读）
            let rows = self
                .dict_data_repo
                .find_active_by_dict_type_in_tenant(layer_tid, dict_type)
                .await?;

            // 4. 写缓存（best-effort）：空结果写空值标记（防穿透），非空写完整 JSON
            let (cache_value, ttl) = if rows.is_empty() {
                (DICT_NULL_MARKER.to_string(), DICT_NULL_TTL)
            } else {
                match serde_json::to_string(&rows) {
                    Ok(json) => (json, DICT_CACHE_TTL),
                    Err(e) => {
                        tracing::warn!("序列化字典数据失败，跳过缓存写入: {}", e);
                        (DICT_NULL_MARKER.to_string(), DICT_NULL_TTL)
                    }
                }
            };
            if let Err(e) = self.store.set_ex(&key, &cache_value, ttl as u64).await {
                tracing::warn!("写入字典缓存 {} 失败: {}", key, e);
            }

            Ok(if rows.is_empty() { None } else { Some(rows) })
        }
        .await;

        // R-1 修复：singleflight 完成后清理 inflight 条目，防止 HashMap 无限增长
        // 安全性：先 drop 本地 Arc 克隆，若 HashMap 中 strong_count == 1 说明仅 HashMap 持有引用，
        // 无其他请求在等待锁，可安全移除；若 strong_count > 1，说明有并发请求正在等待此锁，保留条目
        drop(inflight_lock);
        {
            let mut map = self.inflight.lock().await;
            if let Some(arc) = map.get(&key)
                && Arc::strong_count(arc) == 1
            {
                map.remove(&key);
            }
        }

        result
    }

    /// 按 dict_type 查询字典数据列表（前端下拉用，仅返回正常状态数据）
    ///
    /// 这是字典模块最核心的查询接口，供前端 select 组件使用。
    ///
    /// 多租户（§27.8）：字典数据按**类型归属层**隔离，读时合并、不缓存合并结果。
    /// - `tenant_id = None / Some(0)`：只读平台层；
    /// - `tenant_id = Some(tid)`（tid≠0）：本租户自建类型数据优先，无则回落平台类型数据。
    ///   由于禁止租户创建与平台同名类型，回落不会串读：租户自建类型必然在租户层有数据，
    ///   平台类型必然在平台层有数据，两层互斥。
    pub async fn get_dict_data_by_type(
        &self,
        dict_type: &str,
        tenant_id: Option<i64>,
    ) -> Result<Vec<SysDictDataModel>, ServiceError> {
        let tid = tenant_id.unwrap_or(0);
        // 1. 租户层（tid != 0）：本租户自建类型数据
        if tid != 0
            && let Some(rows) = self.load_dict_data_layer(tid, dict_type).await?
        {
            return Ok(rows);
        }
        // 2. 平台层（或回落）
        Ok(self
            .load_dict_data_layer(0, dict_type)
            .await?
            .unwrap_or_default())
    }

    /// 根据 dict_code 查询字典数据详情（治理视图）
    ///
    /// - 平台操作者（None / Some(0)）：全量可见；
    /// - 租户操作者（Some(tid)）：仅本租户行或平台行可见，否则 **403**（fail-closed）。
    pub async fn get_dict_data_by_id(
        &self,
        dict_code: i64,
        tenant_id: Option<i64>,
    ) -> Result<SysDictDataModel, ServiceError> {
        let model = self
            .dict_data_repo
            .find_active_by_id(dict_code)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.dict.data_not_found")))?;
        if let Some(tid) = Self::tenant_scope_of(tenant_id)
            && model.tenant_id != 0
            && model.tenant_id != tid
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.dict.platform_row_forbidden"
            )));
        }
        Ok(model)
    }

    /// 新增字典数据（写治理，§27.8）
    ///
    /// - 生效类型解析：本租户自建类型优先，否则平台类型（`find_effective_by_dict_type`）；
    ///   类型不存在 → 400。
    /// - 数据行归属层 = **类型归属层**（平台类型 → 0 / 租户自建类型 → 租户 ID）；
    /// - **租户不得给平台类型新增数据** → **403**（fail-closed）。
    pub async fn add_dict_data(
        &self,
        dto: DictDataAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysDictDataModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // 校验 dict_type 存在（限操作者可见域：本租户自建类型优先，否则平台类型）
        let dict_type_model = self
            .dict_type_repo
            .find_effective_by_dict_type(&dto.dict_type, Some(operator_tid))
            .await?
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.dict.type_not_found")))?;
        // 租户不得给平台类型新增数据（只能维护自建类型）
        if operator_tid != 0 && dict_type_model.tenant_id != operator_tid {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.dict.platform_row_forbidden"
            )));
        }
        // 数据行归属层 = 类型归属层（保证与类型同层，杜绝跨层孤儿行）
        let row_tid = dict_type_model.tenant_id;

        // 提前克隆 dict_type，避免后续 move 后无法用于缓存失效
        let dict_type_for_cache = dto.dict_type.clone();

        let now = crate::common::datetime::now_naive();
        let am = SysDictDataActiveModel {
            // 多租户：字典数据归属与其类型相同（平台类型=0 / 租户自建类型=租户 ID）
            tenant_id: Set(row_tid),
            dict_sort: Set(dto.dict_sort),
            dict_label: Set(Some(dto.dict_label)),
            dict_label_en: Set(dto.dict_label_en),
            dict_value: Set(Some(dto.dict_value)),
            dict_type: Set(Some(dto.dict_type)),
            css_class: Set(dto.css_class),
            list_class: Set(dto.list_class),
            is_default: Set(dto.is_default.or(Some("N".to_string()))),
            status: Set(dto.status.or(Some("0".to_string()))),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(dto.remark),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        };

        let dict_data_repo = self.dict_data_repo.clone();
        let operator_owned = operator.to_string();
        let model = self
            .db()
            .transaction::<_, SysDictDataModel, sea_orm::DbErr>(|txn| {
                let dict_data_repo = dict_data_repo.clone();
                let am = am;
                let operator = operator_owned.clone();
                Box::pin(async move {
                    let model = dict_data_repo.base().insert_conn(txn, am).await?;
                    // 审计合规域：INSERT 变更留痕（同事务提交/回滚，失败令业务一并回滚）
                    crate::service::sys_audit_change_service::audit_insert(
                        txn,
                        "sys_dict_data",
                        &model.dict_code.to_string(),
                        &model,
                        None, // add_dict_data 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator.as_str()),
                    )
                    .await?;
                    Ok(model)
                })
            })
            .await?;
        // 数据变更后失效**本归属层**的 dict_type 缓存
        self.invalidate_cache(row_tid, &dict_type_for_cache).await;
        Ok(model)
    }

    /// 修改字典数据（写治理，§27.8）
    ///
    /// - 仅本租户行可改（平台操作者全权）；租户不得改平台类型数据 → **403**；
    /// - dict_type 变更时，新类型必须与数据行**同归属层**（不得跨层搬迁）。
    pub async fn edit_dict_data(
        &self,
        dto: DictDataEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysDictDataModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let existing = self
            .get_dict_data_by_id(dto.dict_code, Some(operator_tid))
            .await?;
        // 多租户越权防护：只能修改本租户字典数据（平台操作者放行；租户不得改平台数据）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.dict.platform_row_forbidden"
            )));
        }
        // 记录旧 dict_type（dict_type 可能变更，需同时失效新旧缓存）
        let old_dict_type = existing.dict_type.clone().unwrap_or_default();
        // 数据行归属层（平台数据=0 / 租户自建数据=租户 ID），用于缓存失效与同层校验
        let row_tid = existing.tenant_id;

        // 校验新 dict_type 与本数据行同归属层
        if dto.dict_type != old_dict_type {
            let type_model = self
                .dict_type_repo
                .find_by_tenant_dict_type(row_tid, &dto.dict_type)
                .await?;
            if type_model.is_none() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.dict.type_not_found"
                )));
            }
        }

        let now = crate::common::datetime::now_naive();
        // 部分更新语义快照（2026-09-26 缺陷修复）：`existing` 随即被 `into()` 转移；
        // 未传字段保持现值，避免字典数据被静默置 NULL / 排序归零 / 默认标记丢失
        let existing_sort = existing.dict_sort;
        let existing_label_en = existing.dict_label_en.clone();
        let existing_css = existing.css_class.clone();
        let existing_list = existing.list_class.clone();
        let existing_default = existing.is_default.clone();
        let existing_status = existing.status.clone();
        // 审计合规域：变更前快照（必须在 existing 被 move 进 ActiveModel 之前计算）
        let before_snapshot = serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);
        let mut am: SysDictDataActiveModel = existing.into();
        am.dict_sort = Set(dto.dict_sort.or(existing_sort));
        am.dict_label = Set(Some(dto.dict_label));
        am.dict_label_en = Set(dto.dict_label_en.or(existing_label_en));
        am.dict_value = Set(Some(dto.dict_value));
        am.dict_type = Set(Some(dto.dict_type.clone()));
        am.css_class = Set(dto.css_class.or(existing_css));
        am.list_class = Set(dto.list_class.or(existing_list));
        am.is_default = Set(dto.is_default.or(existing_default));
        am.status = Set(dto.status.or(existing_status));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.remark = Set(dto.remark);

        let dict_data_repo = self.dict_data_repo.clone();
        let operator_owned = operator.to_string();
        let model = self
            .db()
            .transaction::<_, SysDictDataModel, sea_orm::DbErr>(|txn| {
                let dict_data_repo = dict_data_repo.clone();
                let am = am;
                let before_snapshot = before_snapshot.clone();
                let operator = operator_owned.clone();
                Box::pin(async move {
                    let model = dict_data_repo.base().update_conn(txn, am).await?;
                    // 审计合规域：UPDATE 变更留痕（同事务提交/回滚）
                    crate::service::sys_audit_change_service::audit_update(
                        txn,
                        "sys_dict_data",
                        &model.dict_code.to_string(),
                        &before_snapshot,
                        &model,
                        None, // edit_dict_data 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator.as_str()),
                    )
                    .await?;
                    Ok(model)
                })
            })
            .await?;
        // 失效新旧 dict_type 缓存（限本归属层）
        let mut to_invalidate = vec![dto.dict_type.clone()];
        if dto.dict_type != old_dict_type {
            to_invalidate.push(old_dict_type);
        }
        self.invalidate_caches(row_tid, &to_invalidate).await;
        Ok(model)
    }

    /// 批量删除字典数据（软删除，事务：软删与审计留痕原子化）
    ///
    /// 多租户：租户不得删除平台类型数据（`tenant_id=0`）→ **403**；跨租户行 → 403。
    pub async fn delete_dict_data(
        &self,
        dict_codes: Vec<i64>,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if dict_codes.is_empty() {
            return Ok(());
        }
        // 批量查询所有记录的 dict_type，用于删除后失效缓存（单次 SELECT 替代 N 次）
        let models = self.dict_data_repo.find_active_by_ids(&dict_codes).await?;
        // 租户不得删除平台类型数据（fail-closed 403，先给出明确语义）
        if operator_tid != 0 && models.iter().any(|m| m.tenant_id == 0) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.dict.platform_row_forbidden"
            )));
        }
        // 多租户越权防护：任一所选字典数据跨越操作者租户即整体拒绝（平台操作者放行）
        if models
            .iter()
            .any(|m| !crate::common::tenant::tenant_allowed(operator_tid, m.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        // 按归属层分组收集受影响的 dict_type
        let mut invalidations: std::collections::HashMap<i64, Vec<String>> =
            std::collections::HashMap::new();
        for m in &models {
            if let Some(dt) = m.dict_type.clone() {
                invalidations.entry(m.tenant_id).or_default().push(dt);
            }
        }
        // 事务：批量软删除 + 逐行 DELETE 审计留痕（同事务提交/回滚）
        let dict_data_repo = self.dict_data_repo.clone();
        let operator_owned = operator.to_string();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let dict_data_repo = dict_data_repo.clone();
                let dict_codes = dict_codes.clone();
                let models = models.clone();
                let operator = operator_owned.clone();
                Box::pin(async move {
                    // 批量软删除（单次 UPDATE 替代 N 次）
                    dict_data_repo
                        .soft_delete_many_conn(txn, dict_codes)
                        .await?;
                    for m in &models {
                        // 审计合规域：DELETE 变更留痕（同事务提交/回滚）
                        crate::service::sys_audit_change_service::audit_delete(
                            txn,
                            "sys_dict_data",
                            &m.dict_code.to_string(),
                            m,
                            None, // delete_dict_data 签名仅携带操作人用户名，ID 由回查补齐
                            Some(operator.as_str()),
                        )
                        .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        // 失效所有受影响的 dict_type 缓存（按归属层）
        for (owner_tid, dts) in invalidations {
            self.invalidate_caches(owner_tid, &dts).await;
        }
        Ok(())
    }

    /// 刷新全部字典缓存（删除所有 dict:* 的键）
    ///
    /// 使用 SCAN 遍历所有 dict:* 键并批量删除，避免 KEYS 命令阻塞 Redis。
    pub async fn refresh_all_dict_cache(&self) -> Result<(), ServiceError> {
        // 全量扫描（原 cursor 循环至游标归零的语义 = scan_keys_all ⇒ scan(pattern, None)）
        let keys_to_delete = self
            .store
            .scan(&format!("{}*", DICT_CACHE_PREFIX), None)
            .await
            .map_err(|e| ServiceError::internal(&format!("扫描字典缓存键失败: {}", e)))?;

        if keys_to_delete.is_empty() {
            return Ok(());
        }

        // 批量删除所有 dict:* 键
        let count = self
            .store
            .del(&keys_to_delete)
            .await
            .map_err(|e| ServiceError::internal(&format!("删除字典缓存键失败: {}", e)))?;
        // R5-TRACE-17：字典缓存刷新属**高频常规**操作（每次字典变更都会触发），
        // 原 info 级会在多实例/批量导入场景刷屏；降为 debug，保留排障能力而不淹没告警。
        tracing::debug!("刷新字典缓存：删除 {} 个键", count);
        Ok(())
    }
}
