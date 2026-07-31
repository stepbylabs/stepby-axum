//! 字典模块 Service 层
//!
//! 职责：
//! - 字典类型 CRUD、字典类型查重、按 dict_type 查询字典数据
//! - 字典数据 CRUD、按 dict_type 查询列表（前端下拉用）
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 数据访问通过 Repository 层委托
//! - 多表操作（字典类型变更级联、字典类型删除级联）使用事务保证一致性

use chrono::NaiveDateTime;
use futures::future::FutureExt;
use redis::aio::ConnectionManager;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use utoipa::{IntoParams, ToSchema};
use garde::Validate;

use crate::common::error::ServiceError;
use crate::common::page::{default_page_num, default_page_size, PageDomain};
use crate::entity::sys_dict_data::{
    ActiveModel as SysDictDataActiveModel, Model as SysDictDataModel,
};
use crate::entity::sys_dict_type::{
    ActiveModel as SysDictTypeActiveModel, Model as SysDictTypeModel,
};
use crate::repository::sys_dict_data::SysDictDataRepository;
use crate::repository::sys_dict_type::SysDictTypeRepository;

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
    pub dict_name: Option<String>,
    pub dict_type: Option<String>,
    pub status: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&DictTypeQueryDto> for PageDomain {
    fn from(dto: &DictTypeQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
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
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DictDataQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub dict_type: Option<String>,
    pub dict_label: Option<String>,
    pub status: Option<String>,
}

impl From<&DictDataQueryDto> for PageDomain {
    fn from(dto: &DictDataQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
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

/// 解析时间字符串（%Y-%m-%d 格式），失败返回 ServiceError
fn parse_time(s: &str) -> Result<NaiveDateTime, ServiceError> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| ServiceError::bad_request(&crate::tr!("error.common.time_format_invalid", s = s)))
}

// ==================== Service 实现 ====================

/// 字典模块 Service（字典类型 + 字典数据）
///
/// 数据访问通过 Repository 层委托：
/// - dict_type_repo: sys_dict_type 表 CRUD
/// - dict_data_repo: sys_dict_data 表 CRUD
/// - redis: Redis 连接管理器，用于字典数据缓存（cache-aside 模式）
///
/// R9-FLW-009：缓存穿透防护（空值缓存）+ 击穿防护（singleflight）
pub struct SysDictService {
    dict_type_repo: SysDictTypeRepository,
    dict_data_repo: SysDictDataRepository,
    redis: ConnectionManager,
    /// singleflight 锁表：同 dict_type 的并发查询只允许一个查 DB，其他等待复用结果
    ///
    /// 防止热点 key 失效瞬间 N 个请求同时打 DB（缓存击穿）。
    /// 锁粒度为 dict_type 字符串，不同 dict_type 互不阻塞。
    inflight: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl SysDictService {
    pub fn new(db: DatabaseConnection, redis: ConnectionManager) -> Self {
        Self {
            dict_type_repo: SysDictTypeRepository::new(db.clone()),
            dict_data_repo: SysDictDataRepository::new(db),
            redis,
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn db(&self) -> &DatabaseConnection {
        self.dict_type_repo.base().db()
    }

    // ==================== 缓存辅助方法 ====================

    /// 构造字典缓存 key
    fn cache_key(dict_type: &str) -> String {
        format!("{}{}", DICT_CACHE_PREFIX, dict_type)
    }

    /// 失效指定 dict_type 的缓存（best-effort，失败仅记日志不阻断业务）
    async fn invalidate_cache(&self, dict_type: &str) {
        let key = Self::cache_key(dict_type);
        let mut conn = self.redis.clone();
        if let Err(e) = redis::cmd("DEL")
            .arg(&key)
            .query_async::<()>(&mut conn)
            .await
        {
            tracing::warn!("失效字典缓存 {} 失败: {}", key, e);
        }
    }

    /// 失效多个 dict_type 的缓存（P2-6：改 Redis pipeline 批量 DEL，一次往返）
    ///
    /// 保持 best-effort 语义：失败仅 warn 不阻断业务。
    async fn invalidate_caches(&self, dict_types: &[String]) {
        if dict_types.is_empty() {
            return;
        }
        let mut conn = self.redis.clone();
        // 构造 pipeline：每个 DEL 独立入队，一次发送
        let mut pipe = redis::pipe();
        pipe.atomic(); // 非事务，允许部分成功
        for dt in dict_types {
            pipe.cmd("DEL").arg(Self::cache_key(dt));
        }
        if let Err(e) = pipe.query_async::<Vec<i64>>(&mut conn).await {
            tracing::warn!("批量失效字典缓存失败（{} 个 dict_type）: {}", dict_types.len(), e);
            // 回退到逐个 DEL，保证尽可能多的缓存被清除
            for dt in dict_types {
                self.invalidate_cache(dt).await;
            }
        }
    }

    // ==================== 字典类型 ====================

    /// 分页查询字典类型
    ///
    /// 支持 dict_name 模糊、dict_type 模糊、status 精确、时间范围筛选
    pub async fn get_dict_type_page(
        &self,
        query: DictTypeQueryDto,
    ) -> Result<(Vec<SysDictTypeModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let begin = match query.begin_time.as_deref() {
            Some(s) => Some(parse_time(s)?),
            None => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) => Some(parse_time(s)?),
            None => None,
        };

        let (rows, total) = self
            .dict_type_repo
            .find_page_filtered(
                offset,
                limit,
                query.dict_name.as_deref(),
                query.dict_type.as_deref(),
                query.status.as_deref(),
                begin,
                end,
            )
            .await?;
        Ok((rows, total))
    }

    /// 导出字典类型列表（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    pub async fn export_dict_types(&self, query: DictTypeQueryDto) -> Result<Vec<SysDictTypeModel>, ServiceError> {
        let offset = 0u64;
        let limit = crate::common::page::EXPORT_MAX_ROWS;

        let begin = match query.begin_time.as_deref() {
            Some(s) => Some(parse_time(s)?),
            None => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) => Some(parse_time(s)?),
            None => None,
        };

        let (rows, _) = self
            .dict_type_repo
            .find_page_filtered(
                offset,
                limit,
                query.dict_name.as_deref(),
                query.dict_type.as_deref(),
                query.status.as_deref(),
                begin,
                end,
            )
            .await?;
        Ok(rows)
    }

    /// 查询全部未删除字典类型（前端下拉选择用）
    pub async fn get_all_dict_types(&self) -> Result<Vec<SysDictTypeModel>, ServiceError> {
        let rows = self.dict_type_repo.find_active_all().await?;
        Ok(rows)
    }

    /// 根据 dict_id 查询字典类型详情
    pub async fn get_dict_type_by_id(
        &self,
        dict_id: i64,
    ) -> Result<SysDictTypeModel, ServiceError> {
        let model = self
            .dict_type_repo
            .find_active_by_id(dict_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.dict.type_not_found")))?;
        Ok(model)
    }

    /// 新增字典类型
    ///
    /// 业务校验：dict_type 唯一性（未删除范围内）
    pub async fn add_dict_type(
        &self,
        dto: DictTypeAddDto,
        operator: &str,
    ) -> Result<SysDictTypeModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // dict_type 唯一性校验
        let existing = self.dict_type_repo.find_by_dict_type(&dto.dict_type).await?;
        if existing.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!("error.dict.type_exists")));
        }

        // 提前克隆 dict_type，避免后续 move 后无法用于缓存失效
        let dict_type_for_cache = dto.dict_type.clone();

        let now = chrono::Local::now().naive_local();
        let am = SysDictTypeActiveModel {
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

        let model = self.dict_type_repo.insert(am).await?;
        // 新增字典类型后失效对应缓存（防御性清理，正常情况下无数据）
        self.invalidate_cache(&dict_type_for_cache).await;
        Ok(model)
    }

    /// 修改字典类型（事务：字典类型变更时同步更新 sys_dict_data.dict_type）
    ///
    /// 业务校验：
    /// - 目标存在且未删除
    /// - dict_type 若变更，校验新值唯一性
    /// - 若 dict_type 变更，事务内同步更新 sys_dict_data.dict_type
    pub async fn edit_dict_type(
        &self,
        dto: DictTypeEditDto,
        operator: &str,
    ) -> Result<SysDictTypeModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let existing = self.get_dict_type_by_id(dto.dict_id).await?;

        // dict_type 变更时校验唯一性
        let old_dict_type = existing.dict_type.clone().unwrap_or_default();
        let dict_type_changed = dto.dict_type != old_dict_type;
        if dict_type_changed {
            let conflict = self.dict_type_repo.find_by_dict_type(&dto.dict_type).await?;
            if conflict.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!("error.dict.type_exists")));
            }
        }

        let now = chrono::Local::now().naive_local();
        let mut am: SysDictTypeActiveModel = existing.into();
        am.dict_name = Set(Some(dto.dict_name));
        am.dict_type = Set(Some(dto.dict_type.clone()));
        am.status = Set(dto.status);
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
                async move {
                    // 若 dict_type 变更，同步更新 sys_dict_data.dict_type
                    if dict_type_changed {
                        dict_data_repo
                            .update_dict_type_conn(txn, &old_dict_type, &new_dict_type)
                            .await?;
                    }
                    // 更新字典类型
                    let model = dict_type_repo.base().update_conn(txn, am).await?;
                    Ok(model)
                }
                .boxed()
            })
            .await?;
        // 字典类型变更后失效新旧 dict_type 缓存
        let mut to_invalidate = vec![dto.dict_type.clone()];
        if dict_type_changed {
            to_invalidate.push(old_dict_type);
        }
        self.invalidate_caches(&to_invalidate).await;
        Ok(model)
    }

    /// 批量删除字典类型（事务：级联软删除关联字典数据）
    ///
    /// REGRESS-003：软删除时重命名 dict_type 为 `{original}_deleted_{dict_id}`，
    /// 释放 uk_sys_dict_type 唯一索引，避免无法重新创建同名字典类型。
    pub async fn delete_dict_types(
        &self,
        dict_ids: Vec<i64>,
    ) -> Result<(), ServiceError> {
        // 预查询所有 dict_type 字符串（事务外查询，事务内仅写）
        // 批量查询（单次 SELECT 替代 N 次），并校验全部存在
        let models = self.dict_type_repo.find_active_by_ids(&dict_ids).await?;
        if models.len() != dict_ids.len() {
            return Err(ServiceError::not_found(&crate::tr!("error.dict.type_not_found")));
        }
        // 保持按 dict_ids 输入顺序构建 (dict_id, dict_type)，便于事务内重命名
        let mut dict_types: Vec<(i64, String)> = Vec::with_capacity(dict_ids.len());
        for dict_id in &dict_ids {
            let dt = models
                .iter()
                .find(|m| m.dict_id == *dict_id)
                .and_then(|m| m.dict_type.clone())
                .unwrap_or_default();
            dict_types.push((*dict_id, dt));
        }

        let dict_type_repo = self.dict_type_repo.clone();
        let dict_data_repo = self.dict_data_repo.clone();

        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let dict_type_repo = dict_type_repo.clone();
                let dict_data_repo = dict_data_repo.clone();
                let dict_types = dict_types.clone();
                async move {
                    for (dict_id, dict_type) in &dict_types {
                        // 软删除字典类型并重命名 dict_type（REGRESS-003）
                        // P0-H1 修复：dict_type 列为 VARCHAR(100)，重命名后缀可能超长导致 UPDATE 失败
                        // 截断原始 dict_type 到安全长度，确保 {truncated}_deleted_{dict_id} ≤ 100
                        let suffix = format!("_deleted_{}", dict_id);
                        let max_original_len = 100usize.saturating_sub(suffix.len());
                        let truncated_original = if dict_type.len() > max_original_len {
                            &dict_type[..max_original_len]
                        } else {
                            dict_type.as_str()
                        };
                        let renamed = format!("{}{}", truncated_original, suffix);
                        dict_type_repo
                            .soft_delete_with_rename_conn(txn, *dict_id, renamed)
                            .await?;
                        // 级联软删除关联字典数据（按原始 dict_type，dict_data 表无外键约束）
                        dict_data_repo
                            .soft_delete_by_dict_type_conn(txn, dict_type)
                            .await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await?;
        // 删除字典类型后失效所有相关 dict_type 缓存
        let to_invalidate: Vec<String> = dict_types
            .iter()
            .map(|(_, dt)| dt.clone())
            .collect();
        self.invalidate_caches(&to_invalidate).await;
        Ok(())
    }

    // ==================== 字典数据 ====================

    /// 分页查询字典数据
    ///
    /// 支持 dict_type 精确、dict_label 模糊、status 精确筛选
    pub async fn get_dict_data_page(
        &self,
        query: DictDataQueryDto,
    ) -> Result<(Vec<SysDictDataModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let (rows, total) = self
            .dict_data_repo
            .find_page_filtered(
                offset,
                limit,
                query.dict_type.as_deref(),
                query.dict_label.as_deref(),
                query.status.as_deref(),
            )
            .await?;
        Ok((rows, total))
    }

    /// 导出字典数据（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    pub async fn export_dict_data(
        &self,
        query: DictDataQueryDto,
    ) -> Result<Vec<SysDictDataModel>, ServiceError> {
        let offset = 0u64;
        let limit = crate::common::page::EXPORT_MAX_ROWS;

        let (rows, _) = self
            .dict_data_repo
            .find_page_filtered(
                offset,
                limit,
                query.dict_type.as_deref(),
                query.dict_label.as_deref(),
                query.status.as_deref(),
            )
            .await?;
        Ok(rows)
    }

    /// 按 dict_type 查询字典数据列表（前端下拉用，仅返回正常状态数据）
    ///
    /// 这是字典模块最核心的查询接口，供前端 select 组件使用。
    /// 采用 cache-aside 模式：先查 Redis（key=dict:{dict_type}），命中则直接返回；
    /// 未命中则查 DB，结果序列化后写入 Redis（TTL 30 分钟）。
    /// 缓存读写失败不阻断业务（best-effort），降级为直接查 DB。
    ///
    /// R9-FLW-009 缓存防护：
    /// - 穿透防护：dict_type 不存在时缓存空值标记（TTL 60s），避免反复打 DB
    /// - 击穿防护：热点 key 失效瞬间通过 singleflight 串行化 DB 查询，
    ///   同 dict_type 的并发请求只允许一个查 DB，其他等待复用结果
    pub async fn get_dict_data_by_type(
        &self,
        dict_type: &str,
    ) -> Result<Vec<SysDictDataModel>, ServiceError> {
        let key = Self::cache_key(dict_type);
        let mut conn = self.redis.clone();

        // 1. 尝试从 Redis 读取缓存
        let cached: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .ok()
            .flatten();

        if let Some(json_str) = cached {
            // 空值标记：dict_type 不存在，返回空列表（防穿透）
            if json_str == DICT_NULL_MARKER {
                return Ok(Vec::new());
            }
            match serde_json::from_str::<Vec<SysDictDataModel>>(&json_str) {
                Ok(rows) => return Ok(rows),
                Err(e) => {
                    // 缓存数据损坏，记日志并回退到 DB
                    tracing::warn!("字典缓存 {} 反序列化失败，回退查 DB: {}", key, e);
                }
            }
        }

        // 2. 缓存未命中或损坏，通过 singleflight 串行化 DB 查询（防击穿）
        // 获取或创建 dict_type 对应的 inflight 锁
        let inflight_lock = {
            let mut map = self.inflight.lock().await;
            map.entry(dict_type.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };

        // 持有 inflight 锁期间查 DB + 写缓存（用 async 块收集结果，避免 early return 跳过清理）
        let result: Result<Vec<SysDictDataModel>, ServiceError> = async {
            let _guard = inflight_lock.lock().await;

            // double-check：持有锁后再次查缓存，可能已被前一个持锁请求填充
            let cached: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .ok()
                .flatten();
            if let Some(json_str) = cached {
                if json_str == DICT_NULL_MARKER {
                    return Ok(Vec::new());
                }
                if let Ok(rows) = serde_json::from_str::<Vec<SysDictDataModel>>(&json_str) {
                    return Ok(rows);
                }
            }

            // 3. 查询 DB
            let rows = self.dict_data_repo.find_active_by_dict_type(dict_type).await?;

            // 4. 写入 Redis（best-effort，失败仅记日志）
            // 空结果写入空值标记（防穿透），非空结果写入完整 JSON
            let cache_value = if rows.is_empty() {
                DICT_NULL_MARKER.to_string()
            } else {
                serde_json::to_string(&rows).unwrap_or_else(|e| {
                    tracing::warn!("序列化字典数据失败，跳过缓存写入: {}", e);
                    DICT_NULL_MARKER.to_string()
                })
            };
            let ttl = if rows.is_empty() { DICT_NULL_TTL } else { DICT_CACHE_TTL };
            if let Err(e) = redis::cmd("SETEX")
                .arg(&key)
                .arg(ttl)
                .arg(cache_value)
                .query_async::<()>(&mut conn)
                .await
            {
                tracing::warn!("写入字典缓存 {} 失败: {}", key, e);
            }

            Ok(rows)
        }
        .await;

        // R-1 修复：singleflight 完成后清理 inflight 条目，防止 HashMap 无限增长
        // 安全性：先 drop 本地 Arc 克隆，若 HashMap 中 strong_count == 1 说明仅 HashMap 持有引用，
        // 无其他请求在等待锁，可安全移除；若 strong_count > 1，说明有并发请求正在等待此锁，保留条目
        drop(inflight_lock);
        {
            let mut map = self.inflight.lock().await;
            if let Some(arc) = map.get(dict_type)
                && Arc::strong_count(arc) == 1
            {
                map.remove(dict_type);
            }
        }

        result
    }

    /// 根据 dict_code 查询字典数据详情
    pub async fn get_dict_data_by_id(
        &self,
        dict_code: i64,
    ) -> Result<SysDictDataModel, ServiceError> {
        let model = self
            .dict_data_repo
            .find_active_by_id(dict_code)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.dict.data_not_found")))?;
        Ok(model)
    }

    /// 新增字典数据
    pub async fn add_dict_data(
        &self,
        dto: DictDataAddDto,
        operator: &str,
    ) -> Result<SysDictDataModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // 校验 dict_type 在 sys_dict_type 中存在
        let dict_type_exists = self.dict_type_repo.find_by_dict_type(&dto.dict_type).await?;
        if dict_type_exists.is_none() {
            return Err(ServiceError::bad_request(&crate::tr!("error.dict.type_not_found")));
        }

        // 提前克隆 dict_type，避免后续 move 后无法用于缓存失效
        let dict_type_for_cache = dto.dict_type.clone();

        let now = chrono::Local::now().naive_local();
        let am = SysDictDataActiveModel {
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

        let model = self.dict_data_repo.insert(am).await?;
        // 数据变更后失效对应 dict_type 缓存
        self.invalidate_cache(&dict_type_for_cache).await;
        Ok(model)
    }

    /// 修改字典数据
    pub async fn edit_dict_data(
        &self,
        dto: DictDataEditDto,
        operator: &str,
    ) -> Result<SysDictDataModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let existing = self.get_dict_data_by_id(dto.dict_code).await?;
        // 记录旧 dict_type（dict_type 可能变更，需同时失效新旧缓存）
        let old_dict_type = existing.dict_type.clone().unwrap_or_default();

        // 校验新 dict_type 在 sys_dict_type 中存在（与 add_dict_data 一致）
        if dto.dict_type != old_dict_type {
            let dict_type_exists = self.dict_type_repo.find_by_dict_type(&dto.dict_type).await?;
            if dict_type_exists.is_none() {
                return Err(ServiceError::bad_request(&crate::tr!("error.dict.type_not_found")));
            }
        }

        let now = chrono::Local::now().naive_local();
        let mut am: SysDictDataActiveModel = existing.into();
        am.dict_sort = Set(dto.dict_sort);
        am.dict_label = Set(Some(dto.dict_label));
        am.dict_label_en = Set(dto.dict_label_en);
        am.dict_value = Set(Some(dto.dict_value));
        am.dict_type = Set(Some(dto.dict_type.clone()));
        am.css_class = Set(dto.css_class);
        am.list_class = Set(dto.list_class);
        am.is_default = Set(dto.is_default);
        am.status = Set(dto.status);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.remark = Set(dto.remark);

        let model = self.dict_data_repo.update(am).await?;
        // 失效新旧 dict_type 缓存
        let mut to_invalidate = vec![dto.dict_type.clone()];
        if dto.dict_type != old_dict_type {
            to_invalidate.push(old_dict_type);
        }
        self.invalidate_caches(&to_invalidate).await;
        Ok(model)
    }

    /// 批量删除字典数据（软删除）
    pub async fn delete_dict_data(
        &self,
        dict_codes: Vec<i64>,
    ) -> Result<(), ServiceError> {
        if dict_codes.is_empty() {
            return Ok(());
        }
        // 批量查询所有记录的 dict_type，用于删除后失效缓存（单次 SELECT 替代 N 次）
        let models = self.dict_data_repo.find_active_by_ids(&dict_codes).await?;
        let affected_types: Vec<String> = models
            .iter()
            .filter_map(|m| m.dict_type.clone())
            .collect();
        // 批量软删除（单次 UPDATE 替代 N 次）
        self.dict_data_repo.soft_delete_many(dict_codes).await?;
        // 失效所有受影响的 dict_type 缓存
        self.invalidate_caches(&affected_types).await;
        Ok(())
    }

    /// 刷新全部字典缓存（删除所有 dict:* 的键）
    ///
    /// 使用 SCAN 遍历所有 dict:* 键并批量删除，避免 KEYS 命令阻塞 Redis。
    pub async fn refresh_all_dict_cache(&self) -> Result<(), ServiceError> {
        let mut conn = self.redis.clone();
        let mut keys_to_delete: Vec<String> = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{}*", DICT_CACHE_PREFIX))
                .arg("COUNT")
                .arg(200i64)
                .query_async(&mut conn)
                .await?;
            keys_to_delete.extend(batch);
            if next_cursor == 0 {
                break;
            }
            cursor = next_cursor;
        }

        if keys_to_delete.is_empty() {
            return Ok(());
        }

        // 批量删除所有 dict:* 键
        let count: i64 = redis::cmd("DEL")
            .arg(&keys_to_delete)
            .query_async(&mut conn)
            .await?;
        tracing::info!("刷新字典缓存：删除 {} 个键", count);
        Ok(())
    }
}
