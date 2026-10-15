//! 操作日志模块 Service 层
//!
//! 职责：
//! - 操作日志分页查询（多条件筛选）
//! - 操作日志详情查询
//! - 操作日志批量删除（物理删除）
//! - 操作日志清空
//! - 操作日志记录（供中间件调用，异步写入不阻断主流程）
//!
//! 不依赖任何 Web 框架类型（axum / tower / tower-http）

use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sea_orm::{
    DatabaseConnection, EntityTrait, NotSet, PaginatorTrait, QueryOrder, QuerySelect, Set,
    TransactionTrait,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::config::settings::LogRetentionMode;
use crate::entity::sys_log_archive_anchor::{
    ActiveModel as AnchorActiveModel, Entity as SysLogArchiveAnchor,
};
use crate::entity::sys_oper_log::{
    ActiveModel as SysOperLogActiveModel, Column as OperLogColumn, Model as SysOperLogModel,
};
use crate::repository::base::BaseRepository;
use crate::repository::sys_oper_log::SysOperLogRepository;
use crate::service::oper_log_chain_seed::{
    ChainAnchorSnapshot, GENESIS_SEED, PrevSeed, resolve_prev_seed,
};
use crate::shared_store::SharedStore;
use crate::utils::retry::{RetryPolicy, retry_async};

/// 归档导出单卷字节上限（工程基线 D2"资源硬上限 + 背压"）：超出即中止清理并保留
/// 数据（fail-closed），提示改用外部归档工具或调大保留期——禁止无界内存导出。
const ARCHIVE_MAX_BYTES: usize = 512 * 1024 * 1024;

/// 归档导出分批行数（每批 SELECT 行数，控制单批内存峰值）
const ARCHIVE_BATCH_ROWS: u64 = 5000;

/// 归档对象存储目录（平台租户 0 归属；local 档落 `uploads/0/audit-archive/`）。
///
/// ⚠️ 必须带 `uploads/` 根前缀：`resolve_upload_dir` 对无父段的裸目录名会把根
/// 回落为 cwd（→ `<cwd>/0/audit-archive`，污染工作区且脱离 uploads 隔离语义）。
const ARCHIVE_STORAGE_DIR: &str = "uploads/audit-archive";

/// 操作日志写入的有界重试策略（R5-RATE-29）：3 次尝试 / 100ms 间隔。
///
/// DB 短暂抖动（连接重置、锁等待超时）多为毫秒级可恢复，固定短退避即可覆盖；
/// 次数硬上限确保 DB 长时间不可用时 spawn 任务不会被无限占用。
const OPER_LOG_WRITE_RETRY: RetryPolicy = RetryPolicy::new(3, Duration::from_millis(100));

// ==================== 防篡改 HMAC 链 ====================

/// 链锁键（SharedStore SETNX 互斥：同一时刻仅一个写入方延长链尾）
const OPER_CHAIN_LOCK_KEY: &str = "lock:oper_chain";

/// 链锁抢占间隔（毫秒）：SETNX 未命中后的重试等待
const OPER_CHAIN_LOCK_WAIT_MS: u64 = 300;

/// 链锁抢占尝试次数：重试耗尽即降级（本条 chain_hash 留 NULL，链在非 NULL 子序列上续写）
const OPER_CHAIN_LOCK_ATTEMPTS: u64 = 3;

/// 链锁 TTL（秒）：正常链计算毫秒级完成；TTL 兜底持有者崩溃后的死锁
const OPER_CHAIN_LOCK_TTL_SECS: u64 = 5;

/// 链密钥派生盐（HMAC-SHA256(jwt_secret, 盐) → 32 字节链密钥，不落盘不入日志）
const OPER_CHAIN_KEY_INFO: &[u8] = b"stepby-oper-chain";

/// 链哈希字段拼接分隔符
const OPER_CHAIN_SEP: &str = "|";

/// HMAC-SHA256 别名
type HmacSha256 = Hmac<Sha256>;

/// 从 JWT secret 派生链密钥（HMAC-SHA256(jwt_secret, "stepby-oper-chain")，32 字节）
fn derive_chain_key(jwt_secret: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(jwt_secret.as_bytes())
        .expect("HMAC 接受任意长度密钥，此处不可能失败");
    mac.update(OPER_CHAIN_KEY_INFO);
    mac.finalize().into_bytes().into()
}

/// 计算 payload 的 SHA-256 指纹（hex）。JSON 序列化按 struct 字段声明序，输出确定性一致。
fn payload_hex_digest(payload: &ChainPayload) -> String {
    let json = serde_json::to_string(payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    crate::utils::crypto::hex_encode_digest(&hasher.finalize())
}

/// 计算链节点哈希：HMAC-SHA256(key, prev || "|" || oper_id || "|" || payload_hash)
///
/// `prev`：前驱节点 hex（链首传空串）；`oper_id`：本条日志主键；
/// `payload_hash`：[`payload_hex_digest`] 输出。
fn compute_chain_hash(key: &[u8; 32], prev: &str, oper_id: i64, payload_hash: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 接受 32 字节密钥");
    mac.update(prev.as_bytes());
    mac.update(OPER_CHAIN_SEP.as_bytes());
    mac.update(oper_id.to_string().as_bytes());
    mac.update(OPER_CHAIN_SEP.as_bytes());
    mac.update(payload_hash.as_bytes());
    crate::utils::crypto::hex_encode_digest(&mac.finalize().into_bytes())
}

/// 参与操作日志链哈希计算的最小负载（写入端与校验端共用，字段与顺序必须完全一致）
///
/// 两端构造口径统一执行「空串 → None」归一化（对齐 record_oper_log 写库时的
/// empty→None 行为），保证同一行日志经任一端构造出的序列化结果逐字节相同。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainPayload {
    title: Option<String>,
    business_type: Option<i32>,
    method: Option<String>,
    request_method: Option<String>,
    operator_type: Option<i32>,
    oper_name: Option<String>,
    dept_name: Option<String>,
    oper_url: Option<String>,
    oper_ip: Option<String>,
    oper_location: Option<String>,
    oper_param: Option<String>,
    oper_before: Option<String>,
    oper_diff: Option<String>,
    json_result: Option<String>,
    status: Option<String>,
    error_msg: Option<String>,
    /// 固定 `%Y-%m-%d %H:%M:%S%.6f` 格式（chrono 序列化格式有歧义，链哈希要求确定性）
    oper_time: Option<String>,
    cost_time: Option<i64>,
    tenant_id: i64,
    target_tenant_id: Option<i64>,
}

impl ChainPayload {
    /// 「空串 → None」归一化（对齐 record_oper_log 写库口径）
    fn normalize(s: String) -> Option<String> {
        if s.is_empty() { None } else { Some(s) }
    }

    /// 写入端构造：来自中间件的 [`OperLogRecord`] + 本条 oper_time 字符串
    ///
    /// 必须在 record 被 move 进 ActiveModel 之前调用。
    fn from_parts(record: &OperLogRecord, oper_time: &str) -> Self {
        Self {
            title: Self::normalize(record.title.clone()),
            business_type: Some(record.business_type),
            method: Self::normalize(record.method.clone()),
            request_method: Self::normalize(record.request_method.clone()),
            operator_type: Some(record.operator_type),
            oper_name: Self::normalize(record.oper_name.clone()),
            dept_name: Self::normalize(record.dept_name.clone()),
            oper_url: Self::normalize(record.oper_url.clone()),
            oper_ip: Self::normalize(record.oper_ip.clone()),
            oper_location: Self::normalize(record.oper_location.clone()),
            oper_param: Self::normalize(record.oper_param.clone()),
            oper_before: Self::normalize(record.oper_before.clone()),
            oper_diff: Self::normalize(record.oper_diff.clone()),
            json_result: Self::normalize(record.json_result.clone()),
            status: Self::normalize(record.status.clone()),
            error_msg: Self::normalize(record.error_msg.clone()),
            oper_time: Some(oper_time.to_string()),
            cost_time: Some(record.cost_time),
            tenant_id: record.tenant_id,
            target_tenant_id: record.target_tenant_id,
        }
    }

    /// 校验端构造：从 DB 读回的 [`SysOperLogModel`]（与写入端逐字段对齐）
    fn from_model(m: &SysOperLogModel) -> Self {
        let oper_time = m
            .oper_time
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string());
        Self {
            title: Self::normalize(m.title.clone().unwrap_or_default()),
            business_type: m.business_type,
            method: Self::normalize(m.method.clone().unwrap_or_default()),
            request_method: Self::normalize(m.request_method.clone().unwrap_or_default()),
            operator_type: m.operator_type,
            oper_name: Self::normalize(m.oper_name.clone().unwrap_or_default()),
            dept_name: Self::normalize(m.dept_name.clone().unwrap_or_default()),
            oper_url: Self::normalize(m.oper_url.clone().unwrap_or_default()),
            oper_ip: Self::normalize(m.oper_ip.clone().unwrap_or_default()),
            oper_location: Self::normalize(m.oper_location.clone().unwrap_or_default()),
            oper_param: Self::normalize(m.oper_param.clone().unwrap_or_default()),
            oper_before: Self::normalize(m.oper_before.clone().unwrap_or_default()),
            oper_diff: Self::normalize(m.oper_diff.clone().unwrap_or_default()),
            json_result: Self::normalize(m.json_result.clone().unwrap_or_default()),
            status: Self::normalize(m.status.clone().unwrap_or_default()),
            error_msg: Self::normalize(m.error_msg.clone().unwrap_or_default()),
            oper_time,
            cost_time: m.cost_time,
            tenant_id: m.tenant_id,
            target_tenant_id: m.target_tenant_id,
        }
    }
}

/// HMAC 链上下文（链密钥 + 共享态存储）。`None` = 未启用（chain_hash 恒 NULL）。
#[derive(Clone)]
struct OperChainCtx {
    store: Arc<dyn SharedStore>,
    /// 链密钥（从 JWT secret 派生，32 字节；不落盘不入日志）
    key: [u8; 32],
}

// ==================== DTO ====================

/// 操作日志分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperLogQueryDto {
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
    pub title: Option<String>,
    pub business_type: Option<i32>,
    pub oper_name: Option<String>,
    pub status: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 `params[beginTime]`）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 `params[endTime]`）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
    /// 游标（keyset 深分页）：上一页最后一条 oper_id。存在时启用深分页（PK < last_id），
    /// 不存在时沿用 pageNum/pageSize 的 OFFSET 分页，向后兼容。
    pub last_id: Option<i64>,
    /// 显式「按租户筛选」（`[ui].tenant_filter` 决定前端是否给出入口）。
    ///
    /// 服务层把它与 `tenant_scope` **相与**（AND）⇒ 只能收窄、永不放宽：
    /// 租户操作者即便手工传他租户 id，结果集也只是空集，不存在越权读面。
    pub tenant_id: Option<i64>,
}

impl From<&OperLogQueryDto> for PageDomain {
    fn from(dto: &OperLogQueryDto) -> Self {
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

/// 操作日志记录 DTO（供中间件调用）
#[derive(Debug, Clone)]
pub struct OperLogRecord {
    pub title: String,
    pub business_type: i32,
    pub method: String,
    pub request_method: String,
    pub operator_type: i32,
    pub oper_name: String,
    pub dept_name: String,
    pub oper_url: String,
    pub oper_ip: String,
    pub oper_location: String,
    pub oper_param: String,
    /// 变更前数据快照（JSON 字符串，仅 PUT/DELETE 记录）
    pub oper_before: String,
    /// 字段级变更差异（JSON 数组 [{field,old,new}]，仅 PUT 成功记录）
    pub oper_diff: String,
    pub json_result: String,
    pub status: String,
    pub error_msg: String,
    pub cost_time: i64,
    /// 操作人所属租户（多租户 Phase 2：随 JWT tid 带出；0=平台）
    pub tenant_id: i64,
    /// 被操作资源的目标租户（多租户 Phase 3）
    ///
    /// 仅当操作者租户与目标资源租户不一致（平台代管他租户资源）时由 handler 写入；
    /// 二者一致或无目标租户上下文时为 `None`（写库为 NULL）。
    pub target_tenant_id: Option<i64>,
}

// ==================== 辅助函数 ====================

// ==================== Service 实现 ====================

/// 允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖操作日志业务展示列；`oper_param` / `oper_before` / `json_result` 等大字段与
/// `tenant_id` / `target_tenant_id` 等内部列不开放动态排序。
const SORTABLE_COLUMNS: &[(&str, OperLogColumn)] = &[
    ("oper_id", OperLogColumn::OperId),
    ("title", OperLogColumn::Title),
    ("business_type", OperLogColumn::BusinessType),
    ("oper_name", OperLogColumn::OperName),
    ("operator_type", OperLogColumn::OperatorType),
    ("dept_name", OperLogColumn::DeptName),
    ("oper_ip", OperLogColumn::OperIp),
    ("status", OperLogColumn::Status),
    ("oper_time", OperLogColumn::OperTime),
    ("cost_time", OperLogColumn::CostTime),
];

/// 操作日志模块 Service
#[derive(Clone)]
pub struct SysOperLogService {
    oper_log_repo: SysOperLogRepository,
    /// HMAC 防篡改链上下文（`None` = 未启用；scheduler 等无共享态上下文的构造点保持降级）
    chain: Option<OperChainCtx>,
}

impl SysOperLogService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            oper_log_repo: SysOperLogRepository::new(db),
            chain: None,
        }
    }

    /// 构造带 HMAC 防篡改链能力的 Service（state 装配专用）
    ///
    /// `jwt_secret`：运行时 JWT 签名密钥，链密钥由其派生
    /// （HMAC-SHA256(jwt_secret, "stepby-oper-chain")），不落盘不入日志。
    pub fn with_chain(
        db: DatabaseConnection,
        store: Arc<dyn SharedStore>,
        jwt_secret: &str,
    ) -> Self {
        Self {
            oper_log_repo: SysOperLogRepository::new(db),
            chain: Some(OperChainCtx {
                store,
                key: derive_chain_key(jwt_secret),
            }),
        }
    }

    /// 分页查询操作日志
    ///
    /// 支持 title 模糊、business_type 精确、oper_name 模糊、status 精确、时间范围筛选
    pub async fn get_oper_log_page(
        &self,
        query: OperLogQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<SysOperLogModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_oper_log::Entity>(prop, SORTABLE_COLUMNS)
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

        let (rows, total) = self
            .oper_log_repo
            .find_page_filtered(
                offset,
                limit,
                query.title.as_deref(),
                query.business_type,
                query.oper_name.as_deref(),
                query.status.as_deref(),
                begin,
                end,
                query.last_id,
                tenant_scope,
                query.tenant_id,
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 导出操作日志（受 EXPORT_MAX_ROWS 限制，绕过 PageDomain 的 100 行截断）
    ///
    /// 与 `get_oper_log_page` 的差异：使用 EXPORT_MAX_ROWS 作为 limit，
    /// 而非 PageDomain.limit()（受 MAX_PAGE_SIZE=100 限制），避免静默截断。
    pub async fn export_oper_logs(
        &self,
        query: OperLogQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<SysOperLogModel>, ServiceError> {
        let page = PageDomain::from(&query);
        // 导出与页面列表同序：动态排序白名单解析口径一致
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_oper_log::Entity>(prop, SORTABLE_COLUMNS)
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

        let (rows, _) = self
            .oper_log_repo
            .find_page_filtered(
                0,
                crate::common::page::EXPORT_MAX_ROWS,
                query.title.as_deref(),
                query.business_type,
                query.oper_name.as_deref(),
                query.status.as_deref(),
                begin,
                end,
                None, // 导出固定走 OFFSET 全量路径，不走 keyset
                tenant_scope,
                query.tenant_id,
                sort,
            )
            .await?;
        Ok(rows)
    }

    /// 批量删除操作日志（物理删除）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅删除本租户（含代管目标为本租户）日志；
    /// `None`（平台）→ 不过滤。
    ///
    /// 批次十九收尾（链感知保留）：**批量删除是第三个物理删除路径**（此前漏网——
    /// e2e 批量删除用例实测制造断链 #48021）。编排：待删链行按"链行序相邻且中间
    /// 无幸存链行"切连续段，**每段一个锚点**（散段删除需多锚点：单锚点会让不同
    /// 幸存行的种子判定错配），事务内先锚点们后删除原子提交。
    pub async fn delete_oper_logs(
        &self,
        mut oper_ids: Vec<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<(), ServiceError> {
        if oper_ids.is_empty() {
            return Ok(());
        }
        oper_ids.sort_unstable();
        oper_ids.dedup();
        let db = self.base_db().clone();
        let (min_id, max_id) = (
            *oper_ids.first().expect("非空已判"),
            *oper_ids.last().expect("非空已判"),
        );

        // 待删链行与范围内全部链行（含幸存）——段切分基准
        let all_chain = self
            .oper_log_repo
            .find_chain_rows_in_range(&db, min_id, max_id)
            .await
            .map_err(|e| ServiceError::internal(&format!("链行范围查询失败: {}", e)))?;
        let id_set: std::collections::HashSet<i64> = oper_ids.iter().copied().collect();

        // 散段切分：链行序遍历，遇幸存链行即断段
        let mut segments: Vec<(i64, i64, String)> = Vec::new(); // (first, last, last_hash)
        let mut cur: Option<(i64, i64, String)> = None;
        for (oid, hash) in &all_chain {
            if id_set.contains(oid) {
                match &mut cur {
                    None => cur = Some((*oid, *oid, hash.clone())),
                    Some((_, last, last_hash)) => {
                        *last = *oid;
                        *last_hash = hash.clone();
                    }
                }
            } else if let Some(seg) = cur.take() {
                segments.push(seg);
            }
        }
        if let Some(seg) = cur {
            segments.push(seg);
        }

        // 无链行 ⇒ 删除不影响链，直接删（仍走事务保持路径一致）
        let anchor_repo = BaseRepository::<SysLogArchiveAnchor>::new(db.clone());
        let now = crate::common::datetime::now_naive();
        let tx = db
            .begin()
            .await
            .map_err(|e| ServiceError::internal(&format!("开启删除事务失败: {}", e)))?;
        for (first, last, last_hash) in &segments {
            let anchor = AnchorActiveModel {
                anchor_id: NotSet,
                first_oper_id: Set(*first),
                last_oper_id: Set(*last),
                last_chain_hash: Set(last_hash.clone()),
                deleted_count: Set(0), // 批量删除按行数统计口径无意义，置 0（锚点语义仅链行边界）
                mode: Set("manual".to_string()),
                archive_object_key: Set(None),
                deleted_at: Set(now),
            };
            anchor_repo
                .insert_conn(&tx, anchor)
                .await
                .map_err(|e| ServiceError::internal(&format!("删除锚点登记失败: {}", e)))?;
        }
        self.oper_log_repo
            .delete_by_ids_conn(&tx, &oper_ids, tenant_scope)
            .await
            .map_err(|e| ServiceError::internal(&format!("批量删除失败: {}", e)))?;
        tx.commit()
            .await
            .map_err(|e| ServiceError::internal(&format!("删除事务提交失败: {}", e)))?;
        if !segments.is_empty() {
            tracing::info!(
                segments = segments.len(),
                ids = oper_ids.len(),
                "批量删除完成（散段锚点已登记）"
            );
        }
        Ok(())
    }

    /// 清空操作日志（仅删除 N 天前的日志，保留最近 N 天用于审计）
    ///
    /// 修复 P0-R81-010：原 clean_oper_logs 物理删除全部日志，违反审计合规。
    /// 现仅删除 `days` 天前的日志，默认 30 天。
    /// 配合 handler 层 tracing::warn! 记录操作者信息。
    pub async fn clean_oper_logs(
        &self,
        days: i64,
        tenant_scope: Option<i64>,
    ) -> Result<u64, ServiceError> {
        let cutoff = crate::common::datetime::now_naive() - chrono::Duration::days(days);
        let result = self
            .oper_log_repo
            .delete_older_than(cutoff, tenant_scope)
            .await?;
        Ok(result.rows_affected)
    }

    /// 清空全部操作日志（物理删除，保留向后兼容）
    ///
    /// 注意：此方法会物理删除全部日志，仅在数据迁移/特殊维护场景使用。
    /// 推荐使用 `clean_oper_logs(days)` 进行保留期清理。
    pub async fn clean_all_oper_logs(&self) -> Result<(), ServiceError> {
        self.oper_log_repo.clean_all().await?;
        Ok(())
    }

    /// 清理 N 天前的操作日志（按 oper_time 过滤，保留最近 N 天）
    ///
    /// 供定时任务 cleanup_expired_logs 调用（P0-R81-019）。
    /// 默认保留 90 天，避免操作日志无限增长导致生产崩溃。
    ///
    /// 批次十九（链感知保留，福哥拍板）：`mode` 三档（`[sys_log].retention_mode`）——
    /// - `Keep`：显式保留档，清理空转（容量交给部署方，聚合性能由大屏时间窗兜底）；
    /// - `Delete`：删除前登记锚点（链行边界 + 被删尾行 hash），verify-chain 语义保持；
    /// - `Archive`：删除前导出被删行 JSONL 到存储后端（出厂档）+ 锚点关联对象 key。
    pub async fn cleanup_old_logs(
        &self,
        days: i64,
        mode: LogRetentionMode,
        archive_storage: Option<std::sync::Arc<dyn crate::storage::StorageBackend>>,
    ) -> Result<u64, ServiceError> {
        if mode == LogRetentionMode::Keep {
            return Ok(0);
        }
        let cutoff = crate::common::datetime::now_naive() - chrono::Duration::days(days);
        // 后台定时清理无操作人上下文，按平台视角（None）全量清理
        let cond = SysOperLogRepository::cutoff_condition(cutoff, None);
        self.register_anchor_and_delete(cond, mode, archive_storage)
            .await
    }

    /// 按显式 cutoff 清理（[`Self::cleanup_old_logs`] 的泛化形态）。
    ///
    /// 集成测试黄金路径与运维工具可直接指定时间切点；生产调度走 days 版本。
    pub async fn cleanup_before(
        &self,
        cutoff: chrono::NaiveDateTime,
        mode: LogRetentionMode,
        archive_storage: Option<std::sync::Arc<dyn crate::storage::StorageBackend>>,
    ) -> Result<u64, ServiceError> {
        if mode == LogRetentionMode::Keep {
            return Ok(0);
        }
        let cond = SysOperLogRepository::cutoff_condition(cutoff, None);
        self.register_anchor_and_delete(cond, mode, archive_storage)
            .await
    }

    /// 按时间范围清理操作日志（物理删除 `[begin, end]` 区间的日志，边界含端点）
    ///
    /// 供 `DELETE /monitor/operlog/clean?params[beginTime]=&params[endTime]=` 使用：
    /// 传入 `begin_time` / `end_time`（`%Y-%m-%d`）显式清理指定时间段的日志。
    /// 单侧不传时该侧不设边界。解析失败返回 `ServiceError::bad_request`。
    ///
    /// 批次十九：手动区间清理**同样锚点登记**（防篡改链互斥修复的另一半——手动
    /// clean 删中间段与 cleanup 删尾段一样会断链）。归档导出仅挂在 cleanup job 的
    /// Archive 档（管理员显式区间清理视为知情操作，不重复归档）。
    pub async fn clean_oper_logs_by_range(
        &self,
        begin_time: Option<String>,
        end_time: Option<String>,
        tenant_scope: Option<i64>,
    ) -> Result<u64, ServiceError> {
        let begin = match begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let cond = SysOperLogRepository::range_condition(begin, end, tenant_scope);
        self.register_anchor_and_delete(cond, LogRetentionMode::Delete, None)
            .await
    }

    /// 链感知删除编排：锚点登记 + 物理删除（同一事务原子提交）
    ///
    /// 步骤：
    /// 1. 事务外窗口统计（条件指向过去时间，无并发写入竞态）；
    /// 2. `Archive` 模式：事务外导出 JSONL（导出失败 fail-closed 中止，数据保留）；
    /// 3. 事务内：先写锚点行、后执行删除——锚点失败回滚（无锚点不可删，否则断链），
    ///    删除失败回滚（无孤儿锚点，否则 verify 会把幸存行误判为断裂）。
    ///
    /// `archive_storage`：Archive 档导出后端（scheduler 注入出厂档；`None` + Archive
    /// = 配置矛盾，fail-closed 拒绝清理）。
    async fn register_anchor_and_delete(
        &self,
        cond: sea_orm::Condition,
        mode: LogRetentionMode,
        archive_storage: Option<std::sync::Arc<dyn crate::storage::StorageBackend>>,
    ) -> Result<u64, ServiceError> {
        let db = self.oper_log_repo.base().db();
        let stats = self
            .oper_log_repo
            .delete_window_stats(db, cond.clone())
            .await
            .map_err(|e| ServiceError::internal(&format!("清理窗口统计失败: {}", e)))?;
        if stats.total_rows == 0 {
            return Ok(0);
        }

        // Archive 档导出（事务外）：需要存储后端；缺失即配置矛盾，拒绝删除
        let mut archive_key: Option<String> = None;
        if mode == LogRetentionMode::Archive {
            let storage = archive_storage.ok_or_else(|| {
                ServiceError::internal(
                    "retention_mode=archive 但清理任务未注入存储后端（配置矛盾，fail-closed）",
                )
            })?;
            archive_key = Some(self.export_archive_jsonl(&storage, &cond).await?);
        }

        let anchor_repo = BaseRepository::<SysLogArchiveAnchor>::new(db.clone());
        let tx = db
            .begin()
            .await
            .map_err(|e| ServiceError::internal(&format!("开启清理事务失败: {}", e)))?;

        // 锚点登记：仅当段内存在链行（chain_hash 非 NULL）——纯 NULL 行删除不影响链
        if let (Some(first), Some(last_id), Some(last_hash)) = (
            stats.first_chain_oper_id,
            stats.last_chain_oper_id,
            stats.last_chain_hash,
        ) {
            let anchor = AnchorActiveModel {
                anchor_id: NotSet,
                first_oper_id: Set(first),
                last_oper_id: Set(last_id),
                last_chain_hash: Set(last_hash),
                deleted_count: Set(stats.total_rows),
                mode: Set(mode.as_str().to_string()),
                archive_object_key: Set(archive_key.clone()),
                deleted_at: Set(crate::common::datetime::now_naive()),
            };
            anchor_repo
                .insert_conn(&tx, anchor)
                .await
                .map_err(|e| ServiceError::internal(&format!("清理锚点登记失败: {}", e)))?;
        }

        let result = self
            .oper_log_repo
            .delete_by_condition(&tx, cond)
            .await
            .map_err(|e| ServiceError::internal(&format!("过期日志删除失败: {}", e)))?;
        tx.commit()
            .await
            .map_err(|e| ServiceError::internal(&format!("清理事务提交失败: {}", e)))?;

        tracing::info!(
            deleted = result.rows_affected,
            mode = mode.as_str(),
            anchored = stats.first_chain_oper_id.is_some(),
            archive_key = archive_key.as_deref().unwrap_or("-"),
            "oper_log 清理完成（链感知锚点已登记）"
        );
        Ok(result.rows_affected)
    }

    /// 导出被删窗口全行为 JSONL（逐行 serde 序列化，分批查询控制内存峰值）
    ///
    /// 对象 key：`anchor_{first}_{last}_{ts}.jsonl`；单卷超 [`ARCHIVE_MAX_BYTES`]
    /// 即 fail-closed（错误上抛，清理中止，数据保留）。
    async fn export_archive_jsonl(
        &self,
        storage: &std::sync::Arc<dyn crate::storage::StorageBackend>,
        cond: &sea_orm::Condition,
    ) -> Result<String, ServiceError> {
        let mut buf: Vec<u8> = Vec::new();
        let mut first_oper_id: Option<i64> = None;
        let mut last_oper_id: Option<i64> = None;
        let mut offset: u64 = 0;
        loop {
            let rows = self
                .oper_log_repo
                .fetch_archive_batch(
                    self.oper_log_repo.base().db(),
                    cond.clone(),
                    offset,
                    ARCHIVE_BATCH_ROWS,
                )
                .await
                .map_err(|e| ServiceError::internal(&format!("归档导出读取失败: {}", e)))?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                if first_oper_id.is_none() {
                    first_oper_id = Some(row.oper_id);
                }
                last_oper_id = Some(row.oper_id);
                serde_json::to_writer(&mut buf, row)
                    .map_err(|e| ServiceError::internal(&format!("归档序列化失败: {}", e)))?;
                buf.push(b'\n');
            }
            offset += rows.len() as u64;
            if buf.len() > ARCHIVE_MAX_BYTES {
                return Err(ServiceError::internal(
                    "待归档数据超出单卷上限（512MB），清理已中止（fail-closed，数据保留）",
                ));
            }
            if (rows.len() as u64) < ARCHIVE_BATCH_ROWS {
                break;
            }
        }
        let (first, last) = (
            first_oper_id.ok_or_else(|| ServiceError::internal("归档窗口为空"))?,
            last_oper_id.unwrap_or_default(),
        );
        let key = format!(
            "anchor_{first}_{last}_{}.jsonl",
            chrono::Local::now().format("%Y%m%d%H%M%S")
        );
        storage
            .save(ARCHIVE_STORAGE_DIR, 0, &key, "", &buf)
            .await
            .map_err(|e| ServiceError::internal(&format!("归档对象写入失败: {}", e)))?;
        Ok(key)
    }

    /// 归档锚点分页列表（批次十九收尾：归档下载 UI 的数据源，平台专属）
    ///
    /// 返回 (锚点行, 总数)；按 anchor_id 倒序（最新清理在前）。
    pub async fn list_archive_anchors(
        &self,
        page_num: u64,
        page_size: u64,
    ) -> Result<(Vec<crate::entity::sys_log_archive_anchor::Model>, u64), ServiceError> {
        let page_size = page_size.clamp(1, 100);
        let page_num = page_num.max(1);
        let selector = SysLogArchiveAnchor::find()
            .order_by_desc(crate::entity::sys_log_archive_anchor::Column::AnchorId);
        let total = selector
            .clone()
            .count(self.base_db())
            .await
            .map_err(|e| ServiceError::internal(&format!("锚点计数失败: {}", e)))?;
        let rows = selector
            .offset((page_num - 1) * page_size)
            .limit(page_size)
            .all(self.base_db())
            .await
            .map_err(|e| ServiceError::internal(&format!("锚点查询失败: {}", e)))?;
        Ok((rows, total))
    }

    /// 归档对象读取（平台专属下载端点后端，字节流）
    pub async fn read_archive_object(
        &self,
        anchor_id: i64,
        storage: &std::sync::Arc<dyn crate::storage::StorageBackend>,
    ) -> Result<(String, Vec<u8>), ServiceError> {
        let anchor_repo = BaseRepository::<SysLogArchiveAnchor>::new(self.base_db().clone());
        let anchor = anchor_repo
            .find_by_id(anchor_id)
            .await
            .map_err(|e| ServiceError::internal(&format!("锚点查询失败: {}", e)))?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.oper_log.anchor_not_found"))
            })?;
        let key = anchor.archive_object_key.ok_or_else(|| {
            ServiceError::bad_request(&crate::tr!("error.oper_log.archive_not_ready"))
        })?;
        let bytes = storage
            .read(ARCHIVE_STORAGE_DIR, 0, &key)
            .await
            .map_err(|e| ServiceError::internal(&format!("归档对象读取失败: {}", e)))?
            .ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.oper_log.archive_object_missing"))
            })?;
        Ok((key, bytes))
    }

    fn base_db(&self) -> &sea_orm::DatabaseConnection {
        self.oper_log_repo.base().db()
    }

    /// 审计大屏统计：按业务类型聚合
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅统计本租户；平台 → `None` 全量。
    /// `window_start`：统计窗口下界（None = 全历史）——大屏链路统一传窗口，见
    /// `get_audit_stats`；仪表盘 stats-by-type 链路保持全历史。
    pub async fn stats_by_business_type(
        &self,
        tenant_scope: Option<i64>,
        window_start: Option<chrono::NaiveDateTime>,
    ) -> Result<Vec<AuditBusinessTypeStat>, ServiceError> {
        let rows = self
            .oper_log_repo
            .stats_by_business_type(tenant_scope, window_start)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(bt, cnt)| AuditBusinessTypeStat {
                business_type: bt.unwrap_or(0),
                count: cnt,
            })
            .collect())
    }

    /// 操作日志业务类型分布（仪表盘饼图专用聚合接口，G5）
    ///
    /// 直接基于库内全量 GROUP BY business_type 聚合，替代前端拉取 pageSize=1000
    /// 全量明细后再在客户端分组的低效做法。
    /// 业务类型编码对齐既有约定：1=新增(insert) 2=修改(update) 3=删除(delete) 0/其他=其他(other)。
    pub async fn oper_log_type_stats(
        &self,
        tenant_scope: Option<i64>,
    ) -> Result<OperLogTypeStatsVo, ServiceError> {
        let rows = self
            .oper_log_repo
            .stats_by_business_type(tenant_scope, None)
            .await?;
        let mut vo = OperLogTypeStatsVo {
            insert: 0,
            update: 0,
            delete: 0,
            other: 0,
        };
        for (bt, cnt) in rows {
            match bt.unwrap_or(0) {
                1 => vo.insert += cnt,
                2 => vo.update += cnt,
                3 => vo.delete += cnt,
                _ => vo.other += cnt,
            }
        }
        Ok(vo)
    }

    /// 审计大屏统计：操作人 Top N
    pub async fn stats_top_operators(
        &self,
        limit: u64,
        tenant_scope: Option<i64>,
        window_start: Option<chrono::NaiveDateTime>,
    ) -> Result<Vec<AuditOperatorStat>, ServiceError> {
        let rows = self
            .oper_log_repo
            .stats_top_operators(limit, tenant_scope, window_start)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(name, cnt)| AuditOperatorStat {
                oper_name: name,
                count: cnt,
            })
            .collect())
    }

    /// 审计大屏统计：操作模块（title）Top N
    ///
    /// title 可能是中文原文或 i18n key（module.*），这里统一经 module_title() 翻译后返回，
    /// 保证前端展示为可读模块名。
    pub async fn stats_top_modules(
        &self,
        limit: u64,
        tenant_scope: Option<i64>,
        window_start: Option<chrono::NaiveDateTime>,
    ) -> Result<Vec<AuditModuleStat>, ServiceError> {
        let rows = self
            .oper_log_repo
            .stats_top_modules(limit, tenant_scope, window_start)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(name, cnt)| AuditModuleStat {
                module_name: crate::common::i18n::module_title(&name).into_owned(),
                count: cnt,
            })
            .collect())
    }

    /// 异常操作告警状态检测
    ///
    /// 在一个时间窗口内，检测：
    /// - 失败率是否超过 `fail_rate_threshold`（百分比）
    /// - 是否有操作人失败 Burst >= `fail_threshold`
    /// - 是否有模块失败 Burst >= `fail_threshold`
    ///
    /// 任一命中即 `alert_triggered = true`，供前端展示告警横幅。
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅统计本租户；平台 → `None` 全量。
    pub async fn get_alarm_status(
        &self,
        window_minutes: i64,
        fail_threshold: i64,
        fail_rate_threshold: i64,
        tenant_scope: Option<i64>,
    ) -> Result<AlarmStatusVo, ServiceError> {
        let (total, fail) = self
            .oper_log_repo
            .failure_stats_in_window(window_minutes, tenant_scope)
            .await?;
        let (fail_rate, fail_rate_alarm) = eval_fail_rate(total, fail, fail_rate_threshold);

        let operator_bursts: Vec<AlarmItem> = self
            .oper_log_repo
            .failure_burst_operators(window_minutes, fail_threshold, tenant_scope)
            .await?
            .into_iter()
            .map(|(name, cnt)| AlarmItem { name, count: cnt })
            .collect();

        let module_bursts: Vec<AlarmItem> = self
            .oper_log_repo
            .failure_burst_modules(window_minutes, fail_threshold, tenant_scope)
            .await?
            .into_iter()
            .map(|(name, cnt)| AlarmItem {
                name: crate::common::i18n::module_title(&name).into_owned(),
                count: cnt,
            })
            .collect();

        let alert_triggered =
            fail_rate_alarm || !operator_bursts.is_empty() || !module_bursts.is_empty();

        Ok(AlarmStatusVo {
            config: AlarmConfig {
                window_minutes,
                fail_threshold,
                fail_rate_threshold,
            },
            total_in_window: total,
            fail_in_window: fail,
            fail_rate: (fail_rate * 100.0).round() / 100.0,
            fail_rate_alarm,
            operator_bursts,
            module_bursts,
            alert_triggered,
        })
    }

    /// 审计大屏统计：最近 N 天每日成功/失败
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅统计本租户；平台 → `None` 全量。
    pub async fn stats_daily(
        &self,
        days: i64,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<AuditDailyStat>, ServiceError> {
        let rows = self.oper_log_repo.stats_daily(days, tenant_scope).await?;
        Ok(rows
            .into_iter()
            .map(|(date, success, fail)| AuditDailyStat {
                date,
                success,
                fail,
            })
            .collect())
    }

    /// 审计大屏统计：汇总数据
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅统计本租户；平台 → `None` 全量。
    /// `window_start`：统计窗口下界（None = 全历史）。
    pub async fn stats_summary(
        &self,
        tenant_scope: Option<i64>,
        window_start: Option<chrono::NaiveDateTime>,
    ) -> Result<AuditSummary, ServiceError> {
        let (total, success, fail) = self
            .oper_log_repo
            .stats_summary(tenant_scope, window_start)
            .await?;
        Ok(AuditSummary {
            total,
            success,
            fail,
        })
    }

    /// 统计窗口起点（与 repository stats_daily 的公式严格一致）：
    /// today - (days-1) 的 0 点，保证 summary/分布/Top 与 daily 覆盖同一日期区间
    fn stats_window_start(days: i64) -> chrono::NaiveDateTime {
        let today = crate::common::datetime::today_utc();
        (today - chrono::Duration::days(days - 1)).and_time(chrono::NaiveTime::MIN)
    }

    /// 综合审计统计（一次性返回所有大屏数据）
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅统计本租户；平台 → `None` 全量。
    ///
    /// 批次十九 P2（福哥拍板）：summary / 业务类型分布 / Top 操作人 / Top 模块统一
    /// 加 `days` 时间窗（与前端大屏 7/14/30 选择器同源），聚合数据量从"全表"收敛
    /// 到"窗口内"——保留期（`[sys_log].retention_days`）封顶总量后，窗口进一步把
    /// 聚合复杂度与窗口数据量挂钩，不再随保留窗总量线性上升。窗口起点公式与
    /// `stats_daily` 严格一致（today - (days-1) 的 0 点）。
    pub async fn get_audit_stats(
        &self,
        days: i64,
        tenant_scope: Option<i64>,
    ) -> Result<AuditStatsVo, ServiceError> {
        let window_start = Self::stats_window_start(days);
        // 批次十八性能修复：五路聚合查询并行化（原串行 sum → 并行 max）。
        // oper_log 随 e2e/生产持续增长（SQLite GROUP BY 全表扫 + 临时 B-tree），
        // 串行总耗时线性恶化并打破审计大屏 e2e 的 networkidle 窗口（F4 偶发 30s
        // goto 超时实证）；五查询相互独立，tokio::join! 语义不变。
        let (summary, business_types, top_operators, top_modules, daily) = tokio::join!(
            self.stats_summary(tenant_scope, Some(window_start)),
            self.stats_by_business_type(tenant_scope, Some(window_start)),
            self.stats_top_operators(10, tenant_scope, Some(window_start)),
            self.stats_top_modules(10, tenant_scope, Some(window_start)),
            self.stats_daily(days, tenant_scope),
        );
        Ok(AuditStatsVo {
            summary: summary?,
            business_types: business_types?,
            top_operators: top_operators?,
            top_modules: top_modules?,
            daily: daily?,
        })
    }

    /// 审计合规报告（比 stats 更详细，包含异常事件列表）
    ///
    /// 用于前端"导出合规报告 PDF"功能，一次性返回报告所需的全部数据：
    /// - summary：操作总数 / 成功 / 失败汇总
    /// - business_types：业务类型分布
    /// - top_operators：Top 10 活跃用户
    /// - daily：最近 N 天每日趋势
    /// - anomalies：最近 50 条异常操作（status=1 失败的写操作）
    /// - generated_at / period_from / period_to：报告周期元数据
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅统计本租户；平台 → `None` 全量。
    ///
    /// 批次十九：报告口径与审计大屏同步窗口化——原来 summary 全历史 / daily 窗口
    /// 的割裂口径统一为 days 窗口（报告周期语义本就是窗口）。
    pub async fn get_compliance_report(
        &self,
        days: i64,
        tenant_scope: Option<i64>,
    ) -> Result<ComplianceReportVo, ServiceError> {
        let window_start = Self::stats_window_start(days);
        let summary = self.stats_summary(tenant_scope, Some(window_start)).await?;
        let business_types = self
            .stats_by_business_type(tenant_scope, Some(window_start))
            .await?;
        let top_operators = self
            .stats_top_operators(10, tenant_scope, Some(window_start))
            .await?;
        let top_modules = self
            .stats_top_modules(10, tenant_scope, Some(window_start))
            .await?;
        let daily = self.stats_daily(days, tenant_scope).await?;
        let anomaly_models = self
            .oper_log_repo
            .find_recent_anomalies(50, tenant_scope)
            .await?;
        let anomalies = anomaly_models
            .into_iter()
            .map(|m| OperLogAnomaly {
                oper_id: m.oper_id,
                // 与 stats_top_modules / xlsx 导出一致：module.* 键翻成中文，避免报告露裸键
                title: anomaly_display_title(m.title.as_deref()),
                oper_name: m.oper_name.unwrap_or_default(),
                oper_url: m.oper_url.unwrap_or_default(),
                oper_ip: m.oper_ip.unwrap_or_default(),
                error_msg: m.error_msg.unwrap_or_default(),
                oper_time: m
                    .oper_time
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default(),
            })
            .collect();

        let now = chrono::Local::now();
        let period_to = now.format("%Y-%m-%d 23:59:59").to_string();
        let period_from = (now - chrono::Duration::days(days))
            .format("%Y-%m-%d 00:00:00")
            .to_string();

        Ok(ComplianceReportVo {
            summary,
            business_types,
            top_operators,
            top_modules,
            daily,
            anomalies,
            generated_at: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            period_from,
            period_to,
        })
    }

    /// 记录操作日志（供中间件调用）
    ///
    /// 异步写入不阻断主流程，写入失败仅记日志不返回错误。
    /// 此方法为独立接口，中间件可选择调用。
    ///
    /// 修复 P0-R81-011 / R5-RATE-29：写入复用共享的有界重试助手
    /// （`utils::retry`，3 次尝试 / 100ms 间隔）；重试仍失败时记 `tracing::error!`，
    /// 并携带 oper_url / request_method / oper_name，避免审计记录从日志流中凭空消失。
    ///
    /// 防篡改链：启用链能力时（[`Self::with_chain`]），写入成功后在
    /// `lock:oper_chain` 互斥锁内计算链哈希并回写（insert → 查前驱 → HMAC → UPDATE）；
    /// 锁抢占重试耗尽或共享态后端异常时降级——本条 chain_hash 留 NULL，
    /// 后续日志在前一条非 NULL 节点上续链，校验端对称跳过 NULL 行。
    pub async fn record_oper_log(&self, record: OperLogRecord) {
        // 重试耗尽后的 error 日志需要能定位到具体请求，故在字段被 move 进 ActiveModel 前留副本
        let oper_url = record.oper_url.clone();
        let request_method = record.request_method.clone();
        let oper_name = record.oper_name.clone();

        let now = crate::common::datetime::now_naive();
        // 链负载必须在 record 被 move 进 ActiveModel 之前构造
        // （oper_time 用与写库完全相同的 now 值格式化，保证校验端重算一致）
        let chain_ctx = self.chain.clone();
        let chain_payload = chain_ctx.as_ref().map(|_| {
            ChainPayload::from_parts(&record, &now.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
        });

        let am = SysOperLogActiveModel {
            title: Set(Some(record.title)),
            business_type: Set(Some(record.business_type)),
            method: Set(Some(record.method)),
            request_method: Set(Some(record.request_method)),
            operator_type: Set(Some(record.operator_type)),
            oper_name: Set(Some(record.oper_name)),
            dept_name: Set(Some(record.dept_name)),
            oper_url: Set(Some(record.oper_url)),
            oper_ip: Set(Some(record.oper_ip)),
            oper_location: Set(Some(record.oper_location)),
            oper_param: Set(Some(record.oper_param)),
            oper_before: Set(if record.oper_before.is_empty() {
                None
            } else {
                Some(record.oper_before.clone())
            }),
            oper_diff: Set(if record.oper_diff.is_empty() {
                None
            } else {
                Some(record.oper_diff.clone())
            }),
            json_result: Set(Some(record.json_result)),
            status: Set(Some(record.status)),
            error_msg: Set(if record.error_msg.is_empty() {
                None
            } else {
                Some(record.error_msg)
            }),
            oper_time: Set(Some(now)),
            cost_time: Set(Some(record.cost_time)),
            tenant_id: Set(record.tenant_id),
            target_tenant_id: Set(record.target_tenant_id),
            ..Default::default()
        };

        // 有界重试：最多 OPER_LOG_WRITE_RETRY.max_attempts 次尝试，间隔 OPER_LOG_WRITE_RETRY.interval。
        // 闭包内自行 clone 数据库连接与 ActiveModel，构造所有权自足的 future，
        // 使重试观察不到借用关系（避免 `FnMut() -> Fut` 的借用生命周期问题）。
        let db = self.oper_log_repo.base().db().clone();
        let inserted = retry_async(OPER_LOG_WRITE_RETRY, || {
            let db = db.clone();
            let am = am.clone();
            async move { SysOperLogRepository::new(db).insert(am).await }
        })
        .await;

        match inserted {
            Ok(model) => {
                // 防篡改链：写入成功后计算并回写链哈希（失败仅告警降级，不阻断日志已落库的事实）
                if let (Some(ctx), Some(payload)) = (&chain_ctx, chain_payload)
                    && let Err(e) = self.attach_chain_hash(ctx, model.oper_id, &payload).await
                {
                    tracing::warn!(
                        oper_id = model.oper_id,
                        "操作日志链哈希计算失败（本条降级为 NULL，链将在后续非 NULL 节点续写）: {}",
                        e
                    );
                }
            }
            Err(e) => {
                // 重试耗尽：记录错误日志，携带可定位信息（无法再恢复）
                tracing::error!(
                    oper_url = %oper_url,
                    request_method = %request_method,
                    oper_name = %oper_name,
                    "操作日志写入失败（已尝试 {} 次，放弃）: {}",
                    OPER_LOG_WRITE_RETRY.max_attempts,
                    e
                );
            }
        }
    }

    /// 在互斥锁内计算并回写链哈希（锁：SharedStore SETNX `lock:oper_chain`）
    ///
    /// 流程：SETNX 抢锁（300ms 间隔 × 3 次）→ 查前驱非 NULL chain_hash →
    /// HMAC-SHA256(prev | oper_id | payload_hash) → UPDATE 回写 → 释放锁。
    /// 抢锁失败返回 `Ok(None)`（降级 NULL）；DB 错误向上传播由调用方告警。
    async fn attach_chain_hash(
        &self,
        ctx: &OperChainCtx,
        oper_id: i64,
        payload: &ChainPayload,
    ) -> Result<Option<String>, sea_orm::DbErr> {
        // 抢锁：SETNX + TTL 兜底（持有者崩溃后由 TTL 释放，正常路径毫秒级完成）
        let mut handle = None;
        for _ in 0..OPER_CHAIN_LOCK_ATTEMPTS {
            match ctx
                .store
                .lock_acquire(OPER_CHAIN_LOCK_KEY, OPER_CHAIN_LOCK_TTL_SECS)
                .await
            {
                Ok(Some(h)) => {
                    handle = Some(h);
                    break;
                }
                Ok(None) => {
                    // 锁被其他写入方持有：等待后重试
                    tokio::time::sleep(Duration::from_millis(OPER_CHAIN_LOCK_WAIT_MS)).await;
                }
                Err(e) => {
                    // 共享态后端异常：放弃抢锁（本条降级 NULL，不因链而丢日志）
                    tracing::warn!("链锁抢占异常（降级 NULL）: {}", e);
                    return Ok(None);
                }
            }
        }
        let Some(handle) = handle else {
            // 重试耗尽：降级 NULL（链在后续非 NULL 节点续写，校验端跳过 NULL 行）
            tracing::warn!(
                oper_id,
                "链锁抢占重试耗尽（{} 次 × {}ms），本条降级为 NULL",
                OPER_CHAIN_LOCK_ATTEMPTS,
                OPER_CHAIN_LOCK_WAIT_MS
            );
            return Ok(None);
        };

        // 乱序守卫：更大 oper_id 已抢先写链 → 本条再挂链将与该节点共享前驱
        // （分支链），verify 按 id 升序重算会误报篡改。降级 NULL，链在非 NULL
        // 子序列上续写（与锁抢占耗尽的降级语义一致）。锁保证互斥但不保证写入
        // 顺序与 oper_id 同序，此处补齐顺序约束。
        if self.oper_log_repo.exists_later_chained(oper_id).await? {
            tracing::warn!(
                oper_id,
                "链写入乱序（更大 oper_id 已抢先写链），本条降级为 NULL"
            );
            if let Err(e) = ctx.store.lock_release(&handle).await {
                tracing::warn!(
                    "链锁释放失败（等待 TTL {}s 自动过期）: {}",
                    OPER_CHAIN_LOCK_TTL_SECS,
                    e
                );
            }
            return Ok(None);
        }

        // 锁内：查前驱 → 计算 → 回写
        let prev = self
            .oper_log_repo
            .find_prev_chain_hash(oper_id)
            .await?
            .unwrap_or_default();
        let payload_hash = payload_hex_digest(payload);
        let chain_hash = compute_chain_hash(&ctx.key, &prev, oper_id, &payload_hash);
        self.oper_log_repo
            .set_chain_hash(oper_id, &chain_hash)
            .await?;

        // 释放锁（CAS；释放失败仅由 TTL 兜底，不影响链正确性——锁已护住读改写窗口）
        if let Err(e) = ctx.store.lock_release(&handle).await {
            tracing::warn!(
                "链锁释放失败（等待 TTL {}s 自动过期）: {}",
                OPER_CHAIN_LOCK_TTL_SECS,
                e
            );
        }
        Ok(Some(chain_hash))
    }

    /// 校验操作日志防篡改链完整性（全量，跨租户）
    ///
    /// 链哈希跨租户串联，任何子集校验都会因缺失前驱而误报断裂，故固定全量执行。
    /// 从链首（prev 为空串）起逐条重算 HMAC 并与库内 chain_hash 比对：
    /// - 全部匹配：`valid = true`，`checked` = 参与校验的节点数；
    /// - 首个不匹配：`valid = false`，`broken_at_oper_id` = 该节点 oper_id，立即终止。
    ///
    /// 未启用链能力（[`Self::new`] 构造）时返回 400——无链密钥无法重算 HMAC。
    pub async fn verify_chain(&self) -> Result<ChainVerifyVo, ServiceError> {
        let Some(ctx) = &self.chain else {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.oper_log.chain_disabled"
            )));
        };

        let rows = self
            .oper_log_repo
            .find_chained_ascending()
            .await
            .map_err(|e| ServiceError::internal(&format!("读取操作日志链失败: {}", e)))?;

        // 批次十九：锚点快照（链感知保留）——verify 从"链首起验"升级为
        // "锚点链 + 幸存链整体重算"。被物理删除的区间（cleanup / 手动 clean）
        // 由锚点登记被删尾行 hash；判定规则见 oper_log_chain_seed 模块文档。
        let anchor_repo = BaseRepository::<SysLogArchiveAnchor>::new(self.base_db().clone());
        let anchor_rows = anchor_repo
            .find_many(
                SysLogArchiveAnchor::find()
                    .order_by_asc(crate::entity::sys_log_archive_anchor::Column::AnchorId),
            )
            .await
            .map_err(|e| ServiceError::internal(&format!("读取清理锚点失败: {}", e)))?;
        let anchors: Vec<ChainAnchorSnapshot> = anchor_rows
            .into_iter()
            .map(|a| ChainAnchorSnapshot {
                first_oper_id: a.first_oper_id,
                last_oper_id: a.last_oper_id,
                last_chain_hash: a.last_chain_hash,
                deleted_at: a.deleted_at,
            })
            .collect();
        let gap_count = anchors.len() as i64;

        let mut prev = String::from(GENESIS_SEED);
        let mut prev_oper_id: Option<i64> = None;
        for m in &rows {
            let Some(stored) = m.chain_hash.as_deref() else {
                // 查询已过滤 NULL，理论不可达；防御性跳过
                continue;
            };
            // 种子判定：当前行真实前驱 = 幸存前驱行（Carry）或被删尾行（Anchor）
            let seed_str: String = match resolve_prev_seed(
                prev_oper_id,
                m.oper_id,
                // oper_time 理论必有；缺失时按"删除前已存在"处理（保守方向：误报
                // broken 而非漏报篡改）
                m.oper_time.unwrap_or(chrono::NaiveDateTime::MIN),
                &anchors,
            ) {
                PrevSeed::Carry => prev.clone(),
                PrevSeed::Anchor(h) => h,
            };
            let payload = ChainPayload::from_model(m);
            let payload_hash = payload_hex_digest(&payload);
            let expected = compute_chain_hash(&ctx.key, &seed_str, m.oper_id, &payload_hash);
            if expected != stored {
                return Ok(ChainVerifyVo {
                    checked: rows.len() as i64,
                    broken_at_oper_id: Some(m.oper_id),
                    gap_count,
                    valid: false,
                });
            }
            prev = stored.to_string();
            prev_oper_id = Some(m.oper_id);
        }
        Ok(ChainVerifyVo {
            checked: rows.len() as i64,
            broken_at_oper_id: None,
            gap_count,
            valid: true,
        })
    }
}

// ==================== 审计大屏 VO ====================

/// 操作日志防篡改链校验响应
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChainVerifyVo {
    /// 参与校验的链节点数（chain_hash 非 NULL 的日志条数）
    pub checked: i64,
    /// 首个校验失败节点的 oper_id（`valid = true` 时为 null）
    pub broken_at_oper_id: Option<i64>,
    /// 清理缺口段数（= 锚点行数；批次十九链感知保留——这些区间已被物理删除，
    /// 由锚点登记的被删尾行 hash 续接校验，不影响 valid 判定）
    pub gap_count: i64,
    /// 链是否完整（`valid = true` 且 `gap_count > 0` = 存在清理缺口但校验通过）
    pub valid: bool,
}

/// 审计大屏综合统计响应
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditStatsVo {
    pub summary: AuditSummary,
    pub business_types: Vec<AuditBusinessTypeStat>,
    pub top_operators: Vec<AuditOperatorStat>,
    pub top_modules: Vec<AuditModuleStat>,
    pub daily: Vec<AuditDailyStat>,
}

/// 审计汇总
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditSummary {
    pub total: i64,
    pub success: i64,
    pub fail: i64,
}

/// 业务类型统计项
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditBusinessTypeStat {
    pub business_type: i32,
    pub count: i64,
}

/// 操作日志业务类型分布（仪表盘饼图用，G5）
///
/// 直接返回 insert/update/delete/other 四桶计数，避免前端拉取全量明细再分组。
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperLogTypeStatsVo {
    pub insert: i64,
    pub update: i64,
    pub delete: i64,
    pub other: i64,
}

/// 操作人统计项
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditOperatorStat {
    pub oper_name: String,
    pub count: i64,
}

/// 操作模块统计项
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditModuleStat {
    pub module_name: String,
    pub count: i64,
}

/// 异常操作告警状态响应
///
/// 为一个时间窗口内的操作失败行为做聚合告警判定，供审计大屏展示告警横幅。
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlarmStatusVo {
    /// 告警判定使用的阈值配置（取自参数，回退系统配置默认值）
    pub config: AlarmConfig,
    /// 窗口内操作总数
    pub total_in_window: i64,
    /// 窗口内失败操作数
    pub fail_in_window: i64,
    /// 窗口内失败率（百分比，保留两位小数）
    pub fail_rate: f64,
    /// 失败率是否超过阈值
    pub fail_rate_alarm: bool,
    /// 失败 Burst 的操作人（次数 >= fail_threshold）
    pub operator_bursts: Vec<AlarmItem>,
    /// 失败 Burst 的模块（次数 >= fail_threshold）
    pub module_bursts: Vec<AlarmItem>,
    /// 是否触发告警（失败率超阈值或存在任一 Burst）
    pub alert_triggered: bool,
}

/// 告警判定阈值配置
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlarmConfig {
    /// 时间窗口（分钟）
    pub window_minutes: i64,
    /// 同一对象失败次数阈值
    pub fail_threshold: i64,
    /// 失败率（百分比）阈值
    pub fail_rate_threshold: i64,
}

/// 告警聚合项（操作人 / 模块失败 Burst）
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlarmItem {
    /// 对象名（操作人 / 模块名）
    pub name: String,
    /// 窗口内失败次数
    pub count: i64,
}

/// 每日统计项
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditDailyStat {
    pub date: String,
    pub success: i64,
    pub fail: i64,
}

// ==================== 审计合规报告 VO ====================

/// 审计合规报告响应（比 AuditStatsVo 更详细，包含异常事件列表与报告周期元数据）
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReportVo {
    pub summary: AuditSummary,
    pub business_types: Vec<AuditBusinessTypeStat>,
    pub top_operators: Vec<AuditOperatorStat>,
    pub top_modules: Vec<AuditModuleStat>,
    pub daily: Vec<AuditDailyStat>,
    /// 异常事件列表（失败的写操作，最近 50 条）
    pub anomalies: Vec<OperLogAnomaly>,
    /// 报告生成时间（本地时间，%Y-%m-%d %H:%M:%S）
    pub generated_at: String,
    /// 报告周期开始（%Y-%m-%d 00:00:00）
    pub period_from: String,
    /// 报告周期结束（%Y-%m-%d 23:59:59）
    pub period_to: String,
}

/// 异常操作日志项（用于合规报告 anomalies 列表）
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperLogAnomaly {
    pub oper_id: i64,
    pub title: String,
    pub oper_name: String,
    pub oper_url: String,
    pub oper_ip: String,
    pub error_msg: String,
    pub oper_time: String,
}

/// 计算时间窗口内失败率（百分比，保留两位小数）并判定是否触发失败率告警
///
/// - `total == 0` 视为失败率 0，不触发告警（避免除零）
/// - 告警判定基于原始失败率（未取整），避免取整导致阈值跨界误判；
///   返回的展示失败率则保留两位小数，供审计大屏显示。
pub(crate) fn eval_fail_rate(total: i64, fail: i64, threshold: i64) -> (f64, bool) {
    let raw = if total > 0 {
        (fail as f64) / (total as f64) * 100.0
    } else {
        0.0
    };
    let rounded = (raw * 100.0).round() / 100.0;
    (rounded, raw >= threshold as f64)
}

/// 合规报告 anomalies 的模块标题展示：T-11 新数据存 i18n key（module.*）须翻译，
/// 历史中文原文经 `module_title` 回退原样返回，报告/PDF 永不露裸键。
fn anomaly_display_title(raw: Option<&str>) -> String {
    crate::common::i18n::module_title(raw.unwrap_or_default()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        ChainPayload, OperLogRecord, compute_chain_hash, derive_chain_key, payload_hex_digest,
    };
    use super::{anomaly_display_title, eval_fail_rate};

    /// 构造一条最小可用的 OperLogRecord（空串字段走「空串 → None」归一化路径）
    fn sample_record() -> OperLogRecord {
        OperLogRecord {
            title: "module.user".into(),
            business_type: 2,
            method: "/system/user".into(),
            request_method: "PUT".into(),
            operator_type: 1,
            oper_name: "admin".into(),
            dept_name: String::new(),
            oper_url: "/system/user".into(),
            oper_ip: "127.0.0.1".into(),
            oper_location: String::new(),
            oper_param: String::new(),
            oper_before: String::new(),
            oper_diff: String::new(),
            json_result: "{}".into(),
            status: "0".into(),
            error_msg: String::new(),
            cost_time: 12,
            tenant_id: 0,
            target_tenant_id: None,
        }
    }

    #[test]
    fn derive_chain_key_is_deterministic_and_secret_dependent() {
        let a = derive_chain_key("secret-A");
        let a2 = derive_chain_key("secret-A");
        let b = derive_chain_key("secret-B");
        assert_eq!(a, a2, "同一 secret 派生结果必须一致");
        assert_ne!(a, b, "不同 secret 派生结果必须不同");
    }

    #[test]
    fn chain_hash_changes_with_prev_and_payload() {
        let key = derive_chain_key("test-secret");
        let rec = sample_record();
        let p1 = ChainPayload::from_parts(&rec, "2026-10-03 10:00:00.000000");
        let p2 = ChainPayload::from_parts(&rec, "2026-10-03 10:00:01.000000");
        let h1 = payload_hex_digest(&p1);
        let h1b = payload_hex_digest(&p1);
        assert_eq!(h1, h1b, "同一负载指纹必须确定");

        let c1 = compute_chain_hash(&key, "", 1, &h1);
        let c1b = compute_chain_hash(&key, "", 1, &h1);
        let c2 = compute_chain_hash(&key, &c1, 2, &h1);
        let c3 = compute_chain_hash(&key, "", 1, &payload_hex_digest(&p2));
        assert_eq!(c1, c1b, "同输入链哈希必须确定");
        assert_ne!(c1, c2, "前驱变化必须改变链哈希");
        assert_ne!(c1, c3, "负载变化必须改变链哈希");
        assert_eq!(c1.len(), 64, "HMAC-SHA256 hex 输出 64 字符");
    }

    #[test]
    fn payload_normalization_aligns_write_and_read_paths() {
        // 写入端 from_parts（空串→None）与读取端 from_model（Some("")→None 同款归一化）
        // 的序列化结果必须逐字节一致：写入端与写库 empty→None 口径对齐，
        // 读取端对历史遗留的库内空串行做同款归一化，两端负载才能逐字节可复算。
        let mut rec = sample_record();
        rec.dept_name = "研发部".into();
        rec.oper_param = r#"{"id":1}"#.into();
        let write_side = ChainPayload::from_parts(&rec, "2026-10-03 10:00:00.123456");

        // 手工构造"读回 Model"等价负载：None 字段与归一化后一致
        let mut m = crate::entity::sys_oper_log::Model {
            tenant_id: 0,
            target_tenant_id: None,
            oper_id: 1,
            title: Some(rec.title.clone()),
            business_type: Some(rec.business_type),
            method: Some(rec.method.clone()),
            request_method: Some(rec.request_method.clone()),
            operator_type: Some(rec.operator_type),
            oper_name: Some(rec.oper_name.clone()),
            dept_name: Some(rec.dept_name.clone()),
            oper_url: Some(rec.oper_url.clone()),
            oper_ip: Some(rec.oper_ip.clone()),
            oper_location: Some(rec.oper_location.clone()),
            oper_param: Some(rec.oper_param.clone()),
            oper_before: None,
            oper_diff: None,
            json_result: Some(rec.json_result.clone()),
            status: Some(rec.status.clone()),
            error_msg: None,
            oper_time: Some(
                chrono::NaiveDateTime::parse_from_str(
                    "2026-10-03 10:00:00.123456",
                    "%Y-%m-%d %H:%M:%S%.6f",
                )
                .unwrap(),
            ),
            cost_time: Some(rec.cost_time),
            chain_hash: None,
        };
        let read_side = ChainPayload::from_model(&m);
        assert_eq!(
            serde_json::to_string(&write_side).unwrap(),
            serde_json::to_string(&read_side).unwrap(),
            "写读两端负载必须逐字节一致"
        );

        // 空串字段：写入端归一化为 None；库内写的就是 NULL，读回也是 None，两端一致
        let read_empty = ChainPayload::from_model(&m);
        assert_eq!(read_empty.dept_name, Some("研发部".into()));
        // 反向验证：历史行 oper_param = Some("")（写库归一化生效前的遗留数据）
        // → 读取端同款归一化为 None，与「写入端空串归一化为 None → 库存 NULL」
        // 的等价行负载逐字节一致
        m.oper_param = Some(String::new());
        let read_side2 = ChainPayload::from_model(&m);
        assert_eq!(
            read_side2.oper_param, None,
            "历史行空串 oper_param 应归一化为 None"
        );
        let mut rec2 = rec.clone();
        rec2.oper_param = String::new();
        let write_side2 = ChainPayload::from_parts(&rec2, "2026-10-03 10:00:00.123456");
        assert_eq!(
            serde_json::to_string(&write_side2).unwrap(),
            serde_json::to_string(&read_side2).unwrap(),
            "空串归一化后写读两端必须一致"
        );
    }

    #[test]
    fn record_normalizes_empty_to_none() {
        let rec = sample_record();
        let p = ChainPayload::from_parts(&rec, "2026-10-03 10:00:00.000000");
        assert_eq!(p.dept_name, None, "空串 dept_name 必须归一化为 None");
        assert_eq!(p.oper_param, None);
        assert_eq!(p.title, Some("module.user".into()));
        assert_eq!(p.oper_time, Some("2026-10-03 10:00:00.000000".into()));
    }

    #[test]
    fn anomaly_display_title_translates_module_key() {
        // 轮2回归：module.* 键必须翻成中文，合规报告 PDF 不露裸键
        assert_eq!(anomaly_display_title(Some("module.user")), "用户管理");
        assert_eq!(anomaly_display_title(None), "");
    }

    #[test]
    fn anomaly_display_title_keeps_legacy_chinese_verbatim() {
        assert_eq!(anomaly_display_title(Some("用户管理")), "用户管理");
    }

    #[test]
    fn eval_fail_rate_zero_total_is_zero_no_alarm() {
        let (rate, alarm) = eval_fail_rate(0, 0, 10);
        assert_eq!(rate, 0.0);
        assert!(!alarm);
    }

    #[test]
    fn eval_fail_rate_below_threshold_no_alarm() {
        let (rate, alarm) = eval_fail_rate(1000, 50, 10);
        assert_eq!(rate, 5.0);
        assert!(!alarm);
    }

    #[test]
    fn eval_fail_rate_exactly_threshold_alarms() {
        let (rate, alarm) = eval_fail_rate(100, 10, 10);
        assert_eq!(rate, 10.0);
        assert!(alarm);
    }

    #[test]
    fn eval_fail_rate_exceeds_threshold_alarms() {
        let (rate, alarm) = eval_fail_rate(100, 33, 10);
        assert_eq!(rate, 33.0);
        assert!(alarm);
    }

    #[test]
    fn eval_fail_rate_rounds_to_two_decimals() {
        let (rate, alarm) = eval_fail_rate(3, 1, 25); // 1/3 ≈ 33.333…%
        assert_eq!(rate, 33.33);
        // 原始率 33.33… >= 25，触发告警
        assert!(alarm);
    }

    #[test]
    fn eval_fail_rate_rounding_edge_crossing() {
        // 阈值 25，原失败率 24.999…%（如 749/3000）不告警；取整后仍为 25.00
        let (rate, alarm) = eval_fail_rate(3000, 749, 25);
        assert_eq!(rate, 24.97);
        assert!(!alarm);
    }

    // ==================== 链写入集成（真实 sqlite 迁移库 + LocalStore） ====================
    // 覆盖安全审查轮加固的乱序守卫：锁保证互斥但不保证写入序 = oper_id 序，
    // 乱序时若不拦截会形成分支链（两条 prev 指向同一前驱），verify 按 id 升序
    // 重算必误报篡改。守卫命中 ⇒ 本条降级 NULL，链在非 NULL 子序列上续写。

    use super::SysOperLogService;
    use crate::repository::test_support::migrated_db;
    use crate::shared_store::LocalStore;
    use sea_orm::{DatabaseConnection, EntityTrait};

    /// 隔离测试库 + 带链上下文的 Service（真实 LocalStore 共享态，密钥固定测试值）
    async fn chain_fixture() -> (DatabaseConnection, SysOperLogService) {
        let db = migrated_db().await.unwrap();
        let store: std::sync::Arc<dyn crate::shared_store::SharedStore> =
            std::sync::Arc::new(LocalStore::new(db.clone()));
        let svc = SysOperLogService::with_chain(db.clone(), store, "test-chain-secret");
        (db, svc)
    }

    /// 真实插入一条最小操作日志行（oper_id 显式指定，chain_hash 保持 NULL），返回库内模型
    ///
    /// 返回模型供 `ChainPayload::from_model` 构建 attach 端负载——verify 端重算
    /// 用的正是 from_model（读库路径），两端必须同口径，链哈希才能闭合。
    async fn insert_log_row(
        db: &DatabaseConnection,
        oper_id: i64,
    ) -> crate::entity::sys_oper_log::Model {
        crate::entity::sys_oper_log::Entity::insert(crate::entity::sys_oper_log::ActiveModel {
            oper_id: sea_orm::Set(oper_id),
            tenant_id: sea_orm::Set(0),
            title: sea_orm::Set(Some("module.test".into())),
            oper_name: sea_orm::Set(Some("admin".into())),
            oper_time: sea_orm::Set(Some(
                chrono::NaiveDate::from_ymd_opt(2026, 10, 4)
                    .unwrap()
                    .and_hms_opt(9, 0, 0)
                    .unwrap(),
            )),
            ..Default::default()
        })
        .exec(db)
        .await
        .unwrap();
        crate::entity::sys_oper_log::Entity::find_by_id(oper_id)
            .one(db)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn chain_in_order_write_links_and_verifies() {
        let (db, svc) = chain_fixture().await;
        let ctx = svc.chain.as_ref().unwrap();
        let m1 = insert_log_row(&db, 1).await;
        let m2 = insert_log_row(&db, 2).await;
        let p1 = ChainPayload::from_model(&m1);
        let p2 = ChainPayload::from_model(&m2);

        // 顺序写链：1 → 2（2 的 prev 取自 1 的库内 hash）
        assert!(svc.attach_chain_hash(ctx, 1, &p1).await.unwrap().is_some());
        assert!(svc.attach_chain_hash(ctx, 2, &p2).await.unwrap().is_some());

        let vo = svc.verify_chain().await.unwrap();
        assert!(vo.valid, "顺序写链后全链校验必须通过");
        assert_eq!(vo.checked, 2, "两条非 NULL 节点都参与校验");
        assert_eq!(vo.broken_at_oper_id, None);
    }

    #[tokio::test]
    async fn chain_out_of_order_write_degrades_to_null_and_verify_skips() {
        let (db, svc) = chain_fixture().await;
        let ctx = svc.chain.as_ref().unwrap();
        let m1 = insert_log_row(&db, 1).await;
        let m2 = insert_log_row(&db, 2).await;
        let p1 = ChainPayload::from_model(&m1);
        let p2 = ChainPayload::from_model(&m2);

        // 乱序模拟：oper_id=2 先写链（并发下 id 分配序与 attach 序反转的真实场景）
        assert!(svc.attach_chain_hash(ctx, 2, &p2).await.unwrap().is_some());

        // oper_id=1 后写 → 乱序守卫命中 → 降级 Ok(None)，不产生分支链
        assert!(
            svc.attach_chain_hash(ctx, 1, &p1).await.unwrap().is_none(),
            "更大 oper_id 已抢先写链时，本条必须降级 NULL"
        );

        // 库内真值：1 的 chain_hash 保持 NULL
        let m1_after = crate::entity::sys_oper_log::Entity::find_by_id(1)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(m1_after.chain_hash.is_none(), "降级后不得回写链哈希");

        // verify：NULL 行跳过，链在非 NULL 子序列续写且有效
        let vo = svc.verify_chain().await.unwrap();
        assert!(vo.valid, "降级 NULL 后剩余子链校验必须通过");
        assert_eq!(vo.checked, 1, "仅 oper_id=2 参与校验");
        assert_eq!(vo.broken_at_oper_id, None);
    }

    #[tokio::test]
    async fn chain_verify_detects_tampered_hash() {
        let (db, svc) = chain_fixture().await;
        let ctx = svc.chain.as_ref().unwrap();
        let m1 = insert_log_row(&db, 1).await;
        let m2 = insert_log_row(&db, 2).await;
        let p1 = ChainPayload::from_model(&m1);
        let p2 = ChainPayload::from_model(&m2);
        svc.attach_chain_hash(ctx, 1, &p1).await.unwrap().unwrap();
        svc.attach_chain_hash(ctx, 2, &p2).await.unwrap().unwrap();

        // 真实篡改库内 oper_id=2 的 chain_hash → verify 定位断点
        svc.oper_log_repo
            .set_chain_hash(
                2,
                "deadbeef-deadbeef-deadbeef-deadbeef-deadbeef-deadbeef-deadbeef-dead",
            )
            .await
            .unwrap();

        let vo = svc.verify_chain().await.unwrap();
        assert!(!vo.valid, "链哈希被篡改后校验必须失败");
        assert_eq!(vo.broken_at_oper_id, Some(2), "断点必须定位在被篡改节点");
    }
}
