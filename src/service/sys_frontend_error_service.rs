//! 前端异常与性能监控模块 Service 层（Tier-S #1）
//!
//! 职责：
//! - 批量上报（前端一次提交多条，含异常与 Web Vitals 指标，服务端截断字段后落库）
//! - 分页查询（level / source 精确、name 模糊、时间范围）
//! - 详情查询
//! - 批量删除（物理删除）/ 保留期清理
//! - 概览统计（按来源分布 + 最近 N 天每日 error 数）
//!
//! 不依赖任何 Web 框架类型（axum / tower / tower-http）。

use sea_orm::{DatabaseConnection, Set};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_frontend_error::{
    ActiveModel as FrontendErrorActiveModel, Column as FrontendErrorColumn,
    Model as FrontendErrorModel,
};
use crate::repository::sys_frontend_error::SysFrontendErrorRepository;

// ==================== 字段长度上限（防前端上报超大内容撑爆库） ====================

const MAX_ITEMS_PER_REPORT: usize = 100;
const MAX_NAME_LEN: usize = 255;
const MAX_MESSAGE_LEN: usize = 2000;
const MAX_STACK_LEN: usize = 8000;
const MAX_PAGE_URL_LEN: usize = 1000;
const MAX_USER_AGENT_LEN: usize = 512;
const MAX_LEVEL_LEN: usize = 16;
const MAX_SOURCE_LEN: usize = 32;

/// 性能采样来源（Web Vitals：LCP/FCP/CLS…）。保留期分档与页面默认排除都以它为准，
/// 因此收敛成一个常量，避免"清理按一个字面、查询按另一个字面"这种静默失配。
pub const SOURCE_VITAL: &str = "vital";
/// 允许的来源集合（超出归一化为 other，防枚举膨胀）
/// 对齐前端 errorHub.ErrorSource（api/download/vue/global/unhandledrejection/resource/other）+ Web Vitals 的 vital。
const ALLOWED_SOURCES: &[&str] = &[
    "api",
    "download",
    "vue",
    "global",
    "unhandledrejection",
    "resource",
    SOURCE_VITAL,
    "other",
];
/// 允许的级别集合（超出归一化为 info）
const ALLOWED_LEVELS: &[&str] = &["error", "warning", "info"];
/// 允许的设备类型集合（FCP-011 分桶；超出置 None，防枚举膨胀）
const ALLOWED_DEVICE_TYPES: &[&str] = &["mobile", "tablet", "desktop"];

/// 归一化 `exclude_source`（逗号分隔）→ 白名单内的去重来源列表。
///
/// - 空串/全空白/全非法 ⇒ `None`（不过滤），避免生成 `NOT IN ()` 这类"全真或非法"条件；
/// - 只保留 `ALLOWED_SOURCES` 内的值（与上报侧归一化同源，防止拼错就静默失效）；
/// - 大小写与空白容忍（`VITAL , other` ⇒ `["vital","other"]`）。
fn normalize_exclude_sources(raw: Option<&str>) -> Option<Vec<String>> {
    let raw = raw?;
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let p = part.trim().to_ascii_lowercase();
        if p.is_empty() {
            continue;
        }
        if ALLOWED_SOURCES.contains(&p.as_str()) && !out.contains(&p) {
            out.push(p);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

// ==================== DTO ====================

/// 单条上报项（前端 errorReporter / web-vitals 采集后批量提交）
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FrontendErrorItem {
    pub level: String,
    pub source: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub stack: Option<String>,
    #[serde(default)]
    pub page_url: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    /// 设备类型分桶（FCP-011）：mobile / tablet / desktop；非法值置 None
    #[serde(default)]
    pub device_type: Option<String>,
    #[serde(default)]
    pub view_width: Option<i32>,
    #[serde(default)]
    pub view_height: Option<i32>,
    #[serde(default)]
    pub value: Option<f64>,
}

/// 批量上报请求体
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FrontendReportDto {
    pub items: Vec<FrontendErrorItem>,
}

/// 前端异常分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FrontendErrorQueryDto {
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
    pub level: Option<String>,
    pub source: Option<String>,
    /// 来源**排除**列表（逗号分隔，如 `vital` 或 `vital,other`）。
    ///
    /// 为什么需要它：本表是"异常 + 性能埋点"统一表，实测 101 342 行里
    /// **101 272 行（99.93%）是 `source='vital'` 的 Web Vitals 采样**。
    /// `source` 只能等值命中 ⇒ 「前端错误」页首屏全是 `LCP=…`，
    /// 想只看异常得把 8 个来源逐个查一遍。这个字段让页面能"默认排除采样"。
    /// 只接受 `ALLOWED_SOURCES` 内的值（非法值丢弃，防枚举膨胀）。
    pub exclude_source: Option<String>,
    pub name: Option<String>,
    /// 设备类型分桶筛选（FCP-011）：mobile / tablet / desktop
    pub device_type: Option<String>,
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
    /// 显式「按租户筛选」（`[ui].tenant_filter` 决定前端是否给出入口）。
    ///
    /// 服务层把它与 `tenant_scope` **相与**（AND）⇒ 只能收窄、永不放宽：
    /// 租户操作者即便手工传他租户 id，结果集也只是空集，不存在越权读面。
    pub tenant_id: Option<i64>,
}

impl From<&FrontendErrorQueryDto> for PageDomain {
    fn from(dto: &FrontendErrorQueryDto) -> Self {
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

/// 概览统计响应
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FrontendErrorStatsVo {
    /// 按来源分组计数
    pub by_source: Vec<SourceCount>,
    /// 最近 N 天每日 error 数
    pub daily: Vec<DailyErrorCount>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceCount {
    pub source: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DailyErrorCount {
    pub date: String,
    pub count: i64,
}

// ==================== 辅助函数 ====================

/// 按字符数截断（含边界安全：非 ASCII 按字符而非字节截断）
fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

/// 归一化字符串枚举字段：trim、空则 fallback、超长截断
fn normalize_enum(value: &str, allowed: &[&str], fallback: &str, max_len: usize) -> String {
    let v = value.trim();
    if allowed.contains(&v) {
        truncate(v, max_len)
    } else {
        fallback.to_string()
    }
}

fn opt_truncate(value: &Option<String>, max_chars: usize) -> Option<String> {
    value
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| truncate(s, max_chars))
}

// ==================== Service ====================

/// 允许排序的前端异常列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖业务展示列（主键、级别、来源、错误名、错误信息、页面 URL、User-Agent、
/// 设备类型、指标数值、上报用户、时间；大文本列 user_agent 排序无害）；
/// `tenant_id` 等内部列与调试用超大文本列（stack）不开放动态排序。
const SORTABLE_COLUMNS: &[(&str, FrontendErrorColumn)] = &[
    ("id", FrontendErrorColumn::Id),
    ("level", FrontendErrorColumn::Level),
    ("source", FrontendErrorColumn::Source),
    ("name", FrontendErrorColumn::Name),
    ("message", FrontendErrorColumn::Message),
    ("page_url", FrontendErrorColumn::PageUrl),
    ("user_agent", FrontendErrorColumn::UserAgent),
    ("device_type", FrontendErrorColumn::DeviceType),
    ("value", FrontendErrorColumn::Value),
    ("user_name", FrontendErrorColumn::UserName),
    ("create_time", FrontendErrorColumn::CreateTime),
];

/// 前端异常与性能监控 Service
#[derive(Clone)]
pub struct SysFrontendErrorService {
    repo: SysFrontendErrorRepository,
}

impl SysFrontendErrorService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            repo: SysFrontendErrorRepository::new(db),
        }
    }

    /// 批量上报（返回实际落库条数）。items 超过 MAX_ITEMS_PER_REPORT 时截断丢弃多余项。
    pub async fn report(
        &self,
        items: Vec<FrontendErrorItem>,
        user_name: Option<String>,
        tenant_id: i64,
    ) -> Result<u64, ServiceError> {
        let items: Vec<FrontendErrorItem> = items.into_iter().take(MAX_ITEMS_PER_REPORT).collect();
        if items.is_empty() {
            return Ok(0);
        }
        let models: Vec<FrontendErrorActiveModel> = items
            .into_iter()
            .map(|it| {
                // FCP-010：vitals 同步观察进 Prometheus 直方图/gauge（与落库同源），
                // 供 stepby-frontend-vitals 告警组做 P95 退化检测
                if it.source == "vital"
                    && let (Some(name), Some(value)) = (it.name.as_deref(), it.value)
                {
                    let device = it.device_type.as_deref().unwrap_or("unknown");
                    if name == "CLS" {
                        crate::observability::metrics::MetricsRegistry::global()
                            .set_frontend_cls(device, value);
                    } else {
                        crate::observability::metrics::MetricsRegistry::global()
                            .record_frontend_vital(name, device, value / 1000.0);
                    }
                }
                FrontendErrorActiveModel {
                    level: Set(normalize_enum(
                        &it.level,
                        ALLOWED_LEVELS,
                        "info",
                        MAX_LEVEL_LEN,
                    )),
                    source: Set(normalize_enum(
                        &it.source,
                        ALLOWED_SOURCES,
                        "other",
                        MAX_SOURCE_LEN,
                    )),
                    name: Set(opt_truncate(&it.name, MAX_NAME_LEN)),
                    message: Set(opt_truncate(&it.message, MAX_MESSAGE_LEN)),
                    stack: Set(opt_truncate(&it.stack, MAX_STACK_LEN)),
                    page_url: Set(opt_truncate(&it.page_url, MAX_PAGE_URL_LEN)),
                    user_agent: Set(opt_truncate(&it.user_agent, MAX_USER_AGENT_LEN)),
                    device_type: Set(it
                        .device_type
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| ALLOWED_DEVICE_TYPES.contains(s))
                        .map(str::to_string)),
                    view_width: Set(it.view_width),
                    view_height: Set(it.view_height),
                    value: Set(it.value),
                    user_name: Set(user_name.clone()),
                    // 多租户：上报记录归属上报者租户（平台 0），供列表/统计按租户收敛
                    tenant_id: Set(tenant_id),
                    // 批量 insert_many 不触发 ActiveModelBehavior::before_save，
                    // 故 create_time 必须在此显式写入，否则落库为 NULL 且破坏按天聚合统计。
                    create_time: Set(Some(crate::common::datetime::now_naive())),
                    ..Default::default()
                }
            })
            .collect();
        let affected = self.repo.insert_many(models).await?;
        Ok(affected)
    }

    /// 分页查询
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅本租户记录；平台 → `None` 全量。
    pub async fn get_page(
        &self,
        query: FrontendErrorQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<FrontendErrorModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_frontend_error::Entity>(
                prop,
                SORTABLE_COLUMNS,
            )
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
            .repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                query.level.as_deref(),
                query.source.as_deref(),
                normalize_exclude_sources(query.exclude_source.as_deref()).as_deref(),
                query.name.as_deref(),
                query.device_type.as_deref(),
                begin,
                end,
                tenant_scope,
                query.tenant_id,
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 详情查询（不存在返回 ServiceError::not_found）
    ///
    /// `operator_tid`：租户操作者只能查询本租户记录（越权统一按不存在处理，避免存在性泄露）；
    /// 平台（0）放行。
    pub async fn get_by_id(
        &self,
        id: i64,
        operator_tid: i64,
    ) -> Result<FrontendErrorModel, ServiceError> {
        let model = self.repo.find_by_id(id).await?.ok_or_else(|| {
            ServiceError::not_found(&crate::tr!("error.frontend_error.not_found"))
        })?;
        if !crate::common::tenant::tenant_allowed(operator_tid, model.tenant_id) {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.frontend_error.not_found"
            )));
        }
        Ok(model)
    }

    /// 批量删除（物理删除）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅删除本租户记录；`None`（平台）→ 不过滤。
    pub async fn remove(
        &self,
        ids: Vec<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<(), ServiceError> {
        self.repo.delete_by_ids(ids, tenant_scope).await?;
        Ok(())
    }

    /// 保留期清理：仅删除 days 天前的记录，返回受影响行数
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅清理本租户记录；`None`（平台）→ 全量。
    pub async fn clean(&self, days: i64, tenant_scope: Option<i64>) -> Result<u64, ServiceError> {
        let cutoff = crate::common::datetime::now_naive() - chrono::Duration::days(days);
        let result = self.repo.delete_older_than(cutoff, tenant_scope).await?;
        Ok(result.rows_affected)
    }

    /// 按「性能采样 / 其余」两档清理保留期（批七十九）。
    ///
    /// 两档谓词 `source IN (vital)` 与 `source NOT IN (vital)` **互斥且并集覆盖全表**，
    /// 所以合起来与改造前那一次无条件删除清得一样干净——不存在"分档后漏清某类来源"，
    /// 也不存在同一行被删两次。
    ///
    /// 多租户与 [`Self::clean`] 同口径：`tenant_scope = Some(tid)` 仅清本租户，
    /// `None`（平台）不过滤。读侧与写侧共用同一个谓词参数，不做二次推导。
    ///
    /// 返回 `(vitals 行数, 其余行数)`。
    pub async fn clean_split_vital(
        &self,
        vital_days: i64,
        other_days: i64,
        tenant_scope: Option<i64>,
    ) -> Result<(u64, u64), ServiceError> {
        use crate::repository::sys_frontend_error::SourceFilter;
        let vital = [SOURCE_VITAL.to_string()];
        let now = crate::common::datetime::now_naive();
        let vitals = self
            .repo
            .delete_older_than_sources(
                now - chrono::Duration::days(vital_days),
                tenant_scope,
                SourceFilter::Only(&vital),
            )
            .await?;
        let others = self
            .repo
            .delete_older_than_sources(
                now - chrono::Duration::days(other_days),
                tenant_scope,
                SourceFilter::Except(&vital),
            )
            .await?;
        Ok((vitals, others))
    }

    /// 按时间范围清理（物理删除 `[begin, end]` 区间，任一侧可为空）
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅清理本租户记录；`None`（平台）→ 全量。
    pub async fn clean_by_range(
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
        let result = self
            .repo
            .delete_by_time_range(begin, end, tenant_scope)
            .await?;
        Ok(result.rows_affected)
    }

    /// 概览统计：来源分布 + 最近 days 天每日 error 数
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅统计本租户；平台 → `None` 全量。
    pub async fn get_stats(
        &self,
        days: i64,
        tenant_scope: Option<i64>,
    ) -> Result<FrontendErrorStatsVo, ServiceError> {
        let by_source = self
            .repo
            .stats_by_source(tenant_scope)
            .await?
            .into_iter()
            .map(|(source, count)| SourceCount { source, count })
            .collect();
        let daily = self
            .repo
            .stats_daily_errors(days, tenant_scope)
            .await?
            .into_iter()
            .map(|(date, count)| DailyErrorCount { date, count })
            .collect();
        Ok(FrontendErrorStatsVo { by_source, daily })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `exclude_source` 归一化：只留白名单、去重、容忍空白与大小写。
    ///
    /// 为什么这条必须钉住：它是页面"默认排除性能采样"的唯一开关。若拼错/传了非法值就
    /// 静默变成 `None`（不过滤），页面会悄悄退回"首屏全是 LCP 采样"的老样子，
    /// 而没有任何报错——正是本项目一直在防的"判据静默失效"。
    #[test]
    fn normalize_exclude_sources_filters_and_dedupes() {
        // 正常单值
        assert_eq!(
            normalize_exclude_sources(Some("vital")),
            Some(vec!["vital".to_string()])
        );
        // 多值 + 空白 + 大小写
        assert_eq!(
            normalize_exclude_sources(Some(" VITAL , other ")),
            Some(vec!["vital".to_string(), "other".to_string()])
        );
        // 重复值只留一个
        assert_eq!(
            normalize_exclude_sources(Some("vital,vital")),
            Some(vec!["vital".to_string()])
        );
        // 非法值全丢弃 ⇒ 不过滤（与"没传"同义，避免 NOT IN () 这种非法条件）
        assert_eq!(normalize_exclude_sources(Some("not-a-source")), None);
        assert_eq!(normalize_exclude_sources(Some(" , , ")), None);
        // 缺省/空串 ⇒ 不过滤
        assert_eq!(normalize_exclude_sources(None), None);
        assert_eq!(normalize_exclude_sources(Some("")), None);
    }

    /// 多字节按**字符**截断（按字节截会在汉字中间切片 panic 或产出乱码）。
    #[test]
    fn truncate_counts_characters_not_bytes() {
        assert_eq!(truncate("abcde", 3), "abc");
        assert_eq!(truncate("中文测试消息", 2), "中文");
        assert_eq!(truncate("中文测试消息", 100), "中文测试消息");
        assert_eq!(truncate("", 5), "");
        // 混合：emoji 的组合序列按 char 计（此处钉住实现口径 = Unicode Scalar Value）
        assert_eq!(truncate("a中b", 2), "a中");
    }

    /// 枚举白名单归一：命中取值、未命中回兜底、带空白先 trim。
    #[test]
    fn normalize_enum_allows_only_whitelisted_values() {
        assert_eq!(
            normalize_enum("error", ALLOWED_LEVELS, "error", MAX_LEVEL_LEN),
            "error"
        );
        assert_eq!(
            normalize_enum("  warning ", ALLOWED_LEVELS, "error", MAX_LEVEL_LEN),
            "warning"
        );
        // 白名单外一律回落（不允许任意字符串入库污染分级面）
        assert_eq!(
            normalize_enum("ERROR", ALLOWED_LEVELS, "error", MAX_LEVEL_LEN),
            "error"
        );
        assert_eq!(
            normalize_enum("fatal", ALLOWED_LEVELS, "error", MAX_LEVEL_LEN),
            "error"
        );
        assert_eq!(
            normalize_enum("", ALLOWED_LEVELS, "error", MAX_LEVEL_LEN),
            "error"
        );
        assert_eq!(
            normalize_enum("unknown", ALLOWED_SOURCES, "console", MAX_SOURCE_LEN),
            "console"
        );
    }

    /// 可选字段：空白视为缺失（None），非空白按字符截断。
    #[test]
    fn opt_truncate_treats_blank_as_absent() {
        assert_eq!(opt_truncate(&None, 10), None);
        assert_eq!(opt_truncate(&Some(String::new()), 10), None);
        assert_eq!(opt_truncate(&Some("   ".to_string()), 10), None);
        assert_eq!(
            opt_truncate(&Some("  hello  ".to_string()), 10),
            Some("hello".to_string())
        );
        assert_eq!(
            opt_truncate(&Some("中文测试消息".to_string()), 2),
            Some("中文".to_string())
        );
    }
}
