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
use crate::entity::sys_frontend_error::ActiveModel as FrontendErrorActiveModel;
use crate::entity::sys_frontend_error::Model as FrontendErrorModel;
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

/// 允许的来源集合（超出归一化为 other，防枚举膨胀）
/// 对齐前端 errorHub.ErrorSource（api/download/vue/global/unhandledrejection/resource/other）+ Web Vitals 的 vital。
const ALLOWED_SOURCES: &[&str] = &[
    "api",
    "download",
    "vue",
    "global",
    "unhandledrejection",
    "resource",
    "vital",
    "other",
];
/// 允许的级别集合（超出归一化为 info）
const ALLOWED_LEVELS: &[&str] = &["error", "warning", "info"];

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
    pub level: Option<String>,
    pub source: Option<String>,
    pub name: Option<String>,
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&FrontendErrorQueryDto> for PageDomain {
    fn from(dto: &FrontendErrorQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
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
    ) -> Result<u64, ServiceError> {
        let items: Vec<FrontendErrorItem> = items.into_iter().take(MAX_ITEMS_PER_REPORT).collect();
        if items.is_empty() {
            return Ok(0);
        }
        let models: Vec<FrontendErrorActiveModel> = items
            .into_iter()
            .map(|it| FrontendErrorActiveModel {
                level: Set(normalize_enum(&it.level, ALLOWED_LEVELS, "info", MAX_LEVEL_LEN)),
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
                view_width: Set(it.view_width),
                view_height: Set(it.view_height),
                value: Set(it.value),
                user_name: Set(user_name.clone()),
                // 批量 insert_many 不触发 ActiveModelBehavior::before_save，
                // 故 create_time 必须在此显式写入，否则落库为 NULL 且破坏按天聚合统计。
                create_time: Set(Some(crate::common::datetime::now_naive())),
                ..Default::default()
            })
            .collect();
        let affected = self.repo.insert_many(models).await?;
        Ok(affected)
    }

    /// 分页查询
    pub async fn get_page(
        &self,
        query: FrontendErrorQueryDto,
    ) -> Result<(Vec<FrontendErrorModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
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
                query.name.as_deref(),
                begin,
                end,
            )
            .await?;
        Ok((rows, total))
    }

    /// 详情查询（不存在返回 ServiceError::not_found）
    pub async fn get_by_id(&self, id: i64) -> Result<FrontendErrorModel, ServiceError> {
        self.repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.frontend_error.not_found")))
    }

    /// 批量删除（物理删除）
    pub async fn remove(&self, ids: Vec<i64>) -> Result<(), ServiceError> {
        self.repo.delete_by_ids(ids).await?;
        Ok(())
    }

    /// 保留期清理：仅删除 days 天前的记录，返回受影响行数
    pub async fn clean(&self, days: i64) -> Result<u64, ServiceError> {
        let cutoff = crate::common::datetime::now_naive() - chrono::Duration::days(days);
        let result = self.repo.delete_older_than(cutoff).await?;
        Ok(result.rows_affected)
    }

    /// 按时间范围清理（物理删除 [begin, end] 区间，任一侧可为空）
    pub async fn clean_by_range(
        &self,
        begin_time: Option<String>,
        end_time: Option<String>,
    ) -> Result<u64, ServiceError> {
        let begin = match begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let result = self.repo.delete_by_time_range(begin, end).await?;
        Ok(result.rows_affected)
    }

    /// 概览统计：来源分布 + 最近 days 天每日 error 数
    pub async fn get_stats(&self, days: i64) -> Result<FrontendErrorStatsVo, ServiceError> {
        let by_source = self
            .repo
            .stats_by_source()
            .await?
            .into_iter()
            .map(|(source, count)| SourceCount { source, count })
            .collect();
        let daily = self
            .repo
            .stats_daily_errors(days)
            .await?
            .into_iter()
            .map(|(date, count)| DailyErrorCount { date, count })
            .collect();
        Ok(FrontendErrorStatsVo { by_source, daily })
    }
}
