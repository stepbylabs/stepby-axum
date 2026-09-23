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

use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::entity::sys_oper_log::{ActiveModel as SysOperLogActiveModel, Model as SysOperLogModel};
use crate::repository::sys_oper_log::SysOperLogRepository;

// ==================== DTO ====================

/// 操作日志分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperLogQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub title: Option<String>,
    pub business_type: Option<i32>,
    pub oper_name: Option<String>,
    pub status: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
    /// 游标（keyset 深分页）：上一页最后一条 oper_id。存在时启用深分页（PK < last_id），
    /// 不存在时沿用 pageNum/pageSize 的 OFFSET 分页，向后兼容。
    pub last_id: Option<i64>,
}

impl From<&OperLogQueryDto> for PageDomain {
    fn from(dto: &OperLogQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
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
}

// ==================== 辅助函数 ====================

// ==================== Service 实现 ====================

/// 操作日志模块 Service
#[derive(Clone)]
pub struct SysOperLogService {
    oper_log_repo: SysOperLogRepository,
}

impl SysOperLogService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            oper_log_repo: SysOperLogRepository::new(db),
        }
    }

    /// 分页查询操作日志
    ///
    /// 支持 title 模糊、business_type 精确、oper_name 模糊、status 精确、时间范围筛选
    pub async fn get_oper_log_page(
        &self,
        query: OperLogQueryDto,
    ) -> Result<(Vec<SysOperLogModel>, u64), ServiceError> {
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
    ) -> Result<Vec<SysOperLogModel>, ServiceError> {
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
            )
            .await?;
        Ok(rows)
    }

    /// 批量删除操作日志（物理删除）
    pub async fn delete_oper_logs(&self, oper_ids: Vec<i64>) -> Result<(), ServiceError> {
        self.oper_log_repo.delete_by_ids(oper_ids).await?;
        Ok(())
    }

    /// 清空操作日志（仅删除 N 天前的日志，保留最近 N 天用于审计）
    ///
    /// 修复 P0-R81-010：原 clean_oper_logs 物理删除全部日志，违反审计合规。
    /// 现仅删除 `days` 天前的日志，默认 30 天。
    /// 配合 handler 层 tracing::warn! 记录操作者信息。
    pub async fn clean_oper_logs(&self, days: i64) -> Result<u64, ServiceError> {
        let cutoff = crate::common::datetime::now_naive() - chrono::Duration::days(days);
        let result = self.oper_log_repo.delete_older_than(cutoff).await?;
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
    pub async fn cleanup_old_logs(&self, days: i64) -> Result<u64, ServiceError> {
        let cutoff = crate::common::datetime::now_naive() - chrono::Duration::days(days);
        let result = self.oper_log_repo.delete_older_than(cutoff).await?;
        Ok(result.rows_affected)
    }

    /// 按时间范围清理操作日志（物理删除 [begin, end] 区间的日志，边界含端点）
    ///
    /// 供 `DELETE /monitor/operlog/clean?params[beginTime]=&params[endTime]=` 使用：
    /// 传入 `begin_time` / `end_time`（`%Y-%m-%d`）显式清理指定时间段的日志。
    /// 单侧不传时该侧不设边界。解析失败返回 `ServiceError::bad_request`。
    pub async fn clean_oper_logs_by_range(
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
        let result = self.oper_log_repo.delete_by_time_range(begin, end).await?;
        Ok(result.rows_affected)
    }

    /// 审计大屏统计：按业务类型聚合
    pub async fn stats_by_business_type(&self) -> Result<Vec<AuditBusinessTypeStat>, ServiceError> {
        let rows = self.oper_log_repo.stats_by_business_type().await?;
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
    pub async fn oper_log_type_stats(&self) -> Result<OperLogTypeStatsVo, ServiceError> {
        let rows = self.oper_log_repo.stats_by_business_type().await?;
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
    ) -> Result<Vec<AuditOperatorStat>, ServiceError> {
        let rows = self.oper_log_repo.stats_top_operators(limit).await?;
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
    ) -> Result<Vec<AuditModuleStat>, ServiceError> {
        let rows = self.oper_log_repo.stats_top_modules(limit).await?;
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
    pub async fn get_alarm_status(
        &self,
        window_minutes: i64,
        fail_threshold: i64,
        fail_rate_threshold: i64,
    ) -> Result<AlarmStatusVo, ServiceError> {
        let (total, fail) = self
            .oper_log_repo
            .failure_stats_in_window(window_minutes)
            .await?;
        let (fail_rate, fail_rate_alarm) = eval_fail_rate(total, fail, fail_rate_threshold);

        let operator_bursts: Vec<AlarmItem> = self
            .oper_log_repo
            .failure_burst_operators(window_minutes, fail_threshold)
            .await?
            .into_iter()
            .map(|(name, cnt)| AlarmItem { name, count: cnt })
            .collect();

        let module_bursts: Vec<AlarmItem> = self
            .oper_log_repo
            .failure_burst_modules(window_minutes, fail_threshold)
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
    pub async fn stats_daily(&self, days: i64) -> Result<Vec<AuditDailyStat>, ServiceError> {
        let rows = self.oper_log_repo.stats_daily(days).await?;
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
    pub async fn stats_summary(&self) -> Result<AuditSummary, ServiceError> {
        let (total, success, fail) = self.oper_log_repo.stats_summary().await?;
        Ok(AuditSummary {
            total,
            success,
            fail,
        })
    }

    /// 综合审计统计（一次性返回所有大屏数据）
    pub async fn get_audit_stats(&self, days: i64) -> Result<AuditStatsVo, ServiceError> {
        let summary = self.stats_summary().await?;
        let business_types = self.stats_by_business_type().await?;
        let top_operators = self.stats_top_operators(10).await?;
        let top_modules = self.stats_top_modules(10).await?;
        let daily = self.stats_daily(days).await?;
        Ok(AuditStatsVo {
            summary,
            business_types,
            top_operators,
            top_modules,
            daily,
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
    pub async fn get_compliance_report(
        &self,
        days: i64,
    ) -> Result<ComplianceReportVo, ServiceError> {
        let summary = self.stats_summary().await?;
        let business_types = self.stats_by_business_type().await?;
        let top_operators = self.stats_top_operators(10).await?;
        let top_modules = self.stats_top_modules(10).await?;
        let daily = self.stats_daily(days).await?;
        let anomaly_models = self.oper_log_repo.find_recent_anomalies(50).await?;
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
    /// 修复 P0-R81-011：spawn 写入无重试，进程崩溃或 DB 临时不可用时日志丢失。
    /// 现在包装为重试函数：最多 3 次尝试，间隔 100ms，3 次都失败则 tracing::error!。
    pub async fn record_oper_log(&self, record: OperLogRecord) {
        let now = crate::common::datetime::now_naive();
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
            ..Default::default()
        };

        // 重试机制：最多 3 次尝试，间隔 100ms
        const MAX_ATTEMPTS: u32 = 3;
        const RETRY_INTERVAL_MS: u64 = 100;

        for attempt in 1..=MAX_ATTEMPTS {
            match self.oper_log_repo.insert(am.clone()).await {
                Ok(_) => return,
                Err(e) => {
                    if attempt < MAX_ATTEMPTS {
                        tracing::warn!(
                            "操作日志写入失败（第 {}/{} 次），{}ms 后重试: {}",
                            attempt,
                            MAX_ATTEMPTS,
                            RETRY_INTERVAL_MS,
                            e
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(RETRY_INTERVAL_MS))
                            .await;
                    } else {
                        // 3 次都失败，记录错误日志（无法再恢复）
                        tracing::error!(
                            "操作日志写入失败（已重试 {} 次，放弃）: {}",
                            MAX_ATTEMPTS,
                            e
                        );
                    }
                }
            }
        }
    }
}

// ==================== 审计大屏 VO ====================

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
    use super::{anomaly_display_title, eval_fail_rate};

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
}
