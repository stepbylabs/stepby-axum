//! 登录日志模块 Service 层
//!
//! 职责：
//! - 登录日志分页查询（多条件筛选：ipaddr / user_name / status / 时间范围）
//! - 登录日志批量删除（物理删除）
//! - 解锁用户（删除该用户的登录失败日志）
//! - 清空登录日志
//!
//! 不依赖任何 Web 框架类型（axum / tower / tower-http）

use chrono::NaiveDateTime;
use sea_orm::DatabaseConnection;
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::entity::sys_logininfor::Model as SysLogininforModel;
use crate::repository::sys_logininfor::SysLogininforRepository;

// ==================== DTO ====================

/// 登录日志分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogininforQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// 登录 IP 地址（模糊查询，字段名对齐前端 ipaddr 全小写）
    pub ipaddr: Option<String>,
    /// 用户名称（模糊查询）
    pub user_name: Option<String>,
    /// 登录状态（"0"=成功 "1"=失败，精确查询）
    pub status: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
    /// 游标（keyset 深分页）：上一页最后一条 info_id。存在时启用深分页（PK < last_id），
    /// 不存在时沿用 pageNum/pageSize 的 OFFSET 分页，向后兼容。
    pub last_id: Option<i64>,
}

impl From<&LogininforQueryDto> for PageDomain {
    fn from(dto: &LogininforQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

// ==================== Service 实现 ====================

/// 登录日志模块 Service
pub struct SysLogininforService {
    logininfor_repo: SysLogininforRepository,
}

impl SysLogininforService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            logininfor_repo: SysLogininforRepository::new(db),
        }
    }

    /// 分页查询登录日志
    ///
    /// 支持 ipaddr 模糊、user_name 模糊、status 精确、时间范围筛选，按 login_time 倒序。
    /// begin_time / end_time 为 `%Y-%m-%d` 格式字符串，解析失败返回 `ServiceError::bad_request`。
    pub async fn get_logininfor_page(
        &self,
        query: LogininforQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<SysLogininforModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let begin_time = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end_time = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        let (rows, total) = self
            .logininfor_repo
            .find_page_filtered(
                offset,
                limit,
                query.ipaddr.as_deref(),
                query.user_name.as_deref(),
                query.status.as_deref(),
                begin_time,
                end_time,
                query.last_id,
                tenant_scope,
            )
            .await?;
        Ok((rows, total))
    }

    /// 导出登录日志（受 EXPORT_MAX_ROWS 限制，绕过 PageDomain 的 100 行截断）
    ///
    /// 与 `get_logininfor_page` 的差异：使用 EXPORT_MAX_ROWS 作为 limit，
    /// 而非 PageDomain.limit()（受 MAX_PAGE_SIZE=100 限制），避免静默截断。
    pub async fn export_logininfors(
        &self,
        query: LogininforQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<SysLogininforModel>, ServiceError> {
        let begin_time = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end_time = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        let (rows, _) = self
            .logininfor_repo
            .find_page_filtered(
                0,
                crate::common::page::EXPORT_MAX_ROWS,
                query.ipaddr.as_deref(),
                query.user_name.as_deref(),
                query.status.as_deref(),
                begin_time,
                end_time,
                None, // 导出固定走 OFFSET 全量路径，不走 keyset
                tenant_scope,
            )
            .await?;
        Ok(rows)
    }

    /// 批量删除登录日志（物理删除）
    pub async fn delete_logininfors(&self, info_ids: Vec<i64>) -> Result<(), ServiceError> {
        self.logininfor_repo.delete_by_ids(info_ids).await?;
        Ok(())
    }

    /// 解锁用户（删除该用户的登录失败日志，status=1）
    pub async fn unlock_user(&self, user_name: &str) -> Result<(), ServiceError> {
        self.logininfor_repo.delete_by_user_name(user_name).await?;
        Ok(())
    }

    /// 清空全部登录日志（物理删除）
    pub async fn clean_logininfors(&self) -> Result<(), ServiceError> {
        self.logininfor_repo.clean_all().await?;
        Ok(())
    }

    /// 清理 N 天前的登录日志（按 login_time 过滤，保留最近 N 天）
    ///
    /// 供定时任务 cleanup_expired_logs 调用（P0-R81-019）。
    /// 默认保留 90 天，避免登录日志无限增长导致生产崩溃。
    pub async fn cleanup_old_logs(&self, days: i64) -> Result<u64, ServiceError> {
        let cutoff = crate::common::datetime::now_naive() - chrono::Duration::days(days);
        let result = self.logininfor_repo.delete_older_than(cutoff).await?;
        Ok(result.rows_affected)
    }

    /// 按时间范围清理登录日志（物理删除 [begin, end] 区间的日志，边界含端点）
    ///
    /// 供 `DELETE /monitor/logininfor/clean?params[beginTime]=&params[endTime]=` 使用：
    /// 传入 `begin_time` / `end_time`（`%Y-%m-%d`）显式清理指定时间段的日志。
    /// 单侧不传时该侧不设边界。解析失败返回 `ServiceError::bad_request`。
    pub async fn clean_logininfors_by_range(
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
        let result = self
            .logininfor_repo
            .delete_by_time_range(begin, end)
            .await?;
        Ok(result.rows_affected)
    }

    /// 登录统计：最近 N 天每天成功/失败次数（首页仪表盘用）
    ///
    /// tenant_scope=Some(t) 时按租户维度统计（报表快照等按租户）。
    pub async fn daily_stats(
        &self,
        days: i64,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<LoginDailyStat>, ServiceError> {
        let rows = self.logininfor_repo.daily_stats(days, tenant_scope).await?;
        Ok(rows
            .into_iter()
            .map(|(date, success, fail)| LoginDailyStat {
                date,
                success,
                fail,
            })
            .collect())
    }

    /// 查询自 since 以来失败登录按 IP 分组，返回 count >= min_count 的 (ip, count) 列表
    ///
    /// 用于登录异常检测 scheduler 任务。
    pub async fn find_failed_group_by_ip(
        &self,
        since: NaiveDateTime,
        min_count: i64,
    ) -> Result<Vec<(String, i64)>, ServiceError> {
        Ok(self
            .logininfor_repo
            .find_failed_group_by_ip(since, min_count)
            .await?)
    }

    /// 统计今日登录失败的不重复 IP 数（dashboard stats 用）
    pub async fn count_today_failed_ips(
        &self,
        tenant_scope: Option<i64>,
    ) -> Result<i64, ServiceError> {
        Ok(self
            .logininfor_repo
            .count_today_failed_ips(tenant_scope)
            .await?)
    }

    /// 查询在线用户（最近 30 分钟内登录成功的记录）
    ///
    /// 简化实现：当前未在 Redis 中存储登录 token 列表，故通过 sys_logininfor 表
    /// 查询 status="0" 且 login_time 在最近 30 分钟内的记录，按 login_time 倒序返回。
    /// 限制返回数量上限（默认 500），避免单次查询返回过多记录。
    ///
    /// # 已废弃（P1-19 方案 B）
    ///
    /// 在线用户列表已改用 Redis `online:{token_hash}` → `OnlineSession` JSON 方案
    /// （见 `monitor_online_handler::list`），本方法仅作为 Redis 故障时的 fallback。
    ///
    /// 已知问题（已由新方案修复）：
    /// - 30 分钟硬窗口：登录 31 分钟后从列表消失，即使 JWT 24h 仍有效
    /// - 无法反映登出状态：logout 未删除 online key，登出后仍显示在线 30 分钟
    #[deprecated(
        since = "0.1.0",
        note = "P1-19 方案 B：改用 monitor_online_handler::list 的 Redis SCAN + MGET 方案，本方法仅作 Redis 故障 fallback"
    )]
    pub async fn get_online_users(
        &self,
        ipaddr: Option<&str>,
        user_name: Option<&str>,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<SysLogininforModel>, ServiceError> {
        let since = crate::common::datetime::now_naive() - chrono::Duration::minutes(30);
        let rows = self
            .logininfor_repo
            .find_online(
                since,
                ipaddr,
                user_name,
                crate::common::constants::DROPDOWN_MAX_ROWS,
                tenant_scope,
            )
            .await?;
        Ok(rows)
    }
}

/// 登录每日统计项
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "LoginDailyStat.ts", rename_all = "camelCase")]
pub struct LoginDailyStat {
    /// 日期（YYYY-MM-DD）
    pub date: String,
    /// 成功登录次数
    pub success: i64,
    /// 失败登录次数
    pub fail: i64,
}
