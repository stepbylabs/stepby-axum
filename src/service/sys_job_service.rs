// axum-backend/src/service/sys_job_service.rs
//! 定时任务 Service 层
//!
//! 职责：CRUD 业务逻辑 + 调度器委托（启停/执行）
//! 依赖：SysJobRepository + SysJobLogRepository + Arc<JobScheduler>
//! 约束：不依赖 axum / tower / tower-http

use std::sync::Arc;

use futures::future::FutureExt;
use garde::Validate;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::entity::sys_job::{self, Model as SysJobModel};
use crate::entity::sys_job_log::Model as SysJobLogModel;
use crate::repository::sys_job::SysJobRepository;
use crate::repository::sys_job_log::SysJobLogRepository;
use crate::scheduler::JobScheduler;

/// P3 修复: 定时任务枚举值白名单校验
/// misfire_policy: "1"=立即执行, "2"=执行一次, "3"=放弃执行（可选，默认 "3"）
/// concurrent: "0"=允许, "1"=禁止（可选，默认 "1"）
/// status: "0"=正常, "1"=暂停（可选）
fn validate_job_enum(
    misfire_policy: Option<&str>,
    concurrent: Option<&str>,
    status: Option<&str>,
) -> Result<(), ServiceError> {
    if let Some(m) = misfire_policy
        && m != "1"
        && m != "2"
        && m != "3"
    {
        return Err(ServiceError::bad_request(&format!(
            "misfire_policy 必须为 1/2/3，当前值: {}",
            m
        )));
    }
    if let Some(c) = concurrent
        && c != "0"
        && c != "1"
    {
        return Err(ServiceError::bad_request(&format!(
            "concurrent 必须为 0(允许) 或 1(禁止)，当前值: {}",
            c
        )));
    }
    if let Some(s) = status
        && s != "0"
        && s != "1"
    {
        return Err(ServiceError::bad_request(&format!(
            "status 必须为 0(正常) 或 1(暂停)，当前值: {}",
            s
        )));
    }
    Ok(())
}

// ==================== DTO ====================

/// 任务查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub job_name: Option<String>,
    pub job_group: Option<String>,
    pub status: Option<String>,
}

impl From<&JobQueryDto> for PageDomain {
    fn from(dto: &JobQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 新增任务 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobAddDto {
    #[garde(length(min = 1, max = 64))]
    pub job_name: String,
    #[garde(length(max = 64))]
    pub job_group: String,
    #[garde(length(min = 1, max = 500))]
    pub invoke_target: String,
    #[garde(length(min = 1, max = 255))]
    pub cron_expression: String,
    #[garde(skip)]
    pub misfire_policy: Option<String>,
    #[garde(skip)]
    pub concurrent: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 修改任务 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobEditDto {
    #[garde(skip)]
    pub job_id: i64,
    #[garde(length(min = 1, max = 64))]
    pub job_name: String,
    #[garde(length(max = 64))]
    pub job_group: String,
    #[garde(length(min = 1, max = 500))]
    pub invoke_target: String,
    #[garde(length(min = 1, max = 255))]
    pub cron_expression: String,
    #[garde(skip)]
    pub misfire_policy: Option<String>,
    #[garde(skip)]
    pub concurrent: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 状态切换 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobStatusDto {
    #[garde(skip)]
    pub job_id: i64,
    #[garde(length(min = 1, max = 1))]
    pub status: String,
}

/// 立即执行 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobRunDto {
    #[garde(skip)]
    pub job_id: i64,
    #[garde(length(max = 64))]
    pub job_group: String,
}

/// 日志查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobLogQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub job_name: Option<String>,
    pub job_group: Option<String>,
    pub status: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&JobLogQueryDto> for PageDomain {
    fn from(dto: &JobLogQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

// ==================== VO ====================

/// 任务响应 VO（在 SysJobModel 基础上增加 nextValidTime 计算字段）
#[derive(Debug, Clone, Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename_all = "camelCase")]
pub struct JobVo {
    #[serde(flatten)]
    #[ts(flatten)]
    pub job: SysJobModel,
    /// 下次执行时间（根据 cron_expression 计算，cron 非法时为 None）
    #[ts(optional)]
    pub next_valid_time: Option<String>,
}

impl JobVo {
    /// 从 Model 构造，自动计算 nextValidTime
    pub fn from_model(job: SysJobModel) -> Self {
        let next_valid_time = job
            .cron_expression
            .as_ref()
            .and_then(|cron| calc_next_valid_time(cron));
        Self {
            job,
            next_valid_time,
        }
    }
}

/// 解析 cron 表达式，返回下次执行时间的字符串
///
/// 使用 `croner::Cron::from_str` 解析（与 tokio-cron-scheduler 内部使用的 cron 解析库一致）
/// 成功时返回 `Some("YYYY-MM-DD HH:MM:SS")`
/// 失败时返回 None
pub fn calc_next_valid_time(cron_str: &str) -> Option<String> {
    use std::str::FromStr;
    match croner::Cron::from_str(cron_str) {
        Ok(cron) => cron
            .find_next_occurrence(&chrono::Utc::now(), false)
            .ok()
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string()),
        Err(_) => None,
    }
}

// ==================== Service ====================

/// 定时任务 Service
///
/// 持有 Repository + Scheduler 引用，CRUD 操作同步调度器
pub struct SysJobService {
    job_repo: SysJobRepository,
    job_log_repo: SysJobLogRepository,
    scheduler: Arc<JobScheduler>,
}

impl SysJobService {
    pub fn new(db: DatabaseConnection, scheduler: Arc<JobScheduler>) -> Self {
        Self {
            job_repo: SysJobRepository::new(db.clone()),
            job_log_repo: SysJobLogRepository::new(db),
            scheduler,
        }
    }

    /// 获取数据库连接引用（用于事务）
    fn db(&self) -> &DatabaseConnection {
        self.job_repo.base().db()
    }

    /// 分页查询任务列表
    pub async fn get_job_page(
        &self,
        query: JobQueryDto,
    ) -> Result<(Vec<JobVo>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let (rows, total) = self
            .job_repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                query.job_name.as_deref(),
                query.job_group.as_deref(),
                query.status.as_deref(),
            )
            .await?;

        let vos = rows.into_iter().map(JobVo::from_model).collect();
        Ok((vos, total))
    }

    /// 查询任务详情
    pub async fn get_job_by_id(&self, job_id: i64) -> Result<JobVo, ServiceError> {
        let job = self
            .job_repo
            .find_active_by_id(job_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;
        Ok(JobVo::from_model(job))
    }

    /// 新增任务
    ///
    /// 1. 校验 DTO
    /// 2. 校验 cron 合法性
    /// 3. job_name + job_group 查重
    /// 4. INSERT
    /// 5. 若 status='0' 调用 scheduler.add_job
    pub async fn add_job(
        &self,
        dto: JobAddDto,
        operator: &str,
    ) -> Result<SysJobModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        // P3 修复: 枚举值白名单校验
        validate_job_enum(
            dto.misfire_policy.as_deref(),
            dto.concurrent.as_deref(),
            dto.status.as_deref(),
        )?;

        // cron 合法性校验
        if calc_next_valid_time(&dto.cron_expression).is_none() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.job.cron_invalid"
            )));
        }

        // 查重
        if let Some(_existing) = self
            .job_repo
            .find_by_name_and_group(&dto.job_name, &dto.job_group)
            .await?
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.job.name_exists"
            )));
        }

        let status = dto.status.unwrap_or_else(|| "0".to_string());
        let model = sys_job::ActiveModel {
            job_name: Set(dto.job_name),
            job_group: Set(dto.job_group),
            invoke_target: Set(dto.invoke_target),
            cron_expression: Set(Some(dto.cron_expression)),
            misfire_policy: Set(Some(dto.misfire_policy.unwrap_or_else(|| "3".to_string()))),
            concurrent: Set(Some(dto.concurrent.unwrap_or_else(|| "1".to_string()))),
            status: Set(Some(status.clone())),
            create_by: Set(Some(operator.to_string())),
            remark: Set(dto.remark),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        };

        let job = self.job_repo.insert(model).await?;

        // status='0' 时注册到调度器（容错：失败仅 warn，不阻断 DB 已提交的插入）
        // 与 edit_job/delete_jobs/change_status 保持一致：DB 为 source of truth，重启后调度器从 DB 恢复
        if status == "0"
            && let Err(e) = self.scheduler.add_job(&job).await
        {
            tracing::warn!(
                job_id = job.job_id,
                error = %e,
                "add_job: 调度器 add_job 失败，DB 已插入，重启后调度器从 DB 恢复"
            );
        }

        Ok(job)
    }

    /// 修改任务
    ///
    /// 1. 校验 DTO
    /// 2. 查询任务存在
    /// 3. 校验 cron 合法性
    /// 4. UPDATE
    /// 5. 若 status='0' 调用 scheduler.update_job（若 status='1' 且原 status='0' 调用 scheduler.remove_job）
    ///
    /// P1 修复: 调度器同步失败时仅记录 warn 不阻断，DB 为 source of truth，
    /// 重启后调度器从 DB 加载正确状态。与 delete_jobs/change_status 保持一致的容错策略。
    pub async fn edit_job(
        &self,
        dto: JobEditDto,
        operator: &str,
    ) -> Result<SysJobModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        // P3 修复: 枚举值白名单校验
        validate_job_enum(
            dto.misfire_policy.as_deref(),
            dto.concurrent.as_deref(),
            dto.status.as_deref(),
        )?;

        let existing = self
            .job_repo
            .find_active_by_id(dto.job_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;

        // cron 合法性校验
        if calc_next_valid_time(&dto.cron_expression).is_none() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.job.cron_invalid"
            )));
        }

        let old_status = existing.status.as_deref().unwrap_or("0").to_string();
        let new_status = dto.status.unwrap_or_else(|| old_status.clone());

        let model = sys_job::ActiveModel {
            job_id: Set(dto.job_id),
            job_name: Set(dto.job_name),
            job_group: Set(dto.job_group),
            invoke_target: Set(dto.invoke_target),
            cron_expression: Set(Some(dto.cron_expression)),
            misfire_policy: Set(Some(dto.misfire_policy.unwrap_or_else(|| "3".to_string()))),
            concurrent: Set(Some(dto.concurrent.unwrap_or_else(|| "1".to_string()))),
            status: Set(Some(new_status.clone())),
            update_by: Set(Some(operator.to_string())),
            remark: Set(dto.remark),
            ..Default::default()
        };

        // DB 更新是主操作，必须成功
        let job = self.job_repo.update(model).await?;

        // 同步调度器（容错：失败仅 warn，不阻断 DB 已提交的修改）
        // 与 delete_jobs/change_status 保持一致：DB 为 source of truth，重启后调度器从 DB 恢复
        if new_status == "0" {
            // 新状态为运行 → 更新调度器（remove + add）
            if let Err(e) = self.scheduler.update_job(&job).await {
                tracing::warn!(
                    job_id = job.job_id,
                    error = %e,
                    "edit_job: 调度器 update_job 失败，DB 已更新，重启后调度器从 DB 恢复"
                );
            }
        } else if old_status == "0" {
            // 旧状态为运行，新状态为暂停 → 移除调度器
            if let Err(e) = self.scheduler.remove_job(job.job_id).await {
                tracing::warn!(
                    job_id = job.job_id,
                    error = %e,
                    "edit_job: 调度器 remove_job 失败，DB 已更新为暂停，重启后生效"
                );
            }
        }

        Ok(job)
    }

    /// 批量删除任务
    ///
    /// 1. 遍历 job_ids
    /// 2. 查询任务存在
    /// 3. 事务内批量 soft_delete（P0-76：原子化，避免部分删除）
    /// 4. 事务提交后移除调度器中的任务（若 status='0'）
    ///
    /// REGRESS-003：软删除时重命名 job_name 为 `{original}_deleted_{job_id}`，
    /// 释放 uk_sys_job_name_group 唯一索引，避免无法重新创建同名任务。
    ///
    /// C-06：job_name 预查询移入事务内，使用同一 conn 查询并执行软删除，
    /// 消除"事务外预查询 → 事务内删除"的 TOCTOU 竞态窗口。
    pub async fn delete_jobs(&self, job_ids: Vec<i64>) -> Result<(), ServiceError> {
        let job_repo = self.job_repo.clone();
        // 事务保证：预查询 + 批量软删除原子化（预查询移入事务内，消除 TOCTOU 竞态 C-06）
        // 事务返回需要从调度器移除的 job_id 列表（status='0' 的任务）
        let to_remove_from_scheduler: Vec<i64> = self
            .db()
            .transaction::<_, Vec<i64>, ServiceError>(|txn| {
                let job_ids_inner = job_ids.clone();
                let mut running_jobs: Vec<i64> = Vec::new();
                async move {
                    for job_id in &job_ids_inner {
                        // 预查询任务存在性及状态（事务内查询，消除 TOCTOU 竞态 C-06）
                        if let Some(job) = job_repo.find_active_by_id_conn(txn, *job_id).await? {
                            let status = job.status.as_deref().unwrap_or("1");
                            if status == "0" {
                                running_jobs.push(*job_id);
                            }
                            let renamed = format!("{}_deleted_{}", job.job_name, job_id);
                            job_repo
                                .soft_delete_with_rename_conn(txn, *job_id, renamed)
                                .await?;
                        }
                    }
                    Ok(running_jobs)
                }
                .boxed()
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Transaction(se) => se,
                sea_orm::TransactionError::Connection(db_err) => {
                    tracing::error!("任务删除事务连接错误: {}", db_err);
                    ServiceError::internal(&crate::tr!("error.common.tx_failed"))
                }
            })?;

        // 事务提交成功后，移除调度器中的任务
        // 若此处失败，任务已在 DB 中软删除，重启后不会加载，不影响一致性
        for job_id in &to_remove_from_scheduler {
            if let Err(e) = self.scheduler.remove_job(*job_id).await {
                tracing::warn!("调度器移除任务失败 job_id={}: {}", job_id, e);
            }
        }
        Ok(())
    }

    /// 切换任务状态
    ///
    /// 0→1: remove_job
    /// 1→0: add_job
    ///
    /// P1 修复: 调度器同步失败时仅记录 warn 不阻断，DB 为 source of truth，
    /// 重启后调度器从 DB 加载正确状态。与 delete_jobs 保持一致的容错策略。
    pub async fn change_status(&self, dto: JobStatusDto) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let existing = self
            .job_repo
            .find_active_by_id(dto.job_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;

        let old_status = existing.status.as_deref().unwrap_or("1").to_string();

        let model = sys_job::ActiveModel {
            job_id: Set(dto.job_id),
            status: Set(Some(dto.status.clone())),
            ..Default::default()
        };

        // DB 更新是主操作，必须成功
        let updated = self.job_repo.update(model).await?;

        // 同步调度器（容错：失败仅 warn，不阻断 DB 已提交的状态变更）
        // 与 delete_jobs 保持一致：DB 为 source of truth，重启后调度器从 DB 恢复
        if old_status == "0" && dto.status == "1" {
            // 运行 → 暂停
            if let Err(e) = self.scheduler.remove_job(dto.job_id).await {
                tracing::warn!(
                    job_id = dto.job_id,
                    error = %e,
                    "change_status: 调度器 remove_job 失败，DB 已更新为暂停，重启后生效"
                );
            }
        } else if old_status == "1" && dto.status == "0" {
            // 暂停 → 运行（P1 修复: 使用更新后的 model 而非 existing，确保字段最新）
            if let Err(e) = self.scheduler.add_job(&updated).await {
                tracing::warn!(
                    job_id = dto.job_id,
                    error = %e,
                    "change_status: 调度器 add_job 失败，DB 已更新为运行，重启后生效"
                );
            }
        }

        Ok(())
    }

    /// 手动执行一次
    ///
    /// 1. 校验 DTO
    /// 2. 查询任务存在
    /// 3. 验证 job_group 一致
    /// 4. scheduler.run_once
    pub async fn run_job_once(&self, dto: JobRunDto) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let job = self
            .job_repo
            .find_active_by_id(dto.job_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;

        // 验证 job_group 一致
        if job.job_group != dto.job_group {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.job.group_mismatch"
            )));
        }

        self.scheduler.run_once(&job).await?;
        Ok(())
    }

    /// 分页查询任务日志
    pub async fn get_job_log_page(
        &self,
        query: JobLogQueryDto,
    ) -> Result<(Vec<SysJobLogModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let (rows, total) = self
            .job_log_repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                query.job_name.as_deref(),
                query.job_group.as_deref(),
                query.status.as_deref(),
                // P1：时间解析统一走 parse_query_date（本地日→UTC），与全项目一致
                match query.begin_time.as_deref() {
                    Some(v) if !v.is_empty() => Some(crate::common::datetime::parse_query_date(v)?),
                    _ => None,
                },
                match query.end_time.as_deref() {
                    Some(v) if !v.is_empty() => Some(crate::common::datetime::parse_query_date(v)?),
                    _ => None,
                },
            )
            .await?;

        Ok((rows, total))
    }

    /// 批量删除任务日志
    pub async fn delete_job_logs(&self, ids: Vec<i64>) -> Result<(), ServiceError> {
        self.job_log_repo.delete_by_ids(ids).await?;
        Ok(())
    }

    /// 清空任务日志
    pub async fn clean_job_logs(&self) -> Result<(), ServiceError> {
        self.job_log_repo.clean_all().await?;
        Ok(())
    }

    /// 导出任务列表（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    pub async fn export_jobs(&self, query: JobQueryDto) -> Result<Vec<JobVo>, ServiceError> {
        let (rows, _) = self
            .job_repo
            .find_page_filtered(
                0,
                crate::common::page::EXPORT_MAX_ROWS,
                query.job_name.as_deref(),
                query.job_group.as_deref(),
                query.status.as_deref(),
            )
            .await?;

        let vos = rows.into_iter().map(JobVo::from_model).collect();
        Ok(vos)
    }

    /// 导出任务日志列表（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    pub async fn export_job_logs(
        &self,
        query: JobLogQueryDto,
    ) -> Result<Vec<SysJobLogModel>, ServiceError> {
        let (rows, _) = self
            .job_log_repo
            .find_page_filtered(
                0,
                crate::common::page::EXPORT_MAX_ROWS,
                query.job_name.as_deref(),
                query.job_group.as_deref(),
                query.status.as_deref(),
                // P1：时间解析统一走 parse_query_date（本地日→UTC）
                match query.begin_time.as_deref() {
                    Some(v) if !v.is_empty() => Some(crate::common::datetime::parse_query_date(v)?),
                    _ => None,
                },
                match query.end_time.as_deref() {
                    Some(v) if !v.is_empty() => Some(crate::common::datetime::parse_query_date(v)?),
                    _ => None,
                },
            )
            .await?;

        Ok(rows)
    }

    /// 获取调度器引用（用于启动初始化时 load_from_db）
    pub fn scheduler(&self) -> &Arc<JobScheduler> {
        &self.scheduler
    }

    /// 获取任务 Repository 引用（用于启动初始化时 load_from_db）
    pub fn job_repo(&self) -> &SysJobRepository {
        &self.job_repo
    }
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_next_valid_time_valid() {
        // 标准 5 段 cron（cron crate 默认 5 段：分 时 日 月 周）
        let result = calc_next_valid_time("0 * * * * *");
        // 验证有效 cron 表达式应返回 Some（避免 if let 静默通过 None）
        assert!(
            result.is_some(),
            "有效 cron 表达式 '0 * * * * *' 应返回 Some"
        );
        // 6 段 cron（含秒）或 5 段 cron，只要能解析就返回 Some
        if let Some(time) = result {
            assert!(time.contains(":"));
            // 时间格式应为 "YYYY-MM-DD HH:MM:SS"
            assert_eq!(
                time.len(),
                19,
                "时间格式应为 YYYY-MM-DD HH:MM:SS（19 字符）"
            );
        }
    }

    #[test]
    fn test_calc_next_valid_time_invalid() {
        let result = calc_next_valid_time("invalid cron expression");
        assert!(result.is_none());
    }

    #[test]
    fn test_job_vo_from_model() {
        let job = SysJobModel {
            job_id: 1,
            job_name: "test".to_string(),
            job_group: "DEFAULT".to_string(),
            invoke_target: "ryTask.ryNoParams".to_string(),
            cron_expression: Some("0 * * * * *".to_string()),
            misfire_policy: Some("3".to_string()),
            concurrent: Some("1".to_string()),
            status: Some("0".to_string()),
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
            del_flag: Some("0".to_string()),
        };

        let vo = JobVo::from_model(job);
        assert_eq!(vo.job.job_id, 1);
        // 验证 from_model 正确传递 job 各字段
        assert_eq!(vo.job.job_name, "test");
        assert_eq!(vo.job.invoke_target, "ryTask.ryNoParams");
        assert_eq!(vo.job.cron_expression, Some("0 * * * * *".to_string()));
        assert_eq!(vo.job.status, Some("0".to_string()));
        // next_valid_time 可能是 Some 或 None（取决于 cron 是否可解析）
        // 但 from_model 不应改变 job 原始字段
    }
}
