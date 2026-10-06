// stepby-axum/src/service/sys_job_service.rs
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
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_job::{self, Column as JobColumn, Model as SysJobModel};
use crate::entity::sys_job_log::{Column as JobLogColumn, Model as SysJobLogModel};
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
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    pub job_name: Option<String>,
    pub job_group: Option<String>,
    pub status: Option<String>,
}

impl From<&JobQueryDto> for PageDomain {
    fn from(dto: &JobQueryDto) -> Self {
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
    /// 校验上限与**列宽**对齐（64）：`m20260719_000001` 已对全部安装形态把该列收窄到 64，
    /// 若此处仍按 255 放行，65~255 字符的表达式会通过校验后落库报错（500）
    #[garde(length(min = 1, max = crate::common::constants::CRON_EXPRESSION_MAX_LEN))]
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
    /// 校验上限与**列宽**对齐（64）——理由同 [`JobAddDto::cron_expression`]
    #[garde(length(min = 1, max = crate::common::constants::CRON_EXPRESSION_MAX_LEN))]
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
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
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

/// 允许排序的任务列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖任务业务展示列（主键、名称、分组、调用目标、cron 表达式、状态、创建时间）；
/// `tenant_id` / `del_flag` / 操作审计列（create_by / update_by / update_time / remark）
/// 等内部列不开放动态排序。
const JOB_SORTABLE_COLUMNS: &[(&str, JobColumn)] = &[
    ("job_id", JobColumn::JobId),
    ("job_name", JobColumn::JobName),
    ("job_group", JobColumn::JobGroup),
    ("invoke_target", JobColumn::InvokeTarget),
    ("cron_expression", JobColumn::CronExpression),
    ("status", JobColumn::Status),
    ("create_time", JobColumn::CreateTime),
];

/// 允许排序的任务日志列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖日志业务展示列（主键、任务名、分组、调用目标、状态、创建时间）；
/// `tenant_id` 与大文本列（job_message / exception_info）不开放动态排序。
const JOB_LOG_SORTABLE_COLUMNS: &[(&str, JobLogColumn)] = &[
    ("job_log_id", JobLogColumn::JobLogId),
    ("job_name", JobLogColumn::JobName),
    ("job_group", JobLogColumn::JobGroup),
    ("invoke_target", JobLogColumn::InvokeTarget),
    ("status", JobLogColumn::Status),
    ("create_time", JobLogColumn::CreateTime),
];

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
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户任务；None（平台 0）不过滤。
    pub async fn get_job_page(
        &self,
        query: JobQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<JobVo>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<sys_job::Entity>(prop, JOB_SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let (rows, total) = self
            .job_repo
            .find_page_filtered(
                offset,
                limit,
                query.job_name.as_deref(),
                query.job_group.as_deref(),
                query.status.as_deref(),
                tenant_scope,
                sort,
            )
            .await?;

        let vos = rows.into_iter().map(JobVo::from_model).collect();
        Ok((vos, total))
    }

    /// 查询任务详情（内部/无操作人上下文：不过滤，如 oper_log 变更前快照）
    ///
    /// 多租户：对外详情接口请使用 `get_job_by_id_scoped`（租户用户跨租户不可见）。
    pub async fn get_job_by_id(&self, job_id: i64) -> Result<JobVo, ServiceError> {
        let job = self
            .job_repo
            .find_active_by_id(job_id, None)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;
        Ok(JobVo::from_model(job))
    }

    /// 查询任务详情（多租户过滤）
    ///
    /// tenant_scope=Some(tid) 时跨租户任务视为不存在（404），避免越权读取详情。
    pub async fn get_job_by_id_scoped(
        &self,
        job_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<JobVo, ServiceError> {
        let job = self
            .job_repo
            .find_active_by_id(job_id, tenant_scope)
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
        operator_tid: i64,
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
            // 多租户 Phase 2：定时任务归属操作者租户（平台管理员=0，租户管理员=其 tid）
            tenant_id: Set(operator_tid),
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

        let job_repo = self.job_repo.clone();
        let txn_result = self
            .db()
            .transaction::<_, SysJobModel, sea_orm::DbErr>(|txn| {
                let job_repo = job_repo.clone();
                let model = model;
                let operator = operator.to_string();
                Box::pin(async move {
                    let job = job_repo.base().insert_conn(txn, model).await?;
                    // 审计合规域：INSERT 变更留痕（同事务提交/回滚，失败令业务一并回滚）
                    crate::service::sys_audit_change_service::audit_insert(
                        txn,
                        "sys_job",
                        &job.job_id.to_string(),
                        &job,
                        None, // add_job 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator.as_str()),
                    )
                    .await?;
                    Ok(job)
                })
            })
            .await;
        let job = txn_result.map_err(ServiceError::from)?;

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
        operator_tid: i64,
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
            .find_active_by_id(dto.job_id, None)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;

        // 多租户越权防护：只能修改本租户任务（平台操作者放行）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        // cron 合法性校验
        if calc_next_valid_time(&dto.cron_expression).is_none() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.job.cron_invalid"
            )));
        }

        let old_status = existing.status.as_deref().unwrap_or("0").to_string();
        let new_status = dto.status.unwrap_or_else(|| old_status.clone());

        // 审计合规域：变更前快照（UPDATE 前取存量行）
        let before_snapshot = serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);

        let model = sys_job::ActiveModel {
            job_id: Set(dto.job_id),
            job_name: Set(dto.job_name),
            job_group: Set(dto.job_group),
            invoke_target: Set(dto.invoke_target),
            cron_expression: Set(Some(dto.cron_expression)),
            // 部分更新语义（2026-09-26 缺陷修复）：未传时保持现值，
            // 而非回落默认 "3"/"1"（否则"只改 cron/名称"的 PUT 会重置错过策略与并发策略）
            misfire_policy: Set(dto
                .misfire_policy
                .or_else(|| existing.misfire_policy.clone())),
            concurrent: Set(dto.concurrent.or_else(|| existing.concurrent.clone())),
            status: Set(Some(new_status.clone())),
            update_by: Set(Some(operator.to_string())),
            remark: Set(dto.remark),
            ..Default::default()
        };

        // DB 更新（事务化 + 审计留痕同事务）
        let job_repo = self.job_repo.clone();
        let txn_result = self
            .db()
            .transaction::<_, SysJobModel, sea_orm::DbErr>(|txn| {
                let job_repo = job_repo.clone();
                let model = model;
                let before_snapshot = before_snapshot.clone();
                let operator = operator.to_string();
                Box::pin(async move {
                    let job = job_repo.base().update_conn(txn, model).await?;
                    // 审计合规域：UPDATE 变更留痕（同事务提交/回滚）
                    crate::service::sys_audit_change_service::audit_update(
                        txn,
                        "sys_job",
                        &job.job_id.to_string(),
                        &before_snapshot,
                        &job,
                        None, // edit_job 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator.as_str()),
                    )
                    .await?;
                    Ok(job)
                })
            })
            .await;
        let job = txn_result.map_err(ServiceError::from)?;

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
    pub async fn delete_jobs(
        &self,
        job_ids: Vec<i64>,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let job_repo = self.job_repo.clone();
        let operator = operator.to_string();
        // 事务保证：预查询 + 批量软删除原子化（预查询移入事务内，消除 TOCTOU 竞态 C-06）
        // 事务返回需要从调度器移除的 job_id 列表（status='0' 的任务）
        let to_remove_from_scheduler: Vec<i64> = self
            .db()
            .transaction::<_, Vec<i64>, ServiceError>(|txn| {
                let job_ids_inner = job_ids.clone();
                let operator = operator.clone();
                let mut running_jobs: Vec<i64> = Vec::new();
                async move {
                    for job_id in &job_ids_inner {
                        // 预查询任务存在性及状态（事务内查询，消除 TOCTOU 竞态 C-06）
                        if let Some(job) = job_repo.find_active_by_id_conn(txn, *job_id).await? {
                            // 多租户越权防护：任一所选任务跨越操作者租户即整体拒绝（平台操作者放行）
                            if !crate::common::tenant::tenant_allowed(operator_tid, job.tenant_id) {
                                return Err(ServiceError::forbidden(&crate::tr!(
                                    "error.common.forbidden"
                                )));
                            }
                            let status = job.status.as_deref().unwrap_or("1");
                            if status == "0" {
                                running_jobs.push(*job_id);
                            }
                            let renamed = format!("{}_deleted_{}", job.job_name, job_id);
                            job_repo
                                .soft_delete_with_rename_conn(txn, *job_id, renamed)
                                .await?;
                            // 审计合规域：DELETE 变更留痕（同事务提交/回滚）
                            crate::service::sys_audit_change_service::audit_delete(
                                txn,
                                "sys_job",
                                &job_id.to_string(),
                                &job,
                                None, // delete_jobs 签名仅携带操作人用户名，ID 由回查补齐
                                Some(operator.as_str()),
                            )
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
    pub async fn change_status(
        &self,
        dto: JobStatusDto,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let existing = self
            .job_repo
            .find_active_by_id(dto.job_id, None)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;

        // 多租户越权防护：只能启停本租户任务（平台操作者放行）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

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
    pub async fn run_job_once(
        &self,
        dto: JobRunDto,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let job = self
            .job_repo
            .find_active_by_id(dto.job_id, None)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.task.not_found")))?;

        // 多租户越权防护：只能手动执行本租户任务（平台操作者放行）
        if !crate::common::tenant::tenant_allowed(operator_tid, job.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

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
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户日志；None（平台 0）不过滤。
    pub async fn get_job_log_page(
        &self,
        query: JobLogQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<SysJobLogModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_job_log::Entity>(
                prop,
                JOB_LOG_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let (rows, total) = self
            .job_log_repo
            .find_page_filtered(
                offset,
                limit,
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
                tenant_scope,
                sort,
            )
            .await?;

        Ok((rows, total))
    }

    /// 批量删除任务日志
    ///
    /// 多租户越权防护：任一所选日志跨越操作者租户即整体拒绝（平台操作者放行）。
    pub async fn delete_job_logs(
        &self,
        ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let existing = self.job_log_repo.find_by_ids(&ids).await?;
        if existing
            .iter()
            .any(|l| !crate::common::tenant::tenant_allowed(operator_tid, l.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        self.job_log_repo.delete_by_ids(ids).await?;
        Ok(())
    }

    /// 清空任务日志
    ///
    /// 多租户隔离：平台操作者清空全部，租户管理员仅清空本租户日志。
    pub async fn clean_job_logs(&self, operator_tid: i64) -> Result<(), ServiceError> {
        self.job_log_repo
            .clean_all(crate::common::tenant::tenant_scope(operator_tid))
            .await?;
        Ok(())
    }

    // ==================== G-09：定时任务运行统计报表 ====================

    /// 运行报表窗口默认天数
    pub const JOB_STATS_DEFAULT_DAYS: u32 = 7;
    /// 运行报表窗口上限天数（防一次性聚合过大窗口）
    pub const JOB_STATS_MAX_DAYS: u32 = 30;
    /// 报表数据源行数上界（防失控表拖垮接口；截断时响应 truncated=true 提示缩小窗口/先清日志）
    const JOB_STATS_MAX_ROWS: u64 = 200_000;

    /// 定时任务运行统计报表（G-09：成功率趋势 / 耗时分布 / 失败 TOP 的数据源）
    ///
    /// 聚合口径：
    /// - 成功/失败按 `status`（"0"/"1"）；
    /// - 耗时聚合只用 `duration_ms` 非 NULL 行（G-09 新列；存量旧行为 NULL，跳过不造假）；
    /// - 按天分桶用**服务器本地日期**（与 `parse_query_date` 的"本地日"过滤口径对称，
    ///   UTC 存储时间经 `Local` 换算归桶）；
    /// - 失败 TOP 取失败次数前 10 的 job_name。
    ///
    /// 多租户：tenant_scope=Some(tid) 仅本租户；None（平台 0）不过滤。
    pub async fn get_job_log_stats(
        &self,
        days: Option<u32>,
        tenant_scope: Option<i64>,
    ) -> Result<JobLogStatsVo, ServiceError> {
        let days = days
            .unwrap_or(Self::JOB_STATS_DEFAULT_DAYS)
            .clamp(1, Self::JOB_STATS_MAX_DAYS);
        // 窗口起点 = 本地今天往前推 (days-1) 天的本地 00:00 对应 UTC 瞬间
        let today_local = chrono::Local::now().date_naive();
        let window_start_local = today_local
            .checked_sub_signed(chrono::Duration::days((days - 1) as i64))
            .ok_or_else(|| ServiceError::bad_request("报表窗口日期计算溢出"))?;
        let begin_utc = window_start_local
            .and_time(chrono::NaiveTime::MIN)
            .and_local_timezone(chrono::Local)
            .single()
            .map(|dt| dt.with_timezone(&chrono::Utc).naive_utc())
            .ok_or_else(|| ServiceError::bad_request("报表窗口日期解析失败"))?;

        let rows = self
            .job_log_repo
            .find_window_for_stats(begin_utc, Self::JOB_STATS_MAX_ROWS, tenant_scope)
            .await?;
        let truncated = rows.len() as u64 >= Self::JOB_STATS_MAX_ROWS;
        let mut vo = aggregate_job_stats(rows, days, today_local);
        vo.truncated = truncated;
        Ok(vo)
    }

    /// 导出任务列表（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅导出本租户任务；None（平台 0）不过滤。
    pub async fn export_jobs(
        &self,
        query: JobQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<JobVo>, ServiceError> {
        // 导出与页面列表同序：动态排序白名单解析口径一致
        let page = PageDomain::from(&query);
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<sys_job::Entity>(prop, JOB_SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let (rows, _) = self
            .job_repo
            .find_page_filtered(
                0,
                crate::common::page::EXPORT_MAX_ROWS,
                query.job_name.as_deref(),
                query.job_group.as_deref(),
                query.status.as_deref(),
                tenant_scope,
                sort,
            )
            .await?;

        let vos = rows.into_iter().map(JobVo::from_model).collect();
        Ok(vos)
    }

    /// 导出任务日志列表（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅导出本租户日志；None（平台 0）不过滤。
    pub async fn export_job_logs(
        &self,
        query: JobLogQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<SysJobLogModel>, ServiceError> {
        // 导出与页面列表同序：动态排序白名单解析口径一致
        let page = PageDomain::from(&query);
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_job_log::Entity>(
                prop,
                JOB_LOG_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
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
                tenant_scope,
                sort,
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
            tenant_id: 0,
            job_id: 1,
            job_name: "test".to_string(),
            job_group: "DEFAULT".to_string(),
            invoke_target: "demoTask.demoNoParams".to_string(),
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
        assert_eq!(vo.job.invoke_target, "demoTask.demoNoParams");
        assert_eq!(vo.job.cron_expression, Some("0 * * * * *".to_string()));
        assert_eq!(vo.job.status, Some("0".to_string()));
        // next_valid_time 可能是 Some 或 None（取决于 cron 是否可解析）
        // 但 from_model 不应改变 job 原始字段
    }
}

// ==================== G-09：运行统计报表 VO 与聚合 ====================

/// 运行报表单日聚合桶
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobStatsDailyVo {
    /// 日期（服务器本地时区 `YYYY-MM-DD`）
    pub date: String,
    /// 当日执行总数
    pub total: u64,
    /// 当日成功数（status="0"）
    pub success: u64,
    /// 当日失败数（status="1"）
    pub failed: u64,
    /// 当日成功率（百分数 0-100，1 位小数；total=0 时为 0.0）
    pub success_rate: f64,
    /// 当日平均耗时 ms（仅 duration_ms 非 NULL 行参与；无样本为 0）
    pub avg_ms: u64,
}

/// 运行报表失败 TOP 条目
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobFailureTopVo {
    pub job_name: String,
    pub failed_count: u64,
}

/// 运行报表总 VO（`GET /monitor/jobLog/stats`）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JobLogStatsVo {
    /// 统计窗口天数（1-30，调用方传参 clamp 后回显）
    pub window_days: u32,
    /// 窗口内日志总数
    pub total: u64,
    /// 窗口内成功总数
    pub success: u64,
    /// 窗口内失败总数
    pub failed: u64,
    /// 总成功率（百分数 0-100，1 位小数；total=0 时为 0.0）
    pub success_rate: f64,
    /// 平均耗时 ms（仅 duration_ms 非 NULL 行参与；无样本为 0）
    pub avg_ms: u64,
    /// 最大单次耗时 ms（仅 duration_ms 非 NULL 行；无样本为 0）
    pub max_ms: u64,
    /// 行数截断标记：数据源达到行数上界时为 true（提示缩小窗口或先清理历史日志）
    pub truncated: bool,
    /// 按天序列（含空天补零，窗口完整连续）
    pub daily: Vec<JobStatsDailyVo>,
    /// 失败 TOP 10（按失败次数降序）
    pub top_failures: Vec<JobFailureTopVo>,
}

/// 纯函数：把窗口内调度日志行按本地日期分桶聚合（G-09）
///
/// 应用层聚合（非 SQL GROUP BY date(...)）：三方言日期函数分叉（SQLite date() /
/// MySQL DATE() / PostgreSQL date_trunc），应用层聚合零方言差异且本纯函数可直接单测；
/// 窗口完整性（空天补零）由 `days` + `today_local` 保证。
/// 耗时聚合只取 `duration_ms` 非 NULL 行（存量旧行为 NULL 跳过，不编造 0 拉低均值）；
/// 负值按脏数据防御性跳过。
fn aggregate_job_stats(
    rows: Vec<SysJobLogModel>,
    days: u32,
    today_local: chrono::NaiveDate,
) -> JobLogStatsVo {
    use std::collections::HashMap;

    /// 单日桶累加器
    struct Bucket {
        total: u64,
        success: u64,
        failed: u64,
        dur_ms_sum: u64,
        dur_samples: u64,
    }
    let mut daily_map: HashMap<chrono::NaiveDate, Bucket> = HashMap::new();
    let mut failure_map: HashMap<String, u64> = HashMap::new();

    let mut total = 0u64;
    let mut success = 0u64;
    let mut failed = 0u64;
    let mut dur_ms_sum = 0u64;
    let mut dur_samples = 0u64;
    let mut max_ms = 0u64;

    for row in rows {
        let is_success = row.status.as_deref() == Some("0");
        let is_failed = row.status.as_deref() == Some("1");
        total += 1;
        if is_success {
            success += 1;
        } else if is_failed {
            failed += 1;
        }
        // 本地日期归桶（UTC 存储时间 → 服务器本地日）
        let local_date = row.create_time.map(|utc_naive| {
            use chrono::TimeZone;
            chrono::Local.from_utc_datetime(&utc_naive).date_naive()
        });
        if let Some(d) = local_date {
            let bucket = daily_map.entry(d).or_insert(Bucket {
                total: 0,
                success: 0,
                failed: 0,
                dur_ms_sum: 0,
                dur_samples: 0,
            });
            bucket.total += 1;
            if is_success {
                bucket.success += 1;
            } else if is_failed {
                bucket.failed += 1;
            }
            if let Some(ms) = row.duration_ms.filter(|v| *v >= 0) {
                bucket.dur_ms_sum += ms as u64;
                bucket.dur_samples += 1;
            }
        }
        if is_failed {
            *failure_map.entry(row.job_name.clone()).or_insert(0) += 1;
        }
        if let Some(ms) = row.duration_ms.filter(|v| *v >= 0) {
            let ms = ms as u64;
            dur_ms_sum += ms;
            dur_samples += 1;
            if ms > max_ms {
                max_ms = ms;
            }
        }
    }

    // 按窗口生成完整日期序列（空天补零）
    let mut daily = Vec::with_capacity(days as usize);
    for i in (0..days).rev() {
        let date = today_local - chrono::Duration::days(i as i64);
        let (b_total, b_success, b_failed, b_sum, b_n) = match daily_map.get(&date) {
            Some(b) => (b.total, b.success, b.failed, b.dur_ms_sum, b.dur_samples),
            None => (0, 0, 0, 0, 0),
        };
        daily.push(JobStatsDailyVo {
            date: date.format("%Y-%m-%d").to_string(),
            total: b_total,
            success: b_success,
            failed: b_failed,
            success_rate: rate_percent(b_success, b_total),
            avg_ms: b_sum.checked_div(b_n).unwrap_or(0),
        });
    }

    // 失败 TOP 10（失败次数降序，次数并列按名称字典序稳定排序）
    let mut top: Vec<(String, u64)> = failure_map.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top.truncate(10);

    JobLogStatsVo {
        window_days: days,
        total,
        success,
        failed,
        success_rate: rate_percent(success, total),
        avg_ms: dur_ms_sum.checked_div(dur_samples).unwrap_or(0),
        max_ms,
        truncated: false,
        daily,
        top_failures: top
            .into_iter()
            .map(|(job_name, failed_count)| JobFailureTopVo {
                job_name,
                failed_count,
            })
            .collect(),
    }
}

/// 成功率（百分数 0-100，1 位小数；total=0 → 0.0）
fn rate_percent(success: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    ((success as f64 / total as f64) * 1000.0).round() / 10.0
}

#[cfg(test)]
mod job_stats_tests {
    use super::*;
    use crate::entity::sys_job_log;

    /// 构造一条调度日志（聚合测试数据源）
    fn log_row(
        job_name: &str,
        status: &str,
        duration_ms: Option<i64>,
        create_time: Option<chrono::NaiveDateTime>,
    ) -> sys_job_log::Model {
        sys_job_log::Model {
            tenant_id: 0,
            job_log_id: 0,
            job_name: job_name.to_string(),
            job_group: "DEFAULT".to_string(),
            invoke_target: "test.target".to_string(),
            job_message: None,
            status: Some(status.to_string()),
            exception_info: None,
            duration_ms,
            create_time,
        }
    }

    #[test]
    fn test_aggregate_basic_rates_and_duration() {
        let now_utc = chrono::Utc::now().naive_utc();
        let rows = vec![
            log_row("job_a", "0", Some(100), Some(now_utc)),
            log_row("job_a", "0", Some(200), Some(now_utc)),
            log_row("job_a", "1", Some(900), Some(now_utc)),
            log_row("job_b", "0", None, Some(now_utc)), // 无耗时样本：不参与 avg
        ];
        let today = chrono::Local::now().date_naive();
        let vo = aggregate_job_stats(rows, 3, today);
        assert_eq!(vo.total, 4);
        assert_eq!(vo.success, 3);
        assert_eq!(vo.failed, 1);
        assert_eq!(vo.success_rate, 75.0);
        // 耗时均值只取 3 个样本：(100+200+900)/3 = 400
        assert_eq!(vo.avg_ms, 400);
        assert_eq!(vo.max_ms, 900);
        // 失败 TOP：job_a 1 次
        assert_eq!(vo.top_failures.len(), 1);
        assert_eq!(vo.top_failures[0].job_name, "job_a");
        // 窗口完整：3 天序列且最后一天 = 今天（4 条全落今日）
        assert_eq!(vo.daily.len(), 3);
        assert_eq!(vo.daily[2].total, 4);
        assert_eq!(vo.daily[2].avg_ms, 400);
        // 空天补零
        assert_eq!(vo.daily[0].total, 0);
        assert_eq!(vo.daily[0].success_rate, 0.0);
    }

    #[test]
    fn test_aggregate_empty_window() {
        let today = chrono::Local::now().date_naive();
        let vo = aggregate_job_stats(Vec::new(), 1, today);
        assert_eq!(vo.total, 0);
        assert_eq!(vo.success_rate, 0.0);
        assert_eq!(vo.avg_ms, 0);
        assert_eq!(vo.max_ms, 0);
        assert_eq!(vo.daily.len(), 1);
        assert!(vo.top_failures.is_empty());
        assert!(!vo.truncated);
    }

    #[test]
    fn test_aggregate_skips_negative_duration() {
        let now_utc = chrono::Utc::now().naive_utc();
        let rows = vec![
            // 未知 status：计数但不入成功/失败；耗时统计独立于 status（成败皆有耗时语义）
            log_row("job_x", "9", Some(50), Some(now_utc)),
            // 负耗时（脏数据）：不参与耗时聚合
            log_row("job_x", "0", Some(-5), Some(now_utc)),
        ];
        let today = chrono::Local::now().date_naive();
        let vo = aggregate_job_stats(rows, 1, today);
        assert_eq!(vo.total, 2);
        assert_eq!(vo.success, 1);
        assert_eq!(vo.failed, 0);
        assert_eq!(
            vo.avg_ms, 50,
            "负耗时脏数据不得参与均值（有效样本仅 50ms 一条）"
        );
        assert_eq!(vo.max_ms, 50);
    }

    #[test]
    fn test_rate_percent_edge() {
        assert_eq!(rate_percent(0, 0), 0.0);
        assert_eq!(rate_percent(1, 3), 33.3);
        assert_eq!(rate_percent(2, 3), 66.7);
        assert_eq!(rate_percent(3, 3), 100.0);
    }
}
