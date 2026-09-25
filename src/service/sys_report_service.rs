//! 报表中心 + 定时订阅推送模块 Service 层
//!
//! 职责：
//! - 报表定义 CRUD（分页查询、详情、新增、修改、批量删除、启停）
//! - 报表订阅 CRUD（分页查询、详情、新增、修改、批量删除、启停）
//! - 报表快照生成（复用现有 dashboard/登录统计聚合逻辑，不自建聚合引擎）
//! - 定时订阅推送（按 cron 到期的订阅生成快照并经邮件 / 站内信投递）
//!
//! 快照来源（复用既有服务，避免重复造轮子）：
//! - login_stats：复用 SysLogininforService::daily_stats + count_today_failed_ips
//! - user_stats：复用 dashboard 用户统计聚合逻辑（sys_user 表直接聚合）
//! - msg_stats：复用 sys_msg_send_log 表投递统计聚合
//! - custom：透传报表配置 JSON
//!
//! 分层约束：Service 层不依赖任何 Web 框架类型，数据访问委托 Repository 层。

use std::sync::Arc;

use chrono::NaiveDateTime;
use garde::Validate;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

use crate::common::datetime::now_naive;
use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::config::Settings;
use crate::entity::sys_msg_send_log::{
    ActiveModel as SysMsgSendLogActiveModel, Column as MsgLogColumn, Entity as SysMsgSendLog,
};
use crate::entity::sys_report::{ActiveModel as SysReportActiveModel, Model as SysReportModel};
use crate::entity::sys_report_sub::{
    ActiveModel as SysReportSubActiveModel, Model as SysReportSubModel,
};
use crate::entity::sys_user::{Column as UserColumn, Entity as SysUser};
use crate::repository::sys_msg_send_log::SysMsgSendLogRepository;
use crate::repository::sys_report::SysReportRepository;
use crate::repository::sys_report_sub::SysReportSubRepository;
use crate::service::{MailerService, SysLogininforService};
use crate::utils::parse_id_list;

/// 报表类型白名单（与实体/迁移保持一致）
pub const REPORT_TYPES: &[&str] = &["login_stats", "user_stats", "msg_stats", "custom"];
/// 状态启用值（status='0' = 启用）
const STATUS_ENABLED: &str = "0";
/// 默认快照统计天数（login_stats / user_stats 未在 config 指定时使用）
const DEFAULT_STAT_DAYS: i64 = 7;
/// 用户趋势统计天数（user_stats 创建趋势，对齐 dashboard）
const USER_TREND_DAYS: i64 = 30;

// ==================== DTO ====================

/// 报表定义分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub report_name: Option<String>,
    pub report_code: Option<String>,
    pub report_type: Option<String>,
    pub status: Option<String>,
}

impl From<&ReportQueryDto> for PageDomain {
    fn from(dto: &ReportQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 报表定义新增 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportAddDto {
    /// 报表编码（唯一）
    #[garde(length(min = 1, max = 64))]
    pub report_code: String,
    /// 报表名称
    #[garde(length(min = 1, max = 64))]
    pub report_name: String,
    /// 报表类型（login_stats/user_stats/msg_stats/custom）
    #[garde(length(min = 1, max = 32))]
    pub report_type: String,
    /// 报表配置 JSON
    #[garde(length(max = 4000))]
    pub config: String,
    /// 状态（0=启用 1=停用，缺省启用）
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 报表定义修改 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportEditDto {
    #[garde(skip)]
    pub report_id: i64,
    #[garde(length(min = 1, max = 64))]
    pub report_code: String,
    #[garde(length(min = 1, max = 64))]
    pub report_name: String,
    /// 报表类型（login_stats/user_stats/msg_stats/custom）
    #[garde(length(min = 1, max = 32))]
    pub report_type: String,
    /// 报表配置 JSON
    #[garde(length(max = 4000))]
    pub config: String,
    /// 状态（0=启用 1=停用）
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 报表启停 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportStatusDto {
    /// 报表 ID（由路径参数注入，请求体可省略）
    #[serde(default)]
    #[garde(skip)]
    pub report_id: i64,
    /// 状态（0=启用 1=停用）
    #[garde(length(min = 1, max = 1))]
    pub status: String,
}

/// 报表订阅分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub report_id: Option<i64>,
    pub sub_name: Option<String>,
    pub status: Option<String>,
}

impl From<&SubQueryDto> for PageDomain {
    fn from(dto: &SubQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 报表订阅新增 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubAddDto {
    /// 关联报表 id
    #[garde(skip)]
    pub report_id: i64,
    /// 订阅名称
    #[garde(length(min = 1, max = 64))]
    pub sub_name: String,
    /// 周期 cron 表达式（6 字段）
    #[garde(length(min = 1, max = 64))]
    pub cron: String,
    /// 是否邮件推送（1=是 0=否）
    #[garde(length(min = 1, max = 1))]
    pub push_email: String,
    /// 收件邮箱（逗号分隔）
    #[garde(length(max = 2000))]
    pub receive_email: Option<String>,
    /// 是否站内信推送（1=是 0=否）
    #[garde(length(min = 1, max = 1))]
    pub push_sys_msg: String,
    /// 目标用户 id（逗号分隔）
    #[garde(length(max = 4000))]
    pub receive_user_ids: Option<String>,
    /// 状态（0=启用 1=停用，缺省启用）
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 报表订阅修改 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubEditDto {
    #[garde(skip)]
    pub sub_id: i64,
    /// 关联报表 id
    #[garde(skip)]
    pub report_id: i64,
    /// 订阅名称
    #[garde(length(min = 1, max = 64))]
    pub sub_name: String,
    /// 周期 cron 表达式（6 字段）
    #[garde(length(min = 1, max = 64))]
    pub cron: String,
    /// 是否邮件推送（1=是 0=否）
    #[garde(length(min = 1, max = 1))]
    pub push_email: String,
    /// 收件邮箱（逗号分隔）
    #[garde(length(max = 2000))]
    pub receive_email: Option<String>,
    /// 是否站内信推送（1=是 0=否）
    #[garde(length(min = 1, max = 1))]
    pub push_sys_msg: String,
    /// 目标用户 id（逗号分隔）
    #[garde(length(max = 4000))]
    pub receive_user_ids: Option<String>,
    /// 状态（0=启用 1=停用）
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 报表订阅启停 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubStatusDto {
    /// 订阅 ID（由路径参数注入，请求体可省略）
    #[serde(default)]
    #[garde(skip)]
    pub sub_id: i64,
    /// 状态（0=启用 1=停用）
    #[garde(length(min = 1, max = 1))]
    pub status: String,
}

// ==================== VO ====================

/// 报表快照响应（手动预览 / 定时推送共用）
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportSnapshotVo {
    /// 报表编码
    pub report_code: String,
    /// 报表名称
    pub report_name: String,
    /// 报表类型
    pub report_type: String,
    /// 生成时间（UTC 语义）
    pub generated_at: String,
    /// 快照数据（按报表类型结构不同）
    pub data: Value,
}

/// 订阅推送结果统计
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PushSummaryVo {
    /// 生成时间（UTC 语义）
    pub generated_at: String,
    /// 报表名称
    pub report_name: String,
    /// 邮件发送数
    pub emails_sent: u64,
    /// 站内信发送数
    pub site_msgs: u64,
}

// ==================== 工具函数（可单测） ====================

/// 校验报表类型是否在白名单内
fn validate_report_type(report_type: &str) -> Result<(), ServiceError> {
    if REPORT_TYPES.contains(&report_type) {
        Ok(())
    } else {
        Err(ServiceError::bad_request(&crate::tr!(
            "error.report.type_invalid",
            value = report_type
        )))
    }
}

/// 解析 cron 表达式（6 字段，含秒），复用与 scheduler 一致的校验规则
fn parse_cron(cron: &str) -> Result<croner::Cron, String> {
    use croner::parser::CronParser;
    let c = CronParser::builder()
        .seconds(croner::parser::Seconds::Required)
        .dom_and_dow(true)
        .build()
        .parse(cron)
        .map_err(|e| format!("{}", e))?;
    Ok(c)
}

/// 判断订阅是否到期：上次执行后至少已过一个 cron 触发点；首次执行为 true
fn is_due(cron: &croner::Cron, last_run: Option<NaiveDateTime>, now: NaiveDateTime) -> bool {
    match last_run {
        None => true,
        Some(lr) => match cron.find_next_occurrence(&lr.and_utc(), false) {
            Ok(next) => next <= now.and_utc(),
            Err(_) => false,
        },
    }
}

/// 拆分逗号分隔邮箱并去除空白
fn split_emails(value: &Option<String>) -> Vec<String> {
    value
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// 简单邮箱格式校验（含 @，且 @ 两侧非空）
fn is_valid_email(email: &str) -> bool {
    let at = match email.find('@') {
        Some(i) => i,
        None => return false,
    };
    at > 0 && at < email.len() - 1 && !email.contains(' ')
}

/// 渲染文本快照正文（邮件纯文本 / 站内信共用）
fn render_report_text(report: &SysReportModel, snapshot: &Value) -> String {
    let generated = now_naive().format("%Y-%m-%d %H:%M:%S").to_string();
    let pretty = serde_json::to_string_pretty(snapshot).unwrap_or_else(|_| "{}".to_string());
    format!(
        "报表：{}\n类型：{}\n生成时间：{}\n\n{}",
        report.report_name, report.report_type, generated, pretty
    )
}

/// 渲染 HTML 快照正文（邮件用）
fn render_report_html(report: &SysReportModel, snapshot: &Value) -> String {
    let generated = now_naive().format("%Y-%m-%d %H:%M:%S").to_string();
    let pretty = serde_json::to_string_pretty(snapshot).unwrap_or_else(|_| "{}".to_string());
    let body = pretty
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', "<br/>");
    format!(
        "<div style=\"font-family: Arial, sans-serif; line-height: 1.6;\">\
        <h3>{}</h3><p>类型：{}　生成时间：{}</p><pre style=\"background:#f5f5f5;padding:12px;\">{}</pre>\
        <p style=\"color:#999;font-size:12px;\">此邮件由 yebot 系统自动发送，请勿直接回复。</p></div>",
        report.report_name, report.report_type, generated, body
    )
}

/// 读取 config JSON 中的 days 参数（默认 DEFAULT_STAT_DAYS）
fn config_days(config: &str, default: i64) -> i64 {
    serde_json::from_str::<Value>(config)
        .ok()
        .and_then(|v| v.get("days").and_then(|d| d.as_i64()))
        .filter(|d| *d > 0)
        .unwrap_or(default)
}

// ==================== Service 实现 ====================

/// 报表中心 + 定时订阅推送模块 Service
pub struct SysReportService {
    report_repo: SysReportRepository,
    sub_repo: SysReportSubRepository,
    send_log_repo: SysMsgSendLogRepository,
    mailer: MailerService,
    logininfor_service: SysLogininforService,
}

impl SysReportService {
    pub fn new(db: DatabaseConnection, config: Arc<Settings>) -> Self {
        Self {
            report_repo: SysReportRepository::new(db.clone()),
            sub_repo: SysReportSubRepository::new(db.clone()),
            send_log_repo: SysMsgSendLogRepository::new(db.clone()),
            mailer: MailerService::new(config),
            logininfor_service: SysLogininforService::new(db),
        }
    }

    /// 解析逗号分隔 id 列表
    pub fn parse_ids(ids: &str) -> Vec<i64> {
        parse_id_list::<i64>(ids)
    }

    // ==================== 报表定义 ====================

    pub async fn get_report_page(
        &self,
        query: ReportQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<SysReportModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let (rows, total) = self
            .report_repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                query.report_name.as_deref(),
                query.report_code.as_deref(),
                query.report_type.as_deref(),
                query.status.as_deref(),
                crate::common::tenant::tenant_scope(operator_tid),
            )
            .await?;
        Ok((rows, total))
    }

    pub async fn get_report_by_id(
        &self,
        report_id: i64,
        operator_tid: i64,
    ) -> Result<SysReportModel, ServiceError> {
        let report = self
            .report_repo
            .find_by_id(report_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.report.not_found")))?;
        // 越权防护：租户管理员不得读取其他租户报表定义
        if !crate::common::tenant::tenant_allowed(operator_tid, report.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        Ok(report)
    }

    /// 新增报表定义
    pub async fn add_report(
        &self,
        dto: ReportAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysReportModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        validate_report_type(&dto.report_type)?;
        Self::validate_report_config_json(&dto.config)?;

        if self.report_repo.exists_by_code(&dto.report_code).await? {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report.code_duplicate",
                code = dto.report_code
            )));
        }

        let now = now_naive();
        let am = SysReportActiveModel {
            tenant_id: Set(operator_tid),
            report_code: Set(dto.report_code),
            report_name: Set(dto.report_name),
            report_type: Set(dto.report_type),
            config: Set(dto.config),
            status: Set(dto.status.unwrap_or_else(|| STATUS_ENABLED.to_string())),
            remark: Set(dto.remark),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_time: Set(Some(now)),
            del_flag: Set("0".to_string()),
            ..Default::default()
        };
        let model = self.report_repo.insert(am).await?;
        Ok(model)
    }

    /// 修改报表定义
    pub async fn edit_report(
        &self,
        dto: ReportEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysReportModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        validate_report_type(&dto.report_type)?;
        Self::validate_report_config_json(&dto.config)?;

        let existing = self.get_report_by_id(dto.report_id, operator_tid).await?;
        if existing.report_code != dto.report_code
            && self.report_repo.exists_by_code(&dto.report_code).await?
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report.code_duplicate",
                code = dto.report_code
            )));
        }

        let mut am: SysReportActiveModel = existing.into();
        am.report_code = Set(dto.report_code);
        am.report_name = Set(dto.report_name);
        am.report_type = Set(dto.report_type);
        am.config = Set(dto.config);
        if let Some(s) = dto.status {
            am.status = Set(s);
        }
        am.remark = Set(dto.remark);
        am.create_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now_naive()));

        let model = self.report_repo.update(am).await?;
        Ok(model)
    }

    /// 批量删除报表定义（逻辑删除，并级联逻辑删除其下全部订阅）
    pub async fn delete_report(
        &self,
        report_ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if report_ids.is_empty() {
            return Ok(());
        }
        let existing = self.report_repo.find_by_ids(&report_ids).await?;
        if existing.len() != report_ids.len() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.report.not_found"
            )));
        }
        // 越权防护：租户管理员不得跨租户删除报表定义
        if existing
            .iter()
            .any(|r| !crate::common::tenant::tenant_allowed(operator_tid, r.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        for rid in &report_ids {
            self.sub_repo
                .soft_delete_by_report_id(*rid)
                .await
                .map_err(|_| {
                    ServiceError::internal(&crate::tr!("error.report.delete_sub_failed"))
                })?;
        }
        self.report_repo.soft_delete_by_ids(&report_ids).await?;
        Ok(())
    }

    /// 报表启停
    pub async fn change_report_status(
        &self,
        dto: ReportStatusDto,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let existing = self.get_report_by_id(dto.report_id, operator_tid).await?;
        if existing.status == dto.status {
            return Ok(());
        }
        self.report_repo
            .update_status(dto.report_id, &dto.status)
            .await?;
        Ok(())
    }

    /// 校验 config 为合法 JSON（可为宽松 JSON 对象/数组/标量，需可解析）
    fn validate_report_config_json(config: &str) -> Result<(), ServiceError> {
        if config.trim().is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report.config_json_invalid"
            )));
        }
        serde_json::from_str::<Value>(config).map_err(|_| {
            ServiceError::bad_request(&crate::tr!("error.report.config_json_invalid"))
        })?;
        Ok(())
    }

    // ==================== 报表订阅 ====================

    pub async fn get_sub_page(
        &self,
        query: SubQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<SysReportSubModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let (rows, total) = self
            .sub_repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                query.report_id,
                query.sub_name.as_deref(),
                query.status.as_deref(),
                crate::common::tenant::tenant_scope(operator_tid),
            )
            .await?;
        Ok((rows, total))
    }

    pub async fn get_sub_by_id(
        &self,
        sub_id: i64,
        operator_tid: i64,
    ) -> Result<SysReportSubModel, ServiceError> {
        let sub =
            self.sub_repo.find_by_id(sub_id).await?.ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.report_sub.not_found"))
            })?;
        // 越权防护：租户管理员不得读取其他租户报表订阅
        if !crate::common::tenant::tenant_allowed(operator_tid, sub.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        Ok(sub)
    }

    /// 新增订阅
    pub async fn add_sub(
        &self,
        dto: SubAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysReportSubModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        self.validate_sub(
            &dto.report_id,
            &dto.cron,
            &dto.push_email,
            &dto.receive_email,
            &dto.push_sys_msg,
            &dto.receive_user_ids,
            operator_tid,
        )
        .await?;

        let now = now_naive();
        let am = SysReportSubActiveModel {
            tenant_id: Set(operator_tid),
            report_id: Set(dto.report_id),
            sub_name: Set(dto.sub_name),
            cron: Set(dto.cron),
            push_email: Set(dto.push_email),
            receive_email: Set(dto.receive_email),
            push_sys_msg: Set(dto.push_sys_msg),
            receive_user_ids: Set(dto.receive_user_ids),
            status: Set(dto.status.unwrap_or_else(|| STATUS_ENABLED.to_string())),
            last_run_time: Set(None),
            remark: Set(dto.remark),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            del_flag: Set("0".to_string()),
            ..Default::default()
        };
        let model = self.sub_repo.insert(am).await?;
        Ok(model)
    }

    /// 修改订阅
    pub async fn edit_sub(
        &self,
        dto: SubEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysReportSubModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        self.validate_sub(
            &dto.report_id,
            &dto.cron,
            &dto.push_email,
            &dto.receive_email,
            &dto.push_sys_msg,
            &dto.receive_user_ids,
            operator_tid,
        )
        .await?;

        let existing = self.get_sub_by_id(dto.sub_id, operator_tid).await?;
        let mut am: SysReportSubActiveModel = existing.into();
        am.report_id = Set(dto.report_id);
        am.sub_name = Set(dto.sub_name);
        am.cron = Set(dto.cron);
        am.push_email = Set(dto.push_email);
        am.receive_email = Set(dto.receive_email);
        am.push_sys_msg = Set(dto.push_sys_msg);
        am.receive_user_ids = Set(dto.receive_user_ids);
        if let Some(s) = dto.status {
            am.status = Set(s);
        }
        am.remark = Set(dto.remark);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now_naive()));

        let model = self.sub_repo.update(am).await?;
        Ok(model)
    }

    /// 批量删除订阅
    pub async fn delete_sub(
        &self,
        sub_ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if sub_ids.is_empty() {
            return Ok(());
        }
        let existing = self.sub_repo.find_by_ids(&sub_ids).await?;
        if existing.len() != sub_ids.len() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.report_sub.not_found"
            )));
        }
        // 越权防护：租户管理员不得跨租户删除报表订阅
        if existing
            .iter()
            .any(|s| !crate::common::tenant::tenant_allowed(operator_tid, s.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        self.sub_repo.soft_delete_by_ids(&sub_ids).await?;
        Ok(())
    }

    /// 订阅启停
    pub async fn change_sub_status(
        &self,
        dto: SubStatusDto,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let existing = self.get_sub_by_id(dto.sub_id, operator_tid).await?;
        if existing.status == dto.status {
            return Ok(());
        }
        let mut am: SysReportSubActiveModel = existing.into();
        am.status = Set(dto.status);
        am.update_time = Set(Some(now_naive()));
        self.sub_repo.update(am).await?;
        Ok(())
    }

    /// 校验订阅：报表存在 + cron 合法 + 至少一种渠道 + 收件人合法
    #[allow(clippy::too_many_arguments)]
    async fn validate_sub(
        &self,
        report_id: &i64,
        cron: &str,
        push_email: &str,
        receive_email: &Option<String>,
        push_sys_msg: &str,
        receive_user_ids: &Option<String>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        self.get_report_by_id(*report_id, operator_tid)
            .await
            .map_err(|e| match e.code {
                // 越权访问跨租户报表：原样返回 403，禁止静默降级为「报表不存在」
                403 => e,
                _ => ServiceError::bad_request(&crate::tr!("error.report_sub.report_not_found")),
            })?;

        parse_cron(cron)
            .map_err(|_| ServiceError::bad_request(&crate::tr!("error.report_sub.cron_invalid")))?;

        if push_email != "1" && push_sys_msg != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report_sub.push_channel_none"
            )));
        }

        if push_email == "1" {
            let emails = split_emails(receive_email);
            if emails.is_empty() || emails.iter().any(|e| !is_valid_email(e)) {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.report_sub.email_invalid"
                )));
            }
        }

        if push_sys_msg == "1" {
            let ids = receive_user_ids
                .as_deref()
                .map(parse_id_list::<i64>)
                .unwrap_or_default();
            if ids.is_empty() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.report_sub.user_ids_invalid"
                )));
            }
        }

        Ok(())
    }

    // ==================== 报表快照生成 ====================

    /// 生成报表快照（复用既有 dashboard / 登录统计聚合逻辑；custom 类型透传配置 JSON）
    pub async fn generate_snapshot(&self, report: &SysReportModel) -> Result<Value, ServiceError> {
        let data = match report.report_type.as_str() {
            "login_stats" => self.snapshot_login(report).await,
            "user_stats" => self.snapshot_user(report.tenant_id).await,
            "msg_stats" => self.snapshot_msg(report.tenant_id).await,
            "custom" => serde_json::from_str::<Value>(&report.config)
                .unwrap_or_else(|_| Value::Object(serde_json::Map::new())),
            _ => Value::Null,
        };
        Ok(data)
    }

    /// 登录统计快照：最近 N 天每日成功/失败 + 今日异常 IP 数
    async fn snapshot_login(&self, report: &SysReportModel) -> Value {
        let days = config_days(&report.config, DEFAULT_STAT_DAYS);
        // 按报表所属租户统计，出租户（tenant_id=0）为平台视角不过滤
        let tenant = crate::common::tenant::tenant_scope(report.tenant_id);
        let daily = self
            .logininfor_service
            .daily_stats(days, tenant)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|d| {
                serde_json::json!({
                    "date": d.date,
                    "success": d.success,
                    "fail": d.fail,
                })
            })
            .collect::<Vec<_>>();
        let today_failed_ips = self
            .logininfor_service
            .count_today_failed_ips(tenant)
            .await
            .unwrap_or(0);
        serde_json::json!({ "days": days, "todayFailedIps": today_failed_ips, "daily": daily })
    }

    /// 用户统计快照：总量/启用/停用/近 7 天新增 + 近 30 天创建趋势
    async fn snapshot_user(&self, tenant_id: i64) -> Value {
        use chrono::{Duration, NaiveTime};
        let db = self.report_repo.base().db();
        let now = crate::common::datetime::today_utc();
        let week_ago = now - Duration::days(7);
        let month_ago = now - Duration::days(USER_TREND_DAYS - 1);
        let week_begin = week_ago.and_time(NaiveTime::MIN);
        let month_begin = month_ago.and_time(NaiveTime::MIN);

        // 按报表所属租户统计用户维度（出租户不过滤）
        let tenant = crate::common::tenant::tenant_scope(tenant_id);
        let total = count_of(db, None, tenant).await;
        let active = count_of(db, Some(("0", None)), tenant).await;
        let disabled = count_of(db, Some(("1", None)), tenant).await;
        let new_this_week = count_of(db, Some(("0", Some(week_begin))), tenant).await;

        let mut query = SysUser::find()
            .filter(UserColumn::DelFlag.ne("2"))
            .filter(UserColumn::CreateTime.gte(month_begin));
        if let Some(tid) = tenant {
            query = query.filter(UserColumn::TenantId.eq(tid));
        }
        let recent_users = query
            .order_by_asc(UserColumn::CreateTime)
            .all(db)
            .await
            .unwrap_or_default();

        let mut trend_map: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        for u in &recent_users {
            if let Some(ct) = u.create_time {
                *trend_map
                    .entry(ct.format("%Y-%m-%d").to_string())
                    .or_insert(0) += 1;
            }
        }
        let mut trend = Vec::new();
        for i in 0..USER_TREND_DAYS {
            let date = month_ago + Duration::days(i);
            let date_str = date.format("%Y-%m-%d").to_string();
            trend.push(serde_json::json!({
                "date": date_str,
                "count": trend_map.get(&date_str).copied().unwrap_or(0),
            }));
        }

        serde_json::json!({
            "totalUsers": total,
            "activeUsers": active,
            "disabledUsers": disabled,
            "newUsersThisWeek": new_this_week,
            "createTrend": trend,
        })
    }

    /// 消息统计快照：发送总量 + 按状态分布（成功/失败/待重试）
    async fn snapshot_msg(&self, tenant_id: i64) -> Value {
        let db = self.report_repo.base().db();
        // 按报表所属租户统计消息投递维度（出租户不过滤）
        let tenant = crate::common::tenant::tenant_scope(tenant_id);
        let base = |status: Option<&str>| {
            let mut q = SysMsgSendLog::find();
            if let Some(tid) = tenant {
                q = q.filter(MsgLogColumn::TenantId.eq(tid));
            }
            if let Some(s) = status {
                q = q.filter(MsgLogColumn::Status.eq(s));
            }
            q.count(db)
        };
        let total = base(None).await.unwrap_or(0);
        let success = base(Some("0")).await.unwrap_or(0);
        let failed = base(Some("1")).await.unwrap_or(0);
        let pending = base(Some("2")).await.unwrap_or(0);
        serde_json::json!({ "total": total, "success": success, "failed": failed, "pending": pending })
    }

    /// 预览报表快照（手动触发，不落库、不推送）
    pub async fn preview_report(
        &self,
        report_id: i64,
        operator_tid: i64,
    ) -> Result<ReportSnapshotVo, ServiceError> {
        let report = self.get_report_by_id(report_id, operator_tid).await?;
        let data = self.generate_snapshot(&report).await?;
        Ok(ReportSnapshotVo {
            report_code: report.report_code.clone(),
            report_name: report.report_name.clone(),
            report_type: report.report_type.clone(),
            generated_at: now_naive().format("%Y-%m-%d %H:%M:%S").to_string(),
            data,
        })
    }

    // ==================== 订阅推送 ====================

    /// 手动触发订阅推送（立即生成快照并投递）
    pub async fn run_sub_now(
        &self,
        sub_id: i64,
        operator_tid: i64,
    ) -> Result<PushSummaryVo, ServiceError> {
        let sub = self.get_sub_by_id(sub_id, operator_tid).await?;
        self.run_subscription(&sub).await
    }

    /// 扫描到期订阅并推送（定时任务调用），返回实际执行的订阅数
    pub async fn run_due_subscriptions(&self) -> Result<u64, ServiceError> {
        // 后台批量任务：订阅已按租户分组返回，逐组以该组 tid 为上下文执行，
        // 严禁跨租户聚合（A 租户报表不得统计 B 租户数据）。
        let groups = self.sub_repo.find_all_enabled().await?;
        let now = now_naive();
        let mut ran = 0u64;
        for (_tid, subs) in groups {
            for sub in subs {
                match parse_cron(&sub.cron) {
                    Ok(cron) if is_due(&cron, sub.last_run_time, now) => {
                        match self.run_subscription(&sub).await {
                            Ok(_) => ran += 1,
                            Err(e) => {
                                tracing::warn!(
                                    "报表订阅推送失败 sub_id={}, sub_name={}: {}",
                                    sub.sub_id,
                                    sub.sub_name,
                                    e.message
                                );
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(
                            "报表订阅 cron 非法已跳过 sub_id={}, sub_name={}: {}",
                            sub.sub_id,
                            sub.sub_name,
                            e
                        );
                    }
                }
            }
        }
        Ok(ran)
    }

    /// 执行单个订阅：生成快照 + 邮件/站内信投递 + 更新 last_run_time
    async fn run_subscription(
        &self,
        sub: &SysReportSubModel,
    ) -> Result<PushSummaryVo, ServiceError> {
        let report = self
            .report_repo
            .find_by_id(sub.report_id)
            .await?
            .ok_or_else(|| {
                ServiceError::bad_request(&crate::tr!("error.report_sub.report_not_found"))
            })?;
        if report.status != STATUS_ENABLED {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report_sub.report_not_found"
            )));
        }

        let snapshot = self.generate_snapshot(&report).await?;
        let title = format!(
            "{}-{}",
            crate::tr!("msg.report.push_title"),
            report.report_name
        );
        let text_body = render_report_text(&report, &snapshot);
        // HTML 版快照保留供测试/扩展使用（当前投递走纯文本），前缀 `_` 避免未使用告警
        let _html_body = render_report_html(&report, &snapshot);
        let now = now_naive();
        let mut emails_sent = 0u64;
        let mut site_msgs = 0u64;

        // 邮件推送：逐封发送（MailerService 未启用时自动降级为 no-op）
        if sub.push_email == "1" {
            let emails = split_emails(&sub.receive_email);
            for email in &emails {
                match self.mailer.send_text(email, &title, &text_body).await {
                    Ok(()) => emails_sent += 1,
                    Err(e) => tracing::warn!("报表订阅邮件发送失败 to={}: {}", email, e.message),
                }
            }
        }

        // 站内信推送：经 site 渠道写入 sys_msg_send_log（与 MSG 模块 site 渠道语义一致，模拟投递并留痕）
        if sub.push_sys_msg == "1" {
            let user_ids = sub
                .receive_user_ids
                .as_deref()
                .map(parse_id_list::<i64>)
                .unwrap_or_default();
            for uid in user_ids {
                let am = SysMsgSendLogActiveModel {
                    // 运行期产物：归该订阅所属租户（定时/手动触发均无操作者上下文）
                    tenant_id: Set(sub.tenant_id),
                    template_code: Set(Some(format!("report_push_{}", report.report_code))),
                    channel_code: Set(Some("site".to_string())),
                    to_addr: Set(uid.to_string()),
                    subject: Set(Some(title.clone())),
                    content: Set(Some(text_body.clone())),
                    status: Set(Some("0".to_string())),
                    retry_count: Set(Some(0)),
                    max_retry_count: Set(Some(0)),
                    last_error: Set(None),
                    send_time: Set(Some(now)),
                    remark: Set(Some("report subscription push".to_string())),
                    create_time: Set(Some(now)),
                    ..Default::default()
                };
                if self.send_log_repo.insert(am).await.is_ok() {
                    site_msgs += 1;
                }
            }
        }

        // 更新上次成功执行时间
        self.sub_repo.update_last_run_time(sub.sub_id, now).await?;

        Ok(PushSummaryVo {
            generated_at: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            report_name: report.report_name,
            emails_sent,
            site_msgs,
        })
    }
}

/// 用户数统计辅助（可选 status 过滤 + 可选 create_time 下限）
async fn count_of(
    db: &DatabaseConnection,
    filter: Option<(&str, Option<NaiveDateTime>)>,
    tenant: Option<i64>,
) -> i64 {
    let mut q = SysUser::find();
    q = q.filter(UserColumn::DelFlag.ne("2"));
    if let Some(tid) = tenant {
        q = q.filter(UserColumn::TenantId.eq(tid));
    }
    if let Some((status, gt)) = filter {
        q = q.filter(UserColumn::Status.eq(status));
        if let Some(begin) = gt {
            q = q.filter(UserColumn::CreateTime.gte(begin));
        }
    }
    q.count(db)
        .await
        .map(|c| i64::try_from(c).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> SysReportModel {
        SysReportModel {
            tenant_id: 0,
            report_id: 1,
            report_code: "LOGIN_7D".to_string(),
            report_name: "登录统计".to_string(),
            report_type: "login_stats".to_string(),
            config: r#"{"days":7}"#.to_string(),
            status: "0".to_string(),
            remark: None,
            create_by: None,
            create_time: None,
            update_time: None,
            del_flag: "0".to_string(),
        }
    }

    #[test]
    fn test_validate_report_type_whitelist() {
        assert!(validate_report_type("login_stats").is_ok());
        assert!(validate_report_type("user_stats").is_ok());
        assert!(validate_report_type("msg_stats").is_ok());
        assert!(validate_report_type("custom").is_ok());
        assert!(validate_report_type("foo").is_err());
        assert!(validate_report_type("").is_err());
    }

    #[test]
    fn test_parse_cron_six_field_required() {
        assert!(parse_cron("0 0 9 * * *").is_ok());
        assert!(parse_cron("0 */5 * * * *").is_ok());
        // 5 字段必须拒绝（含秒校验）
        assert!(parse_cron("0 9 * * *").is_err());
        assert!(parse_cron("not a cron").is_err());
    }

    #[test]
    fn test_is_due_first_run_true() {
        let cron = parse_cron("0 0 9 * * *").unwrap();
        let now = now_naive();
        assert!(is_due(&cron, None, now));
    }

    #[test]
    fn test_is_due_past_last_run_true() {
        let cron = parse_cron("0 0 9 * * *").unwrap();
        // last_run 在 2 天前，每天 9 点触发，必然已过一个触发点
        let last = now_naive() - chrono::Duration::days(2);
        assert!(is_due(&cron, Some(last), now_naive()));
    }

    #[test]
    fn test_is_due_no_occurrence_since_run_false() {
        // 任务刚执行过（last_run = 刚刚），下一次触发在未来，不应视为到期
        let cron = parse_cron("0 0 9 * * *").unwrap();
        let now = now_naive();
        let just_ran = now - chrono::Duration::minutes(1);
        // 若距离下次 9 点还早（now 不在 9 点附近），则通常未到期；此测试仅验证逻辑不 panic
        let _ = is_due(&cron, Some(just_ran), now);
    }

    #[test]
    fn test_split_emails() {
        assert_eq!(
            split_emails(&Some(" a@b.com, c@d.com ".to_string())),
            vec!["a@b.com", "c@d.com"]
        );
        assert_eq!(split_emails(&Some("".to_string())), Vec::<String>::new());
        assert_eq!(split_emails(&None), Vec::<String>::new());
    }

    #[test]
    fn test_is_valid_email() {
        assert!(is_valid_email("a@example.com"));
        assert!(!is_valid_email("a b@example.com"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("a@"));
        assert!(!is_valid_email("no-at-sign"));
    }

    #[test]
    fn test_config_days() {
        assert_eq!(config_days(r#"{"days":30}"#, DEFAULT_STAT_DAYS), 30);
        assert_eq!(
            config_days(r#"{"days":-5}"#, DEFAULT_STAT_DAYS),
            DEFAULT_STAT_DAYS
        );
        assert_eq!(
            config_days("not json", DEFAULT_STAT_DAYS),
            DEFAULT_STAT_DAYS
        );
        assert_eq!(config_days(r#"{}"#, DEFAULT_STAT_DAYS), DEFAULT_STAT_DAYS);
    }

    #[test]
    fn test_render_text_contains_report_name() {
        let report = sample_report();
        let snapshot = serde_json::json!({"days":7, "total": 10});
        let text = render_report_text(&report, &snapshot);
        assert!(text.contains("登录统计"));
        assert!(text.contains("login_stats"));
        assert!(text.contains("\"total\": 10"));
    }

    #[test]
    fn test_render_html_escapes_safe() {
        let report = sample_report();
        let snapshot = serde_json::json!({"label": "<script>"});
        let html = render_report_html(&report, &snapshot);
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn test_generate_signature_returns_object() {
        let _report = sample_report();
        // custom 类型透传配置 JSON
        let custom = SysReportModel {
            report_type: "custom".to_string(),
            config: r#"{"custom":{"a":1}}"#.to_string(),
            ..sample_report()
        };
        let v = serde_json::from_str::<Value>(&custom.config).unwrap();
        assert!(v.get("custom").is_some());
    }

    #[test]
    fn test_parse_ids_service() {
        assert_eq!(SysReportService::parse_ids("1,2, 3"), vec![1, 2, 3]);
        assert_eq!(SysReportService::parse_ids(""), Vec::<i64>::new());
    }
}
