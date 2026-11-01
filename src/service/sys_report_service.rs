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
use futures::future::FutureExt;
use garde::Validate;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

use crate::common::datetime::now_naive;
use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::config::Settings;
use crate::entity::sys_msg_send_log::{Column as MsgLogColumn, Entity as SysMsgSendLog};
use crate::entity::sys_report::{
    ActiveModel as SysReportActiveModel, Column as ReportColumn, Model as SysReportModel,
};
use crate::entity::sys_report_sub::{
    ActiveModel as SysReportSubActiveModel, Column as SubColumn, Model as SysReportSubModel,
};
use crate::entity::sys_user::{Column as UserColumn, Entity as SysUser};
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
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    pub report_name: Option<String>,
    pub report_code: Option<String>,
    pub report_type: Option<String>,
    pub status: Option<String>,
}

impl From<&ReportQueryDto> for PageDomain {
    fn from(dto: &ReportQueryDto) -> Self {
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
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    pub report_id: Option<i64>,
    pub sub_name: Option<String>,
    pub status: Option<String>,
}

impl From<&SubQueryDto> for PageDomain {
    fn from(dto: &SubQueryDto) -> Self {
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

/// 解析 cron 表达式（6 字段，含秒），复用与 scheduler 同一入口（含 Quartz 归一）。
fn parse_cron(cron: &str) -> Result<croner::Cron, String> {
    crate::common::cron_compat::parse_cron(cron)
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
        <p style=\"color:#999;font-size:12px;\">此邮件由 stepby 系统自动发送，请勿直接回复。</p></div>",
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

/// 报表定义允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖报表业务展示列；`config` / `tenant_id` / `create_by` / `del_flag` 等内部列不开放动态排序。
const REPORT_SORTABLE_COLUMNS: &[(&str, ReportColumn)] = &[
    ("report_id", ReportColumn::ReportId),
    ("report_code", ReportColumn::ReportCode),
    ("report_name", ReportColumn::ReportName),
    ("report_type", ReportColumn::ReportType),
    ("status", ReportColumn::Status),
    ("create_time", ReportColumn::CreateTime),
];

/// 报表订阅允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖订阅业务展示列；`tenant_id` / `receive_email` / `receive_user_ids` / `del_flag`
/// 等收件人或内部列不开放动态排序（收件人属半敏感信息，避免通过排序侧信道探测）。
const SUB_SORTABLE_COLUMNS: &[(&str, SubColumn)] = &[
    ("sub_id", SubColumn::SubId),
    ("report_id", SubColumn::ReportId),
    ("sub_name", SubColumn::SubName),
    ("cron", SubColumn::Cron),
    ("status", SubColumn::Status),
    ("last_run_time", SubColumn::LastRunTime),
    ("create_time", SubColumn::CreateTime),
];

/// 报表中心 + 定时订阅推送模块 Service
pub struct SysReportService {
    report_repo: SysReportRepository,
    sub_repo: SysReportSubRepository,
    /// 订阅接收人的租户收敛判定用（`find_tenant_ids_by_user_ids` 是唯一读侧通道）
    user_repo: crate::repository::sys_user::SysUserRepository,
    mailer: MailerService,
    logininfor_service: SysLogininforService,
    /// G-16：站内信推送改走统一投递内核（模板渲染 + dispatch + 重试链），不再直插 send_log
    msg_service: crate::service::sys_msg_service::SysMsgService,
}

impl SysReportService {
    pub fn new(db: DatabaseConnection, config: Arc<Settings>) -> Self {
        Self {
            report_repo: SysReportRepository::new(db.clone()),
            sub_repo: SysReportSubRepository::new(db.clone()),
            user_repo: crate::repository::sys_user::SysUserRepository::new(db.clone()),
            mailer: MailerService::new(config.clone()),
            logininfor_service: SysLogininforService::new(db.clone()),
            msg_service: crate::service::sys_msg_service::SysMsgService::new(db, config),
        }
    }

    /// 解析逗号分隔 id 列表（严格：任一项非法即 400，不静默丢弃）
    pub fn parse_ids(ids: &str) -> Result<Vec<i64>, ServiceError> {
        Ok(parse_id_list::<i64>(ids)?)
    }

    // ==================== 报表定义 ====================

    pub async fn get_report_page(
        &self,
        query: ReportQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<SysReportModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_report::Entity>(prop, REPORT_SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
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
                sort,
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
        // b130：先去重保序再判缺失——`?ids=735,735` 是完全合法的幂等请求，
        // 用原始长度当分母会把它判成「不存在」并零删除（台账 b130 §1）。
        let report_ids = crate::common::batch_ids::dedupe_preserving_order(&report_ids);
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
        // E1-f：单事务包络——原实现逐条循环软删订阅 + 再软删报表，中途失败会留下
        // 「部分订阅已删、报表仍在/报表已删、部分订阅残留」的不一致状态。
        // 现将订阅级联软删（一次 IN 批量）与报表软删纳入同一事务，任一步失败整体回滚。
        //
        // b128：`report_code` 是**全局唯一**索引（`report_code VARCHAR(64) NOT NULL UNIQUE`，
        // 唯一索引不看 del_flag），而 `exists_by_code` 只查未删除行 ⇒ 软删行会永久占着
        // 编码，再次新建同 code 报「已存在」而管理端看不到占用者（死路）。软删同时改名释放；
        // 每行新值不同（含主键），无法用一条批量 UPDATE。
        let freed: Vec<(i64, String)> = existing
            .iter()
            .map(|r| {
                (
                    r.report_id,
                    crate::common::soft_delete_key::freed_key(&r.report_code, r.report_id, 64),
                )
            })
            .collect();
        let sub_repo = self.sub_repo.clone();
        let now = crate::common::datetime::now_naive();
        self.report_repo
            .base()
            .db()
            .clone()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                async move {
                    sub_repo
                        .soft_delete_by_report_ids_conn(txn, &report_ids)
                        .await?;
                    for (rid, code) in freed {
                        crate::entity::sys_report::Entity::update_many()
                            .col_expr(
                                crate::entity::sys_report::Column::DelFlag,
                                sea_orm::sea_query::Expr::value("2"),
                            )
                            .col_expr(
                                crate::entity::sys_report::Column::ReportCode,
                                sea_orm::sea_query::Expr::value(code),
                            )
                            .col_expr(
                                crate::entity::sys_report::Column::UpdateTime,
                                sea_orm::sea_query::Expr::value(now),
                            )
                            .filter(crate::entity::sys_report::Column::ReportId.eq(rid))
                            .exec(txn)
                            .await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await?;
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
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_report_sub::Entity>(
                prop,
                SUB_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let (rows, total) = self
            .sub_repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                query.report_id,
                query.sub_name.as_deref(),
                query.status.as_deref(),
                crate::common::tenant::tenant_scope(operator_tid),
                sort,
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
        // b130：先去重保序再判缺失——`?ids=735,735` 是完全合法的幂等请求，
        // 用原始长度当分母会把它判成「不存在」并零删除（台账 b130 §1）。
        let sub_ids = crate::common::batch_ids::dedupe_preserving_order(&sub_ids);
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
    /// 订阅接收人的租户收敛判定（纯函数——**写侧校验与投递侧过滤共用同一谓词**）。
    ///
    /// 立案原因（b89 项 1）：`receive_user_ids` 此前只校验"非空可解析"，投递时逐个
    /// `to_addr = uid` 落 `sys_msg_send_log`，接收人从未按报表/订阅的租户收敛 ⇒ 租户 A
    /// 在订阅里填租户 B 的用户 ID，就把 A 的聚合报表内容投进了 B 的站内信（且 B 从未订阅）。
    /// 这与 b74 B5 立的"先读后派生写的编排里，读侧与写侧必须共用同一租户谓词"是同一条纪律。
    ///
    /// 判定口径三条，逐条都有理由：
    /// - `owned` 来自 `find_tenant_ids_by_user_ids`（已排 `del_flag='2'`）：**查无此人即拒**，
    ///   不"跳过就当没这回事"——把内容投进一个不存在/已删的收件箱，比 400 更难排查；
    /// - 归属用 `tenant_allowed(sub 的 tenant_id, 用户 tenant_id)`，平台（0）代管照常放行；
    /// - 入参去重：`1,1,2` 过去会投两封，去重属派生写的幂等修复。
    pub(crate) fn partition_recipients(
        ids: &[i64],
        owned: &[(i64, i64)],
        tenant_id: i64,
    ) -> (Vec<i64>, Vec<i64>) {
        let mut allowed: Vec<i64> = Vec::new();
        let mut rejected: Vec<i64> = Vec::new();
        for id in ids {
            if allowed.contains(id) || rejected.contains(id) {
                continue;
            }
            match owned.iter().find(|(uid, _)| uid == id) {
                Some((_, tid)) if crate::common::tenant::tenant_allowed(tenant_id, *tid) => {
                    allowed.push(*id)
                }
                _ => rejected.push(*id),
            }
        }
        (allowed, rejected)
    }

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
                .transpose()?
                .unwrap_or_default();
            if ids.is_empty() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.report_sub.user_ids_invalid"
                )));
            }
            // 接收人必须落在本订阅的租户范围内（平台代管 operator_tid=0 时照常放行）
            let owned = self.user_repo.find_tenant_ids_by_user_ids(&ids).await?;
            let (_, rejected) = Self::partition_recipients(&ids, &owned, operator_tid);
            if !rejected.is_empty() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.report_sub.user_ids_foreign"
                )));
            }
        }

        Ok(())
    }

    // ==================== 报表快照生成 ====================

    /// 生成报表快照（复用既有 dashboard / 登录统计聚合逻辑；custom 类型透传配置 JSON）
    ///
    /// 聚合取数失败一律 `?` 上抛：快照里的 0 / 空趋势是**事实**，不能由一次 DB 抖动
    /// 冒充。预览与订阅推送共用本函数，失败时订阅不投递、`last_run_time` 不前进
    /// （否则一封“0 用户 0 消息”的报表会被当成成功投递出去）。
    pub async fn generate_snapshot(&self, report: &SysReportModel) -> Result<Value, ServiceError> {
        let data = match report.report_type.as_str() {
            "login_stats" => self.snapshot_login(report).await?,
            "user_stats" => self.snapshot_user(report.tenant_id).await?,
            "msg_stats" => self.snapshot_msg(report.tenant_id).await?,
            // 配置坏掉不能折成空报表：订阅会发出一张「什么都没有」的报告并推进
            // last_run_time，管理员再也看不到这次失败。落库时已校验过 JSON，
            // 能走到这里说明存量行被外部改坏——按 400 点名理由，让人去修配置。
            "custom" => serde_json::from_str::<Value>(&report.config).map_err(|e| {
                tracing::warn!(
                    report_id = report.report_id,
                    error = %e,
                    "报表 custom 配置解析失败"
                );
                ServiceError::bad_request(&crate::tr!("error.report.config_json_invalid"))
            })?,
            _ => Value::Null,
        };
        Ok(data)
    }

    /// 登录统计快照：最近 N 天每日成功/失败 + 今日异常 IP 数
    async fn snapshot_login(&self, report: &SysReportModel) -> Result<Value, ServiceError> {
        let days = config_days(&report.config, DEFAULT_STAT_DAYS);
        // 按报表所属租户统计，出租户（tenant_id=0）为平台视角不过滤
        let tenant = crate::common::tenant::tenant_scope(report.tenant_id);
        let daily = self
            .logininfor_service
            .daily_stats(days, tenant)
            .await?
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
            .await?;
        Ok(serde_json::json!({ "days": days, "todayFailedIps": today_failed_ips, "daily": daily }))
    }

    /// 用户统计快照：总量/启用/停用/近 7 天新增 + 近 30 天创建趋势
    async fn snapshot_user(&self, tenant_id: i64) -> Result<Value, ServiceError> {
        use chrono::{Duration, NaiveTime};
        let db = self.report_repo.base().db();
        let now = crate::common::datetime::today_utc();
        let week_ago = now - Duration::days(7);
        let month_ago = now - Duration::days(USER_TREND_DAYS - 1);
        let week_begin = week_ago.and_time(NaiveTime::MIN);
        let month_begin = month_ago.and_time(NaiveTime::MIN);

        // 按报表所属租户统计用户维度（出租户不过滤）
        let tenant = crate::common::tenant::tenant_scope(tenant_id);
        let total = count_of(db, None, tenant).await?;
        let active = count_of(db, Some(("0", None)), tenant).await?;
        let disabled = count_of(db, Some(("1", None)), tenant).await?;
        let new_this_week = count_of(db, Some(("0", Some(week_begin))), tenant).await?;

        let mut query = SysUser::find()
            .filter(UserColumn::DelFlag.ne("2"))
            .filter(UserColumn::CreateTime.gte(month_begin));
        if let Some(tid) = tenant {
            query = query.filter(UserColumn::TenantId.eq(tid));
        }
        // §一.16 列投影：这条链只要"每一天新增几个"，`password` 摘要出现在这里没有任何
        // 功能理由。NULL 分支显式下推 SQL（原实现是 `if let Some(ct)` 的内存过滤 ⇒ 语义等价）。
        let recent_create_times: Vec<NaiveDateTime> = query
            .filter(UserColumn::CreateTime.is_not_null())
            .select_only()
            .column(UserColumn::CreateTime)
            .order_by_asc(UserColumn::CreateTime)
            .into_tuple::<NaiveDateTime>()
            .all(db)
            .await?;

        let mut trend_map: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        for ct in &recent_create_times {
            *trend_map
                .entry(ct.format("%Y-%m-%d").to_string())
                .or_insert(0) += 1;
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

        Ok(serde_json::json!({
            "totalUsers": total,
            "activeUsers": active,
            "disabledUsers": disabled,
            "newUsersThisWeek": new_this_week,
            "createTrend": trend,
        }))
    }

    /// 消息统计快照：发送总量 + 按状态分布（成功/失败/待重试）
    async fn snapshot_msg(&self, tenant_id: i64) -> Result<Value, ServiceError> {
        let db = self.report_repo.base().db();
        // 按报表所属租户统计消息投递维度（出租户不过滤）
        let tenant = crate::common::tenant::tenant_scope(tenant_id);
        let mut counts = Vec::with_capacity(4);
        for status in [None, Some("0"), Some("1"), Some("2")] {
            let mut q = SysMsgSendLog::find();
            if let Some(tid) = tenant {
                q = q.filter(MsgLogColumn::TenantId.eq(tid));
            }
            if let Some(s) = status {
                q = q.filter(MsgLogColumn::Status.eq(s));
            }
            counts.push(q.count(db).await?);
        }
        let [total, success, failed, pending] = [counts[0], counts[1], counts[2], counts[3]];
        Ok(
            serde_json::json!({ "total": total, "success": success, "failed": failed, "pending": pending }),
        )
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
        // 投递尝试次数（b98）：只用于"全部失败"判定。没有尝试（渠道都关、收件人为空）
        // 仍算一次已完成；**有尝试且 0 成功**才不得推进 last_run_time——旧实现无论成败
        // 都写 last_run_time，调度器于是把"这轮一封都没发出去"记成"本轮已成功执行"，
        // 下一个 cron 周期到来前不会再重试。
        let mut delivery_attempts = 0u64;

        // 邮件推送：逐封发送（MailerService 未启用时自动降级为 no-op）
        if sub.push_email == "1" {
            let emails = split_emails(&sub.receive_email);
            for email in &emails {
                delivery_attempts += 1;
                match self.mailer.send_text(email, &title, &text_body).await {
                    Ok(()) => emails_sent += 1,
                    Err(e) => tracing::warn!("报表订阅邮件发送失败 to={}: {}", email, e.message),
                }
            }
        }

        // 站内信推送（G-16：改走 SysMsgService::send 统一投递内核——模板渲染 + site
        // 渠道 dispatch（尊重用户消息偏好/免打扰）+ 发送记录落库 + 失败进重试链）。
        // 此前直插 sys_msg_send_log 且 max_retry_count=0，绕过了重试与偏好语义。
        if sub.push_sys_msg == "1" {
            let user_ids = sub
                .receive_user_ids
                .as_deref()
                .map(parse_id_list::<i64>)
                .transpose()?
                .unwrap_or_default();
            // 投递侧再收敛一次（与写侧共用 `partition_recipients`）：订阅落库后用户可能已被
            // 删除或迁租，存量 `receive_user_ids` 不得继续把本报表内容投进别租的收件箱。
            // 剔出的必须留痕——静默少发会让"为什么没收到"变成不可复盘的问题。
            let (deliverable, dropped) = if user_ids.is_empty() {
                (Vec::new(), Vec::new())
            } else {
                let owned = self
                    .user_repo
                    .find_tenant_ids_by_user_ids(&user_ids)
                    .await?;
                Self::partition_recipients(&user_ids, &owned, sub.tenant_id)
            };
            if !dropped.is_empty() {
                tracing::warn!(
                    "报表订阅站内信接收人已不在本租户范围（或已删除），跳过投递 sub_id={}, tenant_id={}, users={:?}",
                    sub.sub_id,
                    sub.tenant_id,
                    dropped
                );
            }
            let user_ids = deliverable;
            // 模板可用性预检：缺失/停用只 warn 一次，避免逐用户刷屏（send 侧 404 语义不变）
            let params_tpl = std::collections::HashMap::from([
                ("report_name".to_string(), report.report_name.clone()),
                ("report_code".to_string(), report.report_code.clone()),
                ("content".to_string(), text_body.clone()),
            ]);
            match self
                .msg_service
                .render_template_by_code("report_push", &params_tpl)
                .await
            {
                Ok(Some(_)) => {
                    for uid in user_ids {
                        let dto = crate::service::sys_msg_service::SendDto {
                            template_code: "report_push".to_string(),
                            channel_code: Some("site".to_string()),
                            to_addr: uid.to_string(),
                            params: params_tpl.clone(),
                        };
                        // 对齐 flow 站内提醒范式：operator="system"、operator_tid=0（平台触发）
                        delivery_attempts += 1;
                        match self.msg_service.send(dto, "system", 0).await {
                            Ok(log) => {
                                // "0"=投递成功 / "2"=待重试（已受理，重试链兜底）均计数；
                                // "1"=重试耗尽失败不计数
                                if log.status.as_deref() != Some("1") {
                                    site_msgs += 1;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "报表订阅站内信推送失败 sub_id={}, to={}: {}",
                                    sub.sub_id,
                                    uid,
                                    e.message
                                );
                            }
                        }
                    }
                }
                Ok(None) => {
                    tracing::warn!(
                        "报表订阅站内信推送跳过：平台模板 report_push 缺失或已停用（sub_id={}）",
                        sub.sub_id
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "报表订阅站内信推送跳过：模板查询失败（sub_id={}）: {}",
                        sub.sub_id,
                        e.message
                    );
                }
            }
        }

        // 全部尝试都失败 ⇒ 本轮不算"已执行"：不推进 last_run_time（否则调度器
        // 下一个 cron 周期到来前不会再重试，一封没发出去却记成成功）。
        if delivery_attempts > 0 && emails_sent + site_msgs == 0 {
            return Err(ServiceError::internal(&crate::tr!(
                "error.report_sub.push_all_failed",
                attempts = delivery_attempts
            )));
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
) -> Result<i64, ServiceError> {
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
    let count = q.count(db).await?;
    Ok(i64::try_from(count).unwrap_or(i64::MAX))
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

    /// 与前端 `src/utils/emailRecipients.ts` **共用同一张用例表**（b144）。
    ///
    /// 这张表是跨仓契约，不是"顺手多测几条"：
    /// - 前端**不得比服务端严**。`ops@mail` / `root@localhost` / `a@123` 是自托管 SMTP
    ///   与内网域的正常形态，服务端接受，而任何"常见邮箱正则"都会拒 ⇒ 用户的合法配置
    ///   在本地就被挡住（AGENTS《前端外部输入归一规范》判据 2：为安全把合法值也挡掉同样是缺陷）；
    /// - 前端**不得比服务端松**，否则 400 仍然要跑一趟网络。
    ///
    /// 反向核对由 `stepby-vue/src/utils/emailMirror.guard.test.ts` 执行：它读本文件，
    /// 要求下表每一条都以**正确的极性**出现在这里——表被单方面改动时那一侧先红。
    #[test]
    fn test_is_valid_email_matches_frontend_mirror() {
        let valid = [
            "a@example.com",
            "ops@mail",
            "root@localhost",
            "a@b@c",
            "x@y",
            "a+b@domain",
            "a@123",
            "用户@例え.jp",
        ];
        let invalid = [
            "a b@example.com",
            "@example.com",
            "a@",
            "no-at-sign",
            "",
            "   ",
            "a@b c.com",
        ];
        for email in valid {
            assert!(
                is_valid_email(email),
                "服务端必须接受 {email}（前端镜像也必须接受）"
            );
        }
        for email in invalid {
            assert!(
                !is_valid_email(email),
                "服务端必须拒绝 {email}（前端镜像也必须拒绝）"
            );
        }
    }

    /// 拆分语义也必须与前端同表：按 `,` 拆 → 逐段 trim → 丢空段（顺序保持）。
    #[test]
    fn test_split_emails_matches_frontend_mirror() {
        assert_eq!(
            split_emails(&Some(" a@b.com ,, c@d.com ,".to_string())),
            vec!["a@b.com".to_string(), "c@d.com".to_string()]
        );
        assert_eq!(
            split_emails(&Some(" , , ".to_string())),
            Vec::<String>::new()
        );
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
        assert_eq!(
            SysReportService::parse_ids("1,2, 3").unwrap(),
            vec![1, 2, 3]
        );
        assert_eq!(SysReportService::parse_ids("").unwrap(), Vec::<i64>::new());
        assert!(SysReportService::parse_ids("1,abc").is_err());
    }

    // ==================== b89 项 1：订阅接收人的租户收敛（跨租户投递回归锁） ====================

    /// 本租户在册用户必须照常放行——否则这条判据变成"永远拒"，下一批就会去放宽它
    #[test]
    fn partition_recipients_keeps_own_tenant_users() {
        let owned = vec![(11, 7), (12, 7)];
        let (ok, bad) = SysReportService::partition_recipients(&[11, 12], &owned, 7);
        assert_eq!(ok, vec![11, 12]);
        assert!(bad.is_empty(), "本租户用户不得被剔出：{bad:?}");
    }

    /// 他租用户必须剔出（这正是立案的缺陷形状：A 的报表投进 B 的收件箱）
    #[test]
    fn partition_recipients_rejects_foreign_tenant_users() {
        let owned = vec![(11, 7), (12, 8)];
        let (ok, bad) = SysReportService::partition_recipients(&[11, 12], &owned, 7);
        assert_eq!(ok, vec![11]);
        assert_eq!(bad, vec![12]);
    }

    /// 查无此人（含已软删——仓储侧已排）必须剔出而不是"当没这回事"投出去
    #[test]
    fn partition_recipients_rejects_unknown_users() {
        let owned = vec![(11, 7)];
        let (ok, bad) = SysReportService::partition_recipients(&[11, 999], &owned, 7);
        assert_eq!(ok, vec![11]);
        assert_eq!(bad, vec![999]);
    }

    /// 平台代管（tid=0）必须照常放行——把代管判成越权等于砍掉平台交付能力
    #[test]
    fn partition_recipients_allows_platform_operator() {
        let owned = vec![(11, 7), (12, 8)];
        let (ok, bad) = SysReportService::partition_recipients(&[11, 12], &owned, 0);
        assert_eq!(ok, vec![11, 12]);
        assert!(bad.is_empty());
    }

    /// 重复 ID 只投一次（派生写的幂等）
    #[test]
    fn partition_recipients_deduplicates() {
        let owned = vec![(11, 7)];
        let (ok, bad) = SysReportService::partition_recipients(&[11, 11, 11], &owned, 7);
        assert_eq!(ok, vec![11]);
        assert!(bad.is_empty());
    }

    /// 归属表为空时不得读成"没有接收人 ⇒ 无需拒绝"：全部剔出
    #[test]
    fn partition_recipients_with_empty_ownership_rejects_everything() {
        let (ok, bad) = SysReportService::partition_recipients(&[11, 12], &[], 7);
        assert!(ok.is_empty());
        assert_eq!(bad, vec![11, 12]);
    }

    /// 守恒正控：两侧并集必须等于去重后的入参集——"少投了"与"投错了"同样不可接受
    #[test]
    fn partition_recipients_is_exhaustive() {
        let owned = vec![(11, 7), (12, 8), (13, 7)];
        let ids = [11, 12, 13, 14, 11];
        let (ok, mut bad) = SysReportService::partition_recipients(&ids, &owned, 7);
        let mut union = ok.clone();
        union.append(&mut bad);
        union.sort_unstable();
        assert_eq!(union, vec![11, 12, 13, 14]);
        assert_eq!(ok.len(), 2);
    }

    // ==================== b142 项 1：快照聚合失败不得折成 0 ====================

    const SOURCE: &str = include_str!("sys_report_service.rs");

    /// 取 `fn <name>` 的**函数体**（花括号配平），而非整份文件——
    /// 整份文件里测试自身会提到这些失败形状，按全文判会自己命中自己。
    fn function_body(name: &str) -> String {
        let marker = format!("fn {name}");
        let start = SOURCE
            .find(&marker)
            .unwrap_or_else(|| panic!("找不到函数 {name}（改名后本锁必须同步）"));
        let open = SOURCE[start..]
            .find('{')
            .map(|i| start + i)
            .expect("函数签名后必须有花括号");
        let mut depth = 0usize;
        for (i, ch) in SOURCE[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return SOURCE[open..=open + i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("函数 {name} 花括号不配平");
    }

    /// 判据：**取数语句**里不得存在"把失败折成默认值"的三类形状。
    ///
    /// 刀口取"含 `.await` 的语句"而不是整段函数体：派生默认值（如
    /// `trend_map.get(&date_str).unwrap_or(0)`——查不到就是 0 天）与整数
    /// 溢出兜底（`i64::try_from(..).unwrap_or(i64::MAX)`）都不是取数失败，
    /// 按全文禁 `unwrap_or(0)` 会把它们一并判红，下一批就会去放宽判据。
    fn folds_errors_into_defaults(body: &str) -> Vec<&'static str> {
        let mut hits = Vec::new();
        for statement in body.split(';') {
            if !statement.contains(".await") {
                continue;
            }
            for needle in ["unwrap_or(0)", "unwrap_or_default()", ".ok()"] {
                if statement.contains(needle) && !hits.contains(&needle) {
                    hits.push(needle);
                }
            }
        }
        hits
    }

    #[test]
    fn snapshot_helpers_never_fold_db_errors_into_zero() {
        for name in [
            "generate_snapshot",
            "snapshot_login",
            "snapshot_user",
            "snapshot_msg",
            "count_of",
        ] {
            let hits = folds_errors_into_defaults(&function_body(name));
            assert!(
                hits.is_empty(),
                "{name} 把取数失败折成了默认值（命中 {hits:?}）：一次 DB 抖动会变成报表里的 0/空趋势，\
                 而预览与订阅推送都会把它当成事实发出去——必须 `?` 上抛"
            );
        }
    }

    /// 接线反查：三条快照分支必须真的用 `?` 传播，而不是只把返回类型改宽
    #[test]
    fn generate_snapshot_propagates_every_branch() {
        let body = function_body("generate_snapshot");
        for needle in [
            "self.snapshot_login(report).await?",
            "self.snapshot_user(report.tenant_id).await?",
            "self.snapshot_msg(report.tenant_id).await?",
        ] {
            assert!(
                body.contains(needle),
                "generate_snapshot 缺少 `{needle}`：分支没走 `?` 时失败会被折叠成空快照"
            );
        }
    }

    /// custom 配置解析失败不得折成空对象：那会让订阅发出一张空报表并推进
    /// `last_run_time`（管理员此后看不到这次失败）。
    #[test]
    fn custom_config_parse_failure_is_not_folded() {
        let body = function_body("generate_snapshot");
        assert!(
            body.contains("error.report.config_json_invalid"),
            "custom 配置解析失败必须点名理由并上抛"
        );
        assert!(
            !body.contains("unwrap_or_else(|_| Value::Object"),
            "HEAD 的空对象兜底必须已删除（否则坏配置 = 一张空报表）"
        );
    }

    /// 判据活性：把缺陷形状（原实现）喂给同一个谓词必须被抓到，
    /// 否则上面两条只能证明"文本里没这些词"，不能证明"这类缺陷会被判红"。
    #[test]
    fn snapshot_fold_detector_is_falsifiable() {
        // HEAD 的真实形状：三处取数各自折成默认值（含一处跨行链式调用）
        let original_shape = r#"
            let total = count_of(db, None, tenant).await;
            let times = query.all(db).await.unwrap_or_default();
            let doc = repo.find_by_id(id).await.ok();
            let n = q.count(db)
                .await
                .map(|c| c as i64)
                .unwrap_or(0);
        "#;
        let hits = folds_errors_into_defaults(original_shape);
        assert_eq!(hits.len(), 3, "缺陷形状必须三处全被抓到：{hits:?}");

        let compliant = r#"
            let total = count_of(db, None, tenant).await?;
            let times = query.all(db).await?;
            let day_count = trend_map.get(&date_str).copied().unwrap_or(0);
            let capped = i64::try_from(count).unwrap_or(i64::MAX);
        "#;
        assert!(
            folds_errors_into_defaults(compliant).is_empty(),
            "合规形状（含派生默认值与整数溢出兜底）不得被误报"
        );
    }
}
