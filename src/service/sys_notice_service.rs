//! 通知公告模块 Service 层
//!
//! 职责：
//! - 通知公告 CRUD（分页查询、详情、新增、修改、批量删除）
//! - notice 表无 del_flag，删除为物理删除
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 数据访问通过 Repository 层委托

use futures::future::FutureExt;
use garde::Validate;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_notice::{
    ActiveModel as SysNoticeActiveModel, Column as NoticeColumn, Model as SysNoticeModel,
};
use crate::entity::sys_user_pref::Model as PrefModel;
use crate::repository::sys_notice::SysNoticeRepository;
use crate::repository::sys_notice_read::{NoticeReadUserVo, SysNoticeReadRepository};
use crate::repository::sys_user_pref::SysUserPrefRepository;
use crate::service::sys_user_pref_service::{PrefChannel, allows_delivery, now_hm_str};
use crate::state::AppState;
use crate::utils::parse_id_list;
use crate::utils::sanitize_html;

/// P3 修复: 通知公告枚举值白名单校验
/// notice_type: "1"=通知, "2"=公告
/// status: "0"=正常, "1"=关闭（可选字段，None 时跳过）
fn validate_notice_enum(notice_type: &str, status: Option<&str>) -> Result<(), ServiceError> {
    if notice_type != "1" && notice_type != "2" {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.notice.notice_type_invalid",
            value = notice_type
        )));
    }
    if let Some(s) = status
        && s != "0"
        && s != "1"
    {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.notice.status_invalid",
            value = s
        )));
    }
    Ok(())
}

// ==================== DTO ====================

/// 通知公告分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct NoticeQueryDto {
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
    pub notice_title: Option<String>,
    pub notice_type: Option<String>,
    pub create_by: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 `params[beginTime]`）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 `params[endTime]`）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&NoticeQueryDto> for PageDomain {
    fn from(dto: &NoticeQueryDto) -> Self {
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

/// 新增通知公告 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NoticeAddDto {
    #[garde(length(min = 1, max = 50))]
    pub notice_title: String,
    /// 公告类型（1=通知 2=公告）
    #[garde(length(min = 1, max = 1))]
    pub notice_type: String,
    #[garde(skip)]
    pub notice_content: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
    /// 是否同时通过邮件通知所有启用状态的用户（true 时调用 MailerService 批量发送）
    #[serde(default)]
    #[garde(skip)]
    pub notify_email: bool,
}

/// 修改通知公告 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NoticeEditDto {
    #[garde(skip)]
    pub notice_id: i64,
    #[garde(length(min = 1, max = 50))]
    pub notice_title: String,
    /// 公告类型（1=通知 2=公告）
    #[garde(length(min = 1, max = 1))]
    pub notice_type: String,
    #[garde(skip)]
    pub notice_content: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 已读用户列表查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct NoticeReadUserQueryDto {
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
    /// 公告 ID（必填）
    pub notice_id: i64,
    /// 搜索关键字（登录名/用户名）
    pub search_value: Option<String>,
}

/// 标记已读 DTO
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoticeMarkReadDto {
    /// 公告 ID
    pub notice_id: i64,
}

/// 批量标记已读 DTO
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoticeMarkReadAllDto {
    /// 公告 ID 列表（逗号分隔）
    pub ids: String,
}

// ==================== 辅助函数 ====================

// HTML 转义收敛到 `crate::utils::sanitize::html_escape`（见下方调用点），避免重复实现。

// ==================== Service 实现 ====================

/// 允许排序的公告列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖公告业务展示列；`notice_content`（长文本）、`tenant_id` 等内部列不开放动态排序。
const NOTICE_SORTABLE_COLUMNS: &[(&str, NoticeColumn)] = &[
    ("notice_id", NoticeColumn::NoticeId),
    ("notice_title", NoticeColumn::NoticeTitle),
    ("notice_type", NoticeColumn::NoticeType),
    ("status", NoticeColumn::Status),
    ("create_by", NoticeColumn::CreateBy),
    ("create_time", NoticeColumn::CreateTime),
];

/// 已读用户列表允许排序的列白名单（prop snake_case → 联表 SQL 列表达式）。
///
/// 已读用户列表为原生 SQL 联表查询（sys_notice_read r + sys_user u + sys_dept d），
/// 无法复用 sea-orm `resolve_column` 的单实体 Column 枚举映射，改为
/// `(prop, SQL 列表达式)` 常量映射；表达式全部来自本常量，无字符串拼接注入面。
const READ_USER_SORTABLE_COLUMNS: &[(&str, &str)] = &[
    ("read_id", "r.read_id"),
    ("user_id", "r.user_id"),
    ("read_time", "r.read_time"),
    ("user_name", "u.user_name"),
    ("nick_name", "u.nick_name"),
    ("dept_name", "d.dept_name"),
    ("phonenumber", "u.phonenumber"),
];

/// 通知公告模块 Service
///
/// 数据访问通过 Repository 层委托：
/// - notice_repo: sys_notice 表 CRUD
/// - read_repo: sys_notice_read 表已读记录
pub struct SysNoticeService {
    notice_repo: SysNoticeRepository,
    read_repo: SysNoticeReadRepository,
    pref_repo: SysUserPrefRepository,
}

impl SysNoticeService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            notice_repo: SysNoticeRepository::new(db.clone()),
            read_repo: SysNoticeReadRepository::new(db.clone()),
            pref_repo: SysUserPrefRepository::new(db),
        }
    }

    /// 获取数据库连接引用（用于事务）
    fn db(&self) -> &DatabaseConnection {
        self.notice_repo.base().db()
    }

    /// 分页查询通知公告
    ///
    /// 支持 notice_title 模糊、notice_type 精确、create_by 精确、时间范围筛选
    pub async fn get_notice_page(
        &self,
        query: NoticeQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<SysNoticeModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_notice::Entity>(prop, NOTICE_SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let begin = match query.begin_time.as_deref() {
            Some(s) => Some(crate::common::datetime::parse_query_date(s)?),
            None => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) => Some(crate::common::datetime::parse_query_date(s)?),
            None => None,
        };

        let (rows, total) = self
            .notice_repo
            .find_page_filtered(
                offset,
                limit,
                query.notice_title.as_deref(),
                query.notice_type.as_deref(),
                query.create_by.as_deref(),
                begin,
                end,
                crate::common::tenant::tenant_scope(operator_tid),
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 根据 notice_id 查询通知公告详情
    pub async fn get_notice_by_id(
        &self,
        notice_id: i64,
        operator_tid: i64,
    ) -> Result<SysNoticeModel, ServiceError> {
        let model = self
            .notice_repo
            .find_active_by_id(notice_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.notice.not_found")))?;
        // 越权防护：租户管理员不得读取其他租户通知公告
        if !crate::common::tenant::tenant_allowed(operator_tid, model.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        Ok(model)
    }

    /// 新增通知公告
    ///
    /// 若 dto.notify_email=true 且 MailerService 已启用，则同步发送邮件给所有启用状态用户。
    /// 邮件发送失败仅记录日志，不阻断 sys_notice 入库主流程。
    /// state 为 None 时跳过邮件发送（scheduler 等无 AppState 场景使用）
    pub async fn add_notice(
        &self,
        dto: NoticeAddDto,
        operator: &str,
        operator_tid: i64,
        state: Option<&AppState>,
    ) -> Result<SysNoticeModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        // P3 修复: 枚举值白名单校验，防止脏数据
        validate_notice_enum(&dto.notice_type, dto.status.as_deref())?;

        let now = crate::common::datetime::now_naive();
        // 净化 notice_content：移除危险标签和事件属性（P0-R19-002）
        let safe_content = dto.notice_content.clone().map(|c| sanitize_html(&c));
        let am = SysNoticeActiveModel {
            tenant_id: Set(operator_tid),
            notice_title: Set(dto.notice_title.clone()),
            notice_type: Set(dto.notice_type.clone()),
            notice_content: Set(safe_content.clone()),
            status: Set(dto.status.or(Some("0".to_string()))),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(dto.remark),
            ..Default::default()
        };

        // 事务：插入 + 审计留痕原子化（失败令业务一并回滚）
        let notice_repo = self.notice_repo.clone();
        let operator_owned = operator.to_string();
        let model = self
            .db()
            .transaction::<_, SysNoticeModel, sea_orm::DbErr>(|txn| {
                let notice_repo = notice_repo.clone();
                let am = am;
                let operator = operator_owned.clone();
                Box::pin(async move {
                    let model = notice_repo.base().insert_conn(txn, am).await?;
                    // 审计合规域：INSERT 变更留痕（同事务提交/回滚）
                    crate::service::sys_audit_change_service::audit_insert(
                        txn,
                        "sys_notice",
                        &model.notice_id.to_string(),
                        &model,
                        None, // add_notice 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator.as_str()),
                    )
                    .await?;
                    Ok(model)
                })
            })
            .await?;

        // 邮件通知（可选）：仅在调用方传入 AppState 且 dto.notify_email=true 时发送
        if dto.notify_email
            && let Some(st) = state
        {
            self.send_notice_email(st, operator_tid, &dto.notice_title, safe_content.as_deref())
                .await;
        }

        Ok(model)
    }

    /// 发送通知邮件给所有启用状态用户
    ///
    /// 查询所有 status='0' 且 email 非空的用户邮箱，调用 MailerService 批量发送。
    /// 失败仅记录 tracing::warn!，不阻断主流程。
    async fn send_notice_email(
        &self,
        state: &AppState,
        tenant_id: i64,
        title: &str,
        content: Option<&str>,
    ) {
        if !state.mailer_service.is_enabled() {
            tracing::debug!("邮件功能未启用，跳过通知公告邮件发送: {}", title);
            return;
        }

        // 查询本租户启用状态用户邮箱，并按个人偏好/免打扰过滤（email_notify 且 announce_notify，且不在免打扰窗口）
        let pairs = match self.find_active_user_email_pairs(state, tenant_id).await {
            Ok(list) if !list.is_empty() => list,
            Ok(_) => {
                tracing::info!("无启用状态用户邮箱，跳过邮件发送: {}", title);
                return;
            }
            Err(e) => {
                tracing::warn!("查询用户邮箱失败，跳过邮件发送: {}", e);
                return;
            }
        };

        // 批量读取用户偏好，过滤出允许接收公告邮件的用户
        let user_ids: Vec<i64> = pairs.iter().map(|(uid, _)| *uid).collect();
        let prefs = match self.pref_repo.find_by_user_ids(&user_ids).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("查询用户消息偏好失败，采用全部投递: {}", e);
                return;
            }
        };
        let mut pref_map = std::collections::HashMap::<i64, &PrefModel>::new();
        for p in &prefs {
            pref_map.insert(p.user_id, p);
        }
        let now_hm = now_hm_str();
        let emails: Vec<String> = pairs
            .into_iter()
            .filter(|(uid, _)| {
                match pref_map.get(uid) {
                    // 无偏好记录 → 默认允许（与缺省行为一致）
                    None => true,
                    Some(p) => allows_delivery(PrefChannel::Email, p, &now_hm),
                }
            })
            .map(|(_, email)| email)
            .collect();
        if emails.is_empty() {
            tracing::info!("无满足消息偏好/免打扰的用户，跳过邮件发送: {}", title);
            return;
        }

        // 构建邮件正文（G-16：平台模板 notice_email 优先，缺失/停用回落内置默认）
        //
        // 模板变量：{{title}}/{{content}}/{{footer}}，均在**代码侧先 html_escape**
        // （模板存储的是 HTML 骨架，变量位注入已转义值，二次转义风险为零——
        // 与 render_template 的纯文本替换语义配合，模板内容本身不参与转义）。
        // 主题前缀保持按请求 locale 双语（notice 发送在请求作用域内），模板只承载正文骨架。
        let params = std::collections::HashMap::from([
            (
                "title".to_string(),
                crate::utils::sanitize::html_escape(title),
            ),
            (
                "content".to_string(),
                crate::utils::sanitize::html_escape(content.unwrap_or("")),
            ),
            (
                "footer".to_string(),
                crate::tr!("notice.email.footer").to_string(),
            ),
        ]);
        // P3：邮件主题前缀按请求 locale 双语（notice 发送在请求作用域内）
        let subject_prefix = crate::common::i18n::pick("【stepby 通知】", "[stepby Notice] ");
        let body = match state
            .msg_service
            .render_template_by_code("notice_email", &params)
            .await
        {
            Ok(Some((_, rendered))) => rendered,
            // 模板缺失/停用/查询失败：回落内置默认骨架（与 seed 的 notice_email 内容一致）
            _ => format!(
                "<div style=\"font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px;\">
                    <h2 style=\"color: #409EFF; border-bottom: 2px solid #409EFF; padding-bottom: 10px;\">{title}</h2>
                    <div style=\"margin: 20px 0;\">{content}</div>
                    <hr style=\"border: none; border-top: 1px solid #ddd; margin: 20px 0;\"/>
                    <p style=\"color: #999; font-size: 12px;\">{footer}</p>
                </div>",
                title = params.get("title").map(String::as_str).unwrap_or(""),
                content = params.get("content").map(String::as_str).unwrap_or(""),
                footer = params.get("footer").map(String::as_str).unwrap_or(""),
            ),
        };
        let subject = format!("{}{}", subject_prefix, title);
        match state
            .mailer_service
            .send_batch(&emails, &subject, &body)
            .await
        {
            Ok(result) => {
                tracing::info!(
                    "通知公告邮件发送完成: title={}, total={}, success={}, failed={}",
                    title,
                    result.total,
                    result.success,
                    result.failed
                );
            }
            Err(e) => {
                tracing::warn!("通知公告邮件发送失败: title={}, error={}", title, e);
            }
        }
    }

    /// 查询本租户所有启用状态用户的 (user_id, email)（status='0' 且 email 非空）
    ///
    /// 返回二元组以支持按用户偏好/免打扰过滤（enforcement）。
    /// tenant_id=0（平台）时不过滤，覆盖全部租户。
    async fn find_active_user_email_pairs(
        &self,
        _state: &AppState,
        tenant_id: i64,
    ) -> Result<Vec<(i64, String)>, ServiceError> {
        use crate::entity::sys_user::{Column as UserColumn, Entity as UserEntity};
        use sea_orm::*;
        let db = self.db();
        // **列投影**（b74 §一.16）：群发只需要 `(user_id, email)`，而未投影的 `find()`
        // 会把整行读进内存——含 `password` 的 argon2 摘要。凭据摘要没有任何理由出现在
        // 通知链路的内存里（一旦该路径将来加日志/序列化，就是凭据外泄面）。
        let mut query = UserEntity::find()
            .select_only()
            .column(UserColumn::UserId)
            .column(UserColumn::Email)
            .filter(UserColumn::Status.eq("0"))
            .filter(UserColumn::DelFlag.eq("0"))
            .filter(UserColumn::Email.is_not_null())
            .filter(UserColumn::Email.ne(""));
        if let Some(tid) = crate::common::tenant::tenant_scope(tenant_id) {
            query = query.filter(UserColumn::TenantId.eq(tid));
        }
        let pairs: Vec<(i64, String)> = query
            .into_tuple::<(i64, Option<String>)>()
            .all(db)
            .await
            .map_err(|_| {
                ServiceError::internal(&crate::tr!("error.notice.user_email_query_failed"))
            })?
            .into_iter()
            .filter_map(|(uid, email)| match email {
                Some(e) if !e.is_empty() => Some((uid, e)),
                _ => None,
            })
            .collect();
        Ok(pairs)
    }

    /// 修改通知公告
    pub async fn edit_notice(
        &self,
        dto: NoticeEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysNoticeModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        // P3 修复: 枚举值白名单校验，防止脏数据
        validate_notice_enum(&dto.notice_type, dto.status.as_deref())?;

        let existing = self.get_notice_by_id(dto.notice_id, operator_tid).await?;

        let now = crate::common::datetime::now_naive();
        // 净化 notice_content：移除危险标签和事件属性（P0-R19-002）
        let safe_content = dto.notice_content.map(|c| sanitize_html(&c));
        // 部分更新语义快照（2026-09-26 缺陷修复）：`existing` 随即被 `into()` 转移；
        // 未传正文/状态时保持现值，避免"只改标题"的 PUT 清空公告正文或隐藏公告
        let existing_content = existing.notice_content.clone();
        let existing_status = existing.status.clone();
        // 审计合规域：变更前快照（必须在 existing 被 move 进 ActiveModel 之前计算）
        let before_snapshot = serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);
        let mut am: SysNoticeActiveModel = existing.into();
        am.notice_title = Set(dto.notice_title);
        am.notice_type = Set(dto.notice_type);
        am.notice_content = Set(safe_content.or(existing_content));
        am.status = Set(dto.status.or(existing_status));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.remark = Set(dto.remark);

        // 事务：更新 + 审计留痕原子化（同事务提交/回滚）
        let notice_repo = self.notice_repo.clone();
        let operator_owned = operator.to_string();
        let model = self
            .db()
            .transaction::<_, SysNoticeModel, sea_orm::DbErr>(|txn| {
                let notice_repo = notice_repo.clone();
                let am = am;
                let before_snapshot = before_snapshot.clone();
                let operator = operator_owned.clone();
                Box::pin(async move {
                    let model = notice_repo.base().update_conn(txn, am).await?;
                    // 审计合规域：UPDATE 变更留痕（同事务提交/回滚）
                    crate::service::sys_audit_change_service::audit_update(
                        txn,
                        "sys_notice",
                        &model.notice_id.to_string(),
                        &before_snapshot,
                        &model,
                        None, // edit_notice 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator.as_str()),
                    )
                    .await?;
                    Ok(model)
                })
            })
            .await?;
        Ok(model)
    }

    /// 批量删除通知公告（物理删除，级联清理已读记录；事务内含 DELETE 审计留痕）
    pub async fn delete_notice(
        &self,
        notice_ids: Vec<i64>,
        operator: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        // 批量校验记录存在（单次 SELECT 替代 N 次）
        if notice_ids.is_empty() {
            return Ok(());
        }
        let existing = self.notice_repo.find_by_ids(&notice_ids).await?;
        if existing.len() != notice_ids.len() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.notice.not_found"
            )));
        }
        // 越权防护：租户管理员不得跨租户删除通知公告
        if existing
            .iter()
            .any(|n| !crate::common::tenant::tenant_allowed(operator_tid, n.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        // 事务保证：通知删除与已读记录级联清理原子化（P0-76），审计留痕同事务
        let notice_repo = self.notice_repo.clone();
        let read_repo = self.read_repo.clone();
        let existing_inner = existing.clone();
        let operator_owned = operator.to_string();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let notice_ids_inner = notice_ids.clone();
                let existing_inner = existing_inner.clone();
                let operator = operator_owned.clone();
                async move {
                    notice_repo
                        .delete_by_ids_conn(txn, notice_ids_inner.clone())
                        .await?;
                    // 审计合规域：DELETE 变更留痕（同事务提交/回滚）
                    for n in &existing_inner {
                        crate::service::sys_audit_change_service::audit_delete(
                            txn,
                            "sys_notice",
                            &n.notice_id.to_string(),
                            n,
                            None, // delete_notice 签名仅携带操作人用户名，ID 由回查补齐
                            Some(operator.as_str()),
                        )
                        .await?;
                    }
                    read_repo
                        .delete_by_notice_ids_conn(txn, notice_ids_inner)
                        .await?;
                    Ok(())
                }
                .boxed()
            })
            .await?;
        Ok(())
    }

    /// 查询顶部公告列表（首页通知铃铛用）
    ///
    /// 返回状态正常的公告，限制 10 条。
    pub async fn get_notice_top(
        &self,
        operator_tid: i64,
    ) -> Result<Vec<SysNoticeModel>, ServiceError> {
        let rows = self
            .notice_repo
            .find_top_notices(10, crate::common::tenant::tenant_scope(operator_tid))
            .await?;
        Ok(rows)
    }

    /// 标记公告已读（已读记录归属随父公告租户）
    pub async fn mark_read(
        &self,
        notice_id: i64,
        user_id: i64,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let notice = self
            .notice_repo
            .find_active_by_id(notice_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.notice.not_found")))?;
        // 越权防护：租户管理员不得标记其他租户公告
        if !crate::common::tenant::tenant_allowed(operator_tid, notice.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        // 从属表归属：read 记录随父公告租户
        self.read_repo
            .mark_read(notice_id, user_id, notice.tenant_id)
            .await?;
        Ok(())
    }

    /// 批量标记公告已读（按父公告租户分组写入已读记录）
    pub async fn mark_read_all(
        &self,
        ids: &str,
        user_id: i64,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let notice_ids: Vec<i64> = parse_id_list::<i64>(ids);
        if notice_ids.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.notice.id_invalid"
            )));
        }
        let notices = self.notice_repo.find_by_ids(&notice_ids).await?;
        // 越权防护：任一公告跨租户即拒绝（不静默忽略）
        if notices
            .iter()
            .any(|n| !crate::common::tenant::tenant_allowed(operator_tid, n.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        // 从属表归属：按父公告租户分组批量插入
        let mut by_tenant: std::collections::BTreeMap<i64, Vec<i64>> =
            std::collections::BTreeMap::new();
        for n in &notices {
            by_tenant.entry(n.tenant_id).or_default().push(n.notice_id);
        }
        for (tid, ids) in by_tenant {
            self.read_repo.mark_read_batch(ids, user_id, tid).await?;
        }
        Ok(())
    }

    /// 标记用户所有未读公告为已读（"全部已读"功能）
    ///
    /// 与 mark_read_all 的区别：
    /// - mark_read_all 需要传入具体 notice IDs，前端只能拿到当前页的 ID
    /// - mark_all_unread_read 服务端查询所有未读并标记，确保跨页未读也被清除
    ///
    /// 返回标记的条数（用于响应消息展示）。tenant_scope 由 operator 推导：
    /// 租户操作者仅处理本租户公告，平台操作者按公告实际租户分组写入。
    pub async fn mark_all_unread_read(
        &self,
        user_id: i64,
        operator_tid: i64,
    ) -> Result<u64, ServiceError> {
        let count = self
            .read_repo
            .mark_all_unread_read(user_id, crate::common::tenant::tenant_scope(operator_tid))
            .await?;
        Ok(count)
    }

    /// 查询公告已读用户列表（分页）
    ///
    /// M1 脱敏影响面补齐（字段级权限 M2 登记）：`NoticeReadUserVo.phonenumber`
    /// 按 M1 三口径掩码（本人行 / 超管 → 原值；其余 operator → 掩码）。
    /// 该出口此前返回手机号原值，与用户列表的 M1 口径漂移，此为脱敏收口。
    /// 字段级权限 M2 的**隐藏裁剪**不作用于本出口（登记口径：M2 首期只开
    /// sys_user 列表域；本出口走 M1 掩码口径）。
    pub async fn get_read_users_page(
        &self,
        query: NoticeReadUserQueryDto,
        operator_user_id: Option<i64>,
        operator_tid: i64,
    ) -> Result<(Vec<NoticeReadUserVo>, u64), ServiceError> {
        // 动态排序透传：先 sanitize（格式白名单），列级白名单在此处解析为 SQL 列表达式
        // （联表原生 SQL 查询，无法走 resolve_column 的 Column 枚举映射）
        let mut page = PageDomain {
            page_num: query.page_num,
            page_size: query.page_size,
            order_by_column: query.order_by_column.clone(),
            is_asc: query.is_asc.clone(),
        };
        page.sanitize_order_fields();
        // 白名单命中 → (SQL 列表达式, 是否升序)；未命中/缺省由 repository 回退默认 read_time DESC
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            let key = sort::camel_to_snake(prop);
            READ_USER_SORTABLE_COLUMNS
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, expr)| {
                    (
                        *expr,
                        matches!(
                            sort::parse_direction(page.is_asc.as_deref()),
                            sea_orm::Order::Asc
                        ),
                    )
                })
        });
        let offset = page.offset();
        let limit = page.limit();
        let (rows, total) = self
            .read_repo
            .find_read_users_page(
                offset,
                limit,
                query.notice_id,
                query.search_value.as_deref(),
                crate::common::tenant::tenant_scope(operator_tid),
                sort,
            )
            .await?;

        // M1 三口径掩码（phonenumber）：每次请求计算一次超管视角，逐行判定
        // （本人行 / 超管 → 原值；其余 → 掩码）。角色查询失败 fail-closed（掩码）。
        let op_is_super = match operator_user_id {
            Some(op_uid) => {
                if op_uid == crate::common::constants::SUPER_ADMIN_USER_ID {
                    true
                } else {
                    match crate::repository::sys_role::SysRoleRepository::new(self.db().clone())
                        .find_by_user_id(op_uid)
                        .await
                    {
                        Ok(roles) => roles.iter().any(|r| r.is_platform_super_admin()),
                        Err(e) => {
                            tracing::warn!(
                                operator_user_id = op_uid,
                                "已读用户列表掩码判定：查询 operator 角色失败，fail-closed 按非超管处理: {}",
                                e
                            );
                            false
                        }
                    }
                }
            }
            None => false,
        };
        let mut rows = rows;
        for row in &mut rows {
            if crate::service::sys_user_service::should_mask_pii(
                operator_user_id,
                row.user_id,
                op_is_super,
            ) && let Some(phone) = row.phonenumber.as_deref()
            {
                row.phonenumber = Some(crate::utils::masking::mask_phone(phone));
            }
        }

        Ok((rows, total))
    }

    /// 统计用户未读公告数（按租户维度）
    pub async fn count_unread(&self, user_id: i64, operator_tid: i64) -> Result<u64, ServiceError> {
        Ok(self
            .read_repo
            .count_unread(user_id, crate::common::tenant::tenant_scope(operator_tid))
            .await?)
    }
}
