//! 通知公告模块 Service 层
//!
//! 职责：
//! - 通知公告 CRUD（分页查询、详情、新增、修改、批量删除）
//! - notice 表无 del_flag，删除为物理删除
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 数据访问通过 Repository 层委托

use chrono::NaiveDateTime;
use futures::future::FutureExt;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use garde::Validate;

use crate::common::error::ServiceError;
use crate::common::page::{default_page_num, default_page_size, PageDomain};
use crate::entity::sys_notice::{
    ActiveModel as SysNoticeActiveModel, Model as SysNoticeModel,
};
use crate::repository::sys_notice::SysNoticeRepository;
use crate::repository::sys_notice_read::{NoticeReadUserVo, SysNoticeReadRepository};
use crate::utils::parse_id_list;
use crate::utils::sanitize_html;
use crate::state::AppState;

/// P3 修复: 通知公告枚举值白名单校验
/// notice_type: "1"=通知, "2"=公告
/// status: "0"=正常, "1"=关闭（可选字段，None 时跳过）
fn validate_notice_enum(notice_type: &str, status: Option<&str>) -> Result<(), ServiceError> {
    if notice_type != "1" && notice_type != "2" {
        return Err(ServiceError::bad_request(&format!(
            "notice_type 必须为 1(通知) 或 2(公告)，当前值: {}",
            notice_type
        )));
    }
    if let Some(s) = status {
        if s != "0" && s != "1" {
            return Err(ServiceError::bad_request(&format!(
                "status 必须为 0(正常) 或 1(关闭)，当前值: {}",
                s
            )));
        }
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
    pub notice_title: Option<String>,
    pub notice_type: Option<String>,
    pub create_by: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&NoticeQueryDto> for PageDomain {
    fn from(dto: &NoticeQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
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

/// 解析时间字符串（%Y-%m-%d 格式），失败返回 ServiceError
fn parse_time(s: &str) -> Result<NaiveDateTime, ServiceError> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| ServiceError::bad_request(&crate::tr!("error.common.time_format_invalid", s = s)))
}

/// HTML 特殊字符转义（用于邮件正文安全渲染）
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
        .replace('\n', "<br/>")
}

// ==================== Service 实现 ====================

/// 通知公告模块 Service
///
/// 数据访问通过 Repository 层委托：
/// - notice_repo: sys_notice 表 CRUD
/// - read_repo: sys_notice_read 表已读记录
pub struct SysNoticeService {
    notice_repo: SysNoticeRepository,
    read_repo: SysNoticeReadRepository,
}

impl SysNoticeService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            notice_repo: SysNoticeRepository::new(db.clone()),
            read_repo: SysNoticeReadRepository::new(db),
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
    ) -> Result<(Vec<SysNoticeModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let begin = match query.begin_time.as_deref() {
            Some(s) => Some(parse_time(s)?),
            None => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) => Some(parse_time(s)?),
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
            )
            .await?;
        Ok((rows, total))
    }

    /// 根据 notice_id 查询通知公告详情
    pub async fn get_notice_by_id(
        &self,
        notice_id: i64,
    ) -> Result<SysNoticeModel, ServiceError> {
        let model = self
            .notice_repo
            .find_active_by_id(notice_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.notice.not_found")))?;
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
        state: Option<&AppState>,
    ) -> Result<SysNoticeModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        // P3 修复: 枚举值白名单校验，防止脏数据
        validate_notice_enum(&dto.notice_type, dto.status.as_deref())?;

        let now = chrono::Local::now().naive_local();
        // 净化 notice_content：移除危险标签和事件属性（P0-R19-002）
        let safe_content = dto.notice_content.clone().map(|c| sanitize_html(&c));
        let am = SysNoticeActiveModel {
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

        let model = self.notice_repo.insert(am).await?;

        // 邮件通知（可选）：仅在调用方传入 AppState 且 dto.notify_email=true 时发送
        if dto.notify_email
            && let Some(st) = state
        {
            self.send_notice_email(st, &dto.notice_title, safe_content.as_deref())
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
        title: &str,
        content: Option<&str>,
    ) {
        if !state.mailer_service.is_enabled() {
            tracing::debug!("邮件功能未启用，跳过通知公告邮件发送: {}", title);
            return;
        }

        // 查询所有启用状态用户的邮箱
        let emails = match self.find_active_user_emails(state).await {
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

        // 构建邮件正文
        let body = format!(
            "<div style=\"font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px;\">
                <h2 style=\"color: #409EFF; border-bottom: 2px solid #409EFF; padding-bottom: 10px;\">{title}</h2>
                <div style=\"margin: 20px 0;\">{content}</div>
                <hr style=\"border: none; border-top: 1px solid #ddd; margin: 20px 0;\"/>
                <p style=\"color: #999; font-size: 12px;\">{footer}</p>
            </div>",
            title = html_escape(title),
            content = html_escape(content.unwrap_or("")),
            footer = crate::tr!("notice.email.footer")
        );

        // P3：邮件主题前缀按请求 locale 双语（notice 发送在请求作用域内）
        let subject_prefix = crate::common::i18n::pick("【yebot 通知】", "[yebot Notice] ");
        let subject = format!("{}{}", subject_prefix, title);
        match state.mailer_service.send_batch(&emails, &subject, &body).await {
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

    /// 查询所有启用状态用户的邮箱（status='0' 且 email 非空）
    async fn find_active_user_emails(&self, _state: &AppState) -> Result<Vec<String>, ServiceError> {
        use sea_orm::*;
        use crate::entity::sys_user::{self, Column as UserColumn};
        let db = self.db();
        let users = sys_user::Entity::find()
            .filter(UserColumn::Status.eq("0"))
            .filter(UserColumn::DelFlag.eq("0"))
            .filter(UserColumn::Email.is_not_null())
            .filter(UserColumn::Email.ne(""))
            .all(db)
            .await
            .map_err(|_| ServiceError::internal(&crate::tr!("error.notice.user_email_query_failed")))?;
        let emails: Vec<String> = users
            .into_iter()
            .filter_map(|u| {
                u.email.filter(|e| !e.is_empty())
            })
            .collect();
        Ok(emails)
    }

    /// 修改通知公告
    pub async fn edit_notice(
        &self,
        dto: NoticeEditDto,
        operator: &str,
    ) -> Result<SysNoticeModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        // P3 修复: 枚举值白名单校验，防止脏数据
        validate_notice_enum(&dto.notice_type, dto.status.as_deref())?;

        let existing = self.get_notice_by_id(dto.notice_id).await?;

        let now = chrono::Local::now().naive_local();
        // 净化 notice_content：移除危险标签和事件属性（P0-R19-002）
        let safe_content = dto.notice_content.map(|c| sanitize_html(&c));
        let mut am: SysNoticeActiveModel = existing.into();
        am.notice_title = Set(dto.notice_title);
        am.notice_type = Set(dto.notice_type);
        am.notice_content = Set(safe_content);
        am.status = Set(dto.status);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.remark = Set(dto.remark);

        let model = self.notice_repo.update(am).await?;
        Ok(model)
    }

    /// 批量删除通知公告（物理删除，级联清理已读记录）
    pub async fn delete_notice(&self, notice_ids: Vec<i64>) -> Result<(), ServiceError> {
        // 批量校验记录存在（单次 SELECT 替代 N 次）
        if notice_ids.is_empty() {
            return Ok(());
        }
        let existing = self.notice_repo.find_by_ids(&notice_ids).await?;
        if existing.len() != notice_ids.len() {
            return Err(ServiceError::not_found(&crate::tr!("error.notice.not_found")));
        }
        // 事务保证：通知删除与已读记录级联清理原子化（P0-76）
        let notice_repo = self.notice_repo.clone();
        let read_repo = self.read_repo.clone();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let notice_ids_inner = notice_ids.clone();
                async move {
                    notice_repo.delete_by_ids_conn(txn, notice_ids_inner.clone()).await?;
                    read_repo.delete_by_notice_ids_conn(txn, notice_ids_inner).await?;
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
    pub async fn get_notice_top(&self) -> Result<Vec<SysNoticeModel>, ServiceError> {
        let rows = self.notice_repo.find_top_notices(10).await?;
        Ok(rows)
    }

    /// 标记公告已读
    pub async fn mark_read(
        &self,
        notice_id: i64,
        user_id: i64,
    ) -> Result<(), ServiceError> {
        self.read_repo.mark_read(notice_id, user_id).await?;
        Ok(())
    }

    /// 批量标记公告已读
    pub async fn mark_read_all(
        &self,
        ids: &str,
        user_id: i64,
    ) -> Result<(), ServiceError> {
        let notice_ids: Vec<i64> = parse_id_list::<i64>(ids);
        if notice_ids.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!("error.notice.id_invalid")));
        }
        self.read_repo.mark_read_batch(notice_ids, user_id).await?;
        Ok(())
    }

    /// 标记用户所有未读公告为已读（"全部已读"功能）
    ///
    /// 与 mark_read_all 的区别：
    /// - mark_read_all 需要传入具体 notice IDs，前端只能拿到当前页的 ID
    /// - mark_all_unread_read 服务端查询所有未读并标记，确保跨页未读也被清除
    ///
    /// 返回标记的条数（用于响应消息展示）
    pub async fn mark_all_unread_read(
        &self,
        user_id: i64,
    ) -> Result<u64, ServiceError> {
        let count = self.read_repo.mark_all_unread_read(user_id).await?;
        Ok(count)
    }

    /// 查询公告已读用户列表（分页）
    pub async fn get_read_users_page(
        &self,
        query: NoticeReadUserQueryDto,
    ) -> Result<(Vec<NoticeReadUserVo>, u64), ServiceError> {
        let page = PageDomain {
            page_num: query.page_num,
            page_size: query.page_size,
            order_by_column: None,
            is_asc: None,
        };
        let offset = page.offset();
        let limit = page.limit();
        let (rows, total) = self
            .read_repo
            .find_read_users_page(offset, limit, query.notice_id, query.search_value.as_deref())
            .await?;
        Ok((rows, total))
    }

    /// 统计用户未读公告数
    pub async fn count_unread(&self, user_id: i64) -> Result<u64, ServiceError> {
        Ok(self.read_repo.count_unread(user_id).await?)
    }
}
