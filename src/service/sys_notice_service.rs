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
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_notice::{
    ActiveModel as SysNoticeActiveModel, Column as NoticeColumn, Model as SysNoticeModel,
};
use crate::entity::sys_user_pref::Model as PrefModel;
use crate::repository::sys_notice::{NoticeFilter, SysNoticeRepository};
use crate::repository::sys_notice_read::{NoticeReadUserVo, SysNoticeReadRepository};
use crate::repository::sys_user_pref::SysUserPrefRepository;
use crate::service::sys_user_pref_service::{PrefChannel, allows_delivery, now_hm_str};
use crate::state::AppState;
use crate::utils::parse_id_list;
use crate::utils::sanitize_html;

/// P3 修复: 通知公告枚举值白名单校验
/// notice_type: "1"=通知, "2"=公告
/// status: "0"=正常, "1"=关闭（可选字段，None 时跳过）
///
/// 合法值来自 [`NOTICE_TYPE_VALUES`] / [`NOTICE_STATUS_VALUES`]——**写侧（新增/修改）与
/// 查询侧（`?status=` 过滤）共用同一份常量**，否则「表单里能选的值」与「列表里能滤的值」
/// 会各自漂移（b80：查询侧此前根本没有 status 谓词，前端 `queryParams.status` 被 serde 静默丢弃）。
fn validate_notice_enum(notice_type: &str, status: Option<&str>) -> Result<(), ServiceError> {
    if !NOTICE_TYPE_VALUES.contains(&notice_type) {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.notice.notice_type_invalid",
            value = notice_type
        )));
    }
    if let Some(s) = status
        && !NOTICE_STATUS_VALUES.contains(&s)
    {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.notice.status_invalid",
            value = s
        )));
    }
    Ok(())
}

/// 公告状态合法值（`sys_notice.status`）；`NOTICE_STATUS_NORMAL` 是"用户可见面"
const NOTICE_STATUS_NORMAL: &str = "0";
const NOTICE_STATUS_VALUES: &[&str] = &[NOTICE_STATUS_NORMAL, "1"];
/// 公告类型合法值（`sys_notice.notice_type`）
const NOTICE_TYPE_VALUES: &[&str] = &["1", "2"];

/// 公告实时推送载荷（WS `notice`）
///
/// `action` 是前后端的稳定契约（b100）：
/// - `published`：新公告对用户可见 ⇒ 前端入通知中心并刷新铃铛
/// - `updated`：已发布公告内容变化 ⇒ 只刷新铃铛，不产生新通知
/// - `closed`：公告下架 ⇒ 只刷新铃铛
/// - `deleted`：公告删除 ⇒ 只刷新铃铛
///
/// 只投递到公告所属租户的在线连接（`broadcast_to_tenant`）；载荷不含正文，
/// 避免把可能含富文本的内容塞进浏览器原生通知。
fn notice_push_payload(model: &SysNoticeModel, action: &str) -> serde_json::Value {
    serde_json::json!({
        "action": action,
        "noticeId": model.notice_id,
        "title": model.notice_title,
        "noticeType": model.notice_type,
    })
}

/// 查询串里的枚举位归一：空/缺省 ⇒ `None`（不过滤）；命中白名单 ⇒ 该值；其余 ⇒ `reject(v)`
///
/// 为什么不能"非法值当没填"：那会让 `?status=9` 静默返回全量，UI 上表现为"筛选生效了但
/// 列表一条没少"——与 b74 抓到的"编译通过但永不执行"同一族。为什么不能"非法值也拦掉"：
/// 空串是 EP `clearable` 选择框清空后的真实产出，拦它等于把正常清空变成报错。
/// 返回 `&'static str` 而非 `String`：白名单值本身是常量，避免下游 `NoticeFilter` 借用 DTO。
///
/// `reject` 取闭包而非键名参数：`tr!` 的键必须是**字面量**（编译期展开），传 `&str` 变量
/// 直接编译不过——这正好把"每个查询位都有自己的文案键"钉在调用处。
fn parse_enum_query(
    raw: Option<&str>,
    allowed: &'static [&'static str],
    reject: impl Fn(&str) -> ServiceError,
) -> Result<Option<&'static str>, ServiceError> {
    let Some(v) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    allowed
        .iter()
        .copied()
        .find(|a| *a == v)
        .map(Some)
        .ok_or_else(|| reject(v))
}

/// `?status=` 查询位解析（文案键与写侧 `validate_notice_enum` 同一个）
fn parse_status_query(raw: Option<&str>) -> Result<Option<&'static str>, ServiceError> {
    parse_enum_query(raw, NOTICE_STATUS_VALUES, |v| {
        ServiceError::bad_request(&crate::tr!("error.notice.status_invalid", value = v))
    })
}

/// `?isRead=` ⇒ 已读态谓词：缺省/空 ⇒ 不过滤；`"1"` ⇒ 仅已读；`"0"` ⇒ 仅未读；其余 ⇒ 400
///
/// 取 `'0'/'1'` 而非 `true/false`：与仓内其余"状态位查询参数"（`status`、`noticeType`、
/// 字典值）同形，前端字典组件直接可用。
fn parse_is_read_query(raw: Option<&str>) -> Result<Option<bool>, ServiceError> {
    let reject =
        |v: &str| ServiceError::bad_request(&crate::tr!("error.notice.is_read_invalid", value = v));
    match parse_enum_query(raw, NOTICE_READ_VALUES, reject)? {
        None => Ok(None),
        // 白名单只有 "0"/"1"，其余分支不可能到达（parse_enum_query 已拒），
        // 但仍不写 `unreachable!`：将来往 NOTICE_READ_VALUES 加值时必须在这里显式表态
        Some(v) if v == NOTICE_READ_UNREAD => Ok(Some(false)),
        Some(v) if v == NOTICE_READ_READ => Ok(Some(true)),
        Some(v) => Err(reject(v)),
    }
}

/// `?isRead=` 合法值：未读 / 已读
const NOTICE_READ_UNREAD: &str = "0";
const NOTICE_READ_READ: &str = "1";
const NOTICE_READ_VALUES: &[&str] = &[NOTICE_READ_UNREAD, NOTICE_READ_READ];

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
    /// 状态精确过滤（`"0"` 正常 / `"1"` 关闭；缺省不过滤）
    ///
    /// b80 新增。前端 `views/system/notice/index.vue` 的 `queryParams.status` 与
    /// `NoticeQueryParams.status` 类型早已存在，但 DTO 没有这个字段 ⇒ serde 静默丢弃，
    /// 该筛选是**假控件**（选了值、请求照发、列表一条不少）。
    #[serde(default)]
    pub status: Option<String>,
    /// 已读态过滤（`"0"` 仅未读 / `"1"` 仅已读；缺省不过滤）
    ///
    /// b80 新增，取代通知中心的"前端过滤当前页"：后者只能过滤**当前页**，
    /// 分页 total 仍是全量 ⇒ "只看未读"翻页会翻到空页、且总数与筛选结果矛盾。
    /// 判定与铃铛未读数共用同一谓词（`SysNoticeRepository::base_query`）。
    #[serde(default)]
    pub is_read: Option<String>,
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

/// 公告行视图对象：公告本体 + **当前操作者的已读态**（b79 P3）
///
/// 为什么需要这一层：前端 `store/modules/notice.ts` 与 `views/system/notice-center/index.vue`
/// 一直按 `row.isRead` 渲染未读标签并把已读态合并进共享 store，而 `/system/notice/list`
/// 与 `/listTop` 返回的是裸 `SysNoticeModel`——**该字段从未存在过**。后果不是"少个字段"，
/// 而是整条已读链路只在内存里成立：刷新后 `readIds` 由 `listTop.isRead` 重建 ⇒ 空集合 ⇒
/// 全部退回"未读"，而同一时刻铃铛的 `unreadCount` 是服务端 `count_unread` 算出来的 0，
/// 两个界面互相矛盾（M87 真机取证：`markReadAll` 返回 200，刷新后行文本仍是「未读」）。
///
/// `flatten` 保证既有消费方（按 `noticeId`/`noticeTitle` 取数的页面与测试）零改动，
/// 新增字段只有 `isRead` 一个。
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct NoticeRowVo {
    /// 公告本体（字段与改造前逐字段等价）
    #[serde(flatten)]
    pub notice: SysNoticeModel,
    /// 当前操作者是否已读该公告（`sys_notice_read` 的 (notice_id, user_id) 行）
    pub is_read: bool,
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
    /// 支持 notice_title 模糊、notice_type 精确、create_by 精确、status 精确、时间范围筛选，
    /// 以及 b80 新增的**服务端已读态筛选**（`isRead`，按 `user_id` 的已读记录半连接）。
    ///
    /// `user_id` 用于已读态：`isRead` 缺省时不参与 SQL；给了就必须给出真实操作者 ID，
    /// 否则"未读"会退化成"全量"（这是另一条静默失效路径，故由参数而非默认值表达）。
    pub async fn get_notice_page(
        &self,
        query: NoticeQueryDto,
        operator_tid: i64,
        user_id: i64,
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
        // 枚举位先过白名单：非法值 400（不得静默当成"未填"，否则前端的筛选又变成一个
        // "选了值、发了请求、列表一条没少"的假控件——status 原本的处境正是如此）
        let status = parse_status_query(query.status.as_deref())?;
        let read = parse_is_read_query(query.is_read.as_deref())?;

        let filter = NoticeFilter {
            tenant_scope: crate::common::tenant::tenant_scope(operator_tid),
            title: query.notice_title.as_deref(),
            notice_type: query.notice_type.as_deref(),
            create_by: query.create_by.as_deref(),
            status,
            begin,
            end,
            read,
            user_id,
        };

        let (rows, total) = self
            .notice_repo
            .find_page_filtered(offset, limit, &filter, sort)
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
        state: Option<&Arc<AppState>>,
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

        // b100：已发布的公告立即推给同租户在线客户端（此前广播通道零生产者，
        // 前端订阅 `notice` 却永远收不到，铃铛要等重连/刷新才更新）。
        // 放在邮件群发之前：邮件是秒级出站，推送不该排队等它。
        if model.status.as_deref() == Some(NOTICE_STATUS_NORMAL)
            && let Some(st) = state
        {
            st.broadcast_to_tenant(
                model.tenant_id,
                "notice",
                notice_push_payload(&model, "published"),
            );
        }

        // 邮件通知（可选）：仅在调用方传入 AppState 且 dto.notify_email=true 时发送。
        //
        // **b140：渲染留在请求作用域、投递改走受守卫后台任务。** 改造前这里是
        // `self.send_notice_email(…).await`——一条 SMTP 批量投递挂在"新增公告"的请求上：
        // ① 公告行**早已提交**，投递却可能在请求层超时（默认档 120s，见
        // `middleware::request_timeout`）处被砍断 ⇒ 操作人看到 408/失败，而公告已经存在，
        // 于是"再点一次"会造出重复公告 + 第二轮群发；② 收件人数由租户人数决定，请求时长
        // 因此不可预测；③ 被砍断的那一批没有任何留痕能说明"发到第几封"。
        // 主题/正文/兜底文案取 `crate::tr!` 的请求 locale，**只能**在请求作用域内取；
        // 收件人枚举、偏好过滤与 SMTP 与 locale 无关，整体交给 `spawn_tracked`
        // （超时 + panic 隔离 + 结局指标，AGENTS B.6）。
        if dto.notify_email
            && let Some(st) = state
        {
            if st.mailer_service.is_enabled() {
                let mail = self
                    .render_notice_email(st, &dto.notice_title, safe_content.as_deref())
                    .await;
                let host = st.clone();
                let tenant_id = operator_tid;
                crate::common::background::spawn_tracked(
                    "notice_email_dispatch",
                    NOTICE_EMAIL_BUDGET,
                    Some(st.observability.metrics.clone()),
                    async move {
                        deliver_notice_emails(host, tenant_id, mail).await;
                    },
                );
            } else {
                tracing::debug!("邮件功能未启用，跳过通知公告邮件发送: {}", dto.notice_title);
            }
        }

        Ok(model)
    }

    /// 渲染公告邮件的**主题与正文**（必须在请求作用域内调用：取 `tr!` 的 locale）
    ///
    /// 与投递拆开是为了让 locale 依赖留在请求里；收件人枚举与 SMTP 都不依赖 locale，
    /// 因此可以（也应该）离开请求路径。
    async fn render_notice_email(
        &self,
        state: &AppState,
        title: &str,
        content: Option<&str>,
    ) -> NoticeMail {
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
        NoticeMail {
            subject: format!("{}{}", subject_prefix, title),
            body,
        }
    }

    /// 查询本租户所有启用状态用户的 (user_id, email)（status='0' 且 email 非空）
    ///
    /// 返回二元组以支持按用户偏好/免打扰过滤（enforcement）。
    /// tenant_id=0（平台）时不过滤，覆盖全部租户。
    async fn find_active_user_email_pairs(
        &self,
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
    ///
    /// `state` 用于把发布/下架/内容变更实时推给同租户在线客户端（None 时跳过推送，
    /// 与 `add_notice` 的邮件参数同口径：调度器等无 AppState 场景不投递）。
    pub async fn edit_notice(
        &self,
        dto: NoticeEditDto,
        operator: &str,
        operator_tid: i64,
        state: Option<&AppState>,
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
        // b100 推送判据：状态迁移与"已发布期间内容变化"都必须在 move 之前快照
        let was_published = existing_status.as_deref() == Some(NOTICE_STATUS_NORMAL);
        let existing_title_for_push = existing.notice_title.clone();
        let existing_content_for_push = existing_content.clone();
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

        // b100：状态迁移/内容变更实时推送（同租户）
        if let Some(st) = state {
            let is_published = model.status.as_deref() == Some(NOTICE_STATUS_NORMAL);
            let action = match (was_published, is_published) {
                (false, true) => Some("published"),
                (true, false) => Some("closed"),
                (true, true)
                    if model.notice_title != existing_title_for_push
                        || model.notice_content != existing_content_for_push =>
                {
                    Some("updated")
                }
                // 未发布 → 未发布：用户本就看不见，不推送
                // 已发布且内容未变：只改了 remark 等不可见面，不推送
                _ => None,
            };
            if let Some(action) = action {
                st.broadcast_to_tenant(
                    model.tenant_id,
                    "notice",
                    notice_push_payload(&model, action),
                );
            }
        }
        Ok(model)
    }

    /// 批量删除通知公告（物理删除，级联清理已读记录；事务内含 DELETE 审计留痕）
    ///
    /// `state` 用于在删除成功后通知同租户在线客户端刷新铃铛（None 时跳过）。
    pub async fn delete_notice(
        &self,
        notice_ids: Vec<i64>,
        operator: &str,
        operator_tid: i64,
        state: Option<&AppState>,
    ) -> Result<(), ServiceError> {
        // 批量校验记录存在（单次 SELECT 替代 N 次）
        if notice_ids.is_empty() {
            return Ok(());
        }
        // b130：先去重保序再判缺失——`?ids=735,735` 是完全合法的幂等请求，
        // 用原始长度当分母会把它判成「不存在」并零删除（台账 b130 §1）。
        let notice_ids = crate::common::batch_ids::dedupe_preserving_order(&notice_ids);
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
        // b100：删除后通知受影响租户刷新铃铛（批量里可能含多租户：平台操作者代管删除）
        if let Some(st) = state {
            let mut tenants: Vec<i64> = existing.iter().map(|n| n.tenant_id).collect();
            tenants.sort_unstable();
            tenants.dedup();
            for tenant_id in tenants {
                st.broadcast_to_tenant(
                    tenant_id,
                    "notice",
                    serde_json::json!({ "action": "deleted" }),
                );
            }
        }
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

    /// 顶部公告 + 当前操作者逐行已读态（`GET /system/notice/listTop` 的实际响应体）
    pub async fn get_notice_top_with_read(
        &self,
        operator_tid: i64,
        user_id: i64,
    ) -> Result<Vec<NoticeRowVo>, ServiceError> {
        let rows = self.get_notice_top(operator_tid).await?;
        self.attach_read_state(rows, user_id, operator_tid).await
    }

    /// 分页公告 + 当前操作者逐行已读态（`GET /system/notice/list` 的实际响应体）
    pub async fn get_notice_page_with_read(
        &self,
        query: NoticeQueryDto,
        operator_tid: i64,
        user_id: i64,
    ) -> Result<(Vec<NoticeRowVo>, u64), ServiceError> {
        let (rows, total) = self.get_notice_page(query, operator_tid, user_id).await?;
        Ok((
            self.attach_read_state(rows, user_id, operator_tid).await?,
            total,
        ))
    }

    /// 把"这一页里我读过哪些"贴到行上。
    ///
    /// 读侧谓词与列表侧**同源**：入参 `rows` 与已读查询套的是**同一个** `tenant_scope(operator_tid)`
    /// （AGENTS 全局铁律 1：先读后派生写的编排里，读侧与写侧必须共用同一租户谓词），
    /// 已读查询另用 `notice_id IN (本页)` 把规模钉在页内 ⇒ 一次查询、不可能带回本页之外的公告。
    async fn attach_read_state(
        &self,
        rows: Vec<SysNoticeModel>,
        user_id: i64,
        operator_tid: i64,
    ) -> Result<Vec<NoticeRowVo>, ServiceError> {
        let ids: Vec<i64> = rows.iter().map(|r| r.notice_id).collect();
        let read = self
            .read_repo
            .find_read_notice_ids_in(
                user_id,
                crate::common::tenant::tenant_scope(operator_tid),
                &ids,
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let is_read = read.contains(&r.notice_id);
                NoticeRowVo { notice: r, is_read }
            })
            .collect())
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
        let notice_ids: Vec<i64> = parse_id_list::<i64>(ids)?;
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

    /// 「我可见的未读公告」谓词——未读角标与跨页「全部已读」的**同一个**事实源
    ///
    /// 三条判据因此结构上不可能互相矛盾：
    /// `count_unread` = 本谓词的行数；`list?isRead=0` 的 total = 本谓词的行数；
    /// `mark_all_unread_read` 标记的集合 = 本谓词命中的行。
    /// 改造前角标用"总数 − 已读数"的**算术差**，一旦某条已读公告被置为关闭（status='1'），
    /// 它仍留在已读数里却不再留在总数里 ⇒ 差值被低估、`max(0)` 再把负数洗成 0（b80 修）。
    fn unread_filter(tenant_scope: Option<i64>, user_id: i64) -> NoticeFilter<'static> {
        NoticeFilter {
            tenant_scope,
            status: Some(NOTICE_STATUS_NORMAL),
            read: Some(false),
            user_id,
            ..Default::default()
        }
    }

    /// 标记用户所有未读公告为已读（"全部已读"功能）
    ///
    /// 与 mark_read_all 的区别：
    /// - mark_read_all 需要传入具体 notice IDs，前端只能拿到当前页的 ID
    /// - mark_all_unread_read 服务端按 `unread_filter` 取未读集合并标记，跨页未读也被清除
    ///
    /// 返回标记的条数（用于响应消息展示）。tenant_scope 由 operator 推导：
    /// 租户操作者仅处理本租户公告，平台操作者按公告实际租户分组写入（读记录租户随父公告）。
    pub async fn mark_all_unread_read(
        &self,
        user_id: i64,
        operator_tid: i64,
    ) -> Result<u64, ServiceError> {
        let tenant_scope = crate::common::tenant::tenant_scope(operator_tid);
        let filter = Self::unread_filter(tenant_scope, user_id);
        let notice_repo = self.notice_repo.clone();
        let read_repo = self.read_repo.clone();
        // 读未读集合与写已读记录必须同一事务：两步之间公告被删除时，非事务实现会把
        // 指向已删公告的读记录写进去（b80 台账 §6 立案）。返回的 marked 是**实际选中**
        // 的未读行数，与角标同源；写入走 `ON CONFLICT DO NOTHING`，并发重复标记仍幂等。
        let marked = self
            .db()
            .clone()
            .transaction::<_, u64, ServiceError>(move |txn| {
                let filter = filter.clone();
                let notice_repo = notice_repo.clone();
                let read_repo = read_repo.clone();
                async move {
                    let unread = notice_repo.find_id_tenant_pairs_conn(&filter, txn).await?;
                    if unread.is_empty() {
                        return Ok(0);
                    }
                    let marked = unread.len() as u64;
                    let mut by_tenant: std::collections::BTreeMap<i64, Vec<i64>> =
                        std::collections::BTreeMap::new();
                    for (notice_id, tid) in unread {
                        by_tenant.entry(tid).or_default().push(notice_id);
                    }
                    for (tid, ids) in by_tenant {
                        read_repo
                            .mark_read_batch_conn(txn, ids, user_id, tid)
                            .await?;
                    }
                    Ok(marked)
                }
                .boxed()
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Transaction(se) => se,
                sea_orm::TransactionError::Connection(db_err) => {
                    tracing::error!(error = %db_err, "mark_all_unread_read 事务连接错误");
                    ServiceError::internal(&crate::tr!("error.common.tx_failed"))
                }
            })?;
        Ok(marked)
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

    /// 统计可见公告总数（`status='0'`，不按已读/类型/标题筛选）
    ///
    /// 与 [`Self::count_unread`] 同一个谓词族（只差 `read` 轴），供通知中心顶部卡片
    /// 做"全部 / 未读 / 已读"三个数的自洽减法——列表接口的 `total` 会随筛选变化，不能当分母。
    pub async fn count_visible(&self, operator_tid: i64) -> Result<u64, ServiceError> {
        Ok(self
            .notice_repo
            .count_by_filter(&NoticeFilter {
                tenant_scope: crate::common::tenant::tenant_scope(operator_tid),
                status: Some(NOTICE_STATUS_NORMAL),
                ..Default::default()
            })
            .await?)
    }

    /// 统计用户未读公告数（按租户维度）
    ///
    /// 直接数 `unread_filter` 命中的行数——与 `list?isRead=0` 的 total、
    /// `mark_all_unread_read` 标记的条数三者同源（b80：改造前是两条 COUNT 的算术差，
    /// 已读公告被关闭时会被低估）。
    pub async fn count_unread(&self, user_id: i64, operator_tid: i64) -> Result<u64, ServiceError> {
        Ok(self
            .notice_repo
            .count_by_filter(&Self::unread_filter(
                crate::common::tenant::tenant_scope(operator_tid),
                user_id,
            ))
            .await?)
    }
}

/// 公告邮件群发的后台投递预算（**止损**，不是耗时预估）。
///
/// 取 30 分钟的依据是一条可算的容量式，而不是"感觉够用"：单封 SMTP 的硬上限是
/// `MAIL_SEND_TIMEOUT`（10s），批量并发是 `MAIL_BATCH_CONCURRENCY`（5），因此**最坏情况**
/// （每封都打满超时）下 30 分钟容得下
/// `30×60 / 10 × 5 = 900` 封；正常投递远快于超时上限，容量按比例更大。
/// 收件人**不设上限**——上限意味着有人收不到公告邮件，那是把功能砍掉而不是加护栏
/// （AGENTS 项目定位：能力全备）。超出容量的表现是 `run_tracked` 那条超时 WARN
/// （`bg:notice_email_dispatch{outcome="timeout"}`），而不是静默少发。
/// 翻这个数需要该指标的实测超时计数（AGENTS B.6 失败审计）。
const NOTICE_EMAIL_BUDGET: Duration = Duration::from_secs(30 * 60);

/// 编译期钳：**最坏情况容量必须够得着一次真实群发**。
///
/// 容量 = `预算 / MAIL_SEND_TIMEOUT × MAIL_BATCH_CONCURRENCY`（每封都打满超时时的下界）。
/// 三个量任一处被改动而容量掉到 500 封以下时，构建当场失败——这比"某天安超大批量、
/// 群发被预算砍在半截且没人知道为什么"便宜得多（AGENTS B.6 的编译期钳法：关系写在代码里，
/// 不留在注释里）。
const _: () = assert!(
    NOTICE_EMAIL_BUDGET.as_secs() / crate::common::constants::MAIL_SEND_TIMEOUT.as_secs()
        * crate::service::mailer_service::MAIL_BATCH_CONCURRENCY as u64
        >= 500,
    "公告邮件预算的最坏情况容量已低于 500 封：要么预算被调小，要么并发/单封超时被调大"
);

/// 公告邮件的渲染产物（主题 + HTML 正文）。
///
/// 单列一个类型的理由是把**生命周期**写进形状：主题/正文取 `tr!` 的请求 locale，只能在
/// 请求作用域内产出；收件人枚举与 SMTP 与 locale 无关，可以离开请求。渲染与投递分家之后，
/// 后台任务里不再有任何一处依赖"当前这个请求是谁、用什么语言"。
struct NoticeMail {
    subject: String,
    body: String,
}

/// 后台投递一封公告邮件给本租户全部满足偏好的收件人。
///
/// 语义（与改造前逐条保持）：邮件未启用不调用；无收件人 INFO 后返回；收件人查询失败
/// WARN 后返回；偏好查询失败**不投递**（原实现是"采用全部投递"却 `return`，注释与事实
/// 相反——这里按代码的真实结局写注释，失败就是不投）。
async fn deliver_notice_emails(state: Arc<AppState>, tenant_id: i64, mail: NoticeMail) {
    let title = mail.subject.clone();
    let pairs = match state
        .notice_service
        .find_active_user_email_pairs(tenant_id)
        .await
    {
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

    // 批量读取用户偏好，过滤出允许接收公告邮件的用户（email_notify 且 announce_notify，
    // 且不在免打扰窗口）
    let user_ids: Vec<i64> = pairs.iter().map(|(uid, _)| *uid).collect();
    let prefs = match state
        .notice_service
        .pref_repo
        .find_by_user_ids(&user_ids)
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("查询用户消息偏好失败，本次不投递: {}", e);
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
    // 群发规模必须可见：运维判断"这次为什么慢/为什么超时"的第一手事实是收件人数，
    // 而不是"发了一封公告邮件"。
    tracing::info!("公告邮件群发开始: 收件人 {} 封", emails.len());
    match state
        .mailer_service
        .send_batch(&emails, &mail.subject, &mail.body)
        .await
    {
        Ok(result) => {
            tracing::info!(
                "通知公告邮件发送完成: subject={}, total={}, success={}, failed={}",
                mail.subject,
                result.total,
                result.success,
                result.failed
            );
        }
        Err(e) => {
            tracing::warn!(
                "通知公告邮件发送失败: subject={}, error={}",
                mail.subject,
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 从两份 yml 里取某个 `error.notice.*` 文案（用于"运行期消息必须逐字命中真实文案"，
    /// 否则 `assert_eq!(err.message, tr!(同一个键))` 在键缺失时两边都等于键名 ⇒ 恒真虚锁，
    /// 见 b74 `data_rule_service` 同款教训）
    fn locale_texts(key_leaf: &str) -> Vec<String> {
        let mut out = Vec::new();
        for f in ["locales/zh-CN.yml", "locales/en-US.yml"] {
            let text = std::fs::read_to_string(f).unwrap_or_else(|e| panic!("{f} 读取失败: {e}"));
            let line = text
                .lines()
                .find(|l| l.trim_start().starts_with(&format!("{key_leaf}:")))
                .unwrap_or_else(|| panic!("{f} 缺 error.notice.{key_leaf} 键"));
            out.push(
                line.split_once(':')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .to_string(),
            );
        }
        out
    }

    /// 取 status 查询位的解析结果（意外拒绝直接 panic，拒绝路径由别的用例专判）
    fn status_of(v: Option<&str>) -> Option<&'static str> {
        parse_status_query(v).unwrap_or_else(|e| panic!("status={v:?} 意外被拒: {}", e.message))
    }

    #[test]
    fn enum_query_parser_treats_absent_and_blank_as_no_filter() {
        // 缺省、空串、纯空白都必须是"不过滤"——EP `clearable` 选择框清空后真实产出空串，
        // 把它当非法值拒掉等于让"清空筛选"变成报错（"为安全把合法值也挡掉"也是缺陷）
        assert_eq!(status_of(None), None);
        for blank in ["", "  ", "\t"] {
            assert_eq!(
                status_of(Some(blank)),
                None,
                "空白输入 {blank:?} 应视为未填"
            );
            assert!(
                parse_is_read_query(Some(blank))
                    .unwrap_or_else(|e| panic!("isRead={blank:?} 意外被拒: {}", e.message))
                    .is_none(),
                "空白 isRead 应视为未填"
            );
        }
    }

    #[test]
    fn enum_query_parser_accepts_exactly_the_whitelist() {
        for v in NOTICE_STATUS_VALUES {
            assert_eq!(status_of(Some(v)), Some(*v), "白名单内的 {v} 必须放行");
        }
        // 已读位：'0'⇒仅未读、'1'⇒仅已读（方向写反会让"只看未读"显示全量，且恒绿）
        assert_eq!(
            parse_is_read_query(Some(NOTICE_READ_UNREAD)).ok().flatten(),
            Some(false)
        );
        assert_eq!(
            parse_is_read_query(Some(NOTICE_READ_READ)).ok().flatten(),
            Some(true)
        );
        // 首尾空白容忍（表单值常带），但 'true' 这类字面量不在白名单
        assert_eq!(parse_is_read_query(Some(" 1 ")).ok().flatten(), Some(true));
        for bogus in ["true", "TRUE", "2", "-1", "abc", "0.5"] {
            assert!(
                parse_is_read_query(Some(bogus)).is_err(),
                "非法 isRead={bogus:?} 必须拒绝，不得静默当成未填"
            );
        }
        // 白名单值本身不得被自己拒掉（控制组：证明上一条的红来自值而非实现）
        for ok in NOTICE_READ_VALUES {
            assert!(
                parse_is_read_query(Some(ok)).is_ok(),
                "isRead={ok:?} 应放行"
            );
        }
    }

    #[test]
    fn enum_query_rejection_message_is_readable_and_echoes_value() {
        // 契约（C.8）：400 + 可读 msg + 回显用户给的值；msg 不得是原始键名
        let err = parse_status_query(Some("9")).expect_err("白名单外必须拒绝");
        assert_eq!(err.code, 400);
        assert!(!err.message.is_empty(), "错误消息不得为空");
        assert!(
            !err.message.contains("error."),
            "消息里出现了原始 i18n 键（键未解析）: {}",
            err.message
        );
        assert!(
            err.message.contains('9'),
            "消息必须回显非法值: {}",
            err.message
        );

        let key = "is_read_invalid";
        let err = parse_is_read_query(Some("zzz")).expect_err("白名单外必须拒绝");
        assert_eq!(err.code, 400);
        assert!(
            !err.message.contains("error."),
            "消息里出现了原始键: {}",
            err.message
        );
        assert!(
            err.message.contains("zzz"),
            "消息必须回显非法值: {}",
            err.message
        );
        // 逐字命中两份文案之一（去掉 %{value} 占位后的前缀必须原样出现在消息里）
        let hit = locale_texts(key).into_iter().any(|tpl| {
            err.message.starts_with(
                tpl.split_once("%{")
                    .map_or(tpl.as_str(), |x| x.0)
                    .trim_end(),
            )
        });
        assert!(hit, "运行期消息未逐字命中 yml 文案前缀: {}", err.message);
    }

    #[test]
    fn query_and_write_whitelists_agree_on_every_non_blank_value() {
        // 单一事实源判据：同一个**非空** status 值，查询侧放行 ⇔ 写侧放行。
        // 若两处各写一份字面量，就会出现"表单能存、列表滤不出来"或反之（b80 的起点缺陷）
        for v in ["0", "1", "2", "9", "x", "true"] {
            let query_ok = parse_status_query(Some(v)).is_ok();
            let write_ok = validate_notice_enum("1", Some(v)).is_ok();
            assert_eq!(query_ok, write_ok, "status={v:?} 查询侧与写侧判定不一致");
        }
        // 刻意的**不对称**：查询串里的空值 = 用户清空了筛选（放行且不过滤）；
        // 写侧的空串 = 载荷脏（拒）。把它俩强行写成一致必然坏掉一侧的真实行为
        assert!(
            parse_status_query(Some("")).is_ok(),
            "查询侧空值必须视为未填"
        );
        assert!(
            validate_notice_enum("1", Some("")).is_err(),
            "写侧空串必须拒（否则脏值落库）"
        );
    }

    #[test]
    fn unread_filter_wires_every_axis() {
        // 未读角标与"跨页全部已读"的唯一谓词。任一字段接错都会让两者与列表悄悄分家，
        // 而这条分家**不会报错**（只会数错），所以必须由构造级判据钉住
        let f = SysNoticeService::unread_filter(Some(7), 42);
        assert_eq!(
            f.tenant_scope,
            Some(7),
            "租户谓词必须透传（否则数到别租户公告）"
        );
        assert_eq!(
            f.status,
            Some(NOTICE_STATUS_NORMAL),
            "未读面只数正常状态公告"
        );
        assert_eq!(
            f.read,
            Some(false),
            "未读面必须是『未读』而非『已读』或不过滤"
        );
        assert_eq!(f.user_id, 42, "已读半连接必须绑定当前用户");
        // 平台视角（tenant_scope=None）保留 None，不得折成 Some(0)——那会把可见集合缩到租户 0
        let p = SysNoticeService::unread_filter(None, 1);
        assert_eq!(p.tenant_scope, None);
        // 时间/标题等无关轴必须为空，否则"全部已读"会跟着筛选条件漏标记
        assert!(f.title.is_none() && f.begin.is_none() && f.end.is_none());
        assert!(f.notice_type.is_none() && f.create_by.is_none());
    }

    /// b140 形状锁：**公告邮件群发不得挂在请求上**，且 **locale 相关的渲染必须留在
    /// 请求作用域内**（在 spawn 之前完成）。
    ///
    /// 立的案是改造前的 `self.send_notice_email(…).await`：一条 SMTP 批量投递串在
    /// "新增公告"请求里，而公告行早已提交 ⇒ 请求层超时砍断投递后，操作人看到失败、
    /// 再点一次就造出重复公告 + 第二轮群发。这条锁判的不是"有没有 await"这种写法，
    /// 而是**两条承诺**：① 投递经 `spawn_tracked`（超时 + panic 隔离 + 结局指标）；
    /// ② 渲染点排在派生之前——写反了会静默丢掉双语（后台任务里 `tr!` 落到兜底 locale），
    /// 而那正是本批最不该有的"改一个缺陷长出一个新缺陷"。
    #[test]
    fn notice_email_dispatch_leaves_the_request_path_after_rendering() {
        let view = crate::common::prod_scan::prod_file(
            "src/service/sys_notice_service.rs",
            &crate::common::prod_scan::Scan {
                comments: crate::common::prod_scan::Comments::Drop,
                ..Default::default()
            },
        )
        .text();

        let spawn = view
            .find("spawn_tracked(")
            .expect("邮件投递必须经 `spawn_tracked`（B.6 统一范式）；裸 `.await` 会挂在请求上");
        let render = view
            .find(".render_notice_email(")
            .expect("主题/正文必须在请求作用域内渲染，否则后台任务拿不到请求 locale");
        assert!(
            render < spawn,
            "渲染必须排在派生**之前**：先 spawn 再渲染 ⇒ `tr!` 在后台线程取到兜底 locale，\
             双语能力静默丢失"
        );
        assert!(
            view.contains("\"notice_email_dispatch\""),
            "后台任务必须有可归因的 label，否则 `/metrics` 里只有一句泛泛的 `bg:*` 超时"
        );
        // 旧的同步形状不得复活
        assert!(
            !view.contains("self.send_notice_email("),
            "邮件投递不得再挂在 `add_notice` 的请求路径上"
        );
        // 预算常量必须真被消费（写了没用 = 没写）
        assert!(
            view.contains("NOTICE_EMAIL_BUDGET"),
            "群发预算必须出现在派生点上，否则超时保护形同虚设"
        );
    }

    /// 合成反证：把两条承诺分别改回缺陷形状，判据必须各自抓到（互不顶班）。
    #[test]
    fn notice_email_shape_lock_is_falsifiable() {
        // ① 退回"请求内同步 await"
        let sync = concat!(
            "if dto.notify_email { ",
            "self.send_notice_email(st, tid, title, body).await; }",
        );
        assert!(
            sync.contains("self.send_notice_email(") && !sync.contains("spawn_tracked("),
            "合成夹具必须真的构成违规形状（否则这条正控是空跑）"
        );

        // ② 渲染排在派生之后（后台取 locale）——顺序反例必须是**可判**的
        let wrong_order = concat!(
            "let host = st.clone();\n",
            "spawn_tracked(async move { let mail = svc.render_notice_email().await; deliver(mail).await; });\n",
        );
        let r = wrong_order
            .find(".render_notice_email(")
            .expect("夹具必须含渲染点");
        let s = wrong_order
            .find("spawn_tracked(")
            .expect("夹具必须含派生点");
        assert!(
            r > s,
            "夹具必须把渲染排在派生**之后**，否则它不构成 ① 那条顺序判据的反例"
        );
        // 真实现必须落在相反的一侧——两侧都判，才不是"只期望抛错等于没测"
        let view = crate::common::prod_scan::prod_file(
            "src/service/sys_notice_service.rs",
            &crate::common::prod_scan::Scan {
                comments: crate::common::prod_scan::Comments::Drop,
                ..Default::default()
            },
        )
        .text();
        assert!(
            view.find(".render_notice_email(").unwrap() < view.find("spawn_tracked(").unwrap(),
            "真实实现的顺序关系必须与反例相反，否则两条判据在同一次改动里一起失效"
        );
    }

    /// b140：批量并发度只能由 `MAIL_BATCH_CONCURRENCY` 给——它是 `NOTICE_EMAIL_BUDGET`
    /// 容量算式的输入，写回字面量会让那条编译期断言量到一个不存在的并发度。
    #[test]
    fn mail_batch_concurrency_is_the_single_source() {
        let view = crate::common::prod_scan::prod_file(
            "src/service/mailer_service.rs",
            &crate::common::prod_scan::Scan {
                comments: crate::common::prod_scan::Comments::Drop,
                ..Default::default()
            },
        )
        .text();
        assert!(
            view.contains(".buffer_unordered(MAIL_BATCH_CONCURRENCY)"),
            "批量投递并发必须取常量"
        );
        assert!(
            !view.contains("buffer_unordered(5)"),
            "并发度不得再写回字面量 5：预算容量式读的是常量，两处各写一遍必然漂"
        );
    }

    /// b140：批量失败日志不得带收件地址（与本文件单封路径同口径，邮箱属 PII）。
    #[test]
    fn batch_send_failure_log_carries_no_recipient() {
        let view = crate::common::prod_scan::prod_file(
            "src/service/mailer_service.rs",
            &crate::common::prod_scan::Scan {
                comments: crate::common::prod_scan::Comments::Drop,
                ..Default::default()
            },
        )
        .text();
        assert!(
            !view.contains("批量发送邮件失败 to="),
            "批量失败日志曾逐封打印收件地址，一次群发失败即在日志留下整串个人邮箱"
        );
        assert!(
            view.contains("批量发送邮件失败"),
            "失败本身仍必须可见（只是不再经由日志泄露地址）——把整句删掉等于把失败藏起来"
        );
    }
}
