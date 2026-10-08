//! 消息渠道与模板管理模块 Service 层
//!
//! 职责：
//! - 消息渠道 CRUD（分页查询、详情、新增、修改、批量删除、连通性测试）
//! - 消息模板 CRUD（分页查询、详情、新增、修改、批量删除）
//! - 发送记录管理（分页查询、批量删除、清空）
//! - 模板变量渲染（`{{var}}` 占位符替换）
//! - 直接发送（按模板 + 渠道落地）
//! - 失败重试（指定记录重试 + 待重试批次批量重试，供定时任务调用）
//!
//! 分层约束：不依赖任何 Web 框架类型（axum / tower / tower-http），
//! 数据访问委托 Repository 层，状态/错误使用 ServiceError。
//!
//! 投递语义：
//! - email 渠道：实际经 MailerService（全局 SMTP 配置）发送
//! - sms / site 渠道：当前无外部网关/站内投递实现，记录日志后视为模拟成功
//! - 发送失败时记录 status='2'（待重试），由 retry_logs / retry_pending 重试，
//!   重试耗尽（retry_count >= max_retry_count）后置为 status='1'（失败）

use std::collections::HashMap;
use std::sync::Arc;

use garde::Validate;
use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::encrypted_value::EncryptedString;
use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::config::Settings;
use crate::entity::sys_msg_channel::{
    ActiveModel as SysMsgChannelActiveModel, Column as ChannelColumn, Model as SysMsgChannelModel,
};
use crate::entity::sys_msg_send_log::{
    ActiveModel as SysMsgSendLogActiveModel, Column as SendLogColumn, Model as SysMsgSendLogModel,
};
use crate::entity::sys_msg_template::{
    ActiveModel as SysMsgTemplateActiveModel, Column as TemplateColumn,
    Model as SysMsgTemplateModel,
};
use crate::repository::sys_msg_channel::SysMsgChannelRepository;
use crate::repository::sys_msg_send_log::SysMsgSendLogRepository;
use crate::repository::sys_msg_template::SysMsgTemplateRepository;
use crate::repository::sys_user_pref::SysUserPrefRepository;
use crate::service::MailerService;
use crate::service::sms_provider::SmsProvider;
use crate::service::sys_user_pref_service::{PrefChannel, allows_delivery, now_hm_str};
use crate::utils::parse_id_list;

/// 渠道类型白名单（与实体/迁移保持一致）
/// 批次十八：+wecom_robot / dingtalk_robot（IM 群机器人——G-15b 小程序的更优替代）
const CHANNEL_TYPES: &[&str] = &["email", "sms", "site", "wecom_robot", "dingtalk_robot"];
/// 默认最大重试次数
const DEFAULT_MAX_RETRY: i32 = 3;

/// 校验渠道类型是否在白名单内
fn validate_channel_type(channel_type: &str) -> Result<(), ServiceError> {
    if CHANNEL_TYPES.contains(&channel_type) {
        Ok(())
    } else {
        Err(ServiceError::bad_request(&crate::tr!(
            "error.msg.channel_type_invalid",
            channel_type = channel_type
        )))
    }
}

/// 渲染模板：将 {{var}} 占位符替换为 params 中的值；未提供的变量替换为空串。
///
/// 手工扫描实现，避免引入正则依赖，同时天然避免用户输入中的正则元字符误解释。
///
/// **有意不引模板引擎**（G-16 深审 2026-10-06 决策）：消息模板场景只需"变量替换"，
/// 不需要控制流（if/for）；引入 minijinja/tera 是为用不到的能力付费（tera 已在
/// 依赖树但仅用于代码生成器脚手架）。若未来确需循环渲染（列表类消息），届时
/// 再评估复用 tera——在此之前请勿重复立项引引擎。
fn render_template(template: &str, params: &HashMap<String, String>) -> String {
    let mut result = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        result.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        match tail.find("}}") {
            Some(end_rel) => {
                let key = tail[..end_rel].trim();
                let value = params.get(key).map(String::as_str).unwrap_or("");
                result.push_str(value);
                rest = &tail[end_rel + 2..];
            }
            None => {
                // 无闭合括号：视为字面量原样追加
                result.push_str(&rest[start..]);
                return result;
            }
        }
    }
    result.push_str(rest);
    result
}

// ==================== DTO ====================

/// 消息渠道分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct ChannelQueryDto {
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
    pub channel_name: Option<String>,
    pub channel_code: Option<String>,
    pub channel_type: Option<String>,
    pub status: Option<String>,
}

impl From<&ChannelQueryDto> for PageDomain {
    fn from(dto: &ChannelQueryDto) -> Self {
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

/// 消息渠道新增 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChannelAddDto {
    #[garde(length(min = 1, max = 64))]
    pub channel_name: String,
    #[garde(length(min = 1, max = 64))]
    pub channel_code: String,
    /// 渠道类型（email/sms/site）
    #[garde(length(min = 1, max = 32))]
    pub channel_type: String,
    #[garde(skip)]
    pub config_json: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 消息渠道修改 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChannelEditDto {
    #[garde(skip)]
    pub channel_id: i64,
    #[garde(length(min = 1, max = 64))]
    pub channel_name: String,
    #[garde(length(min = 1, max = 64))]
    pub channel_code: String,
    /// 渠道类型（email/sms/site）
    #[garde(length(min = 1, max = 32))]
    pub channel_type: String,
    #[garde(skip)]
    pub config_json: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
    /// 显式清空声明（批次 4）：列出的字段写 NULL；缺省 = 保持现值（见 `common::clear_fields`）
    #[serde(default)]
    #[garde(skip)]
    pub clear_fields: Option<Vec<String>>,
}

/// 「显式清空」契约：`configJson` 是**默认安全语义**下唯一清不掉、又确实需要清掉的字段。
///
/// 背景：`config_json` 未传/空串 = 保持现值（防"只改名称的 PUT 擦除已加密的 SMTP 凭据"），
/// 故清空必须显式声明。`remark` 不列入：它的更新语义本就是"未传即写 NULL"，无需额外通道。
impl crate::common::clear_fields::ClearFieldsDto for ChannelEditDto {
    const CLEARABLE_FIELDS: &'static [&'static str] = &["configJson"];

    fn clear_fields(&self) -> Option<&[String]> {
        self.clear_fields.as_deref()
    }

    fn field_value_is_present(&self, field: &str) -> bool {
        match field {
            "configJson" => {
                crate::common::clear_fields::value_is_present(self.config_json.as_deref())
            }
            _ => false,
        }
    }
}

/// 消息渠道出参 VO（G-14：实体 config_json 为 EncryptedString 加密列，
/// Model 直接序列化会输出掩码；渠道配置遵循"管理员配置**明文回显**"产品语义
/// ——编辑表单需回填，故经 VO 显式声明出参为解密后明文，字段与 Model 同构）
#[derive(Debug, Clone, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChannelVo {
    pub tenant_id: i64,
    pub channel_id: i64,
    pub channel_name: String,
    pub channel_code: String,
    pub channel_type: String,
    pub config_json: Option<String>,
    pub status: Option<String>,
    pub create_by: Option<String>,
    pub create_time: Option<String>,
    pub update_by: Option<String>,
    pub update_time: Option<String>,
    pub remark: Option<String>,
    pub del_flag: Option<String>,
}

impl ChannelVo {
    fn from_model(m: &SysMsgChannelModel) -> Self {
        Self {
            tenant_id: m.tenant_id,
            channel_id: m.channel_id,
            channel_name: m.channel_name.clone(),
            channel_code: m.channel_code.clone(),
            channel_type: m.channel_type.clone(),
            // 读路径已自动解密，直取明文（管理员配置回显）
            config_json: m.config_json.as_ref().map(|e| e.0.clone()),
            status: m.status.clone(),
            create_by: m.create_by.clone(),
            create_time: m.create_time.map(|t| t.to_string()),
            update_by: m.update_by.clone(),
            update_time: m.update_time.map(|t| t.to_string()),
            remark: m.remark.clone(),
            del_flag: m.del_flag.clone(),
        }
    }
}

/// 消息模板分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct TemplateQueryDto {
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
    pub template_name: Option<String>,
    pub template_code: Option<String>,
    pub channel_code: Option<String>,
    pub status: Option<String>,
}

impl From<&TemplateQueryDto> for PageDomain {
    fn from(dto: &TemplateQueryDto) -> Self {
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

/// 消息模板新增 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TemplateAddDto {
    #[garde(length(min = 1, max = 64))]
    pub template_name: String,
    #[garde(length(min = 1, max = 64))]
    pub template_code: String,
    /// 渠道编码（默认 email）
    #[garde(length(max = 64))]
    pub channel_code: Option<String>,
    /// 模板主题（支持 {{var}} 变量）
    #[garde(length(min = 1, max = 200))]
    pub template_subject: String,
    /// 模板内容（支持 {{var}} 变量）
    #[garde(length(min = 1))]
    pub template_content: String,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 消息模板修改 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TemplateEditDto {
    #[garde(skip)]
    pub template_id: i64,
    #[garde(length(min = 1, max = 64))]
    pub template_name: String,
    #[garde(length(min = 1, max = 64))]
    pub template_code: String,
    /// 渠道编码（默认 email）
    #[garde(length(max = 64))]
    pub channel_code: Option<String>,
    /// 模板主题（支持 {{var}} 变量）
    #[garde(length(min = 1, max = 200))]
    pub template_subject: String,
    /// 模板内容（支持 {{var}} 变量）
    #[garde(length(min = 1))]
    pub template_content: String,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 发送记录分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct SendLogQueryDto {
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
    pub to_addr: Option<String>,
    pub template_code: Option<String>,
    pub channel_code: Option<String>,
    pub status: Option<String>,
    /// 发送时间范围-起（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 发送时间范围-止（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&SendLogQueryDto> for PageDomain {
    fn from(dto: &SendLogQueryDto) -> Self {
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

/// 直接发送 DTO（按模板 + 渠道 + 参数落地）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SendDto {
    /// 模板编码
    #[garde(length(min = 1, max = 64))]
    pub template_code: String,
    /// 渠道编码（缺省使用模板默认渠道）
    #[garde(length(max = 64))]
    pub channel_code: Option<String>,
    /// 收件地址（邮箱/手机号/站内用户）
    #[garde(length(min = 1, max = 200))]
    pub to_addr: String,
    /// 模板变量参数（key → value）
    #[garde(skip)]
    pub params: HashMap<String, String>,
}

// ==================== Service ====================

/// 允许排序的渠道列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖渠道业务展示列；`config_json`（密钥配置）、`tenant_id` / `del_flag` 等内部列不开放动态排序。
const CHANNEL_SORTABLE_COLUMNS: &[(&str, ChannelColumn)] = &[
    ("channel_id", ChannelColumn::ChannelId),
    ("channel_name", ChannelColumn::ChannelName),
    ("channel_code", ChannelColumn::ChannelCode),
    ("channel_type", ChannelColumn::ChannelType),
    ("status", ChannelColumn::Status),
    ("create_time", ChannelColumn::CreateTime),
    ("update_time", ChannelColumn::UpdateTime),
];

/// 允许排序的模板列白名单（数据库列名 snake_case）。
///
/// `template_subject` / `template_content`（长文本）与内部列不开放动态排序。
const TEMPLATE_SORTABLE_COLUMNS: &[(&str, TemplateColumn)] = &[
    ("template_id", TemplateColumn::TemplateId),
    ("template_name", TemplateColumn::TemplateName),
    ("template_code", TemplateColumn::TemplateCode),
    ("channel_code", TemplateColumn::ChannelCode),
    ("status", TemplateColumn::Status),
    ("create_time", TemplateColumn::CreateTime),
    ("update_time", TemplateColumn::UpdateTime),
];

/// 允许排序的发送记录列白名单（数据库列名 snake_case）。
///
/// 覆盖发送记录业务展示列（含重试次数/发送时间）；`subject` / `content` / `last_error`
/// （长文本）与 `tenant_id` 等内部列不开放动态排序。
const SEND_LOG_SORTABLE_COLUMNS: &[(&str, SendLogColumn)] = &[
    ("log_id", SendLogColumn::LogId),
    ("template_code", SendLogColumn::TemplateCode),
    ("channel_code", SendLogColumn::ChannelCode),
    ("to_addr", SendLogColumn::ToAddr),
    ("status", SendLogColumn::Status),
    ("retry_count", SendLogColumn::RetryCount),
    ("send_time", SendLogColumn::SendTime),
    ("create_time", SendLogColumn::CreateTime),
];

/// 消息渠道与模板管理模块 Service
pub struct SysMsgService {
    channel_repo: SysMsgChannelRepository,
    template_repo: SysMsgTemplateRepository,
    send_log_repo: SysMsgSendLogRepository,
    /// 邮件发送 Service（email 渠道实际投递用）
    mailer: MailerService,
    /// 用户消息偏好 Repository（site 站内信需尊重用户的站内信开关与免打扰）
    pref_repo: SysUserPrefRepository,
}

/// 云厂商模板制投递上下文（G-07 扩展）：云端模板 code + 原始渲染参数 JSON 快照。
/// 快照落 `sys_msg_send_log.sms_params`，重试时原样还原（云厂商无法从渲染后文本反推参数）。
struct SmsCloudCtx<'a> {
    template_code: &'a str,
    params_json: String,
}

impl SysMsgService {
    pub fn new(db: DatabaseConnection, config: Arc<Settings>) -> Self {
        Self {
            channel_repo: SysMsgChannelRepository::new(db.clone()),
            template_repo: SysMsgTemplateRepository::new(db.clone()),
            send_log_repo: SysMsgSendLogRepository::new(db.clone()),
            mailer: MailerService::new(config.clone()),
            pref_repo: SysUserPrefRepository::new(db),
        }
    }

    /// G-16：按编码渲染平台默认模板（不做渠道查找/不落发送记录）
    ///
    /// 供"自带投递链路、只需模板内容"的业务复用（如公告邮件：有用户枚举/偏好过滤/
    /// 批量发送逻辑，比 [`Self::send`] 的单地址投递更重）。语义：
    /// - 模板不存在或已停用 → `Ok(None)`，调用方回落内置默认内容；
    /// - 渲染失败不可能（render_template 无失败路径），返回值恒为渲染后文本。
    pub async fn render_template_by_code(
        &self,
        template_code: &str,
        params: &HashMap<String, String>,
    ) -> Result<Option<(String, String)>, ServiceError> {
        let Some(template) = self.template_repo.find_by_code(template_code, None).await? else {
            return Ok(None);
        };
        if template.status.as_deref() != Some("0") {
            return Ok(None);
        }
        Ok(Some((
            render_template(&template.template_subject, params),
            render_template(&template.template_content, params),
        )))
    }

    /// 校验 config_json 为合法 JSON（存在时）
    fn validate_config_json(config: &Option<String>) -> Result<(), ServiceError> {
        if let Some(json) = config
            && !json.trim().is_empty()
        {
            serde_json::from_str::<serde_json::Value>(json).map_err(|e| {
                tracing::warn!("渠道配置 JSON 解析失败: {}", e);
                ServiceError::bad_request(&crate::tr!("error.msg.config_json_invalid"))
            })?;
        }
        Ok(())
    }

    // ==================== 消息渠道 ====================

    /// 分页查询消息渠道
    pub async fn get_channel_page(
        &self,
        query: ChannelQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<ChannelVo>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_msg_channel::Entity>(
                prop,
                CHANNEL_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let (rows, total) = self
            .channel_repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                query.channel_name.as_deref(),
                query.channel_code.as_deref(),
                query.channel_type.as_deref(),
                query.status.as_deref(),
                crate::common::tenant::tenant_scope(operator_tid),
                sort,
            )
            .await?;
        // G-14：实体读路径已自动解密，出参经 VO 明文回显（管理员配置回填语义）
        Ok((rows.iter().map(ChannelVo::from_model).collect(), total))
    }

    /// 查询渠道详情
    pub async fn get_channel_by_id(
        &self,
        channel_id: i64,
        operator_tid: i64,
    ) -> Result<ChannelVo, ServiceError> {
        // G-14：实体读路径已自动解密，出参经 VO 明文回显（管理员配置回填语义）
        Ok(ChannelVo::from_model(
            &self
                .get_channel_model_by_id(channel_id, operator_tid)
                .await?,
        ))
    }

    /// 内部：查询渠道 Model（含越权校验；供 edit 等需要 ActiveModel 转移所有权的路径复用）
    async fn get_channel_model_by_id(
        &self,
        channel_id: i64,
        operator_tid: i64,
    ) -> Result<SysMsgChannelModel, ServiceError> {
        let model = self
            .channel_repo
            .find_active_by_id(channel_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.msg.channel_not_found")))?;
        // 越权防护：租户管理员不得读取其他租户消息渠道
        if !crate::common::tenant::tenant_allowed(operator_tid, model.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        Ok(model)
    }

    /// 新增消息渠道
    pub async fn add_channel(
        &self,
        dto: ChannelAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<ChannelVo, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        validate_channel_type(&dto.channel_type)?;
        Self::validate_config_json(&dto.config_json)?;

        if self.channel_repo.exists_by_code(&dto.channel_code).await? {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.msg.channel_code_duplicate"
            )));
        }

        let now = crate::common::datetime::now_naive();
        // G-14：config_json（含 SMTP 等凭据）走 EncryptedString 列类型，
        // Set 转换时自动加密（enc3 信封；密钥未配置时迁移期 fail-open 明文）
        let am = SysMsgChannelActiveModel {
            tenant_id: Set(operator_tid),
            channel_name: Set(dto.channel_name),
            channel_code: Set(dto.channel_code),
            channel_type: Set(dto.channel_type),
            config_json: Set(dto.config_json.map(EncryptedString::plaintext)),
            status: Set(dto.status.or(Some("0".to_string()))),
            remark: Set(dto.remark),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        };
        let model = self.channel_repo.insert(am).await?;
        Ok(ChannelVo::from_model(&model))
    }

    /// 修改消息渠道
    pub async fn edit_channel(
        &self,
        dto: ChannelEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<ChannelVo, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        validate_channel_type(&dto.channel_type)?;
        Self::validate_config_json(&dto.config_json)?;
        // 显式清空声明（批次 4）：白名单校验 + 与提交值冲突检测（400），缺省为空集
        let clears = crate::common::clear_fields::resolve(&dto)?;

        let existing = self.get_channel_by_id(dto.channel_id, operator_tid).await?;
        // 唯一编码校验（排除自身）
        if existing.channel_code != dto.channel_code
            && self.channel_repo.exists_by_code(&dto.channel_code).await?
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.msg.channel_code_duplicate"
            )));
        }

        // 部分更新语义快照（existing Model 随即被 `into()` 转移）：未传字段保持现值
        let existing = self
            .get_channel_model_by_id(dto.channel_id, operator_tid)
            .await?;
        let existing_status = existing.status.clone();
        let mut am: SysMsgChannelActiveModel = existing.into();
        am.channel_name = Set(dto.channel_name);
        am.channel_code = Set(dto.channel_code);
        am.channel_type = Set(dto.channel_type);
        // G-14：config_json 走 EncryptedString 列类型，Set 转换时自动加密。
        // **部分更新语义（2026-09-26 缺陷修复）**：仅当显式传入非空配置时才覆盖，
        // 否则保持现值——避免"只改名称"的 PUT 把已加密的渠道配置/密钥擦除为 NULL。
        if let Some(c) = dto.config_json.as_deref().filter(|c| !c.is_empty()) {
            am.config_json = Set(Some(EncryptedString::plaintext(c.to_string())));
        }
        // ③ 显式清空（批次 4）：`clearFields: ["configJson"]` ⇒ 写 NULL（清掉历史凭据）。
        //    与 ② 互斥由 `clear_fields::resolve` 的冲突检测保证（同时给值 + 声明清空 ⇒ 400）。
        if crate::common::clear_fields::is_cleared(&clears, "configJson") {
            am.config_json = Set(None);
        }
        // status 未传时保持现值，避免渠道被静默置 NULL 失效
        am.status = Set(dto.status.or(existing_status));
        am.remark = Set(dto.remark);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(crate::common::datetime::now_naive()));

        let model = self.channel_repo.update(am).await?;
        Ok(ChannelVo::from_model(&model))
    }

    /// 批量删除消息渠道（物理删除；被模板引用的渠道拒绝删除）
    pub async fn delete_channel(
        &self,
        channel_ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if channel_ids.is_empty() {
            return Ok(());
        }
        let existing = self.channel_repo.find_by_ids(&channel_ids).await?;
        if existing.len() != channel_ids.len() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.msg.channel_not_found"
            )));
        }
        // 越权防护：租户管理员不得跨租户删除消息渠道
        if existing
            .iter()
            .any(|c| !crate::common::tenant::tenant_allowed(operator_tid, c.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        // 引用校验：任一渠道被启用模板引用则拒绝删除
        for channel in &existing {
            let refs = self
                .template_repo
                .count_by_channel_code(
                    &channel.channel_code,
                    crate::common::tenant::tenant_scope(operator_tid),
                )
                .await?;
            if refs > 0 {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.msg.channel_in_use",
                    channel_name = channel.channel_name
                )));
            }
        }
        self.channel_repo.delete_by_ids(channel_ids).await?;
        Ok(())
    }

    /// 渠道连通性测试（email 校验 SMTP 配置可用；sms/site 校验配置合法性）
    pub async fn test_channel(
        &self,
        channel_id: i64,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let channel = self
            .get_channel_model_by_id(channel_id, operator_tid)
            .await?;
        match channel.channel_type.as_str() {
            "email" => {
                if !self.mailer.is_enabled() {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.msg.mail_disabled"
                    )));
                }
                Ok(())
            }
            "site" => Ok(()),
            "sms" => {
                // G-07：sms 校验配置完整性（gateway_url/鉴权头配对等），fail-closed
                let cfg = crate::service::sms_provider::SmsChannelConfig::from_config_json(
                    channel.config_json.as_ref().map(|e| e.0.as_str()),
                )
                .map_err(|e| {
                    tracing::warn!(
                        "短信渠道 {} 连通性测试：配置无效: {}",
                        channel.channel_code,
                        e
                    );
                    ServiceError::bad_request(&crate::tr!("error.msg.sms_config_invalid"))
                })?;
                let provider = crate::service::sms_provider::GenericHttpProvider::new();
                provider.probe(&cfg).await.map_err(|e| {
                    ServiceError::bad_request(&format!(
                        "{}: {e}",
                        crate::tr!("error.msg.sms_config_invalid")
                    ))
                })
            }
            // 批次十八：IM 机器人渠道连通性测试 = 配置解析 fail-closed（webhookUrl 形态/
            // secret 可选）；真实可达性由"测试发送"真投递验证（与 sms probe 同语义）
            "wecom_robot" | "dingtalk_robot" => {
                crate::service::im_robot_provider::ImRobotConfig::from_config_json(
                    channel.config_json.as_ref().map(|e| e.0.as_str()),
                )
                .map(|_| ())
                .map_err(|e| {
                    tracing::warn!(
                        "IM 机器人渠道 {} 连通性测试：配置无效: {}",
                        channel.channel_code,
                        e
                    );
                    ServiceError::bad_request(&crate::tr!("error.msg.robot_config_invalid"))
                })
            }
            _ => Err(ServiceError::bad_request(&crate::tr!(
                "error.msg.channel_type_invalid"
            ))),
        }
    }

    // ==================== 消息模板 ====================

    /// 分页查询消息模板
    pub async fn get_template_page(
        &self,
        query: TemplateQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<SysMsgTemplateModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_msg_template::Entity>(
                prop,
                TEMPLATE_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let (rows, total) = self
            .template_repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                query.template_name.as_deref(),
                query.template_code.as_deref(),
                query.channel_code.as_deref(),
                query.status.as_deref(),
                crate::common::tenant::tenant_scope(operator_tid),
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询模板详情
    pub async fn get_template_by_id(
        &self,
        template_id: i64,
        operator_tid: i64,
    ) -> Result<SysMsgTemplateModel, ServiceError> {
        let model = self
            .template_repo
            .find_active_by_id(template_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.msg.template_not_found")))?;
        // 越权防护：租户管理员不得读取其他租户消息模板
        if !crate::common::tenant::tenant_allowed(operator_tid, model.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        Ok(model)
    }

    /// 校验模板绑定的渠道存在且启用（按模板租户维度查找渠道）
    async fn validate_channel_exists(
        &self,
        channel_code: &str,
        tenant_id: i64,
    ) -> Result<SysMsgChannelModel, ServiceError> {
        let channel = self
            .channel_repo
            .find_by_code(channel_code, crate::common::tenant::tenant_scope(tenant_id))
            .await?
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.msg.channel_not_found")))?;
        if channel.status.as_deref() != Some("0") {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.msg.channel_disabled"
            )));
        }
        Ok(channel)
    }

    /// 新增消息模板
    pub async fn add_template(
        &self,
        dto: TemplateAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysMsgTemplateModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        let channel_code = dto
            .channel_code
            .clone()
            .unwrap_or_else(|| "email".to_string());
        self.validate_channel_exists(&channel_code, operator_tid)
            .await?;

        if self
            .template_repo
            .exists_by_code(&dto.template_code)
            .await?
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.msg.template_code_duplicate"
            )));
        }

        let now = crate::common::datetime::now_naive();
        let am = SysMsgTemplateActiveModel {
            tenant_id: Set(operator_tid),
            template_name: Set(dto.template_name),
            template_code: Set(dto.template_code),
            channel_code: Set(channel_code),
            template_subject: Set(dto.template_subject),
            template_content: Set(dto.template_content),
            status: Set(dto.status.or(Some("0".to_string()))),
            remark: Set(dto.remark),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        };
        let model = self.template_repo.insert(am).await?;
        Ok(model)
    }

    /// 修改消息模板
    pub async fn edit_template(
        &self,
        dto: TemplateEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysMsgTemplateModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let existing = self
            .get_template_by_id(dto.template_id, operator_tid)
            .await?;
        // 部分更新语义（2026-09-26 缺陷修复）：未传渠道编码时保持现值，
        // 而非硬编码回落 "email"（否则"只改正文"的 PUT 会把模板静默切到 email 渠道）。
        let channel_code = dto
            .channel_code
            .clone()
            .unwrap_or_else(|| existing.channel_code.clone());
        self.validate_channel_exists(&channel_code, operator_tid)
            .await?;
        if existing.template_code != dto.template_code
            && self
                .template_repo
                .exists_by_code(&dto.template_code)
                .await?
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.msg.template_code_duplicate"
            )));
        }

        // status 未传时保持现值（避免模板被静默置 NULL 失效）
        let existing_status = existing.status.clone();
        let mut am: SysMsgTemplateActiveModel = existing.into();
        am.template_name = Set(dto.template_name);
        am.template_code = Set(dto.template_code);
        am.channel_code = Set(channel_code);
        am.template_subject = Set(dto.template_subject);
        am.template_content = Set(dto.template_content);
        am.status = Set(dto.status.or(existing_status));
        am.remark = Set(dto.remark);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(crate::common::datetime::now_naive()));

        let model = self.template_repo.update(am).await?;
        Ok(model)
    }

    /// 批量删除消息模板
    pub async fn delete_template(
        &self,
        template_ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if template_ids.is_empty() {
            return Ok(());
        }
        let existing = self.template_repo.find_by_ids(&template_ids).await?;
        if existing.len() != template_ids.len() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.msg.template_not_found"
            )));
        }
        // 越权防护：租户管理员不得跨租户删除消息模板
        if existing
            .iter()
            .any(|t| !crate::common::tenant::tenant_allowed(operator_tid, t.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        self.template_repo.delete_by_ids(template_ids).await?;
        Ok(())
    }

    // ==================== 发送记录 ====================

    /// 分页查询发送记录
    pub async fn get_send_log_page(
        &self,
        query: SendLogQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<SysMsgSendLogModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_msg_send_log::Entity>(
                prop,
                SEND_LOG_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        // P1：时间解析统一走 parse_query_date（本地日→UTC），与全项目一致
        let begin_time = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end_time = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let (rows, total) = self
            .send_log_repo
            .find_page_filtered(
                page.offset(),
                page.limit(),
                query.to_addr.as_deref(),
                query.template_code.as_deref(),
                query.channel_code.as_deref(),
                query.status.as_deref(),
                begin_time,
                end_time,
                crate::common::tenant::tenant_scope(operator_tid),
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 批量删除发送记录
    pub async fn delete_send_logs(
        &self,
        log_ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if log_ids.is_empty() {
            return Ok(());
        }
        let existing = self.send_log_repo.find_by_ids(&log_ids).await?;
        if existing.len() != log_ids.len() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.msg.log_not_found"
            )));
        }
        // 越权防护：租户管理员不得跨租户删除发送记录
        if existing
            .iter()
            .any(|l| !crate::common::tenant::tenant_allowed(operator_tid, l.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        self.send_log_repo.delete_by_ids(log_ids).await?;
        Ok(())
    }

    /// 清空发送记录（按操作者租户维度，禁止跨租户 mass-clean）
    pub async fn clean_send_logs(
        &self,
        limit: Option<u64>,
        operator_tid: i64,
    ) -> Result<u64, ServiceError> {
        let result = self
            .send_log_repo
            .clean(limit, crate::common::tenant::tenant_scope(operator_tid))
            .await?;
        Ok(result)
    }

    // ==================== 投递内核 ====================

    /// 按渠道类型实际投递消息
    ///
    /// - email：经 MailerService（全局 SMTP 配置）真实发送
    /// - sms：按渠道 `config_json.provider` 分发——generic 走自由文本 HTTP 网关，
    ///   aliyun/tencent 走云厂商模板制投递（需 `sms_ctx` 携带云端模板 code 与原始参数；
    ///   `send_log.sms_params` 快照保证重试可还原）
    /// - site：站内信投递（尊重用户偏好）
    async fn dispatch(
        &self,
        channel: &SysMsgChannelModel,
        to_addr: &str,
        subject: &str,
        content: &str,
        sms_ctx: Option<SmsCloudCtx<'_>>,
    ) -> Result<(), ServiceError> {
        match channel.channel_type.as_str() {
            "email" => {
                if !self.mailer.is_enabled() {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.msg.mail_disabled"
                    )));
                }
                self.mailer.send_text(to_addr, subject, content).await?;
                Ok(())
            }
            "sms" => {
                // G-07：真实投递——按渠道 config_json 的 provider 分发。
                // generic：自由文本 HTTP 网关（EncryptedString 读路径已解密）；
                // aliyun/tencent：云厂商模板制投递（真实签名 + 真实 HTTP），失败 Err
                // 交由调用方记 status='2' 待重试（B6：超时 + 重试上限 + 失败审计）。
                let raw_cfg = channel.config_json.as_ref().map(|e| e.0.as_str());
                let provider_kind = crate::service::sms_provider::detect_provider_kind(raw_cfg);
                match provider_kind {
                    crate::service::sms_provider::SmsProviderKind::Generic => {
                        let cfg = crate::service::sms_provider::SmsChannelConfig::from_config_json(
                            raw_cfg,
                        )
                        .map_err(|e| {
                            tracing::error!("短信渠道 {} 配置无效: {}", channel.channel_code, e);
                            ServiceError::bad_request(&crate::tr!("error.msg.sms_config_invalid"))
                        })?;
                        let provider = crate::service::sms_provider::GenericHttpProvider::new();
                        let gateway_id =
                            provider.send(&cfg, to_addr, content).await.map_err(|e| {
                                tracing::error!(
                                    "短信投递失败渠道={} to={}: {}",
                                    channel.channel_code,
                                    to_addr,
                                    e
                                );
                                ServiceError::internal(&crate::tr!("error.msg.sms_send_failed"))
                            })?;
                        tracing::info!(
                            "短信投递受理成功渠道={} to={} 网关回执={}",
                            channel.channel_code,
                            to_addr,
                            gateway_id
                        );
                    }
                    kind @ (crate::service::sms_provider::SmsProviderKind::Aliyun
                    | crate::service::sms_provider::SmsProviderKind::Tencent) => {
                        // 云厂商为模板制：必须携带云端模板 code 与原始参数（重试由
                        // send_log.sms_params 快照还原）
                        let Some(ctx) = sms_ctx else {
                            return Err(ServiceError::bad_request(&crate::tr!(
                                "error.msg.sms_template_code_required"
                            )));
                        };
                        let cloud =
                            crate::service::sms_provider::CloudSmsConfig::from_config_json(raw_cfg)
                                .map_err(|e| {
                                    tracing::error!(
                                        "短信云渠道 {} 配置无效: {}",
                                        channel.channel_code,
                                        e
                                    );
                                    ServiceError::bad_request(&crate::tr!(
                                        "error.msg.sms_config_invalid"
                                    ))
                                })?;
                        let params: serde_json::Value =
                            serde_json::from_str(&ctx.params_json).unwrap_or(serde_json::json!({}));
                        let result = match kind {
                            crate::service::sms_provider::SmsProviderKind::Aliyun => {
                                crate::service::sms_provider::AliyunSmsProvider::new()
                                    .send_templated(&cloud, to_addr, ctx.template_code, &params)
                                    .await
                            }
                            _ => {
                                crate::service::sms_provider::TencentSmsProvider::new()
                                    .send_templated(&cloud, to_addr, ctx.template_code, &params)
                                    .await
                            }
                        };
                        match result {
                            Ok(receipt) => {
                                tracing::info!(
                                    "云厂商短信受理成功渠道={} provider={:?} to={} code={} 回执={}",
                                    channel.channel_code,
                                    kind,
                                    to_addr,
                                    ctx.template_code,
                                    receipt
                                );
                            }
                            Err(e) => {
                                tracing::error!(
                                    "云厂商短信投递失败渠道={} to={}: {}",
                                    channel.channel_code,
                                    to_addr,
                                    e
                                );
                                return Err(ServiceError::internal(&crate::tr!(
                                    "error.msg.sms_send_failed"
                                )));
                            }
                        }
                    }
                }
                Ok(())
            }
            "site" => {
                // 站内信投递尊重目标用户消息偏好（站内信开关 sysmsg_notify + 免打扰窗口）：
                // 用户 opt-out 或处于免打扰时间窗内则跳过投递（to_addr 约定为目标用户 id）。
                let Ok(user_id) = to_addr.trim().parse::<i64>() else {
                    return Ok(());
                };
                if let Ok(Some(pref)) = self.pref_repo.find_by_user_id(user_id).await
                    && !allows_delivery(PrefChannel::Sysmsg, &pref, &now_hm_str())
                {
                    tracing::info!("站内信被用户消息偏好/免打扰拦截: to={}", to_addr);
                    return Ok(());
                }
                tracing::info!("消息渠道 site 站内信投递（系统内记录）: to={}", to_addr);
                Ok(())
            }
            // 批次十八（G-15b 更优替代）：IM 群机器人——模板渲染后的 content 组装为
            // text 消息 POST 到群 webhook；errcode != 0 / HTTP 失败 → Err（走重试链）。
            // to_addr 对群机器人无意义（忽略）；config_json 存 webhookUrl [+ 钉钉 secret]。
            "wecom_robot" | "dingtalk_robot" => {
                let raw_cfg = channel.config_json.as_ref().map(|e| e.0.as_str());
                let robot_cfg =
                    crate::service::im_robot_provider::ImRobotConfig::from_config_json(raw_cfg)
                        .map_err(|e| {
                            tracing::error!(
                                "IM 机器人渠道 {} 配置无效: {}",
                                channel.channel_code,
                                e
                            );
                            ServiceError::bad_request(&crate::tr!("error.msg.robot_config_invalid"))
                        })?;
                let result = if channel.channel_type == "wecom_robot" {
                    crate::service::im_robot_provider::WeComRobotProvider::new()
                        .send(&robot_cfg, content)
                        .await
                } else {
                    crate::service::im_robot_provider::DingTalkRobotProvider::new()
                        .send(&robot_cfg, content)
                        .await
                };
                match result {
                    Ok(()) => {
                        tracing::info!(
                            "IM 机器人投递成功渠道={} type={}",
                            channel.channel_code,
                            channel.channel_type
                        );
                        Ok(())
                    }
                    Err(e) => {
                        tracing::error!(
                            "IM 机器人投递失败渠道={} type={}: {}",
                            channel.channel_code,
                            channel.channel_type,
                            e
                        );
                        Err(ServiceError::internal(&crate::tr!(
                            "error.msg.robot_send_failed"
                        )))
                    }
                }
            }
            _ => Err(ServiceError::bad_request(&crate::tr!(
                "error.msg.channel_type_invalid"
            ))),
        }
    }

    // ==================== 直接发送 & 重试 ====================

    /// 按模板 + 渠道 + 参数直接发送，并写入发送记录
    ///
    /// 投递成功记录 status='0'；投递失败记录 status='2'（待重试）并由重试机制兜底。
    pub async fn send(
        &self,
        dto: SendDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysMsgSendLogModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let template = self
            .template_repo
            // 按编码全局查找后做 tenant_allowed 判定（跨租户明确返回 403，不静默降级）
            .find_by_code(&dto.template_code, None)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.msg.template_not_found")))?;
        // 越权防护：租户管理员不得跨租户使用消息模板
        if !crate::common::tenant::tenant_allowed(operator_tid, template.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        if template.status.as_deref() != Some("0") {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.msg.template_disabled"
            )));
        }

        let channel_code = dto
            .channel_code
            .clone()
            .unwrap_or_else(|| template.channel_code.clone());
        let channel = self
            .channel_repo
            .find_by_code(
                &channel_code,
                crate::common::tenant::tenant_scope(template.tenant_id),
            )
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.msg.channel_not_found")))?;
        if channel.status.as_deref() != Some("0") {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.msg.channel_disabled"
            )));
        }

        let subject = render_template(&template.template_subject, &dto.params);
        let content = render_template(&template.template_content, &dto.params);
        let now = crate::common::datetime::now_naive();

        // G-07 扩展：sms 渠道记录原始参数快照（云厂商重试还原用）；云端模板 code 存在时
        // 组装模板制投递上下文（generic 网关忽略 sms_ctx，自由文本照投）
        let sms_params_snapshot = if channel.channel_type == "sms" {
            serde_json::to_string(&dto.params).ok()
        } else {
            None
        };
        let sms_ctx = template
            .sms_template_code
            .as_deref()
            .filter(|c| !c.trim().is_empty())
            .map(|c| SmsCloudCtx {
                template_code: c,
                params_json: sms_params_snapshot.clone().unwrap_or_else(|| "{}".into()),
            });

        let (status, last_error, send_time) = match self
            .dispatch(&channel, &dto.to_addr, &subject, &content, sms_ctx)
            .await
        {
            Ok(()) => ("0".to_string(), None, Some(now)),
            Err(e) => {
                tracing::warn!(
                    "消息发送失败 template={}, to={}: {}",
                    dto.template_code,
                    dto.to_addr,
                    e.message
                );
                // 投递失败 → 待重试
                ("2".to_string(), Some(e.message.clone()), None)
            }
        };

        let am = SysMsgSendLogActiveModel {
            // 运行期产物：归所属模板租户（可能由定时/异步投递触发，无操作者上下文）
            tenant_id: Set(template.tenant_id),
            template_code: Set(Some(dto.template_code)),
            channel_code: Set(Some(channel.channel_code.clone())),
            to_addr: Set(dto.to_addr),
            subject: Set(Some(subject)),
            content: Set(Some(content)),
            sms_params: Set(sms_params_snapshot),
            status: Set(Some(status)),
            retry_count: Set(Some(0)),
            max_retry_count: Set(Some(DEFAULT_MAX_RETRY)),
            last_error: Set(last_error),
            send_time: Set(send_time),
            remark: Set(Some(format!("operator={}", operator))),
            create_time: Set(Some(now)),
            ..Default::default()
        };
        let model = self.send_log_repo.insert(am).await?;
        Ok(model)
    }

    /// 按 log_id 重试发送记录（mark_pending_retry 后调用，或直接对指定记录重发）
    ///
    /// 复用记录中已渲染的 subject/content；成功置 status='0'，
    /// 失败累加 retry_count，未达上限保持 status='2'，达到上限置 status='1'。
    pub async fn retry_logs(
        &self,
        log_ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<u64, ServiceError> {
        if log_ids.is_empty() {
            return Ok(0);
        }
        let logs = self.send_log_repo.find_by_ids(&log_ids).await?;
        if logs.is_empty() {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.msg.log_not_found"
            )));
        }
        // 越权防护：租户管理员不得跨租户重试发送记录
        if logs
            .iter()
            .any(|l| !crate::common::tenant::tenant_allowed(operator_tid, l.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        let mut processed = 0u64;
        for log in logs {
            let channel_code = log.channel_code.clone().unwrap_or_default();
            let channel = self
                .channel_repo
                .find_by_code(
                    &channel_code,
                    crate::common::tenant::tenant_scope(log.tenant_id),
                )
                .await?
                .ok_or_else(|| {
                    ServiceError::not_found(&crate::tr!("error.msg.channel_not_found"))
                })?;

            let subject = log.subject.clone().unwrap_or_default();
            let content = log.content.clone().unwrap_or_default();
            let now = crate::common::datetime::now_naive();

            // G-07 扩展：sms 渠道重试时还原云厂商投递上下文——云端模板 code 从原模板行取
            // （log.template_code 是本系统模板编码），原始参数从 sms_params 快照还原
            let cloud_code: Option<String> = if channel.channel_type == "sms" {
                match log.template_code.as_deref() {
                    Some(tc) => {
                        let t = self
                            .template_repo
                            .find_by_code(tc, crate::common::tenant::tenant_scope(log.tenant_id))
                            .await?;
                        t.and_then(|t| t.sms_template_code)
                    }
                    None => None,
                }
            } else {
                None
            };
            let sms_ctx = cloud_code.as_deref().map(|c| SmsCloudCtx {
                template_code: c,
                params_json: log.sms_params.clone().unwrap_or_else(|| "{}".into()),
            });
            let (status, last_error, send_time, retry_count) = match self
                .dispatch(&channel, &log.to_addr, &subject, &content, sms_ctx)
                .await
            {
                Ok(()) => (
                    "0".to_string(),
                    None,
                    Some(now),
                    log.retry_count.unwrap_or(0),
                ),
                Err(e) => {
                    let retry_count = log.retry_count.unwrap_or(0) + 1;
                    let max = log.max_retry_count.unwrap_or(DEFAULT_MAX_RETRY);
                    let status = if retry_count >= max { "1" } else { "2" };
                    (
                        status.to_string(),
                        Some(e.message.clone()),
                        None,
                        retry_count,
                    )
                }
            };

            let am = SysMsgSendLogActiveModel {
                log_id: Set(log.log_id),
                status: Set(Some(status)),
                retry_count: Set(Some(retry_count)),
                last_error: Set(last_error),
                send_time: Set(send_time),
                ..Default::default()
            };
            self.send_log_repo.update(am).await?;
            processed += 1;
        }
        Ok(processed)
    }

    /// 将指定 log_id 置为待重试状态（前端「触发重试」按钮）
    pub async fn mark_pending_retry(
        &self,
        log_ids: &[i64],
        operator_tid: i64,
    ) -> Result<u64, ServiceError> {
        if log_ids.is_empty() {
            return Ok(0);
        }
        let existing = self.send_log_repo.find_by_ids(log_ids).await?;
        // 越权防护：租户管理员不得跨租户标记发送记录
        if existing
            .iter()
            .any(|l| !crate::common::tenant::tenant_allowed(operator_tid, l.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        let result = self.send_log_repo.mark_pending_retry(log_ids).await?;
        Ok(result.rows_affected)
    }

    /// 待重试批次批量重试（定时任务调用）
    ///
    /// 查询 status='2' 且 retry_count < max_retry_count 的记录，最多 batch_limit 条，逐条重发。
    pub async fn retry_pending(
        &self,
        batch_limit: u64,
        operator_tid: i64,
    ) -> Result<u64, ServiceError> {
        let pending = self
            .send_log_repo
            .find_pending_retry(
                batch_limit,
                crate::common::tenant::tenant_scope(operator_tid),
            )
            .await?;
        let ids: Vec<i64> = pending.iter().map(|l| l.log_id).collect();
        if ids.is_empty() {
            return Ok(0);
        }
        self.retry_logs(ids, operator_tid).await
    }

    /// 解析逗号分隔 id 列表
    pub fn parse_ids(ids: &str) -> Vec<i64> {
        parse_id_list::<i64>(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_template_basic() {
        let mut params = HashMap::new();
        params.insert("name".to_string(), "Alice".to_string());
        params.insert("code".to_string(), "A-123".to_string());
        let out = render_template("Hi {{name}}, your code is {{code}}.", &params);
        assert_eq!(out, "Hi Alice, your code is A-123.");
    }

    #[test]
    fn test_render_template_missing_var_blank() {
        let params = HashMap::new();
        let out = render_template("你好 {{name}} 先生", &params);
        assert_eq!(out, "你好  先生");
    }

    #[test]
    fn test_render_template_no_placeholder_untouched() {
        let params = HashMap::new();
        let out = render_template("纯文本内容，无占位符", &params);
        assert_eq!(out, "纯文本内容，无占位符");
    }

    #[test]
    fn test_render_template_unclosed_brace_literal() {
        let params = HashMap::new();
        let out = render_template("开头的 {{未闭合", &params);
        assert_eq!(out, "开头的 {{未闭合");
    }

    #[test]
    fn test_render_template_trimmed_key() {
        let mut params = HashMap::new();
        params.insert("user".to_string(), "bob".to_string());
        let out = render_template("{{ user }}", &params);
        assert_eq!(out, "bob");
    }

    #[test]
    fn test_validate_channel_type_whitelist() {
        assert!(validate_channel_type("email").is_ok());
        assert!(validate_channel_type("sms").is_ok());
        assert!(validate_channel_type("site").is_ok());
        assert!(validate_channel_type("wechat").is_err());
        assert!(validate_channel_type("").is_err());
    }

    #[test]
    fn test_validate_config_json_valid() {
        assert!(SysMsgService::validate_config_json(&None).is_ok());
        assert!(
            SysMsgService::validate_config_json(&Some(
                r#"{"host":"smtp.example.com"}"#.to_string()
            ))
            .is_ok()
        );
    }

    #[test]
    fn test_validate_config_json_invalid() {
        let err =
            SysMsgService::validate_config_json(&Some("{not valid json".to_string())).unwrap_err();
        assert_eq!(err.code, 400);
    }
}
