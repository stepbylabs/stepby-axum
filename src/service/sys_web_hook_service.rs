//! WebHook 事件订阅 Service 层（G5）
//!
//! 职责：
//! - 回调查配置 CRUD（增删改查、启停、SSRF 目标校验）
//! - 手动测试推送（同步投递并返回结果）
//! - 事件分发（`dispatch_event` 火后即忘：查询启用匹配回调并异步投递）
//! - 出站投递（HTTP POST + 可选 HMAC-SHA256 签名 + 投递留痕到 sys_web_hook_log）
//! - 推送记录管理（查询 / 删除 / 清空 / 按保留期清理 / 失败重试）
//!
//! 分层约束：不依赖任何 Web 框架类型（axum / tower）；错误统一使用 [`ServiceError`]。

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use garde::Validate;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::{IntoParams, ToSchema};

use crate::common::datetime;
use crate::common::error::ServiceError;
use crate::common::i18n::validate;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::common::ssrf;
use crate::entity::sys_web_hook::{
    ActiveModel as SysWebHookActiveModel, Column as WebHookColumn, Model as SysWebHookModel,
};
use crate::entity::sys_web_hook_log::{
    ActiveModel as SysWebHookLogActiveModel, Column as WebHookLogColumn,
    Model as SysWebHookLogModel,
};
use crate::repository::sys_web_hook::SysWebHookRepository;
use crate::repository::sys_web_hook_log::SysWebHookLogRepository;
use crate::repository::sys_webhook_event::SysWebhookEventRepository;

// ==================== 事件常量 ====================

/// 登录成功事件（存量 event_types 订阅口径，保留兼容）
pub const EVENT_LOGIN_SUCCESS: &str = "login_success";
/// 登录失败事件（含账号锁定等态）；payload 含用户名与原因（存量 event_types 订阅口径）
pub const EVENT_LOGIN_FAILURE: &str = "login_failure";
/// v5-D12：SCIM provision 创建用户事件（payload 含 id/userName/externalId）
pub const EVENT_SCIM_USER_PROVISIONED: &str = "scim_user_provisioned";
/// v5-D12：SCIM deprovision 停用用户事件（payload 含 id/userName）
pub const EVENT_SCIM_USER_DEACTIVATED: &str = "scim_user_deactivated";
/// v5-D12 Group：SCIM 建组事件（payload 含 id/displayName/externalId/memberCount）
pub const EVENT_SCIM_GROUP_PROVISIONED: &str = "scim_group_provisioned";
/// v5-D12 Group：SCIM 删组事件（payload 含 id/displayName/externalId）
pub const EVENT_SCIM_GROUP_DELETED: &str = "scim_group_deleted";

/// 事件分发中间件注入的扩展 key（当前仅用于路由分发）
pub const EVENT_HEADERS: [&str; 1] = ["X-Webhook-Event"];

/// 存量事件名 → 事件目录 event_key 映射表（方案 C 单一匹配口径的兼容桥梁）。
///
/// 与 `migration/src/migrations/m20261003_000004_webhook_unify.rs` 的
/// `LEGACY_EVENT_KEY_MAP` **必须保持一致**（集成测试 `webhook_unify.rs` 双向断言
/// 两份表相等，防漂移；数据收敛迁移以同一映射改写存量订阅）。
///
/// 盘点来源（dispatch_event 全部调用点）：
/// - auth_handler 登录成功/失败（方案 C 已删除双发）→ `login_success` / `login_failure`；
/// - webauthn_handler 登录成功/失败 → 同上两个常量；
/// - scim_handler 四个 SCIM 事件 → **不在事件目录**，不映射：派发时按原事件名
///   原样匹配 `subscribed_events`（大小写不敏感），语义与旧 `event_types` 口径等价，
///   不破坏存量用户订阅（数据收敛迁移同样原样保留这些元素）。
/// - 另宽容收录存量用户可能手写的变体：`login` / `login_fail` / `login_failed`。
pub const LEGACY_EVENT_KEY_MAP: &[(&str, &str)] = &[
    ("login", "login.success"),
    ("login_success", "login.success"),
    ("login_failure", "login.failed"),
    ("login_fail", "login.failed"),
    ("login_failed", "login.failed"),
];

/// 查映射表：存量事件名 → 目录 event_key；不在表中则**原样返回**（自定义事件名
/// 与 SCIM 等目录外事件按原名匹配，保持旧口径行为）。
pub fn map_legacy_event_key(event_type: &str) -> &str {
    let lower = event_type.trim().to_ascii_lowercase();
    LEGACY_EVENT_KEY_MAP
        .iter()
        .find(|(k, _)| *k == lower)
        .map_or(event_type, |(_, v)| v)
}

/// 将存量 `event_types`（逗号分隔；空串 = 订阅全部）转换为目录口径键列表。
///
/// 返回 `None` 表示「订阅全部」（空串/全空白/全空元素）；元素经
/// [`map_legacy_event_key`] 映射（命中映射表 → 目录键，否则原样保留）。
/// 供保存/更新 DTO 的兼容转换使用（仅传 `event_types` 的存量前端仍可用）。
pub fn convert_legacy_event_types(event_types: &str) -> Option<Vec<String>> {
    let raw = event_types.trim();
    if raw.is_empty() {
        return None;
    }
    let items: Vec<String> = raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| map_legacy_event_key(s).to_string())
        .collect();
    if items.is_empty() { None } else { Some(items) }
}

/// 出站请求最大体长（1 MiB，防止 payload 异常膨胀）
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// 响应体截断存储上限（8 KiB）
const MAX_STORED_RESPONSE_BYTES: usize = 8 * 1024;
/// 出站投递超时上限（秒）
const MAX_TIMEOUT_SECS: u64 = 30;
/// 订阅事件键数量上限（SubscribedEventsInput 归一后手动校验，防异常膨胀）
const MAX_SUBSCRIBED_EVENT_KEYS: usize = 100;
/// 投递失败记录保留天数（审计保留期，clean 清理）
const LOG_RETENTION_DAYS: i64 = 30;
/// 投递来源：手动测试发送（sys_web_hook_log.source；NULL/其他 = 业务事件派发）
pub const LOG_SOURCE_TEST: &str = "test";
/// 投递来源：事件派发（emit_event / dispatch_event）
pub const LOG_SOURCE_DISPATCH: &str = "dispatch";
/// 投递来源：失败重试
pub const LOG_SOURCE_RETRY: &str = "retry";

// ==================== DTO ====================

/// 回调查配置分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebHookQueryDto {
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
    pub hook_name: Option<String>,
    pub event_types: Option<String>,
    pub status: Option<String>,
}

impl From<&WebHookQueryDto> for PageDomain {
    fn from(dto: &WebHookQueryDto) -> Self {
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

/// 新增回调查配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebHookAddDto {
    #[garde(length(min = 1, max = 100))]
    pub hook_name: String,
    /// 订阅的事件类型（逗号分隔；空串匹配全部）。**deprecated（方案 C）**：仍接受，
    /// 内部经 `convert_legacy_event_types` 转换写入 `subscribed_events`（存量前端兼容）
    #[garde(length(max = 2000))]
    pub event_types: Option<String>,
    /// 订阅的事件目录键。接受三种形态（`SubscribedEventsInput`）：
    /// JSON 数组（新前端）、JSON 数组字符串、逗号分隔串（存量前端）；
    /// 空 = 订阅全部。每个键必须在事件目录内，或属于该回调的存量订阅/影子值
    /// （`validate_subscribed_events` 的 extra_allowed，保护存量自定义事件名）
    #[garde(skip)]
    pub subscribed_events: Option<SubscribedEventsInput>,
    #[garde(length(min = 1, max = 1000))]
    pub target_url: String,
    #[garde(length(max = 255))]
    pub secret: Option<String>,
    /// json / form-urlencoded
    #[garde(length(max = 16))]
    pub content_type: Option<String>,
    #[garde(skip)]
    pub timeout_secs: Option<i32>,
    /// 0=启用 1=停用
    #[garde(length(max = 2))]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 修改回调查配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebHookEditDto {
    #[garde(skip)]
    pub id: i64,
    #[garde(length(min = 1, max = 100))]
    pub hook_name: String,
    /// 语义同新增（deprecated；传入且与现值不同时重新转换覆盖 subscribed_events）
    #[garde(length(max = 2000))]
    pub event_types: Option<String>,
    /// 订阅的事件目录键（语义同新增；未传保持现值）
    #[garde(skip)]
    pub subscribed_events: Option<SubscribedEventsInput>,
    #[garde(length(min = 1, max = 1000))]
    pub target_url: String,
    #[garde(length(max = 255))]
    pub secret: Option<String>,
    #[garde(length(max = 16))]
    pub content_type: Option<String>,
    #[garde(skip)]
    pub timeout_secs: Option<i32>,
    #[garde(length(max = 2))]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 订阅事件入参（方案 C 写入收敛的多形态兼容）：
///
/// - `List(Vec<String>)`：新前端直接提交 JSON 数组；
/// - `Raw(String)`：存量前端提交的字符串——JSON 数组串（如 `["a","b"]`）或
///   逗号分隔串（如 `a,b`，兼容旧版直接透传行为）；空串 = 订阅全部。
///
/// 统一经 [`Self::to_keys`] 归一化为键列表后再校验/落库。
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum SubscribedEventsInput {
    /// 数组形态（新前端）
    List(Vec<String>),
    /// 字符串形态（JSON 数组串 / 逗号分隔串 / 空串）
    Raw(String),
}

impl SubscribedEventsInput {
    /// 归一化为事件键列表（空列表 = 订阅全部）
    pub fn to_keys(&self) -> Vec<String> {
        match self {
            Self::List(v) => v.clone(),
            Self::Raw(s) => {
                let t = s.trim();
                if t.is_empty() {
                    return Vec::new();
                }
                // 优先按 JSON 数组串解析（兼容旧前端 JSON.stringify 提交形态），
                // 解析失败再按逗号分隔串处理
                if let Ok(list) = serde_json::from_str::<Vec<String>>(t) {
                    return list;
                }
                t.split(',').map(|x| x.trim().to_string()).collect()
            }
        }
    }
}

/// 手动测试推送 DTO（复用新增字段；event_type 为空时用 `login_success` 便于演示）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebHookTestDto {
    /// 要模拟投递的事件类型；为空则默认 login_success
    #[garde(length(max = 128))]
    pub event_type: Option<String>,
    /// 测试负载；为空则使用占位负载
    #[garde(skip)]
    pub payload: Option<serde_json::Value>,
}

/// 推送记录分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebHookLogQueryDto {
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
    pub hook_id: Option<i64>,
    pub event_type: Option<String>,
    /// 0=成功 1=失败
    pub status: Option<String>,
    /// 创建时间范围-起（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 创建时间范围-止（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&WebHookLogQueryDto> for PageDomain {
    fn from(dto: &WebHookLogQueryDto) -> Self {
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

/// 事件目录分页查询 DTO（GET /system/webhook/event/list）
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebhookEventQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// 排序字段（白名单：event_key / name / enabled / id；未命中回退 id 升序）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    /// 事件键模糊过滤
    pub event_key: Option<String>,
    /// 事件名称模糊过滤
    pub name: Option<String>,
    /// 状态精确过滤（'1'=启用 '0'=停用）
    pub enabled: Option<String>,
}

impl From<&WebhookEventQueryDto> for PageDomain {
    fn from(dto: &WebhookEventQueryDto) -> Self {
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

/// 事件目录出参 VO
#[derive(Debug, Clone, Serialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "WebhookEventVo",
    export_to = "WebhookEventVo.ts",
    rename_all = "camelCase"
)]
#[schema(as = WebhookEventVo)]
pub struct WebhookEventVo {
    pub id: i64,
    /// 事件键（如 `user.created`）
    pub event_key: String,
    /// 事件名称
    pub name: String,
    /// 事件说明
    pub description: Option<String>,
    /// 负载样例（JSON 文本；test-send 的真实投递数据源）
    pub payload_example: Option<String>,
    /// 状态（'1'=启用 '0'=停用）
    pub enabled: String,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub created_at: Option<chrono::NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub updated_at: Option<chrono::NaiveDateTime>,
}

impl WebhookEventVo {
    fn from_model(m: crate::entity::sys_webhook_event::Model) -> Self {
        Self {
            id: m.id,
            event_key: m.event_key,
            name: m.name,
            description: m.description,
            payload_example: m.payload_example,
            enabled: m.enabled,
            created_at: m.created_at,
            updated_at: m.updated_at,
        }
    }
}

/// 测试发送 DTO（POST /system/webhook/{id}/test-send）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebhookTestSendDto {
    /// 事件目录键（必须存在于 sys_webhook_event；以该事件的 payload_example 构造真实投递）
    #[garde(length(min = 1, max = 64))]
    pub event_key: String,
}

/// 事件目录停用/启用 DTO（PUT /system/webhook/event/{id}/enabled）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebhookEventEnabledDto {
    /// 目标状态：'1' 启用 / '0' 停用（停用 = 目录下架展示并拒绝新订阅与测试发送）
    #[garde(length(min = 1, max = 1))]
    pub enabled: String,
}

/// 单次出站投递结果（供 test / 事件分发留痕）
#[derive(Debug, Clone, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryResult {
    pub ok: bool,
    pub status_code: i32,
    /// 服务端响应体（截断）
    pub response: String,
    /// 失败原因
    pub error: Option<String>,
    pub cost_ms: u64,
    /// 已写入的记录 id
    pub log_id: i64,
}

/// 回调查配置**出参 VO**（脱敏）
///
/// 安全约束（为何需要独立 VO）：`secret` 是出站请求的 HMAC 签名密钥，若随
/// `GET /monitor/webHook/list` / `/{id}` 直出实体，则任何持有
/// `monitor:webHook:list` 的角色（含租户管理员）都能读到密钥，进而伪造第三方
/// 回调签名。故出参**只暴露** `hasSecret`（是否已配置），永不回传密钥原文。
/// 同时不暴露 `tenantId` / `delFlag`：二者为内部字段，前端无任何语义。
///
/// `secret` 的写入语义（与 i18n `webHook.form.secretTip` 一致）：
/// - 新增：传非空则设置，空/缺省则未配置；
/// - 修改：传非空则覆盖，**空/缺省则保持原值**。
#[derive(Debug, Clone, Serialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "WebHookVo",
    export_to = "WebHookVo.ts",
    rename_all = "camelCase"
)]
#[schema(as = WebHookVo)]
pub struct WebHookVo {
    pub id: i64,
    /// 回调名称
    pub hook_name: String,
    /// 订阅的事件类型（逗号分隔；空串匹配全部）
    pub event_types: String,
    /// 订阅的事件目录键（JSON 数组字符串；空/缺省 = 订阅全部）
    pub subscribed_events: Option<String>,
    /// 出站目标 URL
    pub target_url: String,
    /// 请求体格式：json / form-urlencoded
    pub content_type: String,
    /// 超时秒数
    pub timeout_secs: i32,
    /// 状态（0=启用 1=停用）
    pub status: String,
    pub remark: Option<String>,
    /// 是否已配置签名密钥（**不回传密钥原文**）
    pub has_secret: bool,
    pub create_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<chrono::NaiveDateTime>,
    pub update_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub update_time: Option<chrono::NaiveDateTime>,
}

impl WebHookVo {
    /// 由实体模型构造脱敏 VO（**丢弃 `secret` 原文**，仅保留 `hasSecret` 布尔）
    pub fn from_model(m: SysWebHookModel) -> Self {
        Self {
            id: m.id,
            hook_name: m.hook_name,
            event_types: m.event_types,
            subscribed_events: m.subscribed_events,
            target_url: m.target_url,
            content_type: m.content_type,
            timeout_secs: m.timeout_secs,
            status: m.status,
            remark: m.remark,
            has_secret: m.secret.as_ref().is_some_and(|s| !s.0.is_empty()),
            create_by: m.create_by,
            create_time: m.create_time,
            update_by: m.update_by,
            update_time: m.update_time,
        }
    }
}

/// serde 默认值函数：启用态 "0"
fn default_enabled_status() -> String {
    "0".to_string()
}

/// 默认超时（秒）
fn default_timeout_secs() -> i32 {
    10
}

/// 判断回调的事件目录订阅（subscribed_events）是否命中给定事件键
///
/// 匹配规则（迁移 m20261003_000002）：
/// - `NULL` / 空白 = 订阅全部目录事件（兼容存量回调）；
/// - 非空 = JSON 数组字符串，任一元素（忽略首尾空白，大小写不敏感）等于 event_key 即命中；
/// - 非空但非法 JSON 属脏数据 → fail-closed 不匹配（防误发），记 warn 便于排查。
pub fn hook_matches_subscribed(subscribed_events: Option<&str>, event_key: &str) -> bool {
    let raw = subscribed_events.unwrap_or("").trim();
    if raw.is_empty() {
        return true;
    }
    match serde_json::from_str::<Vec<String>>(raw) {
        // event_key 与数组元素均忽略首尾空白 + 大小写不敏感（对齐 hook_matches_event 口径）
        Ok(list) => list
            .iter()
            .any(|s| s.trim().eq_ignore_ascii_case(event_key.trim())),
        Err(e) => {
            tracing::warn!(
                subscribed_events = %raw,
                error = %e,
                "subscribed_events 非法 JSON（fail-closed 不派发），请修正回调配置"
            );
            false
        }
    }
}

/// 按租户口径筛选启用回调组：仅保留与事件同租户（`tenant_id` 精确相等）的回调
///
/// P0 跨租户泄漏修复：[`SysWebHookService::dispatch_event`] 与 [`SysWebHookService::emit`]
/// 两条派发链共用本实现（单一事实源），确保租户口径严格一致、不会漂移——
/// 事件只投递给事件所属租户自己配置的回调，严禁跨租户触达
/// （A 租户事件不得推给 B 租户 WebHook；tid=0 平台事件仅投递平台租户回调组）。
fn filter_groups_by_tenant(
    groups: Vec<(i64, Vec<SysWebHookModel>)>,
    tenant_id: i64,
) -> Vec<SysWebHookModel> {
    groups
        .into_iter()
        .filter(|(tid, _)| *tid == tenant_id)
        .flat_map(|(_, hooks)| hooks)
        .collect()
}

/// 计算请求体签名：HMAC-SHA256(key=secret, data=body) 的十六进制串
///
/// 无 secret 时返回空串（不签名）。约定请求头写入 `X-Webhook-Signature: sha256={hex}`，
/// 与 GitHub/企业微信等主流 Webhook 签名格式一致，便于接收方校验。
pub fn sign_payload(secret: &str, body: &str) -> String {
    if secret.is_empty() {
        return String::new();
    }
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC 密钥任意长度均可接受，初始化不应失败");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ==================== Service ====================

/// 回调查配置允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖回调配置业务展示列；`secret`（签名密钥）、`tenant_id`、`del_flag` 等内部/敏感列不开放动态排序。
const WEB_HOOK_SORTABLE_COLUMNS: &[(&str, WebHookColumn)] = &[
    ("id", WebHookColumn::Id),
    ("hook_name", WebHookColumn::HookName),
    ("event_types", WebHookColumn::EventTypes),
    ("target_url", WebHookColumn::TargetUrl),
    ("content_type", WebHookColumn::ContentType),
    ("timeout_secs", WebHookColumn::TimeoutSecs),
    ("status", WebHookColumn::Status),
    ("create_time", WebHookColumn::CreateTime),
    ("update_time", WebHookColumn::UpdateTime),
];

/// 推送记录允许排序的列白名单。
///
/// 覆盖投递留痕业务展示列（主键、关联回调、事件、目标、状态、响应码、耗时、时间）；
/// `payload` / `response` / `error_msg`（大文本）、`tenant_id` 不开放动态排序。
const WEB_HOOK_LOG_SORTABLE_COLUMNS: &[(&str, WebHookLogColumn)] = &[
    ("id", WebHookLogColumn::Id),
    ("hook_id", WebHookLogColumn::HookId),
    ("hook_name", WebHookLogColumn::HookName),
    ("event_type", WebHookLogColumn::EventType),
    ("target_url", WebHookLogColumn::TargetUrl),
    ("status", WebHookLogColumn::Status),
    ("status_code", WebHookLogColumn::StatusCode),
    ("cost_ms", WebHookLogColumn::CostMs),
    ("create_time", WebHookLogColumn::CreateTime),
];

/// 事件目录允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 任务口径：仅开放 event_key / name / enabled 三业务列（另加主键 id 供稳定排序）；
/// `payload_example`（大文本）、`description` 不开放动态排序。
const WEBHOOK_EVENT_SORTABLE_COLUMNS: &[(&str, crate::entity::sys_webhook_event::Column)] = &[
    ("id", crate::entity::sys_webhook_event::Column::Id),
    (
        "event_key",
        crate::entity::sys_webhook_event::Column::EventKey,
    ),
    ("name", crate::entity::sys_webhook_event::Column::Name),
    ("enabled", crate::entity::sys_webhook_event::Column::Enabled),
];

/// WebHook 事件订阅 Service
pub struct SysWebHookService {
    hook_repo: SysWebHookRepository,
    log_repo: SysWebHookLogRepository,
    /// 事件目录 Repository（订阅校验 / 事件样例查询）
    event_repo: SysWebhookEventRepository,
    /// 出站 HTTP 客户端（禁自动重定向，SSRF 在保存时已校验，投递直连）
    http: reqwest::Client,
    /// 进程内跳板：方便单元测试注入替换出站转发（可选）
    #[allow(dead_code)]
    http_client_override: Option<Arc<reqwest::Client>>,
    db: DatabaseConnection,
    /// v5-E6：secret 信封加密主密钥（CONFIG_ENC_KEY；空=迁移期明文）
    enc_key: String,
}

impl SysWebHookService {
    pub fn new(db: DatabaseConnection, enc_key: String) -> Self {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .user_agent("stepby-webhook/1.0")
            .build()
            .expect("reqwest client 初始化失败");
        Self {
            hook_repo: SysWebHookRepository::new(db.clone()),
            log_repo: SysWebHookLogRepository::new(db.clone()),
            event_repo: SysWebhookEventRepository::new(db.clone()),
            http,
            http_client_override: None,
            db,
            enc_key,
        }
    }

    /// 对目标 URL 执行 SSRF 双层校验（静态 + 动态 DNS），返回规范化 URL
    async fn validate_target_url(&self, raw: &str) -> Result<url::Url, ServiceError> {
        let url = ssrf::validate_url(raw.trim()).map_err(|e| ServiceError::bad_request(&e))?;
        let host = url
            .host_str()
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.web_hook.url_invalid")))?;
        let port = url
            .port_or_known_default()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        ssrf::validate_host_resolution(host, port)
            .await
            .map_err(|e| ServiceError::bad_request(&e))?;
        Ok(url)
    }

    /// 校验订阅的事件目录键（每个 event_key 必须存在于 sys_webhook_event）
    ///
    /// 输入为空列表 = 显式订阅全部，合法。每个键必须在事件目录内，**或**命中
    /// `extra_allowed`（存量豁免集：该回调的影子 `event_types` / 既有
    /// `subscribed_events` 中已存在的自定义事件名，如 `scim_user_provisioned`、
    /// 用户自建串——方案 C 收敛后允许存量配置原样编辑，不强制迁移到目录）。
    /// 返回规范化后的 JSON 数组字符串（去空白；空数组 → None = 订阅全部）。
    async fn validate_subscribed_events(
        &self,
        keys: &[String],
        extra_allowed: &[String],
    ) -> Result<Option<String>, ServiceError> {
        // 键数量防御（原 garde 长度校验随形态归一改为手动检查，防异常膨胀）
        if keys.len() > MAX_SUBSCRIBED_EVENT_KEYS {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.web_hook.event_invalid"
            )));
        }
        for k in keys {
            let k = k.trim();
            if k.is_empty() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.web_hook.event_invalid"
                )));
            }
            // 目录命中需 enabled='1'：停用事件（目录下架）拒绝新订阅；
            // 存量豁免集（extra_allowed）不受目录 enabled 影响（方案 C 兼容口径）。
            let catalog_hit = self.event_repo.find_by_event_key(k).await?;
            let in_catalog = matches!(catalog_hit.as_ref(), Some(e) if e.enabled == "1");
            let in_extra = extra_allowed
                .iter()
                .any(|e| e.trim().eq_ignore_ascii_case(k));
            if in_extra {
                continue;
            }
            if !in_catalog {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.web_hook.event_key_unknown",
                    key = k
                )));
            }
        }
        let cleaned: Vec<&str> = keys.iter().map(|s| s.trim()).collect();
        if cleaned.is_empty() {
            return Ok(None);
        }
        serde_json::to_string(&cleaned)
            .map(Some)
            .map_err(|_| ServiceError::internal(&crate::tr!("error.common.process_failed")))
    }

    /// 从影子 `event_types` 逗号串拆出存量豁免集（trim + 去空）
    fn legacy_event_types_allowlist(event_types: &str) -> Vec<String> {
        event_types
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// 规范化输入（content_type / timeout / status / event_types）
    fn normalize(
        content_type: &Option<String>,
        timeout: &Option<i32>,
        status: &Option<String>,
    ) -> (String, i32, String) {
        let ct = match content_type
            .as_deref()
            .unwrap_or("json")
            .to_ascii_lowercase()
            .as_str()
        {
            "form" | "form-urlencoded" => "form-urlencoded".to_string(),
            _ => "json".to_string(),
        };
        let timeout = timeout
            .unwrap_or(default_timeout_secs())
            .clamp(1, MAX_TIMEOUT_SECS as i32);
        let status = status.clone().unwrap_or_else(default_enabled_status);
        (ct, timeout, status)
    }

    // ==================== 回调查配置 CRUD ====================

    /// 分页查询回调查配置（operator_tid 用于租户过滤：租户管理员仅见本租户）
    ///
    /// 出参为**脱敏 VO**（不含签名密钥原文，仅 `hasSecret`）。
    pub async fn list(
        &self,
        query: WebHookQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<WebHookVo>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_web_hook::Entity>(
                prop,
                WEB_HOOK_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let (rows, total) = self
            .hook_repo
            .find_page_filtered(
                offset,
                limit,
                query.hook_name.as_deref(),
                query.event_types.as_deref(),
                query.status.as_deref(),
                crate::common::tenant::tenant_scope(operator_tid),
                sort,
            )
            .await
            .map_err(ServiceError::from)?;
        Ok((rows.into_iter().map(WebHookVo::from_model).collect(), total))
    }

    /// 查询回调查配置**详情**（脱敏 VO；跨租户按主键访问 → 403）
    pub async fn detail(&self, id: i64, operator_tid: i64) -> Result<WebHookVo, ServiceError> {
        self.get_by_id(id, operator_tid)
            .await
            .map(WebHookVo::from_model)
    }

    /// 根据 id 查询回调查配置**实体**（内部使用）
    ///
    /// 注意：返回体含 `secret` 密文，**严禁直接作为 HTTP 响应体**；对外一律走
    /// [`Self::detail`] / [`Self::list`] 的脱敏 VO。
    pub async fn get_by_id(
        &self,
        id: i64,
        operator_tid: i64,
    ) -> Result<SysWebHookModel, ServiceError> {
        let model = self
            .hook_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.web_hook.not_found")))?;
        if !crate::common::tenant::tenant_allowed(operator_tid, model.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        Ok(model)
    }

    /// 新增回调查配置（保存时执行 SSRF 校验）
    pub async fn add(
        &self,
        dto: WebHookAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysWebHookModel, ServiceError> {
        validate(&dto)?;
        let (content_type, timeout_secs, status) =
            Self::normalize(&dto.content_type, &dto.timeout_secs, &dto.status);
        let event_types = dto.event_types.unwrap_or_default().trim().to_string();
        if !event_types.is_empty() {
            for ev in event_types.split(',') {
                if ev.trim().is_empty() {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.web_hook.event_invalid"
                    )));
                }
            }
        }
        // 订阅的事件目录键：优先取 subscribed_events（多形态归一 + 目录/存量豁免校验）；
        // 未传时由存量 event_types 兼容转换（方案 C：逗号串 → 映射 → JSON 数组），
        // 空串 = 订阅全部（NULL）。转换结果不做目录强校验（存量自定义事件名合法）。
        let subscribed_events = match &dto.subscribed_events {
            Some(input) => {
                let keys = input.to_keys();
                let extra = Self::legacy_event_types_allowlist(&event_types);
                self.validate_subscribed_events(&keys, &extra).await?
            }
            None => convert_legacy_event_types(&event_types)
                .map(|v| serde_json::to_string(&v).unwrap_or_default())
                .filter(|s| !s.is_empty()),
        };
        self.validate_target_url(&dto.target_url).await?;

        let now = crate::common::datetime::now_naive();
        let am = SysWebHookActiveModel {
            tenant_id: Set(operator_tid),
            hook_name: Set(dto.hook_name),
            event_types: Set(event_types),
            subscribed_events: Set(subscribed_events),
            target_url: Set(dto.target_url.trim().to_string()),
            // G-14：EncryptedString 列类型——Set 时自动 seal（幂等，防双重加密）
            secret: Set(dto
                .secret
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(crate::common::encrypted_value::EncryptedString)),
            content_type: Set(content_type),
            timeout_secs: Set(timeout_secs),
            status: Set(status),
            remark: Set(dto.remark),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            del_flag: Set("0".to_string()),
            ..Default::default()
        };
        // WebHook 变更 + 审计留痕同事务：add 原为无事务直插，接入变更留痕后
        // 引入事务保证「变更与留痕」原子性（secret 密文由 record_change 内部打码）
        let hook_repo = self.hook_repo.clone();
        let model = self
            .db
            .transaction::<_, SysWebHookModel, sea_orm::DbErr>(|txn| {
                let am = am.clone();
                // 审计留痕块为 boxed()（需 'static），operator 为 &str 引用生命周期不足，
                // 克隆为 owned String 移入 async move 块
                let operator_owned = operator.to_string();
                async move {
                    let new_hook = hook_repo.base().insert_conn(txn, am).await?;

                    // 审计合规域：INSERT 变更留痕（同事务提交/回滚）
                    let after = serde_json::to_value(&new_hook).unwrap_or(serde_json::Value::Null);
                    let audit_operator =
                        crate::service::sys_audit_change_service::resolve_operator(
                            txn,
                            None, // add 签名仅携带操作人用户名，ID 由回查补齐
                            Some(operator_owned.as_str()),
                        )
                        .await;
                    crate::service::sys_audit_change_service::record_change(
                        txn,
                        "sys_web_hook",
                        &new_hook.id.to_string(),
                        crate::service::sys_audit_change_service::ACTION_INSERT,
                        None,
                        Some(after),
                        audit_operator,
                    )
                    .await?;
                    Ok(new_hook)
                }
                .boxed()
            })
            .await
            .map_err(ServiceError::from)?;
        Ok(model)
    }

    /// 修改回调查配置（保存时重新执行 SSRF 校验）
    pub async fn edit(
        &self,
        dto: WebHookEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysWebHookModel, ServiceError> {
        validate(&dto)?;
        // 越权防护（get_by_id 内已校验租户归属）：租户管理员不得跨租户修改 WebHook 配置
        let existing = self.get_by_id(dto.id, operator_tid).await?;
        // 部分更新语义快照（`existing` 随即被 `into()` 转移）：未传字段保持现值
        let existing_event_types = existing.event_types.clone();
        let existing_subscribed_events = existing.subscribed_events.clone();
        let existing_content_type = existing.content_type.clone();
        let existing_timeout_secs = existing.timeout_secs;
        let existing_status = existing.status.clone();
        // **部分更新语义（2026-09-26 缺陷修复）**：未传时保持现值，而非回落默认值。
        // 否则"只改名称/URL"的 PUT 会把已停用的回调静默启用（status 回落 default_enabled_status）
        // 并清空订阅事件类型、重置 content_type/timeout。
        let (content_type, timeout_secs, status) = Self::normalize(
            &dto.content_type.clone().or(Some(existing_content_type)),
            &dto.timeout_secs.or(Some(existing_timeout_secs)),
            &dto.status.clone().or(Some(existing_status)),
        );
        let event_types = dto
            .event_types
            .clone()
            .unwrap_or_else(|| existing_event_types.clone())
            .trim()
            .to_string();
        if !event_types.is_empty() {
            for ev in event_types.split(',') {
                if ev.trim().is_empty() {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.web_hook.event_invalid"
                    )));
                }
            }
        }
        // 订阅的事件目录键（方案 C 写入收敛）：
        // - 显式传入 subscribed_events → 多形态归一 + 校验（目录键 ∪ 存量豁免集）后覆盖；
        // - 未传时：传了 event_types 且与现值不同 → 重新兼容转换覆盖（存量前端改订阅）；
        //   否则保持现值（部分更新语义：只改名称/URL 不触碰订阅配置）。
        let subscribed_events = match &dto.subscribed_events {
            Some(input) => {
                let keys = input.to_keys();
                // 存量豁免集：影子 event_types（现值 + 本次传入）∪ 既有 subscribed_events 已有键
                let mut extra = Self::legacy_event_types_allowlist(&existing_event_types);
                extra.extend(Self::legacy_event_types_allowlist(&event_types));
                if let Some(list) = existing_subscribed_events
                    .as_deref()
                    .and_then(|cur| serde_json::from_str::<Vec<String>>(cur.trim()).ok())
                {
                    extra.extend(list);
                }
                self.validate_subscribed_events(&keys, &extra).await?
            }
            None => {
                let et_changed =
                    dto.event_types.as_deref().map(str::trim) != Some(existing_event_types.trim());
                if dto.event_types.is_some() && et_changed {
                    convert_legacy_event_types(&event_types)
                        .map(|v| serde_json::to_string(&v).unwrap_or_default())
                        .filter(|s| !s.is_empty())
                } else {
                    existing_subscribed_events
                }
            }
        };
        // 目标 URL 变化时重新做 SSRF 校验
        if dto.target_url.trim() != existing.target_url {
            self.validate_target_url(&dto.target_url).await?;
        }

        let now = crate::common::datetime::now_naive();
        // 审计合规域：变更前快照（必须在 existing 被 move 进 ActiveModel 之前计算）
        let before_snapshot = serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);
        let mut am: SysWebHookActiveModel = existing.into();
        am.hook_name = Set(dto.hook_name);
        am.event_types = Set(event_types);
        am.subscribed_events = Set(subscribed_events);
        am.target_url = Set(dto.target_url.trim().to_string());
        // secret 语义（与 i18n `webHook.form.secretTip` 一致）：**传非空才覆盖**；
        // 空/缺省一律保持原值。此处不能用 `Set(None)`——那会把已配置的签名密钥静默清空，
        // 导致用户「只改 URL」后回调签名能力无声失效（且无任何提示）。
        if let Some(plain) = dto
            .secret
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            // G-14：Set 时自动 seal（幂等）；空/缺省走 NotSet 保持原值
            am.secret = Set(Some(crate::common::encrypted_value::EncryptedString(plain)));
        }
        am.content_type = Set(content_type);
        am.timeout_secs = Set(timeout_secs);
        am.status = Set(status);
        am.remark = Set(dto.remark);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));

        // WebHook 变更 + 审计留痕同事务：edit 原为无事务直更，接入变更留痕后引入事务
        let hook_repo = self.hook_repo.clone();
        let model = self
            .db
            .transaction::<_, SysWebHookModel, sea_orm::DbErr>(|txn| {
                let am = am.clone();
                let before_snapshot = before_snapshot.clone();
                // 审计留痕块为 boxed()（需 'static），operator 为 &str 引用生命周期不足，
                // 克隆为 owned String 移入 async move 块
                let operator_owned = operator.to_string();
                async move {
                    let updated = hook_repo.base().update_conn(txn, am).await?;

                    // 审计合规域：UPDATE 变更留痕（同事务提交/回滚）
                    let after = serde_json::to_value(&updated).unwrap_or(serde_json::Value::Null);
                    let audit_operator =
                        crate::service::sys_audit_change_service::resolve_operator(
                            txn,
                            None, // edit 签名仅携带操作人用户名，ID 由回查补齐
                            Some(operator_owned.as_str()),
                        )
                        .await;
                    crate::service::sys_audit_change_service::record_change(
                        txn,
                        "sys_web_hook",
                        &updated.id.to_string(),
                        crate::service::sys_audit_change_service::ACTION_UPDATE,
                        Some(before_snapshot),
                        Some(after),
                        audit_operator,
                    )
                    .await?;
                    Ok(updated)
                }
                .boxed()
            })
            .await
            .map_err(ServiceError::from)?;
        Ok(model)
    }

    /// 逻辑删除回调查配置（并级联清理其推送记录）
    ///
    /// E1-e：日志清理不再 `let _` 吞错——原实现中推送记录删除失败会被静默忽略，
    /// 出现「配置已删但日志残留」的不一致；现把日志清理与配置软删纳入同一事务，
    /// 任一步失败整体回滚（与 delete_user / remove 租户的原子事务模式一致）。
    pub async fn remove(&self, ids: Vec<i64>, operator_tid: i64) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Ok(());
        }
        // 越权防护：租户管理员不得跨租户删除 WebHook 配置
        let existing = self.hook_repo.find_by_ids(&ids).await?;
        if existing
            .iter()
            .any(|h| !crate::common::tenant::tenant_allowed(operator_tid, h.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        // 审计合规域：变更前快照（批量逐条留痕，必须在 existing 被 move 进事务闭包之前计算）
        let before_snapshots: Vec<serde_json::Value> = existing
            .iter()
            .map(|h| serde_json::to_value(h).unwrap_or(serde_json::Value::Null))
            .collect();
        let log_repo = self.log_repo.clone();
        let hook_repo = self.hook_repo.clone();
        self.db
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let before_snapshots = before_snapshots.clone();
                async move {
                    // 级联清理推送记录（物理删，历史审计走操作日志）
                    log_repo.delete_by_hook_ids_conn(txn, &ids).await?;
                    // 配置软删
                    hook_repo.soft_delete_by_ids_conn(txn, &ids).await?;

                    // 审计合规域：DELETE 变更留痕（逐条；同事务提交/回滚。
                    // remove 签名无操作人信息，操作人两列留空（列可空））
                    let audit_operator =
                        crate::service::sys_audit_change_service::resolve_operator(txn, None, None)
                            .await;
                    for (h, before) in existing.iter().zip(before_snapshots) {
                        crate::service::sys_audit_change_service::record_change(
                            txn,
                            "sys_web_hook",
                            &h.id.to_string(),
                            crate::service::sys_audit_change_service::ACTION_DELETE,
                            Some(before),
                            None,
                            audit_operator.clone(),
                        )
                        .await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await
            .map_err(ServiceError::from)
    }

    /// 启停回调（status：0=启用 1=停用）
    pub async fn change_status(
        &self,
        id: i64,
        status: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if status != "0" && status != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.common.invalid_param"
            )));
        }
        // 越权防护（get_by_id 内已校验租户归属）：租户管理员不得跨租户启停 WebHook 配置
        self.get_by_id(id, operator_tid).await?;
        self.hook_repo
            .update_status(id, status)
            .await
            .map(|_| ())
            .map_err(ServiceError::from)
    }

    // ==================== 出站投递 ====================

    /// 构建出站请求体（json / form-urlencoded）
    fn build_body(&self, hook: &SysWebHookModel, payload: &serde_json::Value) -> String {
        let body = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
        if hook.content_type == "form-urlencoded" {
            flatten_json_to_form(payload)
        } else {
            body
        }
    }

    /// 执行一次出站投递并写入 sys_web_hook_log
    ///
    /// 说明：SSRF 校验仅在保存回调时执行；投递阶段直连目标（由带外调度触发，非用户可改地址）。
    /// `source` 写入 `sys_web_hook_log.source`（'test'=手动测试发送，'dispatch'=事件派发，
    /// 'retry'=失败重试；NULL 兼容存量口径）。
    pub async fn deliver(
        &self,
        hook: &SysWebHookModel,
        event_type: &str,
        payload: &serde_json::Value,
        source: Option<&str>,
    ) -> Result<DeliveryResult, ServiceError> {
        let start = Instant::now();
        let body = self.build_body(hook, payload);
        let timeout =
            Duration::from_secs(hook.timeout_secs.clamp(1, MAX_TIMEOUT_SECS as i32) as u64);

        // 构造日志行（先落库，便于投递期间即可查询“进行中”状态）
        let now = crate::common::datetime::now_naive();
        let log_am = SysWebHookLogActiveModel {
            // 运行期产物：归该 WebHook 配置所属租户（可能由事件分发/重试异步触发，无操作者上下文）
            tenant_id: Set(hook.tenant_id),
            hook_id: Set(Some(hook.id)),
            hook_name: Set(Some(hook.hook_name.clone())),
            event_type: Set(event_type.to_string()),
            target_url: Set(hook.target_url.clone()),
            payload: Set(Some(truncate_utf8(&body, MAX_PAYLOAD_BYTES))),
            status: Set("0".to_string()), // 0=处理中/成功，1=失败
            status_code: Set(None),
            response: Set(None),
            error_msg: Set(None),
            cost_ms: Set(0),
            source: Set(source.map(|s| s.to_string())),
            create_time: Set(Some(now)),
            ..Default::default()
        };
        let saved = self.log_repo.insert(log_am).await?;
        let log_id = saved.id;

        // 出站请求
        let mut builder = self
            .http
            .post(&hook.target_url)
            .timeout(timeout)
            .header("content-type", content_type_header(&hook.content_type))
            .header("user-agent", "stepby-webhook/1.0")
            .header("X-Webhook-Event", event_type);
        // G-14：EncryptedString 读取已自动 unseal，直接取明文签名
        let signature = sign_payload(
            hook.secret
                .as_ref()
                .map(|e| e.0.as_str())
                .unwrap_or_default(),
            &body,
        );
        if !signature.is_empty() {
            builder = builder.header("X-Webhook-Signature", format!("sha256={}", signature));
        }

        let resp = {
            let req = builder.body(body.clone()).build().map_err(|e| {
                ServiceError::bad_request(&format!("WebHook 出站请求构建失败: {e}"))
            })?;
            self.http.execute(req).await
        };

        let (stored_status, status_code, response, error_msg) = match resp {
            Ok(r) => {
                let code = r.status().as_u16() as i32;
                let txt = match r.text().await {
                    Ok(t) => truncate_utf8(&t, MAX_STORED_RESPONSE_BYTES),
                    Err(e) => format!("(读取响应体失败: {e})"),
                };
                let ok = (200..300).contains(&code);
                (
                    if ok { "0" } else { "1" }.to_string(),
                    Some(code),
                    Some(txt),
                    if ok {
                        None
                    } else {
                        Some(format!("HTTP {}", code))
                    },
                )
            }
            Err(e) => (
                "1".to_string(),
                None,
                Some(String::new()),
                Some(e.to_string()),
            ),
        };
        let cost_ms = start.elapsed().as_millis() as i32;

        // 回填结果
        self.log_repo
            .finish_log(
                log_id,
                &stored_status,
                status_code,
                response.clone(),
                error_msg.clone(),
                cost_ms,
            )
            .await?;

        Ok(DeliveryResult {
            ok: stored_status == "0",
            status_code: status_code.unwrap_or(0),
            response: response.unwrap_or_default(),
            error: error_msg,
            cost_ms: cost_ms as u64,
            log_id,
        })
    }

    /// 手动测试推送（同步投递并返回结果；不要求回调已保存）
    pub async fn test_hook(
        &self,
        id: i64,
        dto: WebHookTestDto,
        operator_tid: i64,
    ) -> Result<DeliveryResult, ServiceError> {
        let hook = self.get_by_id(id, operator_tid).await?;
        let event_type = dto
            .event_type
            .unwrap_or_else(|| EVENT_LOGIN_SUCCESS.to_string());
        let payload = dto
            .payload
            .unwrap_or_else(|| serde_json::json!({ "event": event_type, "ts": "test" }));
        // 与配置订阅无关：测试总是尝试投递
        self.deliver(&hook, &event_type, &payload, Some(LOG_SOURCE_TEST))
            .await
    }

    // ==================== 事件分发 ====================

    /// 分发事件到所有启用且订阅匹配的回调（火后即忘；方案 C 收敛后的派发入口）
    ///
    /// 对于每个命中回调 spawn 一个独立任务投递，互不阻塞调用方（如登录请求）。
    /// 投递失败仅落库 + 日志，不向上抛错，保证事件分发绝不阻断主链路。
    ///
    /// 多租户（后台批量任务硬约束）：启用回调**按租户分组**加载，**仅**投递与事件
    /// 同租户（`tenant_id`）的回调组，并在 payload 注入 `tenantId`，严禁跨租户触达
    /// （A 租户事件不得推给 B 租户 WebHook）。
    ///
    /// 方案 C（订阅双轨合并）：匹配口径收敛为 `subscribed_events` 列（旧
    /// `event_types` 口径退役）——入参事件名先经 [`map_legacy_event_key`] 映射
    /// （`login_success` → `login.success` 等目录键；映射表外事件如 `scim_*`
    /// 原样保留），再用 [`hook_matches_subscribed`] 匹配（NULL/空 = 订阅全部，
    /// 兼容存量行为；数据收敛迁移 m20261003_000004 已把存量订阅改写为新列）。
    pub fn dispatch_event(&self, event_type: &str, payload: serde_json::Value, tenant_id: i64) {
        let hook_repo = self.hook_repo.clone();
        let db = self.db.clone();
        let http = Arc::new(self.http.clone());
        let enc_key = self.enc_key.clone();
        let event_type = event_type.to_string();

        tokio::spawn(async move {
            // 先按租户分组加载启用回调，再仅取事件所属租户组并在内存中过滤匹配事件
            let groups = match hook_repo.find_all_enabled().await {
                Ok(g) => g,
                Err(e) => {
                    tracing::warn!(event = %event_type, error = %e, "WebHook 事件分发：加载启用回调失败");
                    return;
                }
            };
            // 方案 C：存量事件名映射为目录键（映射表外原样），统一按 subscribed_events 匹配
            // 租户口径：与 emit 共用 filter_groups_by_tenant（单一事实源，防口径漂移）
            let mapped = map_legacy_event_key(&event_type).to_string();
            let matched: Vec<_> = filter_groups_by_tenant(groups, tenant_id)
                .into_iter()
                .filter(|h| hook_matches_subscribed(h.subscribed_events.as_deref(), &mapped))
                .collect();
            if matched.is_empty() {
                return;
            }
            // 事件 payload 注入租户上下文，接收方据此判定归属
            let payload = {
                let mut p = payload;
                if let serde_json::Value::Object(ref mut m) = p {
                    m.insert("tenantId".to_string(), serde_json::json!(tenant_id));
                }
                p
            };
            for hook in matched {
                let hc = http.clone();
                let db2 = db.clone();
                // 投递事件名统一目录口径（方案 C）；映射表外事件 mapped == 原样，scim 等无损
                let event_type = mapped.clone();
                let payload = payload.clone();
                let enc_key = enc_key.clone();
                tokio::spawn(async move {
                    // 新建一个与 Service 等价的投递器（复用同一 http 客户端与 DB）
                    let svc = SysWebHookService::with_shared(db2, hc, enc_key);
                    if let Err(e) = svc
                        .deliver(&hook, &event_type, &payload, Some(LOG_SOURCE_DISPATCH))
                        .await
                    {
                        tracing::warn!(
                            hook_id = hook.id,
                            event = %event_type,
                            error = %e,
                            "WebHook 出站投递失败"
                        );
                    }
                });
            }
        });
    }

    /// 事件目录派发（subscribed_events 口径；火后即忘，供 [`emit_event`] 调用）
    ///
    /// 与 [`Self::dispatch_event`] 的差异：emit 直接收目录 `event_key`，无旧事件名
    /// 映射步骤；两者匹配口径已统一为 [`hook_matches_subscribed`]（方案 C）。
    ///
    /// P0 跨租户泄漏修复：`tenant_id` 为事件所属租户（由 [`emit_event`] 调用点从
    /// 操作者/事件主体上下文取得）。启用回调经 [`filter_groups_by_tenant`] **仅保留
    /// 与事件同租户的回调**，与 dispatch_event 严格同口径（共用同一过滤实现）——
    /// 严禁跨租户触达（A 租户事件不得推给 B 租户 WebHook）。
    ///
    /// 派发链路：加载启用回调 → 同租户过滤 → `subscribed_events` 过滤
    /// （NULL/空 = 订阅全部）→ 逐回调 spawn 真实出站投递（含 HMAC 签名）
    /// → 失败仅留痕（web_hook_log）。
    fn emit(&self, event_key: &str, payload: serde_json::Value, tenant_id: i64) {
        let hook_repo = self.hook_repo.clone();
        let db = self.db.clone();
        let http = Arc::new(self.http.clone());
        let enc_key = self.enc_key.clone();
        let event_key = event_key.to_string();

        tokio::spawn(async move {
            let groups = match hook_repo.find_all_enabled().await {
                Ok(g) => g,
                Err(e) => {
                    tracing::warn!(event = %event_key, error = %e, "WebHook 目录事件派发：加载启用回调失败");
                    return;
                }
            };
            // 租户口径：先与 dispatch_event 共用 filter_groups_by_tenant 精确同租户过滤，
            // 再取订阅了该 event_key 的启用回调（subscribed_events 空豁免）
            let matched: Vec<_> = filter_groups_by_tenant(groups, tenant_id)
                .into_iter()
                .filter(|h| hook_matches_subscribed(h.subscribed_events.as_deref(), &event_key))
                .collect();
            if matched.is_empty() {
                return;
            }
            for hook in matched {
                let hc = http.clone();
                let db2 = db.clone();
                let event_key = event_key.clone();
                let payload = payload.clone();
                let enc_key = enc_key.clone();
                tokio::spawn(async move {
                    let svc = SysWebHookService::with_shared(db2, hc, enc_key);
                    if let Err(e) = svc
                        .deliver(&hook, &event_key, &payload, Some(LOG_SOURCE_DISPATCH))
                        .await
                    {
                        tracing::warn!(
                            hook_id = hook.id,
                            event = %event_key,
                            error = %e,
                            "WebHook 目录事件出站投递失败"
                        );
                    }
                });
            }
        });
    }

    /// 用共享 http 客户端构造投递器（供事件分发内部使用）
    fn with_shared(db: DatabaseConnection, http: Arc<reqwest::Client>, enc_key: String) -> Self {
        Self {
            hook_repo: SysWebHookRepository::new(db.clone()),
            log_repo: SysWebHookLogRepository::new(db.clone()),
            event_repo: SysWebhookEventRepository::new(db.clone()),
            http: (*http).clone(),
            http_client_override: None,
            db,
            enc_key,
        }
    }

    // ==================== 推送记录管理 ====================

    /// 分页查询推送记录（operator_tid 用于租户过滤：租户管理员仅见本租户）
    pub async fn list_logs(
        &self,
        query: WebHookLogQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<SysWebHookLogModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_web_hook_log::Entity>(
                prop,
                WEB_HOOK_LOG_SORTABLE_COLUMNS,
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
        self.log_repo
            .find_page_filtered(
                offset,
                limit,
                query.hook_id,
                query.event_type.as_deref(),
                query.status.as_deref(),
                begin_time,
                end_time,
                crate::common::tenant::tenant_scope(operator_tid),
                sort,
            )
            .await
            .map_err(ServiceError::from)
    }

    /// 根据 id 查询推送记录详情（跨租户按主键访问 → 403）
    pub async fn get_log_by_id(
        &self,
        id: i64,
        operator_tid: i64,
    ) -> Result<SysWebHookLogModel, ServiceError> {
        let model =
            self.log_repo.find_by_id(id).await?.ok_or_else(|| {
                ServiceError::not_found(&crate::tr!("error.web_hook.log_not_found"))
            })?;
        if !crate::common::tenant::tenant_allowed(operator_tid, model.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        Ok(model)
    }

    /// 删除推送记录
    pub async fn remove_logs(&self, ids: Vec<i64>, operator_tid: i64) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Ok(());
        }
        let existing = self.log_repo.find_by_ids(&ids).await?;
        // 越权防护：租户管理员不得跨租户删除推送记录
        if existing
            .iter()
            .any(|l| !crate::common::tenant::tenant_allowed(operator_tid, l.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        self.log_repo
            .delete_by_ids(ids)
            .await
            .map(|_| ())
            .map_err(ServiceError::from)
    }

    /// 清空推送记录（按保留期：先清理超期，再清剩余；operator_tid 决定租户范围）
    pub async fn clean_logs(&self, operator_tid: i64) -> Result<(u64, u64), ServiceError> {
        let scope = crate::common::tenant::tenant_scope(operator_tid);
        let cutoff =
            crate::common::datetime::now_naive() - chrono::Duration::days(LOG_RETENTION_DAYS);
        let expired = self
            .log_repo
            .delete_older_than(cutoff, scope)
            .await
            .map(|r| r.rows_affected)
            .map_err(ServiceError::from)?;
        let all = self
            .log_repo
            .delete_all(scope)
            .await
            .map(|r| r.rows_affected)
            .map_err(ServiceError::from)?;
        Ok((expired, all))
    }

    /// 重试失败记录（按已保存的 payload 重新投递到原目标）
    pub async fn retry_logs(
        &self,
        ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<usize, ServiceError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let failed = self.log_repo.find_failed_by_ids(&ids).await?;
        // 越权防护：租户管理员不得跨租户重试推送记录
        if failed
            .iter()
            .any(|l| !crate::common::tenant::tenant_allowed(operator_tid, l.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        let mut ok_count = 0usize;
        for log in failed {
            // 依据记录快照构造虚拟 hook 重新投递（hook 可能已删除）
            // G-14：EncryptedString 读取已自动 unseal——虚拟 hook 直接持有
            // Option<EncryptedString>（deliver 签名点统一从 .0 取明文）
            let (target_url, secret) =
                match self.hook_repo.find_by_id(log.hook_id.unwrap_or(-1)).await {
                    Ok(Some(h)) => (h.target_url.clone(), h.secret),
                    _ => (log.target_url.clone(), None),
                };
            let payload: serde_json::Value = log
                .payload
                .as_deref()
                .and_then(|p| serde_json::from_str(p).ok())
                .unwrap_or_else(|| serde_json::json!({ "event": log.event_type, "note": "retry" }));
            let hook = SysWebHookModel {
                // 投递用临时构造（不入库）：tenant_id 沿用原记录，保证重试产物归属不变
                tenant_id: log.tenant_id,
                id: log.hook_id.unwrap_or(-1),
                hook_name: log.hook_name.clone().unwrap_or_default(),
                event_types: String::new(),
                subscribed_events: None,
                target_url,
                secret,
                content_type: "json".to_string(),
                timeout_secs: 10,
                status: "0".to_string(),
                remark: None,
                create_by: None,
                create_time: None,
                update_by: None,
                update_time: None,
                del_flag: "0".to_string(),
            };
            let _ = self
                .deliver(&hook, &log.event_type, &payload, Some(LOG_SOURCE_RETRY))
                .await;
            // deliver 内部会再写一条新记录；成功以交付结果为准
            ok_count += 1;
        }
        Ok(ok_count)
    }

    // ==================== 事件目录 ====================

    /// 分页查询事件目录（过滤 + 动态排序白名单：event_key/name/enabled）
    pub async fn list_events(
        &self,
        query: WebhookEventQueryDto,
    ) -> Result<(Vec<WebhookEventVo>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序（id 升序）
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_webhook_event::Entity>(
                prop,
                WEBHOOK_EVENT_SORTABLE_COLUMNS,
            )
            .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });
        let (rows, total) = self
            .event_repo
            .find_page_filtered(
                offset,
                limit,
                query.event_key.as_deref(),
                query.name.as_deref(),
                query.enabled.as_deref(),
                sort,
            )
            .await
            .map_err(ServiceError::from)?;
        Ok((
            rows.into_iter().map(WebhookEventVo::from_model).collect(),
            total,
        ))
    }

    /// 事件目录停用/启用（system:webhook:event:edit）
    ///
    /// 语义边界：`enabled = '0'` 仅下架目录展示并拒绝新订阅
    /// （[`Self::validate_subscribed_events`]）与测试发送（[`Self::test_send`]）；
    /// 事件派发（emit_event）以 hook 订阅关系为准、不查目录 enabled——
    /// 存量 hook 不因目录停用而中断。
    pub async fn change_event_enabled(&self, id: i64, enabled: &str) -> Result<(), ServiceError> {
        if enabled != "0" && enabled != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.web_hook.event_invalid"
            )));
        }
        let affected = self
            .event_repo
            .update_enabled(id, enabled)
            .await
            .map_err(ServiceError::from)?;
        if affected == 0 {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.common.not_found"
            )));
        }
        Ok(())
    }

    /// 按事件目录构造真实测试发送（POST /system/webhook/{id}/test-send）
    ///
    /// 与 [`Self::test_hook`] 的差异：
    /// - event_key 必须存在于 sys_webhook_event（目录口径）；
    /// - payload 取该事件的 payload_example（真实字段样例）而非占位负载；
    /// - 投递结果返回给调用方，同时留痕 web_hook_log（source='test'，含签名）。
    pub async fn test_send(
        &self,
        id: i64,
        event_key: &str,
        operator_tid: i64,
    ) -> Result<DeliveryResult, ServiceError> {
        let hook = self.get_by_id(id, operator_tid).await?;
        let event = self
            .event_repo
            .find_by_event_key(event_key)
            .await?
            .ok_or_else(|| {
                ServiceError::bad_request(&crate::tr!(
                    "error.web_hook.event_key_unknown",
                    key = event_key
                ))
            })?;
        // 目录停用（下架）事件拒绝测试发送：与订阅校验同口径，避免"目录上看不到
        // 却能按样例投递"的认知割裂；派发链（emit_event）不受影响，存量 hook 照常。
        if event.enabled != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.web_hook.event_disabled"
            )));
        }
        // 样例非法 JSON 时回退最小真实负载（仍可真实投递 + 验签）
        let payload: serde_json::Value = event
            .payload_example
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| serde_json::json!({ "eventKey": event.event_key }));
        self.deliver(
            &hook,
            event.event_key.trim(),
            &payload,
            Some(LOG_SOURCE_TEST),
        )
        .await
    }

    // ==================== 查询辅助 ====================

    /// 事件类型列表常量（供前端下拉提示；不作为枚举强校验，允许自定义事件）
    pub fn supported_events() -> Vec<&'static str> {
        vec![
            EVENT_LOGIN_SUCCESS,
            EVENT_LOGIN_FAILURE,
            // v5-D12：SCIM 用户目录同步事件（provision 创建 / deprovision 停用）
            EVENT_SCIM_USER_PROVISIONED,
            EVENT_SCIM_USER_DEACTIVATED,
            // v5-D12 Group：SCIM 组事件（建组 / 删组）
            EVENT_SCIM_GROUP_PROVISIONED,
            EVENT_SCIM_GROUP_DELETED,
        ]
    }
}

/// 将扁平 JSON 转为 key=value&key2=value2（仅一层；嵌套值按 JSON 编码）
fn flatten_json_to_form(value: &serde_json::Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let serde_json::Value::Object(map) = value {
        for (k, v) in map {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            parts.push(format!("{}={}", k, urlencoding_encode(&val)));
        }
    }
    parts.join("&")
}

/// 极简 percent-encode（仅编码需要转义的字符，覆盖 URL 表单场景）
fn urlencoding_encode(input: &str) -> String {
    let mut out = String::new();
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// 内容类型请求头值
fn content_type_header(content_type: &str) -> &'static str {
    if content_type == "form-urlencoded" {
        "application/x-www-form-urlencoded"
    } else {
        "application/json"
    }
}

/// 按字节上限截断 UTF-8 字符串（避免截断点在多字节字符中间）
fn truncate_utf8(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[截断 {}→{}bytes]", &s[..end], end, s.len())
}

/// 业务事件派发入口（开放域统一事件源，m20261003_000002_webhook_event）
///
/// 供各业务模块在**事务提交成功后**调用（handler 层于 service 成功返回后触发，
/// 避免事务内失败产生假事件）：
///
/// ```ignore
/// crate::service::sys_web_hook_service::emit_event(
///     &state,
///     "user.created",
///     serde_json::json!({ "userId": 1, "userName": "admin", "tenantId": 0 }),
///     operator.tenant_id(),
/// ).await;
/// ```
///
/// # 参数
/// - `tenant_id`：事件所属租户（P0 跨租户泄漏修复新增，**必传且严禁硬编码 0**）。
///   调用点从操作者上下文（`Operator::tenant_id()` / 登录主机租户）或事件主体
///   租户（payload 内 `tenantId`，两者应一致）取得；启用回调**仅匹配同租户**
///   （与 [`SysWebHookService::dispatch_event`] 共用 [`filter_groups_by_tenant`]，
///   严格同口径），A 租户事件不会推给 B 租户回调。
///
/// 行为：查启用回调 → 同租户过滤 → `subscribed_events` 过滤（空/NULL = 订阅全部，
/// JSON 数组含 event_key = 命中）→ 逐回调 spawn 真实出站投递（复用既有签名/HMAC +
/// HTTP 链路）→ 发送失败仅写 `sys_web_hook_log`（source='dispatch'），绝不阻断主链路。
///
/// payload 建议字段与 `sys_webhook_event.payload_example` 种子样例对齐；
/// 本函数在派发前自动注入 `eventKey` 与 `time`（接收方判定归属的事实源）。
pub async fn emit_event(
    state: &crate::state::AppState,
    event_key: &str,
    mut payload: serde_json::Value,
    tenant_id: i64,
) {
    // 注入事件上下文（对象负载时；非对象负载原样透传，不吞业务数据）
    let payload = if let serde_json::Value::Object(ref mut m) = payload {
        m.entry("eventKey")
            .or_insert_with(|| serde_json::json!(event_key));
        m.entry("time")
            .or_insert_with(|| serde_json::json!(crate::common::datetime::now_naive().to_string()));
        payload
    } else {
        payload
    };
    // emit 内部 tokio::spawn 火后即忘，本 await 仅收敛调用侧语义（无阻塞投递）
    state.web_hook_service.emit(event_key, payload, tenant_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_legacy_event_key_translates_known_names() {
        // 映射表内：存量事件名 → 目录键
        assert_eq!(map_legacy_event_key(EVENT_LOGIN_SUCCESS), "login.success");
        assert_eq!(map_legacy_event_key(EVENT_LOGIN_FAILURE), "login.failed");
        // 宽容变体 + 大小写/空白容忍
        assert_eq!(map_legacy_event_key("login"), "login.success");
        assert_eq!(map_legacy_event_key("login_fail"), "login.failed");
        assert_eq!(map_legacy_event_key("Login_Failed"), "login.failed");
        assert_eq!(map_legacy_event_key("  login_success "), "login.success");
        // 映射表外：原样返回（SCIM / 自定义事件名保持旧口径语义）
        assert_eq!(
            map_legacy_event_key(EVENT_SCIM_USER_PROVISIONED),
            EVENT_SCIM_USER_PROVISIONED
        );
        assert_eq!(map_legacy_event_key("my_event"), "my_event");
    }

    #[test]
    fn convert_legacy_event_types_to_catalog_keys() {
        // 空串 = 订阅全部（None）
        assert_eq!(convert_legacy_event_types(""), None);
        assert_eq!(convert_legacy_event_types("   "), None);
        // 全空元素 → 订阅全部
        assert_eq!(convert_legacy_event_types(" , "), None);
        // 映射 + 保留自定义串；空白容忍
        assert_eq!(
            convert_legacy_event_types(" login_success , my_event "),
            Some(vec!["login.success".to_string(), "my_event".to_string()])
        );
        // SCIM 存量事件名原样保留
        assert_eq!(
            convert_legacy_event_types(EVENT_SCIM_USER_PROVISIONED),
            Some(vec![EVENT_SCIM_USER_PROVISIONED.to_string()])
        );
    }

    #[test]
    fn dispatch_and_emit_match_consistently_after_mapping() {
        // 方案 C 防回归：dispatch（映射后走 subscribed_events）与 emit（目录键直配）
        // 对同一 hook 的匹配结果必须一致
        let converted = convert_legacy_event_types("login_success,my_event")
            .map(|v| serde_json::to_string(&v).unwrap_or_default());
        let sub = converted.as_deref();
        assert_eq!(
            sub,
            Some(r#"["login.success","my_event"]"#),
            "转换产物应为 JSON 数组串"
        );
        // dispatch 路径：映射存量名后匹配
        assert!(hook_matches_subscribed(
            sub,
            map_legacy_event_key(EVENT_LOGIN_SUCCESS)
        ));
        // emit 路径：目录键直接匹配 → 与 dispatch 同判定
        assert!(hook_matches_subscribed(sub, "login.success"));
        // 未订阅事件两口径一致不命中
        assert!(!hook_matches_subscribed(sub, "role.created"));
        // NULL（存量空 event_types）= 全部：两口径一致命中
        assert!(hook_matches_subscribed(
            None,
            map_legacy_event_key(EVENT_LOGIN_SUCCESS)
        ));
        assert!(hook_matches_subscribed(None, "login.success"));
    }

    #[test]
    fn dispatch_and_emit_share_tenant_caliber() {
        // P0 跨租户泄漏防回归：dispatch_event 与 emit_event 的租户口径必须严格一致
        // （共用 filter_groups_by_tenant：精确同租户过滤，tid=0 平台事件仅投平台租户回调组）
        fn mk_hook(id: i64, tenant_id: i64, subscribed: Option<&str>) -> SysWebHookModel {
            SysWebHookModel {
                tenant_id,
                id,
                hook_name: format!("hook-{id}"),
                event_types: String::new(),
                subscribed_events: subscribed.map(|s| s.to_string()),
                target_url: "http://127.0.0.1:1/hook".to_string(),
                secret: None,
                content_type: "json".to_string(),
                timeout_secs: 2,
                status: "0".to_string(),
                remark: None,
                create_by: None,
                create_time: None,
                update_by: None,
                update_time: None,
                del_flag: "0".to_string(),
            }
        }
        let groups = vec![
            // 租户 1：一个订阅全部（NULL）+ 一个只订阅 user.created
            (
                1,
                vec![
                    mk_hook(11, 1, None),
                    mk_hook(12, 1, Some(r#"["user.created"]"#)),
                ],
            ),
            // 租户 2：订阅全部
            (2, vec![mk_hook(21, 2, None)]),
            // 平台租户 0：订阅全部
            (0, vec![mk_hook(1, 0, None)]),
        ];
        // 两条派发链同口径模拟：dispatch（映射后 subscribed 匹配）与 emit（目录键直配）
        let ids_by = |tid: i64, event_key: &str| -> Vec<i64> {
            filter_groups_by_tenant(groups.clone(), tid)
                .into_iter()
                .filter(|h| hook_matches_subscribed(h.subscribed_events.as_deref(), event_key))
                .map(|h| h.id)
                .collect()
        };
        // 同租户事件：dispatch 与 emit 命中同一 hook 集合
        assert_eq!(
            ids_by(1, map_legacy_event_key("user.created")),
            vec![11, 12],
            "租户 1 的 user.created 应命中本租户两个回调"
        );
        assert_eq!(
            ids_by(1, "user.created"),
            vec![11, 12],
            "emit 同口径命中一致"
        );
        // 跨租户隔离核心断言：租户 2 触发的事件绝不能命中租户 1 的回调，反之亦然
        assert_eq!(
            ids_by(2, "user.created"),
            vec![21],
            "租户 2 事件只命中租户 2 回调"
        );
        assert_eq!(
            ids_by(1, "role.created"),
            vec![11],
            "未订阅事件：仅『订阅全部』（NULL）回调命中，定向订阅回调不命中"
        );
        // 平台事件（tid=0）：仅平台租户回调组命中，不波及业务租户
        assert_eq!(
            ids_by(0, "user.created"),
            vec![1],
            "平台事件仅命中平台租户回调"
        );
        // 不存在的租户：任何回调都不命中（fail-closed）
        assert_eq!(ids_by(999, "user.created"), Vec::<i64>::new());
    }

    #[test]
    fn legacy_map_identical_with_migration_map() {
        // 服务层映射表与数据收敛迁移映射表必须逐项一致（单一事实源双份，防漂移）
        let svc_map: Vec<(&str, &str)> = LEGACY_EVENT_KEY_MAP.to_vec();
        let mig_map: Vec<(&str, &str)> =
            migration::m20261003_000004_webhook_unify::LEGACY_EVENT_KEY_MAP.to_vec();
        assert_eq!(
            svc_map, mig_map,
            "两份映射表漂移：服务层 {svc_map:?} vs 迁移 {mig_map:?}"
        );
    }

    #[test]
    fn subscribed_input_accepts_all_shapes() {
        // 新前端：数组形态
        let list = serde_json::from_str::<SubscribedEventsInput>(r#"["user.created"]"#)
            .expect("数组形态应可反序列化");
        assert_eq!(list.to_keys(), vec!["user.created".to_string()]);
        // 存量前端：JSON 数组串（旧版 JSON.stringify 提交形态）
        let raw = SubscribedEventsInput::Raw(r#"["user.created","login.success"]"#.to_string());
        assert_eq!(
            raw.to_keys(),
            vec!["user.created".to_string(), "login.success".to_string()]
        );
        // 存量前端：逗号串
        let comma = SubscribedEventsInput::Raw("user.created, login.success".to_string());
        assert_eq!(
            comma.to_keys(),
            vec!["user.created".to_string(), "login.success".to_string()]
        );
        // 空串 = 订阅全部
        assert!(
            SubscribedEventsInput::Raw(String::new())
                .to_keys()
                .is_empty()
        );
    }

    #[test]
    fn sign_payload_empty_secret_returns_empty() {
        assert!(sign_payload("", "hello").is_empty());
    }

    #[test]
    fn hook_matches_subscribed_null_or_empty_matches_all() {
        // NULL / 空 = 订阅全部（兼容存量回调）
        assert!(hook_matches_subscribed(None, "user.created"));
        assert!(hook_matches_subscribed(Some(""), "user.created"));
        assert!(hook_matches_subscribed(Some("   "), "anything.else"));
    }

    #[test]
    fn hook_matches_subscribed_json_array() {
        let sub = Some(r#"["user.created","login.success"]"#);
        assert!(hook_matches_subscribed(sub, "user.created"));
        assert!(hook_matches_subscribed(sub, " login.success "));
        assert!(!hook_matches_subscribed(sub, "role.created"));
        // 脏数据（非法 JSON）fail-closed：不派发
        assert!(!hook_matches_subscribed(
            Some("user.created"),
            "user.created"
        ));
    }

    #[test]
    fn sign_payload_deterministic_hex() {
        // 已知向量：key="secret"，data="msg" 的 HMAC-SHA256
        let sig = sign_payload("secret", "msg");
        assert_eq!(sig.len(), 64);
        // 幂等
        assert_eq!(sig, sign_payload("secret", "msg"));
        assert_ne!(sig, sign_payload("secret", "msg2"));
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn flatten_form_encoding() {
        let v = serde_json::json!({"name": "a b", "count": 2, "note": "x&y"});
        let s = flatten_json_to_form(&v);
        assert!(s.contains("name=a+b"));
        assert!(s.contains("count=2"));
        assert!(s.contains("note=x%26y"));
    }

    #[test]
    fn truncate_respects_boundary() {
        let s = "中文字符串内容";
        let t = truncate_utf8(s, 5);
        // 绝不会在 UTF-8 边界外截断导致非法 UTF-8
        assert!(String::from_utf8(t.as_bytes().to_vec()).is_ok());
    }

    #[tokio::test]
    async fn deliver_to_local_listener_succeeds_and_logs() {
        // 构造本地接收端（真实投递，验证网络链路 + 签名头 + 落库）
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _n = socket.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf);
            let sig = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("x-webhook-signature:"))
                .map(|l| l.to_string())
                .unwrap_or_default();
            let body = r#"{"code":200}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
            sig
        });

        // 直接迁移建好的临时库构造 Service（不经过保存，故无 SSRF 拦截）
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let svc = SysWebHookService::new(db.clone(), String::new());
        let hook = SysWebHookModel {
            tenant_id: 0,
            id: 1,
            hook_name: "本地测试".to_string(),
            event_types: "login_success".to_string(),
            subscribed_events: None,
            target_url: format!("http://{}:{}/hook", addr.ip(), addr.port()),
            secret: Some(crate::common::encrypted_value::EncryptedString(
                "test-secret".to_string(),
            )),
            content_type: "json".to_string(),
            timeout_secs: 5,
            status: "0".to_string(),
            remark: None,
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            del_flag: "0".to_string(),
        };
        let res = svc
            .deliver(
                &hook,
                "login_success",
                &serde_json::json!({"user":"admin"}),
                None,
            )
            .await;
        assert!(res.is_ok(), "投递应成功: {:?}", res.err());
        let res = res.unwrap();
        assert!(res.ok, "业务应成功: {res:?}");
        assert!(res.status_code >= 200 && res.status_code < 300);
        assert_eq!(res.response, r#"{"code":200}"#);

        // 签名头已上报
        let sig = server.await.unwrap();
        assert!(
            sig.to_ascii_lowercase()
                .starts_with("x-webhook-signature: sha256="),
            "应携带签名头: {sig}"
        );

        // 记录已落库且状态=成功
        let log = svc.get_log_by_id(res.log_id, 0).await.unwrap();
        assert_eq!(log.status, "0");
        assert_eq!(log.hook_name.as_deref(), Some("本地测试"));
        assert_eq!(log.event_type, "login_success");
    }

    #[tokio::test]
    async fn deliver_to_unreachable_logs_failure() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let svc = SysWebHookService::new(db.clone(), String::new());
        let hook = SysWebHookModel {
            tenant_id: 0,
            id: 2,
            hook_name: "不可达".to_string(),
            event_types: "login_success".to_string(),
            subscribed_events: None,
            target_url: "http://127.0.0.1:1/unreachable".to_string(),
            secret: None,
            content_type: "json".to_string(),
            timeout_secs: 2,
            status: "0".to_string(),
            remark: None,
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            del_flag: "0".to_string(),
        };
        let res = svc
            .deliver(&hook, "login_success", &serde_json::json!({}), None)
            .await
            .unwrap();
        assert!(!res.ok, "不可达应失败: {res:?}");
        let log = svc.get_log_by_id(res.log_id, 0).await.unwrap();
        assert_eq!(log.status, "1");
        assert!(log.error_msg.is_some());
    }
}
