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

use garde::Validate;
use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::i18n::validate;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::ssrf;
use crate::entity::sys_web_hook::{ActiveModel as SysWebHookActiveModel, Model as SysWebHookModel};
use crate::entity::sys_web_hook_log::{
    ActiveModel as SysWebHookLogActiveModel, Model as SysWebHookLogModel,
};
use crate::repository::sys_web_hook::SysWebHookRepository;
use crate::repository::sys_web_hook_log::SysWebHookLogRepository;

// ==================== 事件常量 ====================

/// 登录成功事件
pub const EVENT_LOGIN_SUCCESS: &str = "login_success";
/// 登录失败事件（含账号锁定等态）；payload 含用户名与原因
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

/// 出站请求最大体长（1 MiB，防止 payload 异常膨胀）
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// 响应体截断存储上限（8 KiB）
const MAX_STORED_RESPONSE_BYTES: usize = 8 * 1024;
/// 出站投递超时上限（秒）
const MAX_TIMEOUT_SECS: u64 = 30;
/// 投递失败记录保留天数（审计保留期，clean 清理）
const LOG_RETENTION_DAYS: i64 = 30;

// ==================== DTO ====================

/// 回调查配置分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebHookQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub hook_name: Option<String>,
    pub event_types: Option<String>,
    pub status: Option<String>,
}

impl From<&WebHookQueryDto> for PageDomain {
    fn from(dto: &WebHookQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 新增回调查配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebHookAddDto {
    #[garde(length(min = 1, max = 100))]
    pub hook_name: String,
    /// 订阅的事件类型（逗号分隔；空串匹配全部）
    #[garde(length(max = 2000))]
    pub event_types: Option<String>,
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
    #[garde(length(max = 2000))]
    pub event_types: Option<String>,
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
    pub hook_id: Option<i64>,
    pub event_type: Option<String>,
    /// 0=成功 1=失败
    pub status: Option<String>,
}

impl From<&WebHookLogQueryDto> for PageDomain {
    fn from(dto: &WebHookLogQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
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

/// serde 默认值函数：启用态 "0"
fn default_enabled_status() -> String {
    "0".to_string()
}

/// 默认超时（秒）
fn default_timeout_secs() -> i32 {
    10
}

/// 判断回调的事件类型配置是否命中给定事件
///
/// event_types 为逗号分隔；空白视为「匹配全部」。
pub fn hook_matches_event(event_types: &str, event_type: &str) -> bool {
    let raw = event_types.trim();
    if raw.is_empty() {
        return true;
    }
    raw.split(',')
        .any(|s| s.trim().eq_ignore_ascii_case(event_type))
}

/// 计算请求体签名：HMAC-SHA256(key=secret, data=body) 的十六进制串
///
/// 无 secret 时返回空串（不签名）。约定请求头写入 `X-Webhook-Signature: sha256={hex}`，
/// 与 GitHub/企业微信等主流 Webhook 签名格式一致，便于接收方校验。
pub fn sign_payload(secret: &str, body: &str) -> String {
    if secret.is_empty() {
        return String::new();
    }
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC 密钥任意长度均可接受，初始化不应失败");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ==================== Service ====================

/// WebHook 事件订阅 Service
pub struct SysWebHookService {
    hook_repo: SysWebHookRepository,
    log_repo: SysWebHookLogRepository,
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
            .user_agent("yebot-webhook/1.0")
            .build()
            .expect("reqwest client 初始化失败");
        Self {
            hook_repo: SysWebHookRepository::new(db.clone()),
            log_repo: SysWebHookLogRepository::new(db.clone()),
            http,
            http_client_override: None,
            db,
            enc_key,
        }
    }

    /// v5-E6：secret 写入口（幂等 seal：key 未配置→明文；已加密→原样；失败→Err）
    fn seal_secret(&self, secret: Option<String>) -> Result<Option<String>, ServiceError> {
        match secret {
            Some(s) if !s.is_empty() => {
                crate::utils::crypto::seal_sensitive_value(&s, &self.enc_key)
                    .map(Some)
                    .map_err(|e| ServiceError::internal(&format!("web_hook secret 加密失败: {e}")))
            }
            _ => Ok(None),
        }
    }

    /// v5-E6：secret 读出口（unseal：明文兼容，解密失败原样返回）
    fn unseal_secret(&self, secret: &Option<String>) -> Option<String> {
        secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| crate::utils::crypto::unseal_sensitive_value(s, &self.enc_key))
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
    pub async fn list(
        &self,
        query: WebHookQueryDto,
        operator_tid: i64,
    ) -> Result<(Vec<SysWebHookModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        self.hook_repo
            .find_page_filtered(
                offset,
                limit,
                query.hook_name.as_deref(),
                query.event_types.as_deref(),
                query.status.as_deref(),
                crate::common::tenant::tenant_scope(operator_tid),
            )
            .await
            .map_err(ServiceError::from)
    }

    /// 根据 id 查询回调查配置详情（跨租户按主键访问 → 403）
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
            return Err(ServiceError::forbidden(&crate::tr!("error.common.forbidden")));
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
        self.validate_target_url(&dto.target_url).await?;

        let now = crate::common::datetime::now_naive();
        let am = SysWebHookActiveModel {
            tenant_id: Set(operator_tid),
            hook_name: Set(dto.hook_name),
            event_types: Set(event_types),
            target_url: Set(dto.target_url.trim().to_string()),
            // v5-E6：secret 信封加密（幂等，防双重加密）
            secret: Set(self.seal_secret(
                dto.secret
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            )?),
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
        self.hook_repo.insert(am).await.map_err(ServiceError::from)
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
        // 目标 URL 变化时重新做 SSRF 校验
        if dto.target_url.trim() != existing.target_url {
            self.validate_target_url(&dto.target_url).await?;
        }

        let now = crate::common::datetime::now_naive();
        let mut am: SysWebHookActiveModel = existing.into();
        am.hook_name = Set(dto.hook_name);
        am.event_types = Set(event_types);
        am.target_url = Set(dto.target_url.trim().to_string());
        // v5-E6：secret 非空才覆盖（留空保持不变）；信封加密（幂等）
        am.secret = Set(self.seal_secret(
            dto.secret
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        )?);
        am.content_type = Set(content_type);
        am.timeout_secs = Set(timeout_secs);
        am.status = Set(status);
        am.remark = Set(dto.remark);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));

        self.hook_repo.update(am).await.map_err(ServiceError::from)
    }

    /// 逻辑删除回调查配置（并级联清理其推送记录）
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
            return Err(ServiceError::forbidden(&crate::tr!("error.common.forbidden")));
        }
        for id in &ids {
            let _ = self.log_repo.delete_by_hook_id(*id).await;
        }
        self.hook_repo
            .soft_delete_by_ids(&ids)
            .await
            .map(|_| ())
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
    pub async fn deliver(
        &self,
        hook: &SysWebHookModel,
        event_type: &str,
        payload: &serde_json::Value,
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
            .header("user-agent", "yebot-webhook/1.0")
            .header("X-Webhook-Event", event_type);
        // v5-E6：secret 为信封加密存储，签名前解密
        let signature = sign_payload(&self.unseal_secret(&hook.secret).unwrap_or_default(), &body);
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
        self.deliver(&hook, &event_type, &payload).await
    }

    // ==================== 事件分发 ====================

    /// 分发事件到所有启用且订阅匹配的回调（火后即忘）
    ///
    /// 对于每个命中回调 spawn 一个独立任务投递，互不阻塞调用方（如登录请求）。
    /// 投递失败仅落库 + 日志，不向上抛错，保证事件分发绝不阻断主链路。
    ///
    /// 多租户（后台批量任务硬约束）：启用回调**按租户分组**加载，**仅**投递与事件
    /// 同租户（`tenant_id`）的回调组，并在 payload 注入 `tenantId`，严禁跨租户触达
    /// （A 租户事件不得推给 B 租户 WebHook）。
    pub fn dispatch_event(&self, event_type: &str, payload: serde_json::Value, tenant_id: i64) {
        let hook_repo = self.hook_repo.clone();
        let log_repo = self.log_repo.clone();
        let http = Arc::new(self.http.clone());
        let db = self.db.clone();
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
            let matched: Vec<_> = groups
                .into_iter()
                .filter(|(tid, _)| *tid == tenant_id)
                .flat_map(|(_, hooks)| hooks)
                .filter(|h| hook_matches_event(&h.event_types, &event_type))
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
                let lr = log_repo.clone();
                let hc = http.clone();
                let db2 = db.clone();
                let event_type = event_type.clone();
                let payload = payload.clone();
                let enc_key = enc_key.clone();
                tokio::spawn(async move {
                    // 新建一个与 Service 等价的投递器（复用同一 http 客户端与 DB）
                    let svc = SysWebHookService::with_shared(db2, hc, enc_key);
                    if let Err(e) = svc.deliver(&hook, &event_type, &payload).await {
                        tracing::warn!(
                            hook_id = hook.id,
                            event = %event_type,
                            error = %e,
                            "WebHook 出站投递失败"
                        );
                    }
                    drop(lr);
                });
            }
        });
    }

    /// 用共享 http 客户端构造投递器（供事件分发内部使用）
    fn with_shared(db: DatabaseConnection, http: Arc<reqwest::Client>, enc_key: String) -> Self {
        Self {
            hook_repo: SysWebHookRepository::new(db.clone()),
            log_repo: SysWebHookLogRepository::new(db.clone()),
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
        self.log_repo
            .find_page_filtered(
                offset,
                limit,
                query.hook_id,
                query.event_type.as_deref(),
                query.status.as_deref(),
                crate::common::tenant::tenant_scope(operator_tid),
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
        let model = self
            .log_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.web_hook.log_not_found")))?;
        if !crate::common::tenant::tenant_allowed(operator_tid, model.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!("error.common.forbidden")));
        }
        Ok(model)
    }

    /// 删除推送记录
    pub async fn remove_logs(
        &self,
        ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Ok(());
        }
        let existing = self.log_repo.find_by_ids(&ids).await?;
        // 越权防护：租户管理员不得跨租户删除推送记录
        if existing
            .iter()
            .any(|l| !crate::common::tenant::tenant_allowed(operator_tid, l.tenant_id))
        {
            return Err(ServiceError::forbidden(&crate::tr!("error.common.forbidden")));
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
            return Err(ServiceError::forbidden(&crate::tr!("error.common.forbidden")));
        }
        let mut ok_count = 0usize;
        for log in failed {
            // 依据记录快照构造虚拟 hook 重新投递（hook 可能已删除）
            // v5-E6：从库里取出的 secret 为密文 → unseal 后交给 deliver 签名
            let (target_url, secret) =
                match self.hook_repo.find_by_id(log.hook_id.unwrap_or(-1)).await {
                    Ok(Some(h)) => (h.target_url.clone(), self.unseal_secret(&h.secret)),
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
            let _ = self.deliver(&hook, &log.event_type, &payload).await;
            // deliver 内部会再写一条新记录；成功以交付结果为准
            ok_count += 1;
        }
        Ok(ok_count)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_matches_empty_event_types_matches_all() {
        assert!(hook_matches_event("", "login_success"));
        assert!(hook_matches_event("  ", "anything"));
    }

    #[test]
    fn hook_matches_comma_separated() {
        assert!(hook_matches_event(
            "login_success,user_created",
            "login_success"
        ));
        assert!(hook_matches_event(
            "login_success,user_created",
            "user_created"
        ));
        assert!(!hook_matches_event(
            "login_success,user_created",
            "login_failure"
        ));
        // 大小写不敏感 + 空白容忍
        assert!(hook_matches_event(
            " Login_Success , user_created ",
            "login_success"
        ));
    }

    #[test]
    fn sign_payload_empty_secret_returns_empty() {
        assert!(sign_payload("", "hello").is_empty());
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
            target_url: format!("http://{}:{}/hook", addr.ip(), addr.port()),
            secret: Some("test-secret".to_string()),
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
            .deliver(&hook, "login_success", &serde_json::json!({"user":"admin"}))
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
            .deliver(&hook, "login_success", &serde_json::json!({}))
            .await
            .unwrap();
        assert!(!res.ok, "不可达应失败: {res:?}");
        let log = svc.get_log_by_id(res.log_id, 0).await.unwrap();
        assert_eq!(log.status, "1");
        assert!(log.error_msg.is_some());
    }
}
