// stepby-axum/src/middleware/oper_log.rs
//! 操作日志记录中间件（Axum 原生 Tower Layer，from_fn_with_state 模式）
//!
//! 设计要点：
//! - 仅记录写操作（POST/PUT/DELETE），GET 请求不记录
//! - 从 request extensions 提取 Claims（由 auth_middleware 注入），获取操作人信息
//! - 从 MatchedPath 提取路由路径，推断业务模块标题
//! - 读取请求体作为 oper_param（脱敏 password 等敏感字段）
//! - 读取响应体作为 json_result（脱敏 token/phone/idCard 等敏感字段，限制最大 2KB，超出截断）
//! - 通过 user_name 异步查询部门名称（dept_name）
//! - 使用 tokio::spawn 异步写入日志，不阻断主流程（spawn 内 catch_unwind 防 panic 击溃 worker）
//! - 记录请求耗时（cost_time）
//! - 操作失败时记录 error_msg，status=1
//!
//! 挂载位置：permission_middleware 之后（layer 顺序：auth → permission → oper_log）
//! 确保只有通过权限校验的请求才记录日志。

use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{HeaderMap, Method};
use axum::middleware::Next;
use axum::response::Response;
use futures::FutureExt;

use crate::service::sys_oper_log_service::OperLogRecord;
use crate::state::AppState;
use crate::utils::ip::extract_client_ip;
// C9（日志脱敏强制）统一出口：脱敏函数自本文件迁移至 utils::masking（行为不变），
// 经别名保持原有调用点与单测引用（mask_phone 等）零改动。
use crate::utils::masking::{
    log_mask_bankcard as mask_bankcard, log_mask_email as mask_email,
    log_mask_idcard as mask_idcard, log_mask_phone as mask_phone,
};

/// 「目标租户单元」：中间件在请求处理前注入到 request extensions，
/// handler 在确知「被操作资源所属租户」时写入，中间件在 `next.run` 返回后读取并落库。
///
/// 多租户 Phase 3：操作者租户（`Claims.tid`）与目标资源租户不同（平台代管）时，
/// 审计日志记录 `target_tenant_id` = 被操作资源租户，使资源所属租户也能检索到该操作；
/// 二者相同或无 handler 写入时为 `None`。
///
/// 内部使用 `Arc<Mutex<Option<i64>>>` 共享内部可变性，避免跨 `await` 持有 `MutexGuard`。
#[derive(Clone, Debug, Default)]
pub struct TargetTenant(pub Arc<std::sync::Mutex<Option<i64>>>);

impl TargetTenant {
    /// 创建空单元（`None` 表示未记录目标租户）
    pub fn new() -> Self {
        Self(Arc::new(std::sync::Mutex::new(None)))
    }

    /// handler 侧写入被操作资源所属租户
    ///
    /// Mutex 中毒时静默忽略（审计字段，不应影响主流程）。
    pub fn set(&self, tenant_id: i64) {
        if let Ok(mut guard) = self.0.lock() {
            *guard = Some(tenant_id);
        }
    }

    /// 中间件侧读取目标租户；未写入或中毒时返回 `None`
    pub fn get(&self) -> Option<i64> {
        self.0.lock().ok().and_then(|guard| *guard)
    }
}

/// 提取器实现：handler 通过 `TargetTenant` 参数注入即可写入目标租户，
/// 无需手工访问 extensions（未注入时返回独立空单元，写入不生效但不报错）。
impl<S> axum::extract::FromRequestParts<S> for TargetTenant
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<TargetTenant>()
            .cloned()
            .unwrap_or_else(TargetTenant::new))
    }
}

/// 日志记录的请求体/响应体阈值（超出则记录截断警告）
/// 原 64KB 过小，正常请求体（如富文本通知、菜单配置）会被静默丢弃，导致日志缺失且转发空体。
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1MB
/// 请求体/响应体读取硬上限（对齐全局 DefaultBodyLimit 10MB，确保转发完整不丢失）
const BODY_READ_LIMIT: usize = 10 * 1024 * 1024; // 10MB
/// 日志字段最大保存字符数（超出截断）
const MAX_LOG_FIELD_LEN: usize = 2000;
/// 操作日志异步写入的超时上限（R6-RUST-13）
/// 超时后 spawn 任务直接放弃，避免日志写入卡死导致 spawn 任务累积
const OPER_LOG_TIMEOUT: Duration = Duration::from_secs(5);

/// 安全截断字符串到指定字节数，确保不截断在 UTF-8 字符中间（C-1 新 P0）
///
/// `String::truncate(new_len)` 在 `new_len` 不在 UTF-8 字符边界时会 panic；
/// 此函数回退到最近的字符边界，并附加 `...(truncated)` 标记。
fn safe_truncate(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = s[..end].to_string();
    result.push_str("...(truncated)");
    result
}

/// 操作日志记录中间件
///
/// 仅对 POST/PUT/DELETE 请求记录日志，GET 请求直接放行。
pub async fn oper_log_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    // 归一化 nest 前缀（/prod-api|/dev-api|/stage-api）：模块推断按去前缀的路由模板匹配，
    // 否则同源部署下所有操作日志都会被推断为"其他"（W-1 同源缺陷）。
    let matched_path = req
        .extensions()
        .get::<MatchedPath>()
        .cloned()
        .map(|p| crate::middleware::normalize_api_prefix(p.as_str()).to_string())
        .unwrap_or_default();

    // 仅记录写操作
    if !is_write_method(method.clone()) {
        return next.run(req).await;
    }

    // 提取操作人信息（auth_middleware 已注入 Claims）
    // 必须在 req.into_parts() 之前从 extensions 读取
    let (oper_name, operator_type, user_id, operator_tid) = req
        .extensions()
        .get::<crate::jwt::Claims>()
        .map(|c| (c.username.clone(), 1i32, c.sub.clone(), c.tid))
        .unwrap_or_else(|| {
            (
                crate::tr!("error.oper_log.anonymous").to_string(),
                0,
                String::new(),
                0i64,
            )
        });

    // 提取客户端真实 IP（含可信代理白名单 + XFF 链校验）
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let headers: HeaderMap = req.headers().clone();
    let oper_ip = extract_client_ip(&headers, peer_ip, &state.config.server.trusted_proxies);

    // P0-M2 修复：记录 path + query string，确保角色授权等通过 query 传参的操作可审计
    // 原 `req.uri().path()` 丢弃 query，导致 cancelAll/selectAll 等接口的 oper_param 为空
    let oper_url = req
        .uri()
        .path_and_query()
        .map(|s| s.to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let title = infer_module_title(&matched_path);
    let business_type = infer_business_type(method.clone(), &matched_path);
    let start = Instant::now();

    // 查询 IP 归属地（mmdb 文件不存在或查询失败时返回空字符串）
    let oper_location = state.ip_locator.locate(&oper_ip);

    // 读取请求体（用于 oper_param + 提取 ID 用于审计快照）
    // SEC-006：检查 Content-Length，超大请求体不缓冲直接透传，避免 10MB×并发数 的内存放大
    let (mut parts, body) = req.into_parts();
    // 多租户 Phase 3：注入「目标租户单元」，供 handler 写入被操作资源所属租户
    let target_tenant = TargetTenant::new();
    parts.extensions.insert(target_tenant.clone());
    let req_content_length = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    let (oper_param, body_bytes_for_snapshot, req) = if req_content_length > MAX_BODY_BYTES {
        // 超大请求体：直接透传，不缓冲，仅记录大小标记
        tracing::debug!(
            len = req_content_length,
            threshold = MAX_BODY_BYTES,
            "请求体超过日志阈值，跳过缓冲直接透传，oper_param 记录大小标记"
        );
        let oper_param = format!("[body too large: {} bytes, skipped]", req_content_length);
        let req = Request::from_parts(parts, body);
        (oper_param, None, req)
    } else {
        // 正常请求体：读取并脱敏
        let body_bytes = match to_bytes(body, BODY_READ_LIMIT).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    limit = BODY_READ_LIMIT,
                    "读取请求体失败（超过读取上限），oper_param 将为空，请求体转发可能受影响"
                );
                Default::default()
            }
        };
        if body_bytes.len() > MAX_BODY_BYTES {
            tracing::warn!(
                len = body_bytes.len(),
                threshold = MAX_BODY_BYTES,
                "请求体超过日志阈值，oper_param 字段将截断记录"
            );
        }
        let oper_param = sanitize_param(String::from_utf8_lossy(&body_bytes).to_string());
        // 保留 body_bytes 副本用于提取 ID（审计快照），仅 PUT 请求需要
        let body_for_snapshot = if method == Method::PUT {
            Some(body_bytes.clone())
        } else {
            None
        };
        let req = Request::from_parts(parts, Body::from(body_bytes));
        (oper_param, body_for_snapshot, req)
    };

    // 提取记录 ID：优先从 URL 路径末段解析，若失败则从请求体 JSON 提取
    // 适用场景：PUT /system/config（ID 在 body 的 configId 字段）、PUT /system/user/profile/resetPwd（body userId）等
    let record_id = extract_record_id(&oper_url, body_bytes_for_snapshot.as_deref());

    // 捕获变更前数据快照 Value（仅 PUT/DELETE 请求）
    // 同时用于：① oper_before 字段；② PUT 成功后与变更后快照比对得到字段级 diff
    let before_value = capture_before_snapshot(&state, &method, &oper_url, record_id).await;
    let oper_before = match &before_value {
        Some(v) => safe_truncate(
            &serde_json::to_string(v).unwrap_or_default(),
            MAX_LOG_FIELD_LEN,
        ),
        None => String::new(),
    };

    // 执行请求
    let response = next.run(req).await;

    // 多租户 Phase 3：读取 handler 写入的目标租户；与操作者租户相同则不记录（NULL）
    let target_tenant_id = target_tenant.get().filter(|t| *t != operator_tid);

    // 计算耗时
    let cost_time = start.elapsed().as_millis() as i64;

    // 读取响应体（用于 json_result）
    // SEC-006：检查 Content-Length，超大响应体不缓冲直接透传，避免内存放大
    let (resp_parts, resp_body) = response.into_parts();
    let resp_content_length = resp_parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    // T-03：二进制响应（xlsx 导出、文件下载等）跳过缓冲与文本脱敏，
    // 避免乱码入库与无谓的内存/CPU 消耗，仅记录类型与大小占位符
    let resp_content_type = resp_parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let is_textual = resp_content_type.is_empty()
        || resp_content_type.contains("json")
        || resp_content_type.starts_with("text/")
        || resp_content_type.starts_with("application/x-www-form-urlencoded");

    let (json_result_raw, response) = if !is_textual {
        let json_result_raw = if resp_content_length > 0 {
            format!(
                "[binary: {}, {} bytes, skipped]",
                resp_content_type, resp_content_length
            )
        } else {
            format!("[binary: {}, skipped]", resp_content_type)
        };
        let response = Response::from_parts(resp_parts, resp_body);
        (json_result_raw, response)
    } else if resp_content_length > MAX_BODY_BYTES {
        // 超大响应体：直接透传，不缓冲
        tracing::debug!(
            len = resp_content_length,
            threshold = MAX_BODY_BYTES,
            "响应体超过日志阈值，跳过缓冲直接透传"
        );
        let json_result_raw = format!(
            "[response too large: {} bytes, skipped]",
            resp_content_length
        );
        let response = Response::from_parts(resp_parts, resp_body);
        (json_result_raw, response)
    } else {
        // 正常响应体：读取并脱敏
        let resp_bytes = match to_bytes(resp_body, BODY_READ_LIMIT).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    limit = BODY_READ_LIMIT,
                    "读取响应体失败（超过读取上限），json_result 将为空，响应回传可能受影响"
                );
                Default::default()
            }
        };
        if resp_bytes.len() > MAX_BODY_BYTES {
            tracing::warn!(
                len = resp_bytes.len(),
                threshold = MAX_BODY_BYTES,
                "响应体超过日志阈值，json_result 字段将截断记录"
            );
        }
        // 脱敏响应体中的 token/phone/idCard/password 等敏感字段，避免明文写入 sys_oper_log（P0-33）
        let json_result_raw = sanitize_response_body(&String::from_utf8_lossy(&resp_bytes));
        // 重新构造 response 返回（使用原始字节，不修改返回给客户端的响应）
        let response = Response::from_parts(resp_parts, Body::from(resp_bytes));
        (json_result_raw, response)
    };

    // 判断操作结果（HTTP 2xx 成功，其他失败）
    let status_code = response.status().as_u16();
    let (status, error_msg) = if (200..300).contains(&status_code) {
        ("0".to_string(), String::new())
    } else {
        ("1".to_string(), format!("HTTP {}", status_code))
    };

    // 截断 json_result（避免过长字段）
    // C-1：使用 safe_truncate 避免在 UTF-8 多字节字符边界处截断导致 panic
    // （String::truncate 在非字符边界处会 panic）
    let json_result = if json_result_raw.len() > MAX_LOG_FIELD_LEN {
        safe_truncate(&json_result_raw, MAX_LOG_FIELD_LEN)
    } else {
        json_result_raw
    };

    // Tier-S #2：PUT 成功后重新读取变更后快照，逐字段计算 before→after 差异
    // 仅在"修改"类操作且请求成功（HTTP 2xx）时计算；写入未改变数据时 before==after，diff 为空
    let oper_diff = if business_type == 2 && status == "0" {
        match (record_id, &before_value) {
            (Some(id), Some(before_val)) => match fetch_snapshot_value(&state, &oper_url, id).await
            {
                Some(after_val) => compute_field_diff(before_val, &after_val),
                None => String::new(),
            },
            _ => String::new(),
        }
    } else {
        String::new()
    };

    // 异步写入日志，不阻断响应
    let record = OperLogRecord {
        title,
        business_type,
        method: matched_path.clone(),
        request_method: method.to_string(),
        operator_type,
        oper_name: oper_name.clone(),
        tenant_id: operator_tid,
        target_tenant_id,
        dept_name: String::new(), // 占位，spawn 任务中查询后填入
        oper_url,
        oper_ip,
        oper_location,
        oper_param,
        oper_before,
        oper_diff,
        json_result,
        status,
        error_msg,
        cost_time,
    };

    // spawn 异步任务写入日志，不等待完成
    // 任务中先查询部门名称，再写入日志
    // 使用 AssertUnwindSafe + catch_unwind 包裹整个 future，防止 spawn 内 panic 击溃 Tokio worker（P0-38）
    // R6-RUST-13：包裹 tokio::time::timeout，避免日志写入卡死导致 spawn 任务无限累积
    let oper_log_service = state.oper_log_service.clone();
    let dept_service = state.dept_service.clone();
    tokio::spawn(async move {
        let result = AssertUnwindSafe(async {
            // 超时保护：超过 5 秒未完成则放弃本次日志写入
            if let Err(_elapsed) = tokio::time::timeout(OPER_LOG_TIMEOUT, async {
                // 查询操作人部门名称（通过 user_id → dept_id → dept_name）
                let dept_name = if !user_id.is_empty() {
                    match user_id.parse::<i64>() {
                        Ok(uid) => match dept_service.get_dept_name_by_user_id(uid).await {
                            Ok(name) => name,
                            Err(e) => {
                                tracing::warn!("查询操作人部门名称失败 (user_id={}): {}", uid, e);
                                String::new()
                            }
                        },
                        Err(_) => String::new(),
                    }
                } else {
                    String::new()
                };

                let mut record = record;
                record.dept_name = dept_name;
                oper_log_service.record_oper_log(record).await;
            })
            .await
            {
                tracing::warn!(
                    timeout_secs = OPER_LOG_TIMEOUT.as_secs(),
                    "oper_log 写入超时，已放弃本次日志记录"
                );
            }
        })
        .catch_unwind()
        .await;

        if let Err(panic_err) = result {
            tracing::error!("oper_log spawn 内发生 panic: {:?}", panic_err);
        }
    });

    response
}

/// 判断是否为写操作（需记录日志）
fn is_write_method(method: Method) -> bool {
    matches!(method, Method::POST | Method::PUT | Method::DELETE)
}

/// 从 URL 路径或请求体 JSON 提取记录 ID
///
/// 优先从 URL 路径末段解析数字 ID（如 /system/user/123 → 123）。
/// 若 URL 无数字 ID（如 PUT /system/config），则从请求体 JSON 提取，
/// 根据路径前缀选择对应的 ID 字段名（configId/userId/roleId/menuId/deptId/postId/noticeId）。
///
/// 返回 None 表示无法提取 ID（如 POST 新增、路径无 ID 且 body 非 JSON）。
fn extract_record_id(oper_url: &str, body: Option<&[u8]>) -> Option<i64> {
    // §5.35：oper_url 为 path+query（P0-M2 审计语义保留），末段含 `?id=..` 时
    // 数字解析会失败——先剥掉 query 只按纯路径取末段。
    let path_only = oper_url.split('?').next().unwrap_or(oper_url);
    // 策略 1：从 URL 路径末段解析数字 ID
    let path_segments: Vec<&str> = path_only.split('/').collect();
    if let Some(last_seg) = path_segments.last()
        && let Ok(id) = last_seg.parse::<i64>()
    {
        return Some(id);
    }

    // 策略 2：从请求体 JSON 提取 ID
    let body_bytes = body?;
    let json: serde_json::Value = serde_json::from_slice(body_bytes).ok()?;

    // 根据路径前缀选择对应的 ID 字段名
    let field_name = if oper_url.starts_with("/system/user") {
        "userId"
    } else if oper_url.starts_with("/system/role") {
        "roleId"
    } else if oper_url.starts_with("/system/menu") {
        "menuId"
    } else if oper_url.starts_with("/system/dept") {
        "deptId"
    } else if oper_url.starts_with("/system/post") {
        "postId"
    } else if oper_url.starts_with("/system/config") {
        "configId"
    } else if oper_url.starts_with("/system/notice") {
        "noticeId"
    } else if oper_url.starts_with("/system/dict/type") {
        "dictId"
    } else if oper_url.starts_with("/system/dict/data") {
        "dictCode"
    } else if oper_url.starts_with("/system/rateLimit") {
        "id"
    } else {
        return None;
    };

    json.get(field_name).and_then(|v| v.as_i64()).or_else(|| {
        json.get(field_name)
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
    })
}

/// 按路径前缀 + 记录 ID 重新读取实体快照（Value 形式）
///
/// 供变更前快照与变更后 diff 计算复用：
/// - 根据请求路径前缀分派到对应 service 的 get_*_by_id
/// - 各 service 返回值均实现 serde::Serialize（Model 或 VO）
/// - 路径不匹配或查询失败时返回 None，不影响主流程
async fn fetch_snapshot_value(
    state: &Arc<AppState>,
    oper_url: &str,
    id: i64,
) -> Option<serde_json::Value> {
    // 根据路径前缀分派到对应 service
    if oper_url.starts_with("/system/user") {
        state
            .user_service
            .get_user_by_id(id)
            .await
            .ok()
            .map(|vo| serde_json::to_value(&vo).unwrap_or_default())
    } else if oper_url.starts_with("/system/role") {
        state
            .role_service
            .get_role_by_id(id, None) // 内部快照提取：无操作人上下文，不过滤
            .await
            .ok()
            .map(|vo| serde_json::to_value(&vo).unwrap_or_default())
    } else if oper_url.starts_with("/system/menu") {
        state
            .menu_service
            .get_menu_by_id(id)
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else if oper_url.starts_with("/system/dept") {
        state
            .dept_service
            .get_dept_by_id(id, None, None) // 内部快照提取：无操作人上下文，不过滤
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else if oper_url.starts_with("/system/post") {
        state
            .post_service
            .get_post_by_id(id, 0) // 内部快照提取：0=平台视角，不做租户越权过滤
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else if oper_url.starts_with("/system/config") {
        state
            .config_service
            .get_config_by_id(id, None) // 内部快照提取：无操作人上下文，不过滤（平台视角）
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else if oper_url.starts_with("/system/notice") {
        state
            .notice_service
            .get_notice_by_id(id, 0) // 内部快照提取：0=平台视角，不做租户越权过滤
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else if oper_url.starts_with("/system/dict/type") {
        state
            .dict_service
            .get_dict_type_by_id(id, None) // 内部快照提取：无操作人上下文，不过滤（平台视角）
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else if oper_url.starts_with("/system/dict/data") {
        state
            .dict_service
            .get_dict_data_by_id(id, None) // 内部快照提取：无操作人上下文，不过滤（平台视角）
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else if oper_url.starts_with("/monitor/job") {
        state
            .job_service
            .get_job_by_id(id)
            .await
            .ok()
            .map(|vo| serde_json::to_value(&vo).unwrap_or_default())
    } else {
        None
    }
}

/// 捕获变更前数据快照（仅对 PUT/DELETE 请求）
///
/// 根据请求路径前缀和记录 ID，调用对应 service 查询旧数据并序列化为 JSON 字符串。
/// 失败时返回空字符串（不影响主流程）。
///
/// 设计要点：
/// - 仅对 PUT/DELETE 触发（POST 是新增，无"变更前"概念）
/// - ID 优先从 URL 路径末段解析，若 URL 无数字 ID 则从请求体 JSON 提取（如 PUT /system/config）
/// - 通过路径前缀分派到对应 service（见 fetch_snapshot_value）
/// - 查询失败或路径不匹配时返回 None，不影响主流程
async fn capture_before_snapshot(
    state: &Arc<AppState>,
    method: &Method,
    oper_url: &str,
    id: Option<i64>,
) -> Option<serde_json::Value> {
    // 仅对 PUT/DELETE 捕获
    if !matches!(method, &Method::PUT | &Method::DELETE) {
        return None;
    }
    let id = id?; // 无 ID，跳过
    fetch_snapshot_value(state, oper_url, id).await
}

/// 计算字段级 before→after 差异（Tier-S #2）
///
/// 比对变更前/后两个 JSON 对象的顶层字段，输出 JSON 数组
/// `[{field, old, new}]`。仅记录发生变化的字段，敏感字段（密码/token/手机号等）
/// 值统一脱敏为 "***"（审计 diff 不应泄露明文）。数组为空时返回空字符串。
/// 结果按 MAX_LOG_FIELD_LEN 截断，避免超长。
fn compute_field_diff(before: &serde_json::Value, after: &serde_json::Value) -> String {
    let (Some(bmap), Some(omap)) = (before.as_object(), after.as_object()) else {
        return String::new();
    };

    // 合并两侧 key，保持稳定顺序（先按变更前字段顺序，再补变更后新增字段）
    let mut keys: Vec<&String> = bmap.keys().collect();
    for k in omap.keys() {
        if !bmap.contains_key(k) {
            keys.push(k);
        }
    }

    let mut diffs: Vec<serde_json::Value> = Vec::new();
    for k in keys {
        let old_v = bmap.get(k);
        let new_v = omap.get(k);
        if old_v == new_v {
            continue;
        }
        // 敏感字段：整字段值脱敏，不泄露旧/新明文
        let (old_out, new_out) = if is_sensitive_key(k) {
            (serde_json::json!("***"), serde_json::json!("***"))
        } else {
            (
                old_v.cloned().unwrap_or(serde_json::Value::Null),
                new_v.cloned().unwrap_or(serde_json::Value::Null),
            )
        };
        diffs.push(serde_json::json!({
            "field": k,
            "old": old_out,
            "new": new_out,
        }));
    }

    if diffs.is_empty() {
        return String::new();
    }
    let s = serde_json::to_string(&diffs).unwrap_or_default();
    safe_truncate(&s, MAX_LOG_FIELD_LEN)
}

/// 判断字段名是否为敏感字段（与 sanitize_value 的脱敏类别保持一致）
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("phone")
        || lower.contains("mobile")
        || lower.contains("idcard")
        || lower.contains("idno")
        || lower.contains("email")
        || lower.contains("bankcard")
        || lower.contains("cardnumber")
        || lower.contains("bank_card")
        || lower.contains("card_number")
        // PII 补漏：昵称与头像 URL 同样是个人标识（详见 `sanitize_value` 同名分支注释）
        || lower.contains("nickname")
        || lower.contains("nick_name")
        || lower.contains("avatar")
        || lower.contains("token")
        || lower == "password"
        || lower == "pwd"
        || lower == "salt"
        || lower == "secret"
        || lower.contains("apikey")
        || lower.contains("api_key")
}

/// 脱敏请求参数（移除敏感字段值）
///
/// REGRESS-010：扩展脱敏字段，覆盖 phone/mobile/phonenumber/idCard/idcard/id_card
/// 密码类、手机号类、身份证类字段值统一替换为 "***"（审计日志无需保留掩码后部分）
fn sanitize_param(s: String) -> String {
    if s.is_empty() {
        return s;
    }
    // 截断过长参数
    // C-1：使用 safe_truncate 避免在 UTF-8 多字节字符边界处截断导致 panic
    let s = if s.len() > MAX_LOG_FIELD_LEN {
        safe_truncate(&s, MAX_LOG_FIELD_LEN)
    } else {
        s
    };

    // 优先尝试 JSON 解析 + 递归脱敏（更准确，能覆盖嵌套对象）
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&s) {
        sanitize_value(&mut value);
        return serde_json::to_string(&value).unwrap_or(s);
    }

    // 非 JSON（form-encoded 等）：字符串模式脱敏
    let mut result = s;
    // REGRESS-010：扩展敏感字段列表
    // P0-33 改进：补充 email/bankCard/idNo/salt/secret/apiKey 等敏感字段
    let sensitive_fields = [
        "password",
        "oldPassword",
        "newPassword",
        "confirmPassword",
        "pwd",
        "phone",
        "mobile",
        "phonenumber",
        "phoneNumber",
        "idCard",
        "idcard",
        "id_card",
        "email",
        "bankCard",
        "bank_card",
        "cardNumber",
        "card_number",
        "idNo",
        // PII 补漏：昵称 / 头像 URL（非 JSON 请求体的字符串模式匹配需精确大小写变体）
        "nickName",
        "nickname",
        "nick_name",
        "avatar",
        "salt",
        "secret",
        "apiKey",
        "api_key",
    ];
    for field in sensitive_fields {
        // 匹配 "field":"value" 模式
        let patterns = [format!("\"{}\":\"", field), format!("\"{}\": \"", field)];
        for pat in &patterns {
            if let Some(idx) = result.find(pat) {
                let value_start = idx + pat.len();
                if let Some(end) = result[value_start..].find('"') {
                    let value_end = value_start + end;
                    let before = &result[..value_start];
                    let after = &result[value_end..];
                    result = format!("{}***{}", before, after);
                }
            }
        }
    }
    result
}

/// 根据路由路径推断业务模块标题（用于日志分类）
///
/// T-11：返回稳定 i18n key（`module.*`），新数据存 key；旧中文数据由展示层
/// `common::i18n::module_title` 回退原样显示。
///
/// M-1：改为 pub(crate) 以便 permission_middleware 在权限拒绝时复用同一映射。
pub(crate) fn infer_module_title(path: &str) -> String {
    // profile 路由需在 /system/user 之前匹配，避免被误分类为 module.user
    if path.starts_with("/system/user/profile") {
        "module.profile".to_string()
    } else if path.starts_with("/system/user") {
        "module.user".to_string()
    } else if path.starts_with("/system/role") {
        "module.role".to_string()
    } else if path.starts_with("/system/menu") {
        "module.menu".to_string()
    } else if path.starts_with("/system/dict") {
        "module.dict".to_string()
    } else if path.starts_with("/system/dept") {
        "module.dept".to_string()
    } else if path.starts_with("/system/post") {
        "module.post".to_string()
    } else if path.starts_with("/system/config") {
        "module.config".to_string()
    } else if path.starts_with("/system/notice") {
        "module.notice".to_string()
    } else if path.starts_with("/system/backup") {
        "module.backup".to_string()
    } else if path.starts_with("/system/task") {
        "module.task".to_string()
    } else if path.starts_with("/system/rateLimit") {
        "module.rateLimit".to_string()
    } else if path.starts_with("/monitor/webHook") {
        "module.webHook".to_string()
    } else if path.starts_with("/monitor/job") {
        "module.job".to_string()
    } else if path.starts_with("/monitor/operlog") {
        "module.operlog".to_string()
    } else if path.starts_with("/monitor/logininfor") {
        "module.logininfor".to_string()
    } else if path.starts_with("/monitor/online") {
        "module.online".to_string()
    } else if path.starts_with("/monitor/cache") {
        "module.cache".to_string()
    } else if path.starts_with("/monitor/server") {
        "module.server".to_string()
    } else if path.starts_with("/monitor/audit-dashboard") {
        "module.auditDashboard".to_string()
    } else if path.starts_with("/tool/gen") {
        "module.gen".to_string()
    } else if path.starts_with("/common/") {
        "module.common".to_string()
    } else if path.starts_with("/system/flow") {
        // 审批工作流（须与 common/i18n.rs 的 MODULE_TITLES 同步登记，V7 §3.5.2）
        "module.flow".to_string()
    } else if path.starts_with("/system/oauth/client") {
        // v5 第八轮：SSO 客户端管理操作日志归类（与 MODULE_TITLES 同步登记）
        "module.oauthClient".to_string()
    } else if path.starts_with("/sso/consent") {
        // v5 第八轮：SSO 同意决策（批准/拒绝）是写操作，须归类（与 MODULE_TITLES 同步登记）
        "module.ssoConsent".to_string()
    } else if path == "/logout"
        || path == "/login"
        || path == "/register"
        || path == "/unlockscreen"
    {
        // 认证相关路由（登出/登录/注册/锁屏解锁）归类为 module.auth
        "module.auth".to_string()
    } else {
        "module.other".to_string()
    }
}

/// 根据 HTTP 方法 + 路由路径推断业务类型
///
/// 对齐前端调用约定的 BusinessType 枚举与 sys_oper_type 字典：
/// - 0=其他 1=新增（POST）2=修改（PUT）3=删除（DELETE）
/// - 5=导出（*/export）6=导入（*/import*）
/// - 7=强退（DELETE /monitor/online/*）8=生成代码（POST /tool/gen/*）9=清空（*/clean）
///
/// T-04：此前仅按 HTTP 方法映射，导出接口（POST）被误记为"新增"。
fn infer_business_type(method: Method, path: &str) -> i32 {
    // 路径优先：特殊业务类型（注意 /import 需先于 /tool/gen 判断）
    if path.ends_with("/export") {
        return 5;
    }
    // M-5：用 ends_with + /import/ 双重匹配，避免误命中 /import_log 等无关路径
    if path.ends_with("/import") || path.contains("/import/") {
        return 6;
    }
    if path.ends_with("/clean") {
        return 9;
    }
    if path.starts_with("/monitor/online/") && method == Method::DELETE {
        return 7;
    }
    if path.starts_with("/tool/gen") && method == Method::POST {
        return 8;
    }
    // 登出操作：不是新增，归类为"其他"（0）
    if path == "/logout" {
        return 0;
    }
    // 解锁用户操作：不是新增，归类为"其他"（0）
    if path.starts_with("/monitor/logininfor/unlock/") {
        return 0;
    }
    match method {
        Method::POST => 1,
        Method::PUT => 2,
        Method::DELETE => 3,
        _ => 0,
    }
}

// ==================== 响应体脱敏（P0-33） ====================

/// 响应体脱敏失败（非 JSON / 序列化失败）时使用的脱敏占位串。
/// 绝不回写原始响应体——原始体可能含 token/手机号/身份证等敏感数据（B5）。
const REDACTED_BODY: &str = "<response body unavailable or contains sensitive data>";

/// 脱敏响应体中的敏感字段（token/phone/idCard/password 等）
///
/// 解析 JSON 后递归处理，遇到敏感 key 时替换 value：
/// - token / password / pwd → "***"
/// - phone / mobile → 中间 4 位掩码
/// - idCard → 中间 8 位掩码
///
/// 非 JSON 响应原样返回（不影响日志可读性）。
fn sanitize_response_body(body: &str) -> String {
    if body.is_empty() {
        return String::new();
    }
    let mut value: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        // B5：解析失败绝不留原始 body（可能含 token/手机号），返回脱敏占位
        Err(_) => return REDACTED_BODY.to_string(),
    };
    sanitize_value(&mut value);
    // B5：序列化失败同样返回脱敏占位，绝不回写原始 body
    serde_json::to_string(&value).unwrap_or_else(|_| REDACTED_BODY.to_string())
}

/// 递归脱敏 JSON 值
fn sanitize_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            // 收集需要脱敏的 key（避免在迭代中修改）
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                let lower = k.to_lowercase();
                let need_mask_phone = lower.contains("phone") || lower.contains("mobile");
                // P0-33 改进：idNo 也走身份证掩码
                let need_mask_idcard = lower.contains("idcard") || lower.contains("idno");
                // P0-33 改进：新增 email 掩码
                let need_mask_email = lower.contains("email");
                // P0-33 改进：新增银行卡号掩码
                let need_mask_bankcard = lower.contains("bankcard")
                    || lower.contains("cardnumber")
                    || lower.contains("bank_card")
                    || lower.contains("card_number");
                // P0-33 改进：salt/secret/apiKey 等同 token 处理（全替换 ***）
                let need_mask_token = lower.contains("token")
                    || lower == "password"
                    || lower == "pwd"
                    || lower == "salt"
                    || lower == "secret"
                    || lower.contains("apikey")
                    || lower.contains("api_key")
                    // PII 补漏（本轮）：昵称与头像 URL 同为个人标识，此前遗漏 ⇒ 改昵称的审计
                    // `oper_diff` 会留下明文昵称、响应体也会回显，主体身份可从审计反查，
                    // 使"匿名化 / 被遗忘权"形同虚设。整字段替换 `***`（昵称保留部分字符
                    // 无意义，不像手机号可保留前 3 后 4）。
                    || lower.contains("nickname")
                    || lower.contains("nick_name")
                    || lower.contains("avatar");
                if need_mask_token {
                    if let Some(val) = map.get_mut(&k) {
                        *val = serde_json::Value::String("***".to_string());
                    }
                } else if need_mask_phone {
                    if let Some(val) = map.get_mut(&k)
                        && let Some(s) = val.as_str()
                    {
                        *val = serde_json::Value::String(mask_phone(s));
                    }
                } else if need_mask_idcard {
                    if let Some(val) = map.get_mut(&k)
                        && let Some(s) = val.as_str()
                    {
                        *val = serde_json::Value::String(mask_idcard(s));
                    }
                } else if need_mask_email {
                    if let Some(val) = map.get_mut(&k)
                        && let Some(s) = val.as_str()
                    {
                        *val = serde_json::Value::String(mask_email(s));
                    }
                } else if need_mask_bankcard {
                    if let Some(val) = map.get_mut(&k)
                        && let Some(s) = val.as_str()
                    {
                        *val = serde_json::Value::String(mask_bankcard(s));
                    }
                } else if let Some(val) = map.get_mut(&k) {
                    sanitize_value(val);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_value(item);
            }
        }
        _ => {}
    }
}

// 脱敏函数已迁移至 utils::masking（C9 统一出口，行为不变）：
// mask_phone / mask_idcard / mask_email / mask_bankcard 现为
// crate::utils::masking::{log_mask_phone, log_mask_idcard, log_mask_email,
// log_mask_bankcard} 的别名引用，见文件头部 use 语句。

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_phone_normal() {
        assert_eq!(mask_phone("13812345678"), "138****5678");
    }

    #[test]
    fn test_mask_phone_short() {
        assert_eq!(mask_phone("123"), "***");
    }

    #[test]
    fn test_mask_idcard_normal() {
        assert_eq!(mask_idcard("110101199001011234"), "1101********34");
    }

    #[test]
    fn test_mask_idcard_short() {
        assert_eq!(mask_idcard("12345"), "***");
    }

    #[test]
    fn test_sanitize_response_body_token() {
        let body = r#"{"token":"abc.def.ghi","msg":"ok"}"#;
        let result = sanitize_response_body(body);
        assert!(result.contains("\"***\""));
        assert!(!result.contains("abc.def.ghi"));
        // 验证非敏感字段 msg 被保留
        assert!(result.contains("msg"), "应保留 msg 字段名");
        assert!(result.contains("ok"), "应保留 msg 的值 'ok'");
    }

    #[test]
    fn test_sanitize_response_body_phone() {
        let body = r#"{"phone":"13812345678"}"#;
        let result = sanitize_response_body(body);
        assert!(result.contains("138****5678"));
        // 验证字段名 phone 被保留
        assert!(result.contains("phone"), "应保留 phone 字段名");
    }

    #[test]
    fn test_sanitize_response_body_nested() {
        let body = r#"{"data":{"password":"secret","mobile":"13900001111"}}"#;
        let result = sanitize_response_body(body);
        assert!(result.contains("\"***\""));
        assert!(result.contains("139****1111"));
        assert!(!result.contains("secret"));
    }

    #[test]
    fn test_sanitize_response_body_non_json() {
        // B5：非 JSON 解析失败时不得回写原始响应体，必须返回脱敏占位
        let body = "plain text response";
        let result = sanitize_response_body(body);
        assert_eq!(result, REDACTED_BODY);
        assert!(!result.contains("plain text response"));
    }

    #[test]
    fn test_sanitize_response_body_invalid_json_with_sensitive_phone() {
        // B5：含敏感字段（phone）的非法 JSON，解析失败分支必须脱敏，
        // 不得泄露手机号明文，且返回占位串。
        let body = "{\"phone\":\"13812345678\""; // 缺少闭合括号，非法 JSON
        let result = sanitize_response_body(body);
        assert!(!result.contains("13812345678"), "不应泄露手机号明文");
        assert!(result.contains(REDACTED_BODY), "应返回脱敏占位串");
    }

    #[test]
    fn test_sanitize_response_body_array() {
        let body = r#"[{"token":"t1"},{"token":"t2"}]"#;
        let result = sanitize_response_body(body);
        assert!(result.contains("\"***\""));
        assert!(!result.contains("t1"));
        assert!(!result.contains("t2"));
    }

    // P0-33 改进：email/bankCard/idNo/salt/apiKey 脱敏测试

    #[test]
    fn test_mask_email_normal() {
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
    }

    #[test]
    fn test_mask_email_no_at() {
        assert_eq!(mask_email("notanemail"), "***");
    }

    #[test]
    fn test_mask_bankcard_normal() {
        // 19 位卡号，保留前 4 后 4，中间 11 个 *
        assert_eq!(mask_bankcard("6222021234567890123"), "6222***********0123");
    }

    #[test]
    fn test_mask_bankcard_short() {
        assert_eq!(mask_bankcard("1234"), "***");
    }

    #[test]
    fn test_sanitize_response_body_email() {
        let body = r#"{"email":"alice@example.com"}"#;
        let result = sanitize_response_body(body);
        assert!(result.contains("a***@example.com"));
        assert!(!result.contains("alice@"));
    }

    #[test]
    fn test_sanitize_response_body_bankcard() {
        let body = r#"{"bankCard":"6222021234567890123"}"#;
        let result = sanitize_response_body(body);
        assert!(result.contains("6222***********0123"));
        assert!(!result.contains("6222021234567890123"));
    }

    #[test]
    fn test_sanitize_response_body_idno() {
        let body = r#"{"idNo":"110101199001011234"}"#;
        let result = sanitize_response_body(body);
        assert!(result.contains("1101********34"));
    }

    #[test]
    fn test_sanitize_response_body_salt_secret_apikey() {
        let body = r#"{"salt":"s3cr3t","apiKey":"ak-12345","secret":"topsecret"}"#;
        let result = sanitize_response_body(body);
        assert!(!result.contains("s3cr3t"));
        assert!(!result.contains("ak-12345"));
        assert!(!result.contains("topsecret"));
        // 三个字段均应被替换为 "***"
        assert_eq!(result.matches("\"***\"").count(), 3);
    }

    /// **PII 补漏回归锁**（本轮）：昵称与头像 URL 此前不在任何脱敏名单内。
    ///
    /// 漏项后果：改昵称的操作会在审计 `oper_diff` 留下前后明文昵称，响应体也会原样回显，
    /// 主体身份可从审计反查 —— 使"匿名化 / 被遗忘权"形同虚设。
    ///
    /// 可证伪性：移除 `sanitize_value` 的 nickname/avatar 分支，本用例立即变红。
    #[test]
    fn test_sanitize_response_body_nickname_and_avatar() {
        let body = r#"{"nickName":"张三丰","avatar":"https://cdn.example.com/u/42.png"}"#;
        let result = sanitize_response_body(body);
        assert!(!result.contains("张三丰"), "昵称必须脱敏");
        assert!(!result.contains("cdn.example.com"), "头像 URL 必须脱敏");
        assert_eq!(result.matches("\"***\"").count(), 2);
        // 下划线形式同样命中
        let snake = sanitize_response_body(r#"{"nick_name":"李四"}"#);
        assert!(!snake.contains("李四"));
    }

    /// **名单一致性锁**：审计 diff 名单（`is_sensitive_key`）与响应体/参数脱敏名单
    /// （`sanitize_value` / `sanitize_param`）必须覆盖同一批 PII 字段。
    ///
    /// 这两处名单历史上是各写一份的（本次已同步把 nickname/avatar 补进三处）；
    /// 本用例作为"下次补字段必须三处同时补"的回归锁。
    #[test]
    fn test_sensitive_field_lists_stay_consistent() {
        for key in [
            "password",
            "pwd",
            "nickName",
            "nick_name",
            "avatar",
            "phonenumber",
            "mobile",
            "email",
            "idCard",
            "idNo",
            "bankCard",
            "cardNumber",
            "apiKey",
            "secret",
            "salt",
            "token",
        ] {
            assert!(is_sensitive_key(key), "审计 diff 名单应覆盖 {key}");
            let body = format!(r#"{{"{key}":"plaintext-value"}}"#);
            let out = sanitize_response_body(&body);
            assert!(
                !out.contains("plaintext-value"),
                "响应体脱敏名单应覆盖 {key}"
            );
        }
    }

    // C-1 新 P0：safe_truncate 单元测试

    #[test]
    fn test_safe_truncate_short_string_unchanged() {
        // 短字符串不应被截断
        assert_eq!(safe_truncate("hello", 100), "hello");
    }

    #[test]
    fn test_safe_truncate_ascii_exact_boundary() {
        // ASCII 字符串在字节边界截断（每个字符 1 字节）
        let s = "abcdefghij";
        assert_eq!(safe_truncate(s, 5), "abcde...(truncated)");
    }

    #[test]
    fn test_safe_truncate_multibyte_no_panic() {
        // 多字节 UTF-8 字符串：3 字节中文字符
        // 模拟 MAX_LOG_FIELD_LEN=2000 落在中文中间的场景（使用更小的阈值）
        let s = "中".repeat(10); // 30 字节
        // 不应在字符中间 panic，结果应是 3 个完整中文 + 截断标记
        let result = safe_truncate(&s, 10);
        assert!(result.ends_with("...(truncated)"));
        // 截断后的字符主体应是合法 UTF-8（前面是完整中文字符）
        let body = result.trim_end_matches("...(truncated)");
        assert!(body.chars().all(|c| c == '中'));
    }

    #[test]
    fn test_safe_truncate_empty_max_bytes() {
        // max_bytes=0 时应返回空字符串 + 截断标记
        let result = safe_truncate("abc", 0);
        assert_eq!(result, "...(truncated)");
    }

    // ==================== G6 审计增强：WebHook 留痕 + 敏感操作分类 ====================

    #[test]
    fn test_infer_module_title_webhook() {
        // WebHook 回调配置 / 推送日志均归类为 module.webHook
        assert_eq!(
            infer_module_title("/monitor/webHook/list"),
            "module.webHook"
        );
        assert_eq!(infer_module_title("/monitor/webHook"), "module.webHook");
        assert_eq!(
            infer_module_title("/monitor/webHook/export"),
            "module.webHook"
        );
        assert_eq!(
            infer_module_title("/monitor/webHook/{id}"),
            "module.webHook"
        );
        assert_eq!(
            infer_module_title("/monitor/webHook/log/list"),
            "module.webHook"
        );
        assert_eq!(
            infer_module_title("/monitor/webHook/log/{id}"),
            "module.webHook"
        );
        // 不干扰相邻模块
        assert_eq!(infer_module_title("/monitor/job"), "module.job");
        assert_eq!(infer_module_title("/monitor/operlog"), "module.operlog");
    }

    #[test]
    fn test_infer_module_title_sso() {
        // v5 第八轮：SSO 同意决策 / 客户端管理操作日志归类
        assert_eq!(infer_module_title("/sso/consent"), "module.ssoConsent");
        assert_eq!(
            infer_module_title("/system/oauth/client"),
            "module.oauthClient"
        );
        assert_eq!(
            infer_module_title("/system/oauth/client/list"),
            "module.oauthClient"
        );
        // grants 自助管理归个人中心（页面在个人中心内）
        assert_eq!(
            infer_module_title("/system/user/profile/sso-grants"),
            "module.profile"
        );
        // 不干扰相邻模块
        assert_eq!(infer_module_title("/system/user"), "module.user");
        assert_eq!(infer_module_title("/sso/authorize"), "module.other");
    }

    #[test]
    fn test_infer_business_type_webhook_operations() {
        // 导出（写出推送记录/回调配置）归类为导出=5
        assert_eq!(
            infer_business_type(Method::POST, "/monitor/webHook/export"),
            5
        );
        assert_eq!(
            infer_business_type(Method::POST, "/monitor/webHook/log/export"),
            5
        );
        // 清空推送记录归类为清空=9
        assert_eq!(
            infer_business_type(Method::DELETE, "/monitor/webHook/log/clean"),
            9
        );
        // 重试属于写操作（POST），无特殊类型匹配 → 按方法=新增=1
        assert_eq!(
            infer_business_type(Method::POST, "/monitor/webHook/log/{ids}/retry"),
            1
        );
        // 启停回调是修改 → PUT=2
        assert_eq!(
            infer_business_type(Method::PUT, "/monitor/webHook/{id}/status"),
            2
        );
    }

    #[test]
    fn test_is_write_method_webhook() {
        // 写操作需被 oper_log 记录以实现敏感操作留痕
        assert!(is_write_method(Method::POST));
        assert!(is_write_method(Method::PUT));
        assert!(is_write_method(Method::DELETE));
        // 查询类 GET 不记录（避免噪声）
        assert!(!is_write_method(Method::GET));
        assert!(!is_write_method(Method::HEAD));
        assert!(!is_write_method(Method::OPTIONS));
    }
}
