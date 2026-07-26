// axum-backend/src/middleware/oper_log.rs
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

use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{HeaderMap, Method};
use axum::middleware::Next;
use axum::response::Response;
use futures::FutureExt;

use crate::utils::ip::extract_client_ip;
use crate::service::sys_oper_log_service::OperLogRecord;
use crate::state::AppState;

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
    let matched_path = req
        .extensions()
        .get::<MatchedPath>()
        .cloned()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();

    // 仅记录写操作
    if !is_write_method(method.clone()) {
        return next.run(req).await;
    }

    // 提取操作人信息（auth_middleware 已注入 Claims）
    // 必须在 req.into_parts() 之前从 extensions 读取
    let (oper_name, operator_type, user_id) = req
        .extensions()
        .get::<crate::jwt::Claims>()
        .map(|c| (c.username.clone(), 1i32, c.sub.clone()))
        .unwrap_or_else(|| ("匿名".to_string(), 0, String::new()));

    // 提取客户端真实 IP（含可信代理白名单 + XFF 链校验）
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let headers: HeaderMap = req.headers().clone();
    let oper_ip = extract_client_ip(&headers, peer_ip, &state.config.server.trusted_proxies);

    let oper_url = req.uri().path().to_string();
    let title = infer_module_title(&matched_path);
    let business_type = infer_business_type(method.clone(), &matched_path);
    let start = Instant::now();

    // 查询 IP 归属地（mmdb 文件不存在或查询失败时返回空字符串）
    let oper_location = state.ip_locator.locate(&oper_ip);

    // 读取请求体（用于 oper_param + 提取 ID 用于审计快照）
    // SEC-006：检查 Content-Length，超大请求体不缓冲直接透传，避免 10MB×并发数 的内存放大
    let (parts, body) = req.into_parts();
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

    // 捕获变更前数据快照（仅 PUT/DELETE 请求）
    let oper_before = capture_before_snapshot(&state, &method, &oper_url, record_id).await;

    // 执行请求
    let response = next.run(req).await;

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
            format!("[binary: {}, {} bytes, skipped]", resp_content_type, resp_content_length)
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
        let json_result_raw = format!("[response too large: {} bytes, skipped]", resp_content_length);
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

    // 异步写入日志，不阻断响应
    let record = OperLogRecord {
        title,
        business_type,
        method: matched_path.clone(),
        request_method: method.to_string(),
        operator_type,
        oper_name: oper_name.clone(),
        dept_name: String::new(), // 占位，spawn 任务中查询后填入
        oper_url,
        oper_ip,
        oper_location,
        oper_param,
        oper_before,
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
    // 策略 1：从 URL 路径末段解析数字 ID
    let path_segments: Vec<&str> = oper_url.split('/').collect();
    if let Some(last_seg) = path_segments.last() {
        if let Ok(id) = last_seg.parse::<i64>() {
            return Some(id);
        }
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
    } else if oper_url.starts_with("/system/rateLimit") {
        "id"
    } else {
        return None;
    };

    json.get(field_name)
        .and_then(|v| v.as_i64())
        .or_else(|| json.get(field_name).and_then(|v| v.as_str()).and_then(|s| s.parse().ok()))
}

/// 捕获变更前数据快照（仅对 PUT/DELETE 请求）
///
/// 根据请求路径前缀和记录 ID，调用对应 service 查询旧数据并序列化为 JSON 字符串。
/// 失败时返回空字符串（不影响主流程）。
///
/// 设计要点：
/// - 仅对 PUT/DELETE 触发（POST 是新增，无"变更前"概念）
/// - ID 优先从 URL 路径末段解析，若 URL 无数字 ID 则从请求体 JSON 提取（如 PUT /system/config）
/// - 通过路径前缀分派到对应 service（user/role/menu/dept/post/config/notice）
/// - 查询失败或路径不匹配时返回空字符串，不影响主流程
async fn capture_before_snapshot(
    state: &Arc<AppState>,
    method: &Method,
    oper_url: &str,
    id: Option<i64>,
) -> String {
    // 仅对 PUT/DELETE 捕获
    if !matches!(method, &Method::PUT | &Method::DELETE) {
        return String::new();
    }

    let id = match id {
        Some(id) => id,
        None => return String::new(), // 无 ID，跳过
    };

    // 根据路径前缀分派到对应 service
    // 各 service 的 get_*_by_id 返回值均实现 serde::Serialize（Model 或 VO）
    let snapshot: Option<serde_json::Value> = if oper_url.starts_with("/system/user") {
        state
            .user_service
            .get_user_by_id(id)
            .await
            .ok()
            .map(|vo| serde_json::to_value(&vo).unwrap_or_default())
    } else if oper_url.starts_with("/system/role") {
        state
            .role_service
            .get_role_by_id(id)
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
            .get_dept_by_id(id)
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else if oper_url.starts_with("/system/post") {
        state
            .post_service
            .get_post_by_id(id)
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else if oper_url.starts_with("/system/config") {
        state
            .config_service
            .get_config_by_id(id)
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else if oper_url.starts_with("/system/notice") {
        state
            .notice_service
            .get_notice_by_id(id)
            .await
            .ok()
            .map(|m| serde_json::to_value(&m).unwrap_or_default())
    } else {
        None
    };

    match snapshot {
        Some(value) => {
            let s = serde_json::to_string(&value).unwrap_or_default();
            safe_truncate(&s, MAX_LOG_FIELD_LEN)
        }
        None => String::new(),
    }
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
        "salt",
        "secret",
        "apiKey",
        "api_key",
    ];
    for field in sensitive_fields {
        // 匹配 "field":"value" 模式
        let patterns = [
            format!("\"{}\":\"", field),
            format!("\"{}\": \"", field),
        ];
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
fn infer_module_title(path: &str) -> String {
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
    } else if path.starts_with("/monitor/job") {
        "module.job".to_string()
    } else if path.starts_with("/monitor/operlog") {
        "module.operlog".to_string()
    } else if path.starts_with("/monitor/logininfor") {
        "module.logininfor".to_string()
    } else if path.starts_with("/monitor/online") {
        "module.online".to_string()
    } else if path.starts_with("/tool/gen") {
        "module.gen".to_string()
    } else if path.starts_with("/common/") {
        "module.common".to_string()
    } else {
        "module.other".to_string()
    }
}

/// 根据 HTTP 方法 + 路由路径推断业务类型
///
/// 对齐 ruoyi-vue3-ts 前端 BusinessType 枚举与 sys_oper_type 字典：
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
    match method {
        Method::POST => 1,
        Method::PUT => 2,
        Method::DELETE => 3,
        _ => 0,
    }
}

// ==================== 响应体脱敏（P0-33） ====================

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
        Err(_) => return body.to_string(),
    };
    sanitize_value(&mut value);
    serde_json::to_string(&value).unwrap_or_else(|_| body.to_string())
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
                    || lower.contains("api_key");
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

/// 手机号脱敏：保留前 3 后 4，中间 4 位用 * 替换
/// 使用 char 迭代避免 UTF-8 多字节边界切片 panic（P0-New-2）
fn mask_phone(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 7 {
        return "***".to_string();
    }
    let head: String = chars[..3].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{}****{}", head, tail)
}

/// 身份证号脱敏：保留前 4 后 2，中间 8 位用 * 替换
/// 使用 char 迭代避免 UTF-8 多字节边界切片 panic（P0-New-2）
fn mask_idcard(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 10 {
        return "***".to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{}********{}", head, tail)
}

/// 邮箱脱敏：保留首字符和 @ 域名，中间用 * 填充（如 a***@example.com）（P0-33 改进）
/// 使用 char 迭代避免 UTF-8 多字节边界切片 panic
fn mask_email(s: &str) -> String {
    match s.find('@') {
        Some(at) if at > 0 => {
            let (local, domain) = s.split_at(at);
            let mut chars = local.chars();
            // 仅保留首字符，其余本地部分替换为 ***
            let head = chars.next().map(|c| c.to_string()).unwrap_or_default();
            format!("{}***{}", head, domain)
        }
        // 非 email 格式或本地部分为空，直接掩码
        _ => "***".to_string(),
    }
}

/// 银行卡号脱敏：保留前 4 后 4，中间用 * 填充（P0-33 改进）
/// 使用 char 迭代避免 UTF-8 多字节边界切片 panic
fn mask_bankcard(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 8 {
        return "***".to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    let mask: String = "*".repeat(chars.len() - 8);
    format!("{}{}{}", head, mask, tail)
}

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
        let body = "plain text response";
        assert_eq!(sanitize_response_body(body), "plain text response");
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
}
