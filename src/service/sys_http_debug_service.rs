//! 在线 HTTP 调试器 Service 层（/tool/http-debug/execute）
//!
//! 职责：接收客户端指定的 target URL + method + 请求头 + 请求体，由服务端代为发起出站 HTTP 请求，
//! 并返回状态码 / 响应头 / 响应体 / 耗时 / 字节数等调试信息，便于非开发同事在后台调试接口。
//!
//! 安全设计（重点：SSRF）：
//! - 目标 URL 必须通过 [`crate::common::ssrf`] 双重校验（静态 scheme+地址 + 动态 DNS 解析），
//!   阻断内网 / 保留地址 / 云元数据端点 / 保留域名后缀。
//! - 手动跟随重定向链：对每一跳 Location 重新执行 SSRF 校验（不信任第一跳之后的目标），
//!   并遵守 301/302/303/307/308 的 method 语义；上限 `MAX_REDIRECTS`。
//! - 仅转发用户显式提供的请求头（`HttpDebugDto.headers`），绝不透传本请求携带的管理员
//!   登录态（Authorization/Cookie），防止把后台 Token 泄漏到目标地址。
//! - 出站请求超时上限 `MAX_TIMEOUT_SECS`，响应体大小上限 `MAX_BODY_BYTES`，避免资源耗尽。
//! - 本接口受 `tool:httpDebug:list` 权限保护（需后台登录 + 授予该权限）。
//!
//! 分层约束：不依赖任何 Web 框架类型；错误统一使用 [`ServiceError`]。

use serde::Deserialize;
use std::time::{Duration, Instant};
use utoipa::ToSchema;

use crate::common::error::ServiceError;
use crate::common::i18n::pick;
use crate::common::ssrf;

/// 请求体 / 响应体最大字节数（1 MiB）——超过则截断并标记
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// 最大重定向跳数
const MAX_REDIRECTS: u32 = 5;
/// 出站请求时长上限（秒）
const MAX_TIMEOUT_SECS: u64 = 30;
/// 默认出站请求时长（秒）
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// 允许的 HTTP method
const ALLOWED_METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// 仅凭据在用户显式提供的 header 中才转发；这些逐跳/连接级字段一律过滤
const HOP_BY_HOP_HEADERS: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "transfer-encoding",
    "te",
    "upgrade",
    "trailer",
    "host",
];

/// 请求头单项（保留用户录入顺序，允许重复键）
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeaderItem {
    pub name: String,
    pub value: String,
}

/// 调试请求 DTO
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HttpDebugDto {
    /// HTTP 方法（GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS）
    pub method: String,
    /// 目标 URL（http/https）
    pub url: String,
    /// 请求头列表
    #[serde(default)]
    pub headers: Vec<HeaderItem>,
    /// 请求体（原始字符串；为空则不发送 body）
    #[serde(default)]
    pub body: Option<String>,
    /// 请求超时（秒），默认 10，上限 30
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// 响应头输出项
#[derive(Debug, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HeaderVo {
    pub name: String,
    pub value: String,
}

/// 调试执行结果 VO
#[derive(Debug, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HttpDebugVo {
    /// 最终 HTTP 状态码（0 表示连接/发送阶段失败）
    pub status: u16,
    /// 状态文本（如 "OK"，HTTP/2 下可能为空）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_text: Option<String>,
    /// 响应头
    pub headers: Vec<HeaderVo>,
    /// 响应体（超过 max_body 时截断）
    pub body: String,
    /// 总耗时（毫秒）
    pub time_ms: u64,
    /// 响应体字节数（截断前的实际大小）
    pub size_bytes: u64,
    /// 跟随的重定向跳数
    pub redirected: u32,
    /// 传输层错误文案（连接被拒 / 超时 / TLS 等；HTTP 层错误不含此项）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 在线 HTTP 调试器 Service
pub struct SysHttpDebugService {
    /// 出站 HTTP 客户端：禁自动重定向（由 `execute` 手动逐跳跟随并做 SSRF 校验）
    http: reqwest::Client,
}

impl Default for SysHttpDebugService {
    fn default() -> Self {
        Self::new()
    }
}

impl SysHttpDebugService {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                // 连接被拒等快速失败；TLS 校验默认开启（rustls）
                .connect_timeout(Duration::from_secs(10))
                .user_agent("stepby-http-debugger/1.0")
                .build()
                .expect("reqwest client 初始化失败"),
        }
    }

    /// 执行一次调试请求（可选地跟随安全重定向链）
    pub async fn execute(&self, dto: HttpDebugDto) -> Result<HttpDebugVo, ServiceError> {
        // ===== 1. 参数规范化 =====
        let method = dto.method.trim().to_ascii_uppercase();
        if !ALLOWED_METHODS.contains(&method.as_str()) {
            return Err(ServiceError::bad_request(pick(
                "不支持的 HTTP 方法",
                "Unsupported HTTP method",
            )));
        }
        let timeout = Duration::from_secs(
            dto.timeout_secs
                .unwrap_or(DEFAULT_TIMEOUT_SECS)
                .min(MAX_TIMEOUT_SECS),
        );

        // ===== 2. 目标 URL 静态 + 动态 SSRF 校验 =====
        let mut base_url =
            ssrf::validate_url(dto.url.trim()).map_err(|e| ServiceError::bad_request(&e))?;
        self.validate_dns(&base_url).await?;

        // ===== 3. 请求体与 method 规范化 =====
        let mut current_method = method;
        let mut body = dto.body.clone().unwrap_or_default();
        if !body.is_empty() && matches!(current_method.as_str(), "GET" | "HEAD" | "OPTIONS") {
            // 校验：GET/HEAD/OPTIONS 不应携带 body，忽略之
            body = String::new();
        }

        // ===== 5. 手动安全跟随重定向链 =====
        // b74（AGENTS B.4）：调试器是**用户指定目标**的出网面，故障面与任何内置依赖都不同，
        // 单独成桶。计数口径：**一次 execute = 一次出站事件**（重定向链是同一个用户动作的
        // 组成部分，拆成多笔会让"链上第 3 跳被 SSRF 挡下"混进总量）；结局在响应体读完后
        // 才判成功，因此传输失败、构建失败、链中拒绝、体读取失败一律记 `error`。
        // 参数/SSRF 预校验阶段的拒绝**不计数**（那时还没有出网）。
        let mut outbound = crate::observability::metrics::OutboundGuard::start("http_debug");
        let start = Instant::now();
        let mut redirected: u32 = 0;
        let mut response;

        loop {
            // 说明：reqwest 的 RequestBuilder 是一次性消费形态，因此这里每跳重建请求并重放
            // 自定义头与 body（重定向下跳仍需保留用户头，故不能在首次构建时固化）。
            let mut rb = self
                .http
                .request(
                    reqwest::Method::from_bytes(current_method.as_bytes()).expect("method 已校验"),
                    base_url.as_str(),
                )
                .timeout(timeout);
            rb = self.apply_headers(rb, &dto.headers);
            if !body.is_empty() && !matches!(current_method.as_str(), "GET" | "HEAD") {
                rb = rb.body(body.clone());
            }
            let req = match rb.build() {
                Ok(r) => r,
                Err(e) => {
                    return Ok(HttpDebugVo::transport_error(
                        format!(
                            "{}{}",
                            pick("请求构造失败：", "Failed to build request: "),
                            e
                        ),
                        start,
                    ));
                }
            };

            response = match self.http.execute(req).await {
                Ok(r) => r,
                Err(e) => {
                    return Ok(HttpDebugVo::transport_error(
                        format!("{}{}", pick("请求发送失败：", "Request failed: "), e),
                        start,
                    ));
                }
            };

            // 5.1 是否可跟随的重定向
            let loc = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let status = response.status();
            let redirectable = matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
                && loc.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
                && redirected < MAX_REDIRECTS;

            if !redirectable {
                break;
            }

            // b71：原 `expect("已判非空")` 依赖上方 redirectable 组合逻辑保证非空（逻辑距离远），
            // 改为模式匹配降级——组合逻辑一旦改动即 break 重试循环，不再构成请求路径 panic 面
            let Some(loc) = loc.filter(|s| !s.is_empty()) else {
                break;
            };
            let next = base_url
                .join(&loc)
                .map_err(|e| ServiceError::bad_request(&e.to_string()))?;

            // 5.2 对下一跳重新执行 SSRF 校验（含 DNS 重解析）
            ssrf::validate_url(next.as_str()).map_err(|e| ServiceError::bad_request(&e))?;
            self.validate_dns(&next).await?;

            // 5.3 更新 method / body（依标准语义）
            // 303 → 一律 GET（去 body）；307/308 → 保持 method+body；
            // 301/302 且当前非 GET/HEAD → 转 GET（去 body）
            if status.as_u16() == 303 {
                current_method = "GET".to_string();
                body.clear();
            } else if matches!(status.as_u16(), 301 | 302 | 307 | 308)
                && !matches!(current_method.as_str(), "GET" | "HEAD")
            {
                if status.as_u16() == 307 || status.as_u16() == 308 {
                    // 保持 method + body，无需改动
                } else {
                    current_method = "GET".to_string();
                    body.clear();
                }
            }

            base_url = next;
            redirected += 1;
        }

        // ===== 6. 组装结果 =====
        let status = response.status().as_u16();
        let status_text = response.status().canonical_reason().map(|s| s.to_string());
        let headers: Vec<HeaderVo> = response
            .headers()
            .iter()
            .map(|(n, v)| HeaderVo {
                name: n.as_str().to_string(),
                value: v.to_str().unwrap_or("[二进制]").to_string(),
            })
            .collect();

        let bytes = response.bytes().await.map_err(|e| {
            ServiceError::bad_request(&format!(
                "{} {e}",
                pick("读取响应体失败：", "Failed to read response body: ")
            ))
        })?;
        outbound.succeeded();
        let size_bytes = bytes.len() as u64;
        let body = decode_body(&bytes, MAX_BODY_BYTES);

        let time_ms = start.elapsed().as_millis() as u64;
        Ok(HttpDebugVo {
            status,
            status_text,
            headers,
            body,
            time_ms,
            size_bytes,
            redirected,
            error: None,
        })
    }

    /// 对 URL 的主机执行动态 DNS 校验（防解析到内网）
    async fn validate_dns(&self, url: &url::Url) -> Result<(), ServiceError> {
        let host = url.host_str().ok_or_else(|| {
            ServiceError::bad_request(pick("URL 缺少主机名", "URL is missing a host"))
        })?;
        let port = url
            .port_or_known_default()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        ssrf::validate_host_resolution(host, port)
            .await
            .map_err(|e| ServiceError::bad_request(&e))
    }

    /// 将用户自定义头应用到 RequestBuilder（每次重定向后重建并重放）
    fn apply_headers(
        &self,
        mut req: reqwest::RequestBuilder,
        headers: &[HeaderItem],
    ) -> reqwest::RequestBuilder {
        for h in headers.iter().filter(|h| !h.name.trim().is_empty()) {
            let name = h.name.trim().to_ascii_lowercase();
            if HOP_BY_HOP_HEADERS.contains(&name.as_str()) {
                continue;
            }
            if let (Ok(n), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                reqwest::header::HeaderValue::from_str(&h.value),
            ) {
                req = req.header(n, v);
            }
        }
        req
    }
}

impl HttpDebugVo {
    /// 传输层错误结果（连接失败 / 超时等，返回 200 但 error 字段携带原因）
    fn transport_error(msg: String, start: Instant) -> Self {
        HttpDebugVo {
            status: 0,
            status_text: None,
            headers: Vec::new(),
            body: String::new(),
            time_ms: start.elapsed().as_millis() as u64,
            size_bytes: 0,
            redirected: 0,
            error: Some(msg),
        }
    }
}

/// 响应体解码（优先按 UTF-8；失败按字节源丢失文本展示，并截断到上限）
fn decode_body(bytes: &[u8], cap: usize) -> String {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let clipped: String = text
        .char_indices()
        .map_while(|(i, c)| (i < cap).then_some(c))
        .collect();
    if bytes.len() > cap {
        format!(
            "{clipped}…\n[响应体超 {cap} 字节已截断，实际 {} 字节]",
            bytes.len()
        )
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_methods_are_uppercase_and_complete() {
        // 常量值统一大写；service 在查询前会把用户输入 to_ascii_uppercase，故此处只需校验大写集合
        assert!(ALLOWED_METHODS.contains(&"GET"));
        assert!(ALLOWED_METHODS.contains(&"POST"));
        assert!(
            !ALLOWED_METHODS.contains(&"get"),
            "常量应为大写，小写不应命中"
        );
        assert!(
            !ALLOWED_METHODS.contains(&"TRACE"),
            "密码级方法 TRACE 不得开放"
        );
    }

    #[test]
    fn hop_by_hop_filtered() {
        let name = "HOST";
        let lowered = name.to_ascii_lowercase();
        assert!(HOP_BY_HOP_HEADERS.contains(&lowered.as_str()));
    }

    #[test]
    fn decode_body_respects_cap() {
        let bytes = vec![b'a'; 100];
        let out = decode_body(&bytes, 50);
        assert!(out.contains("已截断"), "应标注截断: {out}");
        assert!(out.starts_with("aaaaaaaa"), "应保留前段");
    }

    #[test]
    fn decode_body_without_cap() {
        let out = decode_body(b"hello", 100);
        assert_eq!(out, "hello");
    }

    #[test]
    fn transport_error_shape() {
        let vo = HttpDebugVo::transport_error("boom".into(), Instant::now());
        assert_eq!(vo.status, 0);
        assert_eq!(vo.error.as_deref(), Some("boom"));
    }
}
