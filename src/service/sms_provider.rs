// stepby-axum/src/service/sms_provider.rs
//! 可插拔短信投递 Provider（G-07 批次六）
//!
//! **设计决策（深审定稿，替换审计原案）**：
//! - 凭据/网关配置**承载于消息渠道自身的 `config_json`**（EncryptedString 加密列，
//!   G-14 已迁），而非审计原案的全局 `sys.sms.*` 键族——多渠道多凭据、复用渠道
//!   管理 UI 与加密链路，是更优形态；
//! - 首版仅内置 [`GenericHttpProvider`]（通用 HTTP 网关）：与自由 content 模型
//!   （sys_msg_template 渲染产物）完全兼容，且可用本地 HTTP 服务做真实集成测试；
//! - 阿里云/腾讯云等"模板 CODE 制"运营商需要模板 code 体系对齐（sys_msg_template
//!   增加 sms_template_code 字段），作为 trait 的**后续扩展实现**接入，不改 trait 形状；
//! - **fail-closed**：配置缺失/网关失败一律 Err，交由调用方走 status='2' 待重试链
//!   （B6 铁律：超时 + 重试上限 + 失败审计），绝不静默丢弃。

use async_trait::async_trait;

/// 短信渠道配置（从渠道 `config_json` 解析；字段缺失即 Err——fail-closed）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsChannelConfig {
    /// 网关投递 URL（POST）
    pub gateway_url: String,
    /// 鉴权头名（如 `X-Api-Key`；空串 = 不带鉴权头——仅限内网网关）
    pub auth_header: String,
    /// 鉴权头值（EncryptedString 加密存储，读路径已解密）
    pub auth_value: String,
    /// 手机号字段名（网关 JSON body 内，默认 `phone`）
    pub phone_field: String,
    /// 内容字段名（默认 `content`）
    pub content_field: String,
    /// 附加字段（随 body 透传，如 appCode/signName）
    pub extra_fields: Vec<(String, serde_json::Value)>,
}

impl SmsChannelConfig {
    /// 从渠道 config_json（明文，读路径已自动解密）解析；严格校验，缺失即 Err
    pub fn from_config_json(raw: Option<&str>) -> Result<Self, String> {
        let raw = raw
            .filter(|s| !s.trim().is_empty())
            .ok_or("短信渠道未配置 config_json")?;
        let v: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("config_json 不是合法 JSON: {e}"))?;
        let gateway_url = v
            .get("gateway_url")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or("config_json 缺少 gateway_url")?;
        if !gateway_url.starts_with("http://") && !gateway_url.starts_with("https://") {
            return Err(format!("gateway_url 必须为 http(s) URL: {gateway_url}"));
        }
        let auth_header = v
            .get("auth_header")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let auth_value = v
            .get("auth_value")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let phone_field = v
            .get("phone_field")
            .and_then(|x| x.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("phone")
            .to_string();
        let content_field = v
            .get("content_field")
            .and_then(|x| x.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("content")
            .to_string();
        let extra_fields = v
            .get("extra_fields")
            .and_then(|x| x.as_object())
            .map(|m| {
                m.iter()
                    .map(|(k, val)| (k.clone(), val.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !auth_header.is_empty() && auth_value.is_empty() {
            return Err("配置了 auth_header 但缺少 auth_value".to_string());
        }
        Ok(Self {
            gateway_url,
            auth_header,
            auth_value,
            phone_field,
            content_field,
            extra_fields,
        })
    }

    /// 构造 POST JSON body
    pub fn build_body(&self, phone: &str, content: &str) -> serde_json::Value {
        let mut body = serde_json::Map::new();
        body.insert(self.phone_field.clone(), serde_json::json!(phone));
        body.insert(self.content_field.clone(), serde_json::json!(content));
        for (k, v) in &self.extra_fields {
            body.insert(k.clone(), v.clone());
        }
        serde_json::Value::Object(body)
    }
}

/// 短信投递 Provider 抽象（可插拔：首版 GenericHttp；后续阿里云/腾讯云模板制实现）
#[async_trait]
pub trait SmsProvider: Send + Sync {
    /// 发送短信。成功返回网关侧消息标识（如响应体/消息 id 摘要）；失败返回原因。
    async fn send(
        &self,
        cfg: &SmsChannelConfig,
        phone: &str,
        content: &str,
    ) -> Result<String, String>;

    /// 连通性探测（渠道"测试"按钮）：POST 空探活（网关可选实现 422 语义）或配置校验。
    /// 默认实现 = 校验配置完整 + 网关可达性由 send 真实验证。
    async fn probe(&self, cfg: &SmsChannelConfig) -> Result<(), String> {
        if cfg.gateway_url.is_empty() {
            return Err("gateway_url 未配置".to_string());
        }
        Ok(())
    }
}

/// 通用 HTTP 网关 Provider（首版内置）
///
/// 契约：`POST {gateway_url}`，JSON body = `{phone_field, content_field, ...extra_fields}`，
/// 可选鉴权头 `auth_header: auth_value`。2xx 视为投递受理成功。
pub struct GenericHttpProvider {
    http: reqwest::Client,
}

impl GenericHttpProvider {
    pub fn new() -> Self {
        Self {
            // §5.35（B.6 超时铁律）：出站必带超时，防网关无响应挂死 worker
            http: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("sms http client 构建失败（不可恢复的编程错误）"),
        }
    }
}

impl Default for GenericHttpProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SmsProvider for GenericHttpProvider {
    async fn send(
        &self,
        cfg: &SmsChannelConfig,
        phone: &str,
        content: &str,
    ) -> Result<String, String> {
        let mut req = self
            .http
            .post(&cfg.gateway_url)
            .json(&cfg.build_body(phone, content));
        if !cfg.auth_header.is_empty() {
            req = req.header(&cfg.auth_header, &cfg.auth_value);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("短信网关请求失败: {e}"))?;
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "短信网关返回 {status}: {}",
                body_text.chars().take(200).collect::<String>()
            ));
        }
        // 网关消息标识：尽力提取（body 前 120 字符作为留痕）
        Ok(format!(
            "HTTP {status}; body: {}",
            body_text.chars().take(120).collect::<String>()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_CFG: &str = r#"{
        "gateway_url": "https://sms.example.com/send",
        "auth_header": "X-Api-Key",
        "auth_value": "secret-key",
        "phone_field": "mobile",
        "content_field": "text",
        "extra_fields": {"appCode": "app1"}
    }"#;

    #[test]
    fn config_parse_full() {
        let c = SmsChannelConfig::from_config_json(Some(FULL_CFG)).unwrap();
        assert_eq!(c.gateway_url, "https://sms.example.com/send");
        assert_eq!(c.phone_field, "mobile");
        assert_eq!(c.extra_fields.len(), 1);
    }

    #[test]
    fn config_parse_defaults() {
        let c =
            SmsChannelConfig::from_config_json(Some(r#"{"gateway_url":"http://10.0.0.1/send"}"#))
                .unwrap();
        assert_eq!(c.phone_field, "phone");
        assert_eq!(c.content_field, "content");
        assert!(c.auth_header.is_empty());
    }

    #[test]
    fn config_fail_closed_on_missing() {
        assert!(SmsChannelConfig::from_config_json(None).is_err());
        assert!(SmsChannelConfig::from_config_json(Some("")).is_err());
        assert!(SmsChannelConfig::from_config_json(Some("{}")).is_err());
        assert!(SmsChannelConfig::from_config_json(Some("not json")).is_err());
        // 非 http(s) URL 拒绝
        assert!(SmsChannelConfig::from_config_json(Some(r#"{"gateway_url":"ftp://x"}"#)).is_err());
        // 配了头缺值拒绝
        assert!(
            SmsChannelConfig::from_config_json(Some(
                r#"{"gateway_url":"http://x","auth_header":"K"}"#
            ))
            .is_err()
        );
    }

    #[test]
    fn build_body_shape() {
        let c = SmsChannelConfig::from_config_json(Some(FULL_CFG)).unwrap();
        let body = c.build_body("13800000000", "您好");
        assert_eq!(body["mobile"], "13800000000");
        assert_eq!(body["text"], "您好");
        assert_eq!(body["appCode"], "app1");
    }

    #[tokio::test]
    async fn generic_provider_sends_auth_and_body() {
        // 本地 TCP listener 当网关（webhook 测试同款先例）——验证真实 HTTP 链路
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut content_length = 0usize;
            let mut has_auth = false;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("content-length:") {
                    content_length = line.split(':').nth(1).unwrap().trim().parse().unwrap();
                }
                if lower.starts_with("x-api-key:") {
                    has_auth = line.contains("secret-key");
                }
                if line.trim().is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; content_length];
            std::io::Read::read_exact(&mut reader, &mut body).unwrap();
            let body_str = String::from_utf8(body).unwrap();
            let respond =
                format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            let mut w = stream;
            w.write_all(respond.as_bytes()).unwrap();
            (request_line.contains("POST"), has_auth, body_str)
        });

        let cfg = SmsChannelConfig::from_config_json(Some(&format!(
            r#"{{"gateway_url":"http://{addr}/send","auth_header":"X-Api-Key","auth_value":"secret-key","phone_field":"mobile","content_field":"text"}}"#
        )))
        .unwrap();
        let provider = GenericHttpProvider::new();
        let result = provider.send(&cfg, "13800000000", "您好").await.unwrap();
        assert!(result.contains("HTTP 200"), "result={result}");

        let (is_post, has_auth, body_str) = handle.join().unwrap();
        assert!(is_post);
        assert!(has_auth, "鉴权头应携带");
        assert!(body_str.contains(r#""mobile":"13800000000""#));
        assert!(body_str.contains(r#""text":"您好""#));
    }

    #[tokio::test]
    async fn generic_provider_fails_on_500() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
            }
            let mut w = stream;
            w.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\nConnection: close\r\n\r\noops!").unwrap();
        });
        let cfg = SmsChannelConfig::from_config_json(Some(&format!(
            r#"{{"gateway_url":"http://{addr}/send"}}"#
        )))
        .unwrap();
        let provider = GenericHttpProvider::new();
        let err = provider.send(&cfg, "138", "x").await.unwrap_err();
        assert!(err.contains("500"), "err={err}");
    }
}
