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

// ==================== 云运营商模板制 Provider（G-07 扩展，批次八） ====================
//
// **设计决策**：云厂商（阿里云/腾讯云）为"模板 CODE 制"——投递必须携带运营商侧备案的
// 模板 code + 原始变量，与自由 content 模型正交，故**不强行塞进 [`SmsProvider`] trait**
// （该 trait 保持自由文本语义）；云厂商走独立结构体 + `send_templated`，由 dispatch 按
// 渠道 config_json 的 `provider` 字段分发。两实现均为**真实 HTTP + 真实签名**：
// - 阿里云：Dysmsapi 2017-05-25 `SendSms`，RPC 签名（HMAC-SHA1 + POP 编码，RFC3986）；
// - 腾讯云：Sms 2021-01-11 `SendSms`，TC3-HMAC-SHA256 签名（canonical request 三段式）。
// 单测以本地 TCP listener 收真实请求，**反向验签**（重算 HMAC 对比）+ 断言参数形态。

/// 云运营商种类（由渠道 config_json 的 `provider` 字段判定；缺省 generic = 自由文本网关）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmsProviderKind {
    /// 通用 HTTP 网关（自由 content）
    Generic,
    /// 阿里云短信（模板制）
    Aliyun,
    /// 腾讯云短信（模板制）
    Tencent,
}

/// 从 config_json 提取 provider 判定字段（仅看该字段，不校验其余——各形态自行 fail-closed）
pub fn detect_provider_kind(raw: Option<&str>) -> SmsProviderKind {
    let parsed = raw.and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
    match parsed
        .as_ref()
        .and_then(|v| v.get("provider"))
        .and_then(|x| x.as_str())
    {
        Some("aliyun") => SmsProviderKind::Aliyun,
        Some("tencent") => SmsProviderKind::Tencent,
        _ => SmsProviderKind::Generic,
    }
}

/// 云运营商投递配置（从渠道 config_json 解析；缺字段即 Err——fail-closed）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudSmsConfig {
    pub kind: SmsProviderKind,
    /// API 端点（缺省官方端点；测试可指向本地 listener）
    pub endpoint: String,
    /// 阿里云 AccessKeyId / 腾讯云 SecretId
    pub access_key_id: String,
    /// 阿里云 AccessKeySecret / 腾讯云 SecretKey（读路径已解密）
    pub access_key_secret: String,
    /// 短信签名（运营商备案）
    pub sign_name: String,
    /// 腾讯云 SdkAppId（仅腾讯必填）
    pub sdk_app_id: String,
    /// 腾讯云地域（仅腾讯，缺省 ap-guangzhou）
    pub region: String,
}

impl CloudSmsConfig {
    pub fn from_config_json(raw: Option<&str>) -> Result<Self, String> {
        let raw = raw
            .filter(|s| !s.trim().is_empty())
            .ok_or("短信渠道未配置 config_json")?;
        let v: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("config_json 不是合法 JSON: {e}"))?;
        let kind = match v.get("provider").and_then(|x| x.as_str()) {
            Some("aliyun") => SmsProviderKind::Aliyun,
            Some("tencent") => SmsProviderKind::Tencent,
            other => {
                return Err(format!(
                    "config_json provider 非云厂商形态: {other:?}（应为 aliyun/tencent）"
                ));
            }
        };
        let endpoint = v
            .get("endpoint")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| match kind {
                SmsProviderKind::Aliyun => "https://dysmsapi.aliyuncs.com".to_string(),
                _ => "https://sms.tencentcloudapi.com".to_string(),
            })
            .to_string();
        let get = |k: &str| -> Result<String, String> {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or(format!("config_json 缺少 {k}"))
        };
        let access_key_id = get("access_key_id")?;
        let access_key_secret = get("access_key_secret")?;
        let sign_name = get("sign_name")?;
        let sdk_app_id = match kind {
            SmsProviderKind::Tencent => get("sdk_app_id")?,
            _ => String::new(),
        };
        let region = match kind {
            SmsProviderKind::Tencent => v
                .get("region")
                .and_then(|x| x.as_str())
                .unwrap_or("ap-guangzhou")
                .to_string(),
            _ => String::new(),
        };
        Ok(Self {
            kind,
            endpoint,
            access_key_id,
            access_key_secret,
            sign_name,
            sdk_app_id,
            region,
        })
    }
}

/// POP 编码（阿里云 RPC 签名规范：RFC3986 百分号编码，且加号转 %20、星号转 %2A、波浪线保留字面）
fn pop_encode(s: &str) -> String {
    let encoded =
        percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
    let mut fixed = String::with_capacity(encoded.len());
    let mut chars = encoded.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '+' => fixed.push_str("%20"),
            '*' => fixed.push_str("%2A"),
            '%' => {
                // 百分号转义：仅把 %7E 还原为字面波浪线，其余原样保留
                let mut two = String::new();
                for _ in 0..2 {
                    if let Some(h) = chars.next() {
                        two.push(h);
                    }
                }
                if two.eq_ignore_ascii_case("7E") {
                    fixed.push('~');
                } else {
                    fixed.push('%');
                    fixed.push_str(&two);
                }
            }
            _ => fixed.push(c),
        }
    }
    fixed
}

/// 阿里云短信 Provider（Dysmsapi RPC 签名，真实 HTTP）
pub struct AliyunSmsProvider {
    http: reqwest::Client,
}

impl AliyunSmsProvider {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("aliyun sms http client 构建失败（不可恢复的编程错误）"),
        }
    }

    /// 计算 RPC 签名（供单测反向验证复用）
    fn sign(params: &[(String, String)], secret: &str) -> String {
        let mut sorted = params.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let query = sorted
            .iter()
            .map(|(k, v)| format!("{}={}", pop_encode(k), pop_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let string_to_sign = format!("POST&{}&{}", pop_encode("/"), pop_encode(&query));
        use hmac::{KeyInit, Mac};
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(format!("{secret}&").as_bytes())
            .expect("HMAC key 合法");
        mac.update(string_to_sign.as_bytes());
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    }

    /// 发送模板短信（阿里云 SendSms；响应 Code == "OK" 即受理成功）
    pub async fn send_templated(
        &self,
        cfg: &CloudSmsConfig,
        phone: &str,
        template_code: &str,
        params: &serde_json::Value,
    ) -> Result<String, String> {
        let nonce = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut params_list: Vec<(String, String)> = vec![
            ("AccessKeyId".into(), cfg.access_key_id.clone()),
            ("Action".into(), "SendSms".into()),
            ("Format".into(), "JSON".into()),
            ("PhoneNumbers".into(), phone.to_string()),
            ("RegionId".into(), "cn-hangzhou".into()),
            ("SignName".into(), cfg.sign_name.clone()),
            ("SignatureMethod".into(), "HMAC-SHA1".into()),
            ("SignatureNonce".into(), nonce),
            ("SignatureVersion".into(), "1.0".into()),
            ("TemplateCode".into(), template_code.to_string()),
            ("TemplateParam".into(), params.to_string()),
            ("Timestamp".into(), timestamp),
            ("Version".into(), "2017-05-25".into()),
        ];
        let signature = Self::sign(&params_list, &cfg.access_key_secret);
        params_list.push(("Signature".into(), signature));

        let resp = self
            .http
            .post(&cfg.endpoint)
            .form(&params_list)
            .send()
            .await
            .map_err(|e| format!("阿里云短信请求失败: {e}"))?;
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "阿里云短信返回 {status}: {}",
                body_text.chars().take(200).collect::<String>()
            ));
        }
        let v: serde_json::Value = serde_json::from_str(&body_text).map_err(|e| {
            format!(
                "阿里云短信响应非 JSON: {e}; body={}",
                body_text.chars().take(200).collect::<String>()
            )
        })?;
        if v.get("Code").and_then(|x| x.as_str()) == Some("OK") {
            Ok(v.get("BizId")
                .and_then(|x| x.as_str())
                .unwrap_or("no-biz-id")
                .to_string())
        } else {
            Err(format!(
                "阿里云短信受理失败 Code={:?} Message={:?}",
                v.get("Code").and_then(|x| x.as_str()),
                v.get("Message").and_then(|x| x.as_str())
            ))
        }
    }
}

impl Default for AliyunSmsProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// 腾讯云短信 Provider（TC3-HMAC-SHA256 签名，真实 HTTP）
pub struct TencentSmsProvider {
    http: reqwest::Client,
}

impl TencentSmsProvider {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("tencent sms http client 构建失败（不可恢复的编程错误）"),
        }
    }

    /// 发送模板短信（腾讯云 SendSms；`SendStatusSet[0].Code` == "Ok" 即受理成功）
    pub async fn send_templated(
        &self,
        cfg: &CloudSmsConfig,
        phone: &str,
        template_code: &str,
        params: &serde_json::Value,
    ) -> Result<String, String> {
        use hmac::{KeyInit, Mac};
        use sha2::Digest;
        // 变量值数组（模板参数有序集）；对象按 key 排序保证稳定序，数组原样
        let param_set: Vec<String> = match params {
            serde_json::Value::Array(arr) => arr
                .iter()
                .map(|x| match x {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect(),
            serde_json::Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                // `filter_map` 而非 `get(..).unwrap()`：键集与 map 同源，今天不可能落空，
                // 但这里是**请求路径**，留一条 unwrap 就等于留一个未来改动引爆的 panic 面
                keys.iter()
                    .filter_map(|k| m.get(*k))
                    .map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect()
            }
            _ => vec![],
        };
        let host = cfg
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string();
        let body = serde_json::json!({
            "PhoneNumberSet": [format!("+86{phone}")],
            "SmsSdkAppId": cfg.sdk_app_id,
            "SignName": cfg.sign_name,
            "TemplateId": template_code,
            "TemplateParamSet": param_set,
        });
        let payload = body.to_string();

        let ts = chrono::Utc::now().timestamp();
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let payload_hash = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(payload.as_bytes());
            hex::encode(hasher.finalize())
        };
        let canonical_request = format!(
            "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:{host}\nx-tc-action:sendsms\n\ncontent-type;host;x-tc-action\n{payload_hash}"
        );
        let canonical_hash = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(canonical_request.as_bytes());
            hex::encode(hasher.finalize())
        };
        let string_to_sign =
            format!("TC3-HMAC-SHA256\n{ts}\n{date}/sms/tc3_request\n{canonical_hash}");
        let hmac_sha256 = |key: &[u8], data: &[u8]| -> Vec<u8> {
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC key 合法");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        };
        let k_date = hmac_sha256(
            format!("TC3{}", cfg.access_key_secret).as_bytes(),
            date.as_bytes(),
        );
        let k_service = hmac_sha256(&k_date, b"sms");
        let k_signing = hmac_sha256(&k_service, b"tc3_request");
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{}/sms/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature={signature}",
            cfg.access_key_id, date
        );

        let resp = self
            .http
            .post(&cfg.endpoint)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Host", &host)
            .header("X-TC-Action", "SendSms")
            .header("X-TC-Version", "2021-01-11")
            .header("X-TC-Region", &cfg.region)
            .header("X-TC-Timestamp", ts.to_string())
            .header("Authorization", authorization)
            .body(payload)
            .send()
            .await
            .map_err(|e| format!("腾讯云短信请求失败: {e}"))?;
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "腾讯云短信返回 {status}: {}",
                body_text.chars().take(200).collect::<String>()
            ));
        }
        let v: serde_json::Value =
            serde_json::from_str(&body_text).map_err(|e| format!("腾讯云短信响应非 JSON: {e}"))?;
        if let Some(err) = v.pointer("/Response/Error") {
            return Err(format!(
                "腾讯云短信受理失败 Code={:?} Message={:?}",
                err.get("Code").and_then(|x| x.as_str()),
                err.get("Message").and_then(|x| x.as_str())
            ));
        }
        let first_code = v
            .pointer("/Response/SendStatusSet/0/Code")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if first_code == "Ok" {
            Ok(v.pointer("/Response/RequestId")
                .and_then(|x| x.as_str())
                .unwrap_or("no-request-id")
                .to_string())
        } else {
            Err(format!("腾讯云短信受理失败 SendStatus Code={first_code:?}"))
        }
    }
}

impl Default for TencentSmsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 本地 listener 用例专用客户端：显式 `.no_proxy()`。
    ///
    /// 环境若设置了 `HTTP_PROXY`/`HTTPS_PROXY`，reqwest 会把发往 `127.0.0.1` 的请求也交给
    /// 代理，导致本地 listener 连接失败（CI 无代理不暴露此坑）。生产构造 `::new()` 仍**尊重**
    /// 环境代理（企业出站可能需经代理），仅测试注入绕开。
    fn local_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest Client 构建不变量")
    }

    #[test]
    fn cloud_config_parse_fail_closed() {
        // 非 cloud 形态拒绝
        assert!(CloudSmsConfig::from_config_json(Some(r#"{"gateway_url":"http://x"}"#)).is_err());
        assert!(CloudSmsConfig::from_config_json(None).is_err());
        // aliyun 缺凭据拒绝
        assert!(
            CloudSmsConfig::from_config_json(Some(r#"{"provider":"aliyun"}"#)).is_err(),
            "缺 access_key_id/secret/sign_name 应 Err"
        );
        // tencent 缺 sdk_app_id 拒绝
        assert!(
            CloudSmsConfig::from_config_json(Some(
                r#"{"provider":"tencent","access_key_id":"a","access_key_secret":"b","sign_name":"s"}"#
            ))
            .is_err()
        );
        // aliyun 全量 OK + 官方端点缺省
        let c = CloudSmsConfig::from_config_json(Some(
            r#"{"provider":"aliyun","access_key_id":"a","access_key_secret":"b","sign_name":"s"}"#,
        ))
        .unwrap();
        assert_eq!(c.endpoint, "https://dysmsapi.aliyuncs.com");
        assert_eq!(c.kind, SmsProviderKind::Aliyun);
        // detect：无 provider 字段 = generic
        assert_eq!(
            detect_provider_kind(Some(r#"{"gateway_url":"http://x"}"#)),
            SmsProviderKind::Generic
        );
    }

    #[test]
    fn aliyun_pop_encode_rfc3986() {
        // 规范用例：空格→%20、+→%2B（字面加号）、*→%2A、~ 保留、中文 UTF-8 百分号
        assert_eq!(pop_encode("a b"), "a%20b");
        assert_eq!(pop_encode("a*b"), "a%2Ab");
        assert_eq!(pop_encode("a~b"), "a~b");
        assert_eq!(pop_encode("a+b"), "a%2Bb");
        assert_eq!(pop_encode("您好"), "%E6%82%A8%E5%A5%BD");
    }

    #[tokio::test]
    async fn aliyun_provider_signs_and_sends() {
        // 本地 TCP listener 模拟 Dysmsapi：收真实 form 请求 → 反向验签 → 断言参数
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("content-length:") {
                    content_length = line.split(':').nth(1).unwrap().trim().parse().unwrap();
                }
                if line.trim().is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; content_length];
            std::io::Read::read_exact(&mut reader, &mut body).unwrap();
            let body_str = String::from_utf8(body).unwrap();
            let body_json = r#"{"Code":"OK","BizId":"1001"}"#;
            let respond = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_json.len(),
                body_json
            );
            let mut w = stream;
            w.write_all(respond.as_bytes()).unwrap();
            (request_line, body_str)
        });

        let cfg = CloudSmsConfig::from_config_json(Some(&format!(
            r#"{{"provider":"aliyun","endpoint":"http://{addr}","access_key_id":"testAK","access_key_secret":"testSK","sign_name":"测试签名"}}"#
        )))
        .unwrap();
        let provider = AliyunSmsProvider {
            http: local_client(),
        };
        let biz = provider
            .send_templated(
                &cfg,
                "13800000000",
                "SMS_46512345",
                &serde_json::json!({"code": "1234"}),
            )
            .await
            .expect("阿里云发送应成功");
        assert_eq!(biz, "1001");

        let (request_line, body_str) = handle.join().unwrap();
        assert!(request_line.starts_with("POST "), "应为 POST");
        // 解析 form 参数
        let pairs: Vec<(String, String)> = body_str
            .split('&')
            .map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                (
                    k.to_string(),
                    percent_encoding::percent_decode_str(v)
                        .decode_utf8()
                        .unwrap()
                        .to_string(),
                )
            })
            .collect();
        let get = |k: &str| pairs.iter().find(|(pk, _)| pk == k).map(|(_, v)| v.clone());
        assert_eq!(get("Action").as_deref(), Some("SendSms"));
        assert_eq!(get("PhoneNumbers").as_deref(), Some("13800000000"));
        assert_eq!(get("TemplateCode").as_deref(), Some("SMS_46512345"));
        assert_eq!(get("SignName").as_deref(), Some("测试签名"));
        assert!(get("TemplateParam").unwrap().contains("1234"));
        let sig = get("Signature").expect("应携带签名");
        // 反向验签：剔除 Signature 后重算，须与请求携带一致
        let recompute: Vec<(String, String)> = pairs
            .iter()
            .filter(|(k, _)| k != "Signature")
            .cloned()
            .collect();
        assert_eq!(
            sig,
            AliyunSmsProvider::sign(&recompute, "testSK"),
            "签名必须与服务端重算一致（防签名实现漂移）"
        );
    }

    #[tokio::test]
    async fn tencent_provider_signs_and_sends() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut content_length = 0usize;
            let mut auth = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("content-length:") {
                    content_length = line.split(':').nth(1).unwrap().trim().parse().unwrap();
                }
                if lower.starts_with("authorization:") {
                    auth = line.trim().to_string();
                }
                if line.trim().is_empty() {
                    break;
                }
            }
            let mut body = vec![0u8; content_length];
            std::io::Read::read_exact(&mut reader, &mut body).unwrap();
            let body_str = String::from_utf8(body).unwrap();
            let body_json = r#"{"Response":{"RequestId":"req-1","SendStatusSet":[{"Code":"Ok","Message":"send success"}]}}"#;
            let respond = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_json.len(),
                body_json
            );
            let mut w = stream;
            w.write_all(respond.as_bytes()).unwrap();
            (request_line, auth, body_str)
        });

        let cfg = CloudSmsConfig::from_config_json(Some(&format!(
            r#"{{"provider":"tencent","endpoint":"http://{addr}","access_key_id":"AKIDtest","access_key_secret":"testSK","sign_name":"测试签名","sdk_app_id":"1400000001","region":"ap-shanghai"}}"#
        )))
        .unwrap();
        let provider = TencentSmsProvider {
            http: local_client(),
        };
        let req_id = provider
            .send_templated(
                &cfg,
                "13800000000",
                "2000123456",
                &serde_json::json!(["v1", "v2"]),
            )
            .await
            .expect("腾讯云发送应成功");
        assert_eq!(req_id, "req-1");

        let (request_line, auth, body_str) = handle.join().unwrap();
        assert!(request_line.starts_with("POST "), "应为 POST");
        // listener 抓的是整行请求头（含头名小写前缀），剥掉后断言值形态
        let auth_value = auth
            .split_once(':')
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or(auth.clone());
        assert!(
            auth_value.starts_with("TC3-HMAC-SHA256 "),
            "Authorization 应为 TC3 形态: {auth}"
        );
        assert!(
            auth_value.contains("Credential=AKIDtest/"),
            "Credential 应含 SecretId: {auth_value}"
        );
        assert!(
            auth_value.contains("SignedHeaders=content-type;host;x-tc-action"),
            "SignedHeaders 应含三头: {auth_value}"
        );
        let v: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(
            v["PhoneNumberSet"][0], "+8613800000000",
            "腾讯云号码需 +86 前缀"
        );
        assert_eq!(v["SmsSdkAppId"], "1400000001");
        assert_eq!(v["TemplateId"], "2000123456");
        assert_eq!(v["TemplateParamSet"][0], "v1");
    }

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
            let respond = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let mut w = stream;
            w.write_all(respond.as_bytes()).unwrap();
            (request_line.contains("POST"), has_auth, body_str)
        });

        let cfg = SmsChannelConfig::from_config_json(Some(&format!(
            r#"{{"gateway_url":"http://{addr}/send","auth_header":"X-Api-Key","auth_value":"secret-key","phone_field":"mobile","content_field":"text"}}"#
        )))
        .unwrap();
        let provider = GenericHttpProvider {
            http: local_client(),
        };
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
        let provider = GenericHttpProvider {
            http: local_client(),
        };
        let err = provider.send(&cfg, "138", "x").await.unwrap_err();
        assert!(err.contains("500"), "err={err}");
    }
}
