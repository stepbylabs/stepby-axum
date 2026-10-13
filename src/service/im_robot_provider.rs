// stepby-axum/src/service/im_robot_provider.rs
//! IM 群机器人 Provider（企业微信 / 钉钉）——G-15b「小程序」的更优替代实现（批次十八）
//!
//! **归属判定**（audit 后记十五讨论定稿）：
//! - 不进 [`crate::service::sms_provider::SmsProvider`]——短信语义（phone+content）与
//!   群机器人（webhook POST JSON）不符；
//! - 不进 sys_web_hook——webhook 面向程序回调（自有事件 JSON 格式），机器人要求
//!   自有 `msgtype` 格式；
//! - 正确归宿 = **消息渠道**（sys_msg_channel `channel_type = wecom_robot / dingtalk_robot`）：
//!   模板渲染链（sys_msg_template + params）就绪，dispatch 分支把渲染后的 content
//!   组装为机器人 text 消息 POST；`errcode != 0` 视为投递失败（交由发送记录重试链）。
//!
//! 协议（均为真实 HTTP POST JSON）：
//! - 企业微信群机器人：`POST {webhookUrl}` body `{"msgtype":"text","text":{"content":...}}`
//!   → 响应 `{"errcode":0,"errmsg":"ok"}`；
//! - 钉钉自定义机器人：`POST {webhookUrl}` 同 body；配置 `secret` 时启用加签——
//!   `timestamp`（毫秒）+ `sign = urlencode(base64(hmac-sha256(secret, "{ts}\n{secret}")))`
//!   追加到 URL → 响应 `{"errcode":0}`。
//!
//! config_json（EncryptedString 加密列，读路径自动解密）：
//! `{"webhookUrl": "https://...", "secret": "SEC..."}`（secret 仅钉钉加签用，可选）。

use hmac::{Hmac, KeyInit, Mac};
use serde_json::json;
use sha2::Sha256;

/// IM 机器人渠道配置（从渠道 config_json 解析）
#[derive(Debug, Clone)]
pub struct ImRobotConfig {
    /// 机器人 webhook 地址（企微/钉钉后台生成，含 key/access_token）
    pub webhook_url: String,
    /// 钉钉加签密钥（可选；仅 dingtalk_robot 使用）
    pub secret: Option<String>,
}

impl ImRobotConfig {
    /// 从渠道 config_json（明文，读路径已自动解密）解析；严格校验，缺失即 Err
    pub fn from_config_json(raw: Option<&str>) -> Result<Self, String> {
        let raw = raw
            .filter(|s| !s.trim().is_empty())
            .ok_or("IM 机器人渠道未配置 config_json")?;
        let v: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("config_json 不是合法 JSON: {e}"))?;
        let webhook_url = v
            .get("webhookUrl")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or("config_json 缺少 webhookUrl")?;
        if !webhook_url.starts_with("http://") && !webhook_url.starts_with("https://") {
            return Err(format!("webhookUrl 必须为 http(s) URL: {webhook_url}"));
        }
        let secret = v
            .get("secret")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Ok(Self {
            webhook_url,
            secret,
        })
    }
}

/// 组装机器人 text 消息体（企微/钉钉 text 格式一致）
pub fn build_robot_body(content: &str) -> serde_json::Value {
    json!({ "msgtype": "text", "text": { "content": content } })
}

/// percent-encode base64 中的 URL 保留字符（钉钉要求 sign 做 urlEncode；
/// 手写最小实现——与 sms_provider 的 pop_encode 同风格，避免引入额外依赖）
fn encode_base64_for_url(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'+' => out.push_str("%2B"),
            b'/' => out.push_str("%2F"),
            b'=' => out.push_str("%3D"),
            _ => out.push(b as char),
        }
    }
    out
}

/// 钉钉加签 URL：`{webhookUrl}&timestamp={ms}&sign={urlencode(base64(hmac-sha256(secret, "{ts}\n{secret}")))}`
///
/// webhookUrl 已含 `access_token=...` 查询参数，故追加用 `&`。
pub fn dingtalk_signed_url(webhook_url: &str, secret: &str, timestamp_ms: u64) -> String {
    let string_to_sign = format!("{timestamp_ms}\n{secret}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC 接受任意长度 key，不变量不可能失败");
    mac.update(string_to_sign.as_bytes());
    use base64::Engine as _;
    let sign = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    format!(
        "{webhook_url}&timestamp={timestamp_ms}&sign={}",
        encode_base64_for_url(&sign)
    )
}

/// 解析机器人响应 errcode（0 = 成功）
fn parse_errcode(body: &str) -> Result<(), String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        format!(
            "机器人响应不是合法 JSON: {e}（前 120 字节: {}）",
            body.chars().take(120).collect::<String>()
        )
    })?;
    let code = v.get("errcode").and_then(|x| x.as_i64()).ok_or_else(|| {
        format!(
            "机器人响应缺少 errcode 字段（前 120 字节: {}）",
            body.chars().take(120).collect::<String>()
        )
    })?;
    if code == 0 {
        Ok(())
    } else {
        let errmsg = v
            .get("errmsg")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        Err(format!("机器人返回 errcode={code}: {errmsg}"))
    }
}

/// 企业微信群机器人 Provider
pub struct WeComRobotProvider {
    http: reqwest::Client,
}

impl Default for WeComRobotProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl WeComRobotProvider {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest Client 构建不变量（合法 builder 参数）"),
        }
    }

    /// 投递 text 消息。成功 Ok(())；HTTP 失败 / errcode != 0 均 Err（交由重试链）
    pub async fn send(&self, cfg: &ImRobotConfig, content: &str) -> Result<(), String> {
        let resp = self
            .http
            .post(&cfg.webhook_url)
            .json(&build_robot_body(content))
            .send()
            .await
            .map_err(|e| format!("企微机器人请求失败: {e}"))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "企微机器人 HTTP {status}（前 120 字节: {}）",
                body.chars().take(120).collect::<String>()
            ));
        }
        parse_errcode(&body)
    }
}

/// 钉钉自定义机器人 Provider
pub struct DingTalkRobotProvider {
    http: reqwest::Client,
}

impl Default for DingTalkRobotProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DingTalkRobotProvider {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest Client 构建不变量（合法 builder 参数）"),
        }
    }

    /// 投递 text 消息。配置 secret 时启用加签 URL。
    pub async fn send(&self, cfg: &ImRobotConfig, content: &str) -> Result<(), String> {
        let url = match &cfg.secret {
            Some(secret) => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                dingtalk_signed_url(&cfg.webhook_url, secret, ts)
            }
            None => cfg.webhook_url.clone(),
        };
        let resp = self
            .http
            .post(url)
            .json(&build_robot_body(content))
            .send()
            .await
            .map_err(|e| format!("钉钉机器人请求失败: {e}"))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!(
                "钉钉机器人 HTTP {status}（前 120 字节: {}）",
                body.chars().take(120).collect::<String>()
            ));
        }
        parse_errcode(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 本地 listener 用例专用客户端：显式 `.no_proxy()`。
    ///
    /// 环境若设置了 `HTTP_PROXY`/`HTTPS_PROXY`（企业代理 / 本机调试代理），reqwest 会把
    /// 发往 `127.0.0.1` 的请求也交给代理，导致本地 listener 连接失败（CI 无代理不暴露此坑）。
    /// 生产构造 `::new()` 仍**尊重**环境代理（企业出站可能需经代理），仅测试注入绕开。
    fn local_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("reqwest Client 构建不变量")
    }

    // ---------- 纯函数 ----------

    #[test]
    fn test_build_robot_body_shape() {
        let body = build_robot_body("审批待办：请处理单据 X");
        assert_eq!(body["msgtype"], "text");
        assert_eq!(body["text"]["content"], "审批待办：请处理单据 X");
    }

    #[test]
    fn test_dingtalk_signed_url_deterministic_and_encoded() {
        let url = dingtalk_signed_url(
            "https://oapi.dingtalk.com/robot/send?access_token=ABC",
            "SEC7d9cf6",
            1_791_500_000_000,
        );
        // 确定性：同参重算一致
        let again = dingtalk_signed_url(
            "https://oapi.dingtalk.com/robot/send?access_token=ABC",
            "SEC7d9cf6",
            1_791_500_000_000,
        );
        assert_eq!(url, again);
        // 形状：timestamp + sign 追加；base64 保留字符被 percent-encode
        assert!(url.starts_with(
            "https://oapi.dingtalk.com/robot/send?access_token=ABC&timestamp=1791500000000&sign="
        ));
        let sign = url.split("sign=").nth(1).unwrap();
        assert!(!sign.contains('+') && !sign.contains('/') && !sign.contains('='));
        // 秘钥变化 → 签名变化
        let other = dingtalk_signed_url(
            "https://oapi.dingtalk.com/robot/send?access_token=ABC",
            "SEC-other",
            1_791_500_000_000,
        );
        assert_ne!(url, other);
    }

    #[test]
    fn test_im_robot_config_parse() {
        // 缺 config_json
        assert!(ImRobotConfig::from_config_json(None).is_err());
        // 缺 webhookUrl
        assert!(ImRobotConfig::from_config_json(Some(r#"{"secret":"SEC"}"#)).is_err());
        // 非 http(s)
        assert!(ImRobotConfig::from_config_json(Some(r#"{"webhookUrl":"ftp://x"}"#)).is_err());
        // 合法（无 secret）
        let cfg = ImRobotConfig::from_config_json(Some(
            r#"{"webhookUrl":"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=K1"}"#,
        ))
        .unwrap();
        assert!(cfg.secret.is_none());
        // 合法（带 secret）
        let cfg = ImRobotConfig::from_config_json(Some(r#"{"webhookUrl":"https://oapi.dingtalk.com/robot/send?access_token=T1","secret":"SEC1"}"#)).unwrap();
        assert_eq!(cfg.secret.as_deref(), Some("SEC1"));
    }

    // ---------- 本地网关真实投递 ----------

    #[tokio::test]
    async fn wecom_robot_posts_text_and_checks_errcode() {
        // 本地 TCP listener 模拟企微机器人：收真实 POST JSON → 断言 msgtype/content → 返回 errcode=0
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
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
            let respond_body = r#"{"errcode":0,"errmsg":"ok"}"#;
            let respond = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                respond_body.len(),
                respond_body
            );
            let mut w = stream;
            w.write_all(respond.as_bytes()).unwrap();
            String::from_utf8(body).unwrap()
        });

        let cfg = ImRobotConfig::from_config_json(Some(&format!(
            r#"{{"webhookUrl":"http://{addr}/cgi-bin/webhook/send?key=K1"}}"#
        )))
        .unwrap();
        WeComRobotProvider {
            http: local_client(),
        }
        .send(&cfg, "审批待办：e2e")
        .await
        .expect("企微机器人投递应成功");

        let body_str = handle.join().unwrap();
        let body_json: serde_json::Value = serde_json::from_str(&body_str).unwrap();
        assert_eq!(body_json["msgtype"], "text");
        assert_eq!(body_json["text"]["content"], "审批待办：e2e");
    }

    #[tokio::test]
    async fn wecom_robot_errcode_nonzero_is_err() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
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
            let body = r#"{"errcode":94000,"errmsg":"invalid webhook url"}"#;
            let respond = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let mut w = stream;
            w.write_all(respond.as_bytes()).unwrap();
        });

        let cfg = ImRobotConfig::from_config_json(Some(&format!(
            r#"{{"webhookUrl":"http://{addr}/cgi-bin/webhook/send?key=BAD"}}"#
        )))
        .unwrap();
        let err = WeComRobotProvider {
            http: local_client(),
        }
        .send(&cfg, "x")
        .await
        .expect_err("errcode!=0 应 Err");
        assert!(err.contains("94000"), "应携带 errcode: {err}");
        drop(handle);
    }

    #[tokio::test]
    async fn dingtalk_robot_signs_url_when_secret_configured() {
        // 本地 listener：断言请求行含 timestamp 与 sign（加签生效）
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
            }
            let body = r#"{"errcode":0,"errmsg":"ok"}"#;
            let respond = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let mut w = stream;
            w.write_all(respond.as_bytes()).unwrap();
            request_line
        });

        let cfg = ImRobotConfig::from_config_json(Some(&format!(
            r#"{{"webhookUrl":"http://{addr}/robot/send?access_token=T1","secret":"SEC-TEST"}}"#
        )))
        .unwrap();
        DingTalkRobotProvider {
            http: local_client(),
        }
        .send(&cfg, "钉钉待办")
        .await
        .expect("钉钉加签投递应成功");

        let request_line = handle.join().unwrap();
        assert!(
            request_line.contains("timestamp="),
            "应含 timestamp: {request_line}"
        );
        assert!(request_line.contains("sign="), "应含 sign: {request_line}");
    }
}
