//! 邮件发送 Service 层
//!
//! 职责：
//! - 封装 lettre SMTP 客户端，提供同步/异步邮件发送能力
//! - 支持单发与批量发送（批量通过逐封发送实现，避免 SMTP 服务器单次连接配额限制）
//! - 配置未启用（mail.enabled=false）时优雅降级，返回 Ok 但不实际发送
//! - 集成 sys_notice：通知公告新增时可选择同步发送邮件给目标用户
//!
//! 安全要点：
//! - SMTP 密码通过 MAIL_PASSWORD 环境变量注入（settings.rs::from_file 覆盖）
//! - SMTP 连接使用 native-tls 加密（SSL 直连或 STARTTLS）
//! - 发送失败仅记录 tracing::warn!，不阻断主业务流程

use std::sync::Arc;

use futures::stream::{self, StreamExt};
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::common::error::ServiceError;
use crate::config::Settings;

/// HTML 邮件 Content-Type 常量
///
/// `ContentType::parse` 在常量字符串上理论恒成功，但解析失败会 panic。
/// 改为 `unwrap_or` 兜底，避免任何意外场景下 panic 中断服务。
fn html_content_type() -> ContentType {
    ContentType::parse("text/html; charset=utf-8").unwrap_or(ContentType::TEXT_HTML)
}

/// 邮件发送结果统计（批量发送时返回）
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MailBatchResult {
    /// 总数
    pub total: u32,
    /// 成功数
    pub success: u32,
    /// 失败数
    pub failed: u32,
    /// 失败的邮箱列表（供调用方记录日志）
    pub failed_emails: Vec<String>,
}

/// 邮件发送 Service
///
/// 包装 lettre AsyncSmtpTransport，提供单发与批量发送能力。
/// 配置未启用时（mail.enabled=false）所有方法直接返回 Ok，不实际发送。
pub struct MailerService {
    /// SMTP 传输客户端（enabled=false 时为 None）
    transporter: Option<AsyncSmtpTransport<Tokio1Executor>>,
    /// 发件人邮箱地址
    from_email: String,
    /// 发件人显示名称
    from_name: String,
    /// 是否启用
    enabled: bool,
}

impl MailerService {
    /// 根据配置构建 MailerService
    ///
    /// - enabled=false → 返回禁用实例（transporter=None）
    /// - enabled=true 且 host 为空 → 返回禁用实例并记录 warn
    /// - enabled=true 且 host 非空 → 构建 SMTP 客户端
    pub fn new(config: Arc<Settings>) -> Self {
        let mail_cfg = &config.mail;

        if !mail_cfg.enabled {
            return Self {
                transporter: None,
                from_email: mail_cfg.from_email.clone(),
                from_name: mail_cfg.from_name.clone(),
                enabled: false,
            };
        }

        if mail_cfg.host.is_empty() || mail_cfg.from_email.is_empty() {
            tracing::warn!(
                "邮件功能已启用但 host 或 from_email 为空，邮件发送将降级为禁用状态"
            );
            return Self {
                transporter: None,
                from_email: mail_cfg.from_email.clone(),
                from_name: mail_cfg.from_name.clone(),
                enabled: false,
            };
        }

        // 构建 SMTP 客户端
        let builder = if mail_cfg.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&mail_cfg.host)
                .map_err(|e| {
                    tracing::error!("构建 STARTTLS SMTP 客户端失败: {}", e);
                    e
                })
                .ok()
        } else {
            // SSL 直连（端口 465）
            AsyncSmtpTransport::<Tokio1Executor>::relay(&mail_cfg.host)
                .map_err(|e| {
                    tracing::error!("构建 SSL SMTP 客户端失败: {}", e);
                    e
                })
                .ok()
        };

        // AsyncSmtpTransportBuilder 的配置方法返回 self（move 语义），不能用 as_mut 链式调用
        // 通过函数式管道配置
        let builder = builder.map(|b| {
            let b = b.port(mail_cfg.port);
            if !mail_cfg.username.is_empty() {
                b.credentials(Credentials::new(
                    mail_cfg.username.clone(),
                    mail_cfg.password.clone(),
                ))
            } else {
                b
            }
        });

        // builder.build() 将 AsyncSmtpTransportBuilder 转为 AsyncSmtpTransport
        let transporter = builder.map(|b| b.build());

        Self {
            transporter,
            from_email: mail_cfg.from_email.clone(),
            from_name: mail_cfg.from_name.clone(),
            enabled: true,
        }
    }

    /// 是否启用邮件发送
    pub fn is_enabled(&self) -> bool {
        self.enabled && self.transporter.is_some()
    }

    /// 解析发件人 Mailbox
    ///
    /// 注：方法名以 `from_` 开头但需要读取 self 配置，故保留 self 借用，不遵循 `From` trait 命名约定。
    #[allow(clippy::wrong_self_convention)]
    fn from_mailbox(&self) -> Result<Mailbox, ServiceError> {
        let email = self
            .from_email
            .parse()
            .map_err(|_| ServiceError::internal(&crate::tr!("error.mail.from_invalid")))?;
        Ok(Mailbox::new(Some(self.from_name.clone()), email))
    }

    /// 发送单封邮件
    ///
    /// - `to_email`：收件人邮箱
    /// - `subject`：邮件主题
    /// - `html_body`：HTML 邮件正文
    ///
    /// 配置未启用时直接返回 Ok(())，不实际发送。
    pub async fn send(&self, to_email: &str, subject: &str, html_body: &str) -> Result<(), ServiceError> {
        if !self.is_enabled() {
            tracing::debug!("邮件功能未启用，跳过发送给 {}", to_email);
            return Ok(());
        }

        let to_mailbox: lettre::Address = to_email
            .parse()
            .map_err(|_| ServiceError::bad_request(&crate::tr!("error.mail.to_invalid")))?;

        let from_mailbox = self.from_mailbox()?;

        let email = Message::builder()
            .from(from_mailbox)
            .to(Mailbox::new(None, to_mailbox))
            .subject(subject)
            .header(html_content_type())
            .body(html_body.to_string())
            .map_err(|_| ServiceError::internal(&crate::tr!("error.mail.build_failed")))?;

        let transporter = self
            .transporter
            .as_ref()
            .ok_or_else(|| ServiceError::internal(&crate::tr!("error.mail.smtp_not_initialized")))?;

        // P1 修复：SMTP 发送加 10s 超时保护。原实现直接 await，SMTP 服务器
        // 无响应/网络黑洞时会无限挂起，拖住调用方请求（如公告创建链路）。
        tokio::time::timeout(
            crate::common::constants::MAIL_SEND_TIMEOUT,
            transporter.send(email),
        )
        .await
        .map_err(|_| {
            tracing::warn!("邮件发送超时（>10s）: to={}, subject={}", to_email, subject);
            ServiceError::internal(&crate::tr!("error.mail.send_timeout"))
        })?
        .map_err(|_| ServiceError::internal(&crate::tr!("error.mail.send_failed")))?;

        tracing::info!("邮件发送成功: to={}, subject={}", to_email, subject);
        Ok(())
    }

    /// 批量发送邮件
    ///
    /// 并行发送以提升吞吐（并发度 5，避免触发 SMTP 服务器并发连接限制），
    /// 单封失败不影响其他收件人。返回 MailBatchResult 包含成功/失败统计。
    pub async fn send_batch(
        &self,
        to_emails: &[String],
        subject: &str,
        html_body: &str,
    ) -> Result<MailBatchResult, ServiceError> {
        if !self.is_enabled() {
            tracing::debug!("邮件功能未启用，跳过批量发送（{} 封）", to_emails.len());
            return Ok(MailBatchResult {
                total: to_emails.len() as u32,
                success: 0,
                failed: 0,
                failed_emails: vec![],
            });
        }

        let total = to_emails.len() as u32;

        // 并行发送：buffer_unordered(5) 限制并发度为 5，避免 SMTP 服务器并发连接限制
        // 每个 future 持有独立的 MailerService 克隆（transporter 内部为 Arc，克隆廉价）
        let results: Vec<(String, Result<(), ServiceError>)> = stream::iter(to_emails.iter().cloned())
            .map(|email| {
                let svc = self.clone();
                let subject = subject.to_string();
                let html_body = html_body.to_string();
                async move {
                    let res = svc.send(&email, &subject, &html_body).await;
                    (email, res)
                }
            })
            .buffer_unordered(5)
            .collect()
            .await;

        let mut success = 0u32;
        let mut failed_emails = Vec::new();
        for (email, res) in results {
            match res {
                Ok(()) => success += 1,
                Err(e) => {
                    tracing::warn!("批量发送邮件失败 to={}: {}", email, e);
                    failed_emails.push(email);
                }
            }
        }

        let failed = total - success;
        tracing::info!(
            "批量邮件发送完成: total={}, success={}, failed={}",
            total,
            success,
            failed
        );

        Ok(MailBatchResult {
            total,
            success,
            failed,
            failed_emails,
        })
    }

    /// 发送纯文本邮件（HTML 转义后发送）
    pub async fn send_text(&self, to_email: &str, subject: &str, text: &str) -> Result<(), ServiceError> {
        // 简单转义 HTML 特殊字符
        let escaped = text
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\n', "<br/>");
        let html = format!("<div style=\"font-family: Arial, sans-serif; line-height: 1.6;\">{}</div>", escaped);
        self.send(to_email, subject, &html).await
    }
}

impl Clone for MailerService {
    fn clone(&self) -> Self {
        Self {
            // AsyncSmtpTransport 内部使用 Arc，可安全克隆
            transporter: self.transporter.clone(),
            from_email: self.from_email.clone(),
            from_name: self.from_name.clone(),
            enabled: self.enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构建一个禁用状态的 MailerService（不实际发送）
    fn disabled_service() -> MailerService {
        MailerService {
            transporter: None,
            from_email: "noreply@example.com".to_string(),
            from_name: "Yebot".to_string(),
            enabled: false,
        }
    }

    /// 构建一个「启用但指向黑洞地址」的 MailerService，用于触发发送超时
    ///
    /// 10.255.255.1 属 RFC6890 保留私网，本机不可达 → TCP SYN 被黑洞 →
    /// 连接挂起直至 MAIL_SEND_TIMEOUT（10s），用于验证 P1 超时保护（不挂死调用方）。
    fn unreachable_service() -> MailerService {
        let transporter = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("10.255.255.1")
            .port(25)
            .build();
        MailerService {
            transporter: Some(transporter),
            from_email: "noreply@example.com".to_string(),
            from_name: "Yebot".to_string(),
            enabled: true,
        }
    }

    #[test]
    fn test_disabled_service_is_not_enabled() {
        assert!(!disabled_service().is_enabled());
    }

    #[tokio::test]
    async fn test_send_disabled_is_noop_ok() {
        // 禁用状态下 send 必须成功返回（不实际发送、不报错、不 panic）
        let svc = disabled_service();
        let res = svc.send("user@example.com", "主题", "<p>内容</p>").await;
        assert!(
            res.is_ok(),
            "禁用邮件下 send 必须返回 Ok，实际: {:?}",
            res.err()
        );
    }

    #[tokio::test]
    async fn test_send_batch_disabled_returns_zeros() {
        let svc = disabled_service();
        let res = svc
            .send_batch(
                &["a@example.com".to_string(), "b@example.com".to_string()],
                "主题",
                "<p>内容</p>",
            )
            .await
            .unwrap();
        assert_eq!(res.total, 2);
        assert_eq!(res.success, 0);
        assert_eq!(res.failed, 0);
        assert!(res.failed_emails.is_empty());
    }

    #[tokio::test]
    async fn test_send_text_disabled_is_noop_ok() {
        let svc = disabled_service();
        let res = svc.send_text("user@example.com", "主题", "纯文本\n第二行").await;
        assert!(res.is_ok(), "禁用邮件下 send_text 必须返回 Ok");
    }

    #[tokio::test]
    async fn test_send_invalid_to_email_returns_bad_request() {
        // 启用状态下非法收件人地址必须在发送前返回 400（不触发网络）
        let svc = unreachable_service();
        let res = svc.send("not-an-email", "主题", "<p>内容</p>").await;
        assert!(res.is_err(), "非法收件人地址必须返回 Err");
        assert_eq!(res.unwrap_err().code, 400, "地址解析失败应返回 400");
    }

    #[tokio::test]
    async fn test_send_unreachable_smtp_times_out() {
        // P1 修复核心：慢/不可达 SMTP 必须在 MAIL_SEND_TIMEOUT 内返回 Err，而非无限挂起
        let svc = unreachable_service();
        assert!(svc.is_enabled(), "启用状态 is_enabled 必须为 true");
        let start = std::time::Instant::now();
        let res = svc.send("user@example.com", "主题", "<p>内容</p>").await;
        let elapsed = start.elapsed();
        assert!(
            res.is_err(),
            "不可达 SMTP 必须返回 Err（超时保护），实际: {:?}",
            res.ok()
        );
        // 不得超出超时上限过多（10s + 3s 余量），证明没有无限挂起
        assert!(
            elapsed < std::time::Duration::from_secs(13),
            "send 应在超时后快速返回，实际耗时 {:?}",
            elapsed
        );
    }
}
