//! 邮件发送 Service 层
//!
//! 职责：
//! - 封装 lettre SMTP 客户端，提供同步/异步邮件发送能力
//! - 支持单发与批量发送（批量通过逐封发送实现，避免 SMTP 服务器单次连接配额限制）
//! - 配置未启用（`mail.enabled=false`）时优雅降级，返回 Ok 但不实际发送；
//!   **已启用却不可用**（`MailAvailability::Broken`）返回 Err，不伪装成已发送（b144）
//! - 集成 sys_notice：通知公告新增时可选择同步发送邮件给目标用户
//!
//! 安全要点：
//! - SMTP 密码通过 MAIL_PASSWORD 环境变量注入（settings.rs::from_file 覆盖）
//! - SMTP 连接使用 **rustls**（`Cargo.toml` 的 `lettre = { features = ["tokio1-rustls-tls"] }`）；
//!   本行原写"native-tls"，与本仓"rustls / 无原生 OpenSSL"的构建姿态（AGENTS D.12）矛盾，
//!   且与 Cargo 事实相反——注释不得替代依赖声明（b144 订正）。
//! - 发送失败的**可观测口径**：真实 SMTP 错误进 WARN（不含收件地址），指标按 outcome
//!   分类；日志与审计一律经 `utils::masking::log_mask_email`（邮箱属 PII，C.9）。

use std::sync::Arc;

use futures::stream::{self, StreamExt};
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::common::error::ServiceError;
use crate::config::Settings;

/// 批量投递的并发度。
///
/// 取 5 的理由：常见 SMTP 服务端对单连接账号的并发会话数限制在 2~10，5 是不触发
/// 421/450 "too many connections" 的安全中位。
///
/// **这个数是别处的算式输入**，不是纯实现细节：`sys_notice_service::NOTICE_EMAIL_BUDGET`
/// 的"最坏情况能容多少封"由 `预算 / MAIL_SEND_TIMEOUT × 本并发度` 得出，并由该模块的
/// 编译期断言钳住。写回字面量 `5` 会让那条容量式与真实并发脱钩（AGENTS 单一事实源）。
pub const MAIL_BATCH_CONCURRENCY: usize = 5;

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

/// 邮件通道的**可用性三态**（b144）。
///
/// 立项：此前 `enabled = true` 但 SMTP 客户端构建失败时，`transporter = None`
/// 使 `is_enabled()` 为 `false`，于是 `send/send_text` 走"未启用"分支返回 `Ok(())`——
/// 报表订阅据此把 `emails_sent += 1` 并推进 `last_run_time`，公告群发静默跳过，
/// 而 `/health` 的邮件探针同时报"未启用"。**同一个事实有两个相反的结论**，
/// 且运维看到的是"没配"，实际是"配了但坏了"。三态把这两件事分开，
/// 每个消费点必须显式选择结局（合法跳过 / 留痕 / 报错），不得再由布尔值代答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailAvailability {
    /// 未启用（`mail.enabled=false`，或 host / from_email 缺失）：合法关闭态，
    /// 调用方按"不发信"处理，行为与改造前逐字节等价。
    Off,
    /// 已就绪。
    Ready,
    /// **配置声明要发信，但客户端构建失败**：这是故障不是关闭。
    /// 发送类调用必须返回 Err，探针必须报 Down。
    Broken,
}

/// 邮件发送 Service
///
/// 包装 lettre AsyncSmtpTransport，提供单发与批量发送能力。
/// 配置未启用时（mail.enabled=false）所有方法直接返回 Ok，不实际发送；
/// **构建失败**（`MailAvailability::Broken`）一律返回 Err——见 [`MailAvailability`]。
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
    /// - `enabled=false` → 禁用实例（`MailAvailability::Off`，合法关闭态）
    /// - `enabled=true` 但 host / from_email 缺失 → **`Broken`**（不是 Off：运维已声明要发信）
    /// - `enabled=true` 且 `relay()` 拒绝该主机 → **`Broken`**，并落 ERROR 日志
    ///   （`build()` 在本版本 lettre 不可失败，构建失败只有这一条出口）
    /// - `enabled=true` 且构建成功 → `Ready`
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
                "邮件功能已启用但 host 或 from_email 为空，SMTP 客户端未构建；\
                 发信将按失败上报（MailAvailability::Broken），不再伪装成\"未启用\""
            );
            // b144：这里刻意保留 `enabled: true`——可用性由 (enabled, transporter) 派生，
            // "配置说要用" 与 "配置说不要用" 必须是两种结局，否则订阅/群发会把
            // 一封没发出去的邮件记成"已发送"并推进执行时间。
            return Self {
                transporter: None,
                from_email: mail_cfg.from_email.clone(),
                from_name: mail_cfg.from_name.clone(),
                enabled: true,
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

        // builder.build() 将 AsyncSmtpTransportBuilder 转为 AsyncSmtpTransport。
        // ⚠ 本版本（lettre 0.11）的 `build()` **不可失败**（返回 Transport 而非 Result，
        // 由编译器证伪——原审计报告里"`builder.map(|b| b.build())` 吞掉了 build 的 Err"
        // 这一条不成立，见台账 b144 取证订正）。因此唯一的构建失败出口是上面
        // `relay()` / `starttls_relay()` 返回 Err，那里已就地落 ERROR。
        let transporter = builder.map(|b| b.build());
        if transporter.is_none() {
            tracing::error!(
                "邮件已启用（mail.enabled=true）但 SMTP 客户端不可用；\
                 报表订阅与消息渠道会返回 503，公告群发会留 WARN 后跳过"
            );
        }

        Self {
            transporter,
            from_email: mail_cfg.from_email.clone(),
            from_name: mail_cfg.from_name.clone(),
            enabled: true,
        }
    }

    /// 是否启用邮件发送
    ///
    /// 语义 = "`Ready`"，即"现在真的能发"。
    /// **不要用布尔判断"为什么不能发"**——那是 [`Self::availability`] 的职责，
    /// 把 Off 与 Broken 折成一个 `false` 正是 b144 立案的形状。
    pub fn is_enabled(&self) -> bool {
        self.availability() == MailAvailability::Ready
    }

    /// 可用性三态：由 `(enabled, transporter)` 派生，不设第三个字段（两处事实必漂）。
    pub fn availability(&self) -> MailAvailability {
        if !self.enabled {
            MailAvailability::Off
        } else if self.transporter.is_some() {
            MailAvailability::Ready
        } else {
            MailAvailability::Broken
        }
    }

    /// 发送类调用的**共用闸门**（单份实现；三处各写一遍必漂）。
    ///
    /// - `Ok(true)`  → `Ready`，调用方继续发送
    /// - `Ok(false)` → `Off`（`mail.enabled=false`），调用方按"未启用"跳过并返回成功
    ///   （默认值 = 现状 = 关闭态零行为变化）
    /// - `Err`       → `Broken`：配置声明要发信却发不出去，**不得**伪装成跳过。
    ///   取 503 与 `From<DbErr>::ConnectionAcquire` 同口径（服务态问题，非调用方参数错）。
    fn send_gate(&self) -> Result<bool, ServiceError> {
        match self.availability() {
            MailAvailability::Ready => Ok(true),
            MailAvailability::Off => Ok(false),
            MailAvailability::Broken => {
                tracing::error!(
                    "邮件已启用但 SMTP 客户端不可用，本次发送按失败返回（不伪装成已发送）"
                );
                Err(ServiceError::new(
                    503,
                    crate::tr!("error.mail.transport_unavailable"),
                ))
            }
        }
    }

    /// 外部依赖探活（AGENTS #5，`/health` 聚合用）：**只握手、不发信**。
    ///
    /// `lettre` 的 `test_connection` 建立连接、读取服务欢迎语后即结束，**不投递任何
    /// 邮件、不需要收件人**，因此可以被周期探针反复调用而无副作用（对比 `send` 会真的
    /// 发信）。超时由调用方统一施加（见 `handler::health_probes`）。
    ///
    /// 错误文本可能含 SMTP 主机名（运维需要），但 lettre 不会回显凭据；调用方仍会过
    /// 一遍脱敏（[`crate::handler::health_probes::sanitize_detail`]）作为纵深防御。
    pub async fn probe(&self) -> Result<(), ServiceError> {
        let Some(transport) = &self.transporter else {
            // b144：这句文案此前无条件写"mail.enabled=false 或 host/from_email 缺失"，
            // 对"已启用但构建失败"是**假话**——探针会把配置故障说成没配置，
            // 运维照着提示去开开关，而开关本来就是开的。现在按三态给不同原因。
            let reason = match self.availability() {
                MailAvailability::Off => "邮件未启用（mail.enabled=false）",
                MailAvailability::Broken => {
                    "邮件已启用但 SMTP 客户端不可用（host/from_email 缺失或构建失败）"
                }
                MailAvailability::Ready => "SMTP 客户端不可用（状态自相矛盾，请检查构造路径）",
            };
            return Err(ServiceError::internal(reason));
        };
        transport
            .test_connection()
            .await
            .map_err(|e| ServiceError::internal(&format!("SMTP 握手失败: {e}")))?;
        Ok(())
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
    pub async fn send(
        &self,
        to_email: &str,
        subject: &str,
        html_body: &str,
    ) -> Result<(), ServiceError> {
        if !self.send_gate()? {
            tracing::debug!(
                "邮件功能未启用，跳过发送给 {}",
                crate::utils::masking::log_mask_email(to_email)
            );
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

        let transporter = self.transporter.as_ref().ok_or_else(|| {
            ServiceError::internal(&crate::tr!("error.mail.smtp_not_initialized"))
        })?;

        // P1 修复：SMTP 发送加 10s 超时保护。原实现直接 await，SMTP 服务器
        // 无响应/网络黑洞时会无限挂起，拖住调用方请求（如公告创建链路）。
        //
        // b72（AGENTS #4/#9）：改为 match 以区分 timeout 与协议错误两种结局——
        // ① 组件指标按 outcome 分类（`component="mail"`），使 SMTP 故障可与"邮件功能关闭"区分；
        // ② 原实现 `map_err(|_| …)` 把 SMTP 的**真实错误**整体丢弃，运维只能看到"发送失败"，
        //    现在把错误源打进 WARN（**只打错误文本，不打收件地址**——邮箱属 PII，沿用既有脱敏口径）。
        let started = std::time::Instant::now();
        let outcome = match tokio::time::timeout(
            crate::common::constants::MAIL_SEND_TIMEOUT,
            transporter.send(email),
        )
        .await
        {
            Err(_) => {
                crate::observability::metrics::MetricsRegistry::global().record_outbound(
                    "mail",
                    "timeout",
                    started.elapsed().as_secs_f64(),
                );
                tracing::warn!("邮件发送超时（>10s）: subject={subject}");
                return Err(ServiceError::internal(&crate::tr!(
                    "error.mail.send_timeout"
                )));
            }
            Ok(Err(e)) => {
                crate::observability::metrics::MetricsRegistry::global().record_outbound(
                    "mail",
                    "error",
                    started.elapsed().as_secs_f64(),
                );
                tracing::warn!("SMTP 投递失败: {e}（subject={subject}）");
                return Err(ServiceError::internal(&crate::tr!(
                    "error.mail.send_failed"
                )));
            }
            Ok(Ok(_resp)) => "ok",
        };
        crate::observability::metrics::MetricsRegistry::global().record_outbound(
            "mail",
            outcome,
            started.elapsed().as_secs_f64(),
        );

        // b144：本函数上方第 ② 条注释明确写"只打错误文本，不打收件地址（邮箱属 PII）",
        // 而这一行成功日志却把地址原样打出来——同一条口径在同一函数里自相矛盾。
        // C.9 的判据是"未认证者能从中推断什么"，日志对运维可见但对不上审计脱敏面，
        // 一律走 utils::masking::log_mask_email（与 oper_log 同一份实现）。
        tracing::info!(
            "邮件发送成功: to={}, subject={}",
            crate::utils::masking::log_mask_email(to_email),
            subject
        );
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
        if !self.send_gate()? {
            tracing::debug!("邮件功能未启用，跳过批量发送（{} 封）", to_emails.len());
            return Ok(MailBatchResult {
                total: to_emails.len() as u32,
                success: 0,
                failed: 0,
                failed_emails: vec![],
            });
        }

        let total = to_emails.len() as u32;

        // 并行发送：buffer_unordered 限制并发度（见 `MAIL_BATCH_CONCURRENCY`），避免 SMTP
        // 服务器并发连接限制。每个 future 持有独立的 MailerService 克隆（transporter 内部
        // 为 Arc，克隆廉价）
        let results: Vec<(String, Result<(), ServiceError>)> =
            stream::iter(to_emails.iter().cloned())
                .map(|email| {
                    let svc = self.clone();
                    let subject = subject.to_string();
                    let html_body = html_body.to_string();
                    async move {
                        let res = svc.send(&email, &subject, &html_body).await;
                        (email, res)
                    }
                })
                .buffer_unordered(MAIL_BATCH_CONCURRENCY)
                .collect()
                .await;

        let mut success = 0u32;
        let mut failed_emails = Vec::new();
        for (email, res) in results {
            match res {
                Ok(()) => success += 1,
                Err(e) => {
                    // 收件地址不进日志：本文件单封路径早就定了这个口径（"只打错误文本，
                    // 不打收件地址——邮箱属 PII，沿用既有脱敏口径"），批量路径此前漏了一层，
                    // 一封公告群发失败会在日志里留下整串个人邮箱。失败清单仍然**返回给调用方**
                    // （`failed_emails`），可见性没有丢，只是不再经由日志这条旁路外泄。
                    tracing::warn!("批量发送邮件失败: {}", e);
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
    pub async fn send_text(
        &self,
        to_email: &str,
        subject: &str,
        text: &str,
    ) -> Result<(), ServiceError> {
        // 简单转义 HTML 特殊字符
        let escaped = text
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\n', "<br/>");
        let html = format!(
            "<div style=\"font-family: Arial, sans-serif; line-height: 1.6;\">{}</div>",
            escaped
        );
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
            from_name: "Stepby".to_string(),
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
            from_name: "Stepby".to_string(),
            enabled: true,
        }
    }

    #[test]
    fn test_disabled_service_is_not_enabled() {
        assert!(!disabled_service().is_enabled());
    }

    /// 构造「已声明启用、但 SMTP 客户端不可用」的实例——即 `mail.enabled=true`
    /// 而 host 为空 / `relay()` 或 `build()` 失败的运行时形状。
    fn broken_service() -> MailerService {
        MailerService {
            transporter: None,
            from_email: "noreply@example.com".to_string(),
            from_name: "Stepby".to_string(),
            enabled: true,
        }
    }

    /// **三态必须把"没开"与"开了但坏了"分开**（b144 立案的核心判据）。
    ///
    /// 改造前两者都折成 `is_enabled() == false` ⇒ 发送返回 `Ok(())`，
    /// 报表订阅于是把一封没发出去的邮件记成"已发送"并推进 `last_run_time`。
    #[test]
    fn availability_separates_off_from_broken() {
        assert_eq!(disabled_service().availability(), MailAvailability::Off);
        assert_eq!(broken_service().availability(), MailAvailability::Broken);
        assert_eq!(
            unreachable_service().availability(),
            MailAvailability::Ready
        );
        // 布尔语义保持不变（既有调用方不受影响）
        assert!(!broken_service().is_enabled());
        assert!(!disabled_service().is_enabled());
    }

    /// 故障必须返回 Err（503），合法关闭照旧返回 Ok——两支是**相反**的期望，
    /// 只测一支就等于把"永远跳过"也当修好了。
    #[tokio::test]
    async fn broken_transport_is_an_error_not_a_silent_success() {
        let svc = broken_service();
        let err = svc
            .send("user@example.com", "主题", "<p>内容</p>")
            .await
            .expect_err("SMTP 客户端不可用时 send 必须返回 Err，不得伪装成已发送");
        assert_eq!(err.code, 503, "实际码值 {}", err.code);
        assert!(
            !err.message.contains("error."),
            "必须是可读文案而非裸 i18n 键，实际: {}",
            err.message
        );
        // send_text / send_batch 共用同一闸门
        let err2 = svc
            .send_text("user@example.com", "主题", "正文")
            .await
            .expect_err("send_text 同样不得静默成功");
        assert_eq!(err2.code, 503);
        let batch = svc
            .send_batch(
                &["a@example.com".to_string(), "b@example.com".to_string()],
                "主题",
                "<p>x</p>",
            )
            .await
            .expect_err("批量发送同样必须上抛");
        let _ = batch;
    }

    /// 探活的文案必须说清是哪一种，否则运维按"没配"去开一个本来就开的开关。
    #[tokio::test]
    async fn probe_reasons_distinguish_off_from_broken() {
        let off = disabled_service().probe().await.unwrap_err().message;
        let broken = broken_service().probe().await.unwrap_err().message;
        assert!(off.contains("未启用"), "Off 文案: {off}");
        assert!(
            !off.contains("不可用"),
            "Off 不得被说成客户端坏了（两种成因对应两个动作）"
        );
        assert!(broken.contains("不可用"), "Broken 文案: {broken}");
    }

    /// **单一事实源形状锁**：可用性只能由 `(enabled, transporter)` 派生。
    ///
    /// 立此案是因为"加第三个 bool 字段"是这一族的常见走偏：三处状态两处写，
    /// 新构造点漏赋值就是静默错判（编译器不会管）。
    #[test]
    fn availability_is_derived_not_a_stored_flag() {
        let text = crate::common::prod_scan::prod_file(
            "src/service/mailer_service.rs",
            &crate::common::prod_scan::Scan::default(),
        )
        .text();
        let body = fn_body(&text, "pub fn availability(").expect("availability 必须存在");
        assert!(body.contains("self.enabled"), "必须读 enabled");
        assert!(
            body.contains("self.transporter.is_some()"),
            "必须读 transporter"
        );
        // 结构体字段集合不得扩（三态靠派生，不靠新字段）
        let struct_body = fn_body(&text, "pub struct MailerService {")
            .or_else(|| {
                text.split("pub struct MailerService {")
                    .nth(1)
                    .map(|s| s.to_string())
            })
            .expect("MailerService 定义必须存在");
        let fields = struct_body.split('}').next().unwrap_or_default();
        assert_eq!(
            fields.matches(':').count(),
            4,
            "字段集合必须仍是 transporter/from_email/from_name/enabled 四个，实际:\n{fields}"
        );
        // 活性正控：闸门只有一处实现，且**每个**发送入口都接上了它
        // （三处各写 match 必漂；"闸门存在但某个入口没接"是同一族的另一半）。
        assert_eq!(text.matches("fn send_gate(").count(), 1);
        assert_eq!(
            text.matches("self.send_gate()?").count(),
            2,
            "send 与 send_batch 两个入口都必须走闸门，实际命中 {}",
            text.matches("self.send_gate()?").count()
        );
        assert_eq!(
            text.matches("if !self.is_enabled()").count(),
            0,
            "旧的布尔闸门形状必须绝迹（读生产视图，本测试自己的夹具不算）"
        );
        // 上面三条的正控：缺陷形状确实会被抓到
        let defective = "pub async fn send(&self) { if !self.is_enabled() { return Ok(()); } }";
        assert_eq!(defective.matches("if !self.is_enabled()").count(), 1);
        assert_eq!(defective.matches("self.send_gate()?").count(), 0);
    }

    /// 从 `needle` 处取到该顶层条目结束的函数体（按花括号配平，够用且可证伪）。
    fn fn_body(text: &str, needle: &str) -> Option<String> {
        let start = text.find(needle)?;
        let open = text[start..].find('{')? + start;
        let mut depth = 0usize;
        let bytes = text.as_bytes();
        let mut i = open;
        while i < bytes.len() {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(text[open..=i].to_string());
                    }
                }
                _ => {}
            }
            i += 1;
        }
        None
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
        let res = svc
            .send_text("user@example.com", "主题", "纯文本\n第二行")
            .await;
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
