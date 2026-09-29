// backend-axum/src/service/event_outbox_service.rs
//! 出站**领域事件**集成点（`[events]` 段）——**不是**内置消息队列。
//!
//! # 定位（项目准则⑥：原判"不进本仓"改为"提供集成点/开关"）
//!
//! 使用者对"事件驱动 / MQ / 数据同步"的诉求真实存在，但**不应**由本仓内置
//! Kafka / RabbitMQ / Redis Stream：那会把使用者锁死在单一技术栈上，而绝大多数
//! 中后台场景用不到真正的 MQ。故本模块只提供**出站事件契约**：
//!
//! - `outbound = "webhook"` 时，领域事件以 HTTP POST 推到使用者自己声明的地址；
//! - 接收端由使用者自己写（转发到 MQ / 发通知 / 灌数仓 / 归档审计）；
//! - 契约稳定：信封 `{ source, event, occurredAt, data }`，事件名见下方 `EVENT_*` 常量。
//!
//! # 关闭态即现状
//!
//! 默认 `off` ⇒ [`spawn_emit`] 在 **快速判定处直接返回**：不构造载荷、不建 HTTP 客户端、
//! 不 spawn 任务 ⇒ 一个字节都不发，与改造前逐字节等价。
//!
//! # 为什么 fire-and-forget
//!
//! 出站推送是**旁路**，不是业务事务的一部分：推送失败只打 WARN，**绝不影响**
//! 租户创建/启停/删除的返回结果。真实世界的数据对齐由使用者的全量对账脚本兜底。

use chrono::NaiveDateTime;

use crate::config::settings::EventsConfig;

/// 事件：租户创建成功（含平台代建）
pub const EVENT_TENANT_CREATED: &str = "tenant.created";
/// 事件：租户启停状态变更（`status` = '0' 正常 / '1' 停用）
pub const EVENT_TENANT_STATUS_CHANGED: &str = "tenant.status_changed";
/// 事件：租户被删除（进入回收站）
pub const EVENT_TENANT_DELETED: &str = "tenant.deleted";
/// 事件：租户从回收站恢复
pub const EVENT_TENANT_RESTORED: &str = "tenant.restored";

/// 本模块**当前已发布**的全部事件名（冻结契约；新增事件须同步此处与文档）。
pub const ALL_EVENTS: &[&str] = &[
    EVENT_TENANT_CREATED,
    EVENT_TENANT_STATUS_CHANGED,
    EVENT_TENANT_DELETED,
    EVENT_TENANT_RESTORED,
];

/// 载荷来源标识（接收端可据此区分多实例 / 多环境）。
pub const SOURCE: &str = "stepby";

/// 构造事件信封（**纯函数**，便于单测与契约冻结）。
///
/// 键名用 camelCase（与 `[acme]` 出站契约、前端口径一致）；
/// `event` 恒不省略、`data` 恒为对象（接收端无需判存在性）。
pub fn build_envelope(
    event: &str,
    data: serde_json::Value,
    occurred_at: NaiveDateTime,
) -> serde_json::Value {
    serde_json::json!({
        "source": SOURCE,
        "event": event,
        "occurredAt": occurred_at,
        "data": data,
    })
}

/// 推送领域事件（**fire-and-forget**）。
///
/// 同步函数、不返回错误：先做"是否配置了有效 webhook"的快速判定（`off` 时零开销），
/// 命中后 `spawn` 后台任务完成 HTTP 推送，失败只打 WARN。
/// 因此本函数**不可能**影响调用方的业务结果。
pub fn spawn_emit(cfg: EventsConfig, event: &'static str, data: serde_json::Value) {
    let Some(url) = cfg.effective_webhook().map(str::to_string) else {
        return; // off / 地址缺失或非法 ⇒ 不发任何请求（关闭态即现状）
    };
    let timeout = cfg.timeout();
    let secret = cfg.secret.clone();
    // 无 tokio 运行时（如单测 / 迁移进程）时静默跳过：此处不是错误路径，业务已成功
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::debug!(event, "无 tokio 运行时，跳过领域事件推送");
        return;
    };
    handle.spawn(async move {
        let body = build_envelope(event, data, crate::common::datetime::now_naive());
        let bytes = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(event, error = %e, "领域事件载荷序列化失败（跳过本次推送）");
                return;
            }
        };
        let client = match reqwest::Client::builder().timeout(timeout).build() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(event, error = %e, "领域事件推送 HTTP 客户端构建失败");
                return;
            }
        };
        // #10 出站熔断：`off`（默认）恒放行；`on` 且目标已打开 ⇒ 本次直接跳过（业务不受影响）
        if !crate::common::breaker::try_acquire(&url) {
            tracing::debug!(
                event,
                host = %crate::common::breaker::host_of(&url),
                "领域事件推送已被出站熔断跳过"
            );
            return;
        }
        let mut req = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("X-Stepby-Event", event)
            .body(bytes.clone());
        if let Some(secret) = secret.as_deref().filter(|s| !s.is_empty()) {
            req = req.header(
                "X-Stepby-Signature",
                format!(
                    "sha256={}",
                    crate::common::webhook::sign_hmac_sha256(secret, &bytes)
                ),
            );
        }
        let sent_ok = match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(event, "领域事件已推送");
                true
            }
            Ok(resp) => {
                tracing::warn!(
                    event,
                    status = %resp.status(),
                    "领域事件推送被拒（接收端非 2xx；业务不受影响）"
                );
                false
            }
            Err(e) => {
                tracing::warn!(event, error = %e, "领域事件推送失败（业务不受影响）");
                false
            }
        };
        crate::common::breaker::record(&url, sent_ok);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{EventsConfig, EventsOutboundMode};

    fn cfg(mode: &str, url: Option<&str>) -> EventsConfig {
        EventsConfig {
            outbound: mode.to_string(),
            webhook_url: url.map(str::to_string),
            secret: None,
            timeout_secs: 5,
        }
    }

    /// **关闭态即现状**：`off` ⇒ 有效目标为空（一个字节都不发）
    #[test]
    fn test_off_mode_has_no_target() {
        assert_eq!(
            cfg("off", Some("https://ops.example.com/events")).effective_webhook(),
            None
        );
        assert_eq!(cfg("off", None).effective_webhook(), None);
        assert_eq!(EventsOutboundMode::parse("off"), EventsOutboundMode::Off);
        // 非法取值回落 off（fail-safe）
        assert_eq!(EventsOutboundMode::parse("KAFKA!").as_str(), "off");
        assert_eq!(EventsOutboundMode::parse("").as_str(), "off");
    }

    /// `webhook` 模式：地址合法才生效；缺失/非 http(s) 一律视为未配置
    #[test]
    fn test_webhook_mode_requires_http_url() {
        assert_eq!(
            cfg("webhook", Some(" https://ops.example.com/events ")).effective_webhook(),
            Some("https://ops.example.com/events"),
            "两端空白应被裁剪"
        );
        for bad in ["file:///etc/passwd", "ftp://x/y", "ops.example.com", ""] {
            assert_eq!(
                cfg("webhook", Some(bad)).effective_webhook(),
                None,
                "{bad} 不是合法 http(s) 目标，必须视为未配置"
            );
        }
        assert_eq!(cfg("webhook", None).effective_webhook(), None);
        // 大小写不敏感
        assert_eq!(
            cfg("WebHook", Some("https://x/y")).effective_webhook(),
            Some("https://x/y")
        );
    }

    /// 超时夹取：0 不合法（会立即超时）⇒ 抬到 1s；过大 ⇒ 压到 60s
    #[test]
    fn test_timeout_is_clamped() {
        let mut c = cfg("webhook", Some("https://x/y"));
        c.timeout_secs = 0;
        assert_eq!(c.timeout().as_secs(), 1);
        c.timeout_secs = 9999;
        assert_eq!(c.timeout().as_secs(), 60);
        c.timeout_secs = 5;
        assert_eq!(c.timeout().as_secs(), 5);
    }

    /// 信封字段冻结：接收端按这些键名解析，改名即破坏契约
    #[test]
    fn test_envelope_contract() {
        let ts = chrono::NaiveDate::from_ymd_opt(2026, 9, 27)
            .unwrap()
            .and_hms_opt(10, 30, 0)
            .unwrap();
        let env = build_envelope(
            EVENT_TENANT_CREATED,
            serde_json::json!({ "tenantId": 42, "tenantCode": "acme" }),
            ts,
        );
        assert_eq!(env["source"], "stepby");
        assert_eq!(env["event"], "tenant.created");
        assert_eq!(env["occurredAt"], "2026-09-27T10:30:00");
        assert_eq!(env["data"]["tenantId"], 42);
        assert_eq!(env["data"]["tenantCode"], "acme");
        // data 恒为对象（即使空载荷也不省略键）
        let env2 = build_envelope(EVENT_TENANT_DELETED, serde_json::json!({}), ts);
        assert!(env2["data"].is_object());
        assert_eq!(env2["event"], "tenant.deleted");
    }

    /// 事件名清单冻结：删除/改名事件即破坏接收端契约
    #[test]
    fn test_event_names_are_frozen() {
        assert_eq!(
            ALL_EVENTS,
            &[
                "tenant.created",
                "tenant.status_changed",
                "tenant.deleted",
                "tenant.restored",
            ]
        );
    }

    /// `spawn_emit` 在关闭态 / 非法地址下**不产生**任何副作用（无 tokio 运行时也不 panic）
    #[test]
    fn test_spawn_emit_is_noop_when_off() {
        spawn_emit(
            cfg("off", Some("https://ops.example.com/events")),
            EVENT_TENANT_CREATED,
            serde_json::json!({ "tenantId": 1 }),
        );
        spawn_emit(
            cfg("webhook", Some("file:///tmp/x")),
            EVENT_TENANT_CREATED,
            serde_json::json!({ "tenantId": 1 }),
        );
    }
}
