// axum-backend/src/service/acme_service.rs
//! ACME 证书需求**输出**服务（`[acme]` 段）——集成点，**不是**内置签发器。
//!
//! # 定位
//!
//! 本项目是**开源的中后台管理系统**，定位「大而全」：能力要齐备，让使用者自己选择或配置。
//! 但"证书签发"这件事**属网关职责**（NGINX+certbot / Caddy / Traefik / 云 LB 各有成熟方案），
//! 内置一套只会把用户锁死在单一栈上。按项目准则⑥（原判"不进本仓"的项改为**提供集成点/开关**），
//! 本模块只提供**输出契约**：
//!
//! - 域名集合发生**状态迁移**时推送事件——
//!   - 域名 DNS TXT 验证**首次通过**（`verify_status 0/2 → '1'`）⇒ `cert.issue`（需要签发）；
//!   - **已验证**域名被删除 ⇒ `cert.remove`（需要吊销/清理）；
//! - 接收端是**用户自己写的脚本**，由它去调 certbot / acme.sh / Traefik API / 云厂商 API。
//!
//! # 幂等性从何而来
//!
//! 只在**状态迁移**时推送（而非"每次写域名就推"），因此同一状态不会重复触发；
//! 且推送失败只打 WARN——真实世界的对齐由运维用 `deploy/README.md §7.1` 的
//! "按需全量重推"脚本（列出全部 `verify_status='1'` 域名）兜底，无需服务端缓存去重。
//!
//! # 安全姿态
//!
//! - 默认 `off` ⇒ 本模块**一个字节都不发**（`effective_webhook()` 为 `None` 时直接返回）；
//! - 推送 fire-and-forget：失败只 `WARN`，**绝不影响**域名绑定/验证业务本身；
//! - 可选 HMAC-SHA256 签名（`X-Yebot-Signature: sha256=<hex>`）供接收端验签。

use chrono::NaiveDateTime;

use crate::config::settings::AcmeConfig;

/// 事件：需要为该域名签发证书（域名刚通过 DNS TXT 验证）
pub const EVENT_CERT_ISSUE: &str = "cert.issue";
/// 事件：该域名不再需要证书（已验证域名被删除）
pub const EVENT_CERT_REMOVE: &str = "cert.remove";

/// 载荷来源标识（接收端可据此区分多实例/多环境）
const PAYLOAD_SOURCE: &str = "yebot";

/// 构造证书需求事件载荷（**纯函数**，便于单测与契约冻结）。
///
/// 字段刻意用 camelCase（与前端/其它出站契约一致）；`tenantCode` 可能为空（租户行缺失时）。
pub fn build_payload(
    event: &str,
    host: &str,
    tenant_id: i64,
    tenant_code: Option<&str>,
    verify_status: &str,
    occurred_at: NaiveDateTime,
) -> serde_json::Value {
    serde_json::json!({
        "source": PAYLOAD_SOURCE,
        "event": event,
        "host": host,
        "tenantId": tenant_id,
        "tenantCode": tenant_code,
        "verifyStatus": verify_status,
        "occurredAt": occurred_at,
    })
}

/// HMAC-SHA256 签名（hex 小写）。未配置 `secret` 时调用方不应调用本函数。
///
/// 实现收敛在 [`crate::common::webhook::sign_hmac_sha256`]：与 `[events]` 出站事件
/// 共用同一内核，避免两处签名口径漂移。
pub fn sign(secret: &str, body: &[u8]) -> String {
    crate::common::webhook::sign_hmac_sha256(secret, body)
}

/// 推送证书需求事件（**fire-and-forget**）。
///
/// 同步函数、不返回错误：内部先做"是否配置了有效 webhook"的快速判定（`off` 时零开销），
/// 命中后 `spawn` 一个后台任务完成 HTTP 推送，失败只打 WARN。
/// 因此本函数**不可能**影响调用方的业务结果（域名验证/删除照常返回）。
pub fn spawn_emit(
    cfg: AcmeConfig,
    event: &'static str,
    host: String,
    tenant_id: i64,
    tenant_code: Option<String>,
    verify_status: String,
) {
    let Some(url) = cfg.effective_webhook().map(str::to_string) else {
        return; // off / 地址缺失或非法 ⇒ 不发任何请求（关闭态即现状）
    };
    let timeout = cfg.timeout();
    let secret = cfg.secret.clone();
    // 无 tokio 运行时（如单测/迁移进程）时静默跳过：此处不是错误路径，业务已成功
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::debug!("无 tokio 运行时，跳过 ACME 证书需求推送");
        return;
    };
    handle.spawn(async move {
        let occurred_at = crate::common::datetime::now_naive();
        let body = build_payload(
            event,
            &host,
            tenant_id,
            tenant_code.as_deref(),
            &verify_status,
            occurred_at,
        );
        let bytes = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "ACME 证书需求载荷序列化失败（跳过本次推送）");
                return;
            }
        };
        let client = match reqwest::Client::builder().timeout(timeout).build() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "ACME 推送 HTTP 客户端构建失败");
                return;
            }
        };
        let mut req = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("X-Yebot-Event", event)
            .body(bytes.clone());
        if let Some(secret) = secret.as_deref().filter(|s| !s.is_empty()) {
            req = req.header("X-Yebot-Signature", format!("sha256={}", sign(secret, &bytes)));
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(event, host = %host, tenant_id, "ACME 证书需求已推送");
            }
            Ok(resp) => {
                tracing::warn!(
                    event,
                    host = %host,
                    status = %resp.status(),
                    "ACME 证书需求推送被拒（接收端非 2xx；业务不受影响）"
                );
            }
            Err(e) => {
                tracing::warn!(
                    event,
                    host = %host,
                    error = %e,
                    "ACME 证书需求推送失败（业务不受影响；可用 deploy/README §7.1 的全量重推脚本对齐）"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{AcmeConfig, AcmeMode};

    fn cfg(mode: &str, url: Option<&str>) -> AcmeConfig {
        AcmeConfig {
            mode: mode.to_string(),
            webhook_url: url.map(str::to_string),
            secret: None,
            timeout_secs: 5,
        }
    }

    /// **关闭态即现状**：`off` ⇒ 有效目标为空（一个字节都不发）
    #[test]
    fn test_off_mode_has_no_target() {
        assert_eq!(
            cfg("off", Some("https://ops.example.com/acme")).effective_webhook(),
            None
        );
        assert_eq!(cfg("off", None).effective_webhook(), None);
        assert_eq!(AcmeMode::parse("off"), AcmeMode::Off);
        // 非法取值回落 off（fail-safe）
        assert_eq!(AcmeMode::parse("WEBHOOK!").as_str(), "off");
        assert_eq!(AcmeMode::parse("").as_str(), "off");
    }

    /// `webhook` 模式：地址合法才生效；缺失/非 http(s) 一律视为未配置（不静默放开）
    #[test]
    fn test_webhook_mode_requires_http_url() {
        assert_eq!(
            cfg("webhook", Some(" https://ops.example.com/acme ")).effective_webhook(),
            Some("https://ops.example.com/acme"),
            "两端空白应被裁剪"
        );
        assert_eq!(
            cfg("webhook", Some("http://10.0.0.1:9000/acme")).effective_webhook(),
            Some("http://10.0.0.1:9000/acme")
        );
        // 非 http(s) 一律拒绝（防 file:/ftp: 之类被当作推送目标）
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

    /// 载荷字段冻结：接收端脚本按这些键名解析，改名即破坏契约
    #[test]
    fn test_payload_contract() {
        let ts = chrono::NaiveDate::from_ymd_opt(2026, 9, 27)
            .unwrap()
            .and_hms_opt(10, 30, 0)
            .unwrap();
        let p = build_payload(
            EVENT_CERT_ISSUE,
            "shop.example.com",
            12,
            Some("acme"),
            "1",
            ts,
        );
        assert_eq!(p["source"], "yebot");
        assert_eq!(p["event"], "cert.issue");
        assert_eq!(p["host"], "shop.example.com");
        assert_eq!(p["tenantId"], 12);
        assert_eq!(p["tenantCode"], "acme");
        assert_eq!(p["verifyStatus"], "1");
        assert_eq!(p["occurredAt"], "2026-09-27T10:30:00");
        // 租户行缺失时 tenantCode 为 null（不省略键，接收端无需判存在性）
        let p2 = build_payload(EVENT_CERT_REMOVE, "a.example.com", 7, None, "1", ts);
        assert!(p2["tenantCode"].is_null());
        assert_eq!(p2["event"], "cert.remove");
    }

    /// 签名：对齐 HMAC-SHA256 标准测试向量（**外部真值**，非自证）
    ///
    /// 向量来自 RFC 2104 / 常见公开测试用例：key=`key`，
    /// data=`The quick brown fox jumps over the lazy dog`。
    #[test]
    fn test_hmac_sha256_matches_known_vector() {
        assert_eq!(
            sign("key", b"The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        // 同输入同输出（确定性）；不同密钥不同签名
        assert_eq!(sign("k", b"body"), sign("k", b"body"));
        assert_ne!(sign("k1", b"body"), sign("k2", b"body"));
    }

    /// `spawn_emit` 在关闭态下**不产生**任何副作用（无运行时也不 panic）
    #[test]
    fn test_spawn_emit_is_noop_when_off() {
        spawn_emit(
            cfg("off", Some("https://ops.example.com/acme")),
            EVENT_CERT_ISSUE,
            "shop.example.com".to_string(),
            12,
            Some("acme".to_string()),
            "1".to_string(),
        );
        // webhook 模式但地址非法 ⇒ 同样不发
        spawn_emit(
            cfg("webhook", Some("file:///tmp/x")),
            EVENT_CERT_ISSUE,
            "shop.example.com".to_string(),
            12,
            None,
            "1".to_string(),
        );
    }
}
