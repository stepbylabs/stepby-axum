// stepby-axum/src/common/upload_scan.rs
//! 上传文件病毒扫描**集成点**（`[upload_scan]`）。
//!
//! 定位（项目准则⑥）：本仓**不内置杀毒引擎**（ClamAV / VirusTotal 都不进本仓），
//! 而是提供"把文件字节交给使用者自己声明的扫描端点"的协议实现 + 开关，
//! 由使用者按自身合规要求决定开启。
//!
//! **关闭态 = 现状**：`mode = off`（默认）时不校验地址、不建 HTTP 客户端、
//! **一个字节都不出站**，与改造前逐字节等价。
//!
//! 契约（请求/响应）见 [`crate::config::settings::UploadScanConfig`] 的文档注释。

use crate::common::error::AppError;
use crate::common::ssrf::{validate_host_resolution, validate_url};
use crate::config::settings::{UploadScanConfig, UploadScanMode};

/// 单次扫描的原始结果（与处置策略解耦，便于单测直接断言）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    /// 放行（含 `mode = off` 的关闭态）。
    Clean,
    /// 扫描器判定为恶意文件（`clean = false`）。`detail` 仅用于日志，**不回显给客户端**。
    Rejected { detail: String },
    /// 扫描器不可用（地址非法 / DNS 被拒 / 连接失败 / 超时 / 非 2xx / 响应不合约）。
    /// 是拒绝还是放行由 `fail_closed` 决定（见 [`ensure_clean`]）。
    Unavailable { reason: String },
}

/// 解析扫描端点响应体，取出 `clean` 布尔值。
///
/// 契约：HTTP 2xx + JSON `{"clean": true|false, "detail": "可选"}`。
/// 返回 `Err(原因)` 表示**响应不合约**（由调用方按 `fail_closed` 处置）——
/// 不合约**绝不**当作"干净"（fail-closed：不合约 = 不可信）。
pub fn parse_verdict(body: &str) -> Result<bool, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("响应不是合法 JSON：{e}"))?;
    match value.get("clean").and_then(|c| c.as_bool()) {
        Some(clean) => Ok(clean),
        None => Err("响应缺少布尔字段 clean".to_string()),
    }
}

/// 从判定载荷中取出人类可读说明（仅用于日志；缺失时返回空串）。
pub fn verdict_detail(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("detail")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default()
}

/// 扫描文件字节。
///
/// `mode = off` ⇒ 立即返回 [`ScanOutcome::Clean`]，**不发任何请求**。
/// `mode = http` ⇒ 先做 [`validate_url`]（静态：仅 http(s)、拒绝 IP 字面量内网段与保留域名后缀）
/// 与 [`validate_host_resolution`]（动态：解析结果任一为内网/保留段即拒），
/// 复用 [`crate::common::ssrf`] 这一**单一事实源**，避免各出站点各写一套 SSRF 判定。
pub async fn scan_bytes(cfg: &UploadScanConfig, filename: &str, bytes: &[u8]) -> ScanOutcome {
    if cfg.mode() == UploadScanMode::Off {
        return ScanOutcome::Clean; // 关闭态：零出站
    }

    let raw_url = cfg.url.trim();
    if raw_url.is_empty() {
        return ScanOutcome::Unavailable {
            reason: "mode = http 但未配置 url".to_string(),
        };
    }
    let url = match validate_url(raw_url) {
        Ok(u) => u,
        Err(e) => {
            return ScanOutcome::Unavailable {
                reason: format!("扫描端点地址非法（{e}）"),
            };
        }
    };
    let Some(host) = url.host_str().map(str::to_string) else {
        return ScanOutcome::Unavailable {
            reason: "扫描端点地址缺少主机名".to_string(),
        };
    };
    let port = url.port_or_known_default().unwrap_or(443);
    if let Err(e) = validate_host_resolution(&host, port).await {
        return ScanOutcome::Unavailable {
            reason: format!("扫描端点解析被拒（{e}）"),
        };
    }

    // b144：走 `outbound_client::build`，取到内嵌根证书回落（裸构造在缺 `ca-certificates`
    // 的宿主上直接失败 ⇒ 整项病毒扫描被报成"不可用"，而那是宿主缺库、不是扫描端坏了）。
    // 跳转策略保持默认：扫描端点是**部署期配置**（运维写下），不是租户可改的投递目标，
    // 投递类那条"不许离开这台主机"的闸只对 DB 里可改的地址成立。
    let client =
        match crate::common::outbound_client::build_with("av_scan", |b| b.timeout(cfg.timeout())) {
            Ok(c) => c,
            Err(e) => {
                return ScanOutcome::Unavailable {
                    reason: format!("HTTP 客户端构建失败（{e}）"),
                };
            }
        };

    // 文件名经 URL 编码后放入请求头：避免换行/冒号等造成头注入
    let encoded_name: String = url::form_urlencoded::byte_serialize(filename.as_bytes()).collect();
    let mut req = client
        .post(url.as_str())
        .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
        .header("X-Stepby-Filename", encoded_name)
        .body(bytes.to_vec());
    if !cfg.token.trim().is_empty() {
        req = req.bearer_auth(cfg.token.trim());
    }

    // b74（AGENTS B.4）：扫描服务是外部依赖，请求数/耗时/结局必须进指标。本函数出口多，
    // 手写计数必漏 ⇒ RAII 守卫。计数口径：**只有真的发出请求才计数**（本地校验、客户端
    // 构建失败都不算一次出站）；`Rejected`（扫描器判定恶意）算 `ok`——那是扫描器的正常工作结果。
    let mut outbound = crate::observability::metrics::OutboundGuard::start("upload_scan");
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            if !status.is_success() {
                return ScanOutcome::Unavailable {
                    reason: format!("扫描端点返回非 2xx（{status}）"),
                };
            }
            match parse_verdict(&body) {
                Ok(true) => {
                    outbound.succeeded();
                    ScanOutcome::Clean
                }
                Ok(false) => {
                    outbound.succeeded();
                    ScanOutcome::Rejected {
                        detail: verdict_detail(&body),
                    }
                }
                Err(e) => ScanOutcome::Unavailable { reason: e },
            }
        }
        Err(e) => ScanOutcome::Unavailable {
            reason: format!("扫描请求失败（{e}）"),
        },
    }
}

/// 上传前的统一闸门：**放行返回 `Ok(())`，拒绝返回 `Err`**。
///
/// 处置规则：
/// - [`ScanOutcome::Clean`] ⇒ 放行；
/// - [`ScanOutcome::Rejected`] ⇒ **恒拒绝**（400，对外用 i18n 文案；`detail` 只落 tracing，
///   不回显扫描器返回的原文，防反射注入）；
/// - [`ScanOutcome::Unavailable`] ⇒ `fail_closed = true`（默认）⇒ 503 拒绝上传；
///   `false` ⇒ 打 WARN 后放行（使用者显式选择"扫描器挂了也放行"的降级姿态）。
///
/// # 为什么默认 fail-closed
///
/// 开启扫描即表示"把扫描作为上传闸门"。若扫描器不可用时默认放行，
/// 则"扫描器一挂 = 等同于没扫描"，闸门形同虚设。确需降级放行的部署显式置
/// `fail_closed = false`（此时该风险由使用者承担并在部署文档中说明）。
pub async fn ensure_clean(
    cfg: &UploadScanConfig,
    filename: &str,
    bytes: &[u8],
) -> Result<(), AppError> {
    match scan_bytes(cfg, filename, bytes).await {
        ScanOutcome::Clean => Ok(()),
        ScanOutcome::Rejected { detail } => {
            tracing::warn!(
                filename,
                size = bytes.len(),
                scanner_detail = %detail,
                "上传文件被病毒扫描端点判定为恶意，已拒绝"
            );
            Err(AppError::bad_request(&crate::tr!(
                "error.upload_scan.rejected"
            )))
        }
        ScanOutcome::Unavailable { reason } => {
            if cfg.fail_closed {
                tracing::error!(
                    filename,
                    size = bytes.len(),
                    reason = %reason,
                    "病毒扫描端点不可用，按 fail_closed 拒绝上传（503）"
                );
                Err(AppError::new(
                    503,
                    crate::tr!("error.upload_scan.unavailable"),
                ))
            } else {
                tracing::warn!(
                    filename,
                    size = bytes.len(),
                    reason = %reason,
                    "病毒扫描端点不可用，fail_closed = false ⇒ 降级放行（该风险由使用者承担）"
                );
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{UploadScanConfig, UploadScanMode};

    fn http_cfg(url: &str) -> UploadScanConfig {
        UploadScanConfig {
            mode: "http".to_string(),
            url: url.to_string(),
            token: String::new(),
            timeout_secs: 10,
            fail_closed: true,
        }
    }

    /// 关闭态（默认）**零出站**：即便 url 指向不可达地址也必须立即放行（证明不会发起请求）
    #[tokio::test]
    async fn test_off_mode_makes_no_outbound_call() {
        let cfg = UploadScanConfig {
            mode: "off".to_string(),
            // 指向本机一个**必然无人监听**的端口：若真发请求必然连接失败 ⇒ 结果会是 Unavailable
            url: "http://127.0.0.1:9/scan".to_string(),
            token: String::new(),
            timeout_secs: 1,
            fail_closed: true,
        };
        assert_eq!(cfg.mode(), UploadScanMode::Off);
        assert_eq!(
            scan_bytes(&cfg, "a.png", b"x").await,
            ScanOutcome::Clean,
            "off 档必须直接放行（不校验地址、不发起请求）"
        );
        assert!(
            ensure_clean(&cfg, "a.png", b"x").await.is_ok(),
            "off 档闸门必须放行"
        );
    }

    /// `http` 档但地址为空 / scheme 非法 / 内网字面量 ⇒ 一律 Unavailable（**不是 Clean**）
    #[tokio::test]
    async fn test_http_mode_rejects_invalid_or_internal_target() {
        for bad in ["", "file:///etc/passwd", "scan.local/scan"] {
            let cfg = http_cfg(bad);
            assert!(
                matches!(
                    scan_bytes(&cfg, "a.png", b"x").await,
                    ScanOutcome::Unavailable { .. }
                ),
                "{bad:?} 必须判定为不可用而非放行"
            );
        }
        // 内网/环回 IP 字面量被 SSRF 静态层拦截（证明复用同一事实源）
        let cfg = http_cfg("http://127.0.0.1:9/scan");
        match scan_bytes(&cfg, "a.png", b"x").await {
            ScanOutcome::Unavailable { reason } => {
                assert!(
                    reason.contains("地址非法"),
                    "应为静态层拦截，实际：{reason}"
                );
            }
            other => panic!("环回地址必须被 SSRF 静态层拒绝，实际：{other:?}"),
        }
    }

    /// 响应契约解析：仅 `clean` 布尔合法；缺字段 / 非 JSON / 非布尔 ⇒ Err（不合约 ≠ 干净）
    #[test]
    fn test_parse_verdict_contract() {
        assert_eq!(parse_verdict(r#"{"clean":true}"#), Ok(true));
        assert_eq!(
            parse_verdict(r#"{"clean":false,"detail":"Eicar-Test-Signature"}"#),
            Ok(false)
        );
        assert!(
            parse_verdict(r#"{"detail":"missing clean"}"#).is_err(),
            "缺 clean 字段必须视为不合约"
        );
        assert!(
            parse_verdict(r#"{"clean":"yes"}"#).is_err(),
            "clean 非布尔必须视为不合约"
        );
        assert!(parse_verdict("not json").is_err());
        assert!(parse_verdict("").is_err());
        assert_eq!(
            verdict_detail(r#"{"clean":false,"detail":"Eicar"}"#),
            "Eicar"
        );
        assert_eq!(verdict_detail("not json"), "");
    }

    /// fail_closed 语义：不可用时默认拒绝（503），显式置 false 才降级放行
    #[tokio::test]
    async fn test_fail_closed_governs_unavailable() {
        let mut cfg = http_cfg("http://127.0.0.1:9/scan"); // 静态层即被拒 ⇒ Unavailable
        cfg.fail_closed = true;
        let err = ensure_clean(&cfg, "a.png", b"x")
            .await
            .expect_err("fail_closed = true 时扫描器不可用必须拒绝上传");
        assert_eq!(err.code, 503, "不可用时应返回 503");

        cfg.fail_closed = false;
        assert!(
            ensure_clean(&cfg, "a.png", b"x").await.is_ok(),
            "fail_closed = false 时不可用应降级放行"
        );
    }
}
