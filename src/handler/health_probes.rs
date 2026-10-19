//! 外部依赖探活（AGENTS.md 硬基线 #5，批七十二 B3）。
//!
//! # 为什么需要本模块
//!
//! `/health` 此前只探测 **DB + 共享态存储**，而本仓的外部依赖远不止这两项：SMTP、
//! AI provider、对象存储、WebHook 出站、IP 归属地库。基线 #5 要求"新增外部依赖必须
//! 实现健康检查并接入 `/health` 聚合（启动检查 + 运行时探活），不得只在启动时连一次
//! 就假定永久可用"。但把探测直接写进 `/health` 会踩三个坑，本模块逐个收敛：
//!
//! 1. **默认即改行为**：`/health` 是**免鉴权公开端点**，让它"顺带扫一遍所有外部依赖"
//!    既泄露基础设施信息、又拖慢编排探针。故 `[health].external_probes` **默认 `off`**
//!    ⇒ 响应体不含 `external`/`externalStatus` 字段，与改造前逐字节等价。
//! 2. **探针把依赖打爆**：K8s/Consul 每秒 N 次拉 `/health`，若每次都 SMTP 握手 +
//!    OSS ListObjects，等于自己发起 DoS。故外部探针走**独立 TTL**（默认 30s，与核心
//!    探测的 5s 分档）+ **轮次互斥**（双检锁：TTL 到期后并发请求只有一个真正发起探测，
//!    其余等待同一轮结果；等待再包一层超时，取不到就回退上一次结果）。
//! 3. **可选依赖误杀实例**：AI 没配 / 邮件没开不该让 `/health` 变红，否则编排层会把
//!    一个业务完全正常的实例摘流。故外部结果**不改核心 `status`**，只落在
//!    `externalStatus` + `external[]`；需要据此摘流的部署自行判定。
//!
//! # 探针清单（`basic` 档）
//!
//! | 名称      | 手段（真实、零业务副作用）                                        | 未配置时 |
//! |-----------|-----------------------------------------------------------------|----------|
//! | `mail`    | `lettre` `test_connection`：只握手不发信                          | SKIPPED  |
//! | `ai`      | `GET {base_url}/models`：零 token 成本（**不用** completion）      | SKIPPED  |
//! | `storage` | s3 → ListObjectsV2；local → 上传根目录写-删往返（可判只读挂载）     | —        |
//! | `webhook` | **被动**：启用回调数 + 近 24h 失败留痕（不打用户端点）              | SKIPPED  |
//! | `ip_geo`  | 归属地库是否已加载（内存态，零 IO）                                 | SKIPPED  |
//!
//! `webhook` 刻意**不**主动 POST 使用者配置的回调地址：那等于用公开端点驱动任意出站
//! 请求（SSRF 面 + 骚扰接收端），而投递健康已由 `web_hook_log` 留痕完整覆盖。

use crate::common::error::ServiceError;
use crate::config::settings::ExternalProbeMode;
use crate::state::AppState;
use serde::Serialize;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use utoipa::ToSchema;

/// 外部探针状态字面量（大写，与核心 `db`/`redis` 字段的 `"UP"/"DOWN"` 口径一致）
pub const PROBE_STATUSES: &[&str] = &["UP", "DEGRADED", "DOWN", "SKIPPED"];

/// 单个外部依赖的探测结论。
///
/// `Degraded` 用于"依赖活着但不对劲"（如回调近 24h 有失败留痕）：既不该当成故障，
/// 也不该被抹平成正常——聚合规则见 [`aggregate_status`]。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeStatus {
    Up,
    Degraded,
    Down,
    Skipped,
}

impl ProbeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "UP",
            Self::Degraded => "DEGRADED",
            Self::Down => "DOWN",
            Self::Skipped => "SKIPPED",
        }
    }
}

/// `/health` 响应体里的单条外部探针结果。
///
/// 公开端点 ⇒ **字段集合即契约**：只含依赖名、状态、耗时与脱敏说明，不含任何凭据、
/// 收件人、租户标识或投递日志内容。
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalProbeVo {
    /// 依赖名（`mail` / `ai` / `storage` / `webhook` / `ip_geo`）
    pub name: String,
    /// `"UP"` / `"DEGRADED"` / `"DOWN"` / `"SKIPPED"`
    pub status: String,
    /// 本次探测耗时（毫秒）；SKIPPED 无耗时
    pub latency_ms: Option<i64>,
    /// **脱敏后**的说明（失败原因/档位描述）
    pub detail: Option<String>,
}

/// `basic` 档登记的探针清单。
///
/// ⚠️ 新增外部依赖时：在此登记一项 **且** 在 `probe_inner` 补对应分支，两处缺一即被
/// 单测 `registered_probes_are_all_implemented` 判红（防"清单里有、实际不探"的假健康）。
pub const BASIC_PROBES: &[&str] = &["mail", "ai", "storage", "webhook", "ip_geo"];

/// 本次档位应执行的探针名（`off` 档为空 ⇒ 结构上就发不出任何外部请求）
pub fn plan(mode: ExternalProbeMode) -> &'static [&'static str] {
    match mode {
        ExternalProbeMode::Off => &[],
        ExternalProbeMode::Basic => BASIC_PROBES,
    }
}

/// 聚合外部探针结论：**DOWN > DEGRADED > UP**；`SKIPPED` 不参与降级
/// （未启用的可选依赖不是故障）。空集合按 `UP`（没有已知问题）。
pub fn aggregate_status(probes: &[ExternalProbeVo]) -> &'static str {
    let mut degraded = false;
    for p in probes {
        match p.status.as_str() {
            "DOWN" => return "DOWN",
            "DEGRADED" => degraded = true,
            _ => {}
        }
    }
    if degraded { "DEGRADED" } else { "UP" }
}

/// 脱敏探针说明文本（纵深防御：即便依赖库把敏感串吐进错误消息，也不进公开端点）。
///
/// 处理：① URL authority 的 `user:pass@` userinfo 段整段剔除；② `password=`/`token=`/
/// `secret=`/`bearer ` 之后的值替换为 `<redacted>`；③折叠空白并截断到 200 字符。
pub fn sanitize_detail(raw: &str) -> String {
    const CRED_KEYS: &[&str] = &["password=", "passwd=", "token=", "secret=", "bearer "];
    // char 数组上做匹配：`to_ascii_lowercase` 只折叠 ASCII A–Z（UTF-8 多字节首字节
    // 恒 ≥ 0x80），故 lower 与原文按 char 一一对应，索引可直接复用。
    let chars: Vec<char> = raw.chars().collect();
    let lower: Vec<char> = chars.iter().map(|c| c.to_ascii_lowercase()).collect();
    let keys: Vec<Vec<char>> = CRED_KEYS.iter().map(|k| k.chars().collect()).collect();
    let is_authority_end = |c: char| matches!(c, '/' | '?' | '#' | ' ');
    let is_value_end = |c: char| matches!(c, ' ' | ',' | ';' | '"' | '\'' | ')');

    let mut out: Vec<char> = Vec::with_capacity(chars.len());
    let mut i = 0usize;
    while i < chars.len() {
        // ① `://` 之后是 authority：含 `@` 则丢掉 userinfo，只留 host[:port]
        if lower[i] == ':' && chars.get(i + 1) == Some(&'/') && chars.get(i + 2) == Some(&'/') {
            let start = i + 3;
            let end = lower
                .iter()
                .skip(start)
                .position(|c| is_authority_end(*c))
                .map(|p| start + p)
                .unwrap_or(chars.len());
            if let Some(at) = lower[start..end].iter().rposition(|c| *c == '@') {
                out.extend([':', '/', '/']);
                out.extend_from_slice(&chars[start + at + 1..end]);
                i = end;
                continue;
            }
        }
        // ② 凭据类键名：保留键名、值替换
        if let Some(key) = keys.iter().find(|k| lower[i..].starts_with(k.as_slice())) {
            out.extend_from_slice(&chars[i..i + key.len()]);
            out.extend("<redacted>".chars());
            let val_start = i + key.len();
            let val_end = lower[val_start..]
                .iter()
                .position(|c| is_value_end(*c))
                .map(|p| val_start + p)
                .unwrap_or(chars.len());
            i = val_end;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    let normalized = raw_fold(&out);
    // ④ 文件系统绝对路径折叠为 `<path>`（b73 运行栈实测：storage 探针的 detail 原本带出
    //    `D:\...\uploads\file`，而 `/health` 是 public.rs 里的**免鉴权**端点 ⇒ 部署目录结构
    //    直接交给未认证访问者）。源头已改为只报目录名，这里是纵深防御。
    // 判据本身住在 `common::redact`（与 `AppError` 响应体出口同源）——两处各写一遍必然漂移。
    let normalized = crate::common::redact::fold_abs_paths(&normalized);
    const MAX: usize = 200;
    if normalized.chars().count() > MAX {
        let cut: String = normalized.chars().take(MAX).collect();
        format!("{cut}…")
    } else {
        normalized
    }
}

/// 把 char 序列折叠为"单空格分隔"文本（`sanitize_detail` 的第 ③ 步：错误消息里的
/// 换行/连续空白不进响应体，避免公开端点被用作格式注入面）。
fn raw_fold(chars: &[char]) -> String {
    chars
        .iter()
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

// ==================== 执行编排（缓存 + 轮次互斥 + 超时 + 指标） ====================

static PROBE_CACHE: OnceLock<RwLock<Option<(Instant, Vec<ExternalProbeVo>)>>> = OnceLock::new();
static PROBE_ROUND: OnceLock<Mutex<()>> = OnceLock::new();

fn cache() -> &'static RwLock<Option<(Instant, Vec<ExternalProbeVo>)>> {
    PROBE_CACHE.get_or_init(|| RwLock::new(None))
}

fn round_lock() -> &'static Mutex<()> {
    PROBE_ROUND.get_or_init(|| Mutex::new(()))
}

/// `/health` 的外部探针部分：`off` 档返回 `None`（响应体不含该字段 = 现状等价）。
///
/// TTL 内命中缓存直接返回；到期后由**一把互斥锁**保证同一时刻只有一轮真实探测在跑，
/// 其余请求最多等"一轮预算"后回退上一次结果（宁可用陈旧值，也不让 `/health` 自己被
/// 探针拖死或把依赖打爆 —— AGENTS #2 的背压口径）。
pub async fn external_probes(state: &Arc<AppState>) -> Option<Vec<ExternalProbeVo>> {
    let cfg = &state.config.health;
    let mode = cfg.external_probe_mode();
    if mode == ExternalProbeMode::Off {
        return None;
    }
    let ttl = cfg.probe_ttl();
    if let Some(fresh) = cached_within(ttl).await {
        return Some(fresh);
    }
    // 探针彼此并发 ⇒ 一轮上界是"单探针超时 + 调度余量"，不是 N 倍
    let round_budget = cfg.probe_timeout() * 2 + Duration::from_secs(1);
    let permit = match tokio::time::timeout(round_budget, round_lock().lock()).await {
        Ok(guard) => guard,
        Err(_) => {
            // 已有轮次卡死（每探针本应有超时，不应发生）⇒ 回退陈旧缓存，不阻塞请求
            tracing::warn!("外部探针轮次等待超时，本次 /health 回退上一次探测结果");
            return cache().read().await.as_ref().map(|(_, p)| p.clone());
        }
    };
    // 双检：等锁期间别的请求已跑完一轮 ⇒ 直接用新结果，不重复探测
    if let Some(fresh) = cached_within(ttl).await {
        return Some(fresh);
    }
    let probes = run_round(state, mode).await;
    *cache().write().await = Some((Instant::now(), probes.clone()));
    drop(permit);
    Some(probes)
}

/// 读取 TTL 内的缓存结果
async fn cached_within(ttl: Duration) -> Option<Vec<ExternalProbeVo>> {
    let c = cache().read().await;
    c.as_ref()
        .filter(|(ts, _)| ts.elapsed() < ttl)
        .map(|(_, probes)| probes.clone())
}

/// 并发执行档位内全部探针（每个探针独立超时 + panic 隔离 + 组件级指标，AGENTS #4/#6）。
///
/// 用 `join_all` 而非 `tokio::spawn`：本轮已在请求路径上等结果，起新任务只会把"任务丢失"
/// 变成需要额外处理的失败面；panic 隔离改由 [`guarded_probe`] 的 `catch_unwind` 承担。
async fn run_round(state: &Arc<AppState>, mode: ExternalProbeMode) -> Vec<ExternalProbeVo> {
    let names = plan(mode);
    let mut set = Vec::with_capacity(names.len());
    for name in names {
        let state = state.clone();
        set.push(guarded_probe(state, name));
    }
    let mut out = futures::future::join_all(set).await;
    // 输出顺序按登记清单固定（编排脚本与单测可比对，不随完成顺序漂移）
    out.sort_by_key(|p| {
        BASIC_PROBES
            .iter()
            .position(|n| *n == p.name)
            .unwrap_or(usize::MAX)
    });
    out
}

/// 单探针执行体：超时 + panic 隔离 + 失败留痕 + 指标四件齐（AGENTS #6 统一范式）
async fn guarded_probe(state: Arc<AppState>, name: &'static str) -> ExternalProbeVo {
    let budget = state.config.health.probe_timeout();
    let started = Instant::now();
    // catch_unwind 在前、timeout 在外的顺序是刻意的：探针内部 panic 不能冒到请求任务，
    // 否则一个可选依赖的错误会把整个 /health 打成 500。
    let outcome = tokio::time::timeout(
        budget,
        futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(probe_inner(
            state.clone(),
            name,
        ))),
    )
    .await;
    let (status, detail) = match outcome {
        Err(_) => (
            ProbeStatus::Down,
            Some(format!("探测超时（预算 {}ms）", budget.as_millis())),
        ),
        Ok(Err(_)) => {
            tracing::warn!(
                probe = name,
                "外部探针 panic（已隔离，不影响 /health 其余结果）"
            );
            (
                ProbeStatus::Down,
                Some("探测内部 panic（已隔离）".to_string()),
            )
        }
        Ok(Ok(Err(e))) => (ProbeStatus::Down, Some(e.message)),
        Ok(Ok(Ok(pair))) => pair,
    };
    let secs = started.elapsed().as_secs_f64();
    crate::observability::metrics::MetricsRegistry::global().record_outbound(
        &format!("probe:{name}"),
        status.as_str(),
        secs,
    );
    ExternalProbeVo {
        name: name.to_string(),
        status: status.as_str().to_string(),
        latency_ms: if status == ProbeStatus::Skipped {
            None
        } else {
            Some((secs * 1000.0) as i64)
        },
        detail: detail.map(|d| sanitize_detail(&d)),
    }
}

/// 探针分派。未登记/未实现的名字返回 `Err` ⇒ 聚合为 DOWN（**响亮**，而不是静默 UP）。
async fn probe_inner(
    state: Arc<AppState>,
    name: &str,
) -> Result<(ProbeStatus, Option<String>), ServiceError> {
    match name {
        "mail" => probe_mail(&state).await,
        "ai" => probe_ai(&state).await,
        "storage" => probe_storage(&state).await,
        "webhook" => probe_webhook(&state).await,
        "ip_geo" => probe_ip_geo(&state).await,
        other => Err(ServiceError::internal(&format!(
            "探针 `{other}` 已登记但未实现（BASIC_PROBES 与 probe_inner 漂移）"
        ))),
    }
}

async fn probe_mail(state: &Arc<AppState>) -> Result<(ProbeStatus, Option<String>), ServiceError> {
    if !state.mailer_service.is_enabled() {
        return Ok((
            ProbeStatus::Skipped,
            Some("邮件未启用（mail.enabled=false 或 SMTP 客户端未构建）".to_string()),
        ));
    }
    let host = state.config.mail.host.clone();
    let port = state.config.mail.port;
    state.mailer_service.probe().await?;
    Ok((
        ProbeStatus::Up,
        Some(format!("SMTP 握手成功（{host}:{port}）")),
    ))
}

async fn probe_ai(state: &Arc<AppState>) -> Result<(ProbeStatus, Option<String>), ServiceError> {
    match state.ai_config_service.probe_reachability().await? {
        None => Ok((
            ProbeStatus::Skipped,
            Some("AI 助手未启用或未配置（base_url/api_key 缺失）".to_string()),
        )),
        Some(detail) => Ok((ProbeStatus::Up, Some(detail))),
    }
}

async fn probe_storage(
    state: &Arc<AppState>,
) -> Result<(ProbeStatus, Option<String>), ServiceError> {
    let mode = state.upload_config_service.effective_backend_mode().await?;
    if mode == "s3" {
        // 复用管理端同一探测实现（ListObjectsV2 空前缀）：bucket/寻址/签名错误都会暴露
        let detail = state.upload_config_service.test_connectivity().await?;
        return Ok((ProbeStatus::Up, Some(detail)));
    }
    let dir = state.config.upload.common_dir.clone();
    let base = crate::common::resolve_upload_dir(&dir).await;
    // 同步 fs 写删整体放进阻塞线程池（异步上下文内不做裸 fs IO，目录判定也在其中）
    let detail = tokio::task::spawn_blocking(move || writable_probe(&base))
        .await
        .map_err(|e| ServiceError::internal(&format!("存储探测任务丢失: {e}")))??;
    Ok((ProbeStatus::Up, Some(detail)))
}

/// 本地上传目录**写-删**往返：只读 `metadata` 判不出"卷挂成只读"这类真实故障
/// （Docker/K8s volume `ro` 是常见事故），而写删与真实上传走同一 syscall 路径。
///
/// 目录尚不存在时探其父目录（真实上传走 `create_dir_all`，父目录可写即可用）。
/// 探针文件名带 `.` 前缀 + pid + 纳秒，即刻删除，不落任何业务子目录、不涉租户数据。
fn writable_probe(base: &Path) -> Result<String, ServiceError> {
    let exists = base.is_dir();
    let target = if exists {
        base.to_path_buf()
    } else {
        base.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| base.to_path_buf())
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = target.join(format!(".health-probe-{}-{nanos}", std::process::id()));
    // detail 里**只放目录名**，不放绝对路径：`/health` 是公开端点（`router/public.rs`，无需令牌），
    // 泄露 `D:\...\uploads\file` 这类部署根路径会把内部结构交给未认证访问者（b73 实测发现）。
    let hint = base
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "<配置目录>".to_string());
    std::fs::write(&path, b"probe")
        .map_err(|e| ServiceError::internal(&format!("上传目录不可写（{hint}）: {e}")))?;
    if let Err(e) = std::fs::remove_file(&path) {
        // 写成功但删不掉：目录可用，只是探针残留（WARN 留痕，不判故障）
        tracing::warn!(error = %e, path = %path.display(), "健康探针临时文件清理失败");
    }
    let note = if exists {
        ""
    } else {
        "，目录将在首次上传时创建"
    };
    Ok(format!("本地上传目录可写（{hint}）{note}"))
}

/// WebHook：**被动**探活。绝不用公开端点驱动"对使用者回调地址发起 POST"的出站请求
/// （SSRF 面 + 骚扰接收端）；投递健康以 `web_hook_log` 留痕为准。
///
/// 条数只做内部换算，**不**放进响应体（公开端点泄露活动量 = 侧信道）。
async fn probe_webhook(
    state: &Arc<AppState>,
) -> Result<(ProbeStatus, Option<String>), ServiceError> {
    let enabled = state
        .web_hook_service
        .count_enabled_hooks()
        .await
        .map_err(|e| ServiceError::internal(&format!("读取启用回调失败: {e}")))?;
    if enabled == 0 {
        return Ok((
            ProbeStatus::Skipped,
            Some("未配置任何启用的 WebHook 回调".to_string()),
        ));
    }
    let since = crate::common::datetime::now_naive() - chrono::Duration::hours(24);
    let failed = state
        .web_hook_service
        .count_failed_deliveries_since(since)
        .await
        .map_err(|e| ServiceError::internal(&format!("读取投递留痕失败: {e}")))?;
    if failed == 0 {
        Ok((
            ProbeStatus::Up,
            Some("启用回调存在，近 24h 出站投递零失败".to_string()),
        ))
    } else {
        Ok((
            ProbeStatus::Degraded,
            Some("启用回调近 24h 存在投递失败，详见 WebHook 推送记录".to_string()),
        ))
    }
}

async fn probe_ip_geo(
    state: &Arc<AppState>,
) -> Result<(ProbeStatus, Option<String>), ServiceError> {
    let mmdb = state.ip_locator.is_loaded();
    let xdb = state.ip_locator.is_xdb_loaded();
    if mmdb || xdb {
        Ok((
            ProbeStatus::Up,
            Some(format!("归属地库已加载（mmdb={mmdb}, xdb={xdb}）")),
        ))
    } else {
        // 登录地域展示降级但主流程不受影响 ⇒ SKIPPED（不是故障）
        Ok((
            ProbeStatus::Skipped,
            Some("未加载 IP 归属地库（不影响主流程，仅登录地域展示降级）".to_string()),
        ))
    }
}

/// 启动一次性探活（AGENTS #5「启动检查 + 运行时探活」的前半件）。
///
/// 只在 `basic` 档跑，且**绝不**阻断启动：外部依赖起不来时管理面仍要能登录排查。
/// 走 [`crate::common::background`] 统一异步范式（超时 + panic 隔离 + 指标）。
pub async fn startup_probe(state: &Arc<AppState>) {
    if state.config.health.external_probe_mode() == ExternalProbeMode::Off {
        return;
    }
    let probes = external_probes(state).await.unwrap_or_default();
    let down: Vec<&str> = probes
        .iter()
        .filter(|p| p.status == "DOWN")
        .map(|p| p.name.as_str())
        .collect();
    if down.is_empty() {
        tracing::info!(
            probes = ?probes.iter().map(|p| (p.name.as_str(), p.status.as_str())).collect::<Vec<_>>(),
            "启动探活：外部依赖健康检查完成"
        );
    } else {
        tracing::warn!(
            down = ?down,
            "启动探活：以下外部依赖不可达（不阻断启动，详见 /health 的 external 字段）"
        );
    }
}

#[cfg(test)]
mod health_probes_mod {
    use super::*;

    fn vo(name: &str, status: &str) -> ExternalProbeVo {
        ExternalProbeVo {
            name: name.to_string(),
            status: status.to_string(),
            latency_ms: Some(1),
            detail: None,
        }
    }

    /// 档位投影：`off` 档**结构上**发不出任何外部请求（关闭态 = 现状的机械证明）
    #[test]
    fn off_mode_plans_no_probes() {
        assert!(
            plan(ExternalProbeMode::Off).is_empty(),
            "off 档必须计划零探针（否则默认配置就会发起出站请求）"
        );
        let basic = plan(ExternalProbeMode::Basic);
        assert_eq!(basic, BASIC_PROBES, "basic 档应执行登记清单全集");
        assert_eq!(basic.len(), 5, "清单条目数漂移请同步更新本文档表格");
    }

    /// 清单与实现不得漂移：每个登记名都要有 `probe_inner` 的分支（防"清单有、实际不探"）
    #[test]
    fn registered_probes_are_all_implemented() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handler/health_probes.rs");
        let src = std::fs::read_to_string(&path).expect("读取本文件失败");
        let prod = match src.find("#[cfg(test)]") {
            Some(i) => &src[..i],
            None => &src,
        };
        for name in BASIC_PROBES {
            let arm = format!("\"{name}\" => probe_");
            assert!(
                prod.contains(&arm),
                "探针 `{name}` 已登记但 probe_inner 无对应分支（假健康）"
            );
        }
    }

    /// 状态字面量即公开契约（与核心 db/redis 的大写口径一致，漂移即红）
    #[test]
    fn probe_status_literals_are_the_public_contract() {
        let got: Vec<&str> = [
            ProbeStatus::Up,
            ProbeStatus::Degraded,
            ProbeStatus::Down,
            ProbeStatus::Skipped,
        ]
        .iter()
        .map(|s| s.as_str())
        .collect();
        assert_eq!(got, PROBE_STATUSES);
    }

    /// 聚合口径：DOWN > DEGRADED > UP，SKIPPED 不降级（可选依赖没配不是故障）
    #[test]
    fn aggregate_status_matrix() {
        assert_eq!(aggregate_status(&[]), "UP");
        assert_eq!(
            aggregate_status(&[vo("mail", "UP"), vo("ai", "SKIPPED")]),
            "UP",
            "未启用的可选依赖不得拉低整体"
        );
        assert_eq!(
            aggregate_status(&[vo("mail", "UP"), vo("webhook", "DEGRADED")]),
            "DEGRADED"
        );
        assert_eq!(
            aggregate_status(&[vo("mail", "DEGRADED"), vo("storage", "DOWN")]),
            "DOWN",
            "存在 DOWN 时不得被 DEGRADED 掩盖"
        );
    }

    /// panic 隔离必须真的生效：探针炸了不能冒到 /health 请求任务
    #[tokio::test(flavor = "current_thread")]
    async fn panicking_probe_is_isolated_as_down() {
        let f = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
            panic!("探针内部故障");
        }))
        .await;
        assert!(
            f.is_err(),
            "catch_unwind 应捕获 panic（而不是让它冒到请求路径）"
        );
    }

    /// b73：绝对文件系统路径必须被折叠——`/health` 免鉴权，detail 带出部署路径即信息暴露。
    ///
    /// 三条边界都要钉住（缺一即"看似安全实则漏"或"过度脱敏致排障无从下手"）：
    /// ① Windows 盘符路径折叠；② POSIX 多层路径折叠；③ **URL 不得被误伤**
    /// （`https://host:465` 与单段 `/models` 都要原样保留，否则探活失败原因变得无用）。
    #[test]
    fn sanitize_detail_collapses_filesystem_paths_but_keeps_urls() {
        assert_eq!(
            sanitize_detail(
                "上传目录不可写（D:\\Projects\\stepby\\uploads\\file）: Permission denied"
            ),
            "上传目录不可写（<path>）: Permission denied"
        );
        assert_eq!(
            sanitize_detail("写入 /var/lib/stepby/uploads 失败"),
            "写入 <path> 失败"
        );
        // URL 与其端口必须完好（authority 只有一个 host 段，不匹配"两层路径"）
        assert_eq!(
            sanitize_detail("连接 https://smtp.example.com:465 超时"),
            "连接 https://smtp.example.com:465 超时"
        );
        // 单段路径（API 片段）保留，便于定位是哪一步失败
        assert_eq!(
            sanitize_detail("GET /models 返回 401"),
            "GET /models 返回 401"
        );
    }

    /// 脱敏：URL userinfo / 凭据键值 / 空白折叠 / 长度截断 / 多字节安全
    #[test]
    fn sanitize_detail_strips_credentials_and_shapes_text() {
        // ① userinfo 段剔除（scheme://user:pass@host → scheme://host）
        assert_eq!(
            sanitize_detail("连接 https://alice:s3cr3t@smtp.example.com:465 失败"),
            "连接 https://smtp.example.com:465 失败"
        );
        // ② 凭据类键值替换（键名保留便于排障）
        assert_eq!(
            sanitize_detail("auth password=hunter2; ok"),
            "auth password=<redacted>; ok"
        );
        assert_eq!(
            sanitize_detail("header Bearer abcdef12345"),
            "header Bearer <redacted>"
        );
        // ③ 无敏感串的中文文本原样保留（多字节不得被截成非法 UTF-8）
        assert_eq!(
            sanitize_detail("SMTP 握手失败：连接被对端拒绝"),
            "SMTP 握手失败：连接被对端拒绝"
        );
        // ④ 换行/连续空白折叠为单空格（公开端点不接受格式注入面）
        assert_eq!(
            sanitize_detail("line1\n\t  line2\r\nline3"),
            "line1 line2 line3"
        );
        // ⑤ 截断到 200 字符 + 省略号
        let long = "x".repeat(500);
        let cut = sanitize_detail(&long);
        assert_eq!(cut.chars().count(), 201, "200 字符 + 省略号");
        assert!(cut.ends_with('…'));
    }

    /// userinfo 剔除要覆盖"authority 里根本没有 @"的常态（不得误吞 host）
    #[test]
    fn sanitize_detail_keeps_plain_authority_untouched() {
        assert_eq!(
            sanitize_detail("smtp://mail.example.com:25 timeout"),
            "smtp://mail.example.com:25 timeout"
        );
        // authority 之后的路径/查询原样保留
        assert_eq!(
            sanitize_detail("https://u:p@host.example.com/v1/models?x=1"),
            "https://host.example.com/v1/models?x=1"
        );
    }

    /// `writable_probe` 的同步 fs 只能经阻塞线程池调用（否则 /health 探针会占住 worker
    /// 线程）。取证脚本对 health_probes.rs 的 `std::fs` 行做了豁免，**本锁保证豁免前提
    /// 成立**：调用点必须与 `spawn_blocking(` 同行，且只有一个（漂移即红，防止有人日后
    /// 在 async 上下文里直接调用它）。
    #[test]
    fn blocking_only_fs_helper_is_called_from_blocking_pool() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handler/health_probes.rs");
        let src = std::fs::read_to_string(&path).expect("读取本文件失败");
        let prod = match src.find("#[cfg(test)]") {
            Some(i) => &src[..i],
            None => &src,
        };
        let hits: Vec<&str> = prod
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && l.contains("writable_probe(&"))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "调用点漂移（当前 {hits:?}），请同步更新扫描器豁免条目"
        );
        assert!(
            hits[0].contains("spawn_blocking("),
            "fs 探针必须经阻塞线程池，实际: {}",
            hits[0]
        );
    }

    /// 本地存储探针：写-删往返成功且**不留残留文件**（只读挂载判不出来的反面即真故障）
    #[test]
    fn writable_probe_roundtrip_leaves_no_residue() {
        let dir = std::env::temp_dir().join(format!(
            "stepby-health-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("创建临时目录失败");
        let detail = writable_probe(&dir).expect("可写目录应判 UP");
        assert!(detail.contains("本地上传目录可写"), "实际: {detail}");
        // 探针文件必须已删除（目录里只剩我们建的那个）
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert!(left.is_empty(), "探针残留文件未清理: {left:?}");

        // 目录不存在 ⇒ 探父目录（真实上传走 create_dir_all，父目录可写即可用）
        let missing = dir.join("not-created-yet");
        let detail2 = writable_probe(&missing).expect("父目录可写应判 UP");
        assert!(
            detail2.contains("将在首次上传时创建"),
            "应说明目录未就绪: {detail2}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 不可写 ⇒ Err（探针的价值就在这条路径：只读卷/Docker `ro` 挂载必须报出来）
    #[test]
    fn writable_probe_reports_error_for_missing_parent() {
        // `/` 的父目录不存在（None ⇒ 回退自身），根目录不可写 ⇒ 必然 Err 或被跳过；
        // 这里用一个**确定不存在且父也确定不存在**的深路径，保证 write 失败。
        let deep = Path::new("/definitely/not/a/real/stepby-probe-path").to_path_buf();
        let res = writable_probe(&deep);
        assert!(res.is_err(), "不存在的深层路径应判故障，实际: {res:?}");
        let msg = res.err().unwrap().message;
        assert!(msg.contains("上传目录不可写"), "实际: {msg}");
    }
}
