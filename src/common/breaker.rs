// stepby-axum/src/common/breaker.rs
//! #10：**进程内出站 webhook 熔断**（`[resilience] outbound_breaker`）。
//!
//! ## 背景：为什么需要它
//!
//! `[acme]`（证书需求输出）与 `[events]`（领域事件输出）都是 "fire-and-forget POST"：
//! 每次事件 `spawn` 一个后台请求，失败只打 WARN。当目标端点下线时，**每一个事件**都会
//! 再打一次请求 + 一条 WARN —— 既浪费连接/超时预算，又用日志淹没真正的告警。
//!
//! 本模块把"是否放行发送"与"结果记账"收敛到**两个出站共用的进程内熔断内核**：
//! 连续失败达到阈值即打开熔断，冷却期内**直接跳过发送**，到期放行**一次探测**（半开）。
//!
//! ## 默认值 = 现状（关闭态零行为变更）
//!
//! `off`（默认）下 [`try_acquire_at`] 恒 `true`、[`record_at`] 为**空操作且不写任何状态**
//! ⇒ 每次事件照常发送、照常记 WARN，与改造前逐字节等价。非法档位取值回落 `off` 并打 WARN
//! （fail-safe，不拒绝启动）。
//!
//! ## 为什么把 `now: Instant` 作为显式参数
//!
//! 熔断是**时序状态机**（Closed / Open / HalfOpen），把 `Instant` 显式传入可让纯核在**单测中
//! 自由"拨钟"**（无需 sleep、无 flaky），生产路径由 [`try_acquire`] / [`record`] 传入
//! `Instant::now()`。
//!
//! ## 日志口径
//!
//! - **跳过发送**打 `DEBUG`（高频，避免日志风暴）；
//! - **状态迁移**（打开熔断 / 熔断恢复）打 `WARN`，且 URL **只记 host**（目标地址可能含
//!   secret / query，必须脱敏）。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::settings::Settings;

/// 熔断档位字面量（顺序：默认项在前，便于阅读时确认"默认为现状"）
pub const BREAKER_MODES: &[&str] = &["off", "on"];

/// 出站 webhook 熔断档位（项目准则③：取「模式」而非裸 bool）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BreakerMode {
    /// **默认 = 现状**：不做任何熔断，每次都尝试发送。
    #[default]
    Off,
    /// 连续失败达阈值后打开熔断，冷却期内跳过发送，到期放行一次探测（半开）。
    On,
}

impl BreakerMode {
    /// 解析配置串（大小写无关、两端 trim）；未登记取值一律回落 [`BreakerMode::Off`] 并打 WARN。
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "on" => Self::On,
            "off" => Self::Off,
            other => {
                tracing::warn!(
                    value = %other,
                    fallback = "off",
                    allowed = ?BREAKER_MODES,
                    "配置 [resilience].outbound_breaker 取值非法，已回落 off（= 现状：每次都尝试发送）"
                );
                Self::Off
            }
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }
}

/// 失败阈值下界 / 上界（夹取，防止配成 0（恒打开）或过大（形同关闭））。
pub const FAILURE_THRESHOLD_MIN: u32 = 1;
pub const FAILURE_THRESHOLD_MAX: u32 = 1000;
/// 冷却秒数下界 / 上界（夹取，防止配成 0（立即半开）或过大（长时间不探测））。
pub const COOLDOWN_SECS_MIN: u64 = 1;
pub const COOLDOWN_SECS_MAX: u64 = 86_400;

/// 熔断运行参数（**已解析 + 已夹取**）：由 [`BreakerConfig::from_settings`] 从 `[resilience]` 段构造。
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    pub mode: BreakerMode,
    /// 连续失败达到该次数 ⇒ 打开熔断（已夹取 `1..=1000`）。
    pub failure_threshold: u32,
    /// 打开后的冷却秒数，到期放行一次探测（已夹取 `1..=86400`）。
    pub cooldown_secs: u64,
}

impl BreakerConfig {
    /// 从 `[resilience]` 段构造（非法 mode 由 [`BreakerMode::parse`] 打 WARN 并回落 `off`；
    /// 数值越界夹取到上下界）。
    pub fn from_settings(settings: &Settings) -> Self {
        let r = &settings.resilience;
        Self {
            mode: BreakerMode::parse(&r.outbound_breaker),
            failure_threshold: r
                .failure_threshold
                .clamp(FAILURE_THRESHOLD_MIN, FAILURE_THRESHOLD_MAX),
            cooldown_secs: r.cooldown_secs.clamp(COOLDOWN_SECS_MIN, COOLDOWN_SECS_MAX),
        }
    }

    pub fn cooldown(&self) -> Duration {
        Duration::from_secs(self.cooldown_secs)
    }
}

/// 单个 URL 的熔断状态机。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakerState {
    /// 闭合：正常放行；记录连续失败次数。
    Closed { consecutive_failures: u32 },
    /// 打开：冷却期内一律不放行；记录打开时刻用于判定到期。
    Open { opened_at: Instant },
    /// 半开：冷却到期后**只放行一次探测**（`probe_pending` 为真表示已有探测在途）。
    HalfOpen { probe_pending: bool },
}

/// **可测纯核**：不依赖全局、不依赖 tokio，`now: Instant` 由调用方显式传入。
///
/// 内部状态用 `std::sync::Mutex<HashMap<..>>` 保护（出站频率低，锁竞争可忽略；
/// 刻意不引入新依赖）。
#[derive(Debug)]
pub struct BreakerRegistry {
    mode: BreakerMode,
    failure_threshold: u32,
    cooldown: Duration,
    states: Mutex<HashMap<String, BreakerState>>,
}

impl BreakerRegistry {
    pub fn new(mode: BreakerMode, failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            mode,
            failure_threshold,
            cooldown,
            states: Mutex::new(HashMap::new()),
        }
    }

    /// 由 [`BreakerConfig`] 构造。
    pub fn from_config(cfg: &BreakerConfig) -> Self {
        Self::new(cfg.mode, cfg.failure_threshold, cfg.cooldown())
    }

    /// 是否放行**本次**发送。
    ///
    /// - `Off`：恒 `true`，且**不写任何状态**（关闭态零行为变更）。
    /// - `On`：`Open` 且未到冷却 ⇒ `false`；到期 ⇒ 转 `HalfOpen` 并**只放行一次**；
    ///   已有探测在途时再调 ⇒ `false`。
    pub fn try_acquire_at(&self, url: &str, now: Instant) -> bool {
        if self.mode == BreakerMode::Off {
            return true; // 关闭态：不写状态，不做判定
        }
        let mut states = self.lock();
        match states.get(url).copied() {
            Some(BreakerState::Open { opened_at }) => {
                if now.duration_since(opened_at) >= self.cooldown {
                    // 冷却到期：转半开，放行本次探测
                    states.insert(
                        url.to_string(),
                        BreakerState::HalfOpen {
                            probe_pending: true,
                        },
                    );
                    true
                } else {
                    false
                }
            }
            Some(BreakerState::HalfOpen {
                probe_pending: true,
            }) => false, // 探测在途，不放行
            Some(BreakerState::HalfOpen {
                probe_pending: false,
            }) => {
                // 理论不可达（半开态要么在放行时置 pending，要么立即转 Closed/Open）；
                // 保守起见：补放行一次。
                states.insert(
                    url.to_string(),
                    BreakerState::HalfOpen {
                        probe_pending: true,
                    },
                );
                true
            }
            Some(BreakerState::Closed { .. }) | None => true,
        }
    }

    /// 记录一次发送结果。
    ///
    /// - `Off`：空操作（**不写任何状态**）。
    /// - 成功 ⇒ `Closed{0}`（来自 `HalfOpen` 时打 WARN"熔断恢复"）。
    /// - 失败 ⇒ `Closed{n+1}`；`n+1 >= threshold` ⇒ `Open{now}` 并打 WARN（host + 连续失败数）；
    ///   半开失败 ⇒ 直接 `Open{now}`（重新计时）。
    pub fn record_at(&self, url: &str, success: bool, now: Instant) {
        if self.mode == BreakerMode::Off {
            return; // 关闭态：不写状态
        }
        let mut states = self.lock();
        let current = states.get(url).copied();
        if success {
            if matches!(current, Some(BreakerState::HalfOpen { .. })) {
                tracing::warn!(
                    host = %host_of(url),
                    "出站 webhook 熔断恢复（探测成功，目标端点已可用）"
                );
            }
            states.insert(
                url.to_string(),
                BreakerState::Closed {
                    consecutive_failures: 0,
                },
            );
            return;
        }
        let prev_failures = match current {
            Some(BreakerState::Closed {
                consecutive_failures,
            }) => consecutive_failures,
            _ => 0,
        };
        match current {
            Some(BreakerState::HalfOpen { .. }) => {
                states.insert(url.to_string(), BreakerState::Open { opened_at: now });
                tracing::warn!(
                    host = %host_of(url),
                    "出站 webhook 熔断保持打开（半开探测失败，重新进入冷却）"
                );
            }
            Some(BreakerState::Open { .. }) => {
                // 理论不可达（打开态不发送）；保守起见刷新计时
                states.insert(url.to_string(), BreakerState::Open { opened_at: now });
            }
            Some(BreakerState::Closed { .. }) | None => {
                let n = prev_failures + 1;
                if n >= self.failure_threshold {
                    states.insert(url.to_string(), BreakerState::Open { opened_at: now });
                    tracing::warn!(
                        host = %host_of(url),
                        consecutive_failures = n,
                        threshold = self.failure_threshold,
                        cooldown_secs = self.cooldown.as_secs(),
                        "出站 webhook 连续失败达阈值，熔断打开（冷却期内跳过发送）"
                    );
                } else {
                    states.insert(
                        url.to_string(),
                        BreakerState::Closed {
                            consecutive_failures: n,
                        },
                    );
                }
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, BreakerState>> {
        self.states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// **仅测试用**：某 URL 是否存在内部状态（用于可证伪"关闭态不记账"）。
    #[cfg(test)]
    fn has_state(&self, url: &str) -> bool {
        self.lock().contains_key(url)
    }
}

/// 提取 URL 的 **host**（脱敏：不记 secret / query / path）。
///
/// 简单字符串处理（不引入新依赖）：去掉 `scheme://`，再截断到第一个 `/` `?` `#`。
/// 解析不出 host 时回退为 `"<unknown>"`。
pub fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest).trim();
    // 用户信息 `user:pass@host` 只保留 host 部分（避免凭据进日志）
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    if host.is_empty() { "<unknown>" } else { host }
}

/// 全局单例（启动期由 `initialize` 注入；未初始化 = 关闭态）。
static REGISTRY: OnceLock<BreakerRegistry> = OnceLock::new();

/// 启动期注入（**幂等**：重复调用只保留首次）。打印当前档位/阈值/冷却。
pub fn init(cfg: BreakerConfig) {
    let registry = BreakerRegistry::from_config(&cfg);
    let mode = cfg.mode;
    if REGISTRY.set(registry).is_ok() {
        tracing::info!(
            mode = mode.as_str(),
            failure_threshold = cfg.failure_threshold,
            cooldown_secs = cfg.cooldown_secs,
            "出站 webhook 熔断已注入（off = 现状：每次都尝试发送）"
        );
    }
}

/// 是否放行**本次**发送（内部取 `Instant::now()`）。
///
/// **未 `init` 时按 `Off` 处理**（未初始化 = 关闭态 ⇒ 恒 `true`，零行为变更）。
pub fn try_acquire(url: &str) -> bool {
    match REGISTRY.get() {
        Some(registry) => registry.try_acquire_at(url, Instant::now()),
        None => true,
    }
}

/// 记录一次发送结果（内部取 `Instant::now()`）。未 `init` 时空操作。
pub fn record(url: &str, success: bool) {
    if let Some(registry) = REGISTRY.get() {
        registry.record_at(url, success, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on(threshold: u32, cooldown_secs: u64) -> BreakerRegistry {
        BreakerRegistry::new(
            BreakerMode::On,
            threshold,
            Duration::from_secs(cooldown_secs),
        )
    }

    fn off() -> BreakerRegistry {
        BreakerRegistry::new(BreakerMode::Off, 5, Duration::from_secs(60))
    }

    /// 1. `off` ⇒ 恒 true；连续 100 次失败后仍 true；且**内部无该 url 状态**（关闭态不记账）。
    #[test]
    fn test_off_never_blocks_and_records_nothing() {
        let reg = off();
        let now = Instant::now();
        let url = "https://hook.example.com/x";
        for _ in 0..100 {
            reg.record_at(url, false, now);
        }
        assert!(reg.try_acquire_at(url, now), "off 档必须恒放行");
        assert!(
            !reg.has_state(url),
            "off 档不得写入任何状态（关闭态零行为变更，可证伪）"
        );
    }

    /// 2. `on`：连续 `threshold` 次失败 ⇒ 下一次 `try_acquire` 为 false（冷却期内恒 false）。
    #[test]
    fn test_on_opens_after_threshold_and_blocks() {
        let reg = on(5, 60);
        let t0 = Instant::now();
        let url = "https://hook.example.com/a";
        for i in 0..5 {
            assert!(reg.try_acquire_at(url, t0), "未达阈值前应放行（第 {i} 次）");
            reg.record_at(url, false, t0);
        }
        assert!(!reg.try_acquire_at(url, t0), "达阈值后应立即阻断");
        assert!(
            !reg.try_acquire_at(url, t0 + Duration::from_secs(59)),
            "冷却期内必须恒 false"
        );
    }

    /// 3. 冷却到期 ⇒ 放行一次；再调一次（探测未回）⇒ false（半开只放一个探测）。
    #[test]
    fn test_cooldown_expiry_allows_single_probe() {
        let reg = on(3, 30);
        let t0 = Instant::now();
        let url = "https://hook.example.com/b";
        for _ in 0..3 {
            reg.record_at(url, false, t0);
        }
        let t1 = t0 + Duration::from_secs(30);
        assert!(reg.try_acquire_at(url, t1), "冷却到期应放行一次探测");
        assert!(
            !reg.try_acquire_at(url, t1),
            "探测在途时再调必须 false（半开只放一个探测）"
        );
    }

    /// 4. 探测成功 ⇒ 回到 Closed 并清零 ⇒ 之后恒 true。
    #[test]
    fn test_probe_success_closes_and_resets() {
        let reg = on(3, 30);
        let t0 = Instant::now();
        let url = "https://hook.example.com/c";
        for _ in 0..3 {
            reg.record_at(url, false, t0);
        }
        let t1 = t0 + Duration::from_secs(30);
        assert!(reg.try_acquire_at(url, t1));
        reg.record_at(url, true, t1);
        for _ in 0..10 {
            assert!(reg.try_acquire_at(url, t1), "恢复后应恒放行");
        }
    }

    /// 5. 探测失败 ⇒ 回到 Open 并**重新计时**（立即 `try_acquire` 为 false）。
    #[test]
    fn test_probe_failure_reopens_and_restarts_cooldown() {
        let reg = on(3, 30);
        let t0 = Instant::now();
        let url = "https://hook.example.com/d";
        for _ in 0..3 {
            reg.record_at(url, false, t0);
        }
        let t1 = t0 + Duration::from_secs(30);
        assert!(reg.try_acquire_at(url, t1));
        reg.record_at(url, false, t1);
        assert!(!reg.try_acquire_at(url, t1), "探测失败后立即应阻断");
        assert!(
            !reg.try_acquire_at(url, t1 + Duration::from_secs(29)),
            "冷却须从探测失败时刻重新计时"
        );
        assert!(
            reg.try_acquire_at(url, t1 + Duration::from_secs(30)),
            "重新计时满冷却后应再次放行探测"
        );
    }

    /// 6. 成功会清零"未达阈值"的连续失败计数。
    #[test]
    fn test_success_resets_below_threshold_count() {
        let reg = on(5, 60);
        let t0 = Instant::now();
        let url = "https://hook.example.com/e";
        reg.record_at(url, false, t0);
        reg.record_at(url, false, t0);
        reg.record_at(url, true, t0); // 清零
        for _ in 0..4 {
            // threshold-1 = 4 次失败仍不应打开
            reg.record_at(url, false, t0);
        }
        assert!(
            reg.try_acquire_at(url, t0),
            "成功应清零计数：再失败 threshold-1 次仍应放行"
        );
        reg.record_at(url, false, t0); // 第 5 次（达到阈值）
        assert!(!reg.try_acquire_at(url, t0));
    }

    /// 7. 多 url 相互隔离（A 打开不影响 B）。
    #[test]
    fn test_urls_are_isolated() {
        let reg = on(2, 60);
        let t0 = Instant::now();
        let a = "https://hook.example.com/a";
        let b = "https://hook.example.com/b";
        reg.record_at(a, false, t0);
        reg.record_at(a, false, t0);
        assert!(!reg.try_acquire_at(a, t0));
        assert!(reg.try_acquire_at(b, t0), "A 打开不得影响 B");
    }

    /// 8. 解析与夹取：非法 mode ⇒ Off；阈值/冷却越界夹取到上下界。
    #[test]
    fn test_parse_and_clamp() {
        assert_eq!(BreakerMode::parse("on"), BreakerMode::On);
        assert_eq!(BreakerMode::parse("  ON  "), BreakerMode::On);
        assert_eq!(BreakerMode::parse("off"), BreakerMode::Off);
        assert_eq!(BreakerMode::parse("OFF"), BreakerMode::Off);
        for bad in ["", "strict", "true", "1", "enable"] {
            assert_eq!(
                BreakerMode::parse(bad),
                BreakerMode::Off,
                "{bad:?} 非法值必须回落 off（默认=现状）"
            );
        }
        assert_eq!(BreakerMode::default(), BreakerMode::Off);
        assert_eq!(BreakerMode::On.as_str(), "on");
        assert_eq!(BreakerMode::Off.as_str(), "off");
        // 常量清单与枚举双向一致
        assert_eq!(BREAKER_MODES.len(), 2);
        for raw in BREAKER_MODES {
            assert_eq!(BreakerMode::parse(raw).as_str(), *raw);
        }
        // 夹取
        assert_eq!(0u32.clamp(FAILURE_THRESHOLD_MIN, FAILURE_THRESHOLD_MAX), 1);
        assert_eq!(
            100_000u32.clamp(FAILURE_THRESHOLD_MIN, FAILURE_THRESHOLD_MAX),
            1000
        );
        assert_eq!(0u64.clamp(COOLDOWN_SECS_MIN, COOLDOWN_SECS_MAX), 1);
        assert_eq!(
            100_000_000u64.clamp(COOLDOWN_SECS_MIN, COOLDOWN_SECS_MAX),
            86_400
        );
    }

    /// 8b. `from_settings`：从 `[resilience]` 段取模式并夹取数值。
    #[test]
    fn test_from_settings_parses_and_clamps() {
        let mut s = minimal_settings();
        s.resilience.outbound_breaker = "on".to_string();
        s.resilience.failure_threshold = 0;
        s.resilience.cooldown_secs = 0;
        let cfg = BreakerConfig::from_settings(&s);
        assert_eq!(cfg.mode, BreakerMode::On);
        assert_eq!(cfg.failure_threshold, 1);
        assert_eq!(cfg.cooldown_secs, 1);

        s.resilience.outbound_breaker = "bogus".to_string();
        s.resilience.failure_threshold = 999_999;
        s.resilience.cooldown_secs = 999_999_999;
        let cfg = BreakerConfig::from_settings(&s);
        assert_eq!(cfg.mode, BreakerMode::Off, "非法档位必须回落 off");
        assert_eq!(cfg.failure_threshold, 1000);
        assert_eq!(cfg.cooldown_secs, 86_400);
    }

    /// 9. 未 `init` 时全局 `try_acquire` 恒 true（未初始化 = 关闭态）。
    #[test]
    fn test_global_before_init_is_off() {
        // 注意：本模块内**没有任何**用例调用 `init`，故 REGISTRY 恒为未初始化；
        // 生产路径的 init 只在 `initialize::AppInitializer::run` 中调用。
        for _ in 0..5 {
            assert!(try_acquire("https://hook.example.com/never-init"));
            record("https://hook.example.com/never-init", false);
        }
        assert!(try_acquire("https://hook.example.com/never-init"));
    }

    /// host 提取：只保留 host（去 scheme / path / query / 用户信息）。
    #[test]
    fn test_host_of() {
        assert_eq!(
            host_of("https://ops.example.com/hook?x=1"),
            "ops.example.com"
        );
        assert_eq!(host_of("http://10.0.0.1:9000/a/b"), "10.0.0.1:9000");
        assert_eq!(
            host_of("https://user:pw@ops.example.com/x"),
            "ops.example.com"
        );
        assert_eq!(host_of("https://ops.example.com"), "ops.example.com");
        assert_eq!(host_of(""), "<unknown>");
    }

    /// 构造 `Settings` 供 `from_settings` 用例使用：直接反序列化**入库模板**
    /// `config/config.toml.example`（cargo test 的 CWD = crate 根）。
    ///
    /// 好处有二：① 不必手写"最小配置"（任何新增必填字段都会让手写夹具失效）；
    /// ② 顺带锁定"入库模板可被完整反序列化为 `Settings`"这一不变式。
    fn minimal_settings() -> Settings {
        let content = std::fs::read_to_string("config/config.toml.example")
            .expect("入库模板 config/config.toml.example 必须存在");
        toml::from_str::<Settings>(&content)
            .expect("入库模板 config/config.toml.example 应可反序列化为 Settings")
    }
}
