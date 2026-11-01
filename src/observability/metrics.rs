// stepby-axum/src/observability/metrics.rs
//! 轻量 Prometheus 文本格式指标（零外部依赖）
//!
//! 由于后端已有 /metrics 端点（health.rs）暴露进程级指标，本模块补充 **HTTP 业务指标**：
//! - `stepby_http_requests_total{method,status,path}`（counter）
//! - `stepby_http_request_duration_seconds_bucket/sum/count`（histogram）
//!
//! 存储为进程内 `RwLock<HashMap>`，通过全局静态 `OnceLock<Arc<MetricsRegistry>>` 共享。
//! 由 `observability::monitoring_middleware` 在每个请求上记录，
//! 并在 `/metrics` handler 中与健康检查指标合并输出，Prometheus 可直接抓取。
//!
//! 正确性说明：bucket 采用 `value <= le` 的累计计数语义，`+Inf` 桶为总观测数，
//! 符合 Prometheus 直方图约定（可被 rate/histogram_quantile 消费）。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

/// 直方图采样桶边界（秒）。默认 `[5ms,10,25,50,100,250,500,1000ms]`。
pub const DURATION_BUCKETS_S: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];

/// Web Vitals 直方图采样桶边界（秒）。边界对齐 perf-budget.json 运行时预算：
/// FCP ≤ 1.8s、LCP ≤ 2.5s（prometheus histogram_quantile(0.95) 可直接与预算比对）。
pub const VITAL_BUCKETS_S: &[f64] = &[0.1, 0.25, 0.5, 1.0, 1.8, 2.5, 4.0, 8.0];

/// 定时任务耗时直方图采样桶边界（秒，G-09）。
/// 任务耗时量级远大于 HTTP 请求（内置任务普遍 10ms~数分钟），独立桶边界：
/// [100ms, 250ms, 500ms, 1s, 5s, 30s, 60s, 300s]。
pub const JOB_DURATION_BUCKETS_S: &[f64] = &[0.1, 0.25, 0.5, 1.0, 5.0, 30.0, 60.0, 300.0];

/// 时间型 vitals 白名单（CLS 是无量纲分数，走 gauge 单独承载）
pub const VITAL_TIME_NAMES: &[&str] = &["LCP", "FCP", "INP", "TTFB"];
/// 设备类型分桶白名单（FCP-011，与前端 frontendErrorReporter.detectDeviceType 对齐）
pub const VITAL_DEVICES: &[&str] = &["mobile", "tablet", "desktop", "unknown"];

/// 标签组（method + status + path）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LabelSet {
    method: String,
    status: String,
    path: String,
}

/// 某标签组的直方图累计数据
struct DurationSeries {
    count: u64,
    sum_secs: f64,
    /// 长度 = BUCKET_COUNT，`buckets[i]` = 观测值 <= `bounds[i]` 的条数
    buckets: Vec<u64>,
}
impl Default for DurationSeries {
    fn default() -> Self {
        Self {
            count: 0,
            sum_secs: 0.0,
            buckets: vec![0; DURATION_BUCKETS_S.len()],
        }
    }
}

/// 指标注册表
pub struct MetricsRegistry {
    counters: RwLock<HashMap<LabelSet, u64>>,
    durations: RwLock<HashMap<LabelSet, DurationSeries>>,
    total_requests: AtomicU64,
    /// v5-D7：SSO 事件计数（event, outcome）→ 次数（token_issued/token_refreshed/
    /// token_revoked/authorize/logout × ok/各错误码）
    sso_counters: RwLock<HashMap<(String, String), u64>>,
    /// FCP-010：Web Vitals 时间型指标直方图（name ∈ LCP/FCP/INP/TTFB，device ∈ 分桶）
    vitals: RwLock<HashMap<(String, String), VitalSeries>>,
    /// FCP-010：CLS 最新累计值（无量纲分数；会话语义 = "当前页面累计偏移"，gauge 承载）
    cls_gauges: RwLock<HashMap<String, f64>>,
    /// AK 开放 API 请求计数（path, outcome）→ 次数。
    /// outcome：`ok` 或验签失败原因（invalid_signature/timestamp_out_of_window/
    /// nonce_reused/ak_not_found/ak_revoked/expired/owner_disabled/store_unavailable），
    /// 由 `ak_sign` 中间件每请求记录一次。
    ak_counters: RwLock<HashMap<(String, String), u64>>,
    /// AK 开放 API 验签失败计数（reason → 次数；outcome != "ok" 时累计）
    ak_failures: RwLock<HashMap<String, u64>>,
    /// AK 开放 API 耗时直方图（path → 系列，桶边界复用 DURATION_BUCKETS_S）
    ak_durations: RwLock<HashMap<String, DurationSeries>>,
    /// 批七十四 B6：凭据校验计数（algorithm, outcome）→ 次数。
    /// algorithm：`argon2id` / `md5-legacy` / `unknown`（空哈希或哈希串不可解析）；
    /// outcome：`ok` / `mismatch` / `empty_hash` / `malformed_hash`。
    credential_counters: RwLock<HashMap<(String, String), u64>>,
    /// 批七十四 B6：凭据校验耗时直方图（algorithm → 系列，桶边界复用 DURATION_BUCKETS_S）。
    /// 存在的理由：Argon2 的 m/t/p 是**有意的** CPU 成本，参数或依赖一漂移就会悄悄改变
    /// 登录延迟；没有观测面时只能等用户报"登录变慢"（B6 的"可观测"半边）。
    credential_durations: RwLock<HashMap<String, DurationSeries>>,
    /// G-09：定时任务执行计数（job_name, status）→ 次数。
    /// status："0"=成功 / "1"=失败（与 sys_job_log.status 口径一致）。
    job_counters: RwLock<HashMap<(String, String), u64>>,
    /// G-09：定时任务耗时直方图（job_name → 系列，桶边界 JOB_DURATION_BUCKETS_S）
    job_durations: RwLock<HashMap<String, JobDurationSeries>>,
    /// b72（AGENTS #4 组件级指标）：出站依赖 / 后台任务计数（component,outcome）→ 次数。
    /// outcome：`ok` / `error` / `timeout` / `panic` / `rejected`（背压或闸门拒绝）
    outbound_counters: RwLock<HashMap<(String, String), u64>>,
    /// b72：出站依赖 / 后台任务耗时直方图（component → 系列）
    outbound_durations: RwLock<HashMap<String, OutboundDurationSeries>>,
    /// b147：操作录制链路事件计数（phase, outcome）→ 次数。
    ///
    /// phase：`capture`（中间件把一次请求记进录制）/ `preview`（预检）/ `replay`（真执行）；
    /// outcome：采集侧 `recorded|not_mutating|excluded|bad_path|full|error`，
    /// 执行侧 `success|failed|partial`。
    ///
    /// 为什么不复用 `outbound_counters`：那一族的语义是"出站依赖的健康度"，
    /// 把"这次请求因为路径在排除清单里所以没录"记进去，会让出站故障率出现
    /// 与自己无关的噪声（AGENTS B.4「口径失真比缺指标更糟」）。
    recording_counters: RwLock<HashMap<(String, String), u64>>,
    /// 告警指标源：最近 5xx 响应时间戳环形缓冲（真实记录点 =
    /// [`MetricsRegistry::record`]，由 monitoring_middleware 每请求调用）。
    ///
    /// 累计 counter（`counters`）无法回答"最近 N 分钟"窗口问题，故单独维护
    /// 有界时间戳队列：`count_recent_5xx` 按窗口过滤计数。进程内口径
    /// （重启清零、多实例各自统计），与 Prometheus 抓取口径互补不冲突。
    recent_5xx: Mutex<VecDeque<std::time::Instant>>,
}

/// 5xx 环形缓冲容量上限（超出丢弃最旧记录）：
/// 极端场景（5 分钟内 >4096 个 5xx）下告警已必然触发，无需无限累积。
const RECENT_5XX_MAX_ENTRIES: usize = 4096;

/// Web Vitals 直方图系列（桶边界与 DurationSeries 不同，独立类型避免长度耦合）
struct VitalSeries {
    count: u64,
    sum_secs: f64,
    buckets: Vec<u64>,
}

impl VitalSeries {
    fn new() -> Self {
        Self {
            count: 0,
            sum_secs: 0.0,
            buckets: vec![0; VITAL_BUCKETS_S.len()],
        }
    }
}

/// G-09：定时任务耗时直方图系列（桶边界 JOB_DURATION_BUCKETS_S，与 HTTP/vitals 独立）
struct JobDurationSeries {
    count: u64,
    sum_secs: f64,
    buckets: Vec<u64>,
}

/// b72：出站依赖 / 后台任务耗时直方图系列。
///
/// 复用 [`JOB_DURATION_BUCKETS_S`]（0.1s~300s）而非 HTTP 的 5ms~1s 桶：
/// SMTP/S3/LLM 推理这类调用天然在秒级~分钟级，用 HTTP 桶会把全部样本挤进 `+Inf`，
/// 直方图失去区分度（"有指标"不等于"指标可用"）。
type OutboundDurationSeries = JobDurationSeries;

impl JobDurationSeries {
    fn new() -> Self {
        Self {
            count: 0,
            sum_secs: 0.0,
            buckets: vec![0; JOB_DURATION_BUCKETS_S.len()],
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            durations: RwLock::new(HashMap::new()),
            total_requests: AtomicU64::new(0),
            sso_counters: RwLock::new(HashMap::new()),
            vitals: RwLock::new(HashMap::new()),
            cls_gauges: RwLock::new(HashMap::new()),
            ak_counters: RwLock::new(HashMap::new()),
            ak_failures: RwLock::new(HashMap::new()),
            ak_durations: RwLock::new(HashMap::new()),
            credential_counters: RwLock::new(HashMap::new()),
            credential_durations: RwLock::new(HashMap::new()),
            job_counters: RwLock::new(HashMap::new()),
            job_durations: RwLock::new(HashMap::new()),
            outbound_counters: RwLock::new(HashMap::new()),
            recording_counters: RwLock::new(HashMap::new()),
            outbound_durations: RwLock::new(HashMap::new()),
            recent_5xx: Mutex::new(VecDeque::new()),
        }
    }
}

/// 全局共享实例
static GLOBAL: OnceLock<Arc<MetricsRegistry>> = OnceLock::new();

/// b72：出站遥测的 **RAII 守卫**，用于有多个 `?` 提前返回的出站函数（LLM 推理 / IdP 令牌交换）。
///
/// 为什么用它而不是在每个出口写一次 `record_outbound`：这类函数常有 5~6 条失败出口
/// （未配置 / 发送失败 / 非 2xx / 解析失败 / 字段缺失），逐出口埋点**必然漏**且新增分支不会提醒；
/// 守卫在 `Drop` 时按"是否显式 `succeeded()`"定性，保证任何路径都计数一次。
///
/// 用法（伪码，非可编译示例）：
/// ```text
/// let mut tel = OutboundGuard::start("ai");
/// …? ;
/// tel.succeeded();
/// Ok(value)
/// ```
pub struct OutboundGuard {
    component: &'static str,
    started: std::time::Instant,
    ok: bool,
}

impl OutboundGuard {
    pub fn start(component: &'static str) -> Self {
        Self {
            component,
            started: std::time::Instant::now(),
            ok: false,
        }
    }

    /// 标记本次出站**成功**（不调用则按 `error` 记录）
    pub fn succeeded(&mut self) {
        self.ok = true;
    }
}

impl Drop for OutboundGuard {
    fn drop(&mut self) {
        MetricsRegistry::global().record_outbound(
            self.component,
            if self.ok { "ok" } else { "error" },
            self.started.elapsed().as_secs_f64(),
        );
    }
}

impl MetricsRegistry {
    /// 获取全局共享实例
    pub fn global() -> Arc<Self> {
        GLOBAL
            .get_or_init(|| Arc::new(MetricsRegistry::default()))
            .clone()
    }

    /// 记录一次请求
    pub fn record(&self, method: &str, status: u16, path: &str, duration_secs: f64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let key = LabelSet {
            method: method.to_string(),
            status: status.to_string(),
            path: path.to_string(),
        };
        // counter
        let mut counters = match self.counters.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *counters.entry(key.clone()).or_insert(0) += 1;
        drop(counters);

        // 5xx 窗口缓冲（告警指标源 http_5xx_5m）：真实响应状态 >= 500 时登记时间戳。
        // 锁持有时间极短（push/pop，不跨 await），中毒时恢复 Guard 防连锁 panic。
        if status >= 500 {
            let mut ring = match self.recent_5xx.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if ring.len() >= RECENT_5XX_MAX_ENTRIES {
                ring.pop_front();
            }
            ring.push_back(std::time::Instant::now());
        }

        // histogram
        let mut durations = match self.durations.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let series = durations.entry(key).or_default();
        series.count += 1;
        series.sum_secs += duration_secs;
        for (i, bound) in DURATION_BUCKETS_S.iter().enumerate() {
            if duration_secs <= *bound {
                series.buckets[i] += 1;
            }
        }
    }

    /// 累计请求总数（无标签）
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// 最近 `window` 时间窗内的 5xx 响应计数（告警指标 http_5xx_5m 的数据源）。
    ///
    /// 顺带清理窗口外过期记录（惰性收缩，避免长尾低流量场景内存滞留）。
    pub fn count_recent_5xx(&self, window: std::time::Duration) -> u64 {
        let mut ring = match self.recent_5xx.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        while let Some(front) = ring.front() {
            if front.elapsed() > window {
                ring.pop_front();
            } else {
                break;
            }
        }
        ring.len() as u64
    }

    /// v5-D7：记录一次 SSO 事件计数（event/outcome 标签组）
    ///
    /// event：`token_issued`（授权码兑换）/`token_refreshed`（RT 轮换）/
    /// `token_revoked`（RFC 7009）/`authorize`（授权端点判定）/`logout`（end_session）
    /// outcome：`ok` 或 OIDC 错误码（invalid_grant/invalid_client/login_required/...）
    pub fn record_sso_event(&self, event: &str, outcome: &str) {
        let mut counters = match self.sso_counters.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *counters
            .entry((event.to_string(), outcome.to_string()))
            .or_insert(0) += 1;
    }

    /// FCP-010：记录一次时间型 Web Vitals 观测（value 单位**秒**）。
    ///
    /// name 仅接受 LCP/FCP/INP/TTFB（白名单外忽略，防标签基数膨胀）；
    /// device 仅接受 mobile/tablet/desktop（未知设备归入 unknown 分桶）。
    /// 值域防御：非有限值或 <=0 忽略；>60s 记为 60s（防离群值撑爆存储）。
    pub fn record_frontend_vital(&self, name: &str, device: &str, value_secs: f64) {
        if !VITAL_TIME_NAMES.contains(&name) || !value_secs.is_finite() || value_secs <= 0.0 {
            return;
        }
        let device = if VITAL_DEVICES.contains(&device) {
            device
        } else {
            "unknown"
        };
        let clamped = value_secs.min(60.0);
        let mut vitals = match self.vitals.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let series = vitals
            .entry((name.to_string(), device.to_string()))
            .or_insert_with(VitalSeries::new);
        series.count += 1;
        series.sum_secs += clamped;
        for (i, bound) in VITAL_BUCKETS_S.iter().enumerate() {
            if clamped <= *bound {
                series.buckets[i] += 1;
            }
        }
    }

    /// FCP-010：更新 CLS 最新累计值（无量纲；按设备分桶取最新值）。
    pub fn set_frontend_cls(&self, device: &str, value: f64) {
        if !value.is_finite() || value < 0.0 {
            return;
        }
        let device = if VITAL_DEVICES.contains(&device) {
            device
        } else {
            "unknown"
        };
        let mut gauges = match self.cls_gauges.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        gauges.insert(device.to_string(), value.min(100.0));
    }

    /// 凭据校验指标（批七十四 B6）：`utils::password` 每次校验记录一次。
    ///
    /// - 计数：`stepby_credential_verify_total{algorithm,outcome}`
    /// - 耗时：`stepby_credential_verify_duration_seconds{algorithm}`
    ///
    /// 为什么值得单独一族（而不是只靠 `/auth/login` 的 HTTP 直方图）：HTTP 桶把"查库 +
    /// 限流 + Argon2"混在一个耗时里，**Argon2 参数漂移看不出来**（登录 120ms→300ms 会被
    /// 当成"数据库慢了"）。这一族只包校验本身，`{algorithm}` 还能看见存量旧 MD5 哈希的
    /// 残余占比（升级进度）。
    pub fn record_credential_verify(&self, algorithm: &str, outcome: &str, duration_secs: f64) {
        {
            let mut counters = match self.credential_counters.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            *counters
                .entry((algorithm.to_string(), outcome.to_string()))
                .or_insert(0) += 1;
        }
        let mut durations = match self.credential_durations.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let series = durations.entry(algorithm.to_string()).or_default();
        series.count += 1;
        series.sum_secs += duration_secs;
        for (i, bound) in DURATION_BUCKETS_S.iter().enumerate() {
            if duration_secs <= *bound {
                series.buckets[i] += 1;
            }
        }
    }

    /// 渲染凭据校验指标（Prometheus 文本格式）
    fn render_credential_prometheus(&self) -> String {
        let mut s = String::new();
        let counters = match self.credential_counters.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let durations = match self.credential_durations.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.push_str("# HELP stepby_credential_verify_total 凭据校验次数（algorithm,outcome）\n");
        s.push_str("# TYPE stepby_credential_verify_total counter\n");
        let mut keys: Vec<(&(String, String), u64)> =
            counters.iter().map(|(k, v)| (k, *v)).collect();
        keys.sort();
        for ((algorithm, outcome), c) in &keys {
            s.push_str(&format!(
                "stepby_credential_verify_total{{algorithm=\"{}\",outcome=\"{}\"}} {}\n",
                escape_label(algorithm),
                escape_label(outcome),
                c
            ));
        }
        s.push_str("# HELP stepby_credential_verify_duration_seconds 凭据校验耗时分布（秒）\n");
        s.push_str("# TYPE stepby_credential_verify_duration_seconds histogram\n");
        let mut algos: Vec<&String> = durations.keys().collect();
        algos.sort();
        for algorithm in &algos {
            if let Some(series) = durations.get(*algorithm) {
                for (i, bound) in DURATION_BUCKETS_S.iter().enumerate() {
                    s.push_str(&format!(
                        "stepby_credential_verify_duration_seconds_bucket{{algorithm=\"{}\",le=\"{}\"}} {}\n",
                        escape_label(algorithm),
                        bound,
                        series.buckets[i]
                    ));
                }
                s.push_str(&format!(
                    "stepby_credential_verify_duration_seconds_bucket{{algorithm=\"{}\",le=\"+Inf\"}} {}\n",
                    escape_label(algorithm),
                    series.count
                ));
                s.push_str(&format!(
                    "stepby_credential_verify_duration_seconds_sum{{algorithm=\"{}\"}} {}\n",
                    escape_label(algorithm),
                    series.sum_secs
                ));
                s.push_str(&format!(
                    "stepby_credential_verify_duration_seconds_count{{algorithm=\"{}\"}} {}\n",
                    escape_label(algorithm),
                    series.count
                ));
            }
        }
        s
    }

    /// 操作录制链路事件计数（phase, outcome）→ `stepby_recording_events_total`。
    ///
    /// 调用点两处：采集中间件（每次带 `X-Record-Into` 的非读请求一条）与回放执行器
    /// （每趟回放一条终局）。**不记耗时**：采集的 DB 写已经异步化，记时长会得到
    /// "0.2ms"这种与使用者体感无关的数字，反而让人以为它很便宜。
    pub fn record_recording(&self, phase: &str, outcome: &str) {
        let mut counters = match self.recording_counters.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *counters
            .entry((phase.to_string(), outcome.to_string()))
            .or_insert(0) += 1;
    }

    /// AK 开放 API 指标：`ak_sign` 中间件每请求记录一次
    ///
    /// - 请求总量：`stepby_ak_requests_total{path,outcome}`
    /// - 验签失败计数：`stepby_ak_verify_failures_total{reason}`（outcome != "ok" 时累计）
    /// - 耗时直方图：`stepby_ak_request_duration_seconds{path}`（桶边界复用全局 DURATION_BUCKETS_S）
    pub fn record_ak_request(&self, path: &str, outcome: &str, duration_secs: f64) {
        // 请求总量（path, outcome）
        {
            let mut counters = match self.ak_counters.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            *counters
                .entry((path.to_string(), outcome.to_string()))
                .or_insert(0) += 1;
        }
        // 验签失败计数（reason = outcome，ok 不计入）
        if outcome != "ok" {
            let mut failures = match self.ak_failures.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            *failures.entry(outcome.to_string()).or_insert(0) += 1;
        }
        // 耗时直方图
        let mut durations = match self.ak_durations.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let series = durations.entry(path.to_string()).or_default();
        series.count += 1;
        series.sum_secs += duration_secs;
        for (i, bound) in DURATION_BUCKETS_S.iter().enumerate() {
            if duration_secs <= *bound {
                series.buckets[i] += 1;
            }
        }
    }

    /// 渲染 AK 开放 API 指标（Prometheus 文本格式）
    fn render_ak_prometheus(&self) -> String {
        let mut s = String::new();
        let counters = match self.ak_counters.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let failures = match self.ak_failures.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let durations = match self.ak_durations.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        // ===== b147 操作录制链路事件 =====
        // 采集面由 `record_recording` 的实际调用决定。三相位各自成组，使"录不进去"
        // 与"回放不通过"在监控上是两件可分的事（同名一个 outcome 会互相淹没）。
        if let Ok(recording_counters) = self.recording_counters.read() {
            s.push_str(
                "# HELP stepby_recording_events_total 操作录制链路事件数（phase,outcome）\n",
            );
            s.push_str("# TYPE stepby_recording_events_total counter\n");
            let mut rec_keys: Vec<&(String, String)> = recording_counters.keys().collect();
            rec_keys.sort();
            for k in rec_keys {
                if let Some(c) = recording_counters.get(k) {
                    s.push_str(&format!(
                        "stepby_recording_events_total{{phase=\"{}\",outcome=\"{}\"}} {}\n",
                        escape_label(&k.0),
                        escape_label(&k.1),
                        c
                    ));
                }
            }
        }

        s.push_str("# HELP stepby_ak_requests_total AK 开放 API 请求数（path,outcome）\n");
        s.push_str("# TYPE stepby_ak_requests_total counter\n");
        let mut req_keys: Vec<(&(String, String), u64)> =
            counters.iter().map(|(k, v)| (k, *v)).collect();
        req_keys.sort();
        for ((path, outcome), c) in &req_keys {
            s.push_str(&format!(
                "stepby_ak_requests_total{{path=\"{}\",outcome=\"{}\"}} {}\n",
                escape_label(path),
                escape_label(outcome),
                c
            ));
        }

        s.push_str("# HELP stepby_ak_verify_failures_total AK 验签失败计数（reason）\n");
        s.push_str("# TYPE stepby_ak_verify_failures_total counter\n");
        let mut fail_keys: Vec<&String> = failures.keys().collect();
        fail_keys.sort();
        for reason in &fail_keys {
            if let Some(c) = failures.get(*reason) {
                s.push_str(&format!(
                    "stepby_ak_verify_failures_total{{reason=\"{}\"}} {}\n",
                    escape_label(reason),
                    c
                ));
            }
        }

        s.push_str("# HELP stepby_ak_request_duration_seconds AK 开放 API 请求耗时分布（秒）\n");
        s.push_str("# TYPE stepby_ak_request_duration_seconds histogram\n");
        let mut dur_keys: Vec<&String> = durations.keys().collect();
        dur_keys.sort();
        for path in &dur_keys {
            if let Some(series) = durations.get(*path) {
                for (i, bound) in DURATION_BUCKETS_S.iter().enumerate() {
                    s.push_str(&format!(
                        "stepby_ak_request_duration_seconds_bucket{{path=\"{}\",le=\"{}\"}} {}\n",
                        escape_label(path),
                        bound,
                        series.buckets[i]
                    ));
                }
                s.push_str(&format!(
                    "stepby_ak_request_duration_seconds_bucket{{path=\"{}\",le=\"+Inf\"}} {}\n",
                    escape_label(path),
                    series.count
                ));
                s.push_str(&format!(
                    "stepby_ak_request_duration_seconds_sum{{path=\"{}\"}} {}\n",
                    escape_label(path),
                    series.sum_secs
                ));
                s.push_str(&format!(
                    "stepby_ak_request_duration_seconds_count{{path=\"{}\"}} {}\n",
                    escape_label(path),
                    series.count
                ));
            }
        }
        s
    }

    /// FCP-010：渲染 Web Vitals 指标（`stepby_frontend_vital_seconds` histogram +
    /// `stepby_frontend_cls` gauge），供 Prometheus 前端性能退化告警消费。
    fn render_vitals_prometheus(&self) -> String {
        let mut s = String::new();
        let vitals = match self.vitals.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.push_str(
            "# HELP stepby_frontend_vital_seconds Web Vitals 时间型指标分布（秒，name,device）\n",
        );
        s.push_str("# TYPE stepby_frontend_vital_seconds histogram\n");
        let mut keys: Vec<&(String, String)> = vitals.keys().collect();
        keys.sort();
        for key in &keys {
            if let Some(series) = vitals.get(*key) {
                let (name, device) = (*key).clone();
                for (i, bound) in VITAL_BUCKETS_S.iter().enumerate() {
                    s.push_str(&format!(
                        "stepby_frontend_vital_seconds_bucket{{name=\"{}\",device=\"{}\",le=\"{}\"}} {}\n",
                        escape_label(&name),
                        escape_label(&device),
                        bound,
                        series.buckets[i]
                    ));
                }
                s.push_str(&format!(
                    "stepby_frontend_vital_seconds_bucket{{name=\"{}\",device=\"{}\",le=\"+Inf\"}} {}\n",
                    escape_label(&name),
                    escape_label(&device),
                    series.count
                ));
                s.push_str(&format!(
                    "stepby_frontend_vital_seconds_sum{{name=\"{}\",device=\"{}\"}} {}\n",
                    escape_label(&name),
                    escape_label(&device),
                    series.sum_secs
                ));
                s.push_str(&format!(
                    "stepby_frontend_vital_seconds_count{{name=\"{}\",device=\"{}\"}} {}\n",
                    escape_label(&name),
                    escape_label(&device),
                    series.count
                ));
            }
        }
        let gauges = match self.cls_gauges.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.push_str("# HELP stepby_frontend_cls 最新 CLS 累计值（无量纲，device 分桶）\n");
        s.push_str("# TYPE stepby_frontend_cls gauge\n");
        let mut devs: Vec<&String> = gauges.keys().collect();
        devs.sort();
        for dev in devs {
            if let Some(v) = gauges.get(dev) {
                s.push_str(&format!(
                    "stepby_frontend_cls{{device=\"{}\"}} {}\n",
                    escape_label(dev),
                    v
                ));
            }
        }
        s
    }

    /// v5-D7：渲染 SSO 事件计数（`stepby_sso_events_total{event,outcome}`）
    fn render_sso_prometheus(&self) -> String {
        let mut s = String::new();
        s.push_str("# HELP stepby_sso_events_total SSO 协议事件计数（event,outcome）\n");
        s.push_str("# TYPE stepby_sso_events_total counter\n");
        let counters = match self.sso_counters.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut keys: Vec<&(String, String)> = counters.keys().collect();
        keys.sort();
        for (event, outcome) in keys {
            if let Some(c) = counters.get(&(event.clone(), outcome.clone())) {
                s.push_str(&format!(
                    "stepby_sso_events_total{{event=\"{}\",outcome=\"{}\"}} {}\n",
                    escape_label(event),
                    escape_label(outcome),
                    c
                ));
            }
        }
        s
    }

    /// G-09：记录一次定时任务执行（job_name/status/duration_ms）
    ///
    /// status："0"=成功 / "1"=失败（与 sys_job_log.status 口径一致，白名单外忽略防标签基数膨胀）。
    /// 由 `crate::scheduler::execute_with_logging` 每次任务执行后记录一次。
    pub fn record_job_execution(&self, job_name: &str, status: &str, duration_ms: u64) {
        if status != "0" && status != "1" {
            return;
        }
        let job_name = job_name.trim();
        if job_name.is_empty() {
            return;
        }
        // counter（job_name, status）
        {
            let mut counters = match self.job_counters.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            *counters
                .entry((job_name.to_string(), status.to_string()))
                .or_insert(0) += 1;
        }
        // histogram（秒，独立桶边界）
        let secs = duration_ms as f64 / 1000.0;
        let mut durations = match self.job_durations.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let series = durations
            .entry(job_name.to_string())
            .or_insert_with(JobDurationSeries::new);
        series.count += 1;
        series.sum_secs += secs;
        for (i, bound) in JOB_DURATION_BUCKETS_S.iter().enumerate() {
            if secs <= *bound {
                series.buckets[i] += 1;
            }
        }
    }

    /// G-09：渲染定时任务指标（`stepby_job_executions_total{job_name,status}` +
    /// `stepby_job_duration_seconds{job_name}` histogram）
    fn render_job_prometheus(&self) -> String {
        let mut s = String::new();
        let counters = match self.job_counters.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.push_str("# HELP stepby_job_executions_total 定时任务执行计数（job_name,status）\n");
        s.push_str("# TYPE stepby_job_executions_total counter\n");
        let mut keys: Vec<&(String, String)> = counters.keys().collect();
        keys.sort();
        for (job_name, status) in keys {
            if let Some(c) = counters.get(&(job_name.clone(), status.clone())) {
                s.push_str(&format!(
                    "stepby_job_executions_total{{job_name=\"{}\",status=\"{}\"}} {}\n",
                    escape_label(job_name),
                    escape_label(status),
                    c
                ));
            }
        }

        let durations = match self.job_durations.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.push_str("# HELP stepby_job_duration_seconds 定时任务耗时分布（秒）\n");
        s.push_str("# TYPE stepby_job_duration_seconds histogram\n");
        let mut dur_keys: Vec<&String> = durations.keys().collect();
        dur_keys.sort();
        for job_name in &dur_keys {
            if let Some(series) = durations.get(*job_name) {
                for (i, bound) in JOB_DURATION_BUCKETS_S.iter().enumerate() {
                    s.push_str(&format!(
                        "stepby_job_duration_seconds_bucket{{job_name=\"{}\",le=\"{}\"}} {}\n",
                        escape_label(job_name),
                        bound,
                        series.buckets[i]
                    ));
                }
                s.push_str(&format!(
                    "stepby_job_duration_seconds_bucket{{job_name=\"{}\",le=\"+Inf\"}} {}\n",
                    escape_label(job_name),
                    series.count
                ));
                s.push_str(&format!(
                    "stepby_job_duration_seconds_sum{{job_name=\"{}\"}} {}\n",
                    escape_label(job_name),
                    series.sum_secs
                ));
                s.push_str(&format!(
                    "stepby_job_duration_seconds_count{{job_name=\"{}\"}} {}\n",
                    escape_label(job_name),
                    series.count
                ));
            }
        }
        s
    }

    /// b72（AGENTS #4/#6）：记录一次出站依赖调用或后台受守卫任务的结局。
    ///
    /// - `component`：`mail` / `sms` / `webhook` / `storage` / `ai` / `im_robot` / `oauth`
    ///   以及后台任务的 `bg:<label>`（前缀区分，避免与依赖名混淆）
    /// - `outcome`：`ok` / `error` / `timeout` / `panic` / `rejected`
    ///
    /// 计数与耗时**总是成对写入**（与 `render_prometheus` 的"以直方图标签集为准"口径一致），
    /// 否则 Prometheus 侧会出现 `_count` 与 `_total` 对不上的孤儿系列。
    pub fn record_outbound(&self, component: &str, outcome: &str, duration_secs: f64) {
        {
            let mut counters = match self.outbound_counters.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            *counters
                .entry((component.to_string(), outcome.to_string()))
                .or_insert(0) += 1;
        }
        let mut durations = match self.outbound_durations.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let series = durations
            .entry(component.to_string())
            .or_insert_with(OutboundDurationSeries::new);
        series.count += 1;
        series.sum_secs += duration_secs;
        for (i, bound) in JOB_DURATION_BUCKETS_S.iter().enumerate() {
            if duration_secs <= *bound {
                series.buckets[i] += 1;
            }
        }
    }

    /// 渲染出站依赖 / 后台任务指标（Prometheus 文本格式）
    fn render_outbound_prometheus(&self) -> String {
        let mut s = String::new();
        let counters = match self.outbound_counters.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.push_str("# HELP stepby_outbound_requests_total 出站依赖/后台任务调用计数（component,outcome）\n");
        s.push_str("# TYPE stepby_outbound_requests_total counter\n");
        let mut keys: Vec<&(String, String)> = counters.keys().collect();
        keys.sort();
        for (component, outcome) in keys {
            if let Some(c) = counters.get(&(component.clone(), outcome.clone())) {
                s.push_str(&format!(
                    "stepby_outbound_requests_total{{component=\"{}\",outcome=\"{}\"}} {}\n",
                    escape_label(component),
                    escape_label(outcome),
                    c
                ));
            }
        }

        let durations = match self.outbound_durations.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        s.push_str("# HELP stepby_outbound_duration_seconds 出站依赖/后台任务耗时分布（秒）\n");
        s.push_str("# TYPE stepby_outbound_duration_seconds histogram\n");
        let mut dur_keys: Vec<&String> = durations.keys().collect();
        dur_keys.sort();
        for component in &dur_keys {
            if let Some(series) = durations.get(*component) {
                for (i, bound) in JOB_DURATION_BUCKETS_S.iter().enumerate() {
                    s.push_str(&format!(
                        "stepby_outbound_duration_seconds_bucket{{component=\"{}\",le=\"{}\"}} {}\n",
                        escape_label(component),
                        bound,
                        series.buckets[i]
                    ));
                }
                s.push_str(&format!(
                    "stepby_outbound_duration_seconds_bucket{{component=\"{}\",le=\"+Inf\"}} {}\n",
                    escape_label(component),
                    series.count
                ));
                s.push_str(&format!(
                    "stepby_outbound_duration_seconds_sum{{component=\"{}\"}} {}\n",
                    escape_label(component),
                    series.sum_secs
                ));
                s.push_str(&format!(
                    "stepby_outbound_duration_seconds_count{{component=\"{}\"}} {}\n",
                    escape_label(component),
                    series.count
                ));
            }
        }
        s
    }

    /// 渲染 Prometheus 文本格式的 HTTP 业务指标
    pub fn render_prometheus(&self) -> String {
        let mut s = String::new();
        s.push_str("# HELP stepby_http_requests_total 累计 HTTP 请求数（method,status,path）\n");
        s.push_str("# TYPE stepby_http_requests_total counter\n");

        let counters = match self.counters.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let durations = match self.durations.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        // 以直方图标签集为准，保证同类标签下两指标一致
        let mut keys: Vec<&LabelSet> = durations.keys().collect();
        keys.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.method.cmp(&b.method)));

        for key in &keys {
            if let Some(c) = counters.get(key) {
                s.push_str(&format!(
                    "stepby_http_requests_total{{method=\"{}\",status=\"{}\",path=\"{}\"}} {}\n",
                    escape_label(&key.method),
                    escape_label(&key.status),
                    escape_label(&key.path),
                    c
                ));
            }
        }
        // 聚合总数（无标签）
        s.push_str(&format!(
            "stepby_http_requests_total {{}} {}\n",
            self.total_requests()
        ));

        s.push_str("# HELP stepby_http_request_duration_seconds HTTP 请求耗时分布（秒）\n");
        s.push_str("# TYPE stepby_http_request_duration_seconds histogram\n");
        for key in &keys {
            if let Some(series) = durations.get(key) {
                for (i, bound) in DURATION_BUCKETS_S.iter().enumerate() {
                    s.push_str(&format!(
                        "stepby_http_request_duration_seconds_bucket{{method=\"{}\",status=\"{}\",path=\"{}\",le=\"{}\"}} {}\n",
                        escape_label(&key.method),
                        escape_label(&key.status),
                        escape_label(&key.path),
                        bound,
                        series.buckets[i]
                    ));
                }
                s.push_str(&format!(
                    "stepby_http_request_duration_seconds_bucket{{method=\"{}\",status=\"{}\",path=\"{}\",le=\"+Inf\"}} {}\n",
                    escape_label(&key.method),
                    escape_label(&key.status),
                    escape_label(&key.path),
                    series.count
                ));
                s.push_str(&format!(
                    "stepby_http_request_duration_seconds_sum{{method=\"{}\",status=\"{}\",path=\"{}\"}} {}\n",
                    escape_label(&key.method),
                    escape_label(&key.status),
                    escape_label(&key.path),
                    series.sum_secs
                ));
                s.push_str(&format!(
                    "stepby_http_request_duration_seconds_count{{method=\"{}\",status=\"{}\",path=\"{}\"}} {}\n",
                    escape_label(&key.method),
                    escape_label(&key.status),
                    escape_label(&key.path),
                    series.count
                ));
            }
        }
        // v5-D7：SSO 协议事件计数
        s.push_str(&self.render_sso_prometheus());
        // AK 开放 API：请求总量 / 验签失败 / 耗时直方图
        s.push_str(&self.render_credential_prometheus());
        s.push_str(&self.render_ak_prometheus());
        // FCP-010：Web Vitals（前端性能退化告警数据源）
        s.push_str(&self.render_vitals_prometheus());
        // G-09：定时任务执行计数 / 耗时直方图
        s.push_str(&self.render_job_prometheus());
        // b72：出站依赖 / 后台任务指标（AGENTS #4 组件级内建）
        s.push_str(&self.render_outbound_prometheus());
        s
    }
}

/// 转义 Prometheus 标签值中的特殊字符（反斜杠 / 引号 / 换行）
fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// 纯函数：把观测值计入 bucket（测试友好）
#[cfg(test)]
fn bucketize(value: f64, out: &mut [u64]) {
    for (i, bound) in DURATION_BUCKETS_S.iter().enumerate() {
        if value <= *bound {
            out[i] += 1;
        }
    }
}

#[cfg(test)]
pub fn test_instance() -> Arc<MetricsRegistry> {
    Arc::new(MetricsRegistry::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recent_5xx_window_counting() {
        let reg = test_instance();
        // 200 不入缓冲；500/502/503 入缓冲
        reg.record("GET", 200, "/ok", 0.01);
        reg.record("GET", 500, "/boom", 0.01);
        reg.record("POST", 502, "/boom", 0.01);
        reg.record("GET", 503, "/boom", 0.01);
        assert_eq!(reg.count_recent_5xx(std::time::Duration::from_secs(300)), 3);
        // 窗口为零时过期记录全部被惰性清理
        assert_eq!(reg.count_recent_5xx(std::time::Duration::ZERO), 0);
        // 清理后计数归零
        assert_eq!(reg.count_recent_5xx(std::time::Duration::from_secs(300)), 0);
    }

    #[test]
    fn test_bucketize_counts_le_semantics() {
        let mut out = [0u64; DURATION_BUCKETS_S.len()];
        bucketize(0.006, &mut out); // 属于 10ms（0.01）及以上桶
        bucketize(1.5, &mut out); // 超过最大采样桶，仅 +Inf 统计（这里无 max bucket，故不入任何桶）
        // 0.006 <= 0.01..1.0 均计数
        assert_eq!(out[0], 0, "5ms 桶不应含 6ms");
        assert!(out[1] >= 1, "10ms 桶应含 6ms");
    }

    #[test]
    fn test_render_contains_expected_series() {
        let reg = test_instance();
        reg.record("GET", 200, "/health", 0.01);
        reg.record("GET", 500, "/boom", 2.0);
        let text = reg.render_prometheus();
        assert!(text.contains(
            "stepby_http_requests_total{method=\"GET\",status=\"200\",path=\"/health\"} 1"
        ));
        assert!(text.contains("le=\"+Inf\""));
        assert!(text.contains("stepby_http_request_duration_seconds_sum"));
        assert_eq!(reg.total_requests(), 2);
    }

    #[test]
    fn test_sso_events_counter_rendering() {
        // v5-D7：SSO 事件计数按 (event,outcome) 聚合并渲染
        let reg = test_instance();
        reg.record_sso_event("token_issued", "ok");
        reg.record_sso_event("token_issued", "ok");
        reg.record_sso_event("token_issued", "invalid_grant");
        reg.record_sso_event("token_refreshed", "ok");
        reg.record_sso_event("authorize", "login");
        reg.record_sso_event("token_revoked", "ok");
        reg.record_sso_event("logout", "ok");
        let text = reg.render_prometheus();
        assert!(text.contains("stepby_sso_events_total{event=\"token_issued\",outcome=\"ok\"} 2"));
        assert!(text.contains(
            "stepby_sso_events_total{event=\"token_issued\",outcome=\"invalid_grant\"} 1"
        ));
        assert!(
            text.contains("stepby_sso_events_total{event=\"token_refreshed\",outcome=\"ok\"} 1")
        );
        assert!(text.contains("event=\"authorize\""));
        assert!(text.contains("event=\"token_revoked\""));
        assert!(text.contains("event=\"logout\""));
    }

    #[test]
    fn test_ak_request_metrics_rendering() {
        // AK 开放 API：请求总量（path,outcome）/ 失败计数（reason）/ 耗时直方图
        let reg = test_instance();
        reg.record_ak_request("/open/v1/profile", "ok", 0.01);
        reg.record_ak_request("/open/v1/profile", "ok", 0.02);
        reg.record_ak_request("/open/v1/profile", "invalid_signature", 0.005);
        reg.record_ak_request("/open/v1/profile", "nonce_reused", 0.005);
        let text = reg.render_prometheus();
        assert!(
            text.contains("stepby_ak_requests_total{path=\"/open/v1/profile\",outcome=\"ok\"} 2")
        );
        assert!(text.contains(
            "stepby_ak_requests_total{path=\"/open/v1/profile\",outcome=\"invalid_signature\"} 1"
        ));
        assert!(text.contains("stepby_ak_verify_failures_total{reason=\"invalid_signature\"} 1"));
        assert!(text.contains("stepby_ak_verify_failures_total{reason=\"nonce_reused\"} 1"));
        assert!(
            text.contains("stepby_ak_request_duration_seconds_count{path=\"/open/v1/profile\"} 4")
        );
        // ok 不计入失败
        assert!(!text.contains("reason=\"ok\""));
    }

    #[test]
    fn test_frontend_vitals_rendering() {
        // FCP-010：时间型 vitals 走直方图、CLS 走 gauge；白名单外 name/设备归一化
        let reg = test_instance();
        reg.record_frontend_vital("LCP", "mobile", 1.2);
        reg.record_frontend_vital("LCP", "mobile", 0.5);
        reg.record_frontend_vital("FCP", "desktop", 0.9);
        reg.record_frontend_vital("LCP", "smart-tv", 3.0); // 非法设备 → unknown
        reg.record_frontend_vital("XXX", "mobile", 1.0); // 非法指标 → 忽略
        reg.record_frontend_vital("LCP", "mobile", -1.0); // 非法值 → 忽略
        reg.set_frontend_cls("tablet", 0.03);
        let text = reg.render_prometheus();
        assert!(text.contains(
            "stepby_frontend_vital_seconds_bucket{name=\"LCP\",device=\"mobile\",le=\"1.8\"} 2"
        ));
        assert!(text.contains(
            "stepby_frontend_vital_seconds_bucket{name=\"LCP\",device=\"mobile\",le=\"+Inf\"} 2"
        ));
        assert!(text.contains(
            "stepby_frontend_vital_seconds_bucket{name=\"FCP\",device=\"desktop\",le=\"1\"} 1"
        ));
        assert!(text.contains(
            "stepby_frontend_vital_seconds_bucket{name=\"LCP\",device=\"unknown\",le=\"4\"} 1"
        ));
        assert!(!text.contains("name=\"XXX\""));
        assert!(text.contains("stepby_frontend_cls{device=\"tablet\"} 0.03"));
    }

    #[test]
    fn test_job_execution_metrics_rendering() {
        // G-09：任务执行计数（job_name,status）+ 耗时直方图（独立桶边界）；
        // 白名单外 status/空 job_name 忽略防标签基数膨胀
        let reg = test_instance();
        reg.record_job_execution("msg_send_retry", "0", 50);
        reg.record_job_execution("msg_send_retry", "0", 150);
        reg.record_job_execution("msg_send_retry", "1", 1200);
        reg.record_job_execution("report_sub_due", "0", 30_000);
        reg.record_job_execution("bad_job", "2", 100); // 非法 status → 忽略
        reg.record_job_execution("   ", "0", 100); // 空名 → 忽略
        let text = reg.render_prometheus();
        assert!(
            text.contains(
                "stepby_job_executions_total{job_name=\"msg_send_retry\",status=\"0\"} 2"
            )
        );
        assert!(
            text.contains(
                "stepby_job_executions_total{job_name=\"msg_send_retry\",status=\"1\"} 1"
            )
        );
        assert!(
            text.contains(
                "stepby_job_executions_total{job_name=\"report_sub_due\",status=\"0\"} 1"
            )
        );
        assert!(!text.contains("bad_job"));
        // 耗时直方图：50ms → 0.1 桶、150ms → 0.25 桶、1200ms → 5s 桶、30s → 60s 桶
        assert!(text.contains(
            "stepby_job_duration_seconds_bucket{job_name=\"msg_send_retry\",le=\"0.1\"} 1"
        ));
        assert!(text.contains(
            "stepby_job_duration_seconds_bucket{job_name=\"msg_send_retry\",le=\"0.25\"} 2"
        ));
        assert!(text.contains(
            "stepby_job_duration_seconds_bucket{job_name=\"msg_send_retry\",le=\"5\"} 3"
        ));
        assert!(text.contains("stepby_job_duration_seconds_count{job_name=\"msg_send_retry\"} 3"));
        assert!(text.contains(
            "stepby_job_duration_seconds_bucket{job_name=\"report_sub_due\",le=\"60\"} 1"
        ));
    }

    #[test]
    fn test_histogram_cumulative_counts() {
        let reg = test_instance();
        reg.record("GET", 200, "/a", 0.05);
        // count 各桶
        let d = reg.durations.read().unwrap();
        let key = LabelSet {
            method: "GET".into(),
            status: "200".into(),
            path: "/a".into(),
        };
        let s = d.get(&key).unwrap();
        // 0.05 <= 0.05,0.1,...；不小于 0.025 及更小
        assert_eq!(s.count, 1);
        assert!(s.buckets[DURATION_BUCKETS_S.len() - 1] >= 1);
        assert_eq!(s.sum_secs, 0.05);
    }
}
