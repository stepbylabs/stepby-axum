// backend-axum/src/observability/metrics.rs
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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// 直方图采样桶边界（秒）。默认 [5ms,10,25,50,100,250,500,1000ms]。
pub const DURATION_BUCKETS_S: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];

/// Web Vitals 直方图采样桶边界（秒）。边界对齐 perf-budget.json 运行时预算：
/// FCP ≤ 1.8s、LCP ≤ 2.5s（prometheus histogram_quantile(0.95) 可直接与预算比对）。
pub const VITAL_BUCKETS_S: &[f64] = &[0.1, 0.25, 0.5, 1.0, 1.8, 2.5, 4.0, 8.0];

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
    /// 长度 = BUCKET_COUNT，`buckets[i]` = 观测值 <= bounds[i] 的条数
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
}

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

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            durations: RwLock::new(HashMap::new()),
            total_requests: AtomicU64::new(0),
            sso_counters: RwLock::new(HashMap::new()),
            vitals: RwLock::new(HashMap::new()),
            cls_gauges: RwLock::new(HashMap::new()),
        }
    }
}

/// 全局共享实例
static GLOBAL: OnceLock<Arc<MetricsRegistry>> = OnceLock::new();

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
        // FCP-010：Web Vitals（前端性能退化告警数据源）
        s.push_str(&self.render_vitals_prometheus());
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
