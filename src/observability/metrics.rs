// axum-backend/src/observability/metrics.rs
//! 轻量 Prometheus 文本格式指标（零外部依赖）
//!
//! 由于后端已有 /metrics 端点（health.rs）暴露进程级指标，本模块补充 **HTTP 业务指标**：
//! - `yebot_http_requests_total{method,status,path}`（counter）
//! - `yebot_http_request_duration_seconds_bucket/sum/count`（histogram）
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
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            durations: RwLock::new(HashMap::new()),
            total_requests: AtomicU64::new(0),
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

    /// 渲染 Prometheus 文本格式的 HTTP 业务指标
    pub fn render_prometheus(&self) -> String {
        let mut s = String::new();
        s.push_str("# HELP yebot_http_requests_total 累计 HTTP 请求数（method,status,path）\n");
        s.push_str("# TYPE yebot_http_requests_total counter\n");

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
                    "yebot_http_requests_total{{method=\"{}\",status=\"{}\",path=\"{}\"}} {}\n",
                    escape_label(&key.method),
                    escape_label(&key.status),
                    escape_label(&key.path),
                    c
                ));
            }
        }
        // 聚合总数（无标签）
        s.push_str(&format!(
            "yebot_http_requests_total {{}} {}\n",
            self.total_requests()
        ));

        s.push_str("# HELP yebot_http_request_duration_seconds HTTP 请求耗时分布（秒）\n");
        s.push_str("# TYPE yebot_http_request_duration_seconds histogram\n");
        for key in &keys {
            if let Some(series) = durations.get(key) {
                for (i, bound) in DURATION_BUCKETS_S.iter().enumerate() {
                    s.push_str(&format!(
                        "yebot_http_request_duration_seconds_bucket{{method=\"{}\",status=\"{}\",path=\"{}\",le=\"{}\"}} {}\n",
                        escape_label(&key.method),
                        escape_label(&key.status),
                        escape_label(&key.path),
                        bound,
                        series.buckets[i]
                    ));
                }
                s.push_str(&format!(
                    "yebot_http_request_duration_seconds_bucket{{method=\"{}\",status=\"{}\",path=\"{}\",le=\"+Inf\"}} {}\n",
                    escape_label(&key.method),
                    escape_label(&key.status),
                    escape_label(&key.path),
                    series.count
                ));
                s.push_str(&format!(
                    "yebot_http_request_duration_seconds_sum{{method=\"{}\",status=\"{}\",path=\"{}\"}} {}\n",
                    escape_label(&key.method),
                    escape_label(&key.status),
                    escape_label(&key.path),
                    series.sum_secs
                ));
                s.push_str(&format!(
                    "yebot_http_request_duration_seconds_count{{method=\"{}\",status=\"{}\",path=\"{}\"}} {}\n",
                    escape_label(&key.method),
                    escape_label(&key.status),
                    escape_label(&key.path),
                    series.count
                ));
            }
        }
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
            "yebot_http_requests_total{method=\"GET\",status=\"200\",path=\"/health\"} 1"
        ));
        assert!(text.contains("le=\"+Inf\""));
        assert!(text.contains("yebot_http_request_duration_seconds_sum"));
        assert_eq!(reg.total_requests(), 2);
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
