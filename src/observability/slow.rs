// axum-backend/src/observability/slow.rs
//! 慢请求（及慢 SQL）监控缓冲与聚合
//!
//! ## 设计说明（重要）
//! 目标面板名称为「慢 SQL 与慢请求」。真实采集"慢 SQL"需要拦截 SeaORM / sqlx
//! 每一条查询语句并计时，但 sqlx 底层连接池（Pool 级）对不同数据库（sqlite/mysql/pg）
//! 不暴露统一的"每次查询完成"钩子，sea-orm `DatabaseConnection` 也无这样的接口，
//! 跨库实现既不安全也不可靠（属于任务约定的 fallback 场景）。
//!
//! 因此在当前实现中，选择**真实且有用**的替代方案：在 HTTP 中间件层捕获**慢请求**
//! （path + method + status + duration），并统一归入 `/monitor/slow-sql/*` 端点展示，
//! 运维人员据此定位慢接口，再结合日志确认根因。这是可落地的折中方案，
//! 且聚合指标（count/avg/max/top）与有界环形缓冲已完整实现。
//!
//! 存储采用进程内 `RwLock<VecDeque>` 有界环形缓冲（容量可配，默认 200），
//! 通过全局静态 `OnceLock<Arc<SlowRequestBus>>` 共享，供中间件写入 / handler 读取。

use std::collections::VecDeque;
use std::sync::{Arc, OnceLock, RwLock};

use serde::Serialize;
use utoipa::ToSchema;

/// 默认缓冲容量（保留最近 N 条慢请求）
const DEFAULT_CAPACITY: usize = 200;

/// 默认慢请求阈值（毫秒）
const DEFAULT_THRESHOLD_MS: u64 = 300;

/// 单条慢请求记录
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SlowRequestRecord {
    /// HTTP 方法
    pub method: String,
    /// 请求路径（优先使用路由模板，如 /system/user/list，避免高基数）
    pub path: String,
    /// 响应状态码
    pub status: u16,
    /// 耗时（毫秒）
    pub duration_ms: u64,
    /// 发生时间（RFC3339）
    pub at: String,
}

/// 按路径聚合的 Top 慢接口
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TopPath {
    pub path: String,
    pub count: usize,
    pub avg_ms: f64,
    pub max_ms: u64,
}

/// 慢请求聚合统计
#[derive(Debug, Clone, Serialize, ToSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct SlowStats {
    /// 缓冲内当前条数
    pub count: usize,
    /// 平均耗时（毫秒）
    pub avg_ms: f64,
    /// 最大耗时（毫秒）
    pub max_ms: u64,
    /// 耗时超过 1s 的条数（高水位告警参考）
    pub over_1s: usize,
    /// 当前阈值（毫秒）
    pub threshold_ms: u64,
    /// Top 慢接口（按出现次数降序）
    pub top_paths: Vec<TopPath>,
}

/// 内部可变状态
struct Inner {
    threshold_ms: u64,
    capacity: usize,
    entries: VecDeque<SlowRequestRecord>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            threshold_ms: DEFAULT_THRESHOLD_MS,
            capacity: DEFAULT_CAPACITY,
            entries: VecDeque::with_capacity(DEFAULT_CAPACITY),
        }
    }
}

/// 慢请求总线（有界环形缓冲 + 聚合）
pub struct SlowRequestBus {
    inner: RwLock<Inner>,
}

impl Default for SlowRequestBus {
    fn default() -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
        }
    }
}

/// 全局共享实例（懒初始化）
static GLOBAL: OnceLock<Arc<SlowRequestBus>> = OnceLock::new();

impl SlowRequestBus {
    /// 获取全局共享实例
    pub fn global() -> Arc<Self> {
        GLOBAL
            .get_or_init(|| Arc::new(SlowRequestBus::default()))
            .clone()
    }

    /// 记录一次请求（超过阈值才入缓冲）
    pub fn record(&self, method: &str, path: &str, status: u16, duration_ms: u64) {
        if duration_ms < self.threshold_ms() {
            return;
        }
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.entries.push_back(SlowRequestRecord {
            method: method.to_string(),
            path: path.to_string(),
            status,
            duration_ms,
            at: chrono::Utc::now().to_rfc3339(),
        });
        // 超出容量则丢弃最旧记录
        while inner.entries.len() > inner.capacity {
            inner.entries.pop_front();
        }
    }

    /// 当前阈值（毫秒）
    pub fn threshold_ms(&self) -> u64 {
        self.inner
            .read()
            .map(|g| g.threshold_ms)
            .unwrap_or(DEFAULT_THRESHOLD_MS)
    }

    /// 动态配置阈值（毫秒）与缓冲容量（供配置注入，0 值表示保持不变）
    ///
    /// 容量缩小时顺带裁剪超出部分的旧记录，与 record 内的有界逻辑保持一致。
    pub fn configure(&self, threshold_ms: u64, capacity: usize) {
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if threshold_ms > 0 {
            inner.threshold_ms = threshold_ms;
        }
        if capacity > 0 {
            inner.capacity = capacity;
            while inner.entries.len() > inner.capacity {
                inner.entries.pop_front();
            }
        }
    }

    /// 返回全部缓冲记录（最新在前）
    pub fn list(&self) -> Vec<SlowRequestRecord> {
        let inner = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut entries: Vec<SlowRequestRecord> = inner.entries.iter().cloned().collect();
        entries.reverse();
        entries
    }

    /// 清空缓冲
    pub fn clear(&self) -> usize {
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let n = inner.entries.len();
        inner.entries.clear();
        n
    }

    /// 聚合统计
    pub fn stats(&self) -> SlowStats {
        let inner = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut stats = SlowStats {
            threshold_ms: inner.threshold_ms,
            ..Default::default()
        };
        let mut count = 0;
        let mut sum = 0u128;
        let mut max_ms = 0u64;
        let mut over_1s = 0usize;
        let mut by_path: std::collections::HashMap<&str, (usize, u128, u64)> =
            std::collections::HashMap::new();

        for e in &inner.entries {
            count += 1;
            sum += e.duration_ms as u128;
            max_ms = max_ms.max(e.duration_ms);
            if e.duration_ms > 1000 {
                over_1s += 1;
            }
            let entry = by_path.entry(e.path.as_str()).or_insert((0, 0, 0));
            entry.0 += 1;
            entry.1 += e.duration_ms as u128;
            entry.2 = entry.2.max(e.duration_ms);
        }

        stats.count = count;
        stats.max_ms = max_ms;
        stats.over_1s = over_1s;
        stats.avg_ms = if count > 0 {
            (sum as f64) / (count as f64)
        } else {
            0.0
        };

        let mut paths: Vec<TopPath> = by_path
            .into_iter()
            .map(|(path, (cnt, sump, maxp))| TopPath {
                path: path.to_string(),
                count: cnt,
                avg_ms: if cnt > 0 {
                    sump as f64 / cnt as f64
                } else {
                    0.0
                },
                max_ms: maxp,
            })
            .collect();
        paths.sort_by(|a, b| b.count.cmp(&a.count).then(b.max_ms.cmp(&a.max_ms)));
        paths.truncate(10);
        stats.top_paths = paths;
        stats
    }
}

/// 暴露给单测等使用：构造一个可独立封装的实例（不污染全局）
#[cfg(test)]
pub fn test_instance() -> Arc<SlowRequestBus> {
    Arc::new(SlowRequestBus::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_below_threshold_not_recorded() {
        let bus = test_instance();
        bus.record("GET", "/fast", 200, 10);
        assert!(bus.list().is_empty(), "低于阈值不应入缓冲");
    }

    #[test]
    fn test_ring_buffer_capacity() {
        let bus = test_instance();
        // 写入超过容量条目的慢请求（通过写入大量慢请求验证丢弃最旧）
        for i in 0..(DEFAULT_CAPACITY + 50) {
            bus.record("GET", &format!("/path_{}", i % 5), 200, 1000);
        }
        let list = bus.list();
        assert_eq!(list.len(), DEFAULT_CAPACITY, "超出容量应截断为缓冲上限");
        // 最新在前的语义：首条应为最后一次写入的路径
        assert_eq!(list[0].path, "/path_4");
    }

    #[test]
    fn test_stats_aggregate() {
        let bus = test_instance();
        for _ in 0..3 {
            bus.record("GET", "/a", 200, 400);
        }
        bus.record("POST", "/b", 500, 2000);
        let stats = bus.stats();
        assert_eq!(stats.count, 4);
        assert_eq!(stats.max_ms, 2000);
        // 平均 = (400*3 + 2000)/4 = 3200/4 = 800
        assert_eq!(stats.avg_ms, 800.0);
        assert_eq!(stats.over_1s, 1);
        // top_paths 按 count 降序：/a count=3 在前
        assert_eq!(stats.top_paths[0].path, "/a");
        assert_eq!(stats.top_paths[0].count, 3);
    }

    #[test]
    fn test_clear() {
        let bus = test_instance();
        bus.record("GET", "/a", 200, 500);
        assert_eq!(bus.clear(), 1);
        assert!(bus.list().is_empty());
    }

    #[test]
    fn test_configure_threshold_and_capacity() {
        let bus = test_instance();
        // 调低阈值到 200ms，调小容量到 2
        bus.configure(200, 2);
        assert_eq!(bus.threshold_ms(), 200);
        // 300ms 现在应被记录（原默认阈值 300 不会记录）
        bus.record("GET", "/a", 200, 300);
        bus.record("GET", "/b", 200, 300);
        bus.record("GET", "/c", 200, 300);
        assert_eq!(bus.list().len(), 2, "容量缩小为 2 后应只保留最近 2 条");
        assert_eq!(bus.stats().threshold_ms, 200);

        // 0 值表示保持不变
        bus.configure(0, 0);
        assert_eq!(bus.threshold_ms(), 200);
        assert_eq!(bus.list().len(), 2);
    }
}
