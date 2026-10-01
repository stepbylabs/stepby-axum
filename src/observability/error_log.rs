// stepby-axum/src/observability/error_log.rs
//! 错误聚合总线（Error Bus）
//!
//! 通过一个自定义 `tracing_subscriber::Layer` 捕获 `ERROR` 级别日志事件，
//! 聚合 `message` / `module`（target）/ `level`，并尽力提取日志事件内联的
//! `request_id` / `path` 字段（由各处 `tracing::error!(request_id=..., path=...)`
//! 等写法填充；span 内字段不作为事件字段透传时的关联可结合日志落盘实现）。
//!
//! 存储为进程内 `RwLock<VecDeque>` 有界环形缓冲（默认 500 条），
//! 通过全局静态 `OnceLock<Arc<ErrorLogBus>>` 共享。
//! 在 `logger::init_logger` 中以 `.with(ErrorCaptureLayer::new())` 注册。

use std::collections::VecDeque;
use std::sync::{Arc, OnceLock, RwLock};

use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use utoipa::ToSchema;

/// 默认缓冲容量（保留最近 N 条错误）
const DEFAULT_CAPACITY: usize = 500;

/// 单条错误日志记录
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ErrorEntry {
    /// 请求 ID（事件内联字段最佳努力提取，可能为空）
    pub request_id: String,
    /// 请求路径（最佳努力提取，可能为空）
    pub path: String,
    /// 错误消息（事件 message 字段）
    pub message: String,
    /// 模块（tracing target，如 stepby_axum::service::xxx）
    pub module: String,
    /// 日志级别（ERROR）
    pub level: String,
    /// 发生时间（RFC3339）
    pub at: String,
}

/// 按维度聚合的桶（by-module / by-level）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StatBucket {
    pub name: String,
    pub count: usize,
}

/// 错误聚合统计
#[derive(Debug, Clone, Serialize, ToSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ErrorStats {
    pub total: usize,
    pub by_module: Vec<StatBucket>,
    pub by_level: Vec<StatBucket>,
}

/// 内部可变状态
struct Inner {
    capacity: usize,
    entries: VecDeque<ErrorEntry>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            entries: VecDeque::with_capacity(DEFAULT_CAPACITY),
        }
    }
}

/// 错误聚合总线
pub struct ErrorLogBus {
    inner: RwLock<Inner>,
}

impl Default for ErrorLogBus {
    fn default() -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
        }
    }
}

/// 全局共享实例
static GLOBAL: OnceLock<Arc<ErrorLogBus>> = OnceLock::new();

impl ErrorLogBus {
    /// 获取全局共享实例
    pub fn global() -> Arc<Self> {
        GLOBAL
            .get_or_init(|| Arc::new(ErrorLogBus::default()))
            .clone()
    }

    /// 写入一条错误记录（有界丢弃最旧）
    pub fn record(&self, entry: ErrorEntry) {
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.entries.push_back(entry);
        while inner.entries.len() > inner.capacity {
            inner.entries.pop_front();
        }
    }

    /// 动态配置缓冲容量（供配置注入，0 值忽略）；缩小时裁剪超出旧记录
    pub fn set_capacity(&self, capacity: usize) {
        if capacity == 0 {
            return;
        }
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.capacity = capacity;
        while inner.entries.len() > inner.capacity {
            inner.entries.pop_front();
        }
    }

    /// 按 module / level 过滤 + offset/limit 分页，返回 (总数, 当前页)
    ///
    /// 结果最新在前。
    pub fn list(
        &self,
        module: Option<&str>,
        level: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> (usize, Vec<ErrorEntry>) {
        let inner = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut filtered: Vec<&ErrorEntry> = inner
            .entries
            .iter()
            .filter(|e| {
                let m_ok = module
                    .map(|m| m.is_empty() || e.module.contains(m))
                    .unwrap_or(true);
                let l_ok = level
                    .map(|l| l.is_empty() || e.level.eq_ignore_ascii_case(l))
                    .unwrap_or(true);
                m_ok && l_ok
            })
            .collect();
        filtered.reverse();
        let total = filtered.len();
        let page: Vec<ErrorEntry> = filtered
            .into_iter()
            .skip(offset)
            .take(if limit == 0 { usize::MAX } else { limit })
            .cloned()
            .collect();
        (total, page)
    }

    /// 清空缓冲，返回清空条数
    pub fn clear(&self) -> usize {
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let n = inner.entries.len();
        inner.entries.clear();
        n
    }

    /// 聚合：按 module / level 分桶
    pub fn stats(&self) -> ErrorStats {
        let inner = match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut stats = ErrorStats {
            total: inner.entries.len(),
            ..Default::default()
        };
        let mut by_module: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        let mut by_level: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for e in &inner.entries {
            *by_module.entry(e.module.as_str()).or_insert(0) += 1;
            *by_level.entry(e.level.as_str()).or_insert(0) += 1;
        }
        stats.by_module = into_buckets(by_module);
        stats.by_level = into_buckets(by_level);
        stats
    }
}

fn into_buckets(map: std::collections::HashMap<&str, usize>) -> Vec<StatBucket> {
    let mut v: Vec<StatBucket> = map
        .into_iter()
        .map(|(name, count)| StatBucket {
            name: name.to_string(),
            count,
        })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then(a.name.cmp(&b.name)));
    v
}

/// 采集层：把 ERROR 级别事件写入全局错误总线
pub struct ErrorCaptureLayer {
    bus: Arc<ErrorLogBus>,
}

impl ErrorCaptureLayer {
    pub fn new() -> Self {
        Self {
            bus: ErrorLogBus::global(),
        }
    }
}

impl Default for ErrorCaptureLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for ErrorCaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // 仅采集 ERROR 及以上级别（含 panic 通过 tracing::error 记录的场景）
        if *event.metadata().level() < Level::ERROR {
            return;
        }

        // 采集事件内联字段（message 必须来自事件；request_id/path 由
        // `tracing::error!(request_id=..., path=...)` 等写法填充，best-effort）。
        let mut event_fields = FieldMapVisitor::default();
        event.record(&mut event_fields);
        let message = event_fields
            .take("message")
            .unwrap_or_else(|| "<no message>".to_string());
        let request_id = event_fields.take("request_id").unwrap_or_default();
        let path = event_fields.take("path").unwrap_or_default();
        let module = event.metadata().target().to_string();
        let level = event.metadata().level().to_string();

        self.bus.record(ErrorEntry {
            request_id,
            path,
            message,
            module,
            level,
            at: chrono::Utc::now().to_rfc3339(),
        });
    }
}

/// 事件字段访问器：按出现顺序收集字段，`take(name)` 返回值并移除（首次优先）
#[derive(Default)]
struct FieldMapVisitor {
    fields: std::collections::HashMap<String, String>,
    order: Vec<String>,
}

impl FieldMapVisitor {
    fn put(&mut self, name: &str, value: String) {
        if self.order.contains(&name.to_string()) {
            return;
        }
        self.order.push(name.to_string());
        self.fields.insert(name.to_string(), value);
    }

    /// 取走指定字段（首次出现优先）
    fn take(&mut self, name: &str) -> Option<String> {
        self.fields.remove(name)
    }
}

impl Visit for FieldMapVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field.name(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field.name(), value.to_string());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field.name(), value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field.name(), value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field.name(), value.to_string());
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field.name(), value.to_string());
    }
}

/// 暴露给单测的独立实例（不污染全局）
#[cfg(test)]
pub fn test_instance() -> Arc<ErrorLogBus> {
    Arc::new(ErrorLogBus::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(module: &str, level: &str, msg: &str, req: &str) -> ErrorEntry {
        ErrorEntry {
            request_id: req.to_string(),
            path: "/api/x".to_string(),
            message: msg.to_string(),
            module: module.to_string(),
            level: level.to_string(),
            at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn test_ring_capacity() {
        let bus = test_instance();
        for i in 0..(DEFAULT_CAPACITY + 30) {
            bus.record(sample("mod", "ERROR", &format!("m{i}"), "r"));
        }
        let (total, page) = bus.list(None, None, 0, 0);
        assert_eq!(total, DEFAULT_CAPACITY, "超出容量应截断");
        assert_eq!(page.len(), DEFAULT_CAPACITY);
        // 最新在前
        assert_eq!(page[0].message, format!("m{}", DEFAULT_CAPACITY + 29));
    }

    #[test]
    fn test_filter_and_pagination() {
        let bus = test_instance();
        bus.record(sample("auth", "ERROR", "login fail", "a"));
        bus.record(sample("db", "ERROR", "conn fail", "b"));
        bus.record(sample("auth", "ERROR", "token invalid", "c"));

        // 按 module 过滤
        let (total, page) = bus.list(Some("auth"), None, 0, 0);
        assert_eq!(total, 2);
        assert!(page.iter().all(|e| e.module == "auth"));

        // 分页
        let (_t, page) = bus.list(None, None, 1, 1);
        assert_eq!(page.len(), 1);
    }

    #[test]
    fn test_level_filter_case_insensitive() {
        let bus = test_instance();
        bus.record(sample("mod", "ERROR", "a", ""));
        bus.record(sample("mod", "WARN", "b", ""));
        let (total, _) = bus.list(None, Some("error"), 0, 0);
        assert_eq!(total, 1);
    }

    #[test]
    fn test_stats_by_module_level() {
        let bus = test_instance();
        bus.record(sample("a", "ERROR", "1", ""));
        bus.record(sample("a", "ERROR", "2", ""));
        bus.record(sample("b", "ERROR", "3", ""));
        let stats = bus.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.by_module.len(), 2);
        assert_eq!(stats.by_module[0].name, "a");
        assert_eq!(stats.by_module[0].count, 2);
        assert_eq!(stats.by_level[0].name, "ERROR");
        assert_eq!(stats.by_level[0].count, 3);
    }

    #[test]
    fn test_clear() {
        let bus = test_instance();
        bus.record(sample("a", "ERROR", "1", ""));
        assert_eq!(bus.clear(), 1);
        assert_eq!(bus.list(None, None, 0, 0).0, 0);
    }

    #[test]
    fn test_set_capacity_trim() {
        let bus = test_instance();
        for i in 0..5 {
            bus.record(sample("mod", "ERROR", &format!("m{i}"), "r"));
        }
        bus.set_capacity(3);
        assert_eq!(bus.list(None, None, 0, 0).0, 3, "缩小容量应裁剪多余记录");
        // 保留最近 3 条：m2/m3/m4，最新在前 → 首条为 m4
        assert_eq!(bus.list(None, None, 0, 0).1[0].message, "m4");
        // 0 值忽略
        bus.set_capacity(0);
        assert_eq!(bus.list(None, None, 0, 0).0, 3);
    }
}
