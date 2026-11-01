// stepby-axum/src/common/store_outcome.rs
//! 共享态（`SharedStore`）读写的**结局三态**通道（b149 项 18 立项）。
//!
//! # 为什么需要这一层
//!
//! [`crate::shared_store::SharedStore::get`] 返回 `Result<Option<String>>`，
//! [`set_nx_ex`](crate::shared_store::SharedStore::set_nx_ex) 返回 `Result<bool>`。
//! 两者都把"这次操作到底怎么了"拆成**三个**结构上不同的结局：
//!
//! | 调用 | 三态 | 折叠写法的后果 |
//! |---|---|---|
//! | `get` | 命中 / **键确实不存在** / 读不出来 | `unwrap_or(None)` 把"后端坏了"读成"未命中" ⇒ 缓存层失效却无人知道；鉴权类键更坏——会被读成"没有" |
//! | `set_nx_ex` | 抢到 / **被别人抢到** / 存储不可用 | `unwrap_or(false)` 把"存储坏了"读成"没抢到" ⇒ **该做的事整轮不做**（本批实测：两处流程超时提醒窗口都写的是这一支，而**两处注释各自的意图相反**——一处置故障于"未抢占"、一处写"最坏退化为本轮多实例各发一次"，代码却都是 `unwrap_or(false)`，于是两个意图都不可能由代码保证） |
//! | `set_ex` | 写成功 / 写失败 | `let _: Result<(), _> =` 把失败整条丢掉 ⇒ 日志照打"完成" |
//!
//! AGENTS 铁律「多租户」的读侧断面（b74 B5 → b146 → b144 → 本批第四次）说的是同一件事：
//! **范围/状态读失败不得回退成"不限制 / 没有 / 未抢占"**。本模块把三态做成**类型**，
//! 让调用点必须为第三支（`Unavailable`）选一条路，而不是靠"记得写 match"。
//!
//! # 分类是纯函数、留痕在通道里
//!
//! `classify_*` 三支只吃 `Result`，因此**每一支都能被单测喂到**（含 `Err`——真实存储
//! 不会配合造出故障，见 b126 `TokenRevokeOps` 同一条理由）。异步壳只做
//! 「await → classify → 留痕 → 计数」，那一段由源码形状锁钉住（形状锁只判"确实经过
//! 分类器"，判不了分类器本身是否被绕开——那由 `Err` 夹具判）。
//!
//! 留痕放在通道里而不是调用点，理由与 b145 的 `outbound_error_body` 相同：
//! **放在调用点就会漏**，而漏掉的那一处正是"故障与正常同形"的所在。每次故障只打一条
//! （按站点 `AtomicBool`），因为这是每请求路径——刷成日志流水会把真实信号淹掉（b69）。
//!
//! # 边界
//!
//! - **日志不写键名**：键常含令牌哈希 / 会话标识（`sso:userinfo:{sha256}`、
//!   `user_sessions:{uid}:{ip}:{browser}`），写了就是把 PII 放进日志（C.9）。
//!   日志只写**站点标签**（代码里的固定串）。
//! - 错误串先过 [`fold_abs_paths`](crate::common::redact::fold_abs_paths)：`local` 档是
//!   SQLite，驱动的错误串会带数据库文件绝对路径。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::shared_store::{SharedStore, StoreError};

/// 哪些站点在用这条通道。**新增用途必须扩这个表**：它同时是采集面——
/// 计数、只打一次、`/metrics` 渲染、以及"标签必须在生产码出现"的接线反查全由 `ALL` 派生。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// SSO 客户端 logo 的"已校验 URL"缓存读
    SsoLogoRead,
    /// 同上，写
    SsoLogoWrite,
    /// OIDC `/userinfo` 的服务端短 TTL 缓存读（v4-D11）
    SsoUserinfoRead,
    /// 同上，写
    SsoUserinfoWrite,
    /// 登录时回查"同设备旧会话"的令牌哈希（决定要不要清在线列表里的旧条目）
    SessionOldHashRead,
    /// 超时提醒的跨实例互斥窗（首次提醒）
    FlowRemindWindow,
    /// 超时提醒的跨实例互斥窗（升级提醒）
    FlowEscalateWindow,
}

impl Site {
    /// 采集面：`ALL` 的长度是计数数组、渲染与反查的**唯一**长度事实源。
    pub const ALL: &'static [Site] = &[
        Site::SsoLogoRead,
        Site::SsoLogoWrite,
        Site::SsoUserinfoRead,
        Site::SsoUserinfoWrite,
        Site::SessionOldHashRead,
        Site::FlowRemindWindow,
        Site::FlowEscalateWindow,
    ];

    /// 进日志与指标的标签（**不含键名**，见模块文档的边界条目）。
    pub const fn label(self) -> &'static str {
        match self {
            Site::SsoLogoRead => "sso_logo_cache_read",
            Site::SsoLogoWrite => "sso_logo_cache_write",
            Site::SsoUserinfoRead => "sso_userinfo_cache_read",
            Site::SsoUserinfoWrite => "sso_userinfo_cache_write",
            Site::SessionOldHashRead => "login_old_session_lookup",
            Site::FlowRemindWindow => "flow_remind_window",
            Site::FlowEscalateWindow => "flow_escalate_window",
        }
    }

    /// 枚举标识符序列，与 `ALL` **逐位对应**（类型层就钉住长度）。
    ///
    /// 为什么接线反查要用它而不是 `label()`：生产码写的是 `Site::SsoLogoRead`，而指标标签
    /// `sso_logo_read` 从不以字面量出现在消费者里——拿标签去反查会把七条站点全报成
    /// "没接线"（本批第一次真跑正是这副样子），而"匹配不到就放行"等于把这条锁关掉。
    /// 方向取"标识符必须出现在采集面里"：拼错一个名字 ⇒ 那条站点立刻红。
    pub const VARIANTS: [&'static str; 7] = [
        "SsoLogoRead",
        "SsoLogoWrite",
        "SsoUserinfoRead",
        "SsoUserinfoWrite",
        "SessionOldHashRead",
        "FlowRemindWindow",
        "FlowEscalateWindow",
    ];

    /// 该站点在源码里的标识符（接线反查的 needle）。
    pub fn variant(self) -> &'static str {
        Site::VARIANTS[self.index()]
    }

    /// `label()` 的逆映射：接线反查从源码文本取出标签后要能回到 `Site`，
    /// 回不去 = 那条站点没有事实源。
    pub fn from_label(label: &str) -> Option<Site> {
        Site::ALL.iter().copied().find(|s| s.label() == label)
    }

    fn index(self) -> usize {
        Site::ALL
            .iter()
            .position(|s| *s == self)
            .unwrap_or_else(|| panic!("站点 {self:?} 未进 ALL 采集面"))
    }
}

/// `get` 的三态结局
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheRead {
    /// 键在且读到了值
    Hit(String),
    /// 键确实不存在（或未配置）——正常态
    Miss,
    /// 读不出来（后端故障）。**绝不等于 `Miss`**
    Unavailable,
}

impl CacheRead {
    /// 读侧采集面 = 结局标签序列。这里**不放 `CacheRead` 值**：`Hit` 带 `String`，
    /// 而 `const` 上下文要求元素可被编译期求值又不跑 `Drop`（E0493），
    /// 于是这一族以标签为事实源——顺序必须与 `CacheRead::index()` 逐位相同，
    /// 由 `outcome_families_match_their_own_indices` 钉（漏一支是**测试红**，
    /// 而数组长度不符是**编译失败**，两种失败都不许靠人记）。
    pub const LABELS: [&'static str; 3] = ["hit", "miss", "unavailable"];

    /// 造一个 `Hit` 样本（测试与调用点用；采集面不消费它，见 `CacheRead::LABELS` 的理由）
    pub fn hit(v: impl Into<String>) -> Self {
        CacheRead::Hit(v.into())
    }

    pub fn label(&self) -> &'static str {
        match self {
            CacheRead::Hit(_) => "hit",
            CacheRead::Miss => "miss",
            CacheRead::Unavailable => "unavailable",
        }
    }
    /// 计数下标（顺序必须与 `LABELS` 逐位相同，由 `outcome_families_match_their_own_indices` 钉）
    pub fn index(&self) -> usize {
        match self {
            CacheRead::Hit(_) => 0,
            CacheRead::Miss => 1,
            CacheRead::Unavailable => 2,
        }
    }
}

/// `set_nx_ex` 的三态结局
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    /// 抢到窗口（本实例该做这件事）
    Acquired,
    /// 别的实例已持有（正常态：本轮跳过）
    Contended,
    /// 存储不可用 ⇒ **既不是抢到也不是没抢到**。调用点必须自己选一条路：
    /// 本仓两处流程提醒窗口都选"照常执行 + 单独计数"（去重的事实源在 DB 的
    /// `last_reminded_at`，共享态只是多实例互斥窗，漏发比重复一次更坏）。
    /// 此前两处都写 `unwrap_or(false)`＝"没抢到"⇒ 跳过，而两处注释的意图**相反**
    /// （一处写"视为未抢占成功"、一处写"故障时最坏退化为各发一次"）——
    /// 折叠写法让两个意图都无法由代码保证，见 `sys_flow_service::scan_timeouts_with_redis` 的文档。
    Unavailable,
}

impl Window {
    pub const ALL: &'static [Window] = &[Window::Acquired, Window::Contended, Window::Unavailable];
    pub const fn label(self) -> &'static str {
        match self {
            Window::Acquired => "acquired",
            Window::Contended => "contended",
            Window::Unavailable => "unavailable",
        }
    }
    pub const fn index(self) -> usize {
        match self {
            Window::Acquired => 0,
            Window::Contended => 1,
            Window::Unavailable => 2,
        }
    }
}

/// `set_ex` 的结局（写侧只有两支，但"丢掉结局"不是其中任何一支）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAck {
    Done,
    Failed,
}

impl WriteAck {
    pub const ALL: &'static [WriteAck] = &[WriteAck::Done, WriteAck::Failed];
    pub const fn label(self) -> &'static str {
        match self {
            WriteAck::Done => "done",
            WriteAck::Failed => "failed",
        }
    }
    pub const fn index(self) -> usize {
        match self {
            WriteAck::Done => 0,
            WriteAck::Failed => 1,
        }
    }
}

// 编译期把"数组长度 = 采集面长度"钉死：扩 `Site` 忘了改数组，构建即失败。
const _: () = assert!(Site::ALL.len() == 7);
const _: () = assert!(CacheRead::LABELS.len() == 3);
const _: () = assert!(Window::ALL.len() == 3);
const _: () = assert!(WriteAck::ALL.len() == 2);

// ⚠ 这四组**必须是 `static` 而不是 `const`**：`const` 数组在每个**使用点**各生成一份
// 新值，于是 `fetch_add` 落在临时副本上、渲染时读到的又是另一份全零副本 ⇒ 指标恒 0，
// 而 `warn_once` 的"每站点只告警一次"退化成"每次调用都告警"（b69 那条日志洪水反例）。
// 两种坏法都不会让任何既有断言变红——所以由 `counters_accumulate_across_calls` 与
// `warn_once_remembers_that_it_already_spoke` 各自钉住"整进程只有一份"这件事，
// 把 `static` 改回 `const` 会同时红这两条（盘上变异 M-J）。
static READ_COUNTS: [AtomicU64; Site::ALL.len() * CacheRead::LABELS.len()] =
    [const { AtomicU64::new(0) }; Site::ALL.len() * CacheRead::LABELS.len()];
static WINDOW_COUNTS: [AtomicU64; Site::ALL.len() * Window::ALL.len()] =
    [const { AtomicU64::new(0) }; Site::ALL.len() * Window::ALL.len()];
static WRITE_COUNTS: [AtomicU64; Site::ALL.len() * WriteAck::ALL.len()] =
    [const { AtomicU64::new(0) }; Site::ALL.len() * WriteAck::ALL.len()];
/// 每个站点只打一条 WARN（每请求路径，重复打会把真实信号刷成流水，b69）
static WARNED: [AtomicBool; Site::ALL.len()] = [const { AtomicBool::new(false) }; Site::ALL.len()];

fn read_slot(site: Site, outcome_index: usize) -> usize {
    site.index() * CacheRead::LABELS.len() + outcome_index
}
fn window_slot(site: Site, outcome: Window) -> usize {
    site.index() * Window::ALL.len() + outcome.index()
}
fn write_slot(site: Site, outcome: WriteAck) -> usize {
    site.index() * WriteAck::ALL.len() + outcome.index()
}

/// 记一档读侧结局（从异步壳里抽出来，是为了让"计数确实累加了"这件事能被单测喂到）。
fn record_read(site: Site, outcome: &CacheRead) {
    READ_COUNTS[read_slot(site, outcome.index())].fetch_add(1, Ordering::Relaxed);
}
fn record_window(site: Site, outcome: Window) {
    WINDOW_COUNTS[window_slot(site, outcome)].fetch_add(1, Ordering::Relaxed);
}
fn record_write(site: Site, outcome: WriteAck) {
    WRITE_COUNTS[write_slot(site, outcome)].fetch_add(1, Ordering::Relaxed);
}

/// 故障留痕：同一站点整进程只打一条（`swap` 返回旧值，`true` = 已经打过）
fn warn_once(site: Site, detail: &str) {
    if WARNED[site.index()].swap(true, Ordering::Relaxed) {
        return;
    }
    let detail = crate::middleware::oper_log::safe_truncate(
        &crate::common::redact::fold_abs_paths(detail),
        240,
    );
    tracing::warn!(
        "共享态故障（站点 {}）：{detail}——「读不出来」不得读成「未命中」、「存储不可用」\
         不得读成「未抢占」；本轮结局由调用点的三态分支决定",
        site.label()
    );
}

/// **纯**分类：`get` 的返回 → 三态 + （故障时）留痕文本。
///
/// 三支都可被单测喂到（真实存储不会配合造故障），所以 `Err` 那一支不是"想想就知道对"。
pub fn classify_read(raw: Result<Option<String>, StoreError>) -> (CacheRead, Option<String>) {
    match raw {
        Ok(Some(v)) => (CacheRead::Hit(v), None),
        Ok(None) => (CacheRead::Miss, None),
        Err(e) => (CacheRead::Unavailable, Some(e.to_string())),
    }
}

/// **纯**分类：`set_nx_ex` 的返回 → 三态 + （故障时）留痕文本。
pub fn classify_window(raw: Result<bool, StoreError>) -> (Window, Option<String>) {
    match raw {
        Ok(true) => (Window::Acquired, None),
        Ok(false) => (Window::Contended, None),
        Err(e) => (Window::Unavailable, Some(e.to_string())),
    }
}

/// **纯**分类：`set_ex` 的返回 → 结局 + （故障时）留痕文本。
pub fn classify_write(raw: Result<(), StoreError>) -> (WriteAck, Option<String>) {
    match raw {
        Ok(()) => (WriteAck::Done, None),
        Err(e) => (WriteAck::Failed, Some(e.to_string())),
    }
}

/// 读一个键，**三态**返回。
///
/// 拿到 `Unavailable` 时调用点必须显式选一条路（回落取真值 / 跳过并计数），
/// 不得 `if let CacheRead::Hit` 之后把另两支都当"没有"。
pub async fn read_key(store: &dyn SharedStore, key: &str, site: Site) -> CacheRead {
    let (outcome, detail) = classify_read(store.get(key).await);
    if let Some(detail) = detail {
        warn_once(site, &detail);
    }
    record_read(site, &outcome);
    outcome
}

/// 抢一个跨实例互斥窗（`SET NX EX`），**三态**返回。
pub async fn acquire_window(
    store: &dyn SharedStore,
    key: &str,
    ttl_secs: u64,
    site: Site,
) -> Window {
    let (outcome, detail) = classify_window(store.set_nx_ex(key, "1", ttl_secs).await);
    if let Some(detail) = detail {
        warn_once(site, &detail);
    }
    record_window(site, outcome);
    outcome
}

/// 尽力写一个键：失败**必须留痕并计数**，但调用点不必因它中断已提交的业务。
///
/// 返回 [`WriteAck`]（不是 `()`）——"接收了结果又把结局丢掉"这一族形状
/// 由生产码形状锁禁止（`let _: Result`）。
pub async fn write_best_effort(
    store: &dyn SharedStore,
    key: &str,
    value: &str,
    ttl_secs: u64,
    site: Site,
) -> WriteAck {
    let (outcome, detail) = classify_write(store.set_ex(key, value, ttl_secs).await);
    if let Some(detail) = detail {
        warn_once(site, &detail);
    }
    record_write(site, outcome);
    outcome
}

/// 本轮各站点各结局的累计次数（`/metrics` 渲染，接在 `handler/health.rs` 的
/// `metrics` 出口——工程硬基线 B.4「组件级 metrics 内建」：有通道就必须能被看见，
/// 否则运维收到的症状只是"有时候慢"，而"读不出来"与"未命中"在那个症状里同形）。
///
/// 采集面 = `Site::ALL` × 各族标签序列：新增站点或结局漏登记 ⇒
/// `metrics_render_cover_every_site_and_outcome` 红（"有计数、`/metrics` 里看不见"
/// 结构上不可能，AGENTS 前言 ⑥）。
pub fn render_prometheus() -> String {
    let mut out = String::from(
        "# HELP stepby_shared_store_read_total 共享态键读取的三态结局累计（unavailable 非零必须能归因到站点）\n\
         # TYPE stepby_shared_store_read_total counter\n",
    );
    for site in Site::ALL {
        for (i, label) in CacheRead::LABELS.iter().enumerate() {
            let n = READ_COUNTS[read_slot(*site, i)].load(Ordering::Relaxed);
            out.push_str(&format!(
                "stepby_shared_store_read_total{{site=\"{}\",outcome=\"{label}\"}} {n}\n",
                site.label()
            ));
        }
    }
    out.push_str(
        "# HELP stepby_shared_store_window_total 跨实例互斥窗抢占的三态结局累计\
         （contended 与 unavailable 是两件事：前者是别的副本在做，后者是没人能做）\n\
         # TYPE stepby_shared_store_window_total counter\n",
    );
    for site in Site::ALL {
        for outcome in Window::ALL {
            let n = WINDOW_COUNTS[window_slot(*site, *outcome)].load(Ordering::Relaxed);
            out.push_str(&format!(
                "stepby_shared_store_window_total{{site=\"{}\",outcome=\"{}\"}} {n}\n",
                site.label(),
                outcome.label()
            ));
        }
    }
    out.push_str(
        "# HELP stepby_shared_store_write_total 尽力写键的结局累计（failed 即「故障曾发生过」的证据）\n\
         # TYPE stepby_shared_store_write_total counter\n",
    );
    for site in Site::ALL {
        for outcome in WriteAck::ALL {
            let n = WRITE_COUNTS[write_slot(*site, *outcome)].load(Ordering::Relaxed);
            out.push_str(&format!(
                "stepby_shared_store_write_total{{site=\"{}\",outcome=\"{}\"}} {n}\n",
                site.label(),
                outcome.label()
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::prod_scan;
    use crate::common::prod_scan::Scan;

    /// 每个 `Site` 的标签唯一且非空：标签进日志与指标，撞名 = 两个站点混成一桶，
    /// 空 = 指标里出现 `site=""`。
    #[test]
    fn site_labels_are_unique_and_non_empty() {
        let mut seen = std::collections::HashSet::new();
        for site in Site::ALL {
            assert!(!site.label().is_empty(), "{site:?} 标签为空");
            assert!(
                seen.insert(site.label()),
                "站点标签重复：{}（两个站点会被并进同一条指标）",
                site.label()
            );
        }
        assert_eq!(Site::ALL.len(), 7, "采集面条数与编译期钳不一致");
    }

    /// `from_label` 与 `label()` 必须**双向闭合**。
    /// `VARIANTS` 与 `ALL` 必须**逐位**对应：数组长度由类型钉死，顺序错了则由这一条抓。
    ///
    /// 名字本身拼错不在这里判（判不了——没有编译期事实可比），它表现为"该站点没接线"，
    /// 方向是 fail-closed：宁可红一条不存在的站点，也不得静默放行。
    #[test]
    fn variants_align_with_the_all_face_by_index() {
        for (i, site) in Site::ALL.iter().enumerate() {
            assert_eq!(
                site.variant(),
                Site::VARIANTS[i],
                "第 {i} 条站点的标识符与 ALL 错位"
            );
            assert_eq!(
                site.index(),
                i,
                "第 {i} 条站点的 ALL 位次不连续 ⇒ 计数槽位会串"
            );
        }
        assert_eq!(Site::VARIANTS.len(), Site::ALL.len());
    }

    #[test]
    fn label_roundtrip_is_closed() {
        for site in Site::ALL {
            assert_eq!(Site::from_label(site.label()), Some(*site));
        }
        assert_eq!(Site::from_label("不存在的标签"), None);
    }

    /// 结局族的序位与标签必须**同源**：`index()` 与 `ALL` 的顺序错开 ⇒
    /// 计数写进隔壁桶，指标看着正常但张冠李戴（b89 那条"标签与计数同源"）。
    #[test]
    fn outcome_families_match_their_own_indices() {
        // 读侧采集面是**标签**序列（`CacheRead` 含 `String`，const 里放不下值），
        // 所以这里按顺序造出样本，逐位对"标签 = 该序位的 `label()` = `index()`"。
        let read_samples = [CacheRead::hit("x"), CacheRead::Miss, CacheRead::Unavailable];
        assert_eq!(
            read_samples.len(),
            CacheRead::LABELS.len(),
            "读侧样本数与采集面标签数不一致 ⇒ 新增结局没登记"
        );
        for (i, (o, label)) in read_samples.iter().zip(CacheRead::LABELS).enumerate() {
            assert_eq!(o.index(), i, "CacheRead 序位与采集面不一致：{o:?}");
            assert_eq!(o.label(), label, "CacheRead 标签与采集面不一致：{o:?}");
        }
        for (i, o) in Window::ALL.iter().enumerate() {
            assert_eq!(o.index(), i, "Window 序位与 ALL 不一致：{o:?}");
        }
        for (i, o) in WriteAck::ALL.iter().enumerate() {
            assert_eq!(o.index(), i, "WriteAck 序位与 ALL 不一致：{o:?}");
        }
    }

    /// 读侧三态矩阵：每一支都必须由**它自己的输入**得出，且三支互不相同。
    ///
    /// `Ok(None)` 与 `Err` 折叠成同一个值正是本模块立案的缺陷形状，所以这一条
    /// 必须断"两者不相等"，而不是只断各自的值。
    #[test]
    fn classify_read_covers_all_three_arms_distinctly() {
        let (hit, d1) = classify_read(Ok(Some("v".to_string())));
        let (miss, d2) = classify_read(Ok(None));
        let (down, d3) = classify_read(Err(StoreError::backend(&"connection refused")));
        assert!(matches!(hit, CacheRead::Hit(ref v) if v == "v"));
        assert_eq!(miss, CacheRead::Miss);
        assert_eq!(down, CacheRead::Unavailable);
        assert_ne!(miss, down, "「没有」与「读不出来」必须是两个结局");
        assert!(d1.is_none() && d2.is_none(), "正常态不得留痕");
        let detail = d3.expect("Err 分支必须产出留痕文本");
        assert!(
            detail.contains("connection refused"),
            "留痕丢了原因：{detail}"
        );
    }

    /// 窗口三态矩阵（`Ok(false)` 与 `Err` 不得同形——那是本批修掉的真实缺陷）。
    #[test]
    fn classify_window_covers_all_three_arms_distinctly() {
        let (a, d1) = classify_window(Ok(true));
        let (c, d2) = classify_window(Ok(false));
        let (u, d3) = classify_window(Err(StoreError::backend(&"timeout")));
        assert_eq!(a, Window::Acquired);
        assert_eq!(c, Window::Contended);
        assert_eq!(u, Window::Unavailable);
        assert_ne!(c, u, "「没抢到」与「存储坏了」必须是两个结局");
        assert!(d1.is_none() && d2.is_none());
        assert!(d3.expect("Err 必须留痕").contains("timeout"));
    }

    /// 写侧两支：失败必须成为可判定的结局（此前是 `let _: Result` = 没有结局）。
    #[test]
    fn classify_write_names_the_failure() {
        let (done, d1) = classify_write(Ok(()));
        let (failed, d2) = classify_write(Err(StoreError::backend(&"READONLY")));
        assert_eq!(done, WriteAck::Done);
        assert_eq!(failed, WriteAck::Failed);
        assert!(d1.is_none());
        assert!(d2.expect("写失败必须留痕").contains("READONLY"));
    }

    /// 指标族由采集面派生：每个站点的每种结局各一条，**漏一项就渲染不出**。
    /// "有通道、`/metrics` 里看不见"因此结构上不可能（同 `resource_gate`）。
    #[test]
    fn metrics_render_cover_every_site_and_outcome() {
        let text = render_prometheus();
        for site in Site::ALL {
            for label in CacheRead::LABELS {
                assert!(
                    text.contains(&format!(
                        "stepby_shared_store_read_total{{site=\"{}\",outcome=\"{label}\"}}",
                        site.label()
                    )),
                    "读族缺 {}/{label}",
                    site.label()
                );
            }
            for outcome in Window::ALL {
                assert!(
                    text.contains(&format!(
                        "stepby_shared_store_window_total{{site=\"{}\",outcome=\"{}\"}}",
                        site.label(),
                        outcome.label()
                    )),
                    "窗口族缺 {}/{}",
                    site.label(),
                    outcome.label()
                );
            }
            for outcome in WriteAck::ALL {
                assert!(
                    text.contains(&format!(
                        "stepby_shared_store_write_total{{site=\"{}\",outcome=\"{}\"}}",
                        site.label(),
                        outcome.label()
                    )),
                    "写族缺 {}/{}",
                    site.label(),
                    outcome.label()
                );
            }
        }
        // 三族都必须既有 `# HELP` 又有 `# TYPE`，且 HELP 在前（Prometheus 文本格式
        // 的既有族序；抓取器对调序宽容，但**本仓其余族都是 HELP 在前**，混着写
        // 就是"同一件事两种形状"，下一个人不知道该照哪个抄）
        for family in [
            "stepby_shared_store_read_total",
            "stepby_shared_store_window_total",
            "stepby_shared_store_write_total",
        ] {
            let help = text
                .find(&format!("# HELP {family} "))
                .unwrap_or_else(|| panic!("{family} 没有 HELP 行"));
            let type_line = text
                .find(&format!("# TYPE {family} counter"))
                .unwrap_or_else(|| panic!("{family} 没有 TYPE 行"));
            assert!(help < type_line, "{family} 的 HELP 必须排在 TYPE 之前");
        }
    }

    /// 计数槽位互不重叠：同一站点的不同结局必须落在**不同**下标
    /// （槽位算错 = 两个结局并进一个桶，指标恒看似正常）。
    #[test]
    fn count_slots_are_disjoint_per_site_and_outcome() {
        let mut seen = std::collections::HashSet::new();
        for site in Site::ALL {
            for i in 0..CacheRead::LABELS.len() {
                assert!(seen.insert(read_slot(*site, i)), "读族槽位重叠");
            }
        }
        assert_eq!(seen.len(), Site::ALL.len() * CacheRead::LABELS.len());
        let mut wseen = std::collections::HashSet::new();
        for site in Site::ALL {
            for outcome in Window::ALL {
                assert!(wseen.insert(window_slot(*site, *outcome)), "窗口族槽位重叠");
            }
        }
        assert_eq!(wseen.len(), Site::ALL.len() * Window::ALL.len());
        let mut xseen = std::collections::HashSet::new();
        for site in Site::ALL {
            for outcome in WriteAck::ALL {
                assert!(xseen.insert(write_slot(*site, *outcome)), "写族槽位重叠");
            }
        }
        assert_eq!(xseen.len(), Site::ALL.len() * WriteAck::ALL.len());
    }

    /// 取渲染文本里某一族的全部计数之和（并行安全：只判**单调前进**，不判单档）。
    fn rendered_total(family_prefix: &str) -> u64 {
        render_prometheus()
            .lines()
            .filter(|l| l.starts_with(family_prefix))
            .filter_map(|l| l.rsplit(' ').next())
            .filter_map(|v| v.parse::<u64>().ok())
            .sum()
    }

    /// **整进程只有一份计数数组**（`static` 而不是 `const`）：`const` 会在每个使用点
    /// 各生成一份新值 ⇒ `fetch_add` 落在临时副本上、渲染读到的是另一份全零副本，
    /// 于是"指标恒 0"这件事**没有任何既有断言能看见**（b149 由 clippy 抓到，
    /// 但 clippy 是编译期提醒，运行时判据缺位就还是"改回去照样绿"）。
    #[test]
    fn counters_accumulate_across_calls() {
        let before = rendered_total("stepby_shared_store_read_total{");
        record_read(Site::SsoLogoRead, &CacheRead::Unavailable);
        record_read(Site::SsoLogoRead, &CacheRead::Unavailable);
        let after = rendered_total("stepby_shared_store_read_total{");
        assert!(
            after >= before + 2,
            "两次记录之后读族之和必须前进 ≥2，实测 {before} → {after} ⇒              计数数组在每个使用点各得一份副本（`const`），指标恒 0"
        );
    }

    /// 同上，但测**首告记忆**：`const` 时 `WARNED` 每次读回都是新的 `false`，
    /// "每站点只告警一次"静默退化成"每次调用都告警"（b69 的日志洪水反例）。
    #[test]
    fn warn_once_remembers_that_it_already_spoke() {
        let site = Site::FlowRemindWindow;
        warn_once(site, "b149 单例性探针");
        assert!(
            WARNED[site.index()].load(std::sync::atomic::Ordering::Relaxed),
            "告警过一次之后标记必须仍然可读为已告警 ⇒ 读到的若是新副本（`const`），             站点 {} 的首告闸等于没有闸",
            site.label()
        );
    }

    /// 留痕文本必须过路径折叠（`local` 档是 SQLite，错误串会带库文件绝对路径，C.9）。
    ///
    /// 这一条测的是 `warn_once` 用到的那条链，而不是"我记得调了 fold_abs_paths"。
    #[test]
    fn fold_paths_strips_a_database_path() {
        let raw = r#"连接失败: unable to open database file "D:\Projects\stepby\data\app.db""#;
        let folded = crate::common::redact::fold_abs_paths(raw);
        assert!(
            !folded.contains("D:\\Projects\\stepby"),
            "绝对路径没被折叠：{folded}"
        );
    }

    /// **接线反查**：采集面里每个站点的标签都必须在**消费者**的生产码出现
    /// （枚举了一个没人用的站点、或新增站点忘了接，都由这一条抓——"写了没接线=没写"）。
    ///
    /// 采集面**必须剔掉本文件**：标签字面量就写在这里的 `label()` 里，算进面则每条
    /// 恒命中、锁永远绿（前言 ㉞ 那条"反向 needle 不得出现在判据源码里"的同一形状）。
    #[test]
    fn every_site_variant_is_wired_in_production_code() {
        let scan = Scan {
            exclude: &["src/common/store_outcome.rs"],
            ..Scan::default()
        };
        let files = prod_scan::prod_files(&scan);
        prod_scan::require_volume(&files, 300, 40_000, "共享态通道接线反查面");
        let texts: Vec<String> = files.iter().map(|f| f.text()).collect();
        let mut missing = Vec::new();
        for site in Site::ALL {
            let needle = format!("Site::{}", site.variant());
            if !texts.iter().any(|t| t.contains(&needle)) {
                missing.push(needle);
            }
        }
        assert!(
            missing.is_empty(),
            "站点 {missing:?} 在采集面里却没有任何生产码用它 ⇒ 通道写了没接线"
        );
        // 活性正控：一个"只存在于枚举、不存在于消费者"的标签必须被抓成缺失
        // （否则上面的循环可能是"面为空 ⇒ 任何标签都算命中"）
        assert!(
            !texts
                .iter()
                .any(|t| t.contains("Site::B149SiteThatDoesNotExist")),
            "反控文本竟然在面里出现 ⇒ 采集面含了不该含的文件"
        );
    }

    /// **异步壳形状锁**：三个入口函数都必须真的经过对应分类器，
    /// 否则"分类器写好了但壳里直接 `store.get(..).await.ok()`"照样全绿。
    #[test]
    fn async_wrappers_go_through_the_classifiers() {
        let read = function_body("pub async fn read_key");
        assert!(read.contains("store.get("), "read_key 没真的取键：{read}");
        assert!(
            read.contains("classify_read("),
            "read_key 绕过分类器 ⇒ 三态在调用点不可判"
        );
        assert!(!read.contains(".unwrap_or("), "read_key 里不得折叠：{read}");
        // 分类器对了但**没记档** = `/metrics` 恒 0 = 有通道、没观测（B.4）
        assert!(
            read.contains("record_read("),
            "read_key 必须把结局记进计数面：{read}"
        );

        let win = function_body("pub async fn acquire_window");
        assert!(
            win.contains("set_nx_ex("),
            "acquire_window 没真的抢占：{win}"
        );
        assert!(
            win.contains("classify_window("),
            "acquire_window 绕过分类器"
        );
        assert!(
            !win.contains(".unwrap_or("),
            "acquire_window 里不得折叠：{win}"
        );
        assert!(
            win.contains("record_window("),
            "acquire_window 必须把结局记进计数面：{win}"
        );

        let write = function_body("pub async fn write_best_effort");
        assert!(
            write.contains("set_ex("),
            "write_best_effort 没真的写键：{write}"
        );
        assert!(
            write.contains("classify_write("),
            "write_best_effort 绕过分类器"
        );
        assert!(
            !write.contains(".unwrap_or("),
            "write_best_effort 里不得折叠：{write}"
        );
        assert!(
            write.contains("record_write("),
            "write_best_effort 必须把结局记进计数面：{write}"
        );

        // 活性反证：缺陷形状（本批修掉的原样）必须被同一判据抓到
        let defective = "let acquired = store.set_nx_ex(&key, \"1\", ttl).await.unwrap_or(false);";
        assert!(
            defective.contains(".unwrap_or("),
            "反例文本必须含被禁形状，否则上面三条断言是恒真"
        );
    }

    /// `/metrics` 出口确实挂载了本族（写了渲染函数但没接进 `metrics` = 没观测）。
    ///
    /// 名字里带上本族：`encrypted_value` 有同名的另一把挂载锁，两条都按**短名**归因时
    /// 会互相顶班（摘掉一族的挂载，红的却是另一族那条）。
    #[test]
    fn metrics_endpoint_mounts_the_store_outcome_family() {
        let text = prod_scan::prod_file("src/handler/health.rs", &Scan::default()).text();
        let mount = "store_outcome::render_prometheus()";
        let at = text.find(mount).unwrap_or_else(|| {
            panic!("health.rs 的 metrics 出口必须渲染 `{mount}`，否则三态结局只有日志、没有指标")
        });
        // 挂载点必须在出口函数**之内**：整份文件的 `contains` 会被函数之前的注释或另一处
        // 调用满足，那既不是"接进 `/metrics`"，也不是本族该有的一条腿。
        let head = text.find("pub async fn metrics(").unwrap_or_else(|| {
            panic!("找不到 `pub async fn metrics(` ⇒ 出口签名变了，本锁的输入已坏")
        });
        assert!(
            at > head,
            "`store_outcome::render_prometheus()` 出现在 metrics 出口之前 ⇒ 没接进 `/metrics`，\
             三态结局只有日志、没有指标"
        );
    }

    /// 取"以 `head` 起始的函数体"（花括号配平）。取不到即 panic——
    /// 判据输入坏了必须响亮失败，不得返回空串让上面的断言恒真。
    fn function_body(head: &str) -> String {
        let scan = Scan::default();
        let text = prod_scan::prod_file("src/common/store_outcome.rs", &scan).text();
        let at = text
            .find(head)
            .unwrap_or_else(|| panic!("找不到函数头 `{head}` ⇒ 签名变了，本锁的输入已坏"));
        let open = text[at..]
            .find('{')
            .unwrap_or_else(|| panic!("`{head}` 之后找不到左花括号 ⇒ 输入坏"));
        let mut depth = 0usize;
        let bytes = text.as_bytes();
        for i in (at + open)..bytes.len() {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return text[at + open..=i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("函数 `{head}` 花括号不配平 ⇒ 输入坏");
    }
}
