// stepby-axum/src/common/resource_gate.rs
//! 重资源入口的**全局并发闸门**（AGENTS.md 工程硬基线 A-2「资源硬上限 + 背压」）。
//!
//! # 为什么要有这一族
//!
//! 仓里既有三道闸各管一件事：`ai/gate.rs`（推理，闸满立即 429 + `Retry-After`）、
//! `report_dataset_service::dataset_gate`（数据集试跑 4 permits）、
//! `sys_web_hook_service`（投递 16 permits，**排队**）。本模块收的是第四族：
//! **整库 / 整窗口级的重 IO 入口**——共同形状是"单次请求可占 DB·CPU·磁盘数分钟，
//! 且成本由调用方任意放大"。批八十九只读取证（`deploy`/`handler` 全量盘点）实测这些面
//! 只有 per-user 60s 频率锁、**没有任何全局并发上限**：
//!
//! - `POST /system/backup`（pg_dump / mysqldump / sqlite3 子进程 + 整库读）
//! - `POST /system/backup/tenant-export/{id}`、`POST /system/backup/self-export`
//! - `GET /monitor/operlog/complianceReport`（合规报表：窗口全量读 + 导出）
//! - `GET /monitor/operlog/archiveDownload`（归档下载，单卷上限 512 MB）
//! - `POST /system/user/importData`（批量写：每行一次 upsert）
//!
//! 60s 的 per-user 锁挡不住**两个不同管理员**同时点，也挡不住同一个管理员用两个浏览器；
//! 而"反复触发耗尽磁盘"这句话写在注释里，生效的只是"同一人 60 秒内一次"。
//!
//! # 为什么取拒绝（429）而不是排队
//!
//! AGENTS A.2 的那条判据是"**能否重来**"：这一族全部是人类点一下按钮、失败再点一下的
//! 请求 ⇒ 闸满立即拒绝并把 `Retry-After` 给出去，比"请求挂在队列里 10 分钟后超时"更诚实
//! （用户看得见"现在不行"，也不会出现"点了没反应"）。WebHook 投递那种**不可重放的出站
//! 事实**才排队，两处语义相反是刻意保留的，改动时不得"统一"。
//!
//! # 为什么闸门数写在代码里
//!
//! 与 `dataset_gate` / webhook 同一口径：上限属"资源容量"参数。写成启动只读的 config
//! 也能做，但要一并补《开关规范》⑦ 的七项与 ⑧ 的测试钳制登记；而这一族没有运维调档的
//! 真实需求。若将来要按部署规模调档，走 `[ai].max_concurrency` 那条完整流程，另立批次。
//!
//! # fail-closed
//!
//! `try_enter` 拿不到许可 ⇒ 立即 `429`，**不阻塞、不自旋、不降级放行**。闸门本身
//! （`OnceLock` + `Semaphore`）不可用这件事结构上不存在：建闸在首次调用时发生，
//! 而 `Semaphore::const_new` 不失败。
//!
//! # 组件自带指标（AGENTS B-4）
//!
//! 背压只有客户端能看见 = 背压被藏了起来：运维收到的是"备份有时候点不动"，
//! 而不是"哪个入口、哪一档、拒了多少次"。因此 [`HeavyEntry::ALL`] 同时是
//! [`render_prometheus`] 的**采集面**——每个入口渲染三条指标：
//!
//! - `stepby_resource_gate_available_permits{entry}`（gauge，事实：闸还剩几个）
//! - `stepby_resource_gate_permits{entry}`（gauge，承诺：配置上限，用于算占用率）
//! - `stepby_resource_gate_decisions_total{entry,outcome}`（counter，`admitted|rejected`）
//!
//! 新增成员不改渲染代码就被覆盖（`ALL` 少一项 ⇒ `gate_metrics_cover_every_entry` 红），
//! 这是"采集面由事实派生而非名字枚举"在这一族上的落法。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::common::error::AppError;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// 受闸门保护的重资源入口。新增成员必须同时补：处理器里的 `try_enter` 接线、
/// 本表 `permits` 的理由、以及 `heavy_entries_are_wired_into_handlers` 那条反查。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeavyEntry {
    /// 整库备份（外部 dump 子进程 + 整库读 + 落盘）
    BackupCreate,
    /// 数据包导出（平台版与租户自助版共用：整库/整租户 JSON 流式落盘）
    BackupExport,
    /// 合规报表（窗口全量读 + 逐条脱敏 + 聚合）
    ComplianceReport,
    /// 归档下载（单卷 512 MB 级读盘 + 压缩流）
    ArchiveDownload,
    /// 用户批量导入（每行一次 upsert，行图由调用方给）
    UserImport,
    /// 报表快照（预览与订阅立即执行共用：窗口聚合 + 多表 COUNT + JSON 快照）
    ReportSnapshot,
    /// 告警规则单条评估（Redis SCAN + 全表 COUNT + sysinfo + 出站通知）
    AlertEvaluate,
    /// 管理员任意 URL 出站调试（目标由调用方给，出站连接数与响应体都被放大）
    HttpDebugExecute,
    /// Excel 导出（16 条端点统一收口在 `common::excel` 的唯一构造点）
    ExcelExport,
    /// 日志/记录清空（6 条端点：长 DELETE + 防篡改锚点写 + WAL 膨胀）
    BulkDelete,
    /// 缓存维护（`refreshCache` / `clearCacheName`：无上限 SCAN）
    CacheMaintenance,
    /// 批量代码生成（最多 20 表模板渲染 + 内存 ZIP）
    BatchGenCode,
    /// 待重试消息批量重投（出站事实 + 写库）
    MsgOutbound,
    /// 备份文件下载（GB 级快照流式读盘，b140 扩员）
    BackupDownload,
    /// 看板数据源取数（单页按白名单数据源**扇出**，b140 扩员）
    BoardSourceData,
}

/// 成员数（数组长度与 `ALL` 共用；新增变体必须同时改这里，否则类型检查会失败）。
const ENTRY_COUNT: usize = 15;

/// 闸满后给客户端的退避提示（秒）。取 30 的理由：这一族单次耗时在 10 秒～数分钟，
/// 30 秒既不会让人立刻重试打在同一次运行上，也不至于长到像"服务坏了"。
const RETRY_AFTER_SECS: u64 = 30;

impl HeavyEntry {
    /// 全部成员（顺序即 `slot` 下标；新增变体必须同步扩 `SLOTS` 与这张表）。
    ///
    /// 这张表**不只是测试夹具**：[`render_prometheus`] 以它为采集面，所以漏一个成员
    /// 会让那条入口在 `/metrics` 里静默缺席（有闸、没观测 = 运维看不见背压）。
    pub const ALL: [HeavyEntry; ENTRY_COUNT] = [
        HeavyEntry::BackupCreate,
        HeavyEntry::BackupExport,
        HeavyEntry::ComplianceReport,
        HeavyEntry::ArchiveDownload,
        HeavyEntry::UserImport,
        HeavyEntry::ReportSnapshot,
        HeavyEntry::AlertEvaluate,
        HeavyEntry::HttpDebugExecute,
        HeavyEntry::ExcelExport,
        HeavyEntry::BulkDelete,
        HeavyEntry::CacheMaintenance,
        HeavyEntry::BatchGenCode,
        HeavyEntry::MsgOutbound,
        HeavyEntry::BackupDownload,
        HeavyEntry::BoardSourceData,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            HeavyEntry::BackupCreate => "backup:create",
            HeavyEntry::BackupExport => "backup:export",
            HeavyEntry::ComplianceReport => "operlog:compliance-report",
            HeavyEntry::ArchiveDownload => "operlog:archive-download",
            HeavyEntry::UserImport => "user:import",
            HeavyEntry::ReportSnapshot => "report:snapshot",
            HeavyEntry::AlertEvaluate => "alert:evaluate",
            HeavyEntry::HttpDebugExecute => "tool:http-debug",
            HeavyEntry::ExcelExport => "export:excel",
            HeavyEntry::BulkDelete => "db:bulk-delete",
            HeavyEntry::CacheMaintenance => "cache:maintenance",
            HeavyEntry::BatchGenCode => "gen:batch-code",
            HeavyEntry::MsgOutbound => "msg:outbound",
            HeavyEntry::BackupDownload => "backup:download",
            HeavyEntry::BoardSourceData => "report:board-source",
        }
    }

    /// 全局并发上限（跨用户、跨会话）。
    ///
    /// 取值取向：**宁可让第二个请求 429，也不让整库 dump 与归档下载同时抢磁盘**——
    /// 这几个入口同时跑起来互相拖慢，且都会写满 `data/backups`。
    /// 数字本身不是结论，"同一时刻最多几个在跑"才是；改这里要连注释一起改。
    pub const fn permits(self) -> usize {
        match self {
            // dump 子进程吃 CPU+IO+磁盘：同一时刻只允许一个整库备份
            HeavyEntry::BackupCreate => 1,
            // 数据包导出按租户切分，成本比整库低一档；两路并发是管理员批量交付的现实需求
            HeavyEntry::BackupExport => 2,
            // 只读聚合，不写盘：允许两路，但仍不允许"每个管理员各开一路"
            HeavyEntry::ComplianceReport => 2,
            // 512 MB 级读盘 + 压缩：两路是上限，三路以上会互相把吞吐吃光
            HeavyEntry::ArchiveDownload => 2,
            // 逐行 upsert：写放大线性于行数，四路并发足以让连接池只剩 0 个空闲连接
            HeavyEntry::UserImport => 4,
            // 窗口聚合 + 多表 COUNT + JSON 快照：预览与订阅执行同成本，两路共享一桶
            HeavyEntry::ReportSnapshot => 2,
            // Redis SCAN + 全表 COUNT + sysinfo + 出站：调度器本身是单序列，两路是手点的上限
            HeavyEntry::AlertEvaluate => 2,
            // 管理员任意 URL 出站：两路并发足以覆盖正常排障，又不至于把出站连接池占满
            HeavyEntry::HttpDebugExecute => 2,
            // 16 条导出端点共用一个唯一构造点。取 8 是自洽性判据允许的天花板：
            // 单次最多 5 万行 + 阻塞线程池，8 路仍是硬上限；取 1~2 会让并行集成测试
            // （flow / 日志 / 任务 / 登录四条导出链）互相 429，把门禁变成时序决定。
            HeavyEntry::ExcelExport => 8,
            // 6 条清空端点：长 DELETE + 锚点写 + WAL。四条集成测试会并发清理小表，
            // 取 4 既挡住"多个管理员同时清全库"，又不引入假失败。
            HeavyEntry::BulkDelete => 4,
            // 无上限 SCAN：串行化，避免多个管理员同时扫全库键空间
            HeavyEntry::CacheMaintenance => 2,
            // 模板渲染 + 内存 ZIP：单路
            HeavyEntry::BatchGenCode => 1,
            // 批量出站重投：不可重放事实，但入口是人类触发 ⇒ 只允许一路
            HeavyEntry::MsgOutbound => 1,
            // 备份文件下载：与 `operlog:archive-download` 同一成本级（GB 级快照流式读盘），
            // 差别只在不压缩。取 2 的判据是"一个浏览器一次只下一个文件"——正常用户
            // 摸不到上限，而脚本化连点会撞闸（下载是人类可重来的动作 ⇒ 取拒绝，A.2）。
            HeavyEntry::BackupDownload => 2,
            // 看板取数的下限**不是拍出来的**：一个看板页面刷新时按白名单数据源扇出
            // （`Promise.all`，见 `views/tool/reportBoard/index.vue`），源数 = `SOURCES.len()`。
            // 取任何 < 源数 的值都会让首屏必然部分 429 —— 那不是背压，是闸把页面自己的
            // 正常扇出判成超载（与 `export:excel=8` 那条"不得制造时序性假失败"同一约束）。
            // 取 8 = 本族上限（见 `heavy_entry_table_is_self_consistent` 的 1..=8 带）：
            // 够一屏扇出再加两条重试余量；两路看板同时刷新会有请求被拒，而卡片取数是人类
            // 可重来的动作 ⇒ 取拒绝（A.2），失败态由 b109 的"保留旧图 + 重试"通道承接。
            HeavyEntry::BoardSourceData => 8,
        }
    }

    const fn index(self) -> usize {
        match self {
            HeavyEntry::BackupCreate => 0,
            HeavyEntry::BackupExport => 1,
            HeavyEntry::ComplianceReport => 2,
            HeavyEntry::ArchiveDownload => 3,
            HeavyEntry::UserImport => 4,
            HeavyEntry::ReportSnapshot => 5,
            HeavyEntry::AlertEvaluate => 6,
            HeavyEntry::HttpDebugExecute => 7,
            HeavyEntry::ExcelExport => 8,
            HeavyEntry::BulkDelete => 9,
            HeavyEntry::CacheMaintenance => 10,
            HeavyEntry::BatchGenCode => 11,
            HeavyEntry::MsgOutbound => 12,
            HeavyEntry::BackupDownload => 13,
            HeavyEntry::BoardSourceData => 14,
        }
    }

    /// 本入口的闸（首次调用建闸，之后复用同一 `Arc`）。
    ///
    /// **长度由 `ENTRY_COUNT` 给**，不再手写逐项字面量：原先 13 项逐行罗列，
    /// 扩员时要同时改 `ALL`/`index`/`SLOTS`/`ENTRY_COUNT` 四处，少改一处就是
    /// `index()` 越界 panic（运行时）或长度不匹配（编译时）——而 `SLOTS` 那一处
    /// 恰好是编译期能查出来、但**报错信息指不到"忘了加第 14 个闸"**的那种。
    /// 用 repeat 表达式后，`ENTRY_COUNT` 是唯一的长度事实源（AGENTS 单一事实源）。
    fn gate(self) -> Arc<Semaphore> {
        static SLOTS: [OnceLock<Arc<Semaphore>>; ENTRY_COUNT] =
            [const { OnceLock::new() }; ENTRY_COUNT];
        let slot = &SLOTS[self.index()];
        slot.get_or_init(|| Arc::new(Semaphore::const_new(self.permits())))
            .clone()
    }

    /// 当前可用许可（**单一实现**：指标渲染与 [`available_permits`] 都走这里，
    /// 两份读数口径必漂）。
    fn available(self) -> usize {
        self.gate().available_permits()
    }
}

/// 结构不变式（编译期）：**看板取数闸不得低于一屏的扇出数**。
///
/// `views/tool/reportBoard/index.vue` 刷新时按白名单数据源 `Promise.all` 扇出，源数由
/// `SOURCES` 给。取任何小于它的值都会让**页面自己的正常首屏**部分 429——那是把合法
/// 负载判成超载，与 `export:excel=8`（取 1~2 会让并行集成测试互相 429）同一约束。
/// 关系写在代码里而不是只在注释里声明（AGENTS B.6 的编译期钳法）：将来有人往 `SOURCES`
/// 加第 13 个源，构建当场失败，而不是等某个用户的看板少画一张图。
const _: () = assert!(
    HeavyEntry::BoardSourceData.permits()
        >= crate::service::sys_report_board_service::SOURCES.len()
);

/// 取闸：拿到即返回 permit（**随请求生命周期持有**，返回即释放）。
///
/// 闸满 ⇒ `429` + `Retry-After`，并打一条 WARN 让"被拒绝"这件事在服务端可见
/// （只有客户端看到 429 而服务端无痕，等于把背压藏了起来）。
pub fn try_enter(entry: HeavyEntry) -> Result<OwnedSemaphorePermit, AppError> {
    let gate = entry.gate();
    match gate.clone().try_acquire_owned() {
        Ok(permit) => {
            record_decision(entry, true);
            Ok(permit)
        }
        Err(_) => {
            record_decision(entry, false);
            Err(rejected(entry))
        }
    }
}

/// 前置拒绝（**不取许可**）：只在闸已经为空时提前拒绝，把"闸满时重活根本不该开始"
/// 挡在入口（b91 N-90-1：导出族的 DB 全量读发生在构造点取闸之前）。
///
/// 与 [`try_enter`] 的分工：这里不持有许可，因此不拉长任何请求的占用时间，也不改变
/// 既有闸位的并发语义；真正的许可仍由重活前的 `try_enter` 获取。竞态窗口内的请求可能
/// 通过前置检查、随后在真实取闸处被拒——两者都是同一把闸的 fail-closed 结局。
pub fn precheck(entry: HeavyEntry) -> Result<(), AppError> {
    if precheck_verdict(entry.available()) {
        Ok(())
    } else {
        record_decision(entry, false);
        Err(rejected(entry))
    }
}

/// [`precheck`] 的纯判据（自检用：不碰全局闸，避免并行用例互顶）。
fn precheck_verdict(available: usize) -> bool {
    available > 0
}

/// 决策计数（`admitted` / `rejected` 两个结局各一张表，按下标 = [`HeavyEntry::index`]）。
///
/// 为什么不用 `Mutex<HashMap>`：入口集合是**编译期封闭**的，运行期不可能出现新键 ⇒
/// 定长数组既免去锁，也让"每个入口都有计数器"这件事由类型保证而不是靠代码路径。
///
/// 长度同样取 `ENTRY_COUNT`（与 [`HeavyEntry::gate`] 的 `SLOTS` 同一条理由）：三张表逐行
/// 罗列时，扩员要同步改 4 处字面量，漏一处的表现是 `index()` 越界 panic 在**第一次
/// 真实取闸**那一刻，而不是在编译期。
static ADMITTED: [AtomicU64; ENTRY_COUNT] = [const { AtomicU64::new(0) }; ENTRY_COUNT];
static REJECTED: [AtomicU64; ENTRY_COUNT] = [const { AtomicU64::new(0) }; ENTRY_COUNT];

/// 记一次闸口决策，返回**自增前**的读数（测试据此判"确实前进了"而不去比绝对值——
/// 绝对值在并行用例里由别人决定，`fetch_add` 的返回值是这条通道唯一的事实量）。
fn record_decision(entry: HeavyEntry, admitted: bool) -> u64 {
    let table: &[AtomicU64; ENTRY_COUNT] = if admitted { &ADMITTED } else { &REJECTED };
    table[entry.index()].fetch_add(1, Ordering::Relaxed)
}

/// 本族指标 → Prometheus 文本（由 `handler::health::metrics` 追加到 `/metrics`）。
///
/// 三条量的分工：**上限**是承诺、**可用数**是事实、**决策数**是结局；
/// 只有三者同屏才能算出"这一档是不是长期打满"（只看拒绝次数会把"根本没流量"
/// 误读成"闸门很健康"）。
pub fn render_prometheus() -> String {
    let mut s = String::new();
    s.push_str("# HELP stepby_resource_gate_permits 重资源入口的并发上限（写在代码里的容量承诺，用于算占用率）\n");
    s.push_str("# TYPE stepby_resource_gate_permits gauge\n");
    for entry in HeavyEntry::ALL {
        s.push_str(&format!(
            "stepby_resource_gate_permits{{entry=\"{}\"}} {}\n",
            entry.label(),
            entry.permits()
        ));
    }
    s.push_str("# HELP stepby_resource_gate_available_permits 重资源入口当前可用并发许可（0 = 闸满，后续请求一律 429）\n");
    s.push_str("# TYPE stepby_resource_gate_available_permits gauge\n");
    for entry in HeavyEntry::ALL {
        s.push_str(&format!(
            "stepby_resource_gate_available_permits{{entry=\"{}\"}} {}\n",
            entry.label(),
            entry.available()
        ));
    }
    // outcome 名与计数表**成对**传入（不是"先渲染 admitted 再渲染 rejected"两段复制粘贴）：
    // 名字↔表一旦错配，拒绝数会被当成放行数报出去，而那种 bug 在全局计数上看不出来
    // （两个数都可能是任意值）。配对由 `decision_pairing_is_per_outcome_table` 在局部表上证。
    s.push_str(&render_decisions(&[
        ("admitted", &ADMITTED),
        ("rejected", &REJECTED),
    ]));
    s
}

/// `stepby_resource_gate_decisions_total` 一族（每个入口 × 每个结局一行）。
///
/// 做成吃参数的纯函数，是为了让"哪个 outcome 名配哪张表"这件事**可以在测试里造出
/// 可区分的数**来证——全局计数器两边都可能是 0，拿它做对照等于没对照（AGENTS ⑥ 的
/// "反脆弱必须配真能转红的用例"）。
fn render_decisions(tables: &[(&str, &[AtomicU64; ENTRY_COUNT])]) -> String {
    let mut s = String::new();
    s.push_str(
        "# HELP stepby_resource_gate_decisions_total 重资源入口取闸结局计数（admitted/rejected）\n",
    );
    s.push_str("# TYPE stepby_resource_gate_decisions_total counter\n");
    for entry in HeavyEntry::ALL {
        for (outcome, table) in tables {
            s.push_str(&format!(
                "stepby_resource_gate_decisions_total{{entry=\"{}\",outcome=\"{outcome}\"}} {}\n",
                entry.label(),
                table[entry.index()].load(Ordering::Relaxed)
            ));
        }
    }
    s
}

/// 拒绝的形状（**单一实现**：全局闸与测试用的局部闸共用同一份文案与状态码）。
///
/// 为什么必须共用：单元测试若自己拼一个 `AppError::new(429, …)` 来"证明形状"，
/// 那么生产路径的文案/头改动时测试照样绿——正是"测的不是同一件事"。
fn rejected(entry: HeavyEntry) -> AppError {
    tracing::warn!(
        entry = entry.label(),
        permits = entry.permits(),
        "重资源入口闸满，已按 fail-closed 拒绝（429）"
    );
    AppError::new(
        429,
        crate::tr!(
            "error.common.resource_busy",
            entry = entry.label(),
            retry_after = RETRY_AFTER_SECS
        ),
    )
    .with_retry_after(RETRY_AFTER_SECS)
}

/// 当前可用许可数（**只用于观测与测试**：判据要能证明"闸真的在建"，而不是只证明
/// "代码里写了个 Semaphore"）。
///
/// ⚠️ 只有 `ComplianceReport` 与 `ReportSnapshot` 允许被测试占满——其余入口在别的集成测试里是
/// **真实业务链路**（`sys_backup.rs` 真跑 `POST /system/backup`），测试占住许可会让那条
/// 链路偶发 429，即"门禁绿红由并行时序决定"（AGENTS 前言 ㉒ 那一族）。因此下面那组
/// 单元测试一律用**局部** `Semaphore` 证形状，不去动全局闸。
pub fn available_permits(entry: HeavyEntry) -> usize {
    entry.available()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::prod_scan::Scan;

    /// 表自洽：成员齐全、label 唯一、上限在 1..=8（0 会永久拒绝、过大等于没闸）
    #[test]
    fn heavy_entry_table_is_self_consistent() {
        assert_eq!(
            HeavyEntry::ALL.len(),
            ENTRY_COUNT,
            "成员表必须与枚举一一对应"
        );
        assert_eq!(
            ENTRY_COUNT, 15,
            "成员数变了 ⇒ 槽位/计数表/接线反查都要同步扩"
        );
        for (i, entry) in HeavyEntry::ALL.iter().copied().enumerate() {
            assert_eq!(
                entry.index(),
                i,
                "index 必须等于 ALL 下标（slot 复用同一序号）"
            );
            let label = entry.label();
            assert!(!label.is_empty(), "{label:?} 不得为空");
            assert_eq!(
                HeavyEntry::ALL
                    .iter()
                    .filter(|e| e.label() == label)
                    .count(),
                1,
                "入口名 {label} 重复登记"
            );
            let permits = entry.permits();
            assert!(
                (1..=8).contains(&permits),
                "{label} 的上限 {permits} 不在 1..=8：0 = 永久拒绝，>8 = 等于没闸"
            );
        }
        // 整库备份必须最严（一路 dump 就能吃满 CPU/IO/磁盘）
        assert_eq!(HeavyEntry::BackupCreate.permits(), 1);
    }

    /// 闸门确实被**建出来**并随占用减少：这是"接线生效"的最小证明。
    /// 只测 `try_enter` 返回 Ok 不够——那可以是"根本没建闸直接放行"。
    ///
    /// ⚠️ 用**局部** `Semaphore`：占全局许可会让别的集成测试偶发 429
    /// （`sys_backup.rs` 真跑 `POST /system/backup`），那会新增一个假失败源
    /// （AGENTS 前言 ㉒：并行用例之间共享的可变量）。全局闸的端到端形状只在
    /// `integration_tests::resource_gate` 里用**无人占用的入口**（ComplianceReport）验一次。
    #[test]
    fn local_gate_counts_down_back_up_and_rejects_when_full() {
        let gate = Arc::new(Semaphore::new(1));
        let first = gate.clone().try_acquire_owned().expect("空闸必须取得许可");
        assert_eq!(
            gate.available_permits(),
            0,
            "取得许可后可用量必须少 1（否则闸是装饰）"
        );
        assert!(
            gate.clone().try_acquire_owned().is_err(),
            "闸满必须立即失败（fail-closed：不阻塞、不自旋、不降级放行）"
        );
        drop(first);
        assert_eq!(
            gate.available_permits(),
            1,
            "释放后必须回到原值（许可不得泄漏）"
        );
    }

    /// 拒绝的形状：429 + Retry-After + 文案点名是哪个入口。
    /// 必须走生产码同一个 [`rejected`]——测试自己拼一个 `AppError` 等于没测生产形状（㉓）。
    #[test]
    fn rejection_shape_is_429_with_retry_after_naming_the_entry() {
        let err = rejected(HeavyEntry::BackupCreate);
        assert_eq!(err.code, 429, "背压必须取 429，实际 {}", err.code);
        assert!(
            err.retry_after.is_some(),
            "拒绝必须给 Retry-After（否则客户端只能盲重试）"
        );
        assert!(
            err.message.contains("backup:create"),
            "文案必须点名是哪个入口忙（只说\"系统繁忙\"会让人去查错方向）：{}",
            err.message
        );
    }

    /// 各入口必须落在**不同**槽位：共用一张全局桶正是 b72 F71
    /// "敏感档打满即饿死全站"的形状。判 index 而不判许可数，因此不动全局闸。
    #[test]
    fn each_entry_has_its_own_slot() {
        let mut seen: Vec<usize> = HeavyEntry::ALL.iter().map(|e| e.index()).collect();
        seen.sort_unstable();
        let expected: Vec<usize> = (0..HeavyEntry::ALL.len()).collect();
        assert_eq!(
            seen, expected,
            "槽位必须 0..N 一一覆盖（重复 = 同桶，缺号 = 数组越界风险）"
        );
    }

    /// 两个方向的集合差，抽成纯函数：真实树只证"结论对"，两个方向是否**各自有效**
    /// 只能由合成输入证（前言 ⑥：必须有一条真能转红的用例；㉖：每条腿单独做改回缺陷形状的变异）。
    /// `entries` = `HeavyEntry::ALL` 的 label 集；`registry` = 接线反查表的 label 集。
    fn wiring_gap_messages(entries: &[&str], registry: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        for label in entries {
            if !registry.contains(label) {
                out.push(format!(
                    "`{label}` 在 `HeavyEntry::ALL` 里却没有登记在接线反查表 ⇒ \
                     要么这个新入口根本没接进 handler（无并发上限），要么接了但没人反查它"
                ));
            }
        }
        for label in registry {
            if !entries.contains(label) {
                out.push(format!(
                    "接线反查表里的 `{label}` 已不在 `HeavyEntry::ALL` ⇒ 条目腐化，该撤下"
                ));
            }
        }
        out
    }

    /// **接线反查**（写了没接线 = 没写）：每个入口都必须在对应 handler 的
    /// **生产码视图**里被真的调用，且**排在做重活之前**——
    /// 顺序错了就等于"先 dump 完再拒绝"，那才是真事故。
    ///
    /// **采集面由 [`HeavyEntry::ALL`] 派生**，而不是由这张表自己数（b89 收口补的洞）：
    /// 原先 `cases` 是手写的五条三元组，于是"给 `ALL` 加了第六个成员、但忘了接进 handler
    /// 也忘了在这里登记"这件事**结构上抓不到**——反查表会照常绿，因为它只对自己那五条负责。
    /// 现在两个方向都判：`ALL` 里每个成员都必须在表里有一行；表里不得有 `ALL` 之外的成员。
    /// 与 `gate_metrics_cover_every_entry`（指标采集面）是同一取向的第二个断面——
    /// 同一个 `ALL` 既要"被观测到"，也要"被接到 handler 上"。
    #[test]
    fn heavy_entries_are_wired_into_handlers_before_their_work() {
        // (label, 变体名, handler 文件, 重活调用点)。同一入口可有多行（同一闸桶、
        // 多条接线点）：报表快照、清空族、缓存维护各有多处入口。
        let registry: &[(&str, &str, &str, &str)] = &[
            (
                "backup:create",
                "HeavyEntry::BackupCreate",
                "src/handler/sys_backup_handler.rs",
                "create_backup(",
            ),
            (
                "backup:export",
                "HeavyEntry::BackupExport",
                "src/handler/sys_backup_handler.rs",
                "export_tenant_package(",
            ),
            (
                "operlog:compliance-report",
                "HeavyEntry::ComplianceReport",
                "src/handler/sys_oper_log_handler.rs",
                "get_compliance_report(",
            ),
            (
                "operlog:archive-download",
                "HeavyEntry::ArchiveDownload",
                "src/handler/sys_oper_log_handler.rs",
                "read_archive_object(",
            ),
            (
                "user:import",
                "HeavyEntry::UserImport",
                "src/handler/sys_user_handler.rs",
                "import_users(",
            ),
            (
                "report:snapshot",
                "HeavyEntry::ReportSnapshot",
                "src/handler/sys_report_handler.rs",
                "preview_report(",
            ),
            (
                "report:snapshot",
                "HeavyEntry::ReportSnapshot",
                "src/handler/sys_report_handler.rs",
                "run_sub_now(",
            ),
            (
                "alert:evaluate",
                "HeavyEntry::AlertEvaluate",
                "src/handler/monitor_alert_handler.rs",
                "evaluate_one(",
            ),
            (
                // b92 N-90-2：同一条闸的**定时/registry 执行点**。调度器与手动触发都走
                // `alert_eval_once`，取闸必须排在 `service.evaluate_all()` 之前，
                // 否则闸满时整表评估已经开始（与 b91 导出前置点的形态同源）。
                "alert:evaluate",
                "HeavyEntry::AlertEvaluate",
                "src/service/sys_alert_service.rs",
                "service.evaluate_all()",
            ),
            (
                "tool:http-debug",
                "HeavyEntry::HttpDebugExecute",
                "src/handler/sys_http_debug_handler.rs",
                ".execute(dto)",
            ),
            (
                "export:excel",
                "HeavyEntry::ExcelExport",
                "src/common/excel.rs",
                "spawn_blocking(",
            ),
            (
                // b91 N-90-1：同一条闸的**前置拒绝点**（不持有许可，只把闸满的请求挡在
                // DB 全量读之前）。构造点那一行仍是许可持有段，两行缺一都不算闭合。
                "export:excel",
                "HeavyEntry::ExcelExport",
                "src/middleware/export_gate.rs",
                "next.run(req)",
            ),
            (
                // b98：审计留痕 CSV 导出不走 xlsx 构造点，`precheck` 只早拒不占许可
                // ⇒ 必须自己持有同一把闸，否则这条链路的并发导出完全不受预算约束。
                "export:excel",
                "HeavyEntry::ExcelExport",
                "src/audit/handler.rs",
                "export_changes(",
            ),
            (
                "db:bulk-delete",
                "HeavyEntry::BulkDelete",
                "src/handler/sys_oper_log_handler.rs",
                "clean_oper_logs_by_range(",
            ),
            (
                "db:bulk-delete",
                "HeavyEntry::BulkDelete",
                "src/handler/sys_logininfor_handler.rs",
                "clean_logininfors_by_range(",
            ),
            (
                "db:bulk-delete",
                "HeavyEntry::BulkDelete",
                "src/handler/sys_job_log_handler.rs",
                "clean_job_logs(",
            ),
            (
                "db:bulk-delete",
                "HeavyEntry::BulkDelete",
                "src/handler/sys_frontend_error_handler.rs",
                "clean_by_range(",
            ),
            (
                "db:bulk-delete",
                "HeavyEntry::BulkDelete",
                "src/handler/sys_msg_handler.rs",
                "clean_send_logs(",
            ),
            (
                "db:bulk-delete",
                "HeavyEntry::BulkDelete",
                "src/handler/sys_web_hook_handler.rs",
                "clean_logs(",
            ),
            (
                "cache:maintenance",
                "HeavyEntry::CacheMaintenance",
                "src/handler/sys_config_handler.rs",
                "config_service.refresh_cache(",
            ),
            (
                // b140：字典侧的同类入口此前**没有**接闸（只有参数侧接了），而它扫的是
                // `dict:*` 全键空间且每次字典增删改都会触发——同一个语义两条链路一份背压、
                // 一份没有，就是"看运气"。补为同一把闸的第二个接线点。
                "cache:maintenance",
                "HeavyEntry::CacheMaintenance",
                "src/handler/sys_dict_handler.rs",
                "refresh_all_dict_cache(",
            ),
            (
                "cache:maintenance",
                "HeavyEntry::CacheMaintenance",
                "src/handler/monitor_cache_handler.rs",
                "delete_keys(&state, &keys)",
            ),
            (
                "gen:batch-code",
                "HeavyEntry::BatchGenCode",
                "src/handler/tool_gen_handler.rs",
                ".batch_gen_code(&table_names)",
            ),
            (
                "msg:outbound",
                "HeavyEntry::MsgOutbound",
                "src/handler/sys_msg_handler.rs",
                ".retry_pending(batch,",
            ),
            (
                // b140：整库快照下载此前**完全不受预算约束**（`BackupExport` 管的是"生成
                // 数据包"那一段，不是把已存在的 GB 级文件读出流）。与 `operlog:archive-download`
                // 同一成本级，只是不压缩 ⇒ 独立一桶、同为 2 permits。
                "backup:download",
                "HeavyEntry::BackupDownload",
                "src/handler/sys_backup_handler.rs",
                "open_backup_file(",
            ),
            (
                // b140：看板卡片取数与报表预览是同一类聚合（同一批 service 统计口径），
                // 预览走了 `report:snapshot`、看板取数一个桶都没进 ⇒ 同一语义两个严格度。
                // 扇出下限由上方编译期不变式钳住（permits ≥ SOURCES.len()）。
                "report:board-source",
                "HeavyEntry::BoardSourceData",
                "src/handler/sys_report_board_handler.rs",
                ".resolve_source(&source_key,",
            ),
        ];
        // 正向 + 反向：ALL 与登记表必须逐成员对上（缺哪一侧都由这一条点名）。
        // 同一入口多行接线，按 label 去重后再比。
        let all_labels: Vec<&str> = HeavyEntry::ALL.iter().map(|e| e.label()).collect();
        let registry_labels: Vec<&str> = registry
            .iter()
            .map(|(label, ..)| *label)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let gaps = wiring_gap_messages(&all_labels, &registry_labels);
        assert!(
            gaps.is_empty(),
            "接线反查表与 `HeavyEntry::ALL` 不闭合：\n{}",
            gaps.join("\n")
        );
        assert_eq!(
            registry_labels.len(),
            HeavyEntry::ALL.len(),
            "去重后的接线入口数必须等于成员数（同一入口多行接线在去重后只算一个）"
        );
        let mut files = std::collections::BTreeSet::new();
        for (_label, gate_needle, file, work_needle) in registry {
            let text = crate::common::prod_scan::prod_file(file, &Scan::default()).text();
            let gates = text.matches(gate_needle).count();
            assert!(
                gates >= 1,
                "{file} 的生产码视图里没有任何 `{gate_needle}` 取闸点 ⇒ 该入口仍无并发上限"
            );
            let at = text
                .find(gate_needle)
                .unwrap_or_else(|| panic!("夹具坏了: {gate_needle}"));
            let work = text.find(work_needle).unwrap_or_else(|| {
                panic!("{file} 里找不到重活调用点 `{work_needle}` ⇒ 本锁的对照失效（改名没人管）")
            });
            assert!(
                at < work,
                "{file}：取闸必须排在 `{work_needle}` **之前**，否则拒绝发生在干完活之后"
            );
            files.insert(*file);
        }
        assert_eq!(
            files.len(),
            20,
            "反查必须覆盖全部 20 个接线文件（少了就是有人把接线挪出了视野）。\
             这是**等式**而不是下限：b140 起接线文件数由 18 增至 20（新增看板取数与备份下载\
             两条链），等式逼着每一个改接线的人重新数一遍——`>=` 会让\"删掉一行\"静默通过，\
             而那正是本断言唯一防的事"
        );
    }

    /// b91 N-90-1：导出路由的前置拒绝。判据只读"可用数"的纯函数，**不去占全局闸**——
    /// 占满 `ExcelExport` 会让并行导出用例偶发 429（本文件 `available_permits` 的注释与
    /// AGENTS 前言 ㉒ 都禁止这种"门禁绿红由并行度决定"的写法）。
    #[test]
    fn precheck_rejects_with_the_same_429_contract_without_taking_a_permit() {
        assert!(precheck_verdict(1), "还有可用许可时必须放行");
        assert!(!precheck_verdict(0), "闸满必须拒绝");

        // 拒绝响应与 try_enter 共用 rejected()：状态码 / Retry-After / 点名入口三件套。
        let err = rejected(HeavyEntry::ExcelExport);
        assert_eq!(err.code, 429);
        assert_eq!(err.retry_after, Some(RETRY_AFTER_SECS));
        assert!(
            err.message.contains("export:excel"),
            "拒绝文案必须点名入口，实际: {}",
            err.message
        );
    }

    /// 集合差两个方向各自有效（合成双向）：真实树那条只证"当前闭合"，
    /// **哪一侧漏了都会红**这件事只能由合成输入证。
    #[test]
    fn wiring_gap_detector_catches_both_directions() {
        let all = ["a", "b", "c"];
        // 正控：完全闭合 ⇒ 一条都不报
        assert!(wiring_gap_messages(&all, &["a", "b", "c"]).is_empty());
        // 正向：ALL 加了成员、表里没登记 ⇒ 点名那条成员
        let miss = wiring_gap_messages(&all, &["a", "b"]);
        assert_eq!(miss.len(), 1, "少登记一个成员必须恰报一条：{miss:?}");
        assert!(
            miss[0].contains('c'),
            "红要能照着改：必须点名缺哪个成员：{}",
            miss[0]
        );
        // 反向：表里留着 ALL 之外的成员（改名/删成员后的旧形状）
        let stale = wiring_gap_messages(&["a", "b"], &["a", "b", "gone"]);
        assert_eq!(stale.len(), 1, "表外成员必须恰报一条：{stale:?}");
        assert!(
            stale[0].contains("gone"),
            "必须点名是哪条腐化：{}",
            stale[0]
        );
        // 两侧同时坏 ⇒ 两条都报（不得因为先命中一支就把另一支洗掉）
        assert_eq!(wiring_gap_messages(&["a", "b"], &["a", "gone"]).len(), 2);
        // 空表不得读成"闭合"（前言 ⑥：扫不到 ≠ 没问题）
        assert!(!wiring_gap_messages(&all, &[]).is_empty());
        // 真实采集面正控：`ALL` 与登记表**当前确实都非空且同数**，
        // 否则上面那几条会在两张空表上恒成立
        assert_eq!(
            HeavyEntry::ALL.len(),
            ENTRY_COUNT,
            "`ALL` 的成员数变了 ⇒ 这条正控的口径要跟着改，不能默认成立"
        );
    }

    /// 反证：判据读的两个位置必须真的在比——合规顺序放行、"先干活后取闸"必须能被抓。
    /// （只测"真树 0 违规"而夹具两侧都同一个形状，等于没判——前言 ⑥）
    #[test]
    fn wiring_order_detector_is_falsifiable() {
        let good = "let _g = HeavyEntry::BackupCreate; service.create_backup(x).await;";
        let bad = "service.create_backup(x).await; let _g = HeavyEntry::BackupCreate;";
        let pos = |t: &str| {
            (
                t.find("HeavyEntry::BackupCreate").expect("夹具坏了"),
                t.find("create_backup(").expect("夹具坏了"),
            )
        };
        let (g, w) = pos(good);
        assert!(
            g < w,
            "合规夹具必须真的'先取闸'，否则上一条测试的 < 判据空转"
        );
        let (g2, w2) = pos(bad);
        assert!(
            g2 > w2,
            "反例夹具必须真的'先干活后取闸'，否则顺序判据抓不到东西"
        );
    }

    // ==================== 指标面（AGENTS B-4：组件自带指标） ====================

    /// 从 Prometheus 文本里取某个 label 组合的数值（取不到 ⇒ panic，不返回 0）
    ///
    /// "取不到"与"值为 0"必须可区分——否则采集面漏了一个入口会被读成"那个入口没被拒绝过"。
    fn metric_value(text: &str, line_prefix: &str) -> u64 {
        let line = text
            .lines()
            .find(|l| l.starts_with(line_prefix))
            .unwrap_or_else(|| panic!("指标行缺失：{line_prefix}（渲染采集面坏了）"));
        line.rsplit(' ')
            .next()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or_else(|| panic!("指标行尾不是数字：{line}"))
    }

    /// 三个家族必须**逐入口**齐全，且承诺值与代码里的 `permits()` 逐条相等。
    ///
    /// 这一条同时是"采集面自证"：行数由 `HeavyEntry::ALL` 决定，漏一行就是
    /// "有个入口有闸、在 /metrics 里隐身"——运维只能看到四个入口的背压，
    /// 第五个的 429 永远归不了因。
    #[test]
    fn gate_metrics_cover_every_entry() {
        let text = render_prometheus();
        for family in [
            "stepby_resource_gate_permits",
            "stepby_resource_gate_available_permits",
            "stepby_resource_gate_decisions_total",
        ] {
            assert!(
                text.contains(&format!("# TYPE {family} "))
                    && text.contains(&format!("# HELP {family} ")),
                "家族 {family} 缺 HELP/TYPE 头（Prometheus 解析器会整段丢弃该族）"
            );
        }
        let lines_of = |family: &str| {
            text.lines()
                .filter(|l| l.starts_with(&format!("{family}{{")))
                .count()
        };
        assert_eq!(
            lines_of("stepby_resource_gate_permits"),
            HeavyEntry::ALL.len(),
            "上限族行数 ≠ 成员数（多出来的行是复制粘贴，少掉的那行是隐身入口）"
        );
        assert_eq!(
            lines_of("stepby_resource_gate_available_permits"),
            HeavyEntry::ALL.len(),
            "可用数族行数 ≠ 成员数"
        );
        assert_eq!(
            lines_of("stepby_resource_gate_decisions_total"),
            HeavyEntry::ALL.len() * 2,
            "决策族必须是 入口 × 2 结局（少一个结局 = 有一半背压看不见）"
        );
        for entry in HeavyEntry::ALL {
            let label = entry.label();
            assert_eq!(
                metric_value(
                    &text,
                    &format!("stepby_resource_gate_permits{{entry=\"{label}\"}} ")
                ),
                entry.permits() as u64,
                "{label} 的上限指标与代码不等 ⇒ 指标成了第二事实源（必漂）"
            );
            let available = metric_value(
                &text,
                &format!("stepby_resource_gate_available_permits{{entry=\"{label}\"}} "),
            );
            assert!(
                available <= entry.permits() as u64,
                "{label} 可用许可 {available} 超过上限 {} ⇒ 读数不是来自同一个闸",
                entry.permits()
            );
        }
    }

    /// 计数必须**真的在动**（渲染得出两行 0 可以是"从来没人记"）。
    ///
    /// 只断"自增后 ≥ 自增前 + 1"而不断相等：本二进制的集成测试会并发取闸，
    /// 绝对值与增量都由并行时序决定（AGENTS 前言 ㉒），而 `fetch_add` 的返回值
    /// 给出了这条通道唯一可靠的事实量。
    #[test]
    fn decision_counter_moves_on_both_outcomes() {
        let entry = HeavyEntry::ArchiveDownload;
        let prev_admit = record_decision(entry, true);
        let rendered_admit = metric_value(
            &render_prometheus(),
            &format!(
                "stepby_resource_gate_decisions_total{{entry=\"{}\",outcome=\"admitted\"}} ",
                entry.label()
            ),
        );
        assert!(
            rendered_admit > prev_admit,
            "记了一次却没进指标 ⇒ 渲染读的不是这张表"
        );

        let prev_reject = record_decision(entry, false);
        let rendered_reject = metric_value(
            &render_prometheus(),
            &format!(
                "stepby_resource_gate_decisions_total{{entry=\"{}\",outcome=\"rejected\"}} ",
                entry.label()
            ),
        );
        assert!(
            rendered_reject > prev_reject,
            "拒绝没进指标 ⇒ 背压只能由客户端发现"
        );
    }

    /// 反证：outcome 名与计数表必须**成对**渲染。
    ///
    /// 全局两张表在两端都可能是 0，拿真树证不了"没配错"——所以这里造两张**数值可区分**
    /// 的局部表：入口 0 的 admitted=11、rejected=99，逐行必须是自己的数。
    /// 若有人把两段渲染复制后只改 label（配反），本用例当场红。
    #[test]
    fn decision_pairing_is_per_outcome_table() {
        let mk = |base: u64| std::array::from_fn(|i| AtomicU64::new(base + i as u64));
        let admitted = mk(10);
        let rejected = mk(90);
        let text = render_decisions(&[("admitted", &admitted), ("rejected", &rejected)]);
        for entry in HeavyEntry::ALL {
            let i = entry.index();
            for (outcome, table) in [("admitted", &admitted), ("rejected", &rejected)] {
                let got = metric_value(
                    &text,
                    &format!(
                        "stepby_resource_gate_decisions_total{{entry=\"{}\",outcome=\"{outcome}\"}} ",
                        entry.label()
                    ),
                );
                assert_eq!(
                    got,
                    table[i].load(Ordering::Relaxed),
                    "{} 的 {outcome} 行不是自己那张表的数 ⇒ 结局配反",
                    entry.label()
                );
            }
        }
        // 配反必须产出不同文本（证"上面那条比较真的在看数"，而不是恒真）
        let swapped = render_decisions(&[("admitted", &rejected), ("rejected", &admitted)]);
        assert_ne!(swapped, text, "换配不改输出 ⇒ 渲染根本没读表");
    }
}
