//! AI 推理入口的并发闸（AGENTS.md 工程硬基线 A.2「资源硬上限 + 背压」）。
//!
//! 为什么必须有：`POST /ai/chat` 与 `POST /ai/replay` 每次请求都要打一次 LLM
//! （本地 Ollama / 远端 OpenAI 兼容服务），属**重资源入口**——单请求成本从数百毫秒到
//! 数十秒。此前与 `report_dataset` 试跑、分片上传 complete 不同，**没有任何上限**：
//! 一个脚本并发 200 条提问，就能把本机推理队列打满、把远端配额瞬间烧光，
//! 并拖垮同进程里所有普通接口（LLM 慢 → 连接与 worker 长期被占）。
//!
//! 取舍口径（与既有闸门刻意不同）：
//! - **拒绝而非排队**：推理请求是"可重来的人类请求"，与 WebHook 出站事实（不可重放 ⇒ 排队）
//!   相反。让用户等 60s 不如立刻 429，前端可提示"稍后再问"。
//!   `Retry-After` 由**已完成推理的占用均值**给出（`InferenceGate::retry_after_secs`）；
//!   冷启动还没有任何样本时**不发该头**——闸没有窗口语义，猜一个数等于把猜测当承诺。
//!   （b83 前此处只写着"429 + Retry-After"，而 `AppError` 根本没有 header 通道，
//!   这条承诺从未成立。）
//! - **进程级、启动只读**：上限来自 `[ai].max_concurrency`（启动时读取，改后需重启，
//!   与 AGENTS C.7 的配置归类一致）。首个请求完成初始化（`OnceLock`），此后不再接受
//!   不同值——避免"两个入口各自看到不同上限"的口径分裂。
//! - **许可必然归还**：LLM 客户端自带 `timeout_secs`（`ai/provider.rs` reqwest `.timeout`），
//!   因此不存在"持许可卡死"的泄漏路径；闸内的 panic 也由 handler 上层 `Result` 流转，
//!   permit 随栈展开自动释放。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::Semaphore;

/// 缺省上限（配置缺失或非法时回落，永不无界）
pub const DEFAULT_MAX_CONCURRENCY: usize = 4;

/// 推理并发闸。`try_admit` 语义 = **满即拒**（不排队）。
pub struct InferenceGate {
    sem: Arc<Semaphore>,
    limit: usize,
    /// 已完成推理的占用时长均值（毫秒，EWMA α=1/4）。闸满时的 `Retry-After` 由它给出。
    ///
    /// 为什么用观测值而不是常量：闸没有窗口语义，"什么时候有位"取决于**正在跑的那几次要多久**。
    /// 写死一个数（哪怕 1s）就是把猜的数当承诺；均值会随模型/机器自调，冷启动无样本时干脆不发头。
    hold_ms_ewma: Arc<AtomicU64>,
}

/// 一次准入的凭据：持有 `OwnedSemaphorePermit`，drop 即归还额度并记一次占用时长。
///
/// 用 RAII 而非"调用方手动记录"：`/ai/chat` 与 `/ai/replay` 的 `Result` 链上有多条 `?` 出口，
/// 手写记录必然漏（b72 `OutboundGuard` 同一条教训）。
pub struct InferencePermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    started: std::time::Instant,
    hold_ms_ewma: Arc<AtomicU64>,
}

impl Drop for InferencePermit {
    fn drop(&mut self) {
        let ms = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        // EWMA：new = (3*old + sample) / 4。首样本时 old=0 ⇒ 结果 = sample/4，
        // 故用 compare_exchange 把"无样本"直接播种成首个观测值。
        let prev = self.hold_ms_ewma.load(Ordering::Acquire);
        if prev == 0 {
            self.hold_ms_ewma.store(ms.max(1), Ordering::Release);
        } else {
            // `.max(1)` 是必须的：亚毫秒推理会把均值一路衰减到 0，而 0 在本类型里的含义是
            // "还没有任何观测"⇒ 退避提示会凭空消失（自己造的 fail-open）。
            self.hold_ms_ewma.store(
                ((prev.saturating_mul(3).saturating_add(ms)) / 4).max(1),
                Ordering::Release,
            );
        }
    }
}

impl InferenceGate {
    /// 以给定上限建闸。0 或超界一律收敛到 `[1, 256]`（0 会等价"永久拒绝"，属配置错误而非意图）。
    pub fn new(limit: usize) -> Self {
        let clamped = limit.clamp(1, 256);
        Self {
            sem: Arc::new(Semaphore::new(clamped)),
            limit: clamped,
            hold_ms_ewma: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 实际生效上限（`new` 已做 clamp）
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// 尝试占用一个许可；闸满返回 `None`（调用方转 429）。
    ///
    /// 返回 `InferencePermit`（内含 `OwnedSemaphorePermit`）：调用方可以把它从"取许可"的
    /// 函数里带出来，跨过整段推理生命周期，drop 即归还额度并留下一次占用时长观测。
    pub fn try_admit(self: &Arc<Self>) -> Option<InferencePermit> {
        let permit = self.sem.clone().try_acquire_owned().ok()?;
        Some(InferencePermit {
            _permit: permit,
            started: std::time::Instant::now(),
            hold_ms_ewma: self.hold_ms_ewma.clone(),
        })
    }

    /// 闸满时给客户端的退避提示秒数。**没有任何完成样本时返回 `None`**（宁可不发头，
    /// 也不把猜出来的数当承诺）；有样本时取 EWMA 上取整、下限 1 秒。
    pub fn retry_after_secs(&self) -> Option<u64> {
        let ewma_ms = self.hold_ms_ewma.load(Ordering::Acquire);
        if ewma_ms == 0 {
            return None;
        }
        Some(ewma_ms.div_ceil(1000).max(1))
    }
}

/// 进程级单例：首次调用用当次传入的配置上限建闸。
pub fn inference_gate(configured: usize) -> Arc<InferenceGate> {
    static GATE: OnceLock<Arc<InferenceGate>> = OnceLock::new();
    GATE.get_or_init(|| Arc::new(InferenceGate::new(configured.max(1))))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 闸必须真的拦得住：并发度 = 上限时逐个可入，第 N+1 个被拒。
    #[test]
    fn gate_admits_up_to_limit_then_rejects() {
        // 直接 `Arc::new(InferenceGate::new(3))` 建局部闸验证"占满即拒"，不依赖进程单例（并行测试会污染单例）
        let gate = Arc::new(InferenceGate::new(3));
        assert_eq!(gate.limit(), 3);
        let a = gate.try_admit().expect("第 1 个许可应在额度内");
        let b = gate.try_admit().expect("第 2 个许可应在额度内");
        let c = gate.try_admit().expect("第 3 个许可应在额度内");
        assert!(
            gate.try_admit().is_none(),
            "第 4 个并发推理请求必须被拒（否则等于没有闸）"
        );
        drop(a);
        // 释放一个后应重新可入（许可不是计数器，必须能回收）
        assert!(gate.try_admit().is_some(), "许可释放后必须重新放行");
        drop(b);
        drop(c);
    }

    /// clamp 口径：0 不得变成"永久拒绝"，非法大值不得吃掉内存。
    #[test]
    fn zero_and_oversized_limits_are_clamped() {
        assert_eq!(InferenceGate::new(0).limit(), 1);
        assert_eq!(InferenceGate::new(usize::MAX).limit(), 256);
        assert_eq!(InferenceGate::new(7).limit(), 7);
    }

    /// `Retry-After` 的两个分支：**没有观测时不得发头**，有观测时给实测均值（上取整、下限 1s）。
    #[test]
    fn retry_after_absent_until_first_observation() {
        let gate = Arc::new(InferenceGate::new(2));
        assert_eq!(
            gate.retry_after_secs(),
            None,
            "冷启动没有样本时必须不发 Retry-After（猜的数不能当承诺）"
        );
        let p = gate.try_admit().expect("额度内应放行");
        std::thread::sleep(std::time::Duration::from_millis(20));
        drop(p);
        assert_eq!(
            gate.retry_after_secs(),
            Some(1),
            "20ms 占用应报 1 秒（div_ceil + 下限 1）"
        );
        // 包一层不改变闸语义：占满仍拒、释放仍放行
        let a = gate.try_admit().expect("第 1 个");
        let b = gate.try_admit().expect("第 2 个");
        assert!(gate.try_admit().is_none(), "第 3 个必须被拒");
        drop(a);
        assert!(gate.try_admit().is_some(), "释放后必须重新放行");
        drop(b);
    }

    /// 亚毫秒推理不得把均值衰减成 0——0 的含义是"还没有观测"，衰减到 0 会让退避提示凭空消失。
    #[test]
    fn sub_millisecond_holds_never_erase_the_observation() {
        let gate = Arc::new(InferenceGate::new(1));
        for _ in 0..12 {
            let p = gate.try_admit().expect("单次循环内应先占再放");
            drop(p); // 立即 drop ⇒ 样本≈0ms
        }
        assert_eq!(
            gate.retry_after_secs(),
            Some(1),
            "连续亚毫秒占用后仍必须有提示值（下限 1 秒）"
        );
    }

    /// 单例只认首个上限（配置为启动只读，运行期不得被不同调用点改写）
    #[test]
    fn process_gate_initializes_once() {
        let first = inference_gate(9);
        let again = inference_gate(99);
        assert_eq!(
            first.limit(),
            again.limit(),
            "并发闸上限必须固定（启动只读），不能随调用点漂移"
        );
    }

    /// 形状锁：两条推理入口（`/ai/chat`、`/ai/replay`）**都必须**过闸。
    ///
    /// 只给一条加入口 = 另一条成为绕过通道（这与 b71 "同一字段两条写入口径不一致"同源）。
    /// 同时锁 i18n 键在 zh/en 两处都在，防止 429 落到"裸英文 key 字符串"上。
    #[test]
    fn both_inference_entries_admit_through_gate() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let handler = std::fs::read_to_string(manifest.join("src/ai/handler.rs")).unwrap();
        let prod = match handler.find("#[cfg(test)]") {
            Some(i) => &handler[..i],
            None => handler.as_str(),
        };
        let admits = prod.matches("admit_inference(&state)?").count();
        assert_eq!(
            admits, 2,
            "chat 与 replay 两条入口应各调用一次 admit_inference，实际 {admits} 次"
        );
        for locale in ["locales/zh-CN.yml", "locales/en-US.yml"] {
            let text = std::fs::read_to_string(manifest.join(locale)).unwrap();
            assert!(
                text.contains("\n    busy:") || text.contains("\n    busy :"),
                "{locale} 缺少 error.ai.busy 文案（429 会显示成裸 key）"
            );
        }
    }
}
