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
//!   相反。让用户等 60s 不如立刻 429 + `Retry-After`，前端可提示"稍后再问"。
//! - **进程级、启动只读**：上限来自 `[ai].max_concurrency`（启动时读取，改后需重启，
//!   与 AGENTS C.7 的配置归类一致）。首个请求完成初始化（`OnceLock`），此后不再接受
//!   不同值——避免"两个入口各自看到不同上限"的口径分裂。
//! - **许可必然归还**：LLM 客户端自带 `timeout_secs`（`ai/provider.rs` reqwest `.timeout`），
//!   因此不存在"持许可卡死"的泄漏路径；闸内的 panic 也由 handler 上层 `Result` 流转，
//!   permit 随栈展开自动释放。

use std::sync::{Arc, OnceLock};

use tokio::sync::Semaphore;

/// 缺省上限（配置缺失或非法时回落，永不无界）
pub const DEFAULT_MAX_CONCURRENCY: usize = 4;

/// 推理并发闸。`try_admit` 语义 = **满即拒**（不排队）。
pub struct InferenceGate {
    sem: Arc<Semaphore>,
    limit: usize,
}

impl InferenceGate {
    /// 以给定上限建闸。0 或超界一律收敛到 `[1, 256]`（0 会等价"永久拒绝"，属配置错误而非意图）。
    pub fn new(limit: usize) -> Self {
        let clamped = limit.clamp(1, 256);
        Self {
            sem: Arc::new(Semaphore::new(clamped)),
            limit: clamped,
        }
    }

    /// 实际生效上限（`new` 已做 clamp）
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// 尝试占用一个许可；闸满返回 `None`（调用方转 429）。
    ///
    /// 返回 `OwnedSemaphorePermit`（持 `Arc<Semaphore>` 而非借用）：调用方可以把它
    /// 从"取许可"的函数里带出来，跨过整段推理生命周期，permit drop 即归还额度。
    pub fn try_admit(self: &Arc<Self>) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.sem.clone().try_acquire_owned().ok()
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
