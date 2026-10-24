// stepby-axum/src/common/perm_cache.rs
//! `perm:user:*` 权限缓存失效的**唯一实现**（b89 项 13）。
//!
//! ## 立的案
//!
//! 同一段"SCAN `perm:user:*` → 批量 DEL"在仓里有**四份**实现：
//! `sys_menu_service::invalidate_all_perm_cache`、`sys_role_service::invalidate_all_perm_cache`、
//! `sys_tenant_service::invalidate_all_perm_cache` 与 `initialize::tenant` 启动收敛里的那一段。
//! 四份文本必然漂移，而漂移的方向已经发生（b89 实测）：
//!
//! | 站点 | `scan` 失败时 | 原注释 |
//! |---|---|---|
//! | `sys_menu_service.rs:210` | `let Ok(keys) = … else { return; }` ⇒ **静默返回** | "失败即中止（best-effort）" |
//! | `sys_role_service.rs:357` | 同上 ⇒ **静默返回** | 同上 |
//! | `sys_tenant_service.rs:1673` | `tracing::warn!` 后返回 | "失败仅记日志" |
//! | `initialize/tenant.rs:1502` | `if let Ok(keys) = …` ⇒ **整段跳过，无日志** | — |
//!
//! `sys_tenant_service` 的注释写着"对齐 `sys_menu_service` 同名语义"——**与事实相反**：
//! 被对齐的那两份恰恰什么都不打。后果是"授权集合已变而缓存没失效"这一族故障
//! 只在其中一条路径上可观测：管理员改角色授权后用户仍见旧菜单，Redis 抖动时
//! 日志一条没有，直到 TTL（300s）自愈，排障时无法区分"没失效"与"失效失败"。
//!
//! ## 为什么"失败必须可观测"而不是"失败必须上抛"
//!
//! 缓存失效是**旁路动作**：主流程（授权写库）已成功，把旁路失败升级成 5xx 会把
//! "缓存脏读 300 秒"换成"管理员看到保存失败"。所以沿用既有 best-effort 语义，
//! 但把"静默"这一支消掉——Err 一律 `tracing::warn!`（前言 ⑳/㉓ 的同一条纪律：
//! 结局可以是"不阻断"，不可以是"看不见"）。
//!
//! ## `who` 参数
//!
//! 只做日志归因（菜单/角色/租户/启动收敛四条触发路径）：**不得**用它分叉行为，
//! 四条路径的失效面必须同源（`perm:user:*` 全量），否则又回到"四份实现"。
//!
//! ## 为什么是 SCAN 全量而不是 KEYS / 截断 SCAN
//!
//! - `KEYS` 在 Redis 上 O(N) 阻塞主线程，共享存储必须走 `scan` 游标；
//! - `max = None` 即"游标循环到归零"。传 `Some(n)` 是**展示面**的截断语义
//!   （达上限即 WARN 并提前停），用在失效路径上会留下"超 n 个键仍返回旧权限"
//!   的陈旧缓存——与"失效全部"的意图直接冲突（同 `sys_config_service::refresh_cache`
//!   第九批那次订正）。

use std::sync::Arc;

use crate::common::constants::PERM_CACHE_PREFIX;
use crate::shared_store::SharedStore;

/// 失效**全部**用户权限缓存（授权集合变化后的统一出口，best-effort）。
///
/// - `scan` 失败 ⇒ WARN 后返回（不重试：授权行已落库，最长 TTL 后自愈）；
/// - 命中键为空 ⇒ 直接返回（幂等零删除是常态，不该产生日志噪声）；
/// - `del` 失败 ⇒ WARN（非事务，部分成功可接受，残留至 TTL）。
pub async fn invalidate_all_perm_cache(store: &Arc<dyn SharedStore>, who: &str) {
    let pattern = format!("{}*", PERM_CACHE_PREFIX);
    let keys = match store.scan(&pattern, None).await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!(
                who,
                pattern = pattern.as_str(),
                error = %e,
                "权限缓存失效：SCAN 失败，旧授权将残留至 TTL 过期（不重试，主流程不受影响）"
            );
            return;
        }
    };
    if keys.is_empty() {
        return;
    }
    if let Err(e) = store.del(&keys).await {
        tracing::warn!(
            who,
            count = keys.len(),
            error = %e,
            "权限缓存批量删除失败，可能产生脏读直至 TTL 过期"
        );
    } else {
        tracing::debug!(who, count = keys.len(), "权限缓存已失效");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::test_support::migrated_db;
    use crate::shared_store::LocalStore;

    async fn store() -> Arc<dyn SharedStore> {
        let db = migrated_db().await.expect("迁移后的临时库");
        Arc::new(LocalStore::new(db))
    }

    #[tokio::test]
    async fn invalidates_every_perm_user_key_and_only_those() {
        let store = store().await;
        for key in [
            "perm:user:1",
            "perm:user:42",
            "perm:user:7:extra",
            "config:def:sys.index.sideTheme",
            "online:abc",
        ] {
            store.set_ex(key, "v", 300).await.unwrap();
        }
        invalidate_all_perm_cache(&store, "test").await;
        for key in ["perm:user:1", "perm:user:42", "perm:user:7:extra"] {
            assert_eq!(store.get(key).await.unwrap(), None, "{key} 必须被失效");
        }
        // 跨租户/跨用户全量失效是**设计语义**（菜单/角色变更影响所有租户的 perms 下发），
        // 但绝不能顺手清掉别的用途的键——那会把缓存失效写成一次全库清空。
        for key in ["config:def:sys.index.sideTheme", "online:abc"] {
            assert_eq!(
                store.get(key).await.unwrap().as_deref(),
                Some("v"),
                "{key} 不得被权限失效波及"
            );
        }
    }

    #[tokio::test]
    async fn empty_key_set_is_a_quiet_no_op() {
        let store = store().await;
        store.set_ex("online:keep", "v", 300).await.unwrap();
        // 无 perm 键 = 常态（全新部署/幂等重入），不得报错，也不得动别的键
        invalidate_all_perm_cache(&store, "test").await;
        assert_eq!(
            store.get("online:keep").await.unwrap().as_deref(),
            Some("v")
        );
    }

    /// 接线反查（前言 ⑮"写了没接线=没写"）：三条服务侧路径必须**真的**走本函数，
    /// 而不是各自留一份等价实现。判据只看"该函数的方法体里有没有对本函数的调用点"，
    /// 因为模块文档里本来就写着函数名——按全文 `contains` 会匹配到注释而恒绿（前言 ㉖）。
    /// 方法体边界用花括号配对取，不按"下一个 `fn`"猜：猜错会把别的方法里的 `.scan(`
    /// 算进本方法体 ⇒ 一支每轮必红的假判据（前言 ⑯(c)）。
    #[test]
    fn every_service_perm_invalidation_delegates_to_the_single_source() {
        let sites = [
            "src/service/sys_menu_service.rs",
            "src/service/sys_role_service.rs",
            "src/service/sys_tenant_service.rs",
        ];
        for rel in sites {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("读取 {rel} 失败：{e}（站点清单腐化必须响亮失败）"));
            let at = text
                .find("fn invalidate_all_perm_cache")
                .unwrap_or_else(|| {
                    panic!("{rel} 里已找不到 invalidate_all_perm_cache，站点清单需同步更新")
                });
            let body = brace_body(&text[at..]);
            assert!(
                body.contains("invalidate_all_perm_cache(&self.store"),
                "{rel} 的方法体里没有委托调用 ⇒ 它还是自己那一份实现（四份实现必漂）"
            );
            assert!(
                !body.contains(".scan("),
                "{rel} 仍在自己 SCAN ⇒ 委托没生效，失效面会随两份实现漂移"
            );
        }
    }

    /// 活性正控（前言 ⑥：反脆弱必须配一条"真能转红"的正控）：
    /// 合成一份"自己 SCAN 不委托"的方法体，接线判据的两个断言必须都抓得住。
    #[test]
    fn the_wiring_judge_is_falsifiable() {
        let bad = "fn invalidate_all_perm_cache(&self) {\n\
                   let Ok(keys) = self.store.scan(&pattern, None).await else { return; };\n\
                   }\n";
        let body = brace_body(bad);
        assert!(
            !body.contains("invalidate_all_perm_cache(&self.store"),
            "夹具本身必须不构成委托"
        );
        assert!(body.contains(".scan("), "夹具必须含自己 SCAN 的形状");
        // 委托形状：`.scan(` 不得出现在方法体里
        let good = "fn invalidate_all_perm_cache(&self) {\n\
                    crate::common::perm_cache::invalidate_all_perm_cache(&self.store, \"菜单\").await;\n\
                    }\n";
        let gb = brace_body(good);
        assert!(gb.contains("invalidate_all_perm_cache(&self.store"));
        assert!(!gb.contains(".scan("));
    }

    /// 从段首起取第一个 `{` 到其配对 `}` 之间的内容（含两端）。
    fn brace_body(text: &str) -> &str {
        let start = text.find('{').expect("方法体必须以 `{` 开始");
        let mut depth = 0i32;
        for (i, ch) in text[start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            if depth == 0 {
                return &text[start..start + i + 1];
            }
        }
        &text[start..]
    }
}
