//! 安全/一致性守卫的**读取失败不得静默放行**总锁（批七十一）。
//!
//! 背景（本批实证的一类隐蔽缺陷形态）：`if let Ok(x) = …await { … }` 看着"有分支处理"，
//! 实际把**数据库故障**折叠成"没查到/不冲突/不是超管"——于是：
//! - 解锁接口的超管保护（P0-R81-006）在 DB 抖动时被绕过；
//! - SCIM `externalId` 唯一性校验静默通过，IdP 映射被写成重复值（后续按 externalId
//!   反查同步会互相覆盖）；而 PUT 入口更是**完全不校验**（同一字段两条写入口径不一致）；
//! - SSO `/sso/jwks` 在 DB 故障时发布 `{"keys":[]}` 这份**语法合法但内容错误**的文档，
//!   RP 用它校验会全部拒签并可能缓存一段时间（比 5xx 让 RP 沿用上一份更危险）；
//! - `user.updated` 事件的租户归属读失败时回落**操作者**租户 ⇒ 平台管理员代管编辑租户
//!   用户时，事件可能被投给另一个租户的回调组（跨租户投递）；
//! - 审计 `target_tenant_id` 归属预读失败静默 ⇒ 平台代管操作的留痕落到操作者租户。
//!
//! 这些点已在 b71 逐个改为 fail-closed（守卫依赖的读取一律 `?` 上抛）或"保留可用性取舍
//! 但必须 WARN 留痕"。本测试把治理形状**锁死**：复现旧写法即刻红。
//!
//! 口径与同目录 [`no_panic_guard`] 一致——只扫 `#[cfg(test)]` 之前的生产码。

#[cfg(test)]
mod fail_closed_mod {

    /// 取生产码**语句**：`#[cfg(test)]` 之前、并剔除 `//` 行。
    /// b71 治理点的注释会引用被禁的旧写法作为说明（"原写 `if let Ok(..)`"），
    /// 不排除注释就会把"文档"误判成"回归"。采集口径见 [`crate::common::prod_scan`]。
    fn prod_src(rel: &str) -> String {
        crate::common::prod_scan::prod_file(
            rel,
            &crate::common::prod_scan::Scan {
                comments: crate::common::prod_scan::Comments::Drop,
                ..Default::default()
            },
        )
        .text()
    }

    /// 断言生产码语句中**不存在**某段旧写法
    fn assert_absent(rel: &str, needle: &str, why: &str) {
        let prod = prod_src(rel);
        assert!(
            !prod.contains(needle),
            "{rel} 仍含 fail-open 写法 `{needle}` —— {why}\n（b71 已治理，回归请同步更新本锁）"
        );
    }

    #[test]
    fn unlock_guard_must_read_target_user_fail_closed() {
        assert_absent(
            "src/handler/sys_logininfor_handler.rs",
            "if let Ok(Some(user)) = state.user_service.get_user_by_username",
            "超管保护（P0-R81-006）不得因数据库故障被绕过",
        );
    }

    #[test]
    fn scim_external_id_uniqueness_must_not_swallow_db_error() {
        assert_absent(
            "src/service/scim_service.rs",
            "if let Ok(Some(other))",
            "externalId 唯一性校验必须把 DB 故障上抛（否则重复映射静默入库）",
        );
    }

    #[test]
    fn scim_put_and_patch_share_one_external_id_validator() {
        // 同一字段的三条写入口（PUT / PATCH path-op / PATCH no-path-op）必须全部经同一
        // helper 校验，防止再出现"PATCH 查重、PUT 裸写"的口径分叉。
        let prod = prod_src("src/service/scim_service.rs");
        let calls = prod
            .match_indices("self.ensure_external_id_available(")
            .count();
        assert!(
            calls >= 3,
            "scim_service externalId 写入口应有 ≥3 处调用统一校验器，实际 {calls} 处（PUT/PATCH path-op/PATCH no-path-op）"
        );
    }

    #[test]
    fn jwks_must_not_publish_empty_document_on_db_error() {
        assert_absent(
            "src/service/sso_service.rs",
            "if let Ok(clients) = self.client_repo.find_all_enabled()",
            "JWKS 不得在 DB 故障时发布空 keys（RP 会用它误拒所有 RS256 id_token）",
        );
        let prod = prod_src("src/service/sso_service.rs");
        assert!(
            prod.contains("pub async fn jwks(&self) -> Result<serde_json::Value, ServiceError>"),
            "sso_service::jwks 必须以 Result 表达读取失败"
        );
    }

    #[test]
    fn user_event_tenant_must_come_from_authoritative_read() {
        assert_absent(
            "src/handler/sys_user_handler.rs",
            ".unwrap_or(operator.tenant_id());",
            "user.updated 事件租户归属不得在读失败时回落操作者租户（跨租户投递风险）",
        );
        // 正向锁①：编辑路径必须 fail-closed 读目标用户（一次读取供两个消费者）
        let prod = prod_src("src/handler/sys_user_handler.rs");
        assert!(
            prod.contains("get_user_by_id(dto.user_id).await?"),
            "sys_user_handler::edit 必须以 `?` 读取目标用户租户归属（不得静默回落）"
        );
        // 正向锁②：匿名化路径**允许**预读未命中（幂等重放契约：已匿名化用户 get 返回
        // not_found，二次调用必须仍是 200 + 零计数报告——b71 曾误改 fail-closed，
        // 被 integration_tests::user_erasure 实测抓回），但必须留痕。
        assert!(
            prod.contains("匿名化审计归属预读未命中"),
            "匿名化的审计归属预读失败必须 WARN 留痕（静默回落会让平台代管留痕错租户）"
        );
    }

    #[test]
    fn audit_tenant_attribution_failures_are_logged() {
        // 平台代管场景的审计 target_tenant_id 预读允许"不阻断主操作"，但必须留痕。
        // （user 侧另有专测：编辑 fail-closed + 匿名化留痕，故此处不含 sys_user_handler.rs）
        let cases = [
            ("src/handler/sys_dept_handler.rs", 2),
            ("src/handler/sys_post_handler.rs", 1),
            ("src/handler/sys_role_handler.rs", 1),
        ];
        for (rel, expect_min) in cases {
            let prod = prod_src(rel);
            let hits = prod.match_indices("审计归属预读失败").count();
            assert!(
                hits >= expect_min,
                "{rel} 的审计归属预读失败必须有 WARN 留痕（至少 {expect_min} 处，实际 {hits} 处）"
            );
        }
    }

    #[test]
    fn site_preference_read_failure_is_logged_not_silent() {
        assert_absent(
            "src/service/sys_msg_service.rs",
            "if let Ok(Some(pref)) = self.pref_repo.find_by_user_id",
            "站内信偏好（免打扰）读取失败不得静默当作允许投递",
        );
    }

    /// 采集 `src` 下全部 `.rs`（跳过 `target`/`integration_tests`）：改走
    /// [`crate::common::prod_scan::rel_paths`]。此处原本自带一份 `collect_rs`，
    /// 且目录不可读时 `return` 一个空集——那会让本锁在目录改名后**静默空转全绿**，
    /// 正是 B9 要根除的形态；共享实现改成 panic（空采集面不是通过）。
    fn src_rs() -> Vec<String> {
        crate::common::prod_scan::rel_paths("src")
    }

    /// 取 spawn 调用之后的判定窗口：最多 `SPAN_LINES` 行，且**止于下一个 `tokio::spawn(`**
    /// ——避免"隔壁已加守卫的任务"把本条未守卫任务洗白（形状锁最怕假阴性通过）。
    fn spawn_window(prod: &str, call_idx: usize) -> String {
        const SPAN_LINES: usize = 60;
        let start_line = prod[..call_idx].lines().count() - 1;
        let all: Vec<&str> = prod.lines().collect();
        let mut end = (start_line + SPAN_LINES).min(all.len());
        for (offset, line) in all.iter().enumerate().skip(start_line + 1) {
            if line.contains("tokio::spawn(") {
                end = end.min(offset);
                break;
            }
        }
        all[start_line..end].join("\n")
    }

    /// b72（AGENTS B.6 异步任务统一范式）：生产码的 `tokio::spawn` 必须满足——
    /// **panic 隔离**（`catch_unwind`/`AssertUnwindSafe`）**且** **超时**（`timeout(`，
    /// 或走 `common::background::{spawn_tracked,run_tracked}` 由其内含），
    /// 或落在 `EXEMPT` 显式豁免表内并写明取证理由。
    ///
    /// 两个条件都要（而非"之一"）的理由：只隔离 panic 仍可能无限堆积卡死任务；只加超时但
    /// panic 未隔离则任务静默死亡、连失败痕迹都没有。豁免存在的必要性：调度器 job 包装与
    /// 锁续期是**长驻循环**，外层套固定超时会砍断合法长任务——它们的超时由内部机制负责
    /// （job 侧 `execute_with_logging` 尊作业超时、续期侧 `lock_renew` 有存储超时），
    /// 但 panic 隔离仍在原位。
    ///
    /// 与常驻脚本 `scripts/rust_hygiene_scan.py` 的 `spawn_unguarded` 类互为印证：脚本出跨批次差值，
    /// 本锁做提交门禁。b72 实测起点是 **13 处裸 spawn**（`ai/handler` 4、`auth`、`ak_sign`、
    /// `sso_handler`、`ws_handler`、`scheduler` Drop 兜底、`webhook` 派发 2 等），已全部收口或定性豁免。
    #[test]
    fn background_spawn_tasks_are_guarded_or_explicitly_exempted() {
        const EXEMPT: &[(&str, &str, &str)] = &[
            (
                "src/common/background.rs",
                "tokio::spawn(async move {",
                "守卫实现自身的内层派生（timeout + catch_unwind 就在本函数体内）",
            ),
            (
                "src/service/sys_web_hook_service.rs",
                "let Ok(_permit) = gate.acquire_owned().await",
                "出站投递：per-hook `timeout_secs`（clamp MAX_TIMEOUT_SECS）负责超时；panic 时 SemaphorePermit \
                 随任务栈展开归还（不泄漏闸门）；结局落 web_hook_log 审计 + deliver() 记录组件指标",
            ),
            (
                "src/scheduler/mod.rs",
                "let result = AssertUnwindSafe(execute_with_logging(",
                "调度器 job 包装：panic 已隔离；超时由 execute_with_logging 内部按作业配置负责，\
                 外层再套固定超时会截断合法的长任务",
            ),
            (
                "src/scheduler/mod.rs",
                "AssertUnwindSafe(store.lock_renew(&lock_handle, LOCK_TTL_SECS))",
                "分布式锁续期循环：panic 已隔离（逐次迭代捕获，避免续期任务整体死亡导致锁提前失效）；\
                 长驻循环不得套外层超时，单次续期超时由 SharedStore 负责",
            ),
        ];
        let mut violations = Vec::new();
        let mut checked = 0usize;
        // b102：采集面从字面量 `tokio::spawn(` 扩到**运行时句柄别名**。立项取证：
        // acme 推送 / 领域事件出站 / ClusterLock 的 Drop 兜底三处写的是
        // `handle.spawn(` 与 `rt.spawn(`，本锁一条都看不见（"有锁没采集面"）。
        // 只认具名接收者（rt/handle/runtime/tokio_handle）——生产码里的
        // `Command::spawn()` / `std::thread::Builder::spawn()` 不是任务派生，不得误伤。
        const SPAWN_NEEDLES: &[&str] = &[
            "tokio::spawn(",
            "rt.spawn(",
            "handle.spawn(",
            "runtime.spawn(",
            "tokio_handle.spawn(",
        ];
        for rel in src_rs() {
            if rel.contains("integration_tests") || rel == "src/handler/fail_closed_guard.rs" {
                continue;
            }
            let prod = prod_src(&rel);
            let mut hits: Vec<usize> = Vec::new();
            for needle in SPAWN_NEEDLES {
                hits.extend(prod.match_indices(needle).map(|(i, _)| i));
            }
            hits.sort_unstable();
            hits.dedup();
            for idx in hits {
                checked += 1;
                let block = spawn_window(&prod, idx);
                // 走 background helper 即视为两项齐备（超时与 panic 隔离都发生在 helper 内部，
                // 调用点文本看不到 catch_unwind）
                let via_helper = block.contains("run_tracked(") || block.contains("spawn_tracked(");
                let panic_guarded =
                    block.contains("catch_unwind") || block.contains("AssertUnwindSafe");
                let time_guarded = block.contains("timeout(");
                if via_helper || (panic_guarded && time_guarded) {
                    continue;
                }
                let exempted = EXEMPT
                    .iter()
                    .any(|(f, needle, _)| *f == rel && block.contains(needle));
                if !exempted {
                    violations.push(format!(
                        "{}:L{}（panic 隔离={panic_guarded}，超时={time_guarded}）",
                        rel,
                        prod[..idx].lines().count()
                    ));
                }
            }
        }
        assert!(
            checked >= 11,
            "本锁的扫描面本身要有效：实测只见证到 {checked} 处任务派发（b72 基线 ≥8；\
             b102 扩面后基线 ≥11），说明文件遍历或 prod_src 口径出了问题，而非代码变干净了"
        );
        assert!(
            violations.is_empty(),
            "以下生产码任务派发（tokio::spawn 或运行时句柄别名）未同时满足「panic 隔离 + 超时」，也不在豁免表：{violations:?}\n\
             （AGENTS B.6：异步任务必须「超时 + 重试上限 + 失败审计」；请改用 \
             common::background::spawn_tracked / run_tracked，或在 EXEMPT 内登记取证理由）"
        );
    }

    /// b104：凭据撤权（`pwd_ver` 递增 + SSO 令牌全量吊销）不得降级为 WARN 后照常成功。
    ///
    /// 这一族的后果不在"日志里少一条"，而在**授权边界**：auth 中间件不查
    /// `sys_user.status`，一个"已停用"的账号是否真的失去访问能力，完全取决于撤权那两步
    /// 是否成功。b104 前 `change_status` / `reset_pwd` / `update_profile_pwd` 两处失败
    /// 都只 WARN 后返回 200，等于对管理员宣布"已停用/已改密"而旧令牌仍在 TTL 内可用；
    /// 批量删除更是"先删后撤权 + 失败上抛"——错误已报出、用户已删除、重试只会 404。
    ///
    /// 判据：① 业务侧只能经 `store.revoke_credentials`（单一出口）；
    /// ② 每个出口调用点的失败分支都必须 `return Err`（不是 WARN 后继续）。
    #[test]
    fn credential_revocation_must_be_single_entry_and_fail_closed() {
        use crate::common::prod_scan::{Scan, prod_files, require_volume};

        let files = prod_files(&Scan::default());
        require_volume(&files, 300, 40_000, "凭据撤权状锁");

        // ① 单一出口：`shared_store/` 是定义与实现；`sso_service.rs` 是 SSO 登出这条
        //    与平台凭据无关的独立语义（登出只吊销 SSO 令牌，不递增平台密码版本）。
        let mut violations = Vec::new();
        for f in &files {
            if f.rel.starts_with("src/shared_store/") || f.rel == "src/service/sso_service.rs" {
                continue;
            }
            for line in f.lines.iter().filter(|l| !l.trim().is_empty()) {
                if line.contains(".pwd_ver_incr(") || line.contains(".revoke_all_for_user(") {
                    violations.push(format!("{}: {}", f.rel, line.trim()));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "以下生产码绕过 SharedStore::revoke_credentials 直接调用撤权原语：{violations:?}\n\
             （两条腿必须一起走：只递增版本号会留下不透明 SSO AT，只吊销 AT 会让平台 JWT 继续过闸门）"
        );

        // ② 每个出口调用点的失败分支必须上抛
        fn assert_call_fail_closed(rel: &str, call: &str) -> usize {
            let prod = prod_src(rel);
            let mut hits = 0usize;
            for (idx, _) in prod.match_indices(call) {
                hits += 1;
                let tail: String = prod[idx..].chars().take(500).collect();
                // 两种合法形态：`if let Err(e) = … { … return Err(…) }` 与 `…map_err(…)?`
                let fail_closed = tail.contains("return Err(") || tail.contains("map_err(");
                assert!(
                    fail_closed,
                    "{rel} 的 `{call}` 失败分支必须上抛（撤权失败后照常返回成功 = 旧会话仍然可用），\
                     实际片段：{tail}"
                );
            }
            hits
        }

        let handler_hits =
            assert_call_fail_closed("src/handler/sys_user_handler.rs", ".revoke_credentials(");
        assert!(
            handler_hits >= 3,
            "用户写路径（重置 / 自助改密 / 删除）都必须在撤权失败时上抛，实测调用点 {handler_hits} 处"
        );
        let erasure_hits = assert_call_fail_closed(
            "src/service/user_erasure_service.rs",
            ".revoke_credentials(",
        );
        assert!(
            erasure_hits >= 1,
            "用户匿名化必须在破坏性写入前完成撤权，实测调用点 {erasure_hits} 处"
        );
        // 服务层的三条停用入口：`update_user_status`（changeStatus）、`edit_user`
        // （编辑表单改 status）、`import_users`（updateSupport 更新行）
        let service_hits =
            assert_call_fail_closed("src/service/sys_user_service.rs", ".revoke_credentials(");
        assert!(
            service_hits >= 3,
            "停用用户的三个服务层入口都必须撤权，实测调用点 {service_hits} 处"
        );

        // ③ SSO 登出的全量吊销同样不得 best-effort（与同流程的黑名单写入同口径）
        let sso = prod_src("src/service/sso_service.rs");
        assert_eq!(
            sso.matches("revoke_user_sso_tokens(store, uid).await?")
                .count(),
            2,
            "SSO 登出两个调用点都必须用 `?` 上抛（失败返回成功 = RT/AT 仍然有效）"
        );

        // ④ SCIM deprovision 的三条写路径（PUT / PATCH / DELETE）都必须撤权。
        //    少一条 = 那条通道上的"IdP 已停用"只改了 status，旧 JWT 活到 TTL。
        let scim = prod_src("src/service/scim_service.rs");
        assert_eq!(
            scim.matches("self.revoke_after_deactivation(id).await?")
                .count(),
            3,
            "SCIM 的 PUT / PATCH / DELETE 三条停用路径都必须调用 revoke_after_deactivation"
        );
        assert!(
            scim.contains(".revoke_credentials("),
            "SCIM 撤权必须经 SharedStore::revoke_credentials（两条腿一起走）"
        );
    }
}
