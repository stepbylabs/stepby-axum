// stepby-axum/src/common/session_owner.rs
//! 旧会话（v2.13 前的 `online:*` JSON 无 `tenant_id`）的租户归属回查结局。
//!
//! ## 为什么这是一个**类型**而不是一句注释
//!
//! 改造前三处站点（`handler/monitor_online_handler.rs` 的列表与强退、
//! `service/dashboard_service.rs` 的在线数）都写成
//! `tenant_ids_by_user_ids(..).await.unwrap_or_else(|_| HashMap::new())`，
//! 再把查不到的行折算成 `tenant_id = 0`。于是**两种完全不同的事实产出同一个值**：
//!
//! - 「这个用户根本没有租户归属记录（行已删除）」——这是**数据事实**；
//! - 「这次查询失败了」——这是**存储故障**。
//!
//! 后果按站点各不相同，但根因是同一句话：读失败被折成了"没有这件事"（AGENTS 69(a) 族）。
//! 最贵的一处在**强退**：租户管理员踢本租户的旧会话时，`session_tid` 被算成 0，
//! 与 `operator_tid != 0` 不等 ⇒ 返回 **403「无权限访问该资源」**——而归属从头到尾没有被
//! 证明过。界面把一个数据库抖动说成"你越权了"，管理员会去提权限工单，而不是重试；
//! 那条会话仍然活着，却没人知道它为什么踢不掉（漏吊销不可归因）。
//!
//! ## 三条规则（本模块把三条规则做成一个判据点）
//!
//! 1. `Resolved` 与 `Failed` **不得合并**：查询失败一律上抛原因，由调用点决定结局；
//! 2. 「查到了但没有这个用户」⇒ `Orphan`：按既有语义视为平台会话（现状，数据事实）；
//! 3. 「查不出来」⇒ `Unknown`：租户侧的列表与强退都必须**响亮失败**（503），
//!    不得显示成一个不完整的列表，更不得说成 403。
//!
//! 平台操作者（`tenant_id = 0`）不受 2/3 的可见性影响——它本来就看得全，且踢得动，
//! 归属未定时把行标成"平台"只是标签不精确，不阻断任何动作（该残余按实登记
//! `docs/optimization/quality-batch-149-2026-11-02.md` §6 N-149-A）。

use std::collections::HashMap;

/// 租户归属回查的三种结局。
///
/// 泛型 `K` 是回查的键：主路径按 `user_id`（`i64`），Redis 故障的降级路径按 `user_name`
/// （`String`）。两条路共用**同一个结局类型**是刻意的——否则"失败折成空表"这一族会在
/// 第二条路上重新长出来（b90 ①"修一处不是修一类"）。默认 `K = i64` 让主路径的调用点
/// 不必到处写 `<i64>`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LegacyOwnerLookup<K: Eq + std::hash::Hash = i64> {
    /// 屏上没有需要回查的旧会话（`tenant_id == 0` 且键有效的行为零）——
    /// 与 `Resolved(空)` 区分：后者是"查了，一个都没查到"。
    NotNeeded,
    /// 回查成功：`键 -> tenant_id`（未命中的键是真孤儿，见 [`Self::owner_of`] 的 `Orphan`）
    Resolved(HashMap<K, i64>),
    /// 回查失败：字符串是可归因的失败原因（只进日志，不进对外文案——C.9）
    Failed(String),
}

/// 单条会话的租户归属判定（模块内命名不带 `SessionOwner`：
/// `handler/monitor_online_handler.rs` 已有同名的「属主收敛」结构体，撞名会让两处语义互相顶班）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerVerdict {
    /// 归属确定
    Known(i64),
    /// 旧会话，且用户行确实不存在（数据事实）——按平台会话处理（= 现状）
    Orphan,
    /// 旧会话，归属**无法证明**（回查失败）——调用点必须响亮失败，不得折成 0
    Unknown,
}

impl<K: Eq + std::hash::Hash> LegacyOwnerLookup<K> {
    /// 由仓储结局构造（唯一入口：`Err` 绝不允许被折成空表）
    pub(crate) fn from_outcome(user_ids: &[K], outcome: Result<HashMap<K, i64>, String>) -> Self {
        if user_ids.is_empty() {
            return Self::NotNeeded;
        }
        match outcome {
            Ok(map) => Self::Resolved(map),
            Err(reason) => Self::Failed(reason),
        }
    }

    /// 回查是否失败（列表/强退据此决定 503）
    pub(crate) fn failed(&self) -> Option<&str> {
        match self {
            Self::Failed(reason) => Some(reason.as_str()),
            _ => None,
        }
    }

    /// 判定单条会话的归属。
    ///
    /// `session_tenant_id` 直接取 `OnlineSession.tenant_id`：非 0 即 v2.13+ 的新会话，
    /// 归属由会话自己携带，回查结果根本不参与（这一点必须成立，否则"回查失败"会把
    /// 新会话一起拖成 Unknown ——那才是真的把故障放大）。
    pub(crate) fn owner_of(&self, session_tenant_id: i64, key: &K) -> OwnerVerdict {
        if session_tenant_id != 0 {
            return OwnerVerdict::Known(session_tenant_id);
        }
        match self {
            Self::Failed(_) => OwnerVerdict::Unknown,
            // 没有旧会话需要回查 ⇒ 出现 tenant_id=0 的行只能是孤儿（保守按现状处理）
            Self::NotNeeded => OwnerVerdict::Orphan,
            Self::Resolved(map) => match map.get(key) {
                Some(tid) => OwnerVerdict::Known(*tid),
                None => OwnerVerdict::Orphan,
            },
        }
    }
}

/// 租户操作者能否安全地消费这份数据（纯函数，便于逐条证伪）。
///
/// - 平台操作者（`operator_tid == 0`）：不受影响——它不按租户过滤，且踢得动任何会话；
/// - 租户操作者：回查失败 ⇒ `false`（调用点必须 503，因为列表会**静默变短**、
///   强退会被说成 403）。
pub(crate) fn tenant_scope_is_safe<K: Eq + std::hash::Hash>(
    operator_tid: i64,
    lookup: &LegacyOwnerLookup<K>,
) -> bool {
    operator_tid == 0 || lookup.failed().is_none()
}

#[cfg(test)]
mod tests {
    //! 判据落在"三种结局不得互相同形"上：`Resolved(空)`（确实没查到）与 `Failed`
    //! （查不了）必须给出不同结局，否则本模块等于没写——这正是改造前三站点共同的形状。
    use super::*;

    fn map(pairs: &[(i64, i64)]) -> HashMap<i64, i64> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn empty_id_list_is_not_the_same_as_an_empty_result() {
        // NotNeeded：没有旧会话需要回查
        let not_needed = LegacyOwnerLookup::<i64>::from_outcome(&[], Ok(map(&[])));
        assert_eq!(not_needed, LegacyOwnerLookup::NotNeeded);
        // Resolved(空)：查了，但一个用户行都没命中（全是孤儿）
        let resolved_empty = LegacyOwnerLookup::from_outcome(&[7], Ok(map(&[])));
        assert_eq!(
            resolved_empty,
            LegacyOwnerLookup::Resolved(HashMap::new()),
            "有待回查的 ID 时不得短路成 NotNeeded"
        );
        assert_ne!(
            LegacyOwnerLookup::<i64>::NotNeeded,
            LegacyOwnerLookup::Resolved(HashMap::new()),
            "「没要查的」与「查了没查到」必须是两个值"
        );
    }

    #[test]
    fn lookup_failure_must_not_fold_into_an_empty_map() {
        let failed = LegacyOwnerLookup::from_outcome(&[7], Err("db down".into()));
        assert_eq!(failed, LegacyOwnerLookup::Failed("db down".into()));
        assert_eq!(failed.failed(), Some("db down"));
        // 决定性一条：失败与"查到了但没有这个用户"必须给出不同结局
        assert_eq!(
            failed.owner_of(0, &7),
            OwnerVerdict::Unknown,
            "读失败不得被读成孤儿（更不得折成 0）"
        );
        assert_eq!(
            LegacyOwnerLookup::Resolved(map(&[])).owner_of(0, &7),
            OwnerVerdict::Orphan
        );
    }

    #[test]
    fn sessions_carrying_their_own_tenant_are_never_unknown() {
        // 回查失败也拖不到新会话：tenant_id 非 0 时归属由会话自己证明
        let failed = LegacyOwnerLookup::<i64>::Failed("db down".into());
        assert_eq!(failed.owner_of(9, &7), OwnerVerdict::Known(9));
        // user_id 不在回查集合里也无妨（同一道理：判定不看回查结果）
        assert_eq!(
            LegacyOwnerLookup::Resolved(map(&[(1, 2)])).owner_of(3, &99),
            OwnerVerdict::Known(3)
        );
    }

    #[test]
    fn resolved_lookup_answers_from_the_map() {
        let resolved = LegacyOwnerLookup::Resolved(map(&[(7, 3), (8, 4)]));
        assert_eq!(resolved.owner_of(0, &7), OwnerVerdict::Known(3));
        assert_eq!(resolved.owner_of(0, &8), OwnerVerdict::Known(4));
        assert_eq!(resolved.owner_of(0, &9), OwnerVerdict::Orphan);
        assert_eq!(resolved.failed(), None);
    }

    #[test]
    fn tenant_operator_must_not_consume_data_while_the_lookup_is_failing() {
        let failed = LegacyOwnerLookup::<i64>::Failed("db down".into());
        let resolved = LegacyOwnerLookup::Resolved(map(&[(7, 3)]));
        assert!(
            !tenant_scope_is_safe(3, &failed),
            "租户侧：回查失败 ⇒ 不得把静默变短的列表交给它，更不得把踢不动说成越权"
        );
        assert!(
            tenant_scope_is_safe(3, &resolved),
            "对照组：回查成功照常放行"
        );
        assert!(
            tenant_scope_is_safe(0, &failed),
            "平台侧不按租户过滤，且踢得动任何会话 ⇒ 不受这一支影响"
        );
        assert!(
            tenant_scope_is_safe(3, &LegacyOwnerLookup::<i64>::NotNeeded),
            "没有旧会话时不得凭空判失败"
        );
    }

    // ===================== 生产码形状锁（「读失败折成空值」这一族）=====================
    //
    // 本模块的三条规则只有在**所有**归属读取都走它的时候才成立。改造前四处站点
    // （列表 / Redis 降级列表 / 强退 / 在线数）是同一段代码复制四遍，所以判据不能
    // 「逐站点记得改」——必须由事实派生采集面：谁调了归属读取，谁就必须给出结局。
    //
    // 三条腿互相顶不了：
    //   腿 1 folded_reads —— 锚点窗口里出现「折成空值」的标记 ⇒ 违规（与接线无关，最硬）
    //   腿 2 unwired_reads —— 锚点窗口里既没 `?` 上抛也没进本类型 ⇒ 违规（防「新站点各写一份」）
    //   腿 3 出口唯一 —— `LegacyOwnerLookup::from_outcome(` 生产码**恰 4 处**（扩员必须显式改这里）
    // 外加采集面体量地板，与「合成违规必须被抓 / 合规形状必须不报」的正控。

    /// 归属读取锚点（带前导点：只认**调用点**，不认 `pub async fn` 定义点）
    const OWNER_READS: [&str; 3] = [
        ".tenant_ids_by_user_ids(",
        ".tenant_ids_by_user_names(",
        ".find_tenant_ids_by_user_ids(",
    ];
    /// 「读失败被折成空值」的标记
    const FOLD_MARKERS: [&str; 4] = [
        "unwrap_or_else(",
        "unwrap_or_default(",
        ".ok()",
        "unwrap_or(0)",
    ];
    /// 窗口：锚点行**前 4 行到后 6 行**。
    /// 前伸是为了认得出 `from_outcome(&[..], repo.await.map_err(..))` 这种「包裹在锚点之上」的合规形状。
    /// 已知局限按实登记：极端情况下锚点上方恰好出现的 `from_outcome` 能把未接线的锚点洗白——
    /// 但那种形状在本仓不存在（包裹式调用必然紧邻锚点上方），且腿 1 不看窗口上方、独立兜住折叠。
    const BACK: usize = 4;
    const FWD: usize = 6;

    /// 锚点行的窗口文本（折叠全部空白 ⇒ `cargo fmt` 怎么折行都不影响判定，只判语义）
    fn window(lines: &[String], at: usize) -> String {
        let start = at.saturating_sub(BACK);
        let end = (at + FWD + 1).min(lines.len());
        let squeezed: String = lines[start..end].join(" ").split_whitespace().collect();
        // 剥掉**被允许的**那一处 `unwrap_or_default()`：`.failed()` 是在读结局，不是把读取失败折成空值。
        // 不剥的话，接线正确站点自带的"把原因写进 WARN"会把窗口撑出一个假违规（`cargo fmt` 一折行
        // 就可能把它挪进窗口——判据红在自己的排版上，AGENTS ㉑/㉕ 同族）。
        squeezed.replace("failed().unwrap_or_default()", "")
    }

    /// 逐锚点判定，返回违规行号（1 起）：窗口内出现 `markers` 里任一标记即违规。
    fn hits_with(lines: &[String], markers: &[&str]) -> Vec<usize> {
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if !OWNER_READS.iter().any(|a| line.contains(a)) {
                continue;
            }
            let w = window(lines, i);
            if markers.iter().any(|m| w.contains(m)) {
                out.push(i + 1);
            }
        }
        out
    }

    /// 腿 1：失败被折成空值
    fn folded_reads(lines: &[String]) -> Vec<usize> {
        hits_with(lines, &FOLD_MARKERS)
    }

    /// 腿 2：读了归属却没给出结局——既不 `?` 上抛，也没进结局类型。
    ///
    /// 与腿 1 是**两件事**：腿 1 抓"有折叠标记"的形状，腿 2 抓"结果整个被丢掉"的形状
    /// （`let _ = repo.await;` 一个折叠标记都没有，腿 1 看不见，但它同样让失败消失）。
    fn unwired_reads(lines: &[String]) -> Vec<usize> {
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if !OWNER_READS.iter().any(|a| line.contains(a)) {
                continue;
            }
            let w = window(lines, i);
            if !w.contains("from_outcome") && !w.contains(".await?") {
                out.push(i + 1);
            }
        }
        out
    }

    /// 生产码视图（注释剔除 + `#[cfg(test)]` 之后不采）
    fn prod_view(rel: &str) -> Vec<String> {
        crate::common::prod_scan::prod_file(
            rel,
            &crate::common::prod_scan::Scan {
                comments: crate::common::prod_scan::Comments::Drop,
                ..Default::default()
            },
        )
        .lines
    }

    #[test]
    fn owner_read_folding_and_unwired_sites_are_zero_in_production_code() {
        let cfg = crate::common::prod_scan::Scan {
            comments: crate::common::prod_scan::Comments::Drop,
            ..Default::default()
        };
        let files = crate::common::prod_scan::prod_files(&cfg);
        // 采集面地板：腰斩即「扫描器扫不到东西」，不得读成「违规归零」
        crate::common::prod_scan::require_volume(&files, 300, 50_000, "归属读取形状锁");

        let mut folded: Vec<String> = Vec::new();
        let mut unwired: Vec<String> = Vec::new();
        let mut outlets = 0usize;
        for f in &files {
            for line in f.lines.iter() {
                outlets += line.matches("LegacyOwnerLookup::from_outcome(").count();
            }
            // 两条腿都调用**同一份**纯函数（真实树与合成夹具走的是同一把尺，不得各写一遍）
            folded.extend(
                folded_reads(&f.lines)
                    .into_iter()
                    .map(move |at| format!("{}:{} 折成空值", f.rel, at)),
            );
            unwired.extend(
                unwired_reads(&f.lines)
                    .into_iter()
                    .map(move |at| format!("{}:{} 未给出结局", f.rel, at)),
            );
        }
        assert!(
            folded.is_empty(),
            "归属读取的失败被折成空值（读不出来 ≠ 没有这件事）：{}",
            folded.join("、")
        );
        assert!(
            unwired.is_empty(),
            "读了归属却没给出结局（既不 `?` 上抛也不进 LegacyOwnerLookup）：{}",
            unwired.join("、")
        );
        // 出口唯一 + 站点数守恒：新增第五处必须**显式**改这一句，逼作者回答「失败时谁看见」
        assert_eq!(
            outlets, 4,
            "LegacyOwnerLookup::from_outcome 必须恰 4 处（列表 / 降级列表 / 强退 / 在线数）；\
             多出来要说清第 5 个入口是谁，少了就是有人把结局类型绕过去了"
        );
    }

    #[test]
    fn the_four_real_sites_are_actually_wired_through_the_outcome_type() {
        // 反向腿：只判「0 违规」的锁，在有人整段删除接线时**照常绿**——所以每个消费文件
        // 必须逐个证实确实引用了结局类型，且引用数逐只对上。
        let expect = [
            ("src/handler/monitor_online_handler.rs", 3), // 列表 / 强退 / 降级列表
            ("src/service/dashboard_service.rs", 1),      // 在线数
        ];
        for (rel, want) in expect {
            let text = prod_view(rel).join("\n");
            let got = text.matches("LegacyOwnerLookup::from_outcome(").count();
            assert_eq!(
                got, want,
                "{rel} 的归属回查接线数漂移（期望 {want}，实测 {got}）"
            );
            assert!(
                text.contains("OwnerVerdict::"),
                "{rel} 必须按 OwnerVerdict 分流，否则结局类型只是拿在手里没用"
            );
        }
        // 租户侧必须把「归属未证明」翻译成可归因的 503，而不是继续说成 403 越权
        let handler = prod_view("src/handler/monitor_online_handler.rs").join("\n");
        assert_eq!(
            handler
                .matches("error.common.session_owner_unresolved")
                .count(),
            3,
            "三处租户侧响亮失败点（列表 / 强退 / 降级列表）都得用同一个键，少一处就是那里还在撒谎"
        );
    }

    #[test]
    fn the_shape_lock_is_falsifiable() {
        // 正控总量不得为 0：只写「必须被抓」而不写「抓了几条」，恒不报的实现也能全绿。
        let split = |s: &str| -> Vec<String> { s.lines().map(|l| l.to_string()).collect() };

        // ① 旧写法（失败折成空表）：腿 1 必须抓到，且点名到锚点行（第 3 行 = 方法调用那一行）
        let old_fold = split(
            "    let legacy_tenant_map = state
        .user_service
        .tenant_ids_by_user_ids(&legacy_user_ids)
        .await
        .unwrap_or_else(|e| HashMap::new());",
        );
        assert_eq!(
            folded_reads(&old_fold),
            vec![3],
            "「失败折成空表」这一族的本体形状必须被抓"
        );
        assert_eq!(
            unwired_reads(&old_fold),
            vec![3],
            "同一段代码同时也是「没给出结局」——两条腿对旧形状都该红，不是二选一"
        );

        // ② `.ok()` 折叠（强退旧写法）同样必须被腿 1 抓到
        let ok_fold = split(
            "        state
        .user_service
        .tenant_ids_by_user_ids(&[session.user_id])
        .await
        .ok()
        .unwrap_or(0);",
        );
        assert_eq!(folded_reads(&ok_fold), vec![3]);

        // ③ 合规一：`?` 上抛 ⇒ 两条腿都不报
        let via_try = split(
            "    let tid_map = state
        .user_service
        .tenant_ids_by_user_ids(&user_ids)
        .await?;",
        );
        assert!(folded_reads(&via_try).is_empty());
        assert!(unwired_reads(&via_try).is_empty());

        // ④ 合规二：包裹进结局类型 ⇒ 两条腿都不报（这正是本批四处接线的形状）
        let via_outcome = split(
            "    let legacy_owner = LegacyOwnerLookup::from_outcome(
        &legacy_user_ids,
        state
            .user_service
            .tenant_ids_by_user_ids(&legacy_user_ids)
            .await
            .map_err(|e| e.to_string()),
    );",
        );
        assert!(folded_reads(&via_outcome).is_empty());
        assert!(unwired_reads(&via_outcome).is_empty());

        // ⑤ 定义点（`pub async fn tenant_ids_by_user_ids`）不得进面：锚点带前导点
        let definition = split(
            "pub async fn tenant_ids_by_user_ids(
    &self,
    user_ids: &[i64],
) -> Result<HashMap<i64, i64>, ServiceError> {
    Ok(HashMap::new())
}",
        );
        assert!(
            folded_reads(&definition).is_empty(),
            "服务层定义点不是调用点，混进面会让每个改签名的批次都白红一次"
        );

        // ⑥ 降级路径的**名称**维度读取同样在面上（换个方法名就绕过判据是不允许的）
        let name_fold = split(
            "    let tenant_of_name = state
        .user_service
        .tenant_ids_by_user_names(&names)
        .await
        .unwrap_or_else(|e| HashMap::new());",
        );
        assert_eq!(folded_reads(&name_fold), vec![3]);

        // ⑦ 两条腿的**独立性**：结果整个被丢掉（`let _ = …`）一个折叠标记都没有，
        //    腿 1 结构上看不见——只有腿 2 能抓。少了腿 2，"新站点直接忽略 Result"这条路是敞开的。
        let dropped = split(
            "    state
        .user_service
        .tenant_ids_by_user_ids(&legacy_user_ids)
        .await;",
        );
        assert!(
            folded_reads(&dropped).is_empty(),
            "夹具前提：这个形状确实不在腿 1 的视野里（否则下面一条不构成独立性证明）"
        );
        assert_eq!(
            unwired_reads(&dropped),
            vec![3],
            "腿 2 必须独有这一抓——两腿互相顶不了才算两条判据"
        );

        // ⑧ 合规三（反脆弱）：接线正确的站点会紧接着把**结局里的原因**写进 WARN，
        //    那句 `failed().unwrap_or_default()` 不是"把读取失败折成空值"。
        //    不剥掉它，`cargo fmt` 把 WARN 折进窗口的任何一天，判据都会红在自己身上（⑨）。
        let warn_neighbour = split(
            "    let legacy_owner = LegacyOwnerLookup::from_outcome(
        &legacy_user_ids,
        state
            .user_service
            .tenant_ids_by_user_ids(&legacy_user_ids)
            .await
            .map_err(|e| e.to_string()),
    );
    if !tenant_scope_is_safe(operator_tid, &legacy_owner) {
        tracing::warn!(
            \"回查失败: operator_tid={} 原因={}\",
            operator_tid,
            legacy_owner.failed().unwrap_or_default()
        );
    }",
        );
        assert!(
            folded_reads(&warn_neighbour).is_empty(),
            "合法 WARN 里的 `failed().unwrap_or_default()` 不得算成折叠（否则本批四处接线自己就红了）"
        );
        assert!(unwired_reads(&warn_neighbour).is_empty());
    }
}
