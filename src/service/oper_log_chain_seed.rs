// stepby-axum/src/service/oper_log_chain_seed.rs
//! 防篡改链 verify 重算的锚点感知 prev 种子解析（批次十九，纯函数无 IO）
//!
//! 背景：HMAC 链每行 stored hash = H(key, prev, oper_id, payload)，prev 是**前一
//! 链行的 stored hash 明文**，不落库。物理删除（保留期清理 / 手动按区间清理）后，
//! 幸存行的真实前驱可能已被删除——verify 重算必须改用锚点（`sys_log_archive_anchor`）
//! 登记的被删尾行 hash 作种子，否则恒误报 broken。
//!
//! 判定规则（`resolve_prev_seed`）：设当前重算行为 R、前一幸存链行为 P：
//! 1. 取 P 与 R 之间的锚点集合 A = { a : a.last_oper_id < R.oper_id 且
//!    a.first_oper_id > P.oper_id }（P 不存在即链首时，仅要求 last_oper_id < R.oper_id；
//!    **前提**：锚点段内不含幸存链行——该前提**不是天然成立**，由登记侧
//!    [`segment_chain_runs`] 断段保证（两条物理删除路径共用同一判据）；批七十四 B5
//!    实测：租户维度时间范围清理只删本租户行，窗口内他租链行幸存，当时的单锚点
//!    登记踩破此前提 ⇒ 幸存行误报 broken 且 verify 短路后真篡改不可见）；
//! 2. A 为空 ⇒ R 的前驱就是 P（或链首空种子）——`Carry`；
//! 3. A 非空时取 **`last_oper_id` 最大**的 A*（链序最靠近 R 的被删段尾行）：
//!    - 正确性证明：R 的真实前驱 = R 写链时刻的链尾 L；链行序与 oper_id 同序
//!      （写侧乱序检测强制），故 L 被删时必为「R 之前被删行」中 oper_id 最大者——
//!      与各段删除动作的先后（deleted_at）无关。跨批次删除场景（同段分两次调用、
//!      deleted_at 与链序相反）下 deleted_at 键会选错锚点 → 误报 broken
//!      （e2e 实测断链 #48846，批次十九收尾六修正）；deleted_at 仅作同 id 防御 tiebreak。
//!    - `A*.deleted_at < R.oper_time` ⇒ R 写入时删除已完成，写侧"查前驱"续接的是
//!      幸存行 P（或链首空种子）——`Carry`；
//!    - 否则 R 在删除时已存在，其真实前驱是被删尾行——`Anchor(A*.last_chain_hash)`。
//!
//! 已知边界：Carry/Anchor 的时间判定以 oper_time 近似真实写链时刻（毫秒级偏差），
//! 写入与删除毫秒级交错时可能误报 broken——**误报方向保守**（不会漏报真篡改），
//! verify 语义为尽力重算，文档已注明。锚点选择本身（本文件职责）在链序键下无此边界。
//! `sys_flow_log` 等声明"永不清理"的表不经过此逻辑。

use chrono::NaiveDateTime;

/// 锚点快照（verify 重算前一次性拉取，升序无关——内部全量扫描判定）
#[derive(Debug, Clone)]
pub struct ChainAnchorSnapshot {
    pub first_oper_id: i64,
    pub last_oper_id: i64,
    pub last_chain_hash: String,
    pub deleted_at: NaiveDateTime,
}

/// 当前行重算所需的 prev 种子
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrevSeed {
    /// 续接前一幸存链行（prev_row_hash 为 None 时 = 链首空种子）
    Carry,
    /// 用锚点登记的被删尾行 hash 作种子
    Anchor(String),
}

/// 判定幸存链行 R 重算时的 prev 种子（见模块文档判定规则）
///
/// `prev_row_oper_id`：前一幸存链行的 oper_id（None = R 是幸存首行）。Carry 语义下
/// 调用方以"前一幸存行 hash"（链首为空串）作种子，故本函数无需接收 hash 值。
pub fn resolve_prev_seed(
    prev_row_oper_id: Option<i64>,
    row_oper_id: i64,
    row_oper_time: NaiveDateTime,
    anchors: &[ChainAnchorSnapshot],
) -> PrevSeed {
    let between: Vec<&ChainAnchorSnapshot> = anchors
        .iter()
        .filter(|a| {
            a.last_oper_id < row_oper_id && prev_row_oper_id.is_none_or(|p| a.first_oper_id > p)
        })
        .collect();
    let Some(latest) = between
        .iter()
        .max_by_key(|a| (a.last_oper_id, a.deleted_at))
    else {
        return PrevSeed::Carry;
    };
    if latest.deleted_at < row_oper_time {
        // R 写入时该删除已完成：写侧"查前驱"续接的是幸存前驱（或链首空种子）。
        PrevSeed::Carry
    } else {
        PrevSeed::Anchor(latest.last_chain_hash.clone())
    }
}

/// 链首空种子（写侧创世行用空 prev 计算，verify 对称）
pub const GENESIS_SEED: &str = "";

/// 把"本次确实会被删除的链行"按链行序切成**连续段**：`(段首, 段尾, 段尾 hash)`。
///
/// `all_chain`：**全局**链行 `(oper_id, chain_hash)` 升序（含不在删除集里的幸存行）；
/// `deleted`：本次授权后真实待删的 oper_id 集合。
///
/// 为什么必须"见幸存行才断段"：[`resolve_prev_seed`] 的判定 1 依赖前提
/// **"锚点段内不含幸存链行"**（模块文档 §1 括注）。前提破了就不是"少一条锚点"
/// 而是**用错种子**——幸存行只能用上一幸存行 hash 续接，而它的真实前驱可能正是
/// 被删掉的边界行 ⇒ verify 误报 broken，且 verify 遇错即短路返回，断点之后的
/// 真篡改从此不可见（防篡改能力整体失效，方向不保守）。
///
/// 两条物理删除路径共用本函数（单一事实源）：按 id 批量删除（`delete_oper_logs`）
/// 与按时间范围清理（`register_anchor_and_delete`）——后者的删除集在**租户维度**
/// 被裁剪，窗口内他租链行必然幸存（批七十四 B5 同族实测缺陷）。
pub fn segment_chain_runs(
    all_chain: &[(i64, String)],
    deleted: &std::collections::HashSet<i64>,
) -> Vec<(i64, i64, String)> {
    let mut segments: Vec<(i64, i64, String)> = Vec::new();
    let mut cur: Option<(i64, i64, String)> = None;
    for (oid, hash) in all_chain {
        if deleted.contains(oid) {
            match &mut cur {
                None => cur = Some((*oid, *oid, hash.clone())),
                Some((_, last, last_hash)) => {
                    *last = *oid;
                    *last_hash = hash.clone();
                }
            }
        } else if let Some(seg) = cur.take() {
            segments.push(seg);
        }
    }
    if let Some(seg) = cur {
        segments.push(seg);
    }
    segments
}

/// 从**授权后真实待删集合**导出链行区间 `(最小, 最大)`（空集返回 `None`）。
///
/// 立案（b89 项 3）：`delete_oper_logs` 原先写 `oper_ids.first()` / `.last()` 求区间。
/// 调用方确实对**请求集**排过序，但请求集在中间被 `filter_ids_in_scope` 换成**授权集**，
/// 而那一查没有 `ORDER BY` ⇒ 返回顺序由 DB 的扫描序决定（SQLite 常按 rowid 升序、
/// PostgreSQL / MySQL 未定义）。传反的 `min_id > max_id` 时
/// `find_chain_rows_in_range` 的 `gte(min) AND lte(max)` **恒空** ⇒ 一段锚点都不登记，
/// 而 DELETE 照样执行 ⇒ "行被物理删除、链上留下无人认领的缺口"，verify-chain 要么误报
/// broken、要么被短路（批七十四 B5 那条不变式的另一半：区间必须真的是区间的两端）。
///
/// 取 min/max 而不是"依赖上游排序"，让这条不变式**结构上不可能再破**——
/// 与"顺序由注释声明"相反，这里由函数签名保证。
pub fn chain_range(ids: &[i64]) -> Option<(i64, i64)> {
    let min = ids.iter().min().copied()?;
    let max = ids.iter().max().copied()?;
    Some((min, max))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// b89 项 3：区间由值导出，与输入顺序无关（这正是 `first()/last()` 写法会破的地方）
    #[test]
    fn chain_range_is_order_independent() {
        let sorted = [7i64, 9, 11, 13];
        let shuffled = [13i64, 7, 11, 9];
        assert_eq!(chain_range(&sorted), Some((7, 13)));
        assert_eq!(
            chain_range(&shuffled),
            Some((7, 13)),
            "乱序输入必须得到同一区间 ⇒ 判据不得依赖上游排序"
        );
    }

    /// 单元素与重复元素
    #[test]
    fn chain_range_handles_single_and_duplicate() {
        assert_eq!(chain_range(&[42]), Some((42, 42)));
        assert_eq!(chain_range(&[42, 42, 42]), Some((42, 42)));
        assert_eq!(chain_range(&[-5i64, 0, 3]), Some((-5, 3)));
    }

    /// 空集必须返回 None（调用方据此**不做任何事**，而不是拿 0 当区间端点）
    #[test]
    fn chain_range_empty_is_none_not_zero() {
        assert_eq!(chain_range(&[]), None);
    }

    /// 反脆弱：把实现改回"取首尾"的缺陷形状必须被抓（同序相关的那一对）
    #[test]
    fn chain_range_is_falsifiable() {
        let unsorted = [13i64, 7, 11, 9];
        let first_last = (unsorted[0], unsorted[unsorted.len() - 1]);
        assert!(
            first_last.0 > first_last.1,
            "夹具必须真的'首大于尾'，否则本锁什么都没检验"
        );
        assert_eq!(chain_range(&unsorted), Some((7, 13)), "区间必须是真区间");
    }

    fn anchor(first: i64, last: i64, hash: &str, deleted_at: &str) -> ChainAnchorSnapshot {
        ChainAnchorSnapshot {
            first_oper_id: first,
            last_oper_id: last,
            last_chain_hash: hash.to_string(),
            deleted_at: NaiveDateTime::parse_from_str(deleted_at, "%Y-%m-%d %H:%M:%S").unwrap(),
        }
    }

    fn t(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    /// 无锚点：Carry（普通连续链）
    #[test]
    fn no_anchor_carries_prev() {
        let seed = resolve_prev_seed(Some(10), 11, t("2026-10-08 10:00:00"), &[]);
        assert_eq!(seed, PrevSeed::Carry);
    }

    /// 链首被删（cleanup 删最老段）：幸存首行用锚点种子
    #[test]
    fn genesis_deleted_uses_anchor_seed() {
        let anchors = [anchor(1, 100, "h100", "2026-10-08 03:00:00")];
        // 行 101 写入于删除之前（oper_time 早于 deleted_at）→ 前驱是被删尾行
        let seed = resolve_prev_seed(None, 101, t("2026-10-01 10:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Anchor("h100".into()));
    }

    /// 链首被删，但幸存首行写入于删除之后：写侧查前驱无果 → 空种子 Carry
    #[test]
    fn genesis_row_written_after_cleanup_carries_empty() {
        let anchors = [anchor(1, 100, "h100", "2026-10-08 03:00:00")];
        let seed = resolve_prev_seed(None, 101, t("2026-10-08 05:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Carry);
    }

    /// 中间段被删（手动 clean）：行在删除前已存在 → 锚点种子
    #[test]
    fn middle_gap_row_predates_deletion_uses_anchor() {
        let anchors = [anchor(50, 60, "h60", "2026-10-08 03:00:00")];
        // P=49 幸存，R=61 在删除前已存在
        let seed = resolve_prev_seed(Some(49), 61, t("2026-10-01 09:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Anchor("h60".into()));
    }

    /// 中间段被删，但 R 写入于删除之后：写侧续接幸存前驱 → Carry
    #[test]
    fn middle_gap_row_written_after_deletion_carries() {
        let anchors = [anchor(50, 60, "h60", "2026-10-08 03:00:00")];
        let seed = resolve_prev_seed(Some(49), 61, t("2026-10-08 05:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Carry);
    }

    /// 多个锚点夹在 P 与 R 之间：取 last_oper_id 最大者（链序最靠近 R 的被删段尾行）
    #[test]
    fn multiple_anchors_use_largest_last_oper_id() {
        let anchors = [
            anchor(50, 60, "h60", "2026-10-07 03:00:00"),
            anchor(61, 70, "h70", "2026-10-08 03:00:00"),
        ];
        // R=71 在两次删除之前已存在 → 前驱是链序最大被删段尾行 h70
        let seed = resolve_prev_seed(Some(49), 71, t("2026-10-06 09:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Anchor("h70".into()));
        // R=71 在两次删除之后写入 → 写侧续接幸存前驱
        let seed = resolve_prev_seed(Some(49), 71, t("2026-10-08 06:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Carry);
    }

    /// 跨批次删除且 deleted_at 与链序相反（e2e 实测断链 #48846 复现，批次十九收尾六）：
    /// 先删链序较大的段 [61,65]（deleted_at 较早），后删链序较小的段 [50,60]
    /// （deleted_at 较晚）；R=71 写链于两次删除之前，真实前驱 = 链序最大被删行 65。
    /// 旧规则（deleted_at 最晚优先）会误选 h60 → broken；链序键修正后选 h65。
    #[test]
    fn cross_batch_deletion_chain_order_wins_over_deleted_at() {
        let anchors = [
            anchor(50, 60, "h60", "2026-10-08 03:00:01"),
            anchor(61, 65, "h65", "2026-10-08 03:00:00"),
        ];
        let seed = resolve_prev_seed(Some(49), 71, t("2026-10-08 02:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Anchor("h65".into()));
    }

    /// 锚点在 P 之前（与当前行无关）：不参与判定
    #[test]
    fn anchor_before_prev_row_ignored() {
        let anchors = [anchor(1, 10, "h10", "2026-10-07 03:00:00")];
        // P=20 幸存（在锚点段之后），R=21
        let seed = resolve_prev_seed(Some(20), 21, t("2026-10-06 09:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Carry);
    }

    // ==================== segment_chain_runs（锚点登记侧的段切分判据） ====================

    fn chain_ids(rows: &[(i64, i64, String)]) -> Vec<(i64, i64)> {
        rows.iter().map(|(f, l, _)| (*f, *l)).collect()
    }

    fn set(ids: &[i64]) -> std::collections::HashSet<i64> {
        ids.iter().copied().collect()
    }

    /// 全段被删（平台保留期清理的典型形态）⇒ 收敛为 1 段，段尾 hash 取**最后一个**被删行
    #[test]
    fn contiguous_deletion_collapses_to_one_run() {
        let all = vec![
            (1, "h1".to_string()),
            (2, "h2".to_string()),
            (3, "h3".to_string()),
        ];
        let segs = segment_chain_runs(&all, &set(&[1, 2, 3]));
        assert_eq!(chain_ids(&segs), vec![(1, 3)], "相邻被删行必须合并为一段");
        assert_eq!(
            segs[0].2, "h3",
            "段尾 hash 必须是被删尾行的 hash（续接种子）"
        );
    }

    /// 幸存行隔断（租户维度窗口：他租链行留在原地）⇒ 必须断成多段，
    /// 且**段内不得含幸存行**（resolve_prev_seed 判定 1 的前提）
    #[test]
    fn surviving_rows_split_runs() {
        let all = vec![
            (1, "h1".to_string()),
            (2, "h2".to_string()),
            (3, "h3".to_string()),
            (4, "h4".to_string()),
            (5, "h5".to_string()),
        ];
        // 删 1/3/5，2/4 幸存 ⇒ 三段，各段边界都是"仅含被删行"
        let segs = segment_chain_runs(&all, &set(&[1, 3, 5]));
        assert_eq!(
            chain_ids(&segs),
            vec![(1, 1), (3, 3), (5, 5)],
            "幸存行必须断段，否则锚点声称的区间夹着幸存行"
        );
        assert_eq!(
            segs.iter().map(|s| s.2.clone()).collect::<Vec<_>>(),
            vec!["h1", "h3", "h5"],
            "每段种子应为该段自身尾行"
        );
    }

    /// 首尾不完整（部分删除）：只删中间连续段 ⇒ 1 段，不产生"覆盖幸存行"的假段
    #[test]
    fn middle_only_deletion_yields_single_bounded_run() {
        let all = vec![
            (10, "h10".to_string()),
            (11, "h11".to_string()),
            (12, "h12".to_string()),
            (13, "h13".to_string()),
        ];
        let segs = segment_chain_runs(&all, &set(&[11, 12]));
        assert_eq!(chain_ids(&segs), vec![(11, 12)]);
        assert_eq!(segs[0].2, "h12");
    }

    /// 空集双向边界：无链行 / 删除集为空 ⇒ 不得凭空造段
    /// （对照组：B5 修复的"0 行删除仍登记锚点"就是这条边界被踩破）
    #[test]
    fn empty_inputs_produce_no_segments() {
        let all = vec![(1, "h1".to_string()), (2, "h2".to_string())];
        assert!(
            segment_chain_runs(&all, &set(&[])).is_empty(),
            "删除集为空不得登记任何段"
        );
        assert!(
            segment_chain_runs(&[], &set(&[1, 2])).is_empty(),
            "范围内无链行时不得登记任何段"
        );
    }

    /// 段切分与 `resolve_prev_seed` 的**闭环**：按本函数产出的段登记锚点后，
    /// 幸存行必须能各自取到"自己的真实前驱"（跨段不得串种子）
    #[test]
    fn segmented_anchors_seed_each_survivor_with_its_true_predecessor() {
        // 链：1(A) 2(B) 3(A) 4(B) 5(A)，A 清理删 1/3/5 ⇒ 段 [1,1] [3,3] [5,5]
        let anchors = [
            anchor(1, 1, "h1", "2026-10-08 03:00:00"),
            anchor(3, 3, "h3", "2026-10-08 03:00:00"),
            anchor(5, 5, "h5", "2026-10-08 03:00:00"),
        ];
        let when = t("2026-10-01 09:00:00"); // 全部写于删除之前
        // 幸存首行 2：前驱 = 被删 1
        assert_eq!(
            resolve_prev_seed(None, 2, when, &anchors),
            PrevSeed::Anchor("h1".into())
        );
        // 幸存行 4（P=2）：前驱 = 被删 3，**不得**取 h5（链序更大的段）或 h1
        assert_eq!(
            resolve_prev_seed(Some(2), 4, when, &anchors),
            PrevSeed::Anchor("h3".into())
        );
        // 反证：若把三段合并成单锚点 [1,5]（修复前的登记形态），
        // 行 2 无锚点可用（last=5 不小于 2）⇒ Carry 空种子 ⇒ 必然误报 broken
        let merged = [anchor(1, 5, "h5", "2026-10-08 03:00:00")];
        assert_eq!(resolve_prev_seed(None, 2, when, &merged), PrevSeed::Carry);
    }
}
