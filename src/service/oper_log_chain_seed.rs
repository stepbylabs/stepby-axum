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
//!    锚点段为连续区间删除，幸存行不可能落在段内，故该判定与删除时序无关地成立）；
//! 2. A 为空 ⇒ R 的前驱就是 P（或链首空种子）——`Carry`；
//! 3. A 非空时取 `deleted_at` 最晚的 A*：
//!    - `A*.deleted_at < R.oper_time` ⇒ R 写入时删除已完成，写侧"查前驱"续接的是
//!      幸存行 P（或链首空种子）——`Carry`；
//!    - 否则 R 在删除时已存在，其真实前驱是被删尾行——`Anchor(A*.last_chain_hash)`。
//!
//! 已知边界：删除与写入高频交错的极端时序下，"取 deleted_at 最晚"判据可能误报
//! broken——**误报方向保守**（不会漏报真篡改），verify 语义为尽力重算，文档已注明。
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
            a.last_oper_id < row_oper_id
                && prev_row_oper_id.is_none_or(|p| a.first_oper_id > p)
        })
        .collect();
    let Some(latest) = between.iter().max_by_key(|a| a.deleted_at) else {
        return PrevSeed::Carry;
    };
    if latest.deleted_at < row_oper_time {
        // R 写入时该删除已完成：写侧"查前驱"续接的是幸存前驱（或链首空种子）
        PrevSeed::Carry
    } else {
        PrevSeed::Anchor(latest.last_chain_hash.clone())
    }
}

/// 链首空种子（写侧创世行用空 prev 计算，verify 对称）
pub const GENESIS_SEED: &str = "";

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

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

    /// 多个锚点夹在 P 与 R 之间：取 deleted_at 最晚者判定
    #[test]
    fn multiple_anchors_use_latest_deleted_at() {
        let anchors = [
            anchor(50, 60, "h60", "2026-10-07 03:00:00"),
            anchor(61, 70, "h70", "2026-10-08 03:00:00"),
        ];
        // R=71 在两次删除之前已存在 → 前驱是最后被删段尾行 h70
        let seed = resolve_prev_seed(Some(49), 71, t("2026-10-06 09:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Anchor("h70".into()));
        // R=71 在两次删除之后写入 → 写侧续接幸存前驱
        let seed = resolve_prev_seed(Some(49), 71, t("2026-10-08 06:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Carry);
    }

    /// 锚点在 P 之前（与当前行无关）：不参与判定
    #[test]
    fn anchor_before_prev_row_ignored() {
        let anchors = [anchor(1, 10, "h10", "2026-10-07 03:00:00")];
        // P=20 幸存（在锚点段之后），R=21
        let seed = resolve_prev_seed(Some(20), 21, t("2026-10-06 09:00:00"), &anchors);
        assert_eq!(seed, PrevSeed::Carry);
    }
}
