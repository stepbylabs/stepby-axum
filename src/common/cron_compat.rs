//! cron 表达式兼容层（b81 / §10 N-23）。
//!
//! 背景：种子任务沿用 RuoYi/Quartz 风格 `0/10 * * * * ?`，而调度器用
//! `croner` + `Seconds::Required` 解析，明确拒绝"单值步长"（`0/10` 会报
//! `single number steps like "0/10" are not allowed`）。结果是默认任务一旦被启用，
//! `change_status` 只把 DB 改成运行态，`add_job` 失败并留下
//! "DB 已更新为运行，重启后生效" 的 WARN——重启后同样失败。
//!
//! 更早的口径分裂：`sys_job_service::calc_next_valid_time` 用 `Cron::from_str`
//! （默认 5 字段），而调度器要求 6 字段 ⇒ 5 字段表达式能通过 API 校验、却无法被装载。
//! 本模块收敛为**唯一解析入口**：先做 Quartz→croner 归一，再用与调度器相同的
//! `Seconds::Required + dom_and_dow(true)` 解析。service 与 scheduler 都调这里，
//! 不再各自 builder。
//!
//! 归一规则（只做语义等价变换，不做"宽松接受"）：
//! - `?` 仅当位于 day-of-month / day-of-week 字段时换成 `*`（Quartz 的 `?` 只在这两处合法）；
//! - 单值步长 `0/N` ⇒ `*/N`；`N/M` ⇒ `N-<字段上限>/M`（Quartz 的"从 N 起每 M 一次"）。
//!   其余字段（`*`、`a-b`、`a,b`、名字）原样保留；无法识别的形态仍交给 croner 拒绝。

use croner::parser::{CronParser, Seconds};

/// 字段上限（6/7 字段：秒 分 时 日 月 周，可带年字段）。
fn field_max(index: usize) -> u32 {
    match index {
        0 | 1 => 59,
        2 => 23,
        3 => 31,
        4 => 12,
        5 | 6 => 7,
        _ => 0,
    }
}

/// 将 Quartz/RuoYi 风格 cron 归一为 croner 可解析的等价形态。
///
/// 对无法识别的输入只做 trim，不在这里判合法性——非法表达式必须继续由解析器响亮拒绝。
pub fn normalize_quartz_cron(raw: &str) -> String {
    let fields: Vec<&str> = raw.split_whitespace().collect();
    if !(5..=7).contains(&fields.len()) {
        return raw.trim().to_string();
    }
    // Quartz 的 `?` 只允许出现在"日/周"两字段；5 字段时位置是 2/4，6/7 字段时是 3/5。
    let (dom, dow) = if fields.len() >= 6 { (3, 5) } else { (2, 4) };
    let normalized: Vec<String> = fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let mut value = if (index == dom || index == dow) && *field == "?" {
                "*".to_string()
            } else {
                (*field).to_string()
            };
            if let Some((start, step)) = value.split_once('/') {
                let simple_start =
                    !start.contains('*') && !start.contains('-') && !start.contains(',');
                let numeric_step = !step.is_empty() && step.chars().all(|c| c.is_ascii_digit());
                if let (true, Ok(n)) = (simple_start && numeric_step, start.parse::<u32>()) {
                    if n == 0 {
                        value = format!("*/{}", step);
                    } else if field_max(index) >= n {
                        value = format!("{}-{}/{}", n, field_max(index), step);
                    }
                }
            }
            value
        })
        .collect();
    normalized.join(" ")
}

/// 全仓唯一的 cron 解析入口：调度器装载、任务下次执行时间、报表订阅共用。
pub fn parse_cron(raw: &str) -> Result<croner::Cron, String> {
    let expression = normalize_quartz_cron(raw);
    CronParser::builder()
        .seconds(Seconds::Required)
        .dom_and_dow(true)
        .build()
        .parse(&expression)
        .map_err(|e| format!("{}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_quartz_crons_are_normalized_and_parse() {
        for (raw, want) in [
            ("0/10 * * * * ?", "*/10 * * * * *"),
            ("0/15 * * * * ?", "*/15 * * * * *"),
            ("0/20 * * * * ?", "*/20 * * * * *"),
        ] {
            assert_eq!(
                normalize_quartz_cron(raw),
                want,
                "归一结果不符合预期：{raw}"
            );
            assert!(
                parse_cron(raw).is_ok(),
                "种子 cron 必须可被调度器解析：{raw}"
            );
        }
    }

    #[test]
    fn day_question_mark_only_normalized_in_day_fields() {
        assert_eq!(
            normalize_quartz_cron("0 0 3 * * ?"),
            "0 0 3 * * *",
            "day-of-week 的 ? 必须归一"
        );
        assert_eq!(
            normalize_quartz_cron("0 0 0 ? * 1"),
            "0 0 0 * * 1",
            "day-of-month 的 ? 必须归一"
        );
        // 分钟位的 ? 不是合法 Quartz，不得被静默宽恕成 *
        assert_eq!(normalize_quartz_cron("0 ? 3 * * *"), "0 ? 3 * * *");
        assert!(
            parse_cron("0 ? 3 * * *").is_err(),
            "非法位置的 ? 必须继续报错"
        );
    }

    #[test]
    fn explicit_start_step_is_expanded_with_field_bound() {
        assert_eq!(normalize_quartz_cron("5/15 * * * * *"), "5-59/15 * * * * *");
        assert_eq!(normalize_quartz_cron("0 0 0 1/10 * ?"), "0 0 0 1-31/10 * *");
        assert!(parse_cron("5/15 * * * * *").is_ok());
        assert!(parse_cron("0 0 0 1/10 * ?").is_ok());
    }

    #[test]
    fn already_compatible_cron_is_byte_identical() {
        for raw in [
            "0 0 3 * * *",
            "0 */5 * * * *",
            "0 0 4 * * 2",
            "30 5,35 * * * *",
        ] {
            assert_eq!(normalize_quartz_cron(raw), raw);
            assert!(
                parse_cron(raw).is_ok(),
                "既有合法 cron 不得被归一破坏：{raw}"
            );
        }
    }

    #[test]
    fn five_field_cron_stays_rejected() {
        // 调度器要求秒字段；5 字段若在解析入口被接受，会重复 b81 前的口径分裂。
        assert_eq!(normalize_quartz_cron("0 3 * * *"), "0 3 * * *");
        assert!(parse_cron("0 3 * * *").is_err());
    }

    #[test]
    fn malformed_step_still_fails() {
        assert!(parse_cron("0/abc * * * * *").is_err());
        assert!(parse_cron("*/0 * * * * *").is_err());
    }
}
