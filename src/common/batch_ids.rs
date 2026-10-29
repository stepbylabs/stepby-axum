//! 批量操作入参归一（b130）：**去重保序**的唯一实现。
//!
//! ## 立案（真机取证，台账 b130 §1）
//!
//! 批量删除的存在性校验原来拿**原始列表长度**与查回的行数比：
//!
//! ```text
//! DELETE /system/msg/channel/735,735   →  404 消息渠道不存在   （而 735 存在，且零删除）
//! ```
//!
//! 同一个真实 id 写两遍是**完全合法的幂等请求**（前端勾选后重复拼参、脚本重试、
//! `?ids=` 拼接都会出现），得到的却是"不存在"——用户无法自行修复，只能改客户端。
//! 同一形状在后端有 9 处（字典类型 / 消息渠道 / 消息模板 / 发送记录 / 通知公告 /
//! OAuth 提供商 / 报表定义 / 报表订阅 / 代码生成表）。
//!
//! ## 为什么归一必须在**存在性校验之前**、且只有一份实现
//!
//! 去重放在校验之后等于没做（`existing.len()` 已经按原始长度比过了）；放到各站点
//! 各写一遍则必然漂——b127 的 SCIM 组是手写 `Vec::contains` 的 O(n²) 版本，本模块
//! 上线时把它也换成了这一份。判据 `batch_delete_dedupes_before_existence_check`
//! 按**函数体**反查这 9 处（去重调用必须出现在长度比较之前），合成双向钉住方向。
//!
//! ## 语义边界（刻意保留的行为）
//!
//! - `{真实 id},{不存在的 id}` ⇒ **404 + 零删除**（b127 立的"整批要么全做、要么一条不做"）；
//! - `{不存在的 id}` ⇒ 404（批量删除是"点名缺失"，与单条 DELETE 的幂等语义不同族）；
//! - 空列表 ⇒ 200/Ok(0) 无操作；
//! - 顺序保留：审计留痕与错误点名按**输入顺序**给出。

use std::collections::HashSet;

/// 去重并保留首次出现的顺序（O(n)）。
pub fn dedupe_preserving_order(ids: &[i64]) -> Vec<i64> {
    let mut seen = HashSet::with_capacity(ids.len());
    let mut out = Vec::with_capacity(ids.len());
    for &id in ids {
        if seen.insert(id) {
            out.push(id);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::common::prod_scan::{Scan, prod_files, require_volume};
    use std::path::Path;

    use super::dedupe_preserving_order;

    #[test]
    fn dedupe_keeps_first_seen_order() {
        assert_eq!(dedupe_preserving_order(&[]), Vec::<i64>::new());
        assert_eq!(dedupe_preserving_order(&[7]), vec![7]);
        assert_eq!(dedupe_preserving_order(&[3, 1, 3, 2, 1, 3]), vec![3, 1, 2]);
        assert_eq!(dedupe_preserving_order(&[9, 9, 9, 9]), vec![9]);
        assert_eq!(
            dedupe_preserving_order(&[i64::MIN, 0, i64::MAX, 0]),
            vec![i64::MIN, 0, i64::MAX]
        );
    }

    /// 生产码（`src/service/**`）里每处「批量存在性判定」都必须在**同一函数体内、
    /// 且在长度比较之前**调用去重归一。
    ///
    /// 返回违规描述；空集 = 通过。抽成纯函数是为了给合成双向用例喂坏形状。
    fn dedupe_violations(files: &[(String, String)]) -> Vec<String> {
        /// 长度比较的坏形状：`<查回集合>.len() != <原变量>.len()`（= 拿原始长度当分母）。
        /// 两个前缀都是「查询结果 vs 入参」：`existing` 是通用名，`models` 是字典类型的命名。
        const BAD: [&str; 2] = ["existing.len() != ", "models.len() != "];
        let mut out = Vec::new();
        for (rel, text) in files {
            for bad in BAD {
                let mut from = 0usize;
                while let Some(pos) = text[from..].find(bad).map(|p| from + p) {
                    from = pos + bad.len();
                    let Some(body_start) = enclosing_fn_start(text, pos) else {
                        out.push(format!(
                            "{rel}: 找不到 {bad:?} 所在的函数体（判据输入形状变了）"
                        ));
                        continue;
                    };
                    let body = text[body_start..pos].to_string();
                    if !body.contains("dedupe_preserving_order(") {
                        let line = text[..pos].matches('\n').count() + 1;
                        let fname = fn_name_at(text, body_start);
                        out.push(format!(
                            "{rel}:{line} 函数 {fname} 用原始长度判缺失，且在此之前没有调用 dedupe_preserving_order(（重复 id 会被判成不存在）"
                        ));
                        continue;
                    }
                    // 光"调用过"不够：结果必须**遮蔽原名**。写成
                    // `let seen = dedupe_preserving_order(&ids)` 再继续用 `ids`，
                    // 去重对判据毫无影响，静态上看却是"调用在前"（本锁第一版只能抓第一种）。
                    if let Some(bad) = dedupe_shadow_violation(&body) {
                        let line = text[..pos].matches('\n').count() + 1;
                        let fname = fn_name_at(text, body_start);
                        out.push(format!(
                            "{rel}:{line} 函数 {fname} 去重后没有遮蔽原名（{bad}），后续仍可能使用未去重的列表"
                        ));
                    }
                }
            }
        }
        out
    }

    /// 去重结果必须写回**同名**绑定（`let ids = dedupe_preserving_order(&ids)`）。
    /// 返回 `Some(说明)` 表示最后一次去重调用没有遮蔽原名。
    fn dedupe_shadow_violation(body: &str) -> Option<String> {
        const CALL: &str = "dedupe_preserving_order(&";
        let pos = body.rfind(CALL)?;
        let arg: String = body[pos + CALL.len()..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        let line_start = body[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let head = &body[line_start..pos];
        let shadow = format!("let {arg} = ");
        if head.contains(&shadow) {
            None
        } else {
            Some(format!("入参是 {arg}，绑定却写成 `{}`", head.trim()))
        }
    }

    /// 从 `pos` 向前找最近的、缩进严格更浅的 `fn` 定义行。
    fn enclosing_fn_start(text: &str, pos: usize) -> Option<usize> {
        let head = &text[..pos];
        let target_indent = indent_of(head.rsplit('\n').next().unwrap_or(""));
        let mut cursor = head.len();
        while let Some(nl) = head[..cursor].rfind('\n') {
            let line = &head[nl + 1..cursor];
            let trimmed = line.trim_start();
            let is_fn = {
                let t = trimmed
                    .strip_prefix("pub(crate) ")
                    .or_else(|| trimmed.strip_prefix("pub "))
                    .unwrap_or(trimmed);
                let t = t.strip_prefix("async ").unwrap_or(t);
                t.starts_with("fn ")
            };
            if is_fn && indent_of(line) < target_indent {
                return Some(nl + 1);
            }
            cursor = nl;
        }
        None
    }

    fn indent_of(line: &str) -> usize {
        line.chars().take_while(|c| *c == ' ').count()
    }

    fn fn_name_at(text: &str, start: usize) -> String {
        let line = text[start..].lines().next().unwrap_or("");
        line.split("fn ")
            .nth(1)
            .map(|s| s.split(['(', '<']).next().unwrap_or("").trim().to_string())
            .unwrap_or_default()
    }

    #[test]
    fn batch_delete_dedupes_before_existence_check() {
        let cfg = Scan::default();
        let all = prod_files(&cfg);
        require_volume(&all, 350, 40_000, "批量语义形状锁");
        let scoped: Vec<(String, String)> = all
            .iter()
            .filter(|f| f.rel.starts_with("src/service/"))
            .map(|f| (f.rel.clone(), f.text()))
            .collect();
        assert!(
            scoped.len() >= 45,
            "采集面只剩 {} 个 service 文件（b130 实测 51）—— 目录改名让扫描器扫不到东西了",
            scoped.len()
        );

        // 反脆弱：采集面里必须真的能数到这些判定点（否则"零违规"是空转）
        let hits: usize = scoped
            .iter()
            .map(|(_, t)| {
                t.matches("existing.len() != ").count() + t.matches("models.len() != ").count()
            })
            .sum();
        assert!(
            hits >= 8,
            "采集面里只数到 {hits} 处长度判定（实测 9 处）——判据输入坏了，不是通过"
        );

        let violations = dedupe_violations(&scoped);
        assert!(
            violations.is_empty(),
            "批量删除必须先去重再判缺失（b130）：\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn shape_lock_catches_both_directions() {
        let bad = [(
            "src/service/demo.rs".to_string(),
            "impl S {\n    pub async fn del(&self, ids: Vec<i64>) {\n        let existing = r.find(&ids).await?;\n        if existing.len() != ids.len() {\n            return Err(404);\n        }\n    }\n}\n"
                .to_string(),
        )];
        let v = dedupe_violations(&bad);
        assert_eq!(v.len(), 1, "没有去重的坏形状必须被抓到：{v:?}");
        assert!(v[0].contains("demo.rs:4"), "违规要指到行号：{}", v[0]);
        assert!(v[0].contains("del"), "违规要指到函数名：{}", v[0]);

        // 方向一：去重写在长度比较**之后**，等价于没做
        let late = [(
            "src/service/demo.rs".to_string(),
            "impl S {\n    pub async fn del(&self, ids: Vec<i64>) {\n        let existing = r.find(&ids).await?;\n        if existing.len() != ids.len() {\n            return Err(404);\n        }\n        let ids = dedupe_preserving_order(&ids);\n    }\n}\n"
                .to_string(),
        )];
        assert_eq!(
            dedupe_violations(&late).len(),
            1,
            "去重晚于判定必须照常判红（顺序是判据的一部分）"
        );

        // 方向二：合规形状不得误报
        let good = [(
            "src/service/demo.rs".to_string(),
            "impl S {\n    pub async fn del(&self, ids: Vec<i64>) {\n        let ids = dedupe_preserving_order(&ids);\n        let existing = r.find(&ids).await?;\n        if existing.len() != ids.len() {\n            return Err(404);\n        }\n    }\n}\n"
                .to_string(),
        )];
        assert!(
            dedupe_violations(&good).is_empty(),
            "合规形状不得误报：{:?}",
            dedupe_violations(&good)
        );

        // 方向三：调用在前、结果却没遮蔽原名 —— 去重对判据毫无影响，
        // 但只判"有没有调用过"的锁会把它放过去（本锁第一版正是如此）。
        let alias = [(
            "src/service/demo.rs".to_string(),
            "impl S {\n    pub async fn del(&self, ids: Vec<i64>) {\n        let seen = dedupe_preserving_order(&ids);\n        let existing = r.find(&seen).await?;\n        if existing.len() != ids.len() {\n            return Err(404);\n        }\n    }\n}\n"
                .to_string(),
        )];
        let v = dedupe_violations(&alias);
        assert_eq!(v.len(), 1, "去重未遮蔽原名必须被抓到：{v:?}");
        assert!(v[0].contains("遮蔽"), "违规要说明是哪种坏法：{}", v[0]);
    }

    /// 采集面自证：本锁读的是真实文件，不是自造字符串。
    #[test]
    fn lock_reads_real_repository_files() {
        assert!(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/service")
                .is_dir()
        );
    }
}
