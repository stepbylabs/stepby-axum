//! 生产代码防 panic 守卫（批六十六）。
//!
//! 背景：handler 是请求路径的终点——一旦 panic，axum 会中断整条连接（无 HTTP 状态码、
//! 无 `code/msg` 契约、无审计留痕），属"错误响应契约统一"硬基线（AGENTS.md C-8）的破坏。
//! 实证：`sso_handler` 的 `serde_json::to_value(result).unwrap()`、`gen_table_service`
//! 的 `models.pop().unwrap()` 均为"理论上不可能"但语义错误的 panic；
//! 批六十六已改为统一错误响应。
//!
//! 本测试把已治理完成的不变量**锁死**：handler 生产代码（`#[cfg(test)]` 之前）不得出现
//! `.unwrap()`。`expect(...)` 带明确不变量说明、且有对应的错误分级，另行评审放行。

#[cfg(test)]
mod no_panic_mod {
    use std::path::Path;

    /// 已知豁免目录（`#[cfg(test)]` 之前的行）：内含"穷尽匹配守卫"型 `unreachable!`
    /// （如 backend 枚举兜底臂），该类 panic 属**编译期可发现**的穷尽性检查，
    /// 新增 DB 后端变体时会立即暴露，保留 panic 语义更有利。
    const MATCH_GUARD_DIRS: &[&str] = &[
        "src/initialize",
        "src/repository",
        "src/middleware",
        "src/scheduler",
        "src/bin",
    ];

    fn is_match_guard_dir(rel: &str) -> bool {
        MATCH_GUARD_DIRS
            .iter()
            .any(|d| rel == *d || rel.starts_with(&format!("{d}/")))
    }

    #[test]
    fn handlers_must_not_use_unwrap_in_production_code() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let handler_dir = root.join("src/handler");
        let violations = collect_violations(&handler_dir, &["unwrap()"]);
        assert!(
            violations.is_empty(),
            "handler 生产代码禁止 .unwrap()（命中 panic 守卫）：\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn gen_table_service_must_not_panic_on_empty_import_result() {
        // 批六十六回归锁：`import_table` 不得以 panic 表达"契约不满足"
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service/gen_table_service.rs");
        let src = std::fs::read_to_string(&path).expect("读取 gen_table_service.rs 失败");
        let prod = production_prefix(&src);
        assert!(
            !prod.contains("models.pop().unwrap()"),
            "gen_table_service::import_table 仍使用 models.pop().unwrap() —— panic 会中断 request task"
        );
    }

    /** 取 `#[cfg(test)]` 之前的"生产代码"部分 */
    fn production_prefix(src: &str) -> String {
        if let Some(idx) = src.find("#[cfg(test)]") {
            src[..idx].to_string()
        } else {
            src.to_string()
        }
    }

    /** 递归收集命中 unwrap() 的行（跳过测试块、注释行、穷尽匹配守卫目录） */
    fn collect_violations(dir: &Path, needles: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(collect_violations(&p, needles));
                continue;
            }
            if p.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&p) else {
                continue;
            };
            let rel = p
                .strip_prefix(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
                .unwrap_or(&p)
                .display()
                .to_string()
                .replace('\\', "/");
            if is_match_guard_dir(&rel) {
                continue;
            }
            let prod = production_prefix(&src);
            for (i, line) in prod.lines().enumerate() {
                let l = line.trim();
                if l.starts_with("//") {
                    continue;
                }
                if needles.iter().any(|n| line.contains(n)) {
                    out.push(format!("  {rel}:{}  {}", i + 1, l.trim_end()));
                }
            }
        }
        out
    }
}
