//! stepby-axum 性能基准测试示例（R6-BE-ENG-21）
//!
//! 用途：
//!   作为 benches/ 目录的占位示例，演示如何编写并运行性能基准测试。
//!   当前仅使用标准库（std::time::Instant）做简单计时，未引入外部框架。
//!
//! 运行方式：
//!   cargo bench                          # 运行所有 bench
//!   cargo bench --bench example          # 仅运行 example
//!   cargo run --bench example            # 以普通二进制方式运行（便于调试）
//!
//! 未来扩展建议：
//!   引入 criterion 提供统计分析与回归检测：
//!   1. 在 Cargo.toml 添加：criterion = { version = "0.5", features = ["html_reports"] }
//!   2. 将 [[bench]] 的 harness 改为 true（或删除 harness = false）
//!   3. 重写本文件使用 criterion::criterion_group! / criterion_main! 宏
//!
//! 注意：
//!   - 基准测试不参与单元测试（cargo test 不会执行本文件）
//!   - clippy --all-targets 会编译本文件，需保持代码整洁

use std::hint::black_box;
use std::time::Instant;

fn main() {
    println!("=== stepby-axum 示例基准测试 ===\n");

    // 示例 1：字符串拼接性能（format! 宏）
    let start = Instant::now();
    let mut s = String::new();
    for i in 0..10_000 {
        s.push_str(&format!("item_{}\n", black_box(i)));
    }
    let elapsed_format = start.elapsed();
    println!("字符串拼接 (format!, 10000 次): {:?}", elapsed_format);

    // 示例 2：字符串拼接性能（push_str + 手写数字）
    let start = Instant::now();
    let mut s2 = String::new();
    for i in 0..10_000 {
        s2.push_str("item_");
        s2.push_str(&i.to_string());
        s2.push('\n');
    }
    let elapsed_push = start.elapsed();
    println!("字符串拼接 (push_str, 10000 次): {:?}", elapsed_push);

    // 示例 3：Vec<u64> 排序性能（逆序输入触发最坏情况）
    let mut v: Vec<u64> = (0..10_000).rev().collect();
    let start = Instant::now();
    v.sort();
    let elapsed_sort = start.elapsed();
    println!("Vec<u64> 排序 (10000 元素逆序): {:?}", elapsed_sort);

    // 示例 4：哈希查找性能
    use std::collections::HashMap;
    let mut map: HashMap<u64, &'static str> = HashMap::with_capacity(10_000);
    for i in 0..10_000u64 {
        map.insert(i, "value");
    }
    let start = Instant::now();
    let mut hits = 0u64;
    for i in 0..10_000u64 {
        if map.contains_key(&black_box(i)) {
            hits += 1;
        }
    }
    let elapsed_hash = start.elapsed();
    println!("HashMap 查找 (10000 次, hits={}): {:?}", hits, elapsed_hash);

    println!("\n=== 基准测试完成 ===");
    println!("提示：以上为简单计时结果，存在系统调度抖动。");
    println!("      生产级基准测试建议使用 criterion 框架（见文件头注释）。");
}
