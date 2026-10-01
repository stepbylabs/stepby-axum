#![no_main]

//! fuzz target：`stepby_axum::common::webhook::url_is_http`
//!
//! 出站 webhook 目标的 scheme 判定（ACME 证书需求输出 / 领域事件输出共用内核）。
//!
//! 断言的不变量：
//!   ① 绝不 panic；
//!   ② 判定结果**恒等价**于"裁剪两端空白后以 `http://` 或 `https://` 开头"。

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    let trimmed = raw.trim();
    let expected = trimmed.starts_with("http://") || trimmed.starts_with("https://");
    assert_eq!(
        stepby_axum::common::webhook::url_is_http(raw),
        expected,
        "判定必须等价于裁剪后的前缀判定：{raw:?}"
    );
});
