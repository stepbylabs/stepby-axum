#![no_main]

//! fuzz target：`stepby_axum::common::ssrf::validate_url`（出站地址静态校验）
//!
//! 这是 SSRF 的第一道防线，属于安全边界上的**纯函数**（不发起 DNS、不做 IO）。
//!
//! 断言的不变量：
//!   ① 绝不 panic；
//!   ② 放行（`Ok`）的 URL：scheme 必为 http/https，且主机名非空；
//!   ③ 拒绝（`Err`）必须携带非空原因（防止"静默拒绝"无法排查）。
//!
//! 与 `src/common/fuzz_invariants.rs::test_ssrf_validate_url_invariants` 的分工：
//! 那里用固定种子 LCG 生成**确定性**伪随机输入（stable 工具链即可跑、结果可复现、进 CI 门禁）；
//! 本 target 由 libFuzzer 做**覆盖率导向**变异（nightly，非确定性，作为夜间补充，能探索到
//! 手写输入池覆盖不到的解析路径）。

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 仅接受合法 UTF-8：`validate_url` 的入参是 `&str`，非 UTF-8 字节不代表其契约输入。
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    match stepby_axum::common::ssrf::validate_url(raw) {
        Ok(u) => {
            let scheme = u.scheme().to_ascii_lowercase();
            assert!(
                scheme == "http" || scheme == "https",
                "只应放行 http(s)：scheme={scheme:?} 输入={raw:?}"
            );
            assert!(
                !u.host_str().unwrap_or("").is_empty(),
                "放行的 URL 必须有非空主机名：{raw:?}"
            );
        }
        Err(msg) => assert!(!msg.is_empty(), "拒绝必须带原因：{raw:?}"),
    }
});
