// stepby-axum/src/common/fuzz_invariants.rs
//! **确定性不变式测试**（fuzz 风格的属性断言，运行在 stable 工具链上）。
//!
//! # 为什么不是 `cargo-fuzz`
//!
//! `cargo-fuzz` 需要 nightly 工具链 + 独立 fuzz workspace，本仓 CI 走 stable，
//! 直接引入会让该能力**无法在门禁里跑通**（等于假绿）。故这里用**确定性伪随机**
//! （LCG，固定种子）生成大量畸形/对抗性输入，断言"纯函数不 panic + 输出满足不变量"：
//! 可复现、可回归、零新增依赖。覆盖率导向的 `cargo-fuzz` 另登记为单独专题。
//!
//! # 覆盖对象（安全边界上的纯函数）
//!
//! - [`crate::common::ssrf::validate_url`]：出站地址校验（SSRF 第一道防线）；
//! - [`crate::common::clear_fields::resolve`]：显式清空契约的白名单 / 冲突判定；
//! - [`crate::common::webhook::url_is_http`]：出站目标 scheme 判定。

use crate::common::clear_fields::ClearFieldsDto;
use crate::common::{clear_fields, ssrf, webhook};

/// 确定性线性同余发生器（Numerical Recipes 参数）；固定种子 ⇒ 结果可复现
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (self.0 >> 32) as u32
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[(self.next_u32() as usize) % items.len()]
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u32() as usize) % n
        }
    }
}

/// 畸形 URL 片段池（scheme / 凭据 / 主机 / 端口 / 路径 的对抗性素材）
fn url_atoms() -> Vec<String> {
    let mut v: Vec<String> = [
        "http",
        "https",
        "HTTP",
        "HtTpS",
        "file",
        "ftp",
        "gopher",
        "javascript",
        "data",
        "://",
        ":",
        "/",
        "//",
        "/\\",
        "@",
        "?",
        "#",
        "%2f",
        "%00",
        "..",
        "\\",
        " ",
        "\t",
        " ",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",
        "::1",
        "[::1]",
        "localhost",
        "example.com",
        "10.0.0.1",
        "192.168.1.1",
        "0177.0.0.1",
        "2130706433",
        "user:pass",
        "80",
        "443",
        "0",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    v.push("a".repeat(300)); // 超长主机名
    v.push("\u{0}".to_string()); // 内嵌 NUL
    v.push("中".to_string()); // 非 ASCII
    v
}

fn random_url(rng: &mut Lcg, atoms: &[String]) -> String {
    let n = 1 + rng.below(8);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(rng.pick(atoms));
    }
    s
}

// ---------------- ssrf::validate_url 不变量 ----------------

/// 不变量：① 绝不 panic；② 放行的 URL scheme 必为 http(s) 且主机名非空；③ 拒绝必带原因。
#[test]
fn test_ssrf_validate_url_invariants() {
    let atoms = url_atoms();
    let mut rng = Lcg::new(0x5EED_1234);
    let mut accepted = 0usize;
    for _ in 0..5000 {
        let raw = random_url(&mut rng, &atoms);
        match ssrf::validate_url(&raw) {
            Ok(u) => {
                accepted += 1;
                let scheme = u.scheme().to_ascii_lowercase();
                assert!(
                    scheme == "http" || scheme == "https",
                    "只应放行 http(s)，实际 scheme={scheme:?}，输入={raw:?}"
                );
                assert!(
                    !u.host_str().unwrap_or("").is_empty(),
                    "放行的 URL 必须有非空主机名：{raw:?}"
                );
            }
            Err(msg) => assert!(!msg.is_empty(), "拒绝必须带原因：{raw:?}"),
        }
    }
    // 随机组合池多数应被拒绝；若一条都不放行说明池子失真（守卫被断言覆盖）
    assert!(accepted < 5000, "对抗性输入不应全部放行");
}

/// SSRF 红线：内网 / 环回 / 云元数据地址一律拒绝（与随机组合叠加验证）
#[test]
fn test_ssrf_blocks_metadata_and_loopback_hosts() {
    for host in [
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",
        "localhost",
        "10.0.0.1",
        "192.168.1.1",
        "[::1]",
    ] {
        for scheme in ["http", "https"] {
            let url = format!("{scheme}://{host}/latest/meta-data/");
            assert!(
                ssrf::validate_url(&url).is_err(),
                "内网 / 元数据地址必须拒绝：{url}"
            );
        }
    }
}

// ---------------- clear_fields::resolve 不变量 ----------------

/// 最小 DTO（三个可清空字段，值可注入），用于锁定契约本身
struct FakeDto {
    fields: Option<Vec<String>>,
    values: std::collections::HashMap<&'static str, String>,
}

impl clear_fields::ClearFieldsDto for FakeDto {
    const CLEARABLE_FIELDS: &'static [&'static str] = &["configJson", "remark", "leader"];

    fn clear_fields(&self) -> Option<&[String]> {
        self.fields.as_deref()
    }

    fn field_value_is_present(&self, field: &str) -> bool {
        clear_fields::value_is_present(self.values.get(field).map(String::as_str))
    }
}

/// 不变量：① 绝不 panic；② 放行的清空字段必在白名单内；③ 放行字段必不带非空值；
/// ④ 同输入可重复解析（确定性）。
#[test]
fn test_clear_fields_resolve_invariants() {
    const CANDIDATES: &[&str] = &[
        "configJson",
        "remark",
        "leader",
        "unknown",
        "",
        "   ",
        "ConfigJson",
        "configjson",
    ];
    let mut rng = Lcg::new(0xC1EA_0001);
    for _ in 0..4000 {
        let count = rng.below(4);
        let mut fields = Vec::new();
        for _ in 0..count {
            fields.push(rng.pick(CANDIDATES).to_string());
        }
        let mut values: std::collections::HashMap<&'static str, String> =
            std::collections::HashMap::new();
        if rng.below(2) == 0 {
            values.insert("configJson", "{\"k\":1}".to_string());
        }
        if rng.below(2) == 0 {
            values.insert("remark", "   ".to_string()); // 纯空白 = 未提交
        }
        if rng.below(2) == 0 {
            values.insert("leader", "zhang".to_string());
        }

        let dto = FakeDto {
            fields: if rng.below(8) == 0 {
                None
            } else {
                Some(fields.clone())
            },
            values: values.clone(),
        };

        // Err 分支（白名单外字段 / 值+清空冲突 ⇒ 400）只需"不 panic"即达标，故不展开
        if let Ok(clears) = clear_fields::resolve(&dto) {
            for f in &clears {
                assert!(
                    FakeDto::CLEARABLE_FIELDS.contains(f),
                    "放行的清空字段必须在白名单内：{f}"
                );
                assert!(
                    !clear_fields::value_is_present(values.get(*f).map(String::as_str)),
                    "放行清空即不得同时携带非空值：{f}"
                );
            }
            let again = clear_fields::resolve(&dto).expect("同输入应可重复解析");
            assert_eq!(clears, again, "resolve 必须确定性（同输入同输出）");
        }
    }
}

// ---------------- webhook::url_is_http 不变量 ----------------

/// 不变量：判定恒等价于"**裁剪后**以 `http://` 或 `https://` 开头"
#[test]
fn test_webhook_url_is_http_invariant() {
    let atoms = url_atoms();
    let mut rng = Lcg::new(0xBEEF_0007);
    for _ in 0..3000 {
        let raw = random_url(&mut rng, &atoms);
        let t = raw.trim();
        let expected = t.starts_with("http://") || t.starts_with("https://");
        assert_eq!(
            webhook::url_is_http(&raw),
            expected,
            "判定必须等价于裁剪后的前缀判定：{raw:?}"
        );
    }
}
