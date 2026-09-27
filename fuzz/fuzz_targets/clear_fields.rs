#![no_main]

//! fuzz target：`axum_backend::common::clear_fields::resolve`
//!
//! 「显式清空」契约的白名单与冲突判定（DTO 部分更新语义的安全边界）。
//!
//! 输入编码：
//!   - 首个 `0x00` 之前的字节用于派生"字段当前值"（每个可清空字段取一个字节：
//!     `0` = 未提交；`1|2` = 纯空白（视为未提交）；其余 = 非空值）；
//!   - 首个 `0x00` 之后的字节按 `\n` 切分为 `clearFields` 声明列表；
//!     若该段为空则视为未携带 `clearFields`（`None`）。
//!
//! 断言的不变量：
//!   ① 绝不 panic；
//!   ② 放行的清空字段必须 ∈ [`ClearFieldsDto::CLEARABLE_FIELDS`] 白名单；
//!   ③ 放行的清空字段不得同时携带非空值（值 + 清空声明冲突应被拒）；
//!   ④ 同输入可重复解析（`resolve` 必须确定性）。

use std::collections::HashMap;

use axum_backend::common::clear_fields::{self, ClearFieldsDto};
use libfuzzer_sys::fuzz_target;

/// 最小假 DTO：三个可清空字段，值与清空声明均可由 fuzz 输入注入。
struct FakeDto {
    fields: Option<Vec<String>>,
    values: HashMap<&'static str, String>,
}

impl ClearFieldsDto for FakeDto {
    const CLEARABLE_FIELDS: &'static [&'static str] = &["configJson", "remark", "leader"];

    fn clear_fields(&self) -> Option<&[String]> {
        self.fields.as_deref()
    }

    fn field_value_is_present(&self, field: &str) -> bool {
        clear_fields::value_is_present(self.values.get(field).map(String::as_str))
    }
}

fuzz_target!(|data: &[u8]| {
    // 按首个 NUL 切成"值段"与"清空声明段"
    let (value_part, fields_part) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (&data[..0], data),
    };

    // 值段：每个可清空字段取一个字节决定"是否带非空值"
    let mut values: HashMap<&'static str, String> = HashMap::new();
    for (i, f) in FakeDto::CLEARABLE_FIELDS.iter().enumerate() {
        match value_part.get(i).copied() {
            None | Some(0) => {}
            // 纯空白 = 前端清空输入框 ⇒ 视为"未修改"，不算值
            Some(1) | Some(2) => {
                values.insert(f, "   ".to_string());
            }
            Some(b) => {
                values.insert(f, format!("v{b}"));
            }
        }
    }

    // 声明段：按行切分为字段名列表（可含空白 / 未知字段 / 重复 / 空串等畸形输入）
    let fields = if fields_part.is_empty() {
        None
    } else {
        Some(
            String::from_utf8_lossy(fields_part)
                .split('\n')
                .map(str::to_string)
                .collect::<Vec<_>>(),
        )
    };

    let dto = FakeDto {
        fields,
        values: values.clone(),
    };

    // Err 分支（白名单外字段 / 值+清空冲突 ⇒ 400）只需"不 panic"即达标。
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
        // 确定性：同输入必须得到同输出
        let again = clear_fields::resolve(&dto).expect("同输入应可重复解析");
        assert_eq!(clears, again, "resolve 必须确定性（同输入同输出）");
    }
});
