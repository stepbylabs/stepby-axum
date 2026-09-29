#![no_main]

//! fuzz target：`stepby_axum::common::excel::read_xlsx_rows`（xlsx 导入解析入口）
//!
//! 该入口由**用户上传的任意字节**直接驱动（前端仅限制扩展名，内容不可信），
//! 是典型的解析器不可信输入边界（可被用于探测 calamine 的 panic / 资源耗尽）。
//!
//! 断言的不变量：
//!   ① 绝不 panic（任意字节只允许 `Ok` / `Err` 两种结局）；
//!   ② 成功返回时，矩阵中每个单元格都已是字符串化结果（类型上由签名保证）。
//!
//! 注：本入口签名正是"字符串/字节可驱动"的公开 API（`fn(&[u8]) -> Result<Vec<Vec<String>>, _>`），
//! 故纳入 fuzz 覆盖；若其公开 API 无法由字节驱动则本 target 会被跳过（当前可驱动）。

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 只要求"不 panic"；解析成功与否都由 calamine 决定，均为合法结局。
    if let Ok(rows) = stepby_axum::common::excel::read_xlsx_rows(data) {
        // 触达返回结构，确保编译器不会把调用优化掉（并验证行结构可安全遍历）
        for row in &rows {
            for cell in row {
                let _ = cell.len();
            }
        }
    }
});
