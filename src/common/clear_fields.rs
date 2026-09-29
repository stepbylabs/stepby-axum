// backend-axum/src/common/clear_fields.rs
//! 「显式清空」契约（批次 4）——补上"部分更新语义"缺失的另一半能力。
//!
//! # 为什么需要它
//!
//! 2026-09-26 把一批 update 接口的字段语义统一为"**未传 = 保持已加载行的现值**"，
//! 修掉了"只改名称的 PUT 把已加密的渠道密钥擦除为 NULL"等 13 处缺陷。该语义是**默认安全**的，
//! 但副作用是：**再也没法把某字段清空**——传 `null` 被解释为"保持"，传空串被
//! `filter(!is_empty)` 跳过（登记为已知取舍，见 `multitenant-pending-items-ledger §8.10-C`）。
//!
//! 本项目定位「大而全，让使用者自己选择或配置」：**能清空**是配置能力的一部分，
//! 不能因为"默认要安全"就把这条路永久堵死。故补齐**显式清空**契约：
//!
//! - 请求体额外携带 `clearFields: ["configJson", …]`（camelCase，与前端提交口径一致）；
//! - **只有显式声明**的字段才写 NULL ⇒ 不带该字段的请求与改造前**逐条等价**；
//! - 白名单外的字段名 ⇒ **400**（不静默忽略，避免"以为清了其实没清"）；
//! - 同一字段**既声明清空又传了非空值** ⇒ **400**（口径冲突 fail-fast，避免误删）；
//!   空串 / `null` / 空白串一律视为"未修改"，不算冲突——前端表单清空输入框即产生空串。
//!
//! # 用法
//!
//! ```ignore
//! let clears = crate::common::clear_fields::resolve(&dto)?;
//! if clears.contains("configJson") {
//!     am.config_json = Set(None);
//! } else if let Some(c) = dto.config_json.as_deref().filter(|c| !c.is_empty()) {
//!     am.config_json = Set(Some(c.to_string()));
//! }
//! ```

use std::collections::HashSet;

use crate::common::error::ServiceError;

/// 一张"可清空字段"白名单 + 值探测（无 `frame` 依赖，便于在任意 DTO 上实现）。
///
/// `CLEARABLE_FIELDS` 用 **camelCase**：与 `#[serde(rename_all = "camelCase")]` 的线上口径一致，
/// 前端不需要知道 Rust 侧字段名。
pub trait ClearFieldsDto {
    /// 允许被显式清空的字段名（camelCase；**逐条枚举**，禁止前缀/通配）
    const CLEARABLE_FIELDS: &'static [&'static str];

    /// 请求体声明的待清空字段（未携带 = `None`）
    fn clear_fields(&self) -> Option<&[String]>;

    /// 该字段在本次请求里**是否带了非空值**（用于冲突检测；字段名必为 camelCase）
    fn field_value_is_present(&self, field: &str) -> bool;
}

/// 解析并校验清空声明，返回归一后的 camelCase 字段名集合。
///
/// 返回空集合 = "未声明任何清空"（缺省路径，行为与改造前一致）。
pub fn resolve<D: ClearFieldsDto + ?Sized>(dto: &D) -> Result<HashSet<&'static str>, ServiceError> {
    let mut out: HashSet<&'static str> = HashSet::new();
    let Some(requested) = dto.clear_fields() else {
        return Ok(out);
    };
    for raw in requested {
        let name = raw.trim();
        let Some(field) = D::CLEARABLE_FIELDS.iter().find(|f| **f == name) else {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.common.clear_field_unknown",
                field = name
            )));
        };
        if dto.field_value_is_present(field) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.common.clear_field_conflict",
                field = name
            )));
        }
        out.insert(*field);
    }
    Ok(out)
}

/// 该字段是否被显式声明清空（读侧糖，避免调用点写 `clears.contains("x")` 的裸字符串）。
pub fn is_cleared(clears: &HashSet<&'static str>, field: &str) -> bool {
    clears.contains(field)
}

/// 值是否为"非空提交"（供各 DTO 的 [`ClearFieldsDto::field_value_is_present`] 复用）。
///
/// 口径：`None` / 空串 / 纯空白 = 未提交（不算值）。
pub fn value_is_present(value: Option<&str>) -> bool {
    value.map(|v| !v.trim().is_empty()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小实现：两个字段（一个带值、一个不带），用于锁定契约本身。
    struct Fake {
        fields: Option<Vec<String>>,
        config_json: Option<String>,
        remark: Option<String>,
    }

    impl ClearFieldsDto for Fake {
        const CLEARABLE_FIELDS: &'static [&'static str] = &["configJson", "remark"];
        fn clear_fields(&self) -> Option<&[String]> {
            self.fields.as_deref()
        }
        fn field_value_is_present(&self, field: &str) -> bool {
            match field {
                "configJson" => value_is_present(self.config_json.as_deref()),
                "remark" => value_is_present(self.remark.as_deref()),
                _ => false,
            }
        }
    }

    fn fake(fields: Option<&[&str]>) -> Fake {
        Fake {
            fields: fields.map(|f| f.iter().map(|s| s.to_string()).collect()),
            config_json: None,
            remark: None,
        }
    }

    /// 缺省（不带 `clearFields`）⇒ 空集合 = 保持现值（**逐条等价改造前**）
    #[test]
    fn test_absent_means_keep_current_value() {
        assert!(resolve(&fake(None)).expect("缺省应通过").is_empty());
        assert!(resolve(&fake(Some(&[]))).expect("空数组应通过").is_empty());
    }

    /// 显式声明 ⇒ 归一为 camelCase 字段名
    #[test]
    fn test_explicit_declaration_is_normalized() {
        let clears = resolve(&fake(Some(&["configJson"]))).expect("合法声明应通过");
        assert!(is_cleared(&clears, "configJson"));
        assert!(!is_cleared(&clears, "remark"));
        // 两端空白容忍（前端偶发）
        let clears = resolve(&fake(Some(&["  remark "]))).expect("带空白应通过");
        assert!(is_cleared(&clears, "remark"));
    }

    /// **可证伪**：白名单外的字段名必须 400，不得静默忽略
    ///
    /// 若把未知字段改成"跳过"，本断言会从 `Err(400)` 变成 `Ok` ⇒ 变红。
    /// 那会让调用方以为"已清空"而实际未清（静默失效是最危险的失败模式）。
    #[test]
    fn test_unknown_field_is_rejected() {
        let err = resolve(&fake(Some(&["channelName"]))).expect_err("白名单外字段必须被拒");
        assert_eq!(err.code, 400, "应 400，实际 {err:?}");
    }

    /// **可证伪**：同一字段既给值又声明清空 ⇒ 400（避免误删）
    #[test]
    fn test_value_and_clear_conflict_is_rejected() {
        let mut dto = fake(Some(&["configJson"]));
        dto.config_json = Some("{\"host\":\"smtp.example.com\"}".to_string());
        let err = resolve(&dto).expect_err("冲突必须被拒");
        assert_eq!(err.code, 400, "应 400，实际 {err:?}");
    }

    /// 空串 / 空白串不算"给了值" ⇒ 不冲突（前端表单清空输入框即产生空串）
    #[test]
    fn test_blank_value_is_not_a_conflict() {
        for blank in ["", "   ", "\t\n"] {
            let mut dto = fake(Some(&["configJson"]));
            dto.config_json = Some(blank.to_string());
            assert!(
                resolve(&dto).is_ok(),
                "空白值 {blank:?} 不应与清空声明冲突（它本身就是「未修改」）"
            );
        }
    }
}
