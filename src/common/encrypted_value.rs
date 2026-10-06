// stepby-axum/src/common/encrypted_value.rs
//! 字段加密通用层（G-14 深审定稿：sea-orm 自定义列类型）
//!
//! **定位**：RuoYi-Vue-Plus"注解式 + mybatis 拦截器"字段加密在 Rust/sea-orm 语境下的
//! 地道等价物——实体字段声明类型即"注解"（`secret: Option<EncryptedString>`），
//! 取存自动加解密，零调用点散落（对比服务层手动 seal/unseal 的散点风格）。
//!
//! 密文格式：复用 [`crate::utils::crypto`] 的 enc3 信封（AES-256-GCM，PBKDF2 派生，
//! key_id 轮换）；密钥源为 [`crate::utils::crypto::runtime_master_key`]（启动注入）。
//!
//! **必须写死的边界**（与 RuoYi 注解式同款限制）：
//! - 密文列**不可 LIKE / 等值 / 排序查询**——同一明文每次加密结果不同（随机盐/nonce），
//!   `WHERE secret = 'x'` 永远不命中。仅适用于"取回后完整消费"的字段
//!   （secret / token / private key / 凭据 JSON）；需要按值查询的敏感字段
//!   （如手机号）应另存派生索引列（blind index，另行立项）。
//! - 启动回填（v5-E6）使用 raw SQL 绕过实体层——与新类型自动加解密**无冲突**
//!   （回填判据基于密文前缀，实体层不参与回填路径）；**新增加密列时必须同步
//!   登记进 v5-E6 TARGETS 清单**，否则存量明文行不会被迁移。

use sea_orm::TryGetable;
use sea_orm::entity::prelude::*;

use crate::utils::crypto::{runtime_master_key, seal_sensitive_value, unseal_sensitive_value};

/// 加密存储的字符串列类型（enc3 信封，AES-256-GCM）
///
/// - **写入**（`Set` / `insert` / `update`）：自动 `seal_sensitive_value`（幂等：
///   已加密值原样保留，防双重加密；密钥未配置时迁移期 fail-open 原样明文）；
/// - **读取**（`find` / `find_one`）：自动 `unseal_sensitive_value`（解密失败
///   原样返回存储值并记日志——宽松读路径，密文回显优于整列 500）。
///
/// # Examples
///
/// ```ignore
/// // 实体声明（即"注解"）：
/// #[derive(DeriveEntityModel)]
/// pub struct Model {
///     pub secret: Option<EncryptedString>,   // 存取自动加解密
///     pub name: Option<String>,              // 普通列
/// }
///
/// // 写入：ActiveModel { secret: Set(Some(EncryptedString("raw-secret".into()))) }
/// // 读取：model.secret -> Some(EncryptedString("raw-secret"))（已自动解密）
/// ```
/// 注意：Debug 手写全掩码（**不可 derive**）——读路径解密后 `self.0` 持有明文，
/// derive Debug 会把明文打进日志（安全红线）；实体 derive(Debug) 依赖本实现兜底。
#[derive(Clone, PartialEq, Eq, serde::Deserialize, ts_rs::TS, utoipa::ToSchema)]
#[ts(export, export_to = "EncryptedString.ts")]
pub struct EncryptedString(pub String);

impl std::fmt::Debug for EncryptedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptedString(<redacted>)")
    }
}

impl EncryptedString {
    /// 以明文构造（后续写库时自动加密）
    pub fn plaintext(plain: impl Into<String>) -> Self {
        Self(plain.into())
    }

    /// 取明文（读出的值已自动解密；显式出口供测试/特殊场景）
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<String> for EncryptedString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for EncryptedString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// 写侧：转换为存储 Value 时自动加密（幂等 + 迁移期 fail-open，语义同
/// `seal_sensitive_value`）
impl From<EncryptedString> for Value {
    fn from(v: EncryptedString) -> Self {
        let sealed = seal_sensitive_value(&v.0, runtime_master_key());
        // seal 失败（密钥异常）：fail-closed 落库会写坏数据——退化为明文并告警，
        // 与 E6 回填的"不修坏数据"不同，此处是写入路径，宁可明文可读也不写不可解的值
        let stored = match sealed {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    "EncryptedString 加密失败，降级明文存储（请检查 CONFIG_ENC_KEY）: {e}"
                );
                v.0
            }
        };
        Value::String(Some(stored))
    }
}

/// 读侧：从存储 Value 自动解密（解密失败原样返回存储值，宽松读路径）
impl TryGetable for EncryptedString {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &QueryResult,
        index: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let stored = String::try_get_by(res, index)?;
        Ok(Self(unseal_sensitive_value(&stored, runtime_master_key())))
    }
}

/// 列类型声明（TEXT——密文 base64 膨胀约 4/3，TEXT 无长度限制）
///
/// sea-query 0.32 `ValueType`：`try_from` 读取解密、`column_type` 声明 TEXT；
/// NULL 语义由 sea-query 对 `Option<T>` 的 blanket 实现（`Option<EncryptedString>`）承载。
impl sea_orm::sea_query::ValueType for EncryptedString {
    fn try_from(v: Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            Value::String(Some(s)) => Ok(Self(unseal_sensitive_value(&s, runtime_master_key()))),
            Value::String(None) => Ok(Self(String::new())),
            _ => Err(sea_orm::sea_query::ValueTypeErr),
        }
    }

    fn type_name() -> String {
        "encrypted_string".to_string()
    }

    fn array_type() -> sea_orm::sea_query::ArrayType {
        sea_orm::sea_query::ArrayType::String
    }

    fn column_type() -> ColumnType {
        ColumnType::Text
    }
}

/// NULL 语义（sea_query 0.32 `Nullable`——`Option<EncryptedString>` 的 None 分支）
impl sea_orm::sea_query::Nullable for EncryptedString {
    fn null() -> Value {
        Value::String(None)
    }
}

// ==================== 实体 derive 链所需 trait（Serialize/Deserialize/TS/ToSchema） ====================

/// 序列化输出**掩码**（前 2 后 2，中段 ****；≤6 字符全掩码）——实体 Model 直接
/// 序列化返回前端时，敏感值永不回显明文/密文（安全红线）
impl serde::Serialize for EncryptedString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let chars: Vec<char> = self.0.chars().collect();
        let masked = if chars.is_empty() {
            String::new()
        } else if chars.len() <= 6 {
            "*".repeat(chars.len())
        } else {
            format!(
                "{}****{}",
                chars[..2].iter().collect::<String>(),
                chars[chars.len() - 2..].iter().collect::<String>()
            )
        };
        serializer.serialize_str(&masked)
    }
}

#[cfg(test)]
mod tests {
    // 注意：明文回退路径（密钥未配置 → fail-open）依赖 RUNTIME_MASTER_KEY 未初始化，
    // 而 OnceLock 全局态不可逆——无法在本模块与其他 set_runtime_master_key 测试共存；
    // 该路径由 crypto.rs 的 seal_sensitive_value 空密钥测试覆盖，此处不再重复。
    use super::*;

    const KEY: &str = "test-master-key-0123456789abcdef";

    #[test]
    fn test_value_conversion_seals_on_write() {
        crate::utils::crypto::set_runtime_master_key(KEY.to_string());
        let v: Value = EncryptedString::plaintext("raw-secret").into();
        match v {
            Value::String(Some(stored)) => {
                // 写入即加密（enc3 信封）且非明文
                assert!(stored.starts_with("enc3:k1:"), "应写入 v3 信封: {stored}");
                assert!(!stored.contains("raw-secret"));
            }
            other => panic!("应为 Value::String，实际: {other:?}"),
        }
    }

    #[test]
    fn test_value_conversion_idempotent_for_sealed() {
        crate::utils::crypto::set_runtime_master_key(KEY.to_string());
        let once: Value = EncryptedString::plaintext("s").into();
        let sealed = match once {
            Value::String(Some(s)) => s,
            _ => panic!(),
        };
        // 已加密值再写入：幂等原样保留（防双重加密不变量）
        let v: Value = EncryptedString(sealed.clone()).into();
        match v {
            Value::String(Some(s)) => assert_eq!(s, sealed, "已加密值不得二次加密"),
            _ => panic!(),
        }
    }

    #[test]
    fn test_try_from_value_unseals_on_read() {
        crate::utils::crypto::set_runtime_master_key(KEY.to_string());
        let sealed = crate::utils::crypto::encrypt_config_value("plain-xyz", KEY).unwrap();
        let v = Value::String(Some(sealed));
        let got = <EncryptedString as sea_orm::sea_query::ValueType>::try_from(v).unwrap();
        assert_eq!(got.0, "plain-xyz", "读取应自动解密");
    }

    #[test]
    fn test_column_type_and_try_from_null() {
        assert!(matches!(
            <EncryptedString as sea_orm::sea_query::ValueType>::column_type(),
            sea_orm::sea_query::ColumnType::Text
        ));
        // NULL 反序列化：空串承载（Option<EncryptedString> 的 None 由 sea-query blanket 分流）
        let got = <EncryptedString as sea_orm::sea_query::ValueType>::try_from(Value::String(None))
            .unwrap();
        assert_eq!(got.0, "");
    }
}
