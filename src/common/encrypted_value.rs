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
//!   登记进 v5-E6 TARGETS 清单**，否则存量明文行不会被迁移。这一条不再只是注释：
//!   `initialize::encrypted_backfill_contract` 按实体列类型派生采集面做**双向**对账
//!   （漏登记必红、条目腐化也必红、主键名写错同样必红），因为写侧降级
//!   （[`SealOutcome::NoMasterKey`] / [`SealOutcome::Degraded`]）**唯一的自愈通道就是它**。

use sea_orm::TryGetable;
use sea_orm::entity::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::utils::crypto::{
    is_encrypted, runtime_master_key, seal_sensitive_value, unseal_sensitive_value,
};

/// 写侧 seal 的**全部**结局——与 [`crate::utils::crypto::seal_sensitive_value`] 的四条有序出口
/// 加一条失败出口逐一对应。
///
/// 为什么要做成枚举而不是"成功/失败"布尔：改造前这五种在观测面上**只有两种样子**
/// （出参等于入参 / 出参不等），于是「这条本来就是明文，永远不用管」「没配密钥，配好后启动
/// 回填补得上」「密钥坏了，需要人工换回旧 key_id」三种整改动作完全不同的状态互相冒充
/// （b145 §1(c) 凭据三态的同一课，这次长在通用层上）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealOutcome {
    /// 入参为空串：无需加密，永久正常态，不计入任何"待修"面
    Empty,
    /// `CONFIG_ENC_KEY` 未配置：明文写库，**配好密钥后可由 v5-E6 启动回填补上**
    NoMasterKey,
    /// 入参已带信封前缀：幂等原样保留（防双重加密）
    AlreadySealed,
    /// 真加密（新写 enc3 信封）
    Sealed,
    /// `seal` 返回 `Err`：`Into<Value>` 由 sea-orm 内部调用、**结构上没有失败通道**，
    /// 只能降级写明文并计数。降级行仍在 v5-E6 回填面上 ⇒ 密钥修好后下次启动自愈；
    /// 这一条成立的前提由 `initialize::oauth_sso` 的 TARGETS↔实体列双向锁钉住
    /// （列不在回填面上 ⇒ 降级就是永久的；载体是 `crate::initialize` 模块下的
    /// 加密回填契约测试——它把 TARGETS 与实体加密列做双向对账）。
    Degraded,
}

impl SealOutcome {
    /// 采集面：指标渲染与计数表长度都由它给（"有闸、没观测"结构上不可能，AGENTS B.4）
    pub const ALL: &'static [SealOutcome] = &[
        SealOutcome::Empty,
        SealOutcome::NoMasterKey,
        SealOutcome::AlreadySealed,
        SealOutcome::Sealed,
        SealOutcome::Degraded,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SealOutcome::Empty => "empty",
            SealOutcome::NoMasterKey => "no_master_key",
            SealOutcome::AlreadySealed => "already_sealed",
            SealOutcome::Sealed => "sealed",
            SealOutcome::Degraded => "degraded_plaintext",
        }
    }

    ///  exhaustive 匹配 ⇒ 下标由编译期保证，不用 `position().unwrap()`
    /// （扩员时漏一支是**编译失败**，而不是运行期第一次写入才 panic）
    const fn index(self) -> usize {
        match self {
            SealOutcome::Empty => 0,
            SealOutcome::NoMasterKey => 1,
            SealOutcome::AlreadySealed => 2,
            SealOutcome::Sealed => 3,
            SealOutcome::Degraded => 4,
        }
    }
}

/// 读侧 unseal 的全部结局（同一族：改造前"历史明文"与"解不开"都是原样返回）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnsealOutcome {
    /// 空值
    Empty,
    /// 存量明文（回填前的行）：原样通过，属正常态
    LegacyPlaintext,
    /// 信封解密成功
    Decrypted,
    /// 带信封前缀但**解不开**（主密钥轮换未登记旧 key_id / 数据损坏）：
    /// 界面会看见 `enc3:` 串本身——这必须与"没配密钥"分开数
    Undecryptable,
}

impl UnsealOutcome {
    pub const ALL: &'static [UnsealOutcome] = &[
        UnsealOutcome::Empty,
        UnsealOutcome::LegacyPlaintext,
        UnsealOutcome::Decrypted,
        UnsealOutcome::Undecryptable,
    ];

    pub fn label(self) -> &'static str {
        match self {
            UnsealOutcome::Empty => "empty",
            UnsealOutcome::LegacyPlaintext => "legacy_plaintext",
            UnsealOutcome::Decrypted => "decrypted",
            UnsealOutcome::Undecryptable => "undecryptable",
        }
    }

    const fn index(self) -> usize {
        match self {
            UnsealOutcome::Empty => 0,
            UnsealOutcome::LegacyPlaintext => 1,
            UnsealOutcome::Decrypted => 2,
            UnsealOutcome::Undecryptable => 3,
        }
    }
}

const _: () = assert!(SealOutcome::ALL.len() == 5);
const _: () = assert!(UnsealOutcome::ALL.len() == 4);

/// 按 `seal_sensitive_value` 的**分支顺序**归因（顺序即生产码顺序，不得"顺手统一"）：
/// `stored = None` 表示 `Err`，此时落库值就是入参。
pub fn classify_seal(input: &str, master_key: &str, stored: Option<&str>) -> SealOutcome {
    if stored.is_none() {
        SealOutcome::Degraded
    } else if input.is_empty() {
        SealOutcome::Empty
    } else if master_key.is_empty() {
        SealOutcome::NoMasterKey
    } else if is_encrypted(input) {
        SealOutcome::AlreadySealed
    } else {
        SealOutcome::Sealed
    }
}

/// 按 `unseal_sensitive_value` 的分支顺序归因：带前缀而**出参等于入参**只能是解密失败
/// （一次成功的解密不可能产出与密文相同的串）。
pub fn classify_unseal(stored: &str, out: &str) -> UnsealOutcome {
    if stored.is_empty() {
        UnsealOutcome::Empty
    } else if !is_encrypted(stored) {
        UnsealOutcome::LegacyPlaintext
    } else if out == stored {
        UnsealOutcome::Undecryptable
    } else {
        UnsealOutcome::Decrypted
    }
}

static SEAL_COUNTS: [AtomicU64; SealOutcome::ALL.len()] = [const { AtomicU64::new(0) }; 5];
static UNSEAL_COUNTS: [AtomicU64; UnsealOutcome::ALL.len()] = [const { AtomicU64::new(0) }; 4];

/// 每档**只告警一次**：`no_master_key` / `degraded_plaintext` 是可长期持续的状态
/// （密钥一直没配 ⇒ 每次写都命中），逐次打会把真正的故障淹成流水（AGENTS C.9/b69）。
static SEAL_WARNED: [AtomicBool; SealOutcome::ALL.len()] = [const { AtomicBool::new(false) }; 5];

/// 记一次写侧结局并返回自增前的读数（测试取"前进了"这个事实，不取绝对值——
/// 绝对值由并行用例决定，拿它当判据就是把门禁绿红交给调度顺序，AGENTS ④）。
fn record_seal(outcome: SealOutcome) -> u64 {
    SEAL_COUNTS[outcome.index()].fetch_add(1, Ordering::Relaxed)
}

fn record_unseal(outcome: UnsealOutcome) -> u64 {
    UNSEAL_COUNTS[outcome.index()].fetch_add(1, Ordering::Relaxed)
}

/// 两种"需要人动手"的写侧结局各留一条首告，文案点名整改动作而不只是点名失败。
fn warn_once_seal(outcome: SealOutcome, detail: &str) {
    let actionable = matches!(outcome, SealOutcome::NoMasterKey | SealOutcome::Degraded);
    if !actionable || SEAL_WARNED[outcome.index()].swap(true, Ordering::Relaxed) {
        return;
    }
    let hint = match outcome {
        SealOutcome::NoMasterKey => "配置 CONFIG_ENC_KEY 后重启，启动回填（v5-E6）会补上这些行",
        SealOutcome::Degraded => {
            "密钥可用后重启，启动回填（v5-E6）会补上这些行；持续出现请检查主密钥"
        }
        _ => "",
    };
    // 只截断 + 折叠绝对路径：**不得**带上任何敏感值本身（C.9）
    tracing::error!(
        "敏感列写入结局 {}：本次以明文落库（{}）；{hint}；详情：{}",
        outcome.label(),
        "需要归因，勿当成\"这一列本来就该明文\"",
        crate::middleware::oper_log::safe_truncate(
            &crate::common::redact::fold_abs_paths(detail),
            240
        )
    );
}

/// 本族指标 → Prometheus 文本（由 `handler::health::metrics` 追加到 `/metrics`）。
///
/// 采集面 = `SealOutcome::ALL` / `UnsealOutcome::ALL`：新增结局漏登记 ⇒
/// `outcome_families_are_fully_rendered` 红 ⇒ "有计数、`/metrics` 里看不见"结构上不可能。
pub fn render_prometheus() -> String {
    let mut s = String::new();
    s.push_str("# HELP stepby_field_seal_total 敏感列写入结局计数（empty/no_master_key/already_sealed/sealed/degraded_plaintext）\n");
    s.push_str("# TYPE stepby_field_seal_total counter\n");
    for outcome in SealOutcome::ALL {
        s.push_str(&format!(
            "stepby_field_seal_total{{outcome=\"{}\"}} {}\n",
            outcome.label(),
            SEAL_COUNTS[outcome.index()].load(Ordering::Relaxed)
        ));
    }
    s.push_str("# HELP stepby_field_unseal_total 敏感列读取结局计数（empty/legacy_plaintext/decrypted/undecryptable）\n");
    s.push_str("# TYPE stepby_field_unseal_total counter\n");
    for outcome in UnsealOutcome::ALL {
        s.push_str(&format!(
            "stepby_field_unseal_total{{outcome=\"{}\"}} {}\n",
            outcome.label(),
            UNSEAL_COUNTS[outcome.index()].load(Ordering::Relaxed)
        ));
    }
    s
}

/// 读侧唯一通道：解密 + 归因计数（两个读出口都走它，避免"一处计数一处不计数"）。
fn unseal_recorded(stored: &str) -> String {
    let key = runtime_master_key();
    let out = unseal_sensitive_value(stored, key);
    record_unseal(classify_unseal(stored, &out));
    out
}

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
///
/// **为什么这里不能 `?`**：本 trait 由 sea-orm 在 `ActiveValue → Value` 内部调用，
/// 签名上没有失败通道。所以"写不进去"这件事只能折算成**可归因的结局 + 计数 + 首告**，
/// 再由 v5-E6 启动回填把降级行补成密文——而"该列确实在回填面上"由
/// `initialize::oauth_sso` 的 TARGETS↔实体加密列双向锁负责钉住（两半缺一，降级就是永久的）。
impl From<EncryptedString> for Value {
    fn from(v: EncryptedString) -> Self {
        let key = runtime_master_key();
        let sealed = seal_sensitive_value(&v.0, key);
        let outcome = classify_seal(&v.0, key, sealed.as_deref().ok());
        record_seal(outcome);
        let stored = sealed.unwrap_or_else(|e| {
            warn_once_seal(outcome, &e.to_string());
            v.0
        });
        if matches!(outcome, SealOutcome::NoMasterKey) {
            // 无密钥写入是**持续态**（每次写都命中），因此只走首告一次
            warn_once_seal(outcome, "CONFIG_ENC_KEY 未配置");
        }
        Value::String(Some(stored))
    }
}

/// 读侧：从存储 Value 自动解密（解密失败原样返回存储值，宽松读路径；结局计数见
/// [`classify_unseal`]）
impl TryGetable for EncryptedString {
    fn try_get_by<I: sea_orm::ColIdx>(
        res: &QueryResult,
        index: I,
    ) -> Result<Self, sea_orm::TryGetError> {
        let stored = String::try_get_by(res, index)?;
        Ok(Self(unseal_recorded(&stored)))
    }
}

/// 列类型声明（TEXT——密文 base64 膨胀约 4/3，TEXT 无长度限制）
///
/// sea-query 0.32 `ValueType`：`try_from` 读取解密、`column_type` 声明 TEXT；
/// NULL 语义由 sea-query 对 `Option<T>` 的 blanket 实现（`Option<EncryptedString>`）承载。
impl sea_orm::sea_query::ValueType for EncryptedString {
    fn try_from(v: Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
        match v {
            // NULL 也走同一条读通道：`unseal_recorded("")` 的返回与旧写法
            // （直接 `String::new()`）逐字相同，但"这一列是空的"于是也被记进
            // `empty` 档——两条实现记一半的结局，读侧统计就永远对不上写入量（㉘）。
            Value::String(Some(s)) => Ok(Self(unseal_recorded(&s))),
            Value::String(None) => Ok(Self(unseal_recorded(""))),
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

/// 序列化输出**掩码**（前 2 后 2，中段 `****`；**≤8 字符全掩码**）——实体 Model 直接
/// 序列化返回前端时，敏感值永不回显明文/密文（安全红线）。
///
/// 阈值从 6 收到 8 的理由（b149）：旧阈值下 7 字符的值输出 `ab****cd` 形状时明文占比
/// 4/7（57%），"掩码"退化成了"提示长度 + 给出多数原文"；短口令/短 secret 恰好落在这个
/// 区间。取 8 是"前 2 后 2 加起来不少于一半"的那个界——超过它，可见部分占比必然 <50%。
impl serde::Serialize for EncryptedString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let chars: Vec<char> = self.0.chars().collect();
        let masked = if chars.is_empty() {
            String::new()
        } else if chars.len() <= 8 {
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
    use crate::common::prod_scan::Scan;

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

    // ==================== b149 项 17：结局分档（写侧 5 档 / 读侧 4 档） ====================

    /// 分类器必须与 `seal_sensitive_value` 的**真实产出**逐支对上（㉓：夹具形状 = 产出形状，
    /// 不是按被测方的注释造夹具）。
    #[test]
    fn classify_seal_matches_real_branch_order() {
        let key = "test-master-key-0123456789abcdef";
        let cases = [
            ("", "any-key", SealOutcome::Empty),
            ("plain-secret", "", SealOutcome::NoMasterKey),
            ("enc3:k1:AAAA", "any-key", SealOutcome::AlreadySealed),
            ("plain-secret", key, SealOutcome::Sealed),
        ];
        for (input, mk, want) in cases {
            let out = crate::utils::crypto::seal_sensitive_value(input, mk)
                .expect("四条 Ok 出口都不该抛错");
            assert_eq!(
                classify_seal(input, mk, Some(&out)),
                want,
                "真实产出 {input:?}（密钥 {mk:?} → {out:?}）必须归因为 {want:?}；\
                 归错档就是把\"不用管\"和\"要配密钥\"签成同一件事"
            );
        }
        // `Err` 支无法用真实输入构造（AES-GCM 只在随机源/内存失败时抛）。按落库事实归因：
        // 降级时写进去的就是入参本身。写侧接线的可证伪性由盘上变异负责（见台账 b149 §2）。
        assert_eq!(
            classify_seal("s", "k", None),
            SealOutcome::Degraded,
            "加密失败必须落在 degraded_plaintext 档，不得混进 no_master_key（两者整改动作不同）"
        );
    }

    /// 读侧四档矩阵，其中「换密钥后解不开」必须由真实密文 + 真实错误密钥产出。
    #[test]
    fn classify_unseal_matrix() {
        let key = "test-master-key-0123456789abcdef";
        let sealed = crate::utils::crypto::encrypt_config_value("hello", key).unwrap();
        assert_eq!(classify_unseal("", ""), UnsealOutcome::Empty);
        assert_eq!(
            classify_unseal("legacy-plain", "legacy-plain"),
            UnsealOutcome::LegacyPlaintext,
            "回填前的历史明文是正常态"
        );
        let ok = crate::utils::crypto::unseal_sensitive_value(&sealed, key);
        assert_eq!(classify_unseal(&sealed, &ok), UnsealOutcome::Decrypted);
        let bad =
            crate::utils::crypto::unseal_sensitive_value(&sealed, "another-key-0123456789abcdefx");
        assert_eq!(
            classify_unseal(&sealed, &bad),
            UnsealOutcome::Undecryptable,
            "带信封却解不开（密钥轮换没登记旧 key_id / 数据坏了）必须与\"本来就是明文\"分档"
        );
        // 两型的返回值刻意相同（宽松读路径），因此**只有计数能区分**——这正是本档存在的理由
        assert_eq!(bad, sealed);
    }

    /// 采集面自证：渲染的行数必须**等于** `ALL`，且每个 label 都在册。
    /// 漏一支的表现是"有计数、`/metrics` 里看不见"，与 b89 那条"有闸、没观测"同族。
    #[test]
    fn outcome_families_are_fully_rendered() {
        let text = render_prometheus();
        for outcome in SealOutcome::ALL {
            let line = format!("stepby_field_seal_total{{outcome=\"{}\"}}", outcome.label());
            assert!(
                text.contains(&line),
                "写侧结局 {outcome:?} 没进指标面：{line}"
            );
        }
        for outcome in UnsealOutcome::ALL {
            let line = format!(
                "stepby_field_unseal_total{{outcome=\"{}\"}}",
                outcome.label()
            );
            assert!(
                text.contains(&line),
                "读侧结局 {outcome:?} 没进指标面：{line}"
            );
        }
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("stepby_field_seal_total{"))
                .count(),
            SealOutcome::ALL.len(),
            "写侧行数必须等于采集面（多行=重复登记，少行=漏档）"
        );
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("stepby_field_unseal_total{"))
                .count(),
            UnsealOutcome::ALL.len(),
            "读侧行数必须等于采集面"
        );
    }

    /// 计数必须是**进程级单例**：`const` 数组在每个使用点各生成一份新值，
    /// `fetch_add` 落在临时副本上、渲染时读到的又是另一份全零副本 ⇒ 指标恒 0。
    ///
    /// 这一条刻意**不**用"取数前后总量差"来判：总量全局单调，别的用例在并行窗口里也会
    /// 推进它，于是"摘掉一处调用"照样可能绿（绿红由并行度决定，AGENTS ㉒）。改成对
    /// **同一档**连记两次并断言严格前进——原子性保证并发只会让它更大，而 `const` 让它
    /// 恒为 1，两种结局互斥且都确定。
    #[test]
    fn counters_are_shared_across_calls() {
        let a = record_seal(SealOutcome::Empty);
        let b = record_seal(SealOutcome::Empty);
        assert!(
            b > a,
            "seal 同一档连记两次必须前进（实得 {a} → {b}）：还是 {n} 说明计数数组被写成了 \
             `const`，每个使用点各得一份副本",
            n = b
        );
        let c = record_unseal(UnsealOutcome::Empty);
        let d = record_unseal(UnsealOutcome::Empty);
        assert!(d > c, "unseal 同一档连记两次必须前进（实得 {c} → {d}）");
        // 记了档还必须进得了渲染（记了但没人渲染 = 没记）
        assert!(
            render_prometheus().contains("stepby_field_seal_total{outcome=\"empty\"}"),
            "记了档却渲染不出这一行 ⇒ 指标面与计数面脱节"
        );
    }

    /// 摘掉计数/归因就等于回到"只有一行日志"——这条腿只看 `Into<Value>` 的**函数体**
    /// （全文匹配会被本模块其它文本洗绿，㊴②）。
    #[test]
    fn write_channel_body_is_wired_through_the_outcome_type() {
        let text =
            crate::common::prod_scan::prod_file("src/common/encrypted_value.rs", &Scan::default())
                .text();
        let body = impl_block(&text, "impl From<EncryptedString> for Value");
        for needle in ["classify_seal(", "record_seal(", "warn_once_seal("] {
            assert!(
                body.contains(needle),
                "写通道函数体缺少 {needle}：降级/无密钥又退回到\"只有 error! 一行\"，\
                 运维面就无法区分三种整改动作"
            );
        }
        // 降级分支不得再被写成"静默原样返回"
        assert!(
            !body.contains("unwrap_or_default()"),
            "写通道不得把 seal 失败折成默认值"
        );
        // **降级那一条出口自己**必须留痕。取的是**那一个括号内部**的参数，不是" marker
        // 之后的全部余文"：余文里还有无密钥那一支的合法 `warn_once_seal(`（同一函数两处
        // 调用），按"出现过一次"判 ⇒ 摘掉降级首告照样绿（b134「存在一次 ≠ 每个入口都有」）。
        let degraded_leg = paren_arg(&body, "sealed.unwrap_or_else(");
        assert!(
            degraded_leg.contains("warn_once_seal("),
            "seal 失败这一支必须首告（摘掉它 ⇒ 明文永久落库这件事无人知道）"
        );
    }

    /// 读侧的**两条**臂都必须走同一条通道（NULL 那一支是本批立案的原点）。
    ///
    /// 为什么必须是静态形状锁而不是运行时断言：计数是进程级共享的，"这条用例让某个计数
    /// 前进了"在并行跑批里并不能归因到具体哪一臂（b144 那条"并发用例的日志只能按块归因"
    /// 在指标面上的同形）。NULL 臂被摘掉时最坏的症状是"读侧统计永远对不上写入量"，
    /// 而运行时那条用例照样可能绿——所以判据读的是**函数体**，不是计数。
    #[test]
    fn read_channel_arms_all_route_through_the_outcome_type() {
        let text =
            crate::common::prod_scan::prod_file("src/common/encrypted_value.rs", &Scan::default())
                .text();
        let body = function_body(&text, "fn try_from(v: Value)");
        // 逐臂判**排在条数判之前**：NULL 臂被摘掉时，"哪一臂没了"比"少了一处调用"能行动。
        // 顺序反了的话第一条红是集合计数，人得先自己回查是哪一支（AGENTS ⑨"错误提示把人
        // 支使去把事实签反"在归因粒度上的同形）。
        for arm in ["Value::String(Some(s))", "Value::String(None)"] {
            let seg = body
                .split(arm)
                .nth(1)
                .unwrap_or_else(|| panic!("try_from 必须保留 `{arm}` 这一臂：{body}"));
            let arm_body = seg.split("Value::String(").next().unwrap_or(seg);
            assert!(
                arm_body.contains("unseal_recorded("),
                "`{arm}` 这一臂没走读通道 ⇒ 该种存储形态从此不产生任何结局"
            );
        }
        assert_eq!(
            body.matches("unseal_recorded(").count(),
            2,
            "两条臂（有值 / NULL）都必须走同一条读通道，实测 {n} 处\
             （只有一支 ⇒ NULL 被折成\"空串\"而记不进 `empty` 档）",
            n = body.matches("unseal_recorded(").count()
        );
        for bypass in ["String::new()", "unwrap_or_default()", "unwrap_or("] {
            assert!(
                !body.contains(bypass),
                "读通道不得用 {bypass} 把某一种存储形态折成\"正常的空值\""
            );
        }
    }

    /// 挂载腿：指标族必须真的出现在 `/metrics` 聚合里（写了没人调 = 没写，AGENTS ㉗）。
    #[test]
    fn metrics_endpoint_mounts_the_family() {
        let text =
            crate::common::prod_scan::prod_file("src/handler/health.rs", &Scan::default()).text();
        let body = function_body(&text, "pub async fn metrics(");
        assert!(
            body.contains("encrypted_value::render_prometheus()"),
            "`/metrics` 里没有本族指标 ⇒ \"有计数、没人能看见\"，与 b89 那条\"有闸、没观测\"同族"
        );
    }

    /// 掩码阈值：短值必须**全**掩码（旧阈值 6 让 7 字符值回显 4/7）。
    ///
    /// 这一条本身就是承重腿：把阈值改回 6，`len = 7` 与 `len = 8` 两支立刻红——
    /// 不需要再复制一份"旧逻辑"来对照（复制实现会被另一侧改动洗绿，㉘）。
    #[test]
    fn mask_hides_short_secrets_entirely() {
        for len in 1usize..=8 {
            let raw: String = "a".repeat(len);
            let json = serde_json::to_string(&EncryptedString::plaintext(&raw)).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", "*".repeat(len)),
                "{len} 字符的值必须全掩码——可见占比过高的\"掩码\"只是长度提示"
            );
        }
        // 空值仍是空串（不得变成 `"`*0`"` 之外的形状）
        assert_eq!(
            serde_json::to_string(&EncryptedString::plaintext("")).unwrap(),
            "\"\""
        );
    }

    /// 不变式：**任何**长度下可见字符数都不得过半（9 字符 4/9、多字节按字符计、不 panic）。
    #[test]
    fn mask_never_shows_a_majority() {
        for len in 1usize..=40 {
            let raw: String = "abcdefghij".repeat(len).chars().take(len).collect();
            let json = serde_json::to_string(&EncryptedString::plaintext(&raw)).unwrap();
            let masked = json.trim_matches('"');
            let visible = masked.chars().filter(|c| *c != '*').count();
            assert!(
                visible * 2 <= raw.chars().count(),
                "{len} 字符值掩码后可见 {visible} 个 ⇒ 占原文过半（原文 {raw:?} → 掩码 {masked:?}）"
            );
        }
        // 多字节按**字符**计：旧实现按 `chars` 已是对的，这条钉住它不退化成字节索引
        let json =
            serde_json::to_string(&EncryptedString::plaintext("密钥密钥密钥密钥密")).unwrap();
        assert_eq!(json, "\"密钥****钥密\"");
    }

    /// 取 `marker` 之后那个花括号配平的块（判据只能读被真正执行的那一段）。
    fn impl_block(text: &str, marker: &str) -> String {
        block_from(
            text,
            text.find(marker)
                .unwrap_or_else(|| panic!("找不到 {marker}")),
        )
    }

    /// 取某个函数的函数体（按 `fn 名字` 定位后取配平块）。
    fn function_body(text: &str, signature: &str) -> String {
        block_from(
            text,
            text.find(signature)
                .unwrap_or_else(|| panic!("找不到 {signature}")),
        )
    }

    /// 取 `marker`（必须以 `(` 结尾）**那个括号内部**的参数。
    ///
    /// 与 `impl_block`/`function_body` 同一取向：判据只能读被真正执行的那一段，
    /// 不得读"marker 之后的全部余文"——余文会把相邻分支的合法调用一起算进来。
    fn paren_arg(text: &str, marker: &str) -> String {
        let at = text.find(marker).unwrap_or_else(|| {
            panic!("找不到 `{marker}` ⇒ 写通道的 seal 失败处理形状变了，本锁的输入已坏")
        });
        let open = at + marker.len() - 1;
        let bytes = text.as_bytes();
        let mut depth = 0usize;
        for i in open..bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return text[open + 1..i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("括号不配平（判据的输入形状坏了，不得当成\"没违规\"）")
    }

    fn block_from(text: &str, from: usize) -> String {
        let start = text[from..]
            .find('{')
            .unwrap_or_else(|| panic!("{from} 之后没有花括号"));
        let start = from + start;
        let mut depth = 0usize;
        for (i, ch) in text[start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return text[start..start + i + 1].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("花括号不配平（判据的输入形状坏了，不得当成\"没违规\"）")
    }
}
