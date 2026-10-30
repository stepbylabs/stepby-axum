// stepby-axum/src/common/i18n.rs
//! 国际化（i18n）基础设施
//!
//! 分层设计：
//! - garde 校验消息：通过 [`garde::i18n::I18n`] trait 实现（[`ZhCn`]），
//!   由 [`validate`] 统一入口按当前 locale 经 `with_i18n` 执行校验
//! - 业务/通用文案：rust-i18n（t! 宏），经 `t!` 宏按当前 locale 翻译
//! - 模块标题等少量"动态 key"：[`MODULE_TITLES`] 表 + [`module_title`]（本地查表，无 YAML）
//!
//! locale 传递：locale_middleware 读取 `Accept-Language` → 协商 → 经
//! [`LOCALE`]（task-local）作用域注入，[`current_locale`] 在任意位置读取；
//! `tokio::spawn` 逃逸 task-local 后回退默认值（zh-CN），故 spawn 内需显式传 locale。

use std::borrow::Cow;
use std::cell::RefCell;
use std::fmt::Display;

use garde::Report;
use garde::i18n::{I18n, InvalidCreditCard, InvalidEmail, InvalidPhoneNumber, InvalidUrl, IpKind};

tokio::task_local! {
    /// 当前请求的语言（locale_middleware 按作用域注入）
    pub static LOCALE: String;
}

// 阻塞线程同步 locale 回退（用于 spawn_blocking 内的 Excel 生成等场景）
//
// task-local 不跨 spawn_blocking 传播，故在此类同步上下文中通过 thread-local
// 注入 locale，使 [`current_locale`] 能正确返回请求 locale。
thread_local! {
    static SYNC_LOCALE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// 默认语言（无 locale 头 / 未注入时回退）
pub const DEFAULT_LOCALE: &str = "zh-CN";
/// 支持的语言
pub const SUPPORTED_LOCALES: &[&str] = &["zh-CN", "en-US"];

/// 当前 locale（任务级；task-local 外回退 SYNC_LOCALE thread-local，再回退 DEFAULT_LOCALE）
///
/// 返回 `&'static str`：仅支持两种语言，按 task-local / thread-local 值匹配到 'static 字面量，
/// 使 `rust_i18n::t!(... locale=)` 的 `&str` 参数无临时值借用问题。
///
/// 查找顺序：
/// 1. `LOCALE` task-local（locale_middleware 异步作用域注入）
/// 2. `SYNC_LOCALE` thread-local（[`with_locale_sync`] 同步作用域注入，用于 spawn_blocking）
/// 3. `DEFAULT_LOCALE`（zh-CN）
pub fn current_locale() -> &'static str {
    // 1. task-local（异步上下文）
    if let Ok(loc) = LOCALE.try_with(|l| l.as_str().to_string()) {
        return match loc.as_str() {
            "en-US" => "en-US",
            _ => "zh-CN",
        };
    }
    // 2. thread-local（spawn_blocking 同步上下文）
    SYNC_LOCALE.with(|tl| {
        let borrow = tl.borrow();
        match borrow.as_deref() {
            Some("en-US") => "en-US",
            Some("zh-CN") => "zh-CN",
            _ => "zh-CN", // None 或其他值 → 默认
        }
    })
}

/// 同步作用域注入 locale（用于 spawn_blocking 等无法使用 task-local 的场景）
///
/// 在闭包执行期间设置 thread-local locale，执行完毕后清除，避免线程复用污染。
///
/// # 示例
/// ```ignore
/// let locale = "en-US".to_string();
/// tokio::task::spawn_blocking(move || {
///     i18n::with_locale_sync(&locale, || {
///         // 此处 current_locale() 返回 "en-US"
///         build_xlsx_inner(...)
///     })
/// });
/// ```
pub fn with_locale_sync<R>(locale: &str, f: impl FnOnce() -> R) -> R {
    // 设置 thread-local
    SYNC_LOCALE.with(|tl| {
        *tl.borrow_mut() = Some(locale.to_string());
    });
    // 执行闭包（panic 安全性由调用方保证，spawn_blocking 会捕获 panic）
    let result = f();
    // 清除 thread-local（即使 f() panic 也会在 drop 时清除，但 RefCell 不支持 Drop guard；
    // 此处采用 try 用法，spawn_blocking 的 panic 会传播到 await 点，闭包内 panic 时
    // thread-local 残留，但下次 with_locale_sync 调用会覆盖，且线程池复用不会跨请求泄漏）
    SYNC_LOCALE.with(|tl| {
        *tl.borrow_mut() = None;
    });
    result
}

/// 是否为中文（默认语言）
pub fn is_zh() -> bool {
    current_locale().starts_with("zh")
}

/// 简易双语选择：按当前 locale 返回中文或英文文案
///
/// 用于自定义校验函数等不便走 garde I18n / rust-i18n 的 colocated 场景。
pub fn pick<'a>(zh: &'a str, en: &'a str) -> &'a str {
    if is_zh() { zh } else { en }
}

/// 业务文案翻译：rust-i18n 按**当前 locale** 查找固定 key（T-07）
///
/// 用法：`tr!("error.common.not_found")` —— 返回 String。
/// key 必须是字符串字面量（rust-i18n t! 宏要求，便于编译期提取/嵌入）。
/// locale 取当前请求 locale（task-local，无则回退 zh-CN）。
///
/// L-3：扩展支持插值参数 `tr!("msg.hello", name = "Alice")`，
/// 转发给 `rust_i18n::t!` 的 named args 语法，对应 YAML 中 **`%{name}`** 占位符。
///
/// ⚠️ 写成裸 `{name}` **不报错也不警告**——rust_i18n 只替换 `%{name}`，于是用户原样看到
/// `分片 {index} 缺失`。批七十五实测 4 条分片上传文案正是这个形态（`chunk_part_missing` /
/// `chunk_parts_missing` / `chunk_part_too_large` / `chunk_total_too_large`），判据由
/// `tests::i18n_placeholders_match_tr_call_args` 常驻钉住。
#[macro_export]
macro_rules! tr {
    ($key:literal) => {
        rust_i18n::t!($key, locale = $crate::common::i18n::current_locale()).to_string()
    };
    ($key:literal, $($k:ident = $v:expr),+ $(,)?) => {
        rust_i18n::t!($key, locale = $crate::common::i18n::current_locale(), $($k = $v),+).to_string()
    };
}

/// 统一校验入口：按当前 locale 执行 garde 校验
///
/// 所有 `dto.validate()` 调用点统一替换为本函数，
/// 使校验错误消息随请求 locale 变化（zh-CN → 中文，其他 → garde 默认英文）。
///
/// 注意：`with_i18n` 使用 thread-local，闭包内**禁止 await**（校验本身为同步纯函数，安全）。
pub fn validate<T>(dto: &T) -> Result<(), Report>
where
    T: garde::Validate<Context = ()>,
{
    if is_zh() {
        garde::i18n::with_i18n(ZhCn, || dto.validate())
    } else {
        // en-US 及其他：garde DefaultI18n 即英文，无需包装
        dto.validate()
    }
}

/// 操作日志模块标题表：(key, zh, en)
///
/// 与 `middleware::oper_log::infer_module_title` 一一对应；
/// 供 oper_log.title 列展示/导出翻译（T-11）与按标题搜索匹配 key（T-11）。
pub const MODULE_TITLES: &[(&str, &str, &str)] = &[
    ("module.user", "用户管理", "User Management"),
    ("module.profile", "个人中心", "Profile Center"),
    ("module.role", "角色管理", "Role Management"),
    ("module.menu", "菜单管理", "Menu Management"),
    ("module.dict", "字典管理", "Dict Management"),
    ("module.dept", "部门管理", "Dept Management"),
    ("module.post", "岗位管理", "Post Management"),
    ("module.config", "参数设置", "Parameter Settings"),
    ("module.notice", "公告管理", "Announcements"),
    ("module.job", "定时任务", "Scheduled Tasks"),
    ("module.operlog", "操作日志", "Operation Log"),
    ("module.logininfor", "登录日志", "Login Log"),
    ("module.online", "在线用户", "Online Users"),
    ("module.gen", "代码生成", "Code Generation"),
    ("module.common", "通用接口", "Common APIs"),
    ("module.auth", "认证管理", "Authentication"),
    ("module.backup", "数据备份", "Data Backup"),
    ("module.auditChange", "变更留痕", "Audit Trail"),
    ("module.ai", "AI 助手", "AI Copilot"),
    ("module.task", "任务管理", "Task Management"),
    ("module.rateLimit", "限流配置", "Rate Limit"),
    ("module.cache", "缓存监控", "Cache Monitor"),
    ("module.server", "服务器监控", "Server Monitor"),
    ("module.auditDashboard", "审计仪表盘", "Audit Dashboard"),
    ("module.webHook", "WebHook 订阅", "WebHook Subscription"),
    ("module.flow", "审批中心", "Approval Center"),
    (
        "module.oauthClient",
        "SSO 客户端管理",
        "SSO Client Management",
    ),
    ("module.ssoConsent", "SSO 授权同意", "SSO Consent"),
    ("module.other", "其他", "Other"),
];

/// 按 key 翻译模块标题；查无回退 key 原文（兼容旧中文数据）
///
/// L-6 说明：fallback 分支返回 `Cow::Owned(key.to_string())`，生命周期上看似与
/// 函数签名 `Cow<'static, str>` 冲突（Owned 持有新分配的 String），但实际上
/// `Cow::Owned` 的变体本身允许持有任意生命周期的数据，`'static` 约束的是
/// `Cow::Borrowed` 分支所借用的 `'static` 字面量。两条分支类型统一为
/// `Cow<'static, str>`，调用方拿到的 Cow 可向下传递或转 `String`，逻辑正确。
pub fn module_title(key: &str) -> Cow<'static, str> {
    MODULE_TITLES
        .iter()
        .find(|(k, _, _)| *k == key)
        .map(|(_, zh, en)| {
            let s = pick(zh, en);
            Cow::Borrowed(s)
        })
        .unwrap_or_else(|| Cow::Owned(key.to_string()))
}

/// 搜索辅助：返回显示名包含 text 的模块 key（中英文均匹配，英文大小写不敏感）
///
/// 用于 oper_log 按标题搜索时同时匹配旧中文数据与新 key 数据（T-11）。
pub fn module_keys_matching(text: &str) -> Vec<&'static str> {
    let lower = text.to_lowercase();
    MODULE_TITLES
        .iter()
        .filter(|(_, zh, en)| zh.contains(text) || en.to_lowercase().contains(&lower))
        .map(|(k, _, _)| *k)
        .collect()
}

/// garde 中文校验消息
///
/// 实现 `garde::i18n::I18n` trait，覆盖项目实际使用的规则；
/// 未覆盖的规则回落 trait 默认实现（英文），随需要逐步补全。
pub struct ZhCn;

impl I18n for ZhCn {
    fn length_lower_than(&self, min: usize) -> Cow<'static, str> {
        format!("长度不能少于 {min}").into()
    }

    fn length_greater_than(&self, max: usize) -> Cow<'static, str> {
        format!("长度不能超过 {max}").into()
    }

    fn range_lower_than(&self, min: &dyn Display) -> Cow<'static, str> {
        format!("数值不能小于 {min}").into()
    }

    fn range_greater_than(&self, max: &dyn Display) -> Cow<'static, str> {
        format!("数值不能大于 {max}").into()
    }

    fn email_invalid(&self, reason: InvalidEmail) -> Cow<'static, str> {
        let detail = match reason {
            InvalidEmail::Empty => "邮箱不能为空",
            InvalidEmail::MissingAt => "邮箱缺少 @ 符号",
            InvalidEmail::UserLengthExceeded => "邮箱用户名部分过长",
            InvalidEmail::InvalidUser => "邮箱用户名含非法字符",
            InvalidEmail::DomainLengthExceeded => "邮箱域名过长",
            InvalidEmail::InvalidDomain => "邮箱域名含非法字符",
            _ => "邮箱格式不正确",
        };
        detail.into()
    }

    fn url_invalid(&self, reason: InvalidUrl) -> Cow<'static, str> {
        let detail = match reason {
            InvalidUrl::EmptyHost => "URL 缺少主机名",
            InvalidUrl::InvalidPort => "URL 端口号无效",
            InvalidUrl::RelativeUrlWithoutBase => "相对 URL 缺少基础地址",
            _ => "URL 格式不正确",
        };
        detail.into()
    }

    fn pattern_no_match(&self, _pattern: &dyn Display) -> Cow<'static, str> {
        "格式不正确".into()
    }

    fn contains_missing(&self, pattern: &dyn Display) -> Cow<'static, str> {
        format!("必须包含 {pattern}").into()
    }

    fn prefix_missing(&self, pattern: &dyn Display) -> Cow<'static, str> {
        format!("必须以 {pattern} 开头").into()
    }

    fn suffix_missing(&self, pattern: &dyn Display) -> Cow<'static, str> {
        format!("必须以 {pattern} 结尾").into()
    }

    fn required_not_set(&self) -> Cow<'static, str> {
        "不能为空".into()
    }

    fn ascii_invalid(&self) -> Cow<'static, str> {
        "仅允许 ASCII 字符".into()
    }

    fn alphanumeric_invalid(&self) -> Cow<'static, str> {
        "仅允许字母和数字".into()
    }

    fn matches_field_mismatch(&self, field: &dyn Display) -> Cow<'static, str> {
        format!("与字段 {field} 不一致").into()
    }

    fn ip_invalid(&self, kind: IpKind) -> Cow<'static, str> {
        let detail = match kind {
            IpKind::V4 => "IPv4 地址格式不正确",
            IpKind::V6 => "IPv6 地址格式不正确",
            _ => "IP 地址格式不正确",
        };
        detail.into()
    }

    fn phone_number_invalid(&self, _reason: InvalidPhoneNumber) -> Cow<'static, str> {
        "手机号格式不正确".into()
    }

    fn credit_card_invalid(&self, _reason: InvalidCreditCard) -> Cow<'static, str> {
        "银行卡号格式不正确".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(garde::Validate)]
    struct DemoDto {
        #[garde(length(min = 2, max = 5))]
        name: String,
        #[garde(range(min = 1, max = 100))]
        age: i32,
    }

    #[test]
    fn test_validate_zh_messages() {
        let dto = DemoDto {
            name: "a".to_string(),
            age: 200,
        };
        let report = validate(&dto).unwrap_err();
        let msgs: Vec<String> = report.iter().map(|(p, e)| format!("{p}: {e}")).collect();
        let joined = msgs.join("; ");
        assert!(
            joined.contains("长度不能少于 2"),
            "应包含长度下限中文消息: {joined}"
        );
        assert!(
            joined.contains("数值不能大于 100"),
            "应包含范围上限中文消息: {joined}"
        );
        assert!(joined.contains("name"), "应包含字段路径: {joined}");
    }

    #[test]
    fn test_validate_ok() {
        let dto = DemoDto {
            name: "abcd".to_string(),
            age: 50,
        };
        assert!(validate(&dto).is_ok());
    }

    #[test]
    fn test_module_title_lookup() {
        assert_eq!(module_title("module.user"), "用户管理");
        assert_eq!(module_title("module.other"), "其他");
        // G5 WebHook 模块操作日志标题
        assert_eq!(module_title("module.webHook"), "WebHook 订阅");
    }

    #[test]
    fn test_module_title_fallback_raw() {
        // 旧中文数据：key 查无 → 原样返回
        assert_eq!(module_title("用户管理"), "用户管理");
    }

    #[test]
    fn test_module_keys_matching_zh() {
        // "用户" 命中"用户管理"(user) 与"在线用户"(online)
        let keys = module_keys_matching("用户");
        assert!(keys.contains(&"module.user"), "应匹配用户管理: {keys:?}");
        assert!(keys.contains(&"module.online"), "应匹配在线用户: {keys:?}");
    }

    #[test]
    fn test_module_keys_matching_en() {
        // "user" 命中 "User Management"(user) 与 "Online Users"(online，子串)
        let keys = module_keys_matching("USER");
        assert!(keys.contains(&"module.user"), "应匹配 user: {keys:?}");
        assert!(
            keys.contains(&"module.online"),
            "应匹配 online users: {keys:?}"
        );
    }

    #[test]
    fn test_locale_default() {
        // 无 task-local 时回退 zh-CN
        assert_eq!(current_locale(), "zh-CN");
        assert!(is_zh());
    }

    // ---------- 以下为补充覆盖：task-local / sync 注入 / tr! / ZhCn 文案 ----------

    #[tokio::test]
    async fn current_locale_uses_task_local() {
        // task-local 注入 en-US → 作用域内 current_locale 返回 en-US 且非中文
        let got = LOCALE
            .scope("en-US".to_string(), async {
                assert!(!is_zh(), "作用域内应已切换为英文");
                current_locale()
            })
            .await;
        assert_eq!(got, "en-US");
    }

    #[tokio::test]
    async fn current_locale_falls_back_for_unknown_task_local() {
        // task-local 注入未知语言（fr-FR）→ 回退 zh-CN
        let got = LOCALE
            .scope("fr-FR".to_string(), async { current_locale() })
            .await;
        assert_eq!(got, "zh-CN");
    }

    #[test]
    fn with_locale_sync_sets_and_clears() {
        // 默认 zh-CN
        assert_eq!(current_locale(), "zh-CN");
        // 注入 en-US 生效
        let r = with_locale_sync("en-US", || {
            assert_eq!(current_locale(), "en-US");
            assert!(!is_zh());
            assert_eq!(pick("中文", "English"), "English");
            "done"
        });
        assert_eq!(r, "done");
        // 闭包结束后 thread-local 被清除，回退默认
        assert_eq!(current_locale(), "zh-CN");
        assert!(is_zh());
        assert_eq!(pick("中文", "English"), "中文");
    }

    #[test]
    fn tr_macro_translates_with_interpolation() {
        // 无插值：取到非空翻译
        let msg = crate::tr!("error.common.not_found");
        assert!(!msg.is_empty());
        // 插值：{{max}} 被替换
        let too_large = crate::tr!("error.file.too_large", max = 10);
        assert!(too_large.contains("10"), "实际: {too_large}");
        assert!(too_large.contains("MB"), "实际: {too_large}");
    }

    #[test]
    fn module_titles_keys_are_unique_and_nonempty() {
        let mut seen = std::collections::HashSet::new();
        for (k, zh, en) in MODULE_TITLES {
            assert!(!k.is_empty());
            assert!(!zh.is_empty());
            assert!(!en.is_empty());
            assert!(seen.insert(*k), "模块 key 重复: {k}");
        }
    }

    #[test]
    fn zhcn_i18n_messages() {
        use garde::i18n::{InvalidEmail, InvalidUrl, IpKind};
        let zh = ZhCn;
        assert_eq!(zh.length_lower_than(2), "长度不能少于 2");
        assert_eq!(zh.length_greater_than(5), "长度不能超过 5");
        assert_eq!(zh.range_lower_than(&1), "数值不能小于 1");
        assert_eq!(zh.range_greater_than(&100), "数值不能大于 100");
        assert_eq!(zh.email_invalid(InvalidEmail::Empty), "邮箱不能为空");
        assert_eq!(zh.email_invalid(InvalidEmail::MissingAt), "邮箱缺少 @ 符号");
        assert_eq!(
            zh.email_invalid(InvalidEmail::UserLengthExceeded),
            "邮箱用户名部分过长"
        );
        assert_eq!(
            zh.email_invalid(InvalidEmail::InvalidUser),
            "邮箱用户名含非法字符"
        );
        assert_eq!(
            zh.email_invalid(InvalidEmail::DomainLengthExceeded),
            "邮箱域名过长"
        );
        assert_eq!(
            zh.email_invalid(InvalidEmail::InvalidDomain),
            "邮箱域名含非法字符"
        );
        assert_eq!(zh.url_invalid(InvalidUrl::EmptyHost), "URL 缺少主机名");
        assert_eq!(zh.url_invalid(InvalidUrl::InvalidPort), "URL 端口号无效");
        assert_eq!(
            zh.url_invalid(InvalidUrl::RelativeUrlWithoutBase),
            "相对 URL 缺少基础地址"
        );
        assert_eq!(zh.pattern_no_match(&"x"), "格式不正确");
        assert_eq!(zh.contains_missing(&"A"), "必须包含 A");
        assert_eq!(zh.prefix_missing(&"A"), "必须以 A 开头");
        assert_eq!(zh.suffix_missing(&"A"), "必须以 A 结尾");
        assert_eq!(zh.required_not_set(), "不能为空");
        assert_eq!(zh.ascii_invalid(), "仅允许 ASCII 字符");
        assert_eq!(zh.alphanumeric_invalid(), "仅允许字母和数字");
        assert_eq!(zh.matches_field_mismatch(&"pwd"), "与字段 pwd 不一致");
        assert_eq!(zh.ip_invalid(IpKind::V4), "IPv4 地址格式不正确");
        assert_eq!(zh.ip_invalid(IpKind::V6), "IPv6 地址格式不正确");
        assert_eq!(
            zh.phone_number_invalid(garde::i18n::InvalidPhoneNumber::Invalid),
            "手机号格式不正确"
        );
        assert_eq!(
            zh.credit_card_invalid(garde::i18n::InvalidCreditCard::InvalidFormat),
            "银行卡号格式不正确"
        );
    }

    #[test]
    fn validate_en_locale_uses_english_messages() {
        // en-US 注入下 validate 走默认英文文案（非中文）
        let dto = DemoDto {
            name: "a".to_string(),
            age: 200,
        };
        let err = with_locale_sync("en-US", || validate(&dto)).unwrap_err();
        let joined: Vec<String> = err.iter().map(|(p, e)| format!("{p}: {e}")).collect();
        let joined = joined.join("; ");
        assert!(!joined.contains("长度不能少于"), "不应含中文: {joined}");
        assert!(joined.contains("lower than"), "应含英文长度消息: {joined}");
    }

    // ==================== 批七十四 B2：i18n 键必须真的解析得出来 ====================
    //
    // 缺陷形状（本批实测抓到 8 条，`error.dataRule.*` 全部）：新键被追加到 yml **文件末尾**，
    // 而末尾那一段的顶层节是 `alert:` ⇒ 实际路径是 `alert.dataRule.*`。rust_i18n 查不到时
    // **把键名原样返回**（实测 `t!("error.dataRule.value_too_long")` 返回
    // `"error.dataRule.value_too_long"`），于是：
    // - 接口照常 400，消息体是键名 ⇒ 用户看到 `error.dataRule.name_invalid`；
    // - `assert_eq!(err.message, crate::tr!("同一条键"))` 形状的既有单测**两边同时是键名**，恒真；
    // - e2e 只看 `code` 时同样看不见。
    // ⇒ 唯一不虚的判据是直接对账 yml 本体：键路径必须在**每一份** locale 里作为叶子存在。
    //
    // 第二把锁是双语对称性：`fallback = "zh-CN"` 下 en 缺键 ⇒ 英文用户静默收中文，
    // zh 缺键 ⇒ 中文用户收英文。两侧都"看起来正常"，只有集合相等判据能看见。

    /// 缩进式 yml → 叶子键路径集合。
    ///
    /// 只支持本仓 `locales/*.yml` 的规则形态（`indent + key:` 后跟标量或更深一层）；
    /// 注释行、空行、列表项不参与。**刻意不引 serde_yaml**：判据要能独立成立，
    /// 不能依赖运行时加载器——那正是本锁要检验的对象。
    fn yml_leaf_paths(text: &str) -> std::collections::BTreeSet<String> {
        yml_leaf_texts(text).into_keys().collect()
    }

    /// 与 [`yml_leaf_paths`] **同一个**缩进栈解析器，只是把叶子**文本**也带出来。
    ///
    /// 分成两份实现就会漂移：占位符对账需要值，键集对账需要路径——两份解析器一旦
    /// 对"`|` 块算不算叶子"这类边界判断不一致，两把锁看到的语言包就不是同一份文件。
    fn yml_leaf_texts(text: &str) -> std::collections::BTreeMap<String, String> {
        let mut leaves = std::collections::BTreeMap::new();
        // (缩进, 键名) 栈：遇到不深于当前的键就回退到它的兄弟层
        let mut stack: Vec<(usize, String)> = Vec::new();
        for raw in text.lines() {
            let s = raw.trim();
            if s.is_empty() || s.starts_with('#') || s.starts_with("- ") {
                continue;
            }
            let indent = raw.len() - raw.trim_start().len();
            let Some(colon) = s.find(':') else { continue };
            let key = s[..colon].trim();
            if key.is_empty()
                || key.contains(' ')
                || !key
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
            {
                continue;
            }
            let value = s[colon + 1..].trim();
            while stack.last().is_some_and(|(i, _)| *i >= indent) {
                stack.pop();
            }
            let mut path: Vec<String> = stack.iter().map(|(_, k)| k.clone()).collect();
            path.push(key.to_string());
            // 有值 = 叶子；`|` / `>` 多行块本仓未使用，出现即按叶子处理（保守：宁可多纳入）
            if !value.is_empty() && value != "|" && value != ">" {
                leaves.insert(path.join("."), value.to_string());
            }
            stack.push((indent, key.to_string()));
        }
        leaves
    }

    /// 抽取一个叶子文本里的占位符名。
    ///
    /// 返回 `(百分号形态集合, 裸花括号形态集合)`：后者**恒应为空**（rust_i18n 不认 `{x}`，
    /// 会把字面量显示给用户），单独返回是为了让判据能给出可定位的失败信息。
    fn placeholders(text: &str) -> (std::collections::BTreeSet<String>, Vec<String>) {
        let mut pct = std::collections::BTreeSet::new();
        let mut bare = Vec::new();
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0usize;
        while i < chars.len() {
            if chars[i] == '{' {
                let mut j = i + 1;
                let mut buf = String::new();
                while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                    buf.push(chars[j]);
                    j += 1;
                }
                if j < chars.len() && chars[j] == '}' && !buf.is_empty() {
                    let preceded_by_pct = i > 0 && chars[i - 1] == '%';
                    if preceded_by_pct {
                        pct.insert(buf);
                    } else {
                        bare.push(buf);
                    }
                    i = j + 1;
                    continue;
                }
            }
            i += 1;
        }
        (pct, bare)
    }

    /// 全仓 `tr!("key", a = …, b = …)` 调用点：`(文件, 行号, 键, 实参名列表)`。
    ///
    /// 括号深度计数找配对右括号（实参表达式里可能有嵌套括号与字符串内的逗号），再按
    /// **顶层逗号**切分（[`split_top_level_commas`]）——不能按行切，`tr!` 常跨行书写。
    fn tr_call_sites(files: &[(String, String)]) -> Vec<(String, usize, String, Vec<String>)> {
        let mut out = Vec::new();
        for (rel, text) in files {
            let chars: Vec<char> = text.chars().collect();
            let needle: Vec<char> = "tr!(".chars().collect();
            let mut i = 0usize;
            while i + needle.len() <= chars.len() {
                if chars[i..i + needle.len()] != needle[..] {
                    i += 1;
                    continue;
                }
                // 词边界：`include_str!(` / `concat!(` 之类宏名以 `tr!(` 结尾，
                // 不掐边界会把它们的字面量参数当成 i18n 键（首轮实测正是如此，
                // 报出 `tr!("../../templates/entity.tera")` 这种假违规）。
                if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
                    i += 1;
                    continue;
                }
                let start = i + needle.len();
                let mut depth = 1usize;
                let mut j = start;
                while j < chars.len() && depth > 0 {
                    match chars[j] {
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' => depth -= 1,
                        _ => {}
                    }
                    if depth == 0 {
                        break;
                    }
                    j += 1;
                }
                if depth != 0 {
                    i += 1;
                    continue;
                }
                let args_text: String = chars[start..j].iter().collect();
                let parts = split_top_level_commas(&args_text);
                if let Some(first) = parts.first() {
                    let key = strip_string_literal(first);
                    if !key.is_empty() {
                        let arg_names = parts[1..]
                            .iter()
                            .filter_map(|p| {
                                let name = p.split('=').next()?.trim();
                                if name.is_empty()
                                    || !name.chars().all(|c| c.is_alphanumeric() || c == '_')
                                {
                                    None
                                } else {
                                    Some(name.to_string())
                                }
                            })
                            .collect();
                        let line = chars[..i].iter().filter(|c| **c == '\n').count() + 1;
                        out.push((rel.clone(), line, key, arg_names));
                    }
                }
                i = j;
            }
        }
        out
    }

    /// 按顶层逗号切分（忽略嵌套 `()`/`[]`/`{}` 与字符串字面量内的逗号）
    fn split_top_level_commas(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut depth = 0i32;
        let mut in_str = false;
        let mut prev_backslash = false;
        for c in s.chars() {
            if in_str {
                cur.push(c);
                if c == '"' && !prev_backslash {
                    in_str = false;
                }
                prev_backslash = c == '\\' && !prev_backslash;
                continue;
            }
            match c {
                '"' => {
                    in_str = true;
                    prev_backslash = false;
                    cur.push(c);
                }
                '(' | '[' | '{' => {
                    depth += 1;
                    cur.push(c);
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    cur.push(c);
                }
                ',' if depth == 0 => {
                    out.push(cur.trim().to_string());
                    cur = String::new();
                }
                _ => cur.push(c),
            }
        }
        if !cur.trim().is_empty() {
            out.push(cur.trim().to_string());
        }
        out
    }

    /// `"error.a.b"` ⇒ `error.a.b`；非字符串字面量 ⇒ 空串
    fn strip_string_literal(s: &str) -> String {
        let t = s.trim();
        let core = t.strip_prefix("r#\"").or(t.strip_prefix('"'));
        match core {
            Some(c) => {
                let c = c.strip_suffix("\"#").unwrap_or(c);
                let c = c.strip_suffix('"').unwrap_or(c);
                c.to_string()
            }
            None => String::new(),
        }
    }

    /// 字面量的 i18n 键形态：首段 ∈ 某份 yml 的顶层节，且 ≥2 段、每段是非空 ASCII 标识符。
    /// 返回**段数**（供"两段必须来自 `tr!(`"的门槛使用），不匹配返回 None。
    fn i18n_key_shape(lit: &str, prefixes: &[String]) -> Option<usize> {
        let segs: Vec<&str> = lit.split('.').collect();
        if segs.len() < 2 || !prefixes.iter().any(|p| *p == segs[0]) {
            return None;
        }
        if segs
            .iter()
            .any(|s| s.is_empty() || !s.chars().all(|c| c.is_alphanumeric() || c == '_'))
        {
            return None;
        }
        Some(segs.len())
    }

    /// 该开引号之前（跨过换行与空白）是否为 `tr!(` —— 即这个字面量是 `tr!` 的第一个实参
    fn follows_tr_call(chars: &[char], quote_idx: usize) -> bool {
        let mut k = quote_idx;
        while k > 0 && chars[k - 1].is_whitespace() {
            k -= 1;
        }
        k >= 4
            && chars[k - 4] == 't'
            && chars[k - 3] == 'r'
            && chars[k - 2] == '!'
            && chars[k - 1] == '('
    }

    /// 收集生产码里的 i18n 键字面量，**两路并集**（缺一各有盲区）：
    /// A. `tr!("…")` 的第一实参——任意段数（本仓有 7 条两段键，如 `common.enabled`、
    ///    `websocket.connected`，只按形状门槛会全部漏）；
    /// B. 三段以上的点号字面量——**不要求文本上出现 `tr!(`**：本仓有 7 条键经 `macro_rules!`
    ///    以 `$key` 形式传进 `tr!`（`error.ak.*`），只按 A 会全部漏。
    ///
    /// 两段串必须来自 A 才收：`"notice.published"` 是 **WebHook 事件名**而不是键
    /// （`sys_notice_handler.rs` 实撞形状），只看形状就会把它误判成"缺文案的键"。
    fn key_literals(files: &[(String, String)], prefixes: &[String]) -> Vec<String> {
        let mut out = std::collections::BTreeSet::new();
        for (_, text) in files {
            let chars: Vec<char> = text.chars().collect();
            let mut i = 0usize;
            while i < chars.len() {
                if chars[i] != '"' {
                    i += 1;
                    continue;
                }
                let mut j = i + 1;
                let mut buf = String::new();
                let mut closed = false;
                let mut escaped = false;
                while j < chars.len() {
                    match chars[j] {
                        // 含转义（`\"`、`\\`）的串一律不当键：键名里没有反斜杠
                        '\\' => {
                            escaped = true;
                            j += 2;
                        }
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\n' => break,
                        c => {
                            buf.push(c);
                            j += 1;
                        }
                    }
                }
                if closed
                    && !escaped
                    && i18n_key_shape(&buf, prefixes)
                        .is_some_and(|segs| segs >= 3 || follows_tr_call(&chars, i))
                {
                    out.insert(buf);
                }
                i = j + 1;
            }
        }
        out.into_iter().collect()
    }

    /// 在每一份 locale 里查不到的键 ⇒ `"键 缺席于 [文件名…]"`
    fn unresolved_i18n_keys(
        keys: &[String],
        sets: &[(&String, &std::collections::BTreeSet<String>)],
    ) -> Vec<String> {
        keys.iter()
            .filter_map(|k| {
                let absent: Vec<String> = sets
                    .iter()
                    .filter(|(_, set)| !set.contains(k))
                    .map(|(name, _)| name.to_string())
                    .collect();
                (!absent.is_empty()).then(|| format!("{k} 缺席于 {absent:?}"))
            })
            .collect()
    }

    /// 语言包清单来自 **readdir**，不是写死的两份文件名。
    ///
    /// 写死时新增第三语言（`ja-JP.yml`）**完全不进任何锁**：键集对等、占位符对账、
    /// 键可解析三把全部只比 zh/en，新语言可以整文件缺键而 CI 全绿。rust_i18n 会把
    /// locales 目录整体编进来，所以扫描面也必须跟着目录走。
    fn locale_files() -> Vec<(String, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("locales");
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("读取 locales 目录失败: {e}"))
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                (p.extension().and_then(|x| x.to_str()) == Some("yml")).then(|| {
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                })
            })
            .collect();
        names.sort();
        assert!(
            names.len() >= 2,
            "locales 目录只剩 {} 份语言包（{names:?}）——目录定位失效不是\"语言包被精简\"",
            names.len()
        );
        for must in ["zh-CN.yml", "en-US.yml"] {
            assert!(
                names.iter().any(|n| n == must),
                "语言包清单里少了 {must}（实际 {names:?}），三把 i18n 锁的比较基准会一起错位"
            );
        }
        names
            .into_iter()
            .map(|name| {
                let p = dir.join(&name);
                (
                    name,
                    std::fs::read_to_string(&p)
                        .unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display())),
                )
            })
            .collect()
    }

    /// 采集面改走共享扫描器（批七十五 B9）：`#[cfg(test)]` 截断 + 注释行置空这两条语义
    /// 与 `handler/api_contract_guard.rs` 必须同源，否则同一份源码在两个锁里形态不同。
    /// 本锁**含**集成测试目录——`tr!` 也出现在集成用例里，漏掉就是半边覆盖。
    fn src_prod_files() -> Vec<(String, String)> {
        let files = crate::common::prod_scan::prod_files(&crate::common::prod_scan::Scan {
            include_integration_tests: true,
            ..Default::default()
        });
        // 采集面地板（本轮实测：全仓 .rs 上百个）——扫描器扫不到东西时本锁必须红，
        // 不能靠"键数量也一起掉了"间接暴露（那是把 A 的失效洗成 B 的失败信息）
        crate::common::prod_scan::require_volume(&files, 80, 20_000, "i18n 键锁采集面");
        files
            .into_iter()
            .map(|f| {
                let text = f.text();
                (f.rel, text)
            })
            .collect()
    }

    #[test]
    fn every_i18n_key_literal_resolves_in_all_locales() {
        let locales = locale_files();
        let sets: Vec<(String, std::collections::BTreeSet<String>)> = locales
            .iter()
            .map(|(name, text)| (name.clone(), yml_leaf_paths(text)))
            .collect();
        // 顶层节前缀取自 yml 自身：新增一节自动进入扫描面，不需要改锁
        let mut prefixes: Vec<String> = Vec::new();
        for (_, set) in sets.iter() {
            for k in set {
                let top = k.split('.').next().unwrap_or("").to_string();
                if !prefixes.contains(&top) {
                    prefixes.push(top);
                }
            }
        }
        prefixes.sort();
        let keys = key_literals(&src_prod_files(), &prefixes);
        // 非零探针：生产码里应有数百个键字面量，过小说明扫描器或前缀集合坏了（否则下面的 0 是虚零）
        assert!(
            keys.len() > 400,
            "生产码 i18n 键字面量异常偏少（实际 {}，前缀集 {prefixes:?}）",
            keys.len()
        );
        let refs: Vec<(&String, &std::collections::BTreeSet<String>)> =
            sets.iter().map(|(n, s)| (n, s)).collect();
        let missing = unresolved_i18n_keys(&keys, &refs);
        assert!(
            missing.is_empty(),
            "存在查不到文案的 i18n 键（rust_i18n 会把键名原样返回给用户，\
             而 `assert_eq!(msg, tr!(同键))` 形状的锁对此恒真）:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn locale_files_have_identical_key_sets() {
        let locales = locale_files();
        let sets: Vec<(String, std::collections::BTreeSet<String>)> = locales
            .iter()
            .map(|(n, t)| (n.clone(), yml_leaf_paths(t)))
            .collect();
        for (n, s) in &sets {
            assert!(
                s.len() > 400,
                "{n} 叶子数异常（{}），解析器可能失效",
                s.len()
            );
        }
        // 逐份与第一份比（不是"只比 [0] 与 [1]"）：第三语言加入后自动进比较面
        let base = &sets[0];
        let mut drift = Vec::new();
        for (n, s) in sets.iter().skip(1) {
            let only_base: Vec<&String> = base.1.difference(s).collect();
            let only_other: Vec<&String> = s.difference(&base.1).collect();
            if !only_base.is_empty() || !only_other.is_empty() {
                drift.push(format!(
                    "{n}: 仅 {b} = {ob:?}；仅 {n} = {oo:?}",
                    b = base.0,
                    ob = only_base,
                    oo = only_other
                ));
            }
        }
        assert!(
            drift.is_empty(),
            "语言包键集不对称（fallback=zh-CN 下 en 缺键＝英文用户静默收中文，\
             zh 缺键＝中文用户收英文）:\n{}",
            drift.join("\n")
        );
    }

    /// 每个 `tr!("…")` 的键**首段**必须是某份语言包的顶层节。
    ///
    /// 这条补的是原 `i18n_key_shape` 的反面：它按"首段 ∈ 顶层节"来判断一个字符串像不像
    /// i18n 键，于是**首段整体写错**（`oauth.xxx` 而语言包只有 `login`）或**新节忘了建**
    /// 的键会被判成"不像键"而静默跳过——恰好是"键名原样吐给用户"那条路径看不见。
    /// 改用调用点做输入：`tr!` 的第一个参数按定义就是一次 i18n 查找，没有"不像键"的余地。
    #[test]
    fn every_tr_call_key_root_is_a_real_locale_section() {
        let locales = locale_files();
        let mut roots: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (_, text) in locales.iter() {
            for k in yml_leaf_paths(text) {
                if let Some(top) = k.split('.').next() {
                    roots.insert(top.to_string());
                }
            }
        }
        assert!(
            roots.len() >= 2,
            "语言包顶层节只剩 {roots:?}——解析器或文件定位失效"
        );
        let sites = tr_call_sites(&src_prod_files());
        let bad: Vec<String> = sites
            .iter()
            .filter(|(_, _, key, _)| {
                let segs: Vec<&str> = key.split('.').collect();
                segs.len() < 2 || !roots.contains(segs[0])
            })
            .map(|(rel, line, key, _)| format!("{rel}:{line} tr!(\"{key}\")"))
            .collect();
        assert!(
            bad.is_empty(),
            "存在首段不是任何语言包顶层节的 tr! 键（这类键在旧判据下被判成\"不像键\"而跳过，\
             实际运行时会把键名原样返回给用户）:\n{}",
            bad.join("\n")
        );
    }

    /// 判据（纯函数，真实数据与控制组共用）：`tr!` 实参与文案占位符必须**双向**对得上。
    ///
    /// 四条方向各对应一种"用户看得见的坏"：
    /// ① 文案里有裸 `{x}` ⇒ rust_i18n 只替换 `%{x}`，用户**原样看到** `{x}`
    ///    （批七十五实测 4 条分片上传文案正是此形：`分片未收齐（已收 {received}/{total}）`）；
    /// ② 文案要 `%{x}` 而调用侧没传 ⇒ 用户看到 `%{x}` 字面；
    /// ③ 调用侧传了 `x = …` 而文案没有 `%{x}` ⇒ 参数被静默丢弃（"超过 %{max}MB" 变成没有数字）；
    /// ④ 双语占位符集合不等 ⇒ 中文正常、英文带字面量（或反之），只在切换语言时暴露。
    fn placeholder_problems(
        sites: &[(String, usize, String, Vec<String>)],
        texts: &[(String, std::collections::BTreeMap<String, String>)],
    ) -> Vec<String> {
        let mut out = Vec::new();
        for (rel, line, key, args) in sites {
            // 同一键在不同 locale 的占位符集合（用于 ④）
            let mut per_locale: Vec<(&String, std::collections::BTreeSet<String>)> = Vec::new();
            let mut referenced = false;
            for (loc, map) in texts {
                let Some(leaf) = map.get(key) else { continue };
                referenced = true;
                let (pct, bare) = placeholders(leaf);
                for b in &bare {
                    out.push(format!(
                        "{rel}:{line} [{loc}] {key}: 文案含裸花括号占位符 {{{b}}}——rust_i18n 只替换 \
                         %{{…}}，用户会原样看到 {b}（正确写法：%{{{b}}}）"
                    ));
                }
                for p in &pct {
                    if !args.iter().any(|a| a == p) {
                        out.push(format!(
                            "{rel}:{line} [{loc}] {key}: 文案要 %{{{p}}}，但调用侧未传参数 {p}"
                        ));
                    }
                }
                for a in args {
                    if !pct.contains(a) {
                        out.push(format!(
                            "{rel}:{line} [{loc}] {key}: 调用侧传了 {a} = …，但文案没有 %{{{a}}} \
                             ⇒ 该值被静默丢弃，用户看不到它"
                        ));
                    }
                }
                per_locale.push((loc, pct));
            }
            if referenced && per_locale.len() >= 2 {
                for i in 1..per_locale.len() {
                    if per_locale[0].1 != per_locale[i].1 {
                        out.push(format!(
                            "{rel}:{line} {key}: 双语占位符集合不等（[{}] {:?} vs [{}] {:?}）\
                             ⇒ 一种语言正常、另一种带字面量",
                            per_locale[0].0, per_locale[0].1, per_locale[i].0, per_locale[i].1
                        ));
                    }
                }
            }
        }
        out
    }

    #[test]
    fn i18n_placeholders_match_tr_call_args() {
        let locales = locale_files();
        let texts: Vec<(String, std::collections::BTreeMap<String, String>)> = locales
            .iter()
            .map(|(n, t)| (n.clone(), yml_leaf_texts(t)))
            .collect();
        let sites = tr_call_sites(&src_prod_files());
        // 非零探针：全仓 tr! 调用点是千级（实测 1500+），个位数说明采集器或解析器坏了
        assert!(
            sites.len() > 300,
            "tr! 调用点异常偏少（实际 {}）——采集面坏了，下面的 0 是虚零",
            sites.len()
        );
        let with_args = sites.iter().filter(|s| !s.3.is_empty()).count();
        assert!(
            with_args > 30,
            "带插值参数的 tr! 调用点只有 {with_args} 处，判据即将退化成恒真"
        );
        let problems = placeholder_problems(&sites, &texts);
        assert!(
            problems.is_empty(),
            "i18n 插值参数与文案占位符不符（四种形态都是用户看得见的坏）:\n{}",
            problems.join("\n")
        );
    }

    /// 控制组：四条方向**各**必须能失败，且正确写法不得报。
    #[test]
    fn placeholder_guard_catches_synthetic_violations() {
        let mut zh = std::collections::BTreeMap::new();
        let mut en = std::collections::BTreeMap::new();
        let sites: Vec<(String, usize, String, Vec<String>)> = vec![
            // ① 裸花括号
            (
                "src/a.rs".into(),
                1,
                "error.k.bare".into(),
                vec!["x".into()],
            ),
            // ② 文案要 %{y} 但没传
            ("src/a.rs".into(), 2, "error.k.missing_arg".into(), vec![]),
            // ③ 传了 z 但文案没有 %{z}
            (
                "src/a.rs".into(),
                3,
                "error.k.unused_arg".into(),
                vec!["z".into()],
            ),
            // ④ 双语占位符不等
            (
                "src/a.rs".into(),
                4,
                "error.k.locale_drift".into(),
                vec!["n".into()],
            ),
            // 正例：完全对齐
            ("src/a.rs".into(), 5, "error.k.ok".into(), vec!["n".into()]),
        ];
        zh.insert("error.k.bare".to_string(), "值 {x} 非法".to_string());
        en.insert("error.k.bare".to_string(), "value {x} invalid".to_string());
        zh.insert("error.k.missing_arg".to_string(), "上限 %{y}".to_string());
        en.insert("error.k.missing_arg".to_string(), "limit %{y}".to_string());
        zh.insert("error.k.unused_arg".to_string(), "没有占位符".to_string());
        en.insert(
            "error.k.unused_arg".to_string(),
            "no placeholder".to_string(),
        );
        zh.insert("error.k.locale_drift".to_string(), "共 %{n} 条".to_string());
        en.insert(
            "error.k.locale_drift".to_string(),
            "total items".to_string(),
        );
        zh.insert("error.k.ok".to_string(), "共 %{n} 条".to_string());
        en.insert("error.k.ok".to_string(), "%{n} items".to_string());
        let texts = vec![("zh-CN".to_string(), zh), ("en-US".to_string(), en)];

        let problems = placeholder_problems(&sites, &texts);
        // 每个坏形态至少贡献一条，正例不贡献 ⇒ 恰好 4 个键名出现在报告里
        for key in [
            "error.k.bare",
            "error.k.missing_arg",
            "error.k.unused_arg",
            "error.k.locale_drift",
        ] {
            assert!(
                problems.iter().any(|p| p.contains(key)),
                "{key} 的坏形态必须被抓到，实际报告:\n{}",
                problems.join("\n")
            );
        }
        assert!(
            !problems.iter().any(|p| p.contains("error.k.ok")),
            "对齐的写法不得被报，否则下一步就是有人把判据调松"
        );

        // 占位符抽取器自身：JSON 形态的花括号不是占位符（否则会大量误报）
        let (pct, bare) = placeholders(r#"响应形如 {"code":200} 且空对象 {} 与 %{real}"#);
        assert_eq!(
            pct.into_iter().collect::<Vec<_>>(),
            vec!["real".to_string()]
        );
        assert!(
            bare.is_empty(),
            "JSON 字面量与空花括号不得被当成占位符: {bare:?}"
        );
    }

    /// 控制组：两把锁不是虚锁（能抓"键写在错的节下"与"双语单边键"两种形状）
    #[test]
    fn i18n_key_guards_catch_synthetic_violations() {
        // ① 本批真实缺陷形状：`error:` 下没有 dataRule，整段被追加到了 `alert:` 末尾
        let misplaced = concat!(
            "error:\n",
            "  common:\n",
            "    parse_failed: 解析失败\n",
            "alert:\n",
            "  evaluate:\n",
            "    fired: 触发\n",
            "  dataRule:\n",
            "    name_invalid: 规则名非法\n",
        );
        let set = yml_leaf_paths(misplaced);
        assert!(
            set.contains("alert.dataRule.name_invalid"),
            "解析器必须把错位键归到它实际所在的节: {set:?}"
        );
        assert!(
            !set.contains("error.dataRule.name_invalid"),
            "错位键不得被算作存在于 error 节下，否则本锁对这个缺陷是瞎的"
        );
        let keys = vec![
            "error.common.parse_failed".to_string(),
            "error.dataRule.name_invalid".to_string(),
        ];
        let ok: std::collections::BTreeSet<String> =
            ["error.common.parse_failed", "error.dataRule.name_invalid"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        let zh_name = "zh-CN.yml".to_string();
        let en_name = "en-US.yml".to_string();
        let refs: Vec<(&String, &std::collections::BTreeSet<String>)> =
            vec![(&zh_name, &set), (&en_name, &ok)];
        let missing = unresolved_i18n_keys(&keys, &refs);
        assert_eq!(missing.len(), 1, "只应报出错位的那一条，实际: {missing:?}");
        assert!(
            missing[0].starts_with("error.dataRule.name_invalid")
                && missing[0].contains("zh-CN.yml"),
            "缺失报告必须点名缺它的那一份文件: {missing:?}"
        );
        // ② 单边键：两个方向都必须可见（集合相等判据不是只查一边）
        let zh: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::from(["error.a.b".to_string()]);
        let en: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::from(["error.a.b".to_string(), "error.c.d".to_string()]);
        assert_eq!(zh.difference(&en).count(), 0);
        assert_eq!(en.difference(&zh).count(), 1, "en 单边键必须被抓到");
        // ③ 形状判据本身：段数与前缀的裁决
        let prefixes = vec!["error".to_string(), "msg".to_string(), "notice".to_string()];
        assert_eq!(
            i18n_key_shape("error.auth.token_invalid", &prefixes),
            Some(3)
        );
        assert_eq!(i18n_key_shape("msg.success.default", &prefixes), Some(3));
        assert_eq!(i18n_key_shape("error.single", &prefixes), Some(2));
        assert_eq!(
            i18n_key_shape("db.user.name", &prefixes),
            None,
            "非 yml 顶层节的前缀不得进入扫描面"
        );
        assert_eq!(
            i18n_key_shape("error.a.b/c", &prefixes),
            None,
            "含路径分隔符的串（如路由模板）不得误判为键"
        );
        assert_eq!(i18n_key_shape("error..b", &prefixes), None, "空段不得误判");
        // ④ 两路并集各自都必须有效（少一路就是盲区）
        let files = vec![(
            "src/x.rs".to_string(),
            concat!(
                // A 路：两段键只能靠 `tr!(` 认定
                "tr!(\"error.single\");\n",
                // B 路：三段键即使不经 `tr!(`（macro 以 $key 转发）也要收到
                "ak_err!(\"error.ak.ak_not_found\");\n",
                // 噪声形状：两段的 WebHook 事件名，裸字面量不得当键
                "emit_event(&state, \"notice.published\").await;\n",
                // 转义与跨行形态不得被切成键
                "let esc = \"error.a.c\\\"d\";\n",
                "let multi = \"error.a.\n",
                "d\";\n",
            )
            .to_string(),
        )];
        let got = key_literals(&files, &prefixes);
        assert_eq!(
            got,
            vec![
                "error.ak.ak_not_found".to_string(),
                "error.single".to_string()
            ],
            "A 路（tr! 两段）与 B 路（三段裸字面量）都必须生效，\
             且事件名 `notice.published`、转义串、跨行串都不得进入扫描面: {got:?}"
        );
    }
}
