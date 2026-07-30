// axum-backend/src/common/i18n.rs
//! 国际化（i18n）基础设施
//!
//! 分层设计：
//! - garde 校验消息：通过 [`garde::i18n::I18n`] trait 实现（[`ZhCn`]），
//!   由 [`validate`] 统一入口按当前 locale 经 `with_i18n` 执行校验
//! - 业务/通用文案：rust-i18n（t! 宏），经 [`tr`] 按当前 locale 翻译
//! - 模块标题等少量"动态 key"：[`MODULE_TITLES`] 表 + [`module_title`]（本地查表，无 YAML）
//!
//! locale 传递：locale_middleware 读取 `Accept-Language` → 协商 → 经
//! [`LOCALE`]（task-local）作用域注入，[`current_locale`] 在任意位置读取；
//! `tokio::spawn` 逃逸 task-local 后回退默认值（zh-CN），故 spawn 内需显式传 locale。

use std::borrow::Cow;
use std::cell::RefCell;
use std::fmt::Display;

use garde::i18n::{I18n, IpKind, InvalidCreditCard, InvalidEmail, InvalidPhoneNumber, InvalidUrl};
use garde::Report;

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
    if is_zh() {
        zh
    } else {
        en
    }
}

/// 业务文案翻译：rust-i18n 按**当前 locale** 查找固定 key（T-07）
///
/// 用法：`tr!("error.common.not_found")` —— 返回 String。
/// key 必须是字符串字面量（rust-i18n t! 宏要求，便于编译期提取/嵌入）。
/// locale 取当前请求 locale（task-local，无则回退 zh-CN）。
///
/// L-3：扩展支持插值参数 `tr!("msg.hello", name = "Alice")`，
/// 转发给 `rust_i18n::t!` 的 named args 语法，对应 YAML 中 `{{name}}` 占位符。
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
    ("module.notice", "通知公告", "Notice"),
    ("module.job", "定时任务", "Scheduled Tasks"),
    ("module.operlog", "操作日志", "Operation Log"),
    ("module.logininfor", "登录日志", "Login Log"),
    ("module.online", "在线用户", "Online Users"),
    ("module.gen", "代码生成", "Code Generation"),
    ("module.common", "通用接口", "Common APIs"),
    ("module.auth", "认证管理", "Authentication"),
    ("module.backup", "数据备份", "Data Backup"),
    ("module.task", "任务管理", "Task Management"),
    ("module.rateLimit", "限流配置", "Rate Limit"),
    ("module.cache", "缓存监控", "Cache Monitor"),
    ("module.server", "服务器监控", "Server Monitor"),
    ("module.auditDashboard", "审计仪表盘", "Audit Dashboard"),
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
        .filter(|(_, zh, en)| {
            zh.contains(text) || en.to_lowercase().contains(&lower)
        })
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
        assert!(joined.contains("长度不能少于 2"), "应包含长度下限中文消息: {joined}");
        assert!(joined.contains("数值不能大于 100"), "应包含范围上限中文消息: {joined}");
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
        assert!(keys.contains(&"module.online"), "应匹配 online users: {keys:?}");
    }

    #[test]
    fn test_locale_default() {
        // 无 task-local 时回退 zh-CN
        assert_eq!(current_locale(), "zh-CN");
        assert!(is_zh());
    }
}
