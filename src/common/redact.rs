// stepby-axum/src/common/redact.rs
//! 对外文本的敏感形态折叠（C.9 脱敏口径的单一事实源）
//!
//! 为什么单独成模块：绝对路径折叠此前只活在 `handler/health_probes.rs::sanitize_detail`
//! 里（b73 为 `/health` 免鉴权端点补的），而"错误文案进响应体"是同一个泄露面——
//! 判据散落两处必然漂移（同 AGENTS「写了没接线＝没写」的反面：接了但只接一处）。
//! 现在 `/health` 探针 detail 与 `AppError` 响应体出口都调本函数。
//!
//! 判据是"未认证者能从这条字符串推断出什么"，不是"这算不算敏感字段"：
//! 部署目录结构（`D:\Projects\stepby\uploads\…`）对未认证访问者没有排障价值，
//! 只有侦察价值 ⇒ 折叠；而 URL 与端口、单段 API 片段是排障必需且不含目录结构 ⇒ 保留。

use std::sync::LazyLock;

/// POSIX 绝对路径的**已知文件系统根**首段（Linux FHS + macOS + 容器/CI 常见挂载）
///
/// 为什么按"已知根"而不是"任意 ≥3 段"：后者会把 API 路由模板一起折叠掉。
/// 实测（b74 轮 27 的控制组先撞到）：`路由 /system/user/list 未登记权限映射`
/// 这条排障必需文案含三段，按"任意 ≥3 段"会被折成 `路由 <path> 未登记`——
/// 过度脱敏摧毁排障能力，同 AGENTS C.9"边界口径必须同时钉住不误伤排障必需信息"。
/// 文件系统根是**有界集合**（FHS 稳定 + 容器惯例），而路由前缀是无界的（业务随意增删），
/// 按有界集合判定既不漂移又覆盖常见部署形态。
/// 与路由首段的**碰撞已机械核对**（`PERM_ROUTE_TABLE` 全部首段：ai/common/dashboard/
/// getInfo/getRouters/logout/monitor/oauth2/report/sso/system/tool/unlockscreen ⇒ 零交集）。
///
/// 已知残留（如实登记）：非本集合的自定义挂载根（`/nfs-store/…`）不被折叠，
/// 主防线仍是**源头只报 `file_name()`** + 出口侧独立探针（见 `api_contract_guard`）。
const POSIX_FS_ROOTS: &[&str] = &[
    "app",
    "apps",
    "bin",
    "boot",
    "data",
    "dev",
    "etc",
    "home",
    "lib",
    "lib64",
    "media",
    "mnt",
    "opt",
    "proc",
    "private",
    "root",
    "run",
    "sbin",
    "srv",
    "sys",
    "tmp",
    "usr",
    "var",
    "Volumes",
    "workspace",
    "Users",
];

/// 文件系统绝对路径（Windows 盘符形态 / POSIX "已知根 + ≥2 层段"形态）
///
/// 两条分支的边界口径（防"过度脱敏把有用的信息也抹了"）：
/// · Windows：`盘符:分隔符 + ASCII 段`，段字符集**不含**括号/空格/CJK ⇒ `（D:\a\b）` 只吃路径不吃 `）`；
/// · POSIX：必须**行首或空白起手**、首段 ∈ [`POSIX_FS_ROOTS`]、再跟 ≥2 层段
///   ⇒ `https://host/v1/models`（紧跟域名）与 `/system/user/list`（非文件系统根）都不误伤。
static ABS_PATH_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    let roots = POSIX_FS_ROOTS.join("|");
    regex::Regex::new(&format!(
        r"(?P<boundary>^|\s)(?:/(?:{roots})(?:/[A-Za-z0-9._-]+)+)+|[A-Za-z]:[\\/](?:[A-Za-z0-9._-]+[\\/]?)+"
    ))
    .expect("静态正则")
});

/// 把文本中的文件系统绝对路径折叠为 `<path>`，保留路径前的边界字符
/// （空格/行首），使句子读起来仍是完整一句，排障价值只损失目录结构本身。
pub fn fold_abs_paths(text: &str) -> String {
    ABS_PATH_RE
        .replace_all(text, |caps: &regex::Captures| match caps.name("boundary") {
            Some(b) => format!("{}<path>", b.as_str()),
            None => "<path>".to_string(),
        })
        .to_string()
}

/// 文本是否含文件系统绝对路径（供边界锁与日志判据复用同一形态定义）
pub fn contains_abs_path(text: &str) -> bool {
    ABS_PATH_RE.is_match(text)
}

/// 只取路径的**最后一段**（文件名/目录名），用于"日志里要看得见是哪个文件，
/// 但不能把部署目录交出去"的场合（C.9：源头只报 `file_name()`）。
pub fn file_name_of(path: &std::path::Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<unknown>".to_string())
}

// ==================== 遥测文本：查询值脱敏（b132） ====================
//
// 缺陷形态（开发库实测）：`sys_frontend_error.page_url` 直接存 `location.href`，
// 而列表页筛选值会写进地址栏（b131 的 `syncUrlQuery`）⇒ 按用户名/手机号搜索时的一次
// JS 错误，就把用户输入持久化进管理端可查的遥测表。实测 178,386 行里 39,039 行带
// 查询串，其中 `userName=` 命中 2,112 行。
//
// 边界方向与 C.9 一致：**值一律遮蔽，键名保留**（排障要知道"是哪个参数"），
// 凭据类键（`code`/`state`/`token`/`ticket`/`secret`…）**键值一起丢弃**。
// 与前端 `utils/telemetrySanitize.ts` 同口径；前端负责"尽量不发脏数据"，
// 本函数负责**边界兜底**（客户端是用户可改的外部输入，不脱敏就等于没脱敏）。

/// 凭据类查询键：键与值都不进遥测
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "code",
    "state",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "ticket",
    "password",
    "passwd",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "session",
    "sessionid",
    "sid",
    "sig",
    "signature",
];

/// 遥测 page_url 的字符上限（与前端 `MAX_TELEMETRY_PAGE_URL_CHARS` 同值）
pub const MAX_TELEMETRY_PAGE_URL_CHARS: usize = 512;

fn is_query_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '[' | ']')
}

/// 查询值的终止字符：空白与常见包裹符。刻意把 `)`、`,`、`;`、`}` 也算进去，
/// 免得把 `(?token=abc)` 这类括号里的整段吃掉（过度脱敏会毁掉排障文本）。
fn is_query_value_end(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '&' | '#' | '"' | '\'' | '<' | '>' | '`' | ')' | ',' | ';' | ']' | '}'
        )
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect()
}

/// 遥测用的页面地址：origin + path + 参数名（值换 `***`），凭据类参数整体丢弃，
/// hash 整段丢弃；畸形输入退化为"去掉查询串与 hash"，绝不 panic。
pub fn sanitize_telemetry_page_url(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    let (base, query) = match raw.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (raw, None),
    };
    let base = base.split('#').next().unwrap_or(base);
    let mut out = String::with_capacity(base.len() + 32);
    out.push_str(base);
    if let Some(query) = query {
        let query = query.split('#').next().unwrap_or("");
        let mut kept: Vec<String> = Vec::new();
        for pair in query.split('&') {
            let (key, value) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            if key.is_empty() || value.is_empty() {
                continue;
            }
            if SENSITIVE_QUERY_KEYS
                .iter()
                .any(|s| key.eq_ignore_ascii_case(s))
            {
                continue;
            }
            kept.push(format!("{key}=***"));
        }
        if !kept.is_empty() {
            out.push('?');
            out.push_str(&kept.join("&"));
        }
    }
    truncate_chars(&out, MAX_TELEMETRY_PAGE_URL_CHARS)
}

/// 任意文本（错误 message / stack）里的查询值脱敏：`?k=v` / `&k=v` 的值换成 `***`。
/// 无查询对时逐字符返回原串；对已遮蔽文本幂等。
pub fn redact_query_values(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    if !text.contains('?') && !text.contains('&') {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if (c == '?' || c == '&') && i + 1 < chars.len() && is_query_key_char(chars[i + 1]) {
            let mut key_end = i + 1;
            while key_end < chars.len() && is_query_key_char(chars[key_end]) {
                key_end += 1;
            }
            if key_end < chars.len() && chars[key_end] == '=' {
                let mut value_end = key_end + 1;
                while value_end < chars.len() && !is_query_value_end(chars[value_end]) {
                    value_end += 1;
                }
                if value_end > key_end + 1 {
                    out.push(c);
                    out.extend(chars[i + 1..=key_end].iter());
                    out.push_str("***");
                    i = value_end;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 该折叠的必须折叠（双向判据的"红"侧）
    #[test]
    fn folds_windows_and_posix_absolute_paths() {
        assert_eq!(
            fold_abs_paths(
                "上传目录不可写（D:\\Projects\\stepby\\uploads\\file）: Permission denied"
            ),
            "上传目录不可写（<path>）: Permission denied"
        );
        assert_eq!(
            fold_abs_paths("写入 /var/lib/stepby/uploads 失败"),
            "写入 <path> 失败"
        );
        assert_eq!(fold_abs_paths("/etc/hosts"), "<path>");
        // 盘符大小写与反斜杠/正斜杠混用都要吃掉
        assert_eq!(
            fold_abs_paths("open C:/logs/a.txt failed"),
            "open <path> failed"
        );
    }

    /// 不该折叠的一条都不许动（过度脱敏会摧毁排障能力，同属缺陷）
    #[test]
    fn keeps_urls_ports_and_route_templates() {
        // URL：域名后的路径紧跟 authority，不构成"空白起手的已知根路径"
        assert_eq!(
            fold_abs_paths("GET https://api.example.com/v1/models 返回 401"),
            "GET https://api.example.com/v1/models 返回 401"
        );
        assert_eq!(
            fold_abs_paths("redis 连接失败 redis://127.0.0.1:6379/0"),
            "redis 连接失败 redis://127.0.0.1:6379/0"
        );
        // **API 路由模板必须原样保留**：b74 轮 27 的锁实测撞到旧判据把
        // `路由 /system/user/list 未登记` 折成 `路由 <path> 未登记`——权限映射类错误
        // 文案整族失去排障价值。判据改为"POSIX 分支只认已知文件系统根"，
        // 文件系统根是有界集合（FHS 稳定），路由前缀是无界集合（业务随意增删）。
        for route in [
            "路由 /system/user/list 未登记权限映射",
            "档位检查 /monitor/operlog/clean 未登记",
            "端点 /ai/chat 并发闸已满",
        ] {
            assert_eq!(fold_abs_paths(route), route, "路由模板被误伤: {route}");
        }
        // 相对路径不误伤
        assert_eq!(
            fold_abs_paths("目录 uploads/local 不存在"),
            "目录 uploads/local 不存在"
        );
    }

    /// 已知残留（如实登记，不假装没有）：非 FHS 的自定义挂载根（如 `/nfs-store/a/b`）
    /// 不会被本判据折叠。缓解手段是**源头纪律**（只报 `file_name()`）+ 出口侧的
    /// 独立探针（`integration_tests/common_handler.rs` 用更宽的判据断言 `/health` detail，
    /// 故意不复用本函数——否则本函数失效时那条锁会跟着恒真）。
    #[test]
    fn known_residual_non_fhs_root_is_not_folded() {
        assert_eq!(
            fold_abs_paths("写入 /nfs-store/apps/stepby/uploads 失败"),
            "写入 /nfs-store/apps/stepby/uploads 失败"
        );
        // 而任意 FHS 根（含两层形态）必须折
        assert_eq!(fold_abs_paths("写入 /srv/apps/x 失败"), "写入 <path> 失败");
        assert_eq!(fold_abs_paths("读取 /etc/passwd 失败"), "读取 <path> 失败");
    }

    /// `contains_abs_path` 与 `fold_abs_paths` 必须同判据（同一正则，不得两份口径）
    #[test]
    fn detector_and_folder_agree() {
        assert!(contains_abs_path(r"D:\Projects\stepby\uploads\file"));
        // 折叠后逐字不变的串，检测器也不得报——否则两处口径漂移
        for text in [
            "路由 /system/user/list 未登记",
            "目录 uploads/local 不存在",
            "GET https://api.example.com/v1/models 返回 401",
        ] {
            assert_eq!(fold_abs_paths(text), text, "折叠器误伤：{text}");
            assert!(!contains_abs_path(text), "检测器误报：{text}");
        }
    }

    /// `file_name_of` 只留末段（日志面用，不带目录）
    #[test]
    fn file_name_of_keeps_only_last_segment() {
        assert_eq!(
            file_name_of(std::path::Path::new(r"D:\a\b\part-1.bin")),
            "part-1.bin"
        );
        assert_eq!(
            file_name_of(std::path::Path::new("/var/lib/x/y.log")),
            "y.log"
        );
        assert_eq!(file_name_of(std::path::Path::new("..")), "<unknown>");
    }

    // ---------- b132：遥测查询值脱敏 ----------

    #[test]
    fn telemetry_page_url_keeps_origin_path_and_names_only() {
        assert_eq!(
            sanitize_telemetry_page_url(
                "http://localhost:8080/system/user?pageNum=1&pageSize=10&userName=e2e_view_abc"
            ),
            "http://localhost:8080/system/user?pageNum=***&pageSize=***&userName=***"
        );
        // 纯路径原样（没有可泄露的查询值）
        assert_eq!(
            sanitize_telemetry_page_url("http://h/monitor/online"),
            "http://h/monitor/online"
        );
    }

    #[test]
    fn telemetry_page_url_drops_credentials_and_hash() {
        let out = sanitize_telemetry_page_url(
            "https://sso.example.com/callback?code=abc123&state=xyz&access_token=tok&ticket=t1&redirect=%2Fhome#frag",
        );
        assert_eq!(out, "https://sso.example.com/callback?redirect=***");
        for secret in ["abc123", "xyz", "tok", "t1", "frag"] {
            assert!(!out.contains(secret), "凭据泄漏: {secret} in {out}");
        }
        // 大小写不敏感
        assert_eq!(
            sanitize_telemetry_page_url("http://h/p?CODE=abc&Token=t"),
            "http://h/p"
        );
    }

    #[test]
    fn telemetry_page_url_handles_malformed_and_empty() {
        assert_eq!(sanitize_telemetry_page_url(""), "");
        assert_eq!(sanitize_telemetry_page_url("   "), "");
        // 空值参数不产生噪声；无 `=` 的裸参数直接丢弃
        assert_eq!(
            sanitize_telemetry_page_url("http://h/a?empty=&flag&x=1"),
            "http://h/a?x=***"
        );
        // 相对/畸形形态不 panic：base 原样保留，查询值照常遮蔽
        assert_eq!(sanitize_telemetry_page_url("/p?x=1"), "/p?x=***");
        assert_eq!(
            sanitize_telemetry_page_url("not a url?x=1"),
            "not a url?x=***"
        );
    }

    #[test]
    fn telemetry_page_url_is_length_capped() {
        let long = format!(
            "http://h/p?{}",
            (0..200)
                .map(|i| format!("k{i}=v{i}"))
                .collect::<Vec<_>>()
                .join("&")
        );
        let out = sanitize_telemetry_page_url(&long);
        assert_eq!(out.chars().count(), MAX_TELEMETRY_PAGE_URL_CHARS);
        assert!(out.starts_with("http://h/p?k0=***"));
    }

    #[test]
    fn query_values_are_redacted_in_free_text() {
        assert_eq!(
            redact_query_values("Resource load failed: IMG http://h/a.png?token=SECRET&size=64"),
            "Resource load failed: IMG http://h/a.png?token=***&size=***"
        );
        assert_eq!(
            redact_query_values("GET /system/user/list?phonenumber=13800000000 failed"),
            "GET /system/user/list?phonenumber=*** failed"
        );
        // 括号里的查询串：只吃值，不吃右括号
        assert_eq!(redact_query_values("(see /a?x=1)"), "(see /a?x=***)");
        // 幂等
        let once = redact_query_values("a?userName=***&y=1");
        assert_eq!(redact_query_values(&once), once);
    }

    #[test]
    fn plain_text_is_not_mangled() {
        // 无查询对：逐字符不变（含等号的散文、堆栈里的 "reading \"length\"" 都不误伤）
        for text in [
            "TypeError: Cannot read properties of undefined (reading \"length\")",
            "a=1 is not a query (no ? or & prefix)",
            "at fn (http://h/static/js/index.js:1:2)",
        ] {
            assert_eq!(redact_query_values(text), text, "误伤: {text}");
        }
        assert_eq!(redact_query_values(""), "");
    }
}
