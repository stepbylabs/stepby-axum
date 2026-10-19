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
}
