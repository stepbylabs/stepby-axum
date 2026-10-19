// stepby-axum/src/middleware/uri_limit.rs
//! 请求行（URI + 查询串）与请求头长度上限（批七十四 B2 起，批七十五 B7 扩到请求头）。
//!
//! 为什么需要它：`DefaultBodyLimit` 只管**请求体**，查询串完全在它的作用域之外；
//! 实测（本批集成探测）改造前 59KB 的查询串照样 HTTP 200 进业务层。查询串里的
//! LIKE 过滤参数虽已由 `common::like_escape` 的单值 100 字符兜底封顶，但
//! "参数个数不限" 同样是一条免费放大器：`?title=a&title=b&…` 重复上千次即可让
//! 解析层与逐条过滤条件线性膨胀（无鉴权也能打，属自伤面）。
//!
//! ## 口径
//!
//! - `[server].max_uri_bytes` 默认 **16384**（16 KiB）。这不是"改变现状"，而是把
//!   hyper 一直在隐性承担的东西显式化：合法请求的查询串在本仓最长约 1 KB 量级
//!   （分页 + 时间范围 + 多值筛选），16 KiB 有 15 倍余量；
//! - `[server].max_header_bytes` 默认 **65536**（64 KiB），同理是把 hyper 的隐性上界
//!   收紧（见下"hyper 自己承担了什么"）；
//! - 两者取 **0** = 完全不设限（等价改造前行为），供确有超长 URL / 巨型 Cookie 的
//!   集成方显式回退；
//! - 超限返回 **414 / 431** + 统一错误体（C.8，[`crate::common::response::transport_error`]），并在日志里
//!   **只记长度与条数**——查询串常含 token / 验证码 / 用户输入，请求头含
//!   Authorization / Cookie，都不得进日志（C.9）。
//!
//! ## 计量对象是"请求行"而不是"路径+查询串"（批七十五 B7）
//!
//! `Uri::path_and_query()` 只覆盖 origin-form（`/a/b?c=1`）。请求行还可以是
//! **absolute-form**（`GET http://host/a?b=1`，代理转发的标准形态）与
//! **authority-form**（`CONNECT host:443`）。只量 `path_and_query` 时，absolute-form
//! 里的 `http://host` 整段**不计入**（实测少算恰好一段 scheme+authority），
//! authority-form 更是**恒为 0** ⇒ 换个请求行写法就绕过上限。故判据量**完整
//! request-target**（`request_target_len()`，本模块 `pub(crate)` 项，不进公开文档链接），
//! 与 `uri.to_string()` 逐形态双向对账。
//! options-form（`OPTIONS *`）实测新旧口径都是 1，不在被绕过之列。
//!
//! ## hyper 自己承担了什么（写清边界，避免夸大这道闸的效力）
//!
//! 本守卫跑在 **hyper 解析之后**，它挡的是"已经解析成功但过大"的请求进入业务层
//! （参数解析、oper_log 记录、trace/span 复制等），**不是**解析器层的内存上限。
//! 解析器层的上界由 hyper 决定，而 `axum::serve` 不暴露 `ServeConfig`
//! （同 [`crate`] 的 Slowloris 说明，见 `src/main.rs`），本仓因此沿用其默认值：
//! - 请求头**条数**：`DEFAULT_MAX_HEADERS = 100`（`hyper-1.12.0/src/proto/h1/role.rs:31`），
//!   超出即 `431`（同文件 `:500` 的 `Parse::TooLarge → REQUEST_HEADER_FIELDS_TOO_LARGE`）；
//! - 整个请求头块（含请求行）的**字节**：读缓冲上界
//!   `DEFAULT_MAX_BUFFER_SIZE = 8192 + 4096 × 100 = 417792`（约 408 KiB，
//!   `hyper-1.12.0/src/proto/h1/io.rs:23`），`h1_max_header_size` 默认未设。
//!
//! 所以"条数"这一维**刻意不做应用层开关**：应用层再限一条会与 hyper 的 100 并存，
//! 正是 C.7 禁止的"两边都能改但行为不一致"；字节这一维 hyper 默认 408 KiB 过松，
//! 才由本模块收紧到可配档位。

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::AppState;

/// 超限判据的**唯一实现**（中间件与单测共用，不允许两处各写一份比较式）
///
/// `limit == 0` = 完全不设限；等于上限放行（"超限"才拒）。
pub(crate) fn is_over_limit(len: usize, limit: usize) -> bool {
    limit > 0 && len > limit
}

/// 请求行 request-target 的字节数。
///
/// 形态与算法：
/// - **origin-form**（`/a/b?c=1`，本仓 99.9% 的请求）：零分配直接取 `path_and_query`；
/// - **其余形态**（absolute-form `http://host/a?b=1`、authority-form `host:443`、
///   options-form `*`）：交给 `Uri` 的 Display 序列化整条目标。
///
/// 为什么不能一律用 `path_and_query`（B7 根因）：它只覆盖 origin-form，
/// absolute-form 的 `http://host` 整段**不计入**、authority-form（CONNECT）恒为 0，
/// 换一种请求行写法就绕过上限。罕见形态多一次 String 分配是**故意的**：
/// 宁可少优化，也不留下"计量面看不见的那一段输入"。
/// 两向等价由 `request_target_len_matches_serialized_uri` 逐形态钉住。
pub(crate) fn request_target_len(uri: &Uri) -> usize {
    match (uri.scheme_str(), uri.authority(), uri.path_and_query()) {
        (None, None, Some(pq)) => pq.as_str().len(),
        _ => uri.to_string().len(),
    }
}

/// 请求头净字节数：名 + 值逐条求和（不含 `: ` 与 CRLF 分隔符——口径写进错误文案与
/// 配置注释，避免"应用层算的比 hyper 算的少几个字节"被当成缺陷）。
pub(crate) fn header_bytes(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len())
        .sum()
}

/// 中间件层拒绝的统一错误体见 [`crate::common::response::transport_error`]（C.8）：
/// HTTP 状态与 `body.code` 恒等，msg 为本地化文本，且**不经** `map_status`
/// （`legacy` 档会把 414/431 映射成 200——传输层拒绝没有业务码，这个 200 是纯失真）。
///
/// 请求行 / 请求头长度上限守卫（挂在 locale 之内、request_id 之外，使错误文案能吃到协商后的 locale）
pub async fn uri_length_guard(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    use crate::common::response::transport_error;

    let cfg = &state.config.server;
    let uri_limit = cfg.max_uri_bytes as usize;
    let header_limit = cfg.max_header_bytes as usize;
    // 不打印请求行内容：查询串常含 token / 验证码 / 用户输入，只记长度（C.9）
    let uri_len = request_target_len(req.uri());
    if is_over_limit(uri_len, uri_limit) {
        tracing::warn!(
            uri_len,
            limit = uri_limit,
            method = %req.method(),
            "请求行超长已被拒绝（414）"
        );
        return transport_error(
            StatusCode::URI_TOO_LONG,
            crate::tr!("error.common.uri_too_long", limit = uri_limit),
        );
    }
    // 请求头同族闸门（批七十五 B7）。判据顺序：先请求行后请求头——请求行是"更小的一面"，
    // 先量它才能让 414 的归因保持精确（两个都超限时报 414，与实际先命中的检查一致）。
    let h_len = header_bytes(req.headers());
    if is_over_limit(h_len, header_limit) {
        // 只记字节数与条数：Authorization / Cookie 的**值**绝不能进日志（C.9）
        tracing::warn!(
            header_bytes = h_len,
            header_count = req.headers().len(),
            limit = header_limit,
            method = %req.method(),
            "请求头过大已被拒绝（431）"
        );
        return transport_error(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            crate::tr!("error.common.header_too_long", limit = header_limit),
        );
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn zero_means_unlimited() {
        assert!(
            !is_over_limit(usize::MAX / 2, 0),
            "0 = 完全不设限（集成方回退口径）"
        );
    }

    #[test]
    fn boundary_is_inclusive_of_equal_length() {
        // 恰好等于上限必须放行（"超限"才是拒绝条件），否则会把合法请求挡掉
        assert!(!is_over_limit(100, 100));
        assert!(is_over_limit(101, 100));
    }

    /// 四种 request-target 形态必须**全部**算对，且与序列化结果逐字节一致。
    ///
    /// 这是 B7 的根因锁：`path_and_query` 只看得见 origin-form，
    /// absolute-form 的 `http://host` 整段与 authority-form（CONNECT）全串都在计量面之外。
    #[test]
    fn request_target_len_matches_serialized_uri() {
        let cases = [
            "/system/user/list?pageSize=10",
            "http://example.com/system/user/list?pageSize=10&title=aaaa",
            "http://example.com/a/b/c",
            "example.com:443",
            "*",
            "/",
        ];
        for raw in cases {
            let uri: Uri = raw
                .parse()
                .unwrap_or_else(|e| panic!("{raw} 应为合法 URI: {e}"));
            assert_eq!(
                request_target_len(&uri),
                uri.to_string().len(),
                "{raw} 的计量必须等于完整请求行目标（少算一段即绕过上限）"
            );
            // 非零探针：任何形态都必须有**非零**计量，否则"超限判据"对它形同虚设
            assert!(
                request_target_len(&uri) > 0,
                "{raw} 计量为 0 ⇒ 这道闸对它不存在（旧口径在 authority/options-form 正是此形）"
            );
        }

        // 控制组（变异证伪）：absolute-form 用旧口径（只量 path_and_query）确实**少算**，
        // 少算的量恰好是 scheme+authority —— 这就是"换个请求行写法就绕过上限"的数值证据。
        let abs: Uri = "http://example.com/x?y=zzzzzzzzzz".parse().unwrap();
        let only_pq = abs
            .path_and_query()
            .map(|pq| pq.as_str().len())
            .unwrap_or(0);
        assert_eq!(
            request_target_len(&abs) - only_pq,
            "http://example.com".len(),
            "控制组失效：旧口径应恰好少算 scheme+authority，否则本判据测不到东西\
            （旧 {only_pq} vs 新 {}）",
            request_target_len(&abs)
        );
    }

    #[test]
    fn header_bytes_counts_names_and_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str("Bearer abcdef").unwrap(),
        );
        // 13（authorization）+ 13（Bearer abcdef）
        assert_eq!(header_bytes(&headers), 26);
        headers.append("cookie", HeaderValue::from_str("a=1").unwrap());
        // + 6（cookie）+ 3（a=1）
        assert_eq!(
            header_bytes(&headers),
            35,
            "重复同名头必须逐条计入（否则可绕）"
        );
    }

    #[test]
    fn default_limits_have_headroom_over_real_requests() {
        // 默认档必须远高于真实最长查询串，否则这是"为安全把合法请求挡掉"的缺陷
        let default = crate::config::settings::default_max_uri_bytes();
        assert_eq!(
            default, 16384,
            "默认上限变更需同步 config.toml.example 与本文档"
        );
        // 本仓最长的一类查询：分页 + 排序 + 时间范围 + 多值筛选（含 params[beginTime] 形态）
        let longest_real = "pageNum=1&pageSize=1000&orderByColumn=createTime&isAsc=desc&params%5BbeginTime%5D=2026-01-01%2000%3A00%3A00&params%5BendTime%5D=2026-12-31%2023%3A59%3A59&title=".to_string() + &"x".repeat(100);
        assert!(
            longest_real.len() * 10 <= default as usize,
            "默认上限对最长真实查询串（{} 字节）的余量不足 10 倍",
            longest_real.len()
        );

        // 请求头默认档：既要比 hyper 的解析器上界（417792）紧，又要给合法请求留足余量
        let hdr_default = crate::config::settings::default_max_header_bytes();
        assert_eq!(
            hdr_default, 65536,
            "默认请求头上限变更需同步 config.toml.example 与本文档"
        );
        assert!(
            (hdr_default as f64) < 417792.0,
            "应用层上限必须严于 hyper 的读缓冲默认上界，否则这道闸没有意义"
        );
        // 真实最长的一面：JWT（~2KB）+ Cookie + UA/Origin/Referer 等 ≈ 4KB 量级
        let longest_real_headers = 4096;
        assert!(
            longest_real_headers * 10 <= hdr_default as usize,
            "默认请求头上限对真实用量（约 {longest_real_headers} 字节）的余量不足 10 倍"
        );
    }

    /// 统一错误体的形状契约：HTTP 状态 == `body.code`，msg 是本地化文本而非键名。
    ///
    /// `tr!` 只接受字面量键，故三个出口逐条写出（键拼错在这里就是红灯，不会静默）。
    #[test]
    fn transport_error_body_shape_is_unified() {
        use crate::common::response::transport_error;

        let cases = [
            (
                StatusCode::URI_TOO_LONG,
                crate::tr!("error.common.uri_too_long", limit = 16384),
            ),
            (
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                crate::tr!("error.common.header_too_long", limit = 65536),
            ),
            (
                StatusCode::REQUEST_TIMEOUT,
                crate::tr!("error.common.request_timeout"),
            ),
            (
                StatusCode::NOT_FOUND,
                crate::tr!("error.common.route_not_found"),
            ),
        ];
        for (status, msg) in cases {
            assert!(
                !msg.starts_with("error."),
                "键查无文案（返回键名＝键没落在正确的节下）: {msg}"
            );
            assert!(!msg.contains("%{"), "插值未生效: {msg}");
            let resp = transport_error(status, msg.clone());
            assert_eq!(resp.status(), status, "HTTP 状态必须原样");
        }
    }

    /// 取舍钉住：传输层拒绝**不得**经 `map_status` —— `legacy` 档会把 414/431 映射成 200。
    #[test]
    fn transport_rejection_status_is_convention_independent() {
        use crate::common::http_status::{HttpStatusConvention, map_status};
        for code in [408i32, 414, 431] {
            assert_eq!(
                map_status(code, HttpStatusConvention::Legacy),
                StatusCode::OK,
                "{code} 不在 legacy 已知码表内 ⇒ 正因为如此它才必须绕开 map_status"
            );
            assert_eq!(
                map_status(code, HttpStatusConvention::Restful),
                StatusCode::from_u16(code as u16).unwrap(),
                "restful 档才给真实状态"
            );
        }
    }
}
