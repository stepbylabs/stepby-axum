// stepby-axum/src/middleware/response_cache.rs
//
// P3-6：HTTP 响应缓存层
//
// 设计口径（仅对「幂等只读 GET + 白名单」的接口做缓存）：
// - 只缓存 GET 请求，POST/PUT/DELETE 一律不缓存、不读缓存（避免写透污染）。
// - 只缓存白名单中的「静态元数据」接口（字典下拉、字典按类型、参数按 key）。
//   白名单不包含任何带当前用户身份差异的接口（如 /system/user/list、
//   /system/menu/list 等），避免缓存污染登录态、权限判断与个人数据泄漏。
// - 缓存 key = "GET <path>#tid=<tid>"，TTL 默认 60s（可配置），进程内 moka 缓存。
//   多租户（§27.8）：白名单中的字典类型下拉内容随租户域变化（本租户自建类型 + 平台类型），
//   故 key 必须携带租户 ID，杜绝跨租户共享缓存导致的数据串读。
//
// 挂载位置与安全说明：
// - 作为 protected 路由栈中 auth_middleware 之后、rate_limit 之前的 route_layer（最外层之一）。
//   白名单接口为登录后可见的只读元数据，且 key 已按租户隔离，故位于鉴权之后复用安全：
//   首个请求仍需通过 auth+permission 校验并触发真实 DB 查询，之后相同 path+tid 的 GET 命中缓存
//   直接返回，既不重复鉴权也不重复查库，仅服务已登录用户（杜绝未登录可访问的疑虑）。
// - 位于压缩层（CompressionLayer，全局最外层）之内：缓存的是解压后的原始响应体，
//   压缩层对命中/未命中响应一视同仁地统一压缩，不产生 Content-Encoding 与缓存体不一致的问题。

use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use moka::future::Cache;

use crate::common::error::{AppError, ServiceError};
use crate::jwt::claims::Claims;

/// 缓存默认 TTL（60s）
const DEFAULT_TTL_SECS: u64 = 60;

/// 单条缓存响应体的体积上限（1MB）
///
/// 超出上限不缓存、放行原逻辑，避免把超大/流式响应（如导出文件）塞进内存。
const MAX_CACHED_BODY_BYTES: usize = 1024 * 1024;

/// 缓存最大条目数（防止极端情况内存膨胀；每条 ≤1MB，理论最多 ~128MB 上限）
const MAX_CACHE_ENTRIES: u64 = 128;

/// 响应缓存白名单（幂等只读 GET 的纯静态元数据接口）
///
/// 设计约束：**只缓存"变化极慢、可容忍短暂过期、无需写操作失效"的纯静态下拉**。
/// 禁止把任何会被 POST/PUT/DELETE 写操作修改的接口加入白名单——
/// 该缓存层不做"写操作→主动失效"，若缓存可变资源会读到脏数据（曾在
/// `dict/data/type/*`、`configKey/*` 上因集成测试"改删后再查命中旧缓存"而暴露）。
/// 因此白名单仅保留字典类型下拉 `optionselect`（各页面下拉框共用，字典类型变更
/// 属低频运维操作，TTL 60s 的短暂过期可接受），其余一律走原逻辑。
const WHITELIST: &[&str] = &[
    // 字典类型下拉（全量静态下拉，登录后任意用户可见，内容与用户无关；
    // 字典类型表变更极低频，短 TTL 过期可容忍）
    "/system/dict/type/optionselect",
];

/// 缓存的响应体快照
///
/// 存 body + Content-Type，返回时重建 HeaderMap，避免丢失响应类型。
#[derive(Clone)]
struct CachedResponse {
    body: Vec<u8>,
    content_type: Option<HeaderValue>,
}

/// 响应缓存句柄（Clone 廉拷贝，随 from_fn_with_state 注入中间件）
#[derive(Clone)]
pub struct ResponseCache {
    inner: Cache<String, CachedResponse>,
}

impl Default for ResponseCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(DEFAULT_TTL_SECS))
    }
}

impl ResponseCache {
    /// 以指定 TTL 构造响应缓存（route_layer 挂载处可自行配置）
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Cache::builder()
                .time_to_live(ttl)
                .max_capacity(MAX_CACHE_ENTRIES)
                .build(),
        }
    }

    /// 判断请求 path 是否命中白名单（`{...}` 段通配）
    fn is_whitelisted(&self, path: &str) -> bool {
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        WHITELIST.iter().any(|pat| {
            let pat_segs: Vec<&str> = pat.split('/').filter(|s| !s.is_empty()).collect();
            if pat_segs.len() != segs.len() {
                return false;
            }
            pat_segs
                .iter()
                .zip(&segs)
                .all(|(p, s)| p.starts_with('{') || p == s)
        })
    }
}

/// 全量读取下游响应体。
///
/// 读体失败（下游流中断 / 应用层包装故障）必须**响亮失败**：原实现
/// `to_bytes(body, usize::MAX).await.unwrap_or_default()` 会把这个失败折成
/// 空字节，于是客户端收到 **200 + 空响应体**，而且这份空 200 还会被写进缓存
/// 供后续请求复用 60s——一次流故障被固化成"元数据为空"的界面事实。
async fn read_full_body(body: Body) -> Result<Vec<u8>, ServiceError> {
    match to_bytes(body, usize::MAX).await {
        Ok(bytes) => Ok(bytes.to_vec()),
        Err(e) => {
            // 只记错误类型与描述，不带请求体/路径（C.9：结构化日志不泄漏业务数据）
            tracing::warn!(error = %e, "响应缓存：读取下游响应体失败，本次按 500 返回且不入缓存");
            Err(ServiceError::internal(&crate::tr!("error.common.internal")))
        }
    }
}

/// 响应缓存中间件
///
/// - 非 GET 或未命中白名单 → 直接放行（不读缓存、不写缓存）。
/// - 命中白名单且缓存命中 → 直接返回缓存体（含 Content-Type/Content-Length）。
/// - 命中白名单但未命中 → 放行下游；下游为 2xx 成功时按 body 存缓存，否则不缓存。
pub async fn response_cache_middleware(
    State(cache): State<ResponseCache>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // 仅缓存幂等只读 GET 且命中白名单的请求
    if method != Method::GET || !cache.is_whitelisted(&path) {
        return next.run(req).await;
    }

    // 多租户（§27.8）：key 必须携带租户 ID，否则本租户自建字典类型会被跨租户共享缓存串读。
    // 本中间件位于 auth_middleware 之后，Claims 已注入 extensions；缺失时按平台域（0）处理。
    let tid = req.extensions().get::<Claims>().map(|c| c.tid).unwrap_or(0);
    let key = format!("{} {}#tid={}", method, path, tid);

    // 1. 缓存命中：直接返回缓存体
    if let Some(cached) = cache.inner.get(&key).await {
        let body_len = cached.body.len();
        let mut resp = Response::new(Body::from(cached.body));
        if let Some(ct) = cached.content_type {
            resp.headers_mut().insert(header::CONTENT_TYPE, ct);
        }
        // 回填 Content-Length，避免与 body 实际长度不一致
        if let Ok(len) = HeaderValue::from_str(&body_len.to_string()) {
            resp.headers_mut().insert(header::CONTENT_LENGTH, len);
        }
        return resp;
    }

    // 2. 未命中：放行下游，待真实计算完成后再决定是否入缓存
    let resp = next.run(req).await;
    if !resp.status().is_success() {
        // 非 2xx（如 401/403/404）不缓存，保持原始响应
        return resp;
    }

    let (parts, body) = resp.into_parts();
    // 全量读取响应体（白名单接口为静态 JSON，体积可控），再决定是否入缓存
    let bytes = match read_full_body(body).await {
        Ok(bytes) => bytes,
        // 读体失败不缓存、也不返回「空 200」：走统一错误契约（500 + body.code/msg），
        // 前端拿到的是可重试的失败，而不是一份看起来成功的空元数据。
        Err(e) => return AppError::from(e).into_response(),
    };
    let content_type = parts.headers.get(header::CONTENT_TYPE).cloned();

    // 仅缓存未超体积上限的响应；超大/流式响应不入缓存但原样返回
    if bytes.len() <= MAX_CACHED_BODY_BYTES {
        cache
            .inner
            .insert(
                key,
                CachedResponse {
                    body: bytes.to_vec(),
                    content_type,
                },
            )
            .await;
    }

    // 用相同 parts + 已收集的 body 重建响应（保留状态码、其他响应头）
    Response::from_parts(parts, Body::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist_exact_match() {
        let cache = ResponseCache::default();
        assert!(cache.is_whitelisted("/system/dict/type/optionselect"));
        // 白名单已被收紧（仅保留纯静态下拉），可变资源接口不应命中缓存
        // （样本取**在册真旋钮** sys.index.sideTheme：拿一个已退役、库里根本没有行的键
        //   当样本，测的是空气——URL 形状相同但那条请求永远不会再发生）
        assert!(!cache.is_whitelisted("/system/config/configKey/sys.index.sideTheme"));
        assert!(!cache.is_whitelisted("/system/dict/data/type/sys_user_sex"));
    }

    #[test]
    fn test_whitelist_wildcard_match() {
        // 白名单不再含通配段：`{dictType}`/`{configKey}` 类可变资源已移出缓存
        let cache = ResponseCache::default();
        assert!(cache.is_whitelisted("/system/dict/type/optionselect"));
        assert!(!cache.is_whitelisted("/system/dict/data/type/it_type_abc"));
        assert!(!cache.is_whitelisted("/system/config/configKey/it.test.configKey"));
    }

    #[test]
    fn test_whitelist_rejects_segment_mismatch() {
        let cache = ResponseCache::default();
        // 段数不同不匹配
        assert!(!cache.is_whitelisted("/system/dict/type"));
        // 多余层级不匹配
        assert!(!cache.is_whitelisted("/system/dict/type/optionselect/extra"));
        // 非白名单路径不匹配
        assert!(!cache.is_whitelisted("/system/user/list"));
        assert!(!cache.is_whitelisted("/system/menu/list"));
        assert!(!cache.is_whitelisted("/system/dict/type/list"));
        assert!(!cache.is_whitelisted("/system/dict/data/type/sys_user_sex"));
    }

    // ============ b142 项 2：读体失败不得折成「200 + 空响应体」 ============

    #[tokio::test]
    async fn read_full_body_returns_bytes_on_success() {
        let body = Body::from("{\"code\":200}");
        let bytes = read_full_body(body).await.expect("正常响应体必须读到");
        assert_eq!(bytes, b"{\"code\":200}");
    }

    /// 缺陷形状：下游响应流在下发途中报错。原实现 `unwrap_or_default()` 会返回
    /// 一份空 200（且写进缓存 60s）；现在必须是 500 —— 前端可重试，而不是读到
    /// "字典下拉为空"这种看起来成功的元数据。
    #[tokio::test]
    async fn read_full_body_fails_loudly_when_stream_errors() {
        let stream = futures::stream::once(async {
            Err::<axum::body::Bytes, std::io::Error>(std::io::Error::other("upstream body broke"))
        });
        let err = read_full_body(Body::from_stream(stream))
            .await
            .expect_err("读体失败必须上抛，不得折成空字节");
        assert_eq!(err.code, 500, "必须走统一错误契约的 500");
        assert!(!err.message.is_empty(), "错误文案不得为空");
    }

    const SOURCE: &str = include_str!("response_cache.rs");

    fn function_body(name: &str) -> String {
        let marker = format!("fn {name}");
        let start = SOURCE
            .find(&marker)
            .unwrap_or_else(|| panic!("找不到函数 {name}（改名后本锁必须同步）"));
        let open = SOURCE[start..]
            .find('{')
            .map(|i| start + i)
            .expect("函数签名后必须有花括号");
        let mut depth = 0usize;
        for (i, ch) in SOURCE[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return SOURCE[open..=open + i].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("函数 {name} 花括号不配平");
    }

    /// 共用尺（b149 项 27 并轨）：本仓这一族此前有三份互不相等的私有谓词，
    /// 方向取**最严的并集**；下面那条测试保留本地 `unwrap_or_default()` clause，
    /// 因为"换成共用尺"不得顺手放松任何一支既有锁（b87 §6 同一条纪律）。
    fn fold_hits(body: &str) -> Vec<crate::common::fold_scan::FoldHazard> {
        crate::common::fold_scan::folds_errors_into_defaults(body)
    }

    #[test]
    fn body_read_errors_are_never_folded_into_an_empty_cache_entry() {
        let middleware = function_body("response_cache_middleware");
        assert!(
            middleware.contains("read_full_body(body).await"),
            "中间件必须经 read_full_body 读体（否则读体失败会再次被就地折叠）"
        );
        assert!(
            middleware.contains("AppError::from(e).into_response()"),
            "读体失败必须转成统一错误响应，而不是返回下游的半截响应"
        );
        assert!(
            !middleware.contains("unwrap_or_default()"),
            "`unwrap_or_default()` 会把读体失败折成空字节 ⇒ 200 + 空体被缓存"
        );
        assert!(
            fold_hits(&middleware).is_empty(),
            "共用尺在中间件里看到折叠：{:?}",
            fold_hits(&middleware)
        );
        let reader = function_body("read_full_body");
        assert!(
            !reader.contains("unwrap_or_default()"),
            "read_full_body 自己不得把失败折成成功"
        );
        assert!(
            fold_hits(&reader).is_empty(),
            "共用尺在读体函数里看到折叠：{:?}",
            fold_hits(&reader)
        );
        assert!(
            reader.contains("Err(ServiceError::internal"),
            "read_full_body 必须返回 Err（否则调用方无从区分成败）"
        );
    }

    /// 判据活性：原实现的形状必须被同一谓词抓到
    #[test]
    fn empty_cache_fold_detector_is_falsifiable() {
        let original_shape = r#"
            let (parts, body) = resp.into_parts();
            let bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();
            Response::from_parts(parts, Body::from(bytes))
        "#;
        assert!(original_shape.contains("unwrap_or_default()"));
        assert!(!original_shape.contains("read_full_body(body).await"));
        // 并且共用尺也必须抓到它（这条把"文本里含有那个词"升级成"这一型会被判红"）
        assert_eq!(
            fold_hits(original_shape).len(),
            1,
            "HEAD 的读体折叠必须被共用尺抓到"
        );
    }

    /// 共用尺那一支在本文件也必须**独立承重**：`unwrap_or(None)` 这一型不在
    /// 上面那条本地 `unwrap_or_default()` clause 的视野里，只有并集才看得见
    /// （b149 项 27；方向取并集，摘掉本地 clause 等于放松既有那把锁）。
    #[test]
    fn shared_fold_strictness_is_load_bearing_in_cache_read() {
        let blind_to_local_clause =
            "let hit: Option<String> = store.get(&cache_key).await.unwrap_or(None);\n";
        assert!(
            !blind_to_local_clause.contains("unwrap_or_default()"),
            "夹具必须落在本地 clause 的盲区里，否则证明不了新腿"
        );
        assert_eq!(fold_hits(blind_to_local_clause).len(), 1);
        // 正控：读体成功、失败上抛的形状不得被抓
        assert!(
            fold_hits("let bytes = read_full_body(body).await?;\nnext.run(req).await?\n")
                .is_empty()
        );
    }
}
