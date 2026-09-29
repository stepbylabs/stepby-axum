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
use axum::response::Response;
use moka::future::Cache;

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
    let bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();
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
        assert!(!cache.is_whitelisted("/system/config/configKey/sys.index.skinName"));
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
}
