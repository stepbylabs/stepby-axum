// backend-axum/src/common/http_status.rs
//! P2-33：HTTP 状态码约定（`legacy` | `restful`）—— 原「定案跳过」改为**默认关的开关**。
//!
//! ## 背景：为什么当初"跳过"，现在为什么又做成开关
//!
//! `spec.md` 4.1.3/4.1.4 两次以"关键"标注「HTTP 状态码统一 200」，并要求与前端 100% 对齐；
//! 而 `AppError::into_response`（R19-4.3）已按**已知业务码**映射真实 HTTP 状态、未知码回落 200。
//! 两条口径并存：生态一致性（同类后台多为 200+body.code）与可观测性（真实状态码便于网关/监控）
//! **各有正当场景**，属"用户该自己选"的配置项（项目准则①③⑥），而非应当替用户一锤定音的判断。
//!
//! 因此本模块只做两件事：
//! 1. 把"已知码映射"抽成**纯函数**（可单测、无全局副作用）；
//! 2. 提供 `restful` 档：**绝不返回 200 表示业务失败**，未归类业务码一律 `400`
//!    （本仓业务自定义码如 `1003`（TOTP）语义上都是"请求未被接受"，归 400 而非 500）。
//!
//! ## 两档语义（默认值 = 现状）
//!
//! | 档位 | 已知码（400/401/403/404/409/422/429/500/503） | 其它业务码（含 2xx / 601 / 1003 / 0） |
//! |---|---|---|
//! | `legacy`（**默认 = 现状**） | 映射为同名真实 HTTP 状态 | `200 OK`（保持原行为，不破坏非标准业务码） |
//! | `restful` | 同上 | **绝不 200**：标准 HTTP 域（400..=599）取该状态；2xx 取 `200`；其余取 `400` |
//!
//! 关闭态（`legacy`）与改造前**逐字节等价** ⇒ 存量部署零回归。
//!
//! ## 为什么用全局原子量而非把 settings 传进 `IntoResponse`
//!
//! `IntoResponse` 是 trait 方法，签名不含应用状态，无法注入 `Settings`。
//! 故与能力位（`platform_features()`）同法：启动期一次性写入全局，运行期只读。

use std::sync::atomic::{AtomicU8, Ordering};

use axum::http::StatusCode;

/// 合法档位字面量（字典序：`legacy` < `restful`）
pub const HTTP_STATUS_CONVENTIONS: &[&str] = &["legacy", "restful"];

/// HTTP 状态码约定档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpStatusConvention {
    /// **默认 = 现状**：已知业务码映射真实状态，未知码回落 200（R19-4.3）。
    #[default]
    Legacy,
    /// 严格：业务失败一律不返回 200（未归类码按 400 归类）。
    Restful,
}

impl HttpStatusConvention {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Restful => "restful",
        }
    }

    /// 解析档位字面量；**非法值回落 [`Self::Legacy`]（fail-safe：默认 = 现状）**并打 WARN。
    ///
    /// 刻意不 fail-closed 拒绝启动：状态码约定是**展示层**取向，误配不应让服务起不来；
    /// 回落"现状"是最不意外的选择（与 `TenantFilterMode` / `AcmeMode` 同口径）。
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "legacy" => Self::Legacy,
            "restful" => Self::Restful,
            other => {
                tracing::warn!(
                    value = %other,
                    "server.http_status_convention 非法（合法值 {:?}），已回落 legacy（= 现状）",
                    HTTP_STATUS_CONVENTIONS
                );
                Self::Legacy
            }
        }
    }
}

/// 全局档位（0 = legacy，1 = restful）。默认 0 ⇒ 与改造前一致。
static CONVENTION: AtomicU8 = AtomicU8::new(0);

/// 档位 → 原子存储值（**纯函数**，可单测；避免"编码/解码不互逆"这类静默错配）。
pub const fn encode(convention: HttpStatusConvention) -> u8 {
    match convention {
        HttpStatusConvention::Legacy => 0,
        HttpStatusConvention::Restful => 1,
    }
}

/// 原子存储值 → 档位（**纯函数**；未知值一律回落 `Legacy` = 现状，fail-safe）。
pub const fn decode(raw: u8) -> HttpStatusConvention {
    match raw {
        1 => HttpStatusConvention::Restful,
        _ => HttpStatusConvention::Legacy,
    }
}

/// 测试期全局互斥锁：档位是**进程级**状态，测试中任何"写全局"的动作都必须持锁，
/// 否则并行用例之间会互相污染（偶发红灯）。生产路径写全局只发生在启动期一次，无需加锁。
#[cfg(test)]
pub static CONVENTION_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 启动期写入全局档位（由 `initialize` 调用）。
pub fn set_convention(convention: HttpStatusConvention) {
    CONVENTION.store(encode(convention), Ordering::Relaxed);
}

/// 读取当前档位（`IntoResponse` 热路径，Relaxed 足够：仅一个字节的取向标记）。
pub fn convention() -> HttpStatusConvention {
    decode(CONVENTION.load(Ordering::Relaxed))
}

/// 业务码 → HTTP 状态（**纯函数**，两档差异集中于此，便于可证伪单测）。
pub fn map_status(code: i32, convention: HttpStatusConvention) -> StatusCode {
    match convention {
        HttpStatusConvention::Legacy => legacy_status(code),
        HttpStatusConvention::Restful => restful_status(code),
    }
}

/// `legacy`（= 现状）：已知业务码映射同名真实状态，其余（含 200/自定义码）回落 200。
fn legacy_status(code: i32) -> StatusCode {
    match code {
        400 => StatusCode::BAD_REQUEST,
        401 => StatusCode::UNAUTHORIZED,
        403 => StatusCode::FORBIDDEN,
        404 => StatusCode::NOT_FOUND,
        409 => StatusCode::CONFLICT,
        422 => StatusCode::UNPROCESSABLE_ENTITY,
        429 => StatusCode::TOO_MANY_REQUESTS,
        500 => StatusCode::INTERNAL_SERVER_ERROR,
        503 => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::OK,
    }
}

/// `restful`：已知码同 `legacy`；**未归类业务码绝不回落 200**。
///
/// 归类规则（刻意简单、可预测）：
/// - 标准 HTTP 错误域 `400..=599` ⇒ 取该状态码本身（如 `418` → 418）；
/// - `2xx` ⇒ `200`（AppError 理论上不携带成功码，保留安全语义）；
/// - 其余（`0` / `1` / `601` / `1003` / 负数 …）⇒ `400`：本仓自定义业务码语义均为
///   "请求未被接受"（如 `1003` = TOTP 需验证码/验证码错误），归 400 而非 500。
fn restful_status(code: i32) -> StatusCode {
    if (400..=599).contains(&code)
        && let Ok(status) = StatusCode::from_u16(code as u16)
    {
        return status;
    }
    if (200..300).contains(&code) {
        return StatusCode::OK;
    }
    StatusCode::BAD_REQUEST
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 档位解析：合法值双向映射；大小写/空白容忍；非法值回落 legacy（fail-safe）
    #[test]
    fn test_convention_parse() {
        assert_eq!(
            HttpStatusConvention::parse("legacy"),
            HttpStatusConvention::Legacy
        );
        assert_eq!(
            HttpStatusConvention::parse("restful"),
            HttpStatusConvention::Restful
        );
        assert_eq!(
            HttpStatusConvention::parse("  RESTFUL  "),
            HttpStatusConvention::Restful
        );
        for bad in ["", "strict", "rest", "1", "off"] {
            assert_eq!(
                HttpStatusConvention::parse(bad),
                HttpStatusConvention::Legacy,
                "{bad:?} 非法值必须回落 legacy（默认=现状）"
            );
        }
        assert_eq!(
            HttpStatusConvention::default(),
            HttpStatusConvention::Legacy,
            "默认档必须是 legacy"
        );
        assert_eq!(HttpStatusConvention::Legacy.as_str(), "legacy");
        assert_eq!(HttpStatusConvention::Restful.as_str(), "restful");
    }

    /// **可证伪：`legacy` 与改造前逐字节等价**——已知码映射、未知码回落 200。
    #[test]
    fn test_legacy_matches_pre_change_behaviour() {
        for (code, expected) in [
            (400, StatusCode::BAD_REQUEST),
            (401, StatusCode::UNAUTHORIZED),
            (403, StatusCode::FORBIDDEN),
            (404, StatusCode::NOT_FOUND),
            (409, StatusCode::CONFLICT),
            (422, StatusCode::UNPROCESSABLE_ENTITY),
            (429, StatusCode::TOO_MANY_REQUESTS),
            (500, StatusCode::INTERNAL_SERVER_ERROR),
            (503, StatusCode::SERVICE_UNAVAILABLE),
        ] {
            assert_eq!(
                map_status(code, HttpStatusConvention::Legacy),
                expected,
                "legacy 下 {code} 应映射为 {expected}"
            );
        }
        // 未归类码在 legacy 下仍是 200（这就是"现状"，不能被 restful 语义污染）
        for code in [200, 201, 418, 601, 1003, 0, -1] {
            assert_eq!(
                map_status(code, HttpStatusConvention::Legacy),
                StatusCode::OK,
                "legacy 下未归类码 {code} 必须回落 200（= 改造前行为）"
            );
        }
    }

    /// **可证伪：`restful` 下业务失败绝不返回 200**，且自定义码归 400 而非 500。
    #[test]
    fn test_restful_never_returns_200_for_failures() {
        // 已知码与 legacy 同映射
        assert_eq!(
            map_status(403, HttpStatusConvention::Restful),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            map_status(503, HttpStatusConvention::Restful),
            StatusCode::SERVICE_UNAVAILABLE
        );
        // 标准域内非通用码取自身
        assert_eq!(
            map_status(418, HttpStatusConvention::Restful),
            StatusCode::IM_A_TEAPOT
        );
        // 自定义业务码（TOTP 1003 / 其他非标准码）⇒ 400，绝不 200，也不误判 500
        for code in [601, 1003, 1, 0, -1] {
            assert_eq!(
                map_status(code, HttpStatusConvention::Restful),
                StatusCode::BAD_REQUEST,
                "restful 下自定义业务失败码 {code} 应归 400（请求未被接受）"
            );
        }
        // 2xx 业务码保留成功语义（AppError 理论不携带；若携带亦不得变成 4xx）
        assert_eq!(
            map_status(200, HttpStatusConvention::Restful),
            StatusCode::OK
        );
    }

    /// 全局档位：默认 legacy（读默认值，不写全局 ⇒ 与并行用例互不干扰）；
    /// `encode`/`decode` 互逆性单独可证伪；set 后的读回行为在 `error.rs` 的状态码用例中
    /// 以互斥锁保护后验证。
    #[test]
    fn test_global_convention_default_and_encoding() {
        // 纯函数：编码/解码互逆，未知编码回落 legacy
        for c in [HttpStatusConvention::Legacy, HttpStatusConvention::Restful] {
            assert_eq!(decode(encode(c)), c, "encode/decode 必须互逆");
        }
        assert_eq!(decode(255), HttpStatusConvention::Legacy);
        assert_eq!(
            encode(HttpStatusConvention::Legacy),
            0,
            "legacy 必须编码为 0（原子量默认值）"
        );
        // 默认档：原子量初值 0 ⇒ 未初始化时必须是 legacy（= 现状）
        assert_eq!(convention(), HttpStatusConvention::Legacy);
    }

    /// 写入后读回一致（持互斥锁，避免与其他读全局的用例互相污染），并复位为 legacy。
    #[test]
    fn test_set_convention_roundtrip_under_lock() {
        let _guard = CONVENTION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let original = convention();
        set_convention(HttpStatusConvention::Restful);
        assert_eq!(convention(), HttpStatusConvention::Restful);
        set_convention(HttpStatusConvention::Legacy);
        assert_eq!(convention(), HttpStatusConvention::Legacy);
        set_convention(original);
    }

    /// 常量清单与枚举双向一致（防止新增档位时漏改字面量表）
    #[test]
    fn test_modes_list_matches_enum() {
        assert_eq!(HTTP_STATUS_CONVENTIONS.len(), 2);
        for raw in HTTP_STATUS_CONVENTIONS {
            let parsed = HttpStatusConvention::parse(raw);
            assert_eq!(
                parsed.as_str(),
                *raw,
                "{raw} 必须能被 parse 且原样回写（字面量表与枚举漂移）"
            );
        }
    }
}
