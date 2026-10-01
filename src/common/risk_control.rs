// stepby-axum/src/common/risk_control.rs
//! 登录面风控集成点（`[risk_control]`）的**纯判定内核**。
//!
//! 定位（项目准则⑥）：原判"不进本仓"的登录风控（工具型 UA 拦截 / 异地登录检测）改为
//! **提供开关 + 集成点**——本模块只做**判定**（纯函数，可证伪单测覆盖），
//! 判定结果的处置（拒绝登录 / 打 WARN / 写登录日志）由 [`crate::service::AuthService`] 承担。
//!
//! **关闭态 = 现状**：两个档位默认均为 `off` ⇒ [`ua_verdict`] 恒 `Allow`、
//! [`geo_alert`] 恒 `None`，不产生任何额外日志与审计行，与改造前逐字节等价。

use crate::config::settings::{LoginGeoAlertMode, LoginUaFilterMode};

/// 「工具型 UA」判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UaVerdict {
    /// 放行（档位 `off`、UA 未命中特征、或空 UA 在 `block` 档下放行）。
    Allow,
    /// 命中工具型 UA 特征（载荷 = 命中的**特征原文**，仅供日志，不回显给客户端）。
    BlockTool(String),
    /// 空 UA（仅 `strict` 档）。
    BlockEmpty,
}

/// 判定登录请求的 `User-Agent`。
///
/// # 规则（与 [`LoginUaFilterMode`] 的档位语义逐条对应）
///
/// - `off`：恒 [`UaVerdict::Allow`]（**默认 = 现状**）。
/// - `block`：命中 `patterns` 任一特征（**大小写无关子串**）⇒ [`UaVerdict::BlockTool`]；
///   空 UA 放行 —— 空 UA 是弱信号（HTTP/1.0 客户端、部分 SDK 与探针都不发 UA），
///   硬拦误伤面大且易被"加一个 header"绕过，故只在 `strict` 档拦截。
/// - `strict`：在 `block` 基础上**同时**拦截空 UA（[`UaVerdict::BlockEmpty`]），
///   适合"只允许浏览器登录"的封闭部署。
///
/// `patterns` 中的空串/纯空白项被忽略（避免"空特征匹配一切"的事故）。
pub fn ua_verdict(mode: LoginUaFilterMode, patterns: &[String], user_agent: &str) -> UaVerdict {
    if mode == LoginUaFilterMode::Off {
        return UaVerdict::Allow;
    }
    let ua = user_agent.trim();
    if ua.is_empty() {
        return match mode {
            LoginUaFilterMode::Strict => UaVerdict::BlockEmpty,
            _ => UaVerdict::Allow,
        };
    }
    let lower = ua.to_ascii_lowercase();
    for pattern in patterns {
        let p = pattern.trim().to_ascii_lowercase();
        if p.is_empty() {
            continue;
        }
        if lower.contains(&p) {
            return UaVerdict::BlockTool(p);
        }
    }
    UaVerdict::Allow
}

/// 取出用于「异地」比较的**粗粒度地区键**；无法得出可信键时返回 `None`（**不判定**）。
///
/// # 为什么需要"粗粒度"
///
/// 归属地来自 IP 库（ip2region xdb / MaxMind mmdb 双库混合），**城市与 ISP 会漂移**：
/// 移动网络换基站、运营商出口调整、双库命中差异都会改变城市段。若按整串比较，
/// 同一城市换运营商即误报，告警很快会被忽略。
///
/// # 规则
///
/// - 输入为 ip2region 原始管道格式（`国家|区域|省份|城市|ISP`）⇒ 取前两段**非空且非 `0`** 者；
/// - 其余格式（如 [`crate::utils::xdb_reader`] 的 `to_chinese_location()` = "国家 省份 城市"）
///   ⇒ 按空白切分取前两段；
/// - 有效段数 **< 2** ⇒ `None`（只有"中国"这种量级的信息不足以判定"异地"，宁可不判定）；
/// - 全空/全 `0` ⇒ `None`。
///
/// 取"国家 + 省份"两级：足以识别跨省/跨境登录，又不会被市内基站切换或换 ISP 触发。
pub fn coarse_region_key(location: &str) -> Option<String> {
    let raw = location.trim();
    if raw.is_empty() {
        return None;
    }
    let parts: Vec<&str> = if raw.contains('|') {
        raw.split('|').collect()
    } else {
        raw.split_whitespace().collect()
    };
    let mut kept: Vec<&str> = Vec::with_capacity(2);
    for p in parts {
        let p = p.trim();
        if p.is_empty() || p == "0" {
            continue;
        }
        kept.push(p);
        if kept.len() == 2 {
            break;
        }
    }
    if kept.len() < 2 {
        return None;
    }
    Some(kept.join(" "))
}

/// 异地判定：返回 `Some((上次地区键, 本次地区键))` 表示**应该告警**。
///
/// 只有**两侧都能得出可信地区键且不同**时才告警：
/// - 档位 `off` ⇒ `None`（默认 = 现状）；
/// - 任一侧为 `None`（首次登录 / 归属地库未命中 / 地区粒度不足）⇒ `None`（不判定，避免误报）；
/// - 两侧相同 ⇒ `None`。
///
/// 本函数**只产出告警**，从不拦截登录 —— 地区识别基于 IP 库，VPN / 运营商出口都会造成误判，
/// 拦截会变成"用户被自己锁在门外"。
pub fn geo_alert(
    mode: LoginGeoAlertMode,
    previous_location: Option<&str>,
    current_location: &str,
) -> Option<(String, String)> {
    if mode == LoginGeoAlertMode::Off {
        return None;
    }
    let prev = previous_location.and_then(coarse_region_key)?;
    let cur = coarse_region_key(current_location)?;
    if prev == cur {
        return None;
    }
    Some((prev, cur))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{LoginGeoAlertMode, LoginUaFilterMode};

    fn patterns() -> Vec<String> {
        vec!["curl/".to_string(), "python-requests/".to_string()]
    }

    /// 关闭态（默认）恒放行：UA 与地区**都不判定**
    #[test]
    fn test_off_mode_is_noop() {
        assert_eq!(
            ua_verdict(LoginUaFilterMode::Off, &patterns(), "curl/8.0.1"),
            UaVerdict::Allow,
            "off 档必须恒放行（默认 = 现状）"
        );
        assert_eq!(
            ua_verdict(LoginUaFilterMode::Off, &patterns(), ""),
            UaVerdict::Allow
        );
        assert_eq!(
            geo_alert(
                LoginGeoAlertMode::Off,
                Some("中国 广东省"),
                "中国 北京市 北京市"
            ),
            None,
            "off 档必须不产生告警（默认 = 现状）"
        );
    }

    /// `block` 档：命中特征即拦截（大小写无关、子串匹配），未命中放行
    #[test]
    fn test_block_mode_matches_case_insensitive_substring() {
        assert_eq!(
            ua_verdict(LoginUaFilterMode::Block, &patterns(), "curl/8.0.1"),
            UaVerdict::BlockTool("curl/".to_string())
        );
        assert_eq!(
            ua_verdict(
                LoginUaFilterMode::Block,
                &patterns(),
                "Mozilla/5.0 (X11) Python-Requests/2.31"
            ),
            UaVerdict::BlockTool("python-requests/".to_string()),
            "特征匹配必须大小写无关"
        );
        assert_eq!(
            ua_verdict(
                LoginUaFilterMode::Block,
                &patterns(),
                "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"
            ),
            UaVerdict::Allow
        );
    }

    /// `block` 放行空 UA（弱信号，误伤面大）；`strict` 才拦截
    #[test]
    fn test_empty_ua_only_blocked_in_strict_mode() {
        assert_eq!(
            ua_verdict(LoginUaFilterMode::Block, &patterns(), "   "),
            UaVerdict::Allow,
            "block 档空 UA 必须放行（弱信号，硬拦误伤面大）"
        );
        assert_eq!(
            ua_verdict(LoginUaFilterMode::Strict, &patterns(), ""),
            UaVerdict::BlockEmpty
        );
        assert_eq!(
            ua_verdict(LoginUaFilterMode::Strict, &patterns(), "curl/8.0.1"),
            UaVerdict::BlockTool("curl/".to_string()),
            "strict 是 block 的超集"
        );
    }

    /// 空白特征必须被忽略（否则"空特征匹配一切"会把所有登录拦死）
    #[test]
    fn test_blank_pattern_never_matches() {
        let blank = vec!["".to_string(), "   ".to_string()];
        assert_eq!(
            ua_verdict(LoginUaFilterMode::Block, &blank, "Mozilla/5.0"),
            UaVerdict::Allow,
            "空/空白特征不得匹配任何 UA"
        );
        assert_eq!(
            ua_verdict(LoginUaFilterMode::Block, &blank, "curl/8.0.1"),
            UaVerdict::Allow,
            "空特征清单 ⇒ 无特征可命中"
        );
    }

    /// 粗粒度地区键：管道格式与空白格式都取"国家 + 省份"，粒度不足则 `None`
    #[test]
    fn test_coarse_region_key() {
        // ip2region 原始管道格式：国家|区域|省份|城市|ISP ⇒ 国家 + 省份（区域 0 被跳过）
        assert_eq!(
            coarse_region_key("中国|0|广东省|深圳市|电信").as_deref(),
            Some("中国 广东省")
        );
        // to_chinese_location() 的空白格式
        assert_eq!(
            coarse_region_key("中国 广东省 深圳市").as_deref(),
            Some("中国 广东省")
        );
        // 粒度不足（仅国家/仅省份）⇒ 不判定
        assert_eq!(coarse_region_key("中国"), None, "仅国家不足以判定异地");
        assert_eq!(coarse_region_key("中国 "), None);
        assert_eq!(coarse_region_key("中国|0|0|0|0"), None);
        assert_eq!(coarse_region_key(""), None);
        assert_eq!(coarse_region_key("   "), None);
        assert_eq!(coarse_region_key("0"), None);
    }

    /// 异地告警：同省份不告警（即使城市/ISP 不同）；跨省份告警；任一侧未知不告警
    #[test]
    fn test_geo_alert_semantics() {
        let mode = LoginGeoAlertMode::Alert;
        // 同省不同城/不同 ISP ⇒ 不告警（城市与 ISP 漂移是常态，告警会变噪音）
        assert_eq!(
            geo_alert(
                mode,
                Some("中国|0|广东省|深圳市|电信"),
                "中国|0|广东省|广州市|联通"
            ),
            None
        );
        // 同省且一侧信息更细 ⇒ 不告警（取前两级后相等）
        assert_eq!(
            geo_alert(mode, Some("中国 广东省"), "中国 广东省 深圳市"),
            None
        );
        // 跨省 ⇒ 告警，载荷为两侧的粗粒度键
        assert_eq!(
            geo_alert(mode, Some("中国 广东省 深圳市"), "中国 北京市 北京市"),
            Some(("中国 广东省".to_string(), "中国 北京市".to_string()))
        );
        // 首次登录（无上一次）⇒ 不告警
        assert_eq!(geo_alert(mode, None, "中国 广东省 深圳市"), None);
        // 本次或上次归属地未命中/粒度不足 ⇒ 不告警（避免误报）
        assert_eq!(geo_alert(mode, Some(""), "中国 广东省 深圳市"), None);
        assert_eq!(geo_alert(mode, Some("中国 广东省 深圳市"), ""), None);
        assert_eq!(geo_alert(mode, Some("中国 广东省"), "中国"), None);
    }
}
