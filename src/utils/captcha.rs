// axum-backend/src/utils/captcha.rs

use captcha::Captcha;
use captcha::filters::{Dots, Noise, Wave};
use uuid::Uuid;

/// 验证码结果
pub struct CaptchaResult {
    /// 验证码 key（存 Redis，TTL 5 分钟）
    pub uuid: String,
    /// Base64 图片（不含 data:image/png;base64, 前缀）
    pub img_base64: String,
    /// 验证码明文（存 Redis 用于校验）
    pub code: String,
}

/// 生成 5 位字母数字验证码（使用 captcha 1.0 API）
///
/// 安全加固：
/// - 字符集排除易混淆字符（0/O、1/I/L），32 字符
/// - 长度 5 位（组合空间 32^5 ≈ 3300 万）
/// - 多重滤镜叠加：Noise(0.5) + Wave 扭曲 + Dots 干扰点，有效抵御 OCR 识别
/// - captcha 1.0 关键变化：
///   - add_chars(n) 返回 &mut Self（不再返回 String），通过 chars_as_string() 获取明文
///   - view(w, h) 需要指定宽高
///   - as_base64() 直接返回 Option<String>（无需手动 base64 编码）
///   - Noise::new(strength) 需要强度参数
///
/// 已知 bug 修复：captcha 1.0 的 `add_char()` 在字体不支持某字符的 PNG 时静默跳过
/// （`random_char_as_image` 返回 None 时 `chars.push` 不执行），导致 `add_chars(5)`
/// 实际添加的字符数可能少于 5。修复方式：循环添加直到达到目标长度，最多重试 20 次
/// 避免无限循环（理论上 32 字符集中全部不被字体支持才会触发）。
pub fn generate_captcha() -> CaptchaResult {
    let mut captcha = Captcha::new();
    captcha.set_chars(
        &"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            .chars()
            .collect::<Vec<_>>(),
    );

    // 修复 captcha 1.0 bug：add_chars(5) 可能因字体不支持某些字符而少于 5 位
    // 循环添加直到达到 5 位，最多重试 20 次避免无限循环
    let target_len = 5usize;
    let mut retries = 0;
    while captcha.chars_as_string().len() < target_len && retries < 20 {
        captcha.add_char();
        retries += 1;
    }

    // 多重滤镜叠加，增强抗 OCR 能力
    captcha.apply_filter(Noise::new(0.5));
    captcha.apply_filter(Wave::new(2.0, 8.0).horizontal());
    captcha.apply_filter(Wave::new(3.0, 6.0).vertical());
    captcha.apply_filter(Dots::new(5).min_radius(2).max_radius(4));
    captcha.view(
        crate::common::constants::CAPTCHA_IMG_WIDTH,
        crate::common::constants::CAPTCHA_IMG_HEIGHT,
    );

    let code = captcha.chars_as_string();
    let img_base64 = captcha.as_base64().unwrap_or_default();
    let uuid = Uuid::new_v4().to_string();

    // 兜底：如果经过重试仍然不足 5 位（极端情况），用随机字符补齐
    let code = if code.len() < target_len {
        let charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let mut chars: Vec<char> = code.chars().collect();
        use rand::Rng;
        let mut rng = rand::thread_rng();
        while chars.len() < target_len {
            // charset 均为 ASCII 字符，as_bytes() 索引安全且比 chars().nth() 高效
            let bytes = charset.as_bytes();
            let idx = rng.gen_range(0..bytes.len());
            chars.push(char::from(bytes[idx]));
        }
        chars.into_iter().collect()
    } else {
        code
    };

    CaptchaResult {
        uuid,
        img_base64,
        code,
    }
}

#[cfg(test)]
mod tests {
    use super::generate_captcha;

    #[test]
    fn test_captcha_code_length() {
        // 验证修复后验证码长度始终为 5
        for _ in 0..crate::common::constants::CAPTCHA_NOISE_DOTS {
            let result = generate_captcha();
            assert_eq!(
                result.code.len(),
                5,
                "验证码长度应为 5，实际为 {}：{}",
                result.code.len(),
                result.code
            );
            assert!(!result.img_base64.is_empty(), "图片 base64 不应为空");
            assert!(!result.uuid.is_empty(), "uuid 不应为空");
        }
    }

    #[test]
    fn test_captcha_charset() {
        // 验证验证码只包含允许的字符
        let allowed = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        for _ in 0..50 {
            let result = generate_captcha();
            for c in result.code.chars() {
                assert!(
                    allowed.contains(c),
                    "验证码包含不允许的字符 {}：{}",
                    c,
                    result.code
                );
            }
        }
    }
}
