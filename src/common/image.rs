// axum-backend/src/common/image.rs

//! 图片格式识别工具（C13：从 common_handler / sys_user_handler 抽出的公共方法）

/// 通过文件头 magic bytes 识别图片真实格式
///
/// 返回标准化扩展名（小写）：
/// - JPEG: FF D8 FF
/// - PNG: 89 50 4E 47 0D 0A 1A 0A
/// - GIF: 47 49 46 38 (37/39)
pub(crate) fn detect_image_ext(bytes: &[u8]) -> Option<String> {
    // JPEG: FF D8 FF
    if bytes.len() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF {
        return Some("jpg".to_string());
    }
    // PNG: 89 50 4E 47 0D 0A 1A 0A（需 8 字节）
    if bytes.len() >= 8
        && bytes[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    {
        return Some("png".to_string());
    }
    // GIF: 47 49 46 38 (37/39)（需 5 字节）
    if bytes.len() >= 5
        && bytes[0..4] == [0x47, 0x49, 0x46, 0x38]
        && (bytes[4] == 0x37 || bytes[4] == 0x39)
    {
        return Some("gif".to_string());
    }
    None
}

/// 标准化扩展名（jpeg → jpg）
pub(crate) fn normalize_ext(ext: &str) -> String {
    let lower = ext.to_lowercase();
    match lower.as_str() {
        "jpeg" => "jpg".to_string(),
        _ => lower,
    }
}
