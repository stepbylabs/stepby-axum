// stepby-axum/src/common/image.rs

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
    if bytes.len() >= 8 && bytes[0..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
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

#[cfg(test)]
mod tests {
    //! 覆盖意图：图片格式识别（magic bytes → jpg/png/gif）、字节长度不足/未知格式返回
    //! None，以及扩展名标准化（jpeg→jpg、大小写归一、其它原样保留）。

    use super::*;

    const JPG: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0x00];
    const PNG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
    const GIF87A: &[u8] = &[0x47, 0x49, 0x46, 0x38, 0x37, 0x61];
    const GIF89A: &[u8] = &[0x47, 0x49, 0x46, 0x38, 0x39, 0x61];

    #[test]
    fn detect_image_ext_recognizes_jpeg_png_gif() {
        assert_eq!(detect_image_ext(JPG).as_deref(), Some("jpg"));
        assert_eq!(detect_image_ext(PNG).as_deref(), Some("png"));
        assert_eq!(detect_image_ext(GIF87A).as_deref(), Some("gif"));
        assert_eq!(detect_image_ext(GIF89A).as_deref(), Some("gif"));
    }

    #[test]
    fn detect_image_ext_requires_minimum_length() {
        // JPEG 需 3 字节：2 字节前缀不算 JPEG
        assert_eq!(detect_image_ext(&JPG[..2]), None);
        // PNG 需 8 字节：前缀相同但截断到 7 字节 → None
        assert_eq!(detect_image_ext(&PNG[..7]), None);
        // GIF 需 5 字节（含 37/39）：仅 4 字节 GIF8 头 → None
        assert_eq!(detect_image_ext(&GIF87A[..4]), None);
        // 空字节 → None
        assert_eq!(detect_image_ext(b""), None);
    }

    #[test]
    fn detect_image_ext_rejects_unknown_and_fake() {
        // 未知格式
        assert_eq!(detect_image_ext(b"hello world"), None);
        // GIF 第 5 字节非 37/39（伪造 GIF 头）→ None
        assert_eq!(detect_image_ext(&[0x47, 0x49, 0x46, 0x38, 0x00]), None);
        // 前 3 字节像 JPEG 但第 3 字节不对 → None
        assert_eq!(detect_image_ext(&[0xFF, 0xD8, 0x00]), None);
    }

    #[test]
    fn normalize_ext_standardizes_jpeg_and_case() {
        assert_eq!(normalize_ext("jpeg"), "jpg");
        assert_eq!(normalize_ext("JPEG"), "jpg");
        assert_eq!(normalize_ext("Jpg"), "jpg");
        // 非 jpeg 原样小写保留
        assert_eq!(normalize_ext("png"), "png");
        assert_eq!(normalize_ext("PNG"), "png");
        assert_eq!(normalize_ext("gif"), "gif");
    }
}
