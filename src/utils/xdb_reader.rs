//! ip2region xdb 文件读取器（v2/v3 格式自实现）
//!
//! 设计目标：
//! - 无外部依赖，纯 Rust 实现 xdb 二进制搜索
//! - 全文件加载到内存（FullCache 模式），查询性能 O(log n)
//! - 线程安全（不可变结构，加载完成后只读）
//! - 文件不存在或格式不正确时优雅降级（返回 None）
//!
//! xdb 文件格式（v2 binary tree）：
//! ```text
//! +------------+-------------------+-------------------+----------+
//! | 16 bytes   | 4 bytes           | 4 bytes           | 4 bytes  |
//! +------------+-------------------+-------------------+----------+
//! | header     | start_index_ptr   | end_index_ptr     | reserved |
//! +------------+-------------------+-------------------+----------+
//! | 索引区（每项 12 bytes）                                       |
//! |   4 bytes: start_ip (big endian u32)                         |
//! |   4 bytes: end_ip (big endian u32)                           |
//! |   4 bytes: data_ptr（高 8 位=数据长度，低 24 位=数据偏移）    |
//! +--------------------------------------------------------------+
//! | 数据区                                                       |
//! |   每个数据项：UTF-8 字符串（如"中国|0|广东省|深圳市|电信"）  |
//! +--------------------------------------------------------------+
//! ```
//!
//! 查询流程：
//! 1. 将 IPv4 转为 u32（big endian）
//! 2. 在索引区做二叉搜索，找到 start_ip <= target <= end_ip 的索引项
//! 3. 从 data_ptr 解析出数据偏移和长度
//! 4. 读取数据区对应字节，解码为 UTF-8 字符串
//! 5. 用 `|` 分隔为 5 段：国家|区域|省份|城市|ISP

use std::sync::Arc;

/// xdb 文件头长度（固定 16 字节）
const XDB_HEADER_SIZE: usize = 16;
/// 每个索引项长度（固定 12 字节）
const XDB_INDEX_ENTRY_SIZE: usize = 12;

/// xdb 查询结果（5 段格式）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdbRegion {
    /// 国家（如 "中国" / "United States"）
    pub country: String,
    /// 区域（通常为 "0" 表示无）
    pub region: String,
    /// 省份（如 "广东省" / "California"）
    pub province: String,
    /// 城市（如 "深圳市" / "San Francisco"）
    pub city: String,
    /// ISP（如 "电信" / "Comcast"）
    pub isp: String,
}

impl XdbRegion {
    /// 从 "国家|区域|省份|城市|ISP" 格式字符串解析
    pub fn parse(s: &str) -> Self {
        let parts: Vec<&str> = s.split('|').collect();
        let get = |i: usize| -> String {
            parts.get(i).map(|s| s.to_string()).unwrap_or_default()
        };
        Self {
            country: get(0),
            region: get(1),
            province: get(2),
            city: get(3),
            isp: get(4),
        }
    }

    /// 拼接为中文归属地（国家 省份 城市，空字段过滤）
    pub fn to_chinese_location(&self) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(3);
        if !self.country.is_empty() && self.country != "0" {
            parts.push(self.country.clone());
        }
        if !self.province.is_empty() && self.province != "0" {
            parts.push(self.province.clone());
        }
        if !self.city.is_empty() && self.city != "0" {
            parts.push(self.city.clone());
        }
        parts.join(" ")
    }

    /// 原始格式字符串（"国家|区域|省份|城市|ISP"）
    pub fn to_raw(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.country, self.region, self.province, self.city, self.isp
        )
    }
}

/// xdb 读取器（全文件加载到内存）
///
/// 加载完成后为不可变结构，可安全通过 Arc 共享给多线程查询。
/// 文件不存在或格式错误时返回 None（调用方应处理降级场景）。
pub struct XdbReader {
    /// 完整文件内容（header + 索引区 + 数据区）
    data: Arc<Vec<u8>>,
    /// 索引区起始偏移
    start_index_ptr: usize,
    /// 索引项总数（= (end - start) / 12）
    index_count: usize,
}

impl XdbReader {
    /// 从文件路径加载 xdb
    ///
    /// 失败场景（返回 None）：
    /// - 文件不存在
    /// - 文件小于 16 字节（无 header）
    /// - header 中的 start_index_ptr / end_index_ptr 越界
    /// - 索引区长度不是 12 的倍数
    pub fn from_file(path: &str) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        if data.len() < XDB_HEADER_SIZE + XDB_INDEX_ENTRY_SIZE {
            tracing::warn!(
                "xdb 文件 {} 太小（{} bytes < {}），无法加载",
                path,
                data.len(),
                XDB_HEADER_SIZE + XDB_INDEX_ENTRY_SIZE
            );
            return None;
        }

        // 解析 header：start_index_ptr 在偏移 4，end_index_ptr 在偏移 8（big endian u32）
        let start_index_ptr = u32::from_be_bytes([
            data[4], data[5], data[6], data[7],
        ]) as usize;
        let end_index_ptr = u32::from_be_bytes([
            data[8], data[9], data[10], data[11],
        ]) as usize;

        // 边界校验
        if start_index_ptr >= data.len() || end_index_ptr > data.len() || start_index_ptr >= end_index_ptr {
            tracing::warn!(
                "xdb 文件 {} header 指针无效：start={}, end={}, file_size={}",
                path, start_index_ptr, end_index_ptr, data.len()
            );
            return None;
        }

        let index_bytes = end_index_ptr - start_index_ptr;
        if index_bytes % XDB_INDEX_ENTRY_SIZE != 0 {
            tracing::warn!(
                "xdb 文件 {} 索引区长度 {} 不是 {} 的倍数",
                path, index_bytes, XDB_INDEX_ENTRY_SIZE
            );
            return None;
        }

        let index_count = index_bytes / XDB_INDEX_ENTRY_SIZE;

        tracing::info!(
            "xdb 文件加载成功：path={}, size={}B, index_count={}, data_region=[{}, {}]",
            path, data.len(), index_count, end_index_ptr, data.len()
        );

        Some(Self {
            data: Arc::new(data),
            start_index_ptr,
            index_count,
        })
    }

    /// 查询 IPv4 归属地
    ///
    /// 返回 `Ok(Some(region))` 表示命中，`Ok(None)` 表示未命中，`Err` 表示查询异常。
    pub fn lookup_ipv4(&self, ip: &str) -> Option<XdbRegion> {
        let ip_u32 = parse_ipv4_to_u32(ip)?;
        self.lookup_ipv4_u32(ip_u32)
    }

    /// 通过 u32 形式的 IPv4 查询（big endian）
    pub fn lookup_ipv4_u32(&self, ip: u32) -> Option<XdbRegion> {
        if self.index_count == 0 {
            return None;
        }

        // 二叉搜索：找到 start_ip <= ip <= end_ip 的索引项
        let mut lo: usize = 0;
        let mut hi: usize = self.index_count;

        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry_offset = self.start_index_ptr + mid * XDB_INDEX_ENTRY_SIZE;

            if entry_offset + XDB_INDEX_ENTRY_SIZE > self.data.len() {
                return None;
            }

            let start_ip = u32::from_be_bytes([
                self.data[entry_offset],
                self.data[entry_offset + 1],
                self.data[entry_offset + 2],
                self.data[entry_offset + 3],
            ]);
            let end_ip = u32::from_be_bytes([
                self.data[entry_offset + 4],
                self.data[entry_offset + 5],
                self.data[entry_offset + 6],
                self.data[entry_offset + 7],
            ]);
            let data_ptr = u32::from_be_bytes([
                self.data[entry_offset + 8],
                self.data[entry_offset + 9],
                self.data[entry_offset + 10],
                self.data[entry_offset + 11],
            ]);

            if ip < start_ip {
                hi = mid;
            } else if ip > end_ip {
                lo = mid + 1;
            } else {
                // 命中：解析 data_ptr
                // 高 8 位为数据长度，低 24 位为数据偏移
                let data_len = ((data_ptr >> 24) & 0xFF) as usize;
                let data_offset = (data_ptr & 0x00FFFFFF) as usize;

                if data_offset + data_len > self.data.len() || data_len == 0 {
                    tracing::debug!(
                        "xdb 查询命中但数据指针越界：ip={}, data_offset={}, data_len={}, file_size={}",
                        ip, data_offset, data_len, self.data.len()
                    );
                    return None;
                }

                let raw_bytes = &self.data[data_offset..data_offset + data_len];
                let raw_str = std::str::from_utf8(raw_bytes).ok()?;
                return Some(XdbRegion::parse(raw_str));
            }
        }

        None
    }

    /// 查询是否已加载
    pub fn is_loaded(&self) -> bool {
        !self.data.is_empty() && self.index_count > 0
    }
}

/// 解析 IPv4 字符串为 u32（big endian）
///
/// "1.2.3.4" → 0x01020304
fn parse_ipv4_to_u32(ip: &str) -> Option<u32> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let b0: u8 = parts[0].parse().ok()?;
    let b1: u8 = parts[1].parse().ok()?;
    let b2: u8 = parts[2].parse().ok()?;
    let b3: u8 = parts[3].parse().ok()?;
    Some(u32::from_be_bytes([b0, b1, b2, b3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_to_u32() {
        assert_eq!(parse_ipv4_to_u32("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4_to_u32("1.2.3.4"), Some(0x01020304));
        assert_eq!(parse_ipv4_to_u32("255.255.255.255"), Some(0xFFFFFFFF));
        assert_eq!(parse_ipv4_to_u32("256.1.1.1"), None);
        assert_eq!(parse_ipv4_to_u32("1.2.3"), None);
        assert_eq!(parse_ipv4_to_u32("invalid"), None);
    }

    #[test]
    fn test_xdb_region_parse() {
        let r = XdbRegion::parse("中国|0|广东省|深圳市|电信");
        assert_eq!(r.country, "中国");
        assert_eq!(r.region, "0");
        assert_eq!(r.province, "广东省");
        assert_eq!(r.city, "深圳市");
        assert_eq!(r.isp, "电信");
        assert_eq!(r.to_chinese_location(), "中国 广东省 深圳市");
    }

    #[test]
    fn test_xdb_region_parse_with_zero_fields() {
        let r = XdbRegion::parse("澳大利亚|0|昆士兰|0|0");
        assert_eq!(r.to_chinese_location(), "澳大利亚 昆士兰");
    }

    #[test]
    fn test_xdb_region_parse_empty() {
        let r = XdbRegion::parse("");
        assert_eq!(r.country, "");
        assert_eq!(r.to_chinese_location(), "");
    }

    #[test]
    fn test_xdb_region_to_raw() {
        let r = XdbRegion::parse("中国|0|广东省|深圳市|电信");
        assert_eq!(r.to_raw(), "中国|0|广东省|深圳市|电信");
    }

    #[test]
    fn test_xdb_reader_load_nonexistent_file() {
        let reader = XdbReader::from_file("nonexistent.xdb");
        assert!(reader.is_none());
    }
}
