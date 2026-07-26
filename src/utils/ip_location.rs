//! IP 归属地查询工具（基于 MaxMindDB 离线数据库 + ip2region 双库混合）
//!
//! 使用 maxminddb Reader 加载 GeoLite2-City.mmdb 文件，
//! 根据 IP 查询国家/省份/城市信息，拼接为 "国家 省份 城市" 格式。
//!
//! 设计要点：
//! - mmdb 文件不存在时所有查询返回空字符串（graceful 降级）
//! - 内网 IP（10.x / 172.16-31.x / 192.168.x / 127.x）直接返回 "内网IP"
//! - 查询失败或字段缺失时返回空字符串，不抛错
//! - Reader 通过 ArcSwap 持有，支持热加载（不重启服务即可更新 mmdb 文件）
//! - 双库混合模式：ip2region xdb 优先（国内精度更高），未命中再查 mmdb

use arc_swap::ArcSwapOption;
use maxminddb::Reader;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;

use crate::utils::xdb_reader::XdbReader;

/// mmdb 数据库中城市记录的最小化反序列化结构
///
/// 仅提取 names.zh-CN 字段用于拼接中文归属地
#[derive(Debug, Deserialize)]
struct CityRecord {
    #[serde(default)]
    country: Option<CountryRecord>,
    #[serde(default)]
    subdivisions: Option<SubdivisionsRecord>,
    #[serde(default)]
    city: Option<CityNameRecord>,
}

#[derive(Debug, Deserialize)]
struct CountryRecord {
    #[serde(default)]
    names: Option<Names>,
}

#[derive(Debug, Deserialize)]
struct SubdivisionsRecord {
    #[serde(default)]
    names: Option<Names>,
}

#[derive(Debug, Deserialize)]
struct CityNameRecord {
    #[serde(default)]
    names: Option<Names>,
}

#[derive(Debug, Deserialize)]
struct Names {
    #[serde(rename = "zh-CN", default)]
    zh_cn: Option<String>,
}

/// IP 归属地查询器
///
/// 持有 maxminddb Reader（已读取到内存），线程安全，支持热加载。
/// 若 mmdb 文件不存在则 reader 为 None，所有查询返回空字符串。
///
/// 热加载实现：reader 字段使用 ArcSwapOption<Arc<Reader<Vec<u8>>>>
/// - 查询时通过 load() 获取当前 Arc<Reader>（无锁读）
/// - reload() 时通过 store() 原子替换为新 Arc<Reader>
/// - 多线程并发查询与热加载互不阻塞
///
/// 双库混合模式：
/// - xdb_reader 字段使用 ArcSwapOption<XdbReader>
/// - 查询时优先查 xdb（国内 IP 精度更高），未命中再查 mmdb
/// - xdb 文件不存在或格式错误时 xdb_reader 为 None，自动降级为 mmdb-only
pub struct IpLocator {
    reader: ArcSwapOption<Reader<Vec<u8>>>,
    xdb_reader: ArcSwapOption<XdbReader>,
}

impl IpLocator {
    /// 创建 IpLocator，若 mmdb 文件不存在则返回 None（所有查询返回空字符串）
    pub fn new(mmdb_path: &str) -> Self {
        let reader = match Reader::open_readfile(mmdb_path) {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                tracing::warn!("加载 mmdb 文件 {} 失败，IP 归属地查询将返回空: {}", mmdb_path, e);
                None
            }
        };
        Self {
            reader: ArcSwapOption::new(reader),
            xdb_reader: ArcSwapOption::new(None),
        }
    }

    /// 创建 IpLocator 并尝试加载 mmdb + xdb（双库模式）
    ///
    /// - mmdb 必须可加载（否则查询返回空）
    /// - xdb 加载失败时降级为 mmdb-only（xdb_enabled 为 false 时也不加载）
    pub fn new_with_xdb(mmdb_path: &str, xdb_path: &str, xdb_enabled: bool) -> Self {
        let locator = Self::new(mmdb_path);
        if xdb_enabled {
            locator.reload_xdb(xdb_path).ok();
        }
        locator
    }

    /// 热加载 mmdb 文件（不重启服务即可更新 IP 库）
    ///
    /// 流程：
    /// 1. 读取新 mmdb 文件到内存
    /// 2. 通过 ArcSwap 原子替换旧 Reader
    /// 3. 旧 Reader 由 Arc 引用计数自动回收
    ///
    /// # 参数
    /// - `mmdb_path`：mmdb 文件路径
    ///
    /// # 返回
    /// 成功返回 Ok(())，失败返回 anyhow::Error
    pub fn reload(&self, mmdb_path: &str) -> anyhow::Result<()> {
        let new_reader = Reader::open_readfile(mmdb_path)
            .map_err(|e| anyhow::anyhow!("加载 mmdb 文件 {} 失败: {}", mmdb_path, e))?;
        self.reader.store(Some(Arc::new(new_reader)));
        tracing::info!("mmdb 文件热加载成功: {}", mmdb_path);
        Ok(())
    }

    /// 热加载 xdb 文件（不重启服务即可更新 ip2region 数据库）
    ///
    /// 流程：
    /// 1. 从文件加载 XdbReader（全文件读入内存）
    /// 2. 通过 ArcSwap 原子替换旧 XdbReader
    /// 3. 旧 XdbReader 由 Arc 引用计数自动回收
    ///
    /// 失败场景：
    /// - 文件不存在
    /// - 文件格式错误（header 指针无效、索引长度不是 12 的倍数）
    pub fn reload_xdb(&self, xdb_path: &str) -> anyhow::Result<()> {
        match XdbReader::from_file(xdb_path) {
            Some(new_reader) => {
                self.xdb_reader.store(Some(Arc::new(new_reader)));
                tracing::info!("xdb 文件热加载成功: {}", xdb_path);
                Ok(())
            }
            None => anyhow::bail!("加载 xdb 文件 {} 失败（文件不存在或格式错误）", xdb_path),
        }
    }

    /// 获取当前 mmdb reader 是否已加载（用于状态查询）
    pub fn is_loaded(&self) -> bool {
        self.reader.load().is_some()
    }

    /// 获取当前 xdb reader 是否已加载（用于状态查询）
    pub fn is_xdb_loaded(&self) -> bool {
        self.xdb_reader
            .load()
            .as_ref()
            .map(|r| r.is_loaded())
            .unwrap_or(false)
    }

    /// 查询 IP 归属地（双库混合：xdb 优先，未命中回退 mmdb）
    ///
    /// 返回格式：
    /// - "中国 北京 北京"（国家 省份 城市，空格分隔）
    /// - "内网IP"（内网 IP）
    /// - ""（查询失败或字段缺失）
    pub fn locate(&self, ip: &str) -> String {
        // 内网 IP 直接返回 i18n 文案
        if is_private_ip(ip) {
            return crate::tr!("error.ip_location.private_ip").to_string();
        }

        // 1. 优先查 xdb（国内精度更高，仅支持 IPv4）
        if let Some(xdb_guard) = self.xdb_reader.load().as_ref() {
            if let Some(region) = xdb_guard.lookup_ipv4(ip) {
                let location = region.to_chinese_location();
                if !location.is_empty() {
                    return location;
                }
            }
            // xdb 未命中或解析为空，回退到 mmdb
        }

        // 2. 回退查 mmdb（支持 IPv4 + IPv6）
        let reader_guard = self.reader.load();
        let reader = match &*reader_guard {
            Some(r) => r,
            None => return String::new(),
        };

        let addr: IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => return String::new(),
        };

        // maxminddb 0.29 API：lookup() 返回 LookupResult（延迟解码），
        // 需通过 decode::<T>() 按 T 反序列化。未命中时 decode 返回 Ok(None)。
        let record: CityRecord = match reader.lookup(addr) {
            Ok(r) => match r.decode::<CityRecord>() {
                Ok(Some(rec)) => rec,
                _ => return String::new(),
            },
            Err(_) => return String::new(),
        };

        // 拼接中文归属地（国家 省份 城市）
        let mut parts: Vec<String> = Vec::with_capacity(3);
        if let Some(country) = &record.country
            && let Some(names) = &country.names
            && let Some(ref zh) = names.zh_cn
            && !zh.is_empty()
        {
            parts.push(zh.clone());
        }
        if let Some(subs) = &record.subdivisions
            && let Some(names) = &subs.names
            && let Some(ref zh) = names.zh_cn
            && !zh.is_empty()
        {
            parts.push(zh.clone());
        }
        if let Some(city) = &record.city
            && let Some(names) = &city.names
            && let Some(ref zh) = names.zh_cn
            && !zh.is_empty()
        {
            parts.push(zh.clone());
        }

        parts.join(" ")
    }
}

/// 判断 IP 是否为内网地址
///
/// 覆盖范围：
/// - 10.0.0.0/8
/// - 172.16.0.0/12（172.16.x ~ 172.31.x）
/// - 192.168.0.0/16
/// - 127.0.0.0/8（回环）
/// - IPv6 回环 ::1 / IPv6 链路本地 fe80::/10
fn is_private_ip(ip: &str) -> bool {
    let addr: IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 127.0.0.0/8
            if octets[0] == 127 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            // ::1 回环
            if v6.is_loopback() {
                return true;
            }
            // fe80::/10 链路本地
            let segments = v6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ip_v4() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("10.255.255.255"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("172.31.255.255"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("127.0.0.1"));
    }

    #[test]
    fn test_is_not_private_ip_v4() {
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("172.15.0.1"));
        assert!(!is_private_ip("172.32.0.1"));
        assert!(!is_private_ip("11.0.0.1"));
        assert!(!is_private_ip("128.0.0.1"));
    }

    #[test]
    fn test_is_private_ip_v6() {
        assert!(is_private_ip("::1"));
        assert!(is_private_ip("fe80::1"));
    }

    #[test]
    fn test_locate_with_missing_file() {
        // 文件不存在时返回空字符串
        let locator = IpLocator::new("nonexistent.mmdb");
        assert_eq!(locator.locate("8.8.8.8"), "");
        // 内网 IP 仍返回 "内网IP"
        assert_eq!(locator.locate("127.0.0.1"), "内网IP");
        assert_eq!(locator.locate("10.0.0.1"), "内网IP");
    }

    #[test]
    fn test_locate_with_real_mmdb() {
        // 如果 data/GeoLite2-City.mmdb 存在，验证可以查询公网 IP 归属地
        let locator = IpLocator::new("data/GeoLite2-City.mmdb");
        if locator.is_loaded() {
            let result = locator.locate("8.8.8.8");
            assert!(!result.is_empty(), "Google DNS 8.8.8.8 应能查询到归属地");
            println!("8.8.8.8 归属地: {}", result);
        }
        // 内网 IP 无论文件是否存在都返回 "内网IP"
        assert_eq!(locator.locate("127.0.0.1"), "内网IP");
    }

    #[test]
    fn test_reload_function() {
        // 验证热加载 API 可用性（不依赖实际 mmdb 文件存在）
        let locator = IpLocator::new("nonexistent.mmdb");
        assert!(!locator.is_loaded());
        // reload 一个不存在的文件应失败
        let result = locator.reload("nonexistent.mmdb");
        assert!(result.is_err());
    }
}
