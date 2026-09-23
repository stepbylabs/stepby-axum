//! S3 兼容对象存储后端（MinIO / AWS S3 / 阿里云 OSS / 腾讯 COS，F1）
//!
//! 基于 reqwest + 自研 AWS SigV4 签名（[`super::sigv4`]）。支持两种寻址风格，由配置
//! `path_style` 决定（真实生效，非占位）：
//! - **路径风格**（path-style，`path_style=true`，默认，适用 MinIO/OSS/COS）：
//!   对象 URI `/{bucket}/{key}`，请求地址 `{endpoint}/{bucket}/{key}`，
//!   访问 URL `{public_endpoint|endpoint}/{bucket}/{key}`
//! - **虚拟主机风格**（virtual-host，`path_style=false`，AWS S3 推荐）：
//!   bucket 作子域，Host 头 `{bucket}.{authority}`，对象 URI `/{key}`，
//!   请求地址 `{scheme}://{bucket}.{authority}{path}/{key}`，访问 URL `{public_base}/{key}`
//!
//! 对象 key 组织为 `uploads/{dir}/{filename}`（与本地目录结构对应），前端无需改动。

use async_trait::async_trait;

use crate::common::error::AppError;
use crate::config::S3StorageConfig;
use crate::storage::{
    StorageBackend, StorageObject, canonical_headers, canonical_request, payload_hash, sha256_hex,
    signature, signing_key, string_to_sign,
};

/// S3 兼容对象存储后端
pub struct S3Backend {
    client: reqwest::Client,
    access_key: String,
    secret_key: String,
    region: String,
    bucket: String,
    /// 是否路径风格寻址：true → `/{bucket}/{key}`（MinIO/OSS/COS）；
    /// false → 虚拟主机风格 `{bucket}.{host}/{key}`（AWS S3 推荐）
    path_style: bool,
    /// 实际发请求的基址（含 scheme，path-style 时为 endpoint，virtual-host 时 bucket 作子域），无末尾 `/`
    request_base: String,
    /// 参与 SigV4 规范化的 Host 头值（须与 reqwest 实际发出的 Host 一致）
    canonical_host: String,
    /// 对外公开 URL 前缀（可为 CDN），去除末尾 `/`；缺省回退 request_base
    public_base: String,
}

impl S3Backend {
    /// 依据配置构建后端。校验必需字段：access_key / secret_key / endpoint / bucket。
    pub fn try_new(cfg: &S3StorageConfig) -> Result<Self, AppError> {
        if cfg.access_key.trim().is_empty()
            || cfg.secret_key.trim().is_empty()
            || cfg.endpoint.trim().is_empty()
            || cfg.bucket.trim().is_empty()
        {
            return Err(AppError::bad_request(&crate::tr!(
                "error.storage.s3_missing_config"
            )));
        }

        let endpoint_base = cfg.endpoint.trim_end_matches('/').to_string();
        let endpoint_authority = parse_authority(&endpoint_base).ok_or_else(|| {
            AppError::bad_request(&crate::tr!("error.storage.s3_invalid_endpoint"))
        })?;
        let path_style = cfg.path_style;

        // 解析 endpoint，供两种寻址风格构建请求基址与 canonical Host：
        // - path-style：请求基址 = endpoint 原样（可含网关路径），canonical Host = endpoint authority，
        //   对象 URI = /{bucket}/{key}
        // - virtual-host：请求基址 = {scheme}://{bucket}.{authority}{path}，
        //   canonical Host = {bucket}.{authority}，对象 URI = /{key}
        let (scheme, endpoint_path) = split_endpoint(&endpoint_base);
        let bucket = cfg.bucket.trim();
        let (request_base, canonical_host) = if path_style {
            (endpoint_base.clone(), endpoint_authority.clone())
        } else {
            (
                format!("{scheme}://{bucket}.{endpoint_authority}{endpoint_path}"),
                format!("{bucket}.{endpoint_authority}"),
            )
        };

        let public_base = if cfg.public_endpoint.trim().is_empty() {
            request_base.clone()
        } else {
            cfg.public_endpoint.trim_end_matches('/').to_string()
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                tracing::error!("S3 客户端构建失败: {e}");
                AppError::internal(&crate::tr!("error.storage.s3_client_build_failed"))
            })?;

        Ok(Self {
            client,
            access_key: cfg.access_key.trim().to_string(),
            secret_key: cfg.secret_key.trim().to_string(),
            region: cfg.region.trim().to_string(),
            bucket: cfg.bucket.trim().to_string(),
            path_style,
            request_base,
            canonical_host,
            public_base,
        })
    }

    /// 组装对象 key：`uploads/{dir}/{filename}`（dir 去除首尾 `/`）
    fn object_key(&self, dir: &str, filename: &str) -> String {
        let dir = dir.trim_matches('/');
        if dir.is_empty() {
            filename.to_string()
        } else {
            format!("{dir}/{filename}")
        }
    }

    /// 对象 URI（SigV4 canonical URI 及请求路径，不含 host）：
    /// - path-style：`/{bucket}/{key}`
    /// - virtual-host：`/{key}`
    fn object_uri(&self, key: &str) -> String {
        if self.path_style {
            format!("/{}/{key}", self.bucket)
        } else {
            format!("/{key}")
        }
    }

    /// 列举请求的 canonical URI（bucket 根）：
    /// - path-style：`/{bucket}/`
    /// - virtual-host：`/`
    fn list_uri(&self) -> String {
        if self.path_style {
            format!("/{}/", self.bucket)
        } else {
            "/".to_string()
        }
    }

    /// 对象访问 URL（返回前端）：
    /// - path-style：`{public_base}/{bucket}/{key}`
    /// - virtual-host：`{public_base}/{key}`（public_base 已含 bucket 子域或为桶专属 CDN）
    fn object_url(&self, key: &str) -> String {
        if self.path_style {
            format!("{}/{}/{key}", self.public_base, self.bucket)
        } else {
            format!("{}/{key}", self.public_base)
        }
    }

    /// 发送 SigV4 签名请求并校验 HTTP 状态。
    ///
    /// `method`/`uri`/`query` 参与签名，`content_type` 与 `body` 仅按需附加。
    async fn signed_send(
        &self,
        method: reqwest::Method,
        uri: &str,
        query: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<reqwest::Response, AppError> {
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let date = &amz_date[0..8];
        let body_hash = payload_hash(body);

        let mut headers = vec![
            ("host".to_string(), self.canonical_host.clone()),
            ("x-amz-content-sha256".to_string(), body_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        if let Some(ct) = content_type {
            headers.push(("content-type".to_string(), ct.to_string()));
        }
        let (headers_block, signed_headers) = canonical_headers(&headers);

        let canonical_uri = uri; // 对象路径均为安全字符（字母数字 .- _ /），无需额外编码
        let creq = canonical_request(
            method.as_str(),
            canonical_uri,
            query,
            &headers_block,
            &signed_headers,
            &body_hash,
        );
        let canonical_hash = sha256_hex(creq.as_bytes());
        let sts = string_to_sign(&amz_date, date, &self.region, "s3", &canonical_hash);
        let skey = signing_key(&self.secret_key, date, &self.region, "s3");
        let sig = signature(&skey, &sts);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}/{}/s3/aws4_request, SignedHeaders={signed_headers}, Signature={sig}",
            self.access_key, date, self.region
        );

        let mut url = format!("{}{}", self.request_base, canonical_uri);
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }

        let mut req = self
            .client
            .request(method, &url)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &body_hash)
            .header("authorization", &authorization);
        if let Some(ct) = content_type {
            req = req.header("content-type", ct);
        }
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }

        let resp = req.send().await.map_err(|e| {
            tracing::error!("S3 请求失败: {e}");
            AppError::internal(&crate::tr!("error.storage.s3_request_failed"))
        })?;
        Ok(resp)
    }

    /// 校验响应状态；非 2xx 抛出带状态码的错误
    async fn ensure_ok(&self, resp: reqwest::Response) -> Result<reqwest::Response, AppError> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(200).collect();
        tracing::error!("S3 返回错误状态 {}: {snippet}", status.as_u16());
        Err(AppError::internal(&crate::tr!(
            "error.storage.s3_status",
            status = status.as_u16(),
            detail = snippet
        )))
    }

    /// ListObjectsV2 分页拉取指定前缀下全部对象
    async fn list_all(&self, prefix: &str) -> Result<Vec<(String, u64)>, AppError> {
        let mut objects: Vec<(String, u64)> = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut params: Vec<(String, String)> = vec![
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), uri_encode(prefix)),
            ];
            if let Some(token) = &continuation {
                params.push(("continuation-token".to_string(), uri_encode(token)));
            }
            params.sort_by(|a, b| a.0.cmp(&b.0));
            let query: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
            let query = query.join("&");

            let resp = self
                .signed_send(reqwest::Method::GET, &self.list_uri(), &query, None, b"")
                .await?;
            let xml = resp.text().await.map_err(|e| {
                tracing::error!("读取 ListObjectsV2 响应失败: {e}");
                AppError::internal(&crate::tr!("error.storage.s3_list_failed"))
            })?;

            let parsed: ListBucketResult = quick_xml::de::from_str(&xml).map_err(|e| {
                tracing::error!(
                    "解析 ListObjectsV2 响应失败: {e}，body: {}",
                    xml.chars().take(150).collect::<String>()
                );
                AppError::internal(&crate::tr!("error.storage.s3_list_failed"))
            })?;

            for c in parsed.contents {
                objects.push((c.key, c.size));
            }

            let truncated = parsed.is_truncated.map(|s| s == "true").unwrap_or(false);
            if !truncated {
                break;
            }
            match parsed.next_token {
                Some(t) if !t.is_empty() => continuation = Some(t),
                _ => break,
            }
        }
        Ok(objects)
    }
}

/// ListObjectsV2 响应（仅解析本业务所需字段）
#[derive(Debug, serde::Deserialize)]
struct ListBucketResult {
    #[serde(rename = "IsTruncated")]
    is_truncated: Option<String>,
    #[serde(rename = "NextContinuationToken")]
    next_token: Option<String>,
    #[serde(rename = "Contents", default)]
    contents: Vec<Contents>,
}

#[derive(Debug, serde::Deserialize)]
struct Contents {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Size", default)]
    size: u64,
}

/// 提取 URL 的 authority（host[:port]），带证书/端口容错
fn parse_authority(base: &str) -> Option<String> {
    let parsed = url::Url::parse(base).ok()?;
    let host = parsed.host_str()?.to_lowercase();
    let authority = if let Some(port) = parsed.port() {
        format!("{host}:{port}")
    } else {
        host
    };
    Some(authority)
}

/// 拆分 endpoint 为 `(scheme, path)`：
/// - `scheme` 形如 `http` / `https`（供虚拟主机风格重建 `{scheme}://{bucket}.{authority}{path}`）
/// - `path` 为 endpoint 的路径部分（去除末尾 `/`；根路径返回空串），用于网关前缀场景
///
/// endpoint 已由 `parse_authority` 校验可解析，此处对不可解析情形回退为 `https` + 空路径。
fn split_endpoint(base: &str) -> (String, String) {
    match url::Url::parse(base) {
        Ok(parsed) => {
            let path = parsed.path().trim_end_matches('/').to_string();
            (parsed.scheme().to_string(), path)
        }
        Err(_) => ("https".to_string(), String::new()),
    }
}

/// RFC3986 百分比编码，用于 **查询字符串组件**（SigV4 query 编码规则）：
/// 除 alphanumeric 与 `-._~` 外全部编码（含 `/`、`?`、`=`、空格）。
/// 注意：对象 key 的 **路径**（canonical URI）不做此编码，`/` 保留为路径分隔符，
/// 由 `object_uri` 原样拼接（对象 key 已由调用方保证为安全字符）。
fn uri_encode(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len() * 2);
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xF) as usize] as char);
        }
    }
    out
}

fn content_type_for(key: &str) -> Option<&'static str> {
    Some(
        match std::path::Path::new(key)
            .extension()
            .and_then(|e| e.to_str())
        {
            Some("jpg") | Some("jpeg") => "image/jpeg",
            Some("png") => "image/png",
            Some("gif") => "image/gif",
            Some("pdf") => "application/pdf",
            Some("zip") => "application/zip",
            Some("txt") => "text/plain",
            Some("doc") => "application/msword",
            Some("docx") => {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            }
            Some("xls") => "application/vnd.ms-excel",
            Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            _ => "application/octet-stream",
        },
    )
}

#[async_trait]
impl StorageBackend for S3Backend {
    fn kind(&self) -> &'static str {
        "s3"
    }

    async fn save(
        &self,
        dir: &str,
        key: &str,
        _url_prefix: &str,
        bytes: &[u8],
    ) -> Result<String, AppError> {
        if key.is_empty()
            || key.contains('/')
            || key.contains('\\')
            || key.contains("..")
            || key.contains('\0')
        {
            return Err(AppError::bad_request(&crate::tr!(
                "error.file.invalid_name"
            )));
        }
        let object_key = self.object_key(dir, key);
        let uri = self.object_uri(&object_key);
        let content_type = content_type_for(&object_key);
        let resp = self
            .signed_send(reqwest::Method::PUT, &uri, "", content_type, bytes)
            .await?;
        self.ensure_ok(resp).await?;

        tracing::info!(bucket = %self.bucket, key = %object_key, size = bytes.len(), "S3 对象上传成功");
        Ok(self.object_url(&object_key))
    }

    async fn read(&self, dir: &str, key: &str) -> Result<Option<Vec<u8>>, AppError> {
        if key.is_empty()
            || key.contains('/')
            || key.contains('\\')
            || key.contains("..")
            || key.contains('\0')
        {
            return Err(AppError::bad_request(&crate::tr!(
                "error.file.invalid_name"
            )));
        }
        let object_key = self.object_key(dir, key);
        let uri = self.object_uri(&object_key);
        let resp = self
            .signed_send(reqwest::Method::GET, &uri, "", None, b"")
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let bytes = self.ensure_ok(resp).await?.bytes().await.map_err(|e| {
            tracing::error!("读取 S3 对象失败: {e}");
            AppError::internal(&crate::tr!("error.storage.s3_request_failed"))
        })?;
        Ok(Some(bytes.to_vec()))
    }

    async fn delete(&self, dir: &str, key: &str) -> Result<(), AppError> {
        if key.is_empty()
            || key.contains('/')
            || key.contains('\\')
            || key.contains("..")
            || key.contains('\0')
        {
            return Err(AppError::bad_request(&crate::tr!(
                "error.file.invalid_name"
            )));
        }
        let object_key = self.object_key(dir, key);
        let uri = self.object_uri(&object_key);
        // DELETE 对象存在时返回 204，不存在时返回 404——两者均视为成功（幂等）
        let resp = self
            .signed_send(reqwest::Method::DELETE, &uri, "", None, b"")
            .await?;
        let status = resp.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        tracing::error!(
            "S3 删除对象失败: {} {}",
            status.as_u16(),
            body.chars().take(200).collect::<String>()
        );
        Err(AppError::internal(&crate::tr!(
            "error.storage.s3_status",
            status = status.as_u16(),
            detail = body.chars().take(200).collect::<String>()
        )))
    }

    async fn list(&self, dir: &str, _url_prefix: &str) -> Result<Vec<StorageObject>, AppError> {
        // 前缀对象 key：`uploads/{dir}/`
        let dir_trim = dir.trim_matches('/');
        let prefix = if dir_trim.is_empty() {
            "".to_string()
        } else {
            format!("{dir_trim}/")
        };
        let mut out = Vec::new();
        for (key, size) in self.list_all(&prefix).await? {
            // 文件名 = key 最后一段
            let name = key.rsplit('/').next().unwrap_or(&key).to_string();
            out.push(StorageObject {
                url: self.object_url(&key),
                name,
                size,
                modified_secs: 0, // S3 列表不返回该时间；如需请扩展解析 LastModified
            });
        }
        Ok(out)
    }
}

/// 供测试使用的确定性 URI 编码断言
#[cfg(test)]
mod tests {
    // 覆盖意图：S3 后端纯逻辑测试——URI 编码、authority 提取、对象 key 组装、
    // content-type 自动推断、key 安全校验、配置缺失检查。不涉及实际网络请求。

    use super::*;

    #[test]
    fn uri_encode_rfc3986() {
        // 查询字符串组件：`/`、`?`、`=`、空格均需编码
        assert_eq!(
            uri_encode("uploads/file/a b.png"),
            "uploads%2Ffile%2Fa%20b.png"
        );
        assert_eq!(uri_encode("a/b?c=d"), "a%2Fb%3Fc%3Dd");
        assert_eq!(uri_encode("safe-_.~"), "safe-_.~");
        assert_eq!(uri_encode("你好"), "%E4%BD%A0%E5%A5%BD");
    }

    #[test]
    fn authority_parsing() {
        assert_eq!(
            parse_authority("https://minio.example.com:9000").as_deref(),
            Some("minio.example.com:9000")
        );
        assert_eq!(
            parse_authority("http://localhost:9000").as_deref(),
            Some("localhost:9000")
        );
        assert_eq!(
            parse_authority("https://s3.cn-north-1.amazonaws.com.cn").as_deref(),
            Some("s3.cn-north-1.amazonaws.com.cn")
        );
        assert_eq!(parse_authority("not a url"), None);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn missing_config_is_rejected() {
        let mut cfg = S3StorageConfig::default();
        cfg.access_key = "ak".into();
        cfg.secret_key = "sk".into();
        cfg.endpoint = "".into(); // endpoint 缺失
        assert!(S3Backend::try_new(&cfg).is_err());

        let mut cfg = S3StorageConfig::default();
        cfg.access_key = "".into(); // access_key 缺失
        cfg.secret_key = "sk".into();
        cfg.endpoint = "http://localhost:9000".into();
        assert!(S3Backend::try_new(&cfg).is_err());

        let mut cfg = S3StorageConfig::default();
        cfg.access_key = "ak".into();
        cfg.secret_key = "".into(); // secret_key 缺失
        cfg.endpoint = "http://localhost:9000".into();
        assert!(S3Backend::try_new(&cfg).is_err());

        let mut cfg = S3StorageConfig::default();
        cfg.access_key = "ak".into();
        cfg.secret_key = "sk".into();
        cfg.endpoint = "http://localhost:9000".into();
        cfg.bucket = "".into(); // bucket 缺失
        assert!(S3Backend::try_new(&cfg).is_err());
    }

    #[test]
    fn content_type_for_detects_common_extensions() {
        assert_eq!(content_type_for("photo.jpg"), Some("image/jpeg"));
        assert_eq!(content_type_for("photo.jpeg"), Some("image/jpeg"));
        assert_eq!(content_type_for("icon.png"), Some("image/png"));
        assert_eq!(content_type_for("anim.gif"), Some("image/gif"));
        assert_eq!(content_type_for("doc.pdf"), Some("application/pdf"));
        assert_eq!(content_type_for("readme.txt"), Some("text/plain"));
        assert_eq!(content_type_for("data.zip"), Some("application/zip"));
        assert_eq!(content_type_for("doc.doc"), Some("application/msword"));
        assert_eq!(
            content_type_for("doc.docx"),
            Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        );
        assert_eq!(
            content_type_for("sheet.xls"),
            Some("application/vnd.ms-excel")
        );
        assert_eq!(
            content_type_for("sheet.xlsx"),
            Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        );
        assert_eq!(
            content_type_for("unknown.bin"),
            Some("application/octet-stream")
        );
        assert_eq!(content_type_for("noext"), Some("application/octet-stream"));
    }

    #[test]
    fn object_key_assembly() {
        let cfg = S3StorageConfig {
            access_key: "ak".into(),
            secret_key: "sk".into(),
            endpoint: "http://localhost:9000".into(),
            bucket: "yebot".into(),
            ..Default::default()
        };
        let backend = S3Backend::try_new(&cfg).expect("完整配置应成功");

        // dir 为空 → key 直接是文件名
        assert_eq!(backend.object_key("", "abc.png"), "abc.png");
        // dir 有前后斜杠 → 修剪后拼接
        assert_eq!(
            backend.object_key("/uploads/file/", "abc.png"),
            "uploads/file/abc.png"
        );
        // 正常 dir
        assert_eq!(
            backend.object_key("uploads/file", "abc.png"),
            "uploads/file/abc.png"
        );
    }

    #[test]
    fn object_uri_includes_bucket() {
        let cfg = S3StorageConfig {
            access_key: "ak".into(),
            secret_key: "sk".into(),
            endpoint: "http://localhost:9000".into(),
            bucket: "my-bucket".into(),
            ..Default::default()
        };
        let backend = S3Backend::try_new(&cfg).expect("完整配置应成功");

        assert_eq!(backend.object_uri("object.png"), "/my-bucket/object.png");
        assert_eq!(
            backend.object_uri("uploads/object.png"),
            "/my-bucket/uploads/object.png"
        );
    }

    #[test]
    fn object_url_uses_public_base() {
        let cfg = S3StorageConfig {
            access_key: "ak".into(),
            secret_key: "sk".into(),
            endpoint: "http://minio:9000".into(),
            bucket: "bucket".into(),
            public_endpoint: "https://cdn.example.com".into(),
            ..Default::default()
        };
        let backend = S3Backend::try_new(&cfg).expect("完整配置应成功");

        assert_eq!(
            backend.object_url("key.png"),
            "https://cdn.example.com/bucket/key.png"
        );
    }

    #[test]
    fn object_url_falls_back_to_endpoint_when_public_empty() {
        let cfg = S3StorageConfig {
            access_key: "ak".into(),
            secret_key: "sk".into(),
            endpoint: "http://minio:9000".into(),
            bucket: "bucket".into(),
            public_endpoint: String::new(), // public_endpoint 为空
            ..Default::default()
        };
        let backend = S3Backend::try_new(&cfg).expect("完整配置应成功");

        assert_eq!(
            backend.object_url("key.png"),
            "http://minio:9000/bucket/key.png"
        );
    }

    #[test]
    fn s3_debug_redacts_secret() {
        let cfg = S3StorageConfig {
            access_key: "AKIAEXAMPLE".into(),
            secret_key: "secret123456".into(),
            endpoint: "http://localhost:9000".into(),
            bucket: "bucket".into(),
            ..Default::default()
        };
        // Debug 实现脱敏 secret_key → "<redacted>"
        let debug = format!("{cfg:?}");
        assert!(debug.contains("secret_key: \"<redacted>\""));
        assert!(debug.contains("access_key: \"AKIAEXAMPLE\"")); // access_key 不脱敏
    }

    // ---------- 虚拟主机风格（path_style=false）寻址计算 ----------

    #[test]
    fn virtual_host_addressing_computes_uri_host_and_url() {
        let cfg = S3StorageConfig {
            access_key: "ak".into(),
            secret_key: "sk".into(),
            endpoint: "https://s3.us-east-1.amazonaws.com".into(),
            region: "us-east-1".into(),
            bucket: "mybucket".into(),
            path_style: false,
            public_endpoint: String::new(),
        };
        let backend = S3Backend::try_new(&cfg).expect("完整配置应成功");

        // canonical Host = bucket 作子域
        assert_eq!(
            backend.canonical_host,
            "mybucket.s3.us-east-1.amazonaws.com"
        );
        // 请求基址含 bucket 子域
        assert_eq!(
            backend.request_base,
            "https://mybucket.s3.us-east-1.amazonaws.com"
        );
        // 对象 URI 不含 bucket（虚拟主机风格）
        assert_eq!(
            backend.object_uri("uploads/file/a.png"),
            "/uploads/file/a.png"
        );
        // 列举 URI 为根
        assert_eq!(backend.list_uri(), "/");
        // 访问 URL：public_base 回退 request_base，不含 bucket 段
        assert_eq!(
            backend.object_url("uploads/file/a.png"),
            "https://mybucket.s3.us-east-1.amazonaws.com/uploads/file/a.png"
        );
    }

    #[test]
    fn virtual_host_with_public_base_and_gateway_path() {
        // endpoint 含网关路径时，虚拟主机风格保留路径
        let cfg = S3StorageConfig {
            access_key: "ak".into(),
            secret_key: "sk".into(),
            endpoint: "https://gateway.example.com/s3".into(),
            bucket: "bkt".into(),
            path_style: false,
            public_endpoint: "https://cdn.example.com".into(),
            ..Default::default()
        };
        let backend = S3Backend::try_new(&cfg).expect("完整配置应成功");
        assert_eq!(backend.canonical_host, "bkt.gateway.example.com");
        assert_eq!(backend.request_base, "https://bkt.gateway.example.com/s3");
        // public_endpoint 显式给出时，URL 走 CDN 根 + key（虚拟主机不再拼 bucket）
        assert_eq!(backend.object_url("k.png"), "https://cdn.example.com/k.png");
    }

    #[test]
    fn path_style_addressing_preserves_legacy_shape() {
        // path_style=true：canonical Host 不含 bucket，URI 含 bucket 段（MinIO/OSS/COS 行为不变）
        let cfg = S3StorageConfig {
            access_key: "ak".into(),
            secret_key: "sk".into(),
            endpoint: "http://127.0.0.1:9000".into(),
            bucket: "bkt".into(),
            path_style: true,
            ..Default::default()
        };
        let backend = S3Backend::try_new(&cfg).expect("完整配置应成功");
        assert_eq!(backend.canonical_host, "127.0.0.1:9000");
        assert_eq!(backend.request_base, "http://127.0.0.1:9000");
        assert_eq!(backend.object_uri("f.txt"), "/bkt/f.txt");
        assert_eq!(backend.list_uri(), "/bkt/");
        assert_eq!(
            backend.object_url("f.txt"),
            "http://127.0.0.1:9000/bkt/f.txt"
        );
    }
}

#[cfg(test)]
mod wire_tests {
    //! S3 后端**真实 HTTP 回环**集成测试（F1 / Tier A #7）
    //!
    //! 与纯逻辑单测不同，本模块在进程内用 `axum::serve` 启动一个 S3 兼容的假端点，
    //! 让 **真实的 `S3Backend`**（reqwest + 自研 SigV4 签名，业务代码完全不 mock）通过
    //! 真实 TCP 连接发起 PUT/GET/DELETE/ListObjectsV2，服务端：
    //! 1. 用本 crate 的 sigv4 函数**重算签名**并比对 Authorization 头（验证签名链正确）；
    //! 2. 校验 `x-amz-content-sha256 == sha256(body)`（验证 payload 完整性）；
    //! 3. 维护内存对象存储，回读断言字节一致、列举解析正确、删除幂等。
    //!
    //! 这是脱离真实 MinIO 也能覆盖「对象存储多后端」S3 链路端到端跑通的最强验证。
    //! 使用 path-style（127.0.0.1 无法解析 bucket 子域，虚拟主机风格由纯逻辑单测覆盖）。

    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::extract::{Request, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::any;
    use tokio::net::TcpListener;

    use super::*;

    const BUCKET: &str = "testbucket";
    const REGION: &str = "us-east-1";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/secretkey";

    #[derive(Clone)]
    struct FakeS3 {
        store: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }

    impl FakeS3 {
        fn new() -> Self {
            Self {
                store: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }
    }

    /// 从 Authorization 头重算 SigV4 签名并与客户端一致（仅对无查询串的对象操作严格校验）
    fn verify_sigv4(req: &Request, body: &[u8]) -> Result<(), String> {
        let headers = req.headers();
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or("缺少 Authorization 头")?;
        let signed_headers = auth
            .split_once("SignedHeaders=")
            .map(|(_, r)| r.split(',').next().unwrap_or(""))
            .filter(|s| !s.is_empty())
            .ok_or("无法解析 SignedHeaders")?;
        let client_sig = auth
            .rsplit_once("Signature=")
            .map(|(_, r)| r.trim())
            .ok_or("无法解析 Signature")?;
        let amz_date = headers
            .get("x-amz-date")
            .and_then(|v| v.to_str().ok())
            .ok_or("缺少 x-amz-date")?
            .to_string();
        let payload_hdr = headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .ok_or("缺少 x-amz-content-sha256")?;

        // payload 完整性：头声明的哈希必须等于请求体真实 sha256
        if sha256_hex(body) != payload_hdr {
            return Err("x-amz-content-sha256 与请求体不一致".to_string());
        }

        // 依据 SignedHeaders 逐项取出服务端实际收到的头值，重建 canonical headers
        let mut hv: Vec<(String, String)> = Vec::new();
        for name in signed_headers.split(';') {
            let val = headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| format!("缺少参与签名的头: {name}"))?;
            hv.push((name.to_string(), val.to_string()));
        }
        let (headers_block, signed) = canonical_headers(&hv);
        if signed != signed_headers {
            return Err(format!(
                "SignedHeaders 排序不一致: {signed} != {signed_headers}"
            ));
        }

        let date = &amz_date[..8];
        let creq = canonical_request(
            req.method().as_str(),
            req.uri().path(),
            "", // 本测试仅对无查询串的对象操作校验签名
            &headers_block,
            &signed,
            payload_hdr,
        );
        let canonical_hash = sha256_hex(creq.as_bytes());
        let sts = string_to_sign(&amz_date, date, REGION, "s3", &canonical_hash);
        let skey = signing_key(SECRET, date, REGION, "s3");
        let expected = signature(&skey, &sts);
        if expected != client_sig {
            return Err(format!("签名不匹配: 期望 {expected}, 实得 {client_sig}"));
        }
        Ok(())
    }

    async fn handle(State(st): State<FakeS3>, req: Request) -> Response {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or("").to_string();
        let (parts, body) = req.into_parts();
        let body = axum::body::to_bytes(body, 32 * 1024 * 1024)
            .await
            .unwrap_or_default();
        let req_view = Request::from_parts(parts, axum::body::Body::empty());
        // req_view 复用头/方法/uri 供验签（body 已单独取出）

        // ListObjectsV2：GET /{bucket}/?list-type=2&...
        if method == reqwest::Method::GET && query.contains("list-type") {
            let store = st.store.lock().unwrap();
            let mut xml = String::from(
                r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated>"#,
            );
            for (key, bytes) in store.iter() {
                xml.push_str("<Contents><Key>");
                xml.push_str(key);
                xml.push_str("</Key><Size>");
                xml.push_str(&bytes.len().to_string());
                xml.push_str("</Size></Contents>");
            }
            xml.push_str("</ListBucketResult>");
            return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response();
        }

        // 对象操作：路径 /{bucket}/{key}
        let prefix = format!("/{BUCKET}/");
        let Some(key) = path.strip_prefix(&prefix) else {
            return (StatusCode::NOT_FOUND, "bad path").into_response();
        };
        let key = key.to_string();

        if let Err(msg) = verify_sigv4(&req_view, &body) {
            return (
                StatusCode::FORBIDDEN,
                format!("signature verify failed: {msg}"),
            )
                .into_response();
        }

        let mut store = st.store.lock().unwrap();
        match method.as_str() {
            "PUT" => {
                store.insert(key, body.to_vec());
                StatusCode::OK.into_response()
            }
            "GET" => match store.get(&key) {
                Some(bytes) => (StatusCode::OK, bytes.clone()).into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            },
            "DELETE" => {
                store.remove(&key);
                StatusCode::NO_CONTENT.into_response()
            }
            other => (StatusCode::METHOD_NOT_ALLOWED, format!("unhandled {other}")).into_response(),
        }
    }

    /// 启动假 S3 服务，返回后端可用的 endpoint。
    async fn spawn_fake_s3() -> (String, FakeS3) {
        let st = FakeS3::new();
        let router = Router::new().fallback(any(handle)).with_state(st.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        (format!("http://{addr}"), st)
    }

    fn backend_for(endpoint: &str) -> S3Backend {
        let cfg = S3StorageConfig {
            access_key: "AKIAEXAMPLE".into(),
            secret_key: SECRET.into(),
            endpoint: endpoint.into(),
            region: REGION.into(),
            bucket: BUCKET.into(),
            path_style: true,
            public_endpoint: String::new(),
        };
        S3Backend::try_new(&cfg).expect("构建 S3 后端失败")
    }

    #[tokio::test]
    async fn s3_backend_full_roundtrip_over_real_http_with_signature_verification() {
        let (endpoint, _st) = spawn_fake_s3().await;
        let backend = backend_for(&endpoint);
        assert_eq!(backend.kind(), "s3");

        let dir = "uploads/file";
        let filename = "hello-1234.txt";
        let payload = b"the quick brown fox".to_vec();

        // save → PUT（真实签名 + 服务端验签 + 落内存）
        let url = backend
            .save(dir, filename, "/uploads/file", &payload)
            .await
            .expect("save 失败");
        assert_eq!(url, format!("{endpoint}/{BUCKET}/{dir}/{filename}"));

        // read → GET
        let got = backend
            .read(dir, filename)
            .await
            .expect("read 失败")
            .expect("对象应存在");
        assert_eq!(got, payload, "回读字节应与写入一致");

        // list → GET /?list-type=2
        let list = backend.list(dir, "/uploads/file").await.expect("list 失败");
        assert_eq!(list.len(), 1, "应恰好列举一个对象");
        assert_eq!(list[0].name, filename);
        assert_eq!(list[0].size, payload.len() as u64);
        assert_eq!(list[0].url, format!("{endpoint}/{BUCKET}/{dir}/{filename}"));

        // delete → DELETE，随后 read 为 None，重复 delete 幂等
        backend.delete(dir, filename).await.expect("delete 失败");
        assert_eq!(backend.read(dir, filename).await.unwrap(), None);
        backend.delete(dir, filename).await.expect("重复删除应幂等");
    }

    #[tokio::test]
    async fn tampered_body_fails_server_signature_verification() {
        // 直连假端点：故意让 x-amz-content-sha256 与真实 body 不一致应被服务端拒绝（403）。
        // 证明验签路径确实生效，而非恒真。
        let (endpoint, st) = spawn_fake_s3().await;
        let backend = backend_for(&endpoint);
        let _ = backend
            .save("uploads/file", "ok.txt", "/uploads/file", b"abc")
            .await
            .expect("正常 save 应成功");
        assert_eq!(st.store.lock().unwrap().len(), 1);

        // 绕过 backend，手工构造签名正确但 payload 头错误的请求，确认服务端会拒绝。
        let url = format!("{endpoint}/{BUCKET}/uploads/file/evil.txt");
        let bad_body = b"real-bytes".to_vec();
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let date = &amz_date[..8];
        let wrong_hash = sha256_hex(b"definitely-not-the-body");
        let headers = vec![
            (
                "host".to_string(),
                url.replace("http://", "")
                    .split('/')
                    .next()
                    .unwrap()
                    .to_string(),
            ),
            ("x-amz-content-sha256".to_string(), wrong_hash.clone()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        let (hb, sh) = canonical_headers(&headers);
        let creq = canonical_request(
            "PUT",
            "/testbucket/uploads/file/evil.txt",
            "",
            &hb,
            &sh,
            &wrong_hash,
        );
        let ch = sha256_hex(creq.as_bytes());
        let sts = string_to_sign(&amz_date, date, REGION, "s3", &ch);
        let skey = signing_key(SECRET, date, REGION, "s3");
        let sig = signature(&skey, &sts);
        let resp = reqwest::Client::new()
            .put(&url)
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &wrong_hash)
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/{date}/{REGION}/s3/aws4_request, SignedHeaders={sh}, Signature={sig}"
                ),
            )
            .body(bad_body)
            .send()
            .await
            .expect("请求应送达");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "payload 头与请求体不一致应被服务端验签拒绝"
        );
    }
}
