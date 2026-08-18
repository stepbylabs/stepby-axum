//! S3 兼容对象存储后端（MinIO / AWS S3 / 阿里云 OSS / 腾讯 COS，F1）
//!
//! 基于 reqwest + 自研 AWS SigV4 签名（[`super::sigv4`]），采用路径风格（path-style）寻址：
//! - 对象 key：`uploads/{dir}/{filename}`（与本地目录结构对应）
//! - 请求地址：`{endpoint}/{bucket}/{key}`
//! - 访问 URL：`{public_endpoint|endpoint}/{bucket}/{key}`（返回前端，无需改前端）

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
    /// 存储端点（用于发请求，如 `https://minio.example.com:9000`），去除末尾 `/`
    endpoint_base: String,
    /// endpoint 的 authority（host[:port]），作为 SigV4 canonical Host 头
    endpoint_authority: String,
    /// 对外公开 URL 前缀（可为 CDN），去除末尾 `/`；缺省回退 endpoint_base
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
        let public_base = if cfg.public_endpoint.trim().is_empty() {
            endpoint_base.clone()
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
            endpoint_base,
            endpoint_authority,
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

    /// 对象 URI（路径风格）：`/{bucket}/{key}`
    fn object_uri(&self, key: &str) -> String {
        format!("/{}/{key}", self.bucket)
    }

    /// 对象访问 URL
    fn object_url(&self, key: &str) -> String {
        format!("{}/{}/{key}", self.public_base, self.bucket)
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
            ("host".to_string(), self.endpoint_authority.clone()),
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

        let mut url = format!("{}{}", self.endpoint_base, canonical_uri);
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
                .signed_send(
                    reqwest::Method::GET,
                    &format!("/{}/", self.bucket),
                    &query,
                    None,
                    b"",
                )
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
    }
}
