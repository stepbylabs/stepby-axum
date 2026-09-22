//! 个人访问令牌（PAT）模块 Service 层
//!
//! 职责：
//! - 签发令牌：生成 `ybt_` 前缀随机明文（仅此接口返回一次），落库存 SHA-256 摘要 + 展示前缀；
//! - 鉴权查库：`verify_token` 按摘要命中且 status='0' 且未过期时返回属主身份 + scopes；
//! - 自助/管理列表与吊销：出参统一走脱敏 `PatVo`，绝不返回 token_hash；
//! - scope 选项：`scope_options` 返回当前用户可授予的权限标识（来自 menu_service 权限集）。
//!
//! 安全红线：
//! - 明文不落库；
//! - 吊销即时生效（每请求查库，无缓存）；
//! - `scope_allows` 为鉴权作用域匹配的单一实现，供 permission 中间件复用。
//!
//! 分层约束：不依赖 axum/tower；错误用 ServiceError。

use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;
use crate::common::error::ServiceError;
use crate::config::PatConfig;
use crate::entity::sys_pat::Model as PatModel;
use crate::repository::sys_pat::SysPatRepository;
use crate::service::SysMenuService;

/// 令牌出参 VO（脱敏：不含 token_hash）
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SysPat.ts", rename_all = "camelCase")]
#[schema(as = SysPat)]
pub struct PatVo {
    pub pat_id: String,
    pub user_id: i64,
    /// 属主用户名（管理员列表展示；自助列表可空）
    #[serde(default)]
    pub user_name: String,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
}

/// 新建令牌请求 DTO
#[derive(Debug, Clone, Deserialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "PatCreateDto.ts", rename_all = "camelCase")]
#[schema(as = PatCreateDto)]
pub struct CreatePatDto {
    pub name: String,
    pub scopes: Vec<String>,
    /// 有效期（天）：省略 → 使用配置默认；0 → 永不过期；正数 → 按天（受上限裁剪）
    #[serde(default)]
    #[ts(optional)]
    pub expire_days: Option<i64>,
}

/// 新建令牌结果：明文 `token` 仅此一次返回
#[derive(Debug, Clone, Serialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "PatCreateResult.ts", rename_all = "camelCase")]
#[schema(as = PatCreateResult)]
pub struct CreatePatResult {
    pub token: String,
    pub pat: PatVo,
}

/// 鉴权命中的令牌信息（供 auth 中间件合成 Claims）
#[derive(Debug, Clone)]
pub struct VerifiedPat {
    pub pat_id: String,
    pub user_id: i64,
    pub username: String,
    pub scopes: Vec<String>,
}

/// 个人访问令牌 Service
#[derive(Clone)]
pub struct SysPatService {
    pat_repo: SysPatRepository,
    menu_service: SysMenuService,
}

impl SysPatService {
    pub fn new(db: DatabaseConnection, menu_service: SysMenuService) -> Self {
        Self {
            pat_repo: SysPatRepository::new(db),
            menu_service,
        }
    }

    /// 签发令牌，返回一次性明文 + 脱敏视图
    pub async fn create(
        &self,
        user_id: i64,
        username: &str,
        dto: CreatePatDto,
        config: &PatConfig,
    ) -> Result<CreatePatResult, ServiceError> {
        let name = dto.name.trim();
        if name.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.pat.name_required"
            )));
        }
        if name.chars().count() > 100 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.pat.name_too_long"
            )));
        }
        if dto.scopes.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.pat.scopes_empty"
            )));
        }
        for s in &dto.scopes {
            if !is_valid_perm_key(s) {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.pat.scopes_invalid",
                    value = s
                )));
            }
        }

        // 每用户有效令牌数上限
        let active = self.pat_repo.count_active_by_user(user_id).await?;
        if active >= config.max_per_user.max(1) as u64 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.pat.count_exceeded",
                max = config.max_per_user
            )));
        }

        let now = datetime::now_naive();
        let expires_at = resolve_expiry(now, dto.expire_days, config);

        // 生成明文令牌：prefix + 32 随机字节（hex，64 字符）
        let mut buf = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        let secret = hex_encode(&buf);
        let token = format!("{}{}", config.prefix, secret);
        let token_hash = crate::utils::crypto::token_hash(&token);
        let token_prefix: String = token.chars().take(11).collect();

        let scopes_json = serde_json::to_string(&dto.scopes)
            .map_err(|_| ServiceError::internal(&crate::tr!("error.pat.create_failed")))?;

        let model = PatModel {
            pat_id: format!("{:x}", uuid::Uuid::new_v4().simple()),
            user_id,
            name: name.to_string(),
            token_hash,
            token_prefix,
            scopes: scopes_json,
            status: "0".to_string(),
            expires_at,
            last_used_at: None,
            create_by: username.to_string(),
            create_time: Some(now),
            update_time: Some(now),
        };
        self.pat_repo.insert(model.clone()).await?;

        Ok(CreatePatResult {
            token,
            pat: vo_from_model(model, String::new()),
        })
    }

    /// 自助分页列表（仅本人令牌）
    pub async fn list_mine(
        &self,
        user_id: i64,
        page_num: u64,
        page_size: u64,
    ) -> Result<(Vec<PatVo>, u64), ServiceError> {
        let (offset, limit) = page_args(page_num, page_size);
        let (rows, total) = self
            .pat_repo
            .find_page_by_user(user_id, offset, limit)
            .await?;
        Ok((
            rows.into_iter()
                .map(|m| vo_from_model(m, String::new()))
                .collect(),
            total,
        ))
    }

    /// 管理员分页列表（可含全部，联属主用户名）
    pub async fn list_all(
        &self,
        user_id: Option<i64>,
        page_num: u64,
        page_size: u64,
    ) -> Result<(Vec<PatVo>, u64), ServiceError> {
        let (offset, limit) = page_args(page_num, page_size);
        let (rows, total) = self.pat_repo.find_page_all(user_id, offset, limit).await?;
        let ids: Vec<i64> = rows.iter().map(|r| r.user_id).collect();
        let names: std::collections::HashMap<i64, String> = self
            .pat_repo
            .find_usernames(&ids)
            .await?
            .into_iter()
            .collect();
        let vos = rows
            .into_iter()
            .map(|m| {
                let uname = names.get(&m.user_id).cloned().unwrap_or_default();
                vo_from_model(m, uname)
            })
            .collect();
        Ok((vos, total))
    }

    /// 自助吊销（越权保护：仅本人令牌）
    pub async fn revoke_mine(&self, pat_id: &str, user_id: i64) -> Result<(), ServiceError> {
        let affected = self.pat_repo.revoke(pat_id, Some(user_id)).await?;
        if affected == 0 {
            return Err(ServiceError::not_found(&crate::tr!("error.pat.not_found")));
        }
        Ok(())
    }

    /// 管理员吊销（不限属主）
    pub async fn revoke_by_admin(&self, pat_id: &str) -> Result<(), ServiceError> {
        let affected = self.pat_repo.revoke(pat_id, None).await?;
        if affected == 0 {
            return Err(ServiceError::not_found(&crate::tr!("error.pat.not_found")));
        }
        Ok(())
    }

    /// 当前用户可授予的 scope 选项（其权限集；超管返回 `*:*:*` + 常见通配分组）
    pub async fn scope_options(&self, user_id: i64) -> Result<Vec<String>, ServiceError> {
        let perms = self
            .menu_service
            .get_permissions_by_user_id(user_id)
            .await?;
        let mut out: Vec<String> = perms.clone();
        // 超管权限集为 ["*:*:*"]，额外提供常用通配分组便于签发受限令牌
        if perms.iter().any(|p| p == "*:*:*") {
            for w in ["*:*:*", "system:*:*", "monitor:*:*", "tool:*:*"] {
                if !out.iter().any(|x| x == w) {
                    out.push(w.to_string());
                }
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// 鉴权：按明文令牌摘要命中有效令牌则返回属主身份 + scopes
    ///
    /// 校验：enabled（由调用方 middleware 前置判断）→ 摘要命中 → status='0' → 未过期。
    pub async fn verify_token(&self, token: &str) -> Result<Option<VerifiedPat>, ServiceError> {
        let hash = crate::utils::crypto::token_hash(token);
        let Some(row) = self.pat_repo.find_by_hash(&hash).await? else {
            return Ok(None);
        };
        if row.status != "0" {
            return Ok(None);
        }
        if let Some(exp) = row.expires_at && exp <= datetime::now_naive() {
            return Ok(None);
        }
        let scopes: Vec<String> = serde_json::from_str(&row.scopes).unwrap_or_default();
        Ok(Some(VerifiedPat {
            pat_id: row.pat_id.clone(),
            user_id: row.user_id,
            username: row.create_by.clone(),
            scopes,
        }))
    }

    /// best-effort 更新最近使用时间（供中间件 spawn 调用，失败忽略）
    pub async fn touch_last_used(&self, pat_id: &str) {
        if let Err(e) = self.pat_repo.touch_last_used(pat_id).await {
            tracing::debug!("更新 PAT last_used_at 失败（忽略）: {}", e);
        }
    }
}

// ==================== 纯函数辅助 ====================

/// 权限标识格式校验：`*` 或 1~3 段以 ':' 分隔，每段为 `*` 或 `[A-Za-z0-9_-]+`
pub fn is_valid_perm_key(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 {
        return false;
    }
    let segs: Vec<&str> = s.split(':').collect();
    if segs.is_empty() || segs.len() > 3 {
        return false;
    }
    segs.iter().all(|seg| {
        !seg.is_empty()
            && (*seg == "*"
                || seg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
    })
}

/// 作用域匹配：granted 集合中是否存在通配覆盖 required 的项（按 ':' 分段，`*` 匹配任一段）。
///
/// 与 permission 中间件的“用户是否具备权限”共同构成 PAT 请求的有效权限判定。
pub fn scope_allows(granted: &[String], required: &str) -> bool {
    let req: Vec<&str> = required.split(':').collect();
    granted.iter().any(|g| {
        let gs: Vec<&str> = g.split(':').collect();
        // 逐段比对：段数需一致（缺省段按 '*' 处理，便于 "*:*:*" / "system:*" 覆盖三段）
        (0..req.len()).all(|i| {
            let seg = gs.get(i).copied().unwrap_or("*");
            seg == "*" || seg == req[i]
        })
    })
}

/// 解析过期时间：None→默认；Some(0)→永不过期；Some(d>0)→按天（受 max 裁剪）
fn resolve_expiry(
    now: chrono::NaiveDateTime,
    expire_days: Option<i64>,
    config: &PatConfig,
) -> Option<chrono::NaiveDateTime> {
    let days = match expire_days {
        None => config.default_expire_days,
        Some(0) => return None, // 永不过期
        Some(d) if d < 0 => config.default_expire_days,
        Some(d) => d,
    };
    let days = if config.max_expire_days > 0 {
        days.clamp(1, config.max_expire_days)
    } else {
        days.max(1)
    };
    Some(now + chrono::Duration::days(days))
}

fn page_args(page_num: u64, page_size: u64) -> (u64, u64) {
    let size = page_size.clamp(1, 100);
    let num = page_num.max(1);
    ((num - 1) * size, size)
}

fn fmt_dt(dt: Option<chrono::NaiveDateTime>) -> Option<String> {
    dt.map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
}

fn vo_from_model(m: PatModel, user_name: String) -> PatVo {
    PatVo {
        pat_id: m.pat_id,
        user_id: m.user_id,
        user_name,
        name: m.name,
        token_prefix: m.token_prefix,
        scopes: serde_json::from_str(&m.scopes).unwrap_or_default(),
        status: m.status,
        expires_at: fmt_dt(m.expires_at),
        last_used_at: fmt_dt(m.last_used_at),
        create_time: fmt_dt(m.create_time),
    }
}

/// hex 编码（避免为此引入额外依赖）
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_perm_key() {
        assert!(is_valid_perm_key("system:notice:list"));
        assert!(is_valid_perm_key("*:*:*"));
        assert!(is_valid_perm_key("monitor:*:*"));
        assert!(is_valid_perm_key("system:user"));
        assert!(is_valid_perm_key("tool.gen"));
        assert!(!is_valid_perm_key(""));
        assert!(!is_valid_perm_key("a:b:c:d"));
        assert!(!is_valid_perm_key("a::b"));
        assert!(!is_valid_perm_key("a b"));
        assert!(!is_valid_perm_key("a:b!c"));
    }

    #[test]
    fn test_scope_allows_exact_and_wildcard() {
        let g = vec!["system:notice:list".to_string(), "monitor:*:*".to_string()];
        assert!(scope_allows(&g, "system:notice:list"));
        assert!(scope_allows(&g, "monitor:operlog:query"));
        assert!(!scope_allows(&g, "system:user:edit"));
        // 超管令牌 scope "*:*:*" 覆盖一切
        let all = vec!["*:*:*".to_string()];
        assert!(scope_allows(&all, "anything:goes:here"));
        // 缺省段按 '*' 处理："system:*" 覆盖三段
        let two = vec!["system:*".to_string()];
        assert!(scope_allows(&two, "system:user:edit"));
    }

    #[test]
    fn test_resolve_expiry() {
        let now = datetime::now_naive();
        let cfg = PatConfig {
            enabled: true,
            prefix: "ybt_".to_string(),
            default_expire_days: 90,
            max_expire_days: 365,
            max_per_user: 20,
        };
        assert!(resolve_expiry(now, Some(0), &cfg).is_none());
        let d30 = resolve_expiry(now, Some(30), &cfg).unwrap();
        assert_eq!((d30 - now).num_days(), 30);
        // 超上限裁剪到 365
        let big = resolve_expiry(now, Some(9999), &cfg).unwrap();
        assert_eq!((big - now).num_days(), 365);
        // None → 默认 90
        let def = resolve_expiry(now, None, &cfg).unwrap();
        assert_eq!((def - now).num_days(), 90);
    }

    #[test]
    fn test_page_args_clamps() {
        assert_eq!(page_args(0, 0), (0, 1));
        assert_eq!(page_args(2, 10), (10, 10));
        assert_eq!(page_args(3, 9999), (200, 100));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x0a]), "00ff0a");
    }
}
