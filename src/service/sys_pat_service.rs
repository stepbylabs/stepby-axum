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

use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
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
    /// 是否已开通开放 API AK/SK 凭据（access_key 与 secret_key 均非空；
    /// 前端轮换/吊销按钮恒常显——后端操作幂等，本字段供后续优化展示态）
    #[serde(default)]
    pub has_ak: bool,
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
    /// 是否同时开通开放 API 的 AK/SK 凭据（true → 生成 access_key/secret_key；
    /// SK 明文仅创建响应返回一次，落库为信封密文）
    #[serde(default)]
    #[ts(optional)]
    pub with_ak: Option<bool>,
}

/// 新建令牌结果：明文 `token` 仅此一次返回
#[derive(Debug, Clone, Serialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "PatCreateResult.ts", rename_all = "camelCase")]
#[schema(as = PatCreateResult)]
pub struct CreatePatResult {
    pub token: String,
    pub pat: PatVo,
    /// 开放 API access_key（"ak" + 24 位 hex；开通 AK 时返回）
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub access_key: Option<String>,
    /// 开放 API secret_key 明文（仅创建/轮换响应返回一次，绝不落库）
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub secret_key: Option<String>,
}

/// 轮换 AK/SK 结果：新 SK 明文仅此一次返回
#[derive(Debug, Clone, Serialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "PatRotateAkResult.ts", rename_all = "camelCase")]
#[schema(as = PatRotateAkResult)]
pub struct RotateAkResult {
    pub access_key: String,
    pub secret_key: String,
}

/// 鉴权命中的令牌信息（供 auth 中间件合成 Claims）
#[derive(Debug, Clone)]
pub struct VerifiedPat {
    pub pat_id: String,
    pub user_id: i64,
    pub username: String,
    pub scopes: Vec<String>,
    /// Phase 3：令牌归属租户（随 token 行带出，供鉴权中间件合成 claims.tid 与
    /// 租户生命周期闸门判定；PAT 属用户级凭据，租户随用户）
    pub tenant_id: i64,
}

/// AK/SK 验签查库命中的凭据信息（供 ak_sign 中间件注入请求扩展）
#[derive(Debug, Clone)]
pub struct VerifiedAk {
    pub pat_id: String,
    pub user_id: i64,
    pub tenant_id: i64,
    pub access_key: String,
    /// 解密后的 SK 明文（仅进程内用于 HMAC 验签，绝不落日志/响应）
    pub secret_plain: String,
    /// PAT 名称（/open/v1/profile 展示用）
    pub pat_name: String,
    pub username: String,
    pub expires_at: Option<chrono::NaiveDateTime>,
}

/// AK 查库结果（区分失败原因，供中间件映射不同 401 i18n key；
/// 不区分"不存在"与"SK 损坏"等细节，避免存在性探测）
#[derive(Debug, Clone)]
pub enum AkLookup {
    /// 命中且有效（PAT 有效 + 属主存活 + SK 可解密）
    Valid(VerifiedAk),
    /// AK 不存在（含 revoke-ak 已清空的）
    NotFound,
    /// AK 所属 PAT 已吊销（status='1'）
    Revoked,
    /// AK 所属 PAT 已过期
    Expired,
    /// 属主账号已删除/停用（口径对齐 verify_token 的属主校验）
    OwnerDisabled,
}

/// 开放 API /open/v1/profile 出参
#[derive(Debug, Clone, Serialize, ToSchema, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "OpenProfileVo.ts", rename_all = "camelCase")]
#[schema(as = OpenProfileVo)]
pub struct OpenProfileVo {
    /// PAT 名称
    pub pat_name: String,
    /// 属主用户名
    pub username: String,
    /// 归属租户 ID
    pub tenant_id: i64,
    /// PAT 过期时间（None = 永不过期）
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub expires_at: Option<String>,
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

    /// 签发令牌，返回一次性明文 + 脱敏视图（tenant_id 随 operator 带出，PAT 归 operator 租户）
    ///
    /// `enc_key`：CONFIG_ENC_KEY 主密钥（SK 信封加密用，与 oauth client_secret 同机制）。
    /// `dto.with_ak = true` 时同时生成 AK/SK：SK 明文仅本响应返回一次。
    pub async fn create(
        &self,
        user_id: i64,
        tenant_id: i64,
        username: &str,
        dto: CreatePatDto,
        config: &PatConfig,
        enc_key: &str,
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
        {
            use rand_os::{Rng, SeedableRng, rngs::StdRng};
            let mut rng =
                StdRng::try_from_rng(&mut rand_os::rngs::SysRng).expect("OS RNG seed failed");
            rng.fill_bytes(&mut buf);
        }
        let secret = hex_encode(&buf);
        let token = format!("{}{}", config.prefix, secret);
        let token_hash = crate::utils::crypto::token_hash(&token);
        let token_prefix: String = token.chars().take(11).collect();

        let scopes_json = serde_json::to_string(&dto.scopes)
            .map_err(|_| ServiceError::internal(&crate::tr!("error.pat.create_failed")))?;

        // 开放 API AK/SK（with_ak=true 时开通）：SK 明文仅响应一次，落库为 v2 信封密文
        // （跟随 oauth client_secret 的 seal_sensitive_value 机制——SK 需原文做 HMAC 验签，
        // 故采用可逆的 AES-256-GCM 信封加密而非单向哈希）
        let mut ak_plain: Option<String> = None;
        let mut sk_plain_out: Option<String> = None;
        let mut ak_column: Option<String> = None;
        let mut sk_column: Option<String> = None;
        if dto.with_ak.unwrap_or(false) {
            let ak = generate_access_key();
            let sk = generate_secret_key();
            let sealed = crate::utils::crypto::seal_sensitive_value(&sk, enc_key)
                .map_err(|_| ServiceError::internal(&crate::tr!("error.pat.create_failed")))?;
            ak_column = Some(ak.clone());
            sk_column = Some(sealed);
            ak_plain = Some(ak);
            sk_plain_out = Some(sk);
        }

        let model = PatModel {
            pat_id: format!("{:x}", uuid::Uuid::new_v4().simple()),
            tenant_id,
            user_id,
            name: name.to_string(),
            token_hash,
            token_prefix,
            scopes: scopes_json,
            status: "0".to_string(),
            expires_at,
            access_key: ak_column,
            secret_key: sk_column,
            last_used_at: None,
            create_by: username.to_string(),
            create_time: Some(now),
            update_time: Some(now),
        };
        self.pat_repo.insert(model.clone()).await?;

        Ok(CreatePatResult {
            token,
            pat: vo_from_model(model, String::new()),
            access_key: ak_plain,
            secret_key: sk_plain_out,
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
    ///
    /// `tenant_scope`：租户操作者 → `Some(tid)` 仅本租户令牌；平台 → `None` 全量。
    pub async fn list_all(
        &self,
        user_id: Option<i64>,
        page_num: u64,
        page_size: u64,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<PatVo>, u64), ServiceError> {
        let (offset, limit) = page_args(page_num, page_size);
        let (rows, total) = self
            .pat_repo
            .find_page_all(user_id, offset, limit, tenant_scope)
            .await?;
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
        let affected = self.pat_repo.revoke(pat_id, Some(user_id), None).await?;
        if affected == 0 {
            return Err(ServiceError::not_found(&crate::tr!("error.pat.not_found")));
        }
        Ok(())
    }

    /// 管理员吊销（不限属主，但受租户归属收敛：仅本租户令牌）
    ///
    /// `operator_tid`：租户管理员只能吊销本租户令牌（跨租户统一按不存在处理，避免存在性泄露）；
    /// 平台（0）不限。
    pub async fn revoke_by_admin(
        &self,
        pat_id: &str,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let affected = self
            .pat_repo
            .revoke(
                pat_id,
                None,
                crate::common::tenant::tenant_scope(operator_tid),
            )
            .await?;
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
    /// 校验：enabled（由调用方 middleware 前置判断）→ 摘要命中 → status='0' → 未过期
    /// → 属主 sys_user 存活（E1-a：`del_flag != '2'` 且 `status = '0'`）。
    /// 属主已软删/停用时令牌立即失效（与 JWT 链路的租户停用闸门口径一致：
    /// 账号生命周期关闭则其全部凭据随之失效）。
    pub async fn verify_token(&self, token: &str) -> Result<Option<VerifiedPat>, ServiceError> {
        let hash = crate::utils::crypto::token_hash(token);
        let Some(row) = self.pat_repo.find_by_hash(&hash).await? else {
            return Ok(None);
        };
        if row.status != "0" {
            return Ok(None);
        }
        if let Some(exp) = row.expires_at
            && exp <= datetime::now_naive()
        {
            return Ok(None);
        }
        // E1-a：回查属主 sys_user，已删/停用账号的 PAT 一律拒绝（纵深防御：
        // delete_user 事务内会物理清理 PAT，此处再兜底覆盖历史遗留与任何旁路删除）
        let owner = crate::entity::sys_user::Entity::find_by_id(row.user_id)
            .one(self.pat_repo.base().db())
            .await?;
        let Some(owner) = owner else {
            return Ok(None);
        };
        if owner.del_flag.as_deref() == Some("2") || owner.status.as_deref() != Some("0") {
            return Ok(None);
        }
        let scopes: Vec<String> = serde_json::from_str(&row.scopes).unwrap_or_default();
        Ok(Some(VerifiedPat {
            pat_id: row.pat_id.clone(),
            user_id: row.user_id,
            username: row.create_by.clone(),
            scopes,
            tenant_id: row.tenant_id,
        }))
    }

    /// best-effort 更新最近使用时间（供中间件 spawn 调用，失败忽略）
    pub async fn touch_last_used(&self, pat_id: &str) {
        if let Err(e) = self.pat_repo.touch_last_used(pat_id).await {
            tracing::debug!("更新 PAT last_used_at 失败（忽略）: {}", e);
        }
    }

    // ══ 开放 API AK/SK 域 ══

    /// 轮换 AK/SK：重置 SK（AK 不变），新 SK 明文仅本次响应返回一次
    ///
    /// - 属主校验：仅本人 PAT 可轮换（越权按不存在处理，避免存在性泄露）；
    /// - 未开通 AK 的 PAT → 404 语义错误（error.ak.not_enabled）；
    /// - 旧 SK 轮换后立即失效（覆盖写信封密文）。
    pub async fn rotate_ak(
        &self,
        pat_id: &str,
        user_id: i64,
        enc_key: &str,
    ) -> Result<RotateAkResult, ServiceError> {
        let db = self.pat_repo.base().db();
        let Some(row) = crate::entity::sys_pat::Entity::find_by_id(pat_id.to_string())
            .one(db)
            .await?
        else {
            return Err(ServiceError::not_found(&crate::tr!("error.pat.not_found")));
        };
        // 越权保护：非本人令牌统一按不存在处理
        if row.user_id != user_id {
            return Err(ServiceError::not_found(&crate::tr!("error.pat.not_found")));
        }
        let access_key = row
            .access_key
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.ak.not_enabled")))?;

        let secret_plain = generate_secret_key();
        let sealed = crate::utils::crypto::seal_sensitive_value(&secret_plain, enc_key)
            .map_err(|_| ServiceError::internal(&crate::tr!("error.pat.create_failed")))?;

        let mut am: crate::entity::sys_pat::ActiveModel = row.into();
        am.secret_key = Set(Some(sealed));
        am.update_time = Set(Some(datetime::now_naive()));
        am.update(db).await?;

        Ok(RotateAkResult {
            access_key,
            secret_key: secret_plain,
        })
    }

    /// 吊销 AK/SK：清空两列（幂等；仅本人 PAT，越权按不存在处理）
    ///
    /// 清空后 AK 鉴权查库即 NotFound（即时生效，无缓存），SK 密文一并清除。
    pub async fn revoke_ak(&self, pat_id: &str, user_id: i64) -> Result<(), ServiceError> {
        let db = self.pat_repo.base().db();
        let Some(row) = crate::entity::sys_pat::Entity::find_by_id(pat_id.to_string())
            .one(db)
            .await?
        else {
            return Err(ServiceError::not_found(&crate::tr!("error.pat.not_found")));
        };
        if row.user_id != user_id {
            return Err(ServiceError::not_found(&crate::tr!("error.pat.not_found")));
        }
        let mut am: crate::entity::sys_pat::ActiveModel = row.into();
        am.access_key = Set(None);
        am.secret_key = Set(None);
        am.update_time = Set(Some(datetime::now_naive()));
        am.update(db).await?;
        Ok(())
    }

    /// AK 鉴权查库（ak_sign 中间件每请求调用；吊销/过期/属主停用即时生效）
    ///
    /// 校验链：access_key 唯一命中 → PAT status='0' → 未过期 → 属主 sys_user 存活
    /// （与 verify_token 的 E1-a 属主口径一致）→ SK 密文可解密。
    /// SK 解密失败按 NotFound 处理（fail-closed，不泄露区分信息）。
    pub async fn verify_ak(
        &self,
        access_key: &str,
        enc_key: &str,
    ) -> Result<AkLookup, ServiceError> {
        use crate::entity::sys_pat::{Column as PatColumn, Entity as SysPat};
        let db = self.pat_repo.base().db();
        let Some(row) = SysPat::find()
            .filter(PatColumn::AccessKey.eq(access_key))
            .one(db)
            .await?
        else {
            return Ok(AkLookup::NotFound);
        };
        if row.status != "0" {
            return Ok(AkLookup::Revoked);
        }
        if let Some(exp) = row.expires_at
            && exp <= datetime::now_naive()
        {
            return Ok(AkLookup::Expired);
        }
        // 属主存活校验（E1-a 同口径：del_flag != '2' 且 status = '0'）
        let owner = crate::entity::sys_user::Entity::find_by_id(row.user_id)
            .one(db)
            .await?;
        let Some(owner) = owner else {
            return Ok(AkLookup::OwnerDisabled);
        };
        if owner.del_flag.as_deref() == Some("2") || owner.status.as_deref() != Some("0") {
            return Ok(AkLookup::OwnerDisabled);
        }
        let Some(sealed) = row.secret_key.clone().filter(|s| !s.is_empty()) else {
            return Ok(AkLookup::NotFound);
        };
        // SK 需原文参与 HMAC-SHA256 验签 → 采用可逆信封加密存储；此处解密取回原文
        let secret_plain = match crate::utils::crypto::decrypt_config_value(&sealed, enc_key) {
            Ok(s) => s,
            Err(e) => {
                // 密钥不匹配/数据损坏：fail-closed 拒绝，日志只记根因不落任何密钥信息
                tracing::error!("PAT AK secret_key 解密失败（按不存在处理）: {}", e);
                return Ok(AkLookup::NotFound);
            }
        };
        Ok(AkLookup::Valid(VerifiedAk {
            pat_id: row.pat_id.clone(),
            user_id: row.user_id,
            tenant_id: row.tenant_id,
            access_key: row.access_key.clone().unwrap_or_default(),
            secret_plain,
            pat_name: row.name.clone(),
            username: owner.user_name,
            expires_at: row.expires_at,
        }))
    }

    /// 开放 API /open/v1/profile 数据源（真实查库；属主用户名优先取 sys_user，缺失回退 create_by）
    pub async fn open_profile(&self, pat_id: &str) -> Result<Option<OpenProfileVo>, ServiceError> {
        use crate::entity::sys_user;
        let db = self.pat_repo.base().db();
        let Some(row) = crate::entity::sys_pat::Entity::find_by_id(pat_id.to_string())
            .one(db)
            .await?
        else {
            return Ok(None);
        };
        let username = sys_user::Entity::find_by_id(row.user_id)
            .one(db)
            .await?
            .map(|u| u.user_name)
            .unwrap_or_else(|| row.create_by.clone());
        Ok(Some(OpenProfileVo {
            pat_name: row.name,
            username,
            tenant_id: row.tenant_id,
            expires_at: fmt_dt(row.expires_at),
        }))
    }
}

// ==================== 纯函数辅助 ====================

/// 生成开放 API access_key："ak" + 12 随机字节 hex（总长 26，满足列宽 VARCHAR(32)）
fn generate_access_key() -> String {
    use rand_os::{Rng, SeedableRng, rngs::StdRng};
    let mut buf = [0u8; 12];
    let mut rng = StdRng::try_from_rng(&mut rand_os::rngs::SysRng).expect("OS RNG seed failed");
    rng.fill_bytes(&mut buf);
    format!("ak{}", hex_encode(&buf))
}

/// 生成开放 API secret_key：36 随机字节的 base64url（无填充，恰 48 字符）
///
/// base64url 字符集不含 '+' '/'，作为签名密钥/HTTP 头取值均安全。
fn generate_secret_key() -> String {
    use base64::Engine;
    use rand_os::{Rng, SeedableRng, rngs::StdRng};
    let mut buf = [0u8; 36];
    let mut rng = StdRng::try_from_rng(&mut rand_os::rngs::SysRng).expect("OS RNG seed failed");
    rng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

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
        // 仅 VO 组装判定：AK 与 SK 密文列均非空即视为已开通（不动其它逻辑）
        has_ak: m.access_key.is_some() && m.secret_key.is_some(),
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
            prefix: "sb_".to_string(),
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

    #[test]
    fn test_generate_access_key_shape() {
        let ak = generate_access_key();
        assert!(ak.starts_with("ak"), "AK 应以 ak 前缀开头: {ak}");
        assert_eq!(ak.len(), 26, "AK 应为 ak + 24 hex 字符");
        assert!(ak[2..].chars().all(|c| c.is_ascii_hexdigit()));
        // 随机性：两次生成不重复
        assert_ne!(generate_access_key(), generate_access_key());
    }

    #[test]
    fn test_generate_secret_key_shape() {
        let sk = generate_secret_key();
        assert_eq!(sk.len(), 48, "SK 应为 48 字符 base64url，实际: {sk}");
        assert!(
            sk.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "SK 应为 base64url 字符集（无 + / =），实际: {sk}"
        );
        assert_ne!(generate_secret_key(), generate_secret_key());
    }
}
