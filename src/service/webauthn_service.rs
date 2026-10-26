// stepby-axum/src/service/webauthn_service.rs
//! WebAuthn / Passkey 服务（能力位 `auth.webauthn`，默认 **off**）。
//!
//! # 定位
//!
//! 在既有账号体系上提供 **passkey（免密码）登录**与**自助绑定/管理**：
//! - 持久化实现 [`PasskeyStore`]（SeaORM 落库；挑战等临时态存共享态存储，带 TTL）；
//! - 封装注册 / 认证四条流程与凭据自助管理；
//! - 登录成功**复用既有登录完成链路**（`AuthService` 签发 JWT + 在线会话 + 登录日志）。
//!
//! # 守卫顺序（fail-closed）
//!
//! 1. **能力位非 `on` ⇒ 404**（与 `[sso].introspection_enabled` 同口径，不暴露"存在但被关"）；
//! 2. `rp_id` / `origin` 未配置且无法推导 ⇒ 503（服务器未就绪，拒绝静默失效）；
//! 3. 用户不存在 / 已停用 / 已删除 / 租户闸门拒绝 ⇒ 自助面 404/403、登录面统一 401；
//! 4. 归属校验：删除/重命名仅限本人凭据（Repository 以 `user_id` 收窄，0 行 ⇒ 404）。
//!
//! # 反用户名枚举（公开 `login/start` 的取舍）
//!
//! 公开 `login/start` 对"用户不存在 / 账号停用 / 租户停用 / 无凭据"一律返回**与密码登录
//! 失败同形**的 `401 error.auth.login_failed`（码 + 文案完全一致）。这牺牲了"精确提示
//! 无 passkey"的友好度，换来用户名不可枚举——与密码登录的既有策略（C-1）一致，属**有意**权衡。

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use passkey_server::error::{PasskeyError, Result as PasskeyResult};
use passkey_server::types::{
    CredentialDescriptor, LoginResponse, PasskeyState, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, RegistrationResponse, StoredPasskey,
};
use passkey_server::{
    PasskeyConfig, PasskeyStore, finish_login, finish_registration, start_login, start_registration,
};
use sea_orm::{DatabaseConnection, Set};
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::ServiceError;
use crate::common::features::{FeatureSet, mode_reaches};
use crate::config::settings::{ResolvedWebauthn, Settings};
use crate::entity::sys_user::Model as SysUserModel;
use crate::entity::sys_user_credential::{
    ActiveModel as CredentialActiveModel, Model as CredentialModel,
};
use crate::repository::sys_user::SysUserRepository;
use crate::repository::sys_user_credential::SysUserCredentialRepository;
use crate::service::sys_tenant_service::{SysTenantService, TenantLoginState};

/// 能力位键（与 `governance::FEATURES` 登记项逐字一致）
pub const FEATURE_WEBAUTHN: &str = "auth.webauthn";

/// Redis 键前缀：WebAuthn 临时态（挑战 / 会话）
const STATE_KEY_PREFIX: &str = "webauthn:state:";

/// `create_passkey` 内部拒绝标记（同名 / 同凭据重复注册）。
///
/// 因 [`PasskeyStore`] 的 trait 签名只能返回 [`PasskeyError`]，用带标记的
/// `DatabaseError` 把"业务拒绝原因"透传到服务层的映射函数（非静默，非假实现）。
const DUP_CREDENTIAL_MARKER: &str = "webauthn:duplicate_credential";
const DUP_NAME_MARKER: &str = "webauthn:duplicate_name";

// ==================== DTO / VO ====================

/// Passkey 注册完成请求（对应 `navigator.credentials.create` 结果的 `toJSON()`）。
#[derive(Debug, Clone, Serialize, Deserialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    export_to = "WebauthnRegisterFinishDto.ts",
    rename_all = "camelCase"
)]
pub struct WebauthnRegisterFinishDto {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AttestationResponseDto,
    /// 凭据名（可空；缺省由认证器 AAGUID 派生）
    #[serde(default)]
    pub name: Option<String>,
}

/// 注册响应内的证明对象（Base64url）
#[derive(Debug, Clone, Serialize, Deserialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    export_to = "WebauthnRegisterFinishDto.ts",
    rename_all = "camelCase"
)]
pub struct AttestationResponseDto {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub attestation_object: String,
}

/// Passkey 登录开始请求
#[derive(Debug, Clone, Serialize, Deserialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    export_to = "WebauthnLoginStartDto.ts",
    rename_all = "camelCase"
)]
pub struct WebauthnLoginStartDto {
    pub username: String,
}

/// Passkey 登录完成请求（对应 `navigator.credentials.get` 结果的 `toJSON()`，
/// 另需回传 `login/start` 时使用的 `username` 以完成归属校验）。
#[derive(Debug, Clone, Serialize, Deserialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    export_to = "WebauthnLoginFinishDto.ts",
    rename_all = "camelCase"
)]
pub struct WebauthnLoginFinishDto {
    /// 与 `login/start` 一致的登录名
    pub username: String,
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AssertionResponseDto,
}

/// 登录响应内的断言对象（Base64url）
#[derive(Debug, Clone, Serialize, Deserialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    export_to = "WebauthnLoginFinishDto.ts",
    rename_all = "camelCase"
)]
pub struct AssertionResponseDto {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(default)]
    pub user_handle: Option<String>,
}

/// 凭据列表项（自助管理出参）
#[derive(Debug, Clone, Serialize, Deserialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    export_to = "WebauthnCredentialVo.ts",
    rename_all = "camelCase"
)]
pub struct WebauthnCredentialVo {
    /// 凭据主键（删除路径参数 `credId`）
    pub cred_id: i64,
    pub name: String,
    pub sign_count: i64,
    #[ts(as = "Option<String>")]
    pub last_used_at: Option<String>,
    #[ts(as = "Option<String>")]
    pub create_time: Option<String>,
}

impl From<CredentialModel> for WebauthnCredentialVo {
    fn from(m: CredentialModel) -> Self {
        Self {
            cred_id: m.cred_id,
            name: m.name,
            sign_count: m.sign_count,
            last_used_at: m.last_used_at.map(fmt_dt),
            create_time: m.create_time.map(fmt_dt),
        }
    }
}

impl WebauthnRegisterFinishDto {
    fn into_lib(self) -> RegistrationResponse {
        RegistrationResponse {
            id: self.id,
            raw_id: self.raw_id,
            type_: self.type_,
            response: passkey_server::types::AttestationResponse {
                client_data_json: self.response.client_data_json,
                attestation_object: self.response.attestation_object,
            },
            client_extension_results: None,
            name: self.name,
        }
    }
}

impl WebauthnLoginFinishDto {
    fn into_lib(self) -> LoginResponse {
        LoginResponse {
            id: self.id,
            raw_id: self.raw_id,
            type_: self.type_,
            response: passkey_server::types::AssertionResponse {
                client_data_json: self.response.client_data_json,
                authenticator_data: self.response.authenticator_data,
                signature: self.response.signature,
                user_handle: self.response.user_handle,
            },
            client_extension_results: None,
        }
    }
}

// ==================== Service ====================

/// WebAuthn / Passkey Service（同时是 [`PasskeyStore`] 的持久化实现）。
#[derive(Clone)]
pub struct WebauthnService {
    store: Arc<dyn crate::shared_store::SharedStore>,
    user_repo: SysUserRepository,
    cred_repo: SysUserCredentialRepository,
    tenant_service: SysTenantService,
    /// 平台层能力集（按 `config.features` 净化解析；支持每实例/集成测试独立配置）
    features: FeatureSet,
    /// 解析后的有效 WebAuthn 信任锚；`None` = 未配置且无法推导（请求期 503）
    resolved: Option<ResolvedWebauthn>,
}

impl WebauthnService {
    pub fn new(
        db: DatabaseConnection,
        store: Arc<dyn crate::shared_store::SharedStore>,
        tenant_service: SysTenantService,
        config: Arc<Settings>,
    ) -> Self {
        let features = FeatureSet::sanitized(config.features.0.clone());
        let resolved = config.webauthn.resolved(&config.server);
        Self {
            user_repo: SysUserRepository::new(db.clone()),
            cred_repo: SysUserCredentialRepository::new(db),
            store,
            tenant_service,
            features,
            resolved,
        }
    }

    /// 守卫①：能力位非 `on` ⇒ 404（端点表现为"不存在"，与关闭态/无此功能等价）。
    ///
    /// `pub`：HTTP 层的 [`WebauthnEnabled`](crate::handler::webauthn_handler::WebauthnEnabled)
    /// 提取器需在请求体解析前调用它（保证关闭态统一 404）。
    pub fn ensure_enabled(&self) -> Result<(), ServiceError> {
        if mode_reaches(&self.features, FEATURE_WEBAUTHN, "on") {
            Ok(())
        } else {
            Err(ServiceError::not_found(&crate::tr!(
                "error.webauthn.disabled"
            )))
        }
    }

    /// 守卫②：RP 信任锚就绪（`rp_id` / `origin` 未配置且无法推导 ⇒ 503）。
    fn ensure_ready(&self) -> Result<&ResolvedWebauthn, ServiceError> {
        self.resolved
            .as_ref()
            .ok_or_else(|| ServiceError::new(503, crate::tr!("error.webauthn.config_missing")))
    }

    fn passkey_config(&self, r: &ResolvedWebauthn) -> PasskeyConfig {
        PasskeyConfig {
            rp_id: r.rp_id.clone(),
            rp_name: r.rp_name.clone(),
            origin: r.origin.clone(),
            state_ttl: i64::try_from(r.state_ttl_secs).unwrap_or(300),
        }
    }

    /// 守卫③（自助面）：加载本人用户，不存在 ⇒ 404、已停用 ⇒ 403。
    async fn load_active_user(&self, user_id: i64) -> Result<SysUserModel, ServiceError> {
        let user = self
            .user_repo
            .find_active_by_user_id(user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if user.status.as_deref() == Some("1") {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.webauthn.user_unavailable"
            )));
        }
        Ok(user)
    }

    /// 守卫③（登录面）：按用户名加载可用用户；任一不满足统一返回与密码登录失败同形的 401。
    async fn load_login_user(&self, username: &str) -> Result<SysUserModel, ServiceError> {
        let user = self
            .user_repo
            .find_active_by_user_name(username)
            .await?
            .ok_or_else(login_failed)?;
        if user.status.as_deref() == Some("1") {
            return Err(login_failed());
        }
        // 多租户闸门：与密码登录同口径（停用/超期/已删除 ⇒ 拒绝）
        if user.tenant_id != 0 {
            match self
                .tenant_service
                .resolve_login_state(user.tenant_id)
                .await
            {
                Ok(TenantLoginState::Active) | Ok(TenantLoginState::Grace) => {}
                Err(_) => return Err(login_failed()),
            }
        }
        Ok(user)
    }

    // ---------- 自助：注册 / 管理 ----------

    /// 开始注册：返回发送给 `navigator.credentials.create` 的 options（JSON）。
    pub async fn register_start(&self, user_id: i64) -> Result<serde_json::Value, ServiceError> {
        self.ensure_enabled()?;
        let resolved = self.ensure_ready()?.clone();
        let user = self.load_active_user(user_id).await?;
        let config = self.passkey_config(&resolved);
        let display_name = if user.nick_name.trim().is_empty() {
            user.user_name.clone()
        } else {
            user.nick_name.clone()
        };
        let options: PublicKeyCredentialCreationOptions = start_registration(
            self,
            &user.user_id.to_string(),
            &user.user_name,
            &display_name,
            &config,
            now_ms(),
        )
        .await
        .map_err(map_passkey_error)?;
        serde_json::to_value(options).map_err(Into::into)
    }

    /// 完成注册：校验证明对象后落库（同凭据/同名重复注册 ⇒ 400）。
    pub async fn register_finish(
        &self,
        user_id: i64,
        dto: WebauthnRegisterFinishDto,
    ) -> Result<(), ServiceError> {
        self.ensure_enabled()?;
        let resolved = self.ensure_ready()?.clone();
        let user = self.load_active_user(user_id).await?;
        let config = self.passkey_config(&resolved);
        finish_registration(
            self,
            &user.user_id.to_string(),
            &config,
            dto.into_lib(),
            now_ms(),
        )
        .await
        .map_err(map_passkey_error)?;
        Ok(())
    }

    /// 列出本人全部凭据（并列 `tenant_id` 收窄，纵深防御；见仓储层注释）。
    pub async fn list_credentials(
        &self,
        user_id: i64,
        tenant_id: i64,
    ) -> Result<Vec<WebauthnCredentialVo>, ServiceError> {
        self.ensure_enabled()?;
        let rows = self.cred_repo.list_by_user(user_id, tenant_id).await?;
        Ok(rows.into_iter().map(WebauthnCredentialVo::from).collect())
    }

    /// 删除本人凭据（仅限本人：0 行受影响 ⇒ 404，等价"不存在"）。
    pub async fn delete_credential(&self, user_id: i64, cred_id: i64) -> Result<(), ServiceError> {
        self.ensure_enabled()?;
        let affected = self.cred_repo.delete_owned(cred_id, user_id).await?;
        if affected == 0 {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.webauthn.credential_not_found"
            )));
        }
        Ok(())
    }

    // ---------- 公开：登录 ----------

    /// 开始登录：返回发送给 `navigator.credentials.get` 的 options（JSON），
    /// `allowCredentials` 限定为**该用户已绑定的凭据**。
    ///
    /// 反枚举：用户不存在 / 停用 / 租户停用 / 无凭据 ⇒ 统一 401（与密码登录失败同形）。
    pub async fn login_start(&self, username: &str) -> Result<serde_json::Value, ServiceError> {
        self.ensure_enabled()?;
        let resolved = self.ensure_ready()?.clone();
        let config = self.passkey_config(&resolved);
        let user = self.load_login_user(username).await?;
        let credentials = self
            .cred_repo
            .list_by_user(user.user_id, user.tenant_id)
            .await?;
        if credentials.is_empty() {
            return Err(login_failed());
        }
        let mut options: PublicKeyCredentialRequestOptions = start_login(self, &config, now_ms())
            .await
            .map_err(map_login_finish_error)?;
        options.allow_credentials = Some(
            credentials
                .into_iter()
                .map(|c| CredentialDescriptor {
                    type_: "public-key".into(),
                    id: c.credential_id,
                    transports: None,
                })
                .collect(),
        );
        serde_json::to_value(options).map_err(Into::into)
    }

    /// 完成登录：校验断言并返回**已认证用户**（令牌签发由既有登录完成链路承担）。
    pub async fn login_finish(
        &self,
        username: &str,
        dto: WebauthnLoginFinishDto,
    ) -> Result<SysUserModel, ServiceError> {
        self.ensure_enabled()?;
        let resolved = self.ensure_ready()?.clone();
        let config = self.passkey_config(&resolved);
        let user = self.load_login_user(username).await?;
        let user_id = finish_login(self, &config, dto.into_lib(), now_ms())
            .await
            .map_err(map_login_finish_error)?;
        // 防错配：断言所用的凭据必须属于本次请求的用户（否则拒绝，绝不放行为他人身份）
        if user_id != user.user_id.to_string() {
            return Err(login_failed());
        }
        Ok(user)
    }
}

// ==================== PasskeyStore 实现（SeaORM 落库 + 共享态存储临时态） ====================

#[async_trait]
impl PasskeyStore for WebauthnService {
    async fn create_passkey(
        &self,
        user_id: String,
        cred_id: &str,
        public_key: &str,
        name: &str,
        counter: i64,
        created_at: i64,
    ) -> PasskeyResult<()> {
        let uid: i64 = user_id
            .parse()
            .map_err(|_| PasskeyError::DatabaseError("invalid user id".into()))?;

        // 先解析用户（重复注册的 `tenant_id` 收窄与落库归属都需要它）
        let user = self
            .user_repo
            .base()
            .find_by_id(uid)
            .await
            .map_err(db_err)?
            .ok_or_else(|| PasskeyError::DatabaseError("user not found".into()))?;

        // 重复注册拒绝（凭据唯一索引为最终防线；此处先给出明确业务原因）
        if self
            .cred_repo
            .find_by_credential_id(cred_id)
            .await
            .map_err(db_err)?
            .is_some()
        {
            return Err(PasskeyError::DatabaseError(DUP_CREDENTIAL_MARKER.into()));
        }
        if self
            .cred_repo
            .exists_name(uid, user.tenant_id, name)
            .await
            .map_err(db_err)?
        {
            return Err(PasskeyError::DatabaseError(DUP_NAME_MARKER.into()));
        }

        let am = CredentialActiveModel {
            cred_id: sea_orm::NotSet,
            user_id: Set(uid),
            tenant_id: Set(user.tenant_id),
            credential_id: Set(cred_id.to_string()),
            public_key: Set(public_key.to_string()),
            name: Set(name.to_string()),
            sign_count: Set(counter),
            last_used_at: Set(None),
            create_time: Set(Some(ms_to_naive(created_at))),
            del_flag: Set(Some("0".to_string())),
        };
        self.cred_repo.insert(am).await.map_err(db_err)?;
        Ok(())
    }

    async fn get_passkey(&self, cred_id: &str) -> PasskeyResult<Option<StoredPasskey>> {
        let found = self
            .cred_repo
            .find_by_credential_id(cred_id)
            .await
            .map_err(db_err)?;
        Ok(found.map(|m| StoredPasskey {
            user_id: m.user_id.to_string(),
            cred_id: m.credential_id.clone(),
            public_key: m.public_key.clone(),
            name: m.name.clone(),
            created_at: naive_to_ms(m.create_time).unwrap_or(0),
            last_used_at: naive_to_ms(m.last_used_at)
                .or_else(|| naive_to_ms(m.create_time))
                .unwrap_or(0),
            counter: m.sign_count,
        }))
    }

    async fn list_passkeys(&self, user_id: String) -> PasskeyResult<Vec<StoredPasskey>> {
        let uid: i64 = user_id
            .parse()
            .map_err(|_| PasskeyError::DatabaseError("invalid user id".into()))?;
        // 解析归属用户的租户，用于 `tenant_id` 收窄（纵深防御）
        let user = self
            .user_repo
            .base()
            .find_by_id(uid)
            .await
            .map_err(db_err)?
            .ok_or_else(|| PasskeyError::DatabaseError("user not found".into()))?;
        let rows = self
            .cred_repo
            .list_by_user(uid, user.tenant_id)
            .await
            .map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|m| StoredPasskey {
                user_id: m.user_id.to_string(),
                cred_id: m.credential_id.clone(),
                public_key: m.public_key.clone(),
                name: m.name.clone(),
                created_at: naive_to_ms(m.create_time).unwrap_or(0),
                last_used_at: naive_to_ms(m.last_used_at)
                    .or_else(|| naive_to_ms(m.create_time))
                    .unwrap_or(0),
                counter: m.sign_count,
            })
            .collect())
    }

    async fn delete_passkey(&self, user_id: String, cred_id: &str) -> PasskeyResult<()> {
        let uid: i64 = user_id
            .parse()
            .map_err(|_| PasskeyError::DatabaseError("invalid user id".into()))?;
        let affected = self
            .cred_repo
            .delete_by_credential_id(uid, cred_id)
            .await
            .map_err(db_err)?;
        if affected == 0 {
            return Err(PasskeyError::PasskeyNotFound);
        }
        Ok(())
    }

    async fn update_passkey_counter(
        &self,
        cred_id: &str,
        new_counter: i64,
        last_used_at: i64,
    ) -> PasskeyResult<()> {
        self.cred_repo
            .update_counter(cred_id, new_counter, ms_to_naive(last_used_at))
            .await
            .map_err(db_err)
    }

    async fn update_passkey_name(&self, cred_id: &str, new_name: &str) -> PasskeyResult<()> {
        self.cred_repo
            .update_name(cred_id, new_name)
            .await
            .map_err(db_err)
    }

    async fn save_state(&self, id: &str, state_json: &str, expires_at: i64) -> PasskeyResult<()> {
        let now = now_ms();
        let ttl_ms = expires_at - now;
        if ttl_ms <= 0 {
            // 已过期：无需落库（get_state 将返回 None ⇒ 会话过期）
            return Ok(());
        }
        let ttl_secs = ((ttl_ms + 999) / 1000).max(1) as u64;
        let state = PasskeyState {
            id: id.to_string(),
            state_json: state_json.to_string(),
            expires_at,
        };
        let payload = serde_json::to_string(&state)
            .map_err(|e| PasskeyError::InternalError(format!("state serialize failed: {e}")))?;
        let key = format!("{STATE_KEY_PREFIX}{id}");
        self.store
            .set_ex(&key, &payload, ttl_secs)
            .await
            .map_err(|e| PasskeyError::DatabaseError(format!("shared store setex failed: {e}")))
    }

    async fn get_state(&self, id: &str) -> PasskeyResult<Option<PasskeyState>> {
        let key = format!("{STATE_KEY_PREFIX}{id}");
        let raw =
            self.store.get(&key).await.map_err(|e| {
                PasskeyError::DatabaseError(format!("shared store get failed: {e}"))
            })?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let state: PasskeyState = serde_json::from_str(&raw)
            .map_err(|e| PasskeyError::InternalError(format!("state parse failed: {e}")))?;
        if state.expires_at <= now_ms() {
            // 过期 state 的删除是 best-effort（键本身还有 TTL 兜底），但失败必须留痕：
            // 静默 `.ok()` 会让"存储侧一直删不掉"永远不可见（b97）。
            if let Err(e) = self.delete_state(id).await {
                tracing::warn!(error = %e, "WebAuthn 过期 state 清理失败（键将按 TTL 自然过期）");
            }
            return Ok(None);
        }
        Ok(Some(state))
    }

    async fn delete_state(&self, id: &str) -> PasskeyResult<()> {
        let key = format!("{STATE_KEY_PREFIX}{id}");
        self.store
            .del(std::slice::from_ref(&key))
            .await
            // del 返回删除条数（u64），本方法只关心成功与否 → 丢弃返回值（原 DEL 语义：键可能已过期，不存在不算失败）
            .map(|_| ())
            .map_err(|e| PasskeyError::DatabaseError(format!("shared store del failed: {e}")))
    }
}

// ==================== 工具 ====================

/// 与密码登录失败**同形**的通用错误（防用户名枚举；码与文案完全一致）。
fn login_failed() -> ServiceError {
    ServiceError::unauthorized(&crate::tr!("error.auth.login_failed"))
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn ms_to_naive(ms: i64) -> NaiveDateTime {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|dt| dt.naive_utc())
        .unwrap_or_else(crate::common::datetime::now_naive)
}

fn naive_to_ms(dt: Option<NaiveDateTime>) -> Option<i64> {
    dt.map(|d| d.and_utc().timestamp_millis())
}

fn fmt_dt(dt: NaiveDateTime) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn db_err(e: sea_orm::DbErr) -> PasskeyError {
    PasskeyError::DatabaseError(e.to_string())
}

/// 注册 / 自助面错误映射：校验类 ⇒ 400；重复注册 ⇒ 400（区分原因）；内部 ⇒ 500；未找到 ⇒ 404。
fn map_passkey_error(e: PasskeyError) -> ServiceError {
    match &e {
        PasskeyError::DatabaseError(msg) if msg.contains(DUP_CREDENTIAL_MARKER) => {
            ServiceError::bad_request(&crate::tr!("error.webauthn.duplicate_credential"))
        }
        PasskeyError::DatabaseError(msg) if msg.contains(DUP_NAME_MARKER) => {
            ServiceError::bad_request(&crate::tr!("error.webauthn.duplicate_name"))
        }
        PasskeyError::RegistrationSessionExpired | PasskeyError::LoginSessionExpired => {
            ServiceError::bad_request(&crate::tr!("error.webauthn.session_expired"))
        }
        PasskeyError::PasskeyNotFound => {
            ServiceError::not_found(&crate::tr!("error.webauthn.credential_not_found"))
        }
        // 来源失配（WebAuthn 信任锚不一致）——**可运维诊断的关键分支**：
        // 浏览器 clientDataJSON.origin 与配置 origin 不符即到此（典型成因：E2E 由后端在
        // :8080 同源托管 SPA，而 [webauthn].origin 从 cors_origins 推导成了 Vite dev 源
        // :5173）。响应仍统一为 400「响应无效」（不向客户端泄露信任锚），但**服务端必须留痕**
        // 期望/实到来源 + 处置指引，否则运维只能看到无语境的 400（历史误判为"算法缺陷"即此因）。
        PasskeyError::OriginMismatch { expected, got } => {
            tracing::warn!(
                expected = %expected,
                got = %got,
                "WebAuthn 来源失配：配置 origin 与页面服务源不一致 —— 请核对 [webauthn].origin / \
                 环境变量 WEBAUTHN_ORIGIN 是否等于前端页面真实来源"
            );
            ServiceError::bad_request(&crate::tr!("error.webauthn.invalid_response"))
        }
        PasskeyError::DatabaseError(_) | PasskeyError::InternalError(_) => {
            tracing::error!(error = %e, "WebAuthn 内部错误");
            ServiceError::internal(&crate::tr!("error.webauthn.internal"))
        }
        // 其余校验类失败（挑战失配 / rp_id 哈希 / 签名 / 操作类型…）统一 400；
        // 留一条 DEBUG 级上下文便于本地排障（响应不泄露细节）。
        other => {
            tracing::debug!(error = %other, "WebAuthn 响应校验失败（返回统一 400）");
            ServiceError::bad_request(&crate::tr!("error.webauthn.invalid_response"))
        }
    }
}

/// 登录面错误映射：校验类 ⇒ 401（与密码登录失败同形，防枚举）；内部 ⇒ 500。
fn map_login_finish_error(e: PasskeyError) -> ServiceError {
    match e {
        PasskeyError::DatabaseError(msg) => {
            tracing::error!(error = %msg, "WebAuthn 登录内部错误（数据库）");
            ServiceError::internal(&crate::tr!("error.webauthn.internal"))
        }
        PasskeyError::InternalError(msg) => {
            tracing::error!(error = %msg, "WebAuthn 登录内部错误");
            ServiceError::internal(&crate::tr!("error.webauthn.internal"))
        }
        _ => login_failed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `map_passkey_error` 契约锁（可证伪）——重点是**来源失配**这一最易误判的分支。
    ///
    /// 背景：E2E 由后端在 :8080 同源托管 SPA，而 `[webauthn].origin` 若从 `cors_origins`
    /// 推导成了 Vite dev 源（:5173），浏览器 clientDataJSON.origin（:8080）与配置不符 ⇒
    /// 库返回 `OriginMismatch`。历史因该分支落入 `_` 兜底且**无日志**，被误判为
    /// "算法缺陷（缺 RS256）"。本测试钉死：来源失配 ⇒ 统一 400（不泄露信任锚），
    /// 且不会被误判为 500/401。
    #[test]
    fn origin_mismatch_maps_to_uniform_400() {
        let e = map_passkey_error(PasskeyError::OriginMismatch {
            expected: "http://localhost:5173".to_string(),
            got: "http://localhost:8080".to_string(),
        });
        assert_eq!(e.code, 400, "来源失配应返回统一 400（不泄露信任锚）");
    }

    /// 其余校验类失败（挑战失配 / rp_id 哈希 / 签名 / 操作类型）同样统一 400。
    #[test]
    fn other_validation_failures_map_to_400() {
        for e in [
            PasskeyError::InvalidChallenge,
            PasskeyError::RpIdHashMismatch,
            PasskeyError::InvalidOperationType,
            PasskeyError::InvalidSignature("bad".to_string()),
            PasskeyError::UserPresentFlagNotSet,
        ] {
            assert_eq!(map_passkey_error(e).code, 400);
        }
    }

    /// 会话过期 ⇒ 400；凭据不存在 ⇒ 404；内部错误 ⇒ 500（错误分级不回归）。
    #[test]
    fn error_grading_is_stable() {
        assert_eq!(
            map_passkey_error(PasskeyError::RegistrationSessionExpired).code,
            400
        );
        assert_eq!(
            map_passkey_error(PasskeyError::LoginSessionExpired).code,
            400
        );
        assert_eq!(map_passkey_error(PasskeyError::PasskeyNotFound).code, 404);
        assert_eq!(
            map_passkey_error(PasskeyError::InternalError("x".to_string())).code,
            500
        );
    }
}
