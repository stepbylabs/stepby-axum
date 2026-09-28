// axum-backend/src/service/sys_tenant_domain_service.rs
//! 租户域名绑定服务（多租户 Phase 3 域名链路，文档 §27.7 / §29.6）
//!
//! 链路定位：TLS 与 host 路由交 Nginx/网关；网关解析域名后注入内部头
//! `X-Tenant-Code`，后端仅信任可信反代来源（见 `middleware::tenant_host`）。
//! 本服务负责域名绑定台账的读写、DNS TXT 校验、host→tid 解析回源与缓存失效。
//!
//! 关键语义：
//! - `domain` **全局唯一**（唯一索引不分软删，历史占用同样拦截）→ 占用探测用
//!   `find_by_domain_any`（含软删行）；
//! - 域名类型 `domain_type`：`'0'` 子域名（平台分配，免 DNS 验证）/ `'1'` 自定义域名
//!   （需 DNS TXT 验证 `_stepby-verify.{domain}` = verify_token）；
//! - **操作者范围由能力位 `tenant.domain_self_service` 决定**（见 [`DomainScope`]）：
//!   - 关闭态（默认 = 现状）：域名管理整体平台专属，租户操作者一律 **403**；
//!   - 开启态（平台 `[features]` ∩ 租户套餐两层均非 `off`）：**平台操作者**可管理全部租户域名；
//!     **租户操作者**仅可管理本租户域名，且只能**新增自定义域名**（子域名由平台分配，
//!     否则租户可无验证占用任意主机名 ⇒ host→tid 劫持）；
//! - 缓存：`tenant:host:{domain}`（域名→tid，TTL 300s），miss 回源后回填，
//!   未命中不缓存（负缓存缺失）。

use std::collections::HashMap;
use std::time::Duration;

use chrono::NaiveDateTime;
use redis::aio::ConnectionManager;
use sea_orm::sea_query::Expr;
use sea_orm::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime::{self, now_naive};
use crate::common::error::ServiceError;
use crate::common::tenant::tenant_allowed;
use crate::entity::sys_tenant_domain::{
    ActiveModel as DomainActiveModel, Column as DomainColumn, Entity as SysTenantDomain,
    Model as DomainModel,
};
use crate::repository::sys_tenant::SysTenantRepository;
use crate::repository::sys_tenant_domain::SysTenantDomainRepository;
use crate::utils::dns_txt::{self, DnsError};

/// 域名→tid 缓存 TTL（秒）
const DOMAIN_CACHE_TTL_SECS: i64 = 300;
/// DNS TXT 查询超时（秒）
const DNS_TXT_TIMEOUT_SECS: u64 = 5;
/// 子域名类型标记
const DOMAIN_TYPE_SUBDOMAIN: &str = "0";
/// 自定义域名类型标记
const DOMAIN_TYPE_CUSTOM: &str = "1";
/// 租户域名自助能力位键（注册表见 `common::features::KNOWN_FEATURES`）
pub const FEATURE_DOMAIN_SELF_SERVICE: &str = "tenant.domain_self_service";

/// `tenant:host:{domain}` 键名（域名 → tid）
fn domain_host_key(domain: &str) -> String {
    format!("tenant:host:{}", domain)
}

/// 域名管理的**操作者数据范围**（由能力位解析得出，是所有接口的唯一准入判据）。
///
/// 「关闭态即现状」：能力位 `off` 时租户操作者拿不到 [`DomainScope::Tenant`]，
/// 一律 403；平台操作者不受能力位影响（恒 [`DomainScope::Platform`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainScope {
    /// 平台操作者：可见/可写全部租户的域名
    Platform,
    /// 租户操作者（能力位开启）：**仅**本租户域名
    Tenant(i64),
}

impl DomainScope {
    /// 该范围是否允许触达 `resource_tid` 归属的资源（复用 `common::tenant::tenant_allowed`）
    fn allows(self, resource_tid: i64) -> bool {
        match self {
            DomainScope::Platform => true,
            DomainScope::Tenant(tid) => tenant_allowed(tid, resource_tid),
        }
    }
}

/// 跨租户越权（域名归属与操作者租户不一致）——显式 403，**禁止静默降级**
fn cross_tenant_denied() -> ServiceError {
    ServiceError::forbidden(&crate::tr!("error.tenant.domain_cross_tenant"))
}

/// 由能力集解析操作者范围（纯函数，便于单测；唯一准入判据，调用点 [`SysTenantDomainService::resolve_scope`]）
///
/// - `operator_tid == 0` ⇒ 平台（不受能力位影响）；
/// - 否则需 `tenant.domain_self_service` 非 `off`，否则 403（关闭态即现状）。
fn scope_from_features(
    operator_tid: i64,
    features: &crate::common::features::FeatureSet,
) -> Result<DomainScope, ServiceError> {
    if operator_tid == 0 {
        return Ok(DomainScope::Platform);
    }
    if features.is_on(FEATURE_DOMAIN_SELF_SERVICE) {
        Ok(DomainScope::Tenant(operator_tid))
    } else {
        Err(ServiceError::forbidden(&crate::tr!(
            "error.tenant.domain_platform_only"
        )))
    }
}

/// 由范围推导「列表实际过滤值」（纯函数，便于单测；调用点 [`SysTenantDomainService::list`]）
///
/// 租户范围内**显式传入他租户 id 一律 403**——不静默降级为"忽略参数"，
/// 否则越权尝试会被伪装成一次正常空列表（违反"禁止静默降级"硬约束）。
fn effective_list_filter(
    scope: DomainScope,
    requested: Option<i64>,
) -> Result<Option<i64>, ServiceError> {
    match scope {
        DomainScope::Platform => Ok(requested),
        DomainScope::Tenant(tid) => {
            if let Some(r) = requested
                && r != tid
            {
                return Err(cross_tenant_denied());
            }
            Ok(Some(tid))
        }
    }
}

/// 租户范围内的**写入归属守卫**（纯函数，便于单测；调用点 [`SysTenantDomainService::add`]）
///
/// 两条约束缺一不可：
/// ① 归属租户必须等于自身（`dto.tenant_id` 来自请求体，不可信）；
/// ② 只能是自定义域名（子域名免 DNS 验证，放给租户等于允许其无验证占用任意主机名）。
fn ensure_tenant_write_allowed(
    scope: DomainScope,
    dto_tenant_id: i64,
    domain_type: &str,
) -> Result<(), ServiceError> {
    let DomainScope::Tenant(tid) = scope else {
        return Ok(());
    };
    if dto_tenant_id != tid {
        return Err(cross_tenant_denied());
    }
    if domain_type != DOMAIN_TYPE_CUSTOM {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.tenant.domain_subdomain_platform_only"
        )));
    }
    Ok(())
}

// ==================== DTO / Vo ====================

/// 租户域名视图
#[derive(Debug, Clone, Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename = "TenantDomainVo", rename_all = "camelCase")]
#[schema(as = TenantDomainVo)]
pub struct TenantDomainVo {
    pub domain_id: i64,
    pub tenant_id: i64,
    /// 归属租户名（缺失为空）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_name: Option<String>,
    pub domain: String,
    /// '0' 子域名 / '1' 自定义域名
    pub domain_type: String,
    /// '0' 主域名 / '1' 附加域名
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<String>,
    /// '0' 待验证 / '1' 已验证 / '2' 验证失败
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_status: Option<String>,
    /// DNS TXT 校验 token（归属租户与平台可见——`list` 已按 [`DomainScope`] 行级收窄，
    /// 租户只会拿到本租户行，且租户需据它配置 TXT 记录）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_token: Option<String>,
    /// 验证通过时间
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub verified_at: Option<NaiveDateTime>,
    /// '0' 启用 / '1' 停用
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_by: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub create_time: Option<NaiveDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_by: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub update_time: Option<NaiveDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remark: Option<String>,
}

/// DNS TXT 验证结果
#[derive(Debug, Clone, Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename = "TenantDomainVerifyVo", rename_all = "camelCase")]
#[schema(as = TenantDomainVerifyVo)]
pub struct TenantDomainVerifyVo {
    pub domain_id: i64,
    /// 归属租户 ID（审计 target_tenant_id 用）
    pub tenant_id: i64,
    pub domain: String,
    /// 是否验证通过
    pub verified: bool,
    /// 验证后状态：'1' 已验证 / '2' 验证失败
    pub verify_status: String,
    /// 需配置的 TXT 记录名
    pub txt_record: String,
    /// 需配置的 TXT 记录值（仅平台操作者可见）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txt_value: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    pub verified_at: Option<NaiveDateTime>,
}

/// 新增域名 DTO
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = TenantDomainAddDto)]
pub struct TenantDomainAddDto {
    /// 归属租户 ID
    pub tenant_id: i64,
    /// 绑定域名（小写、去端口）
    pub domain: String,
    /// '0' 子域名 / '1' 自定义域名
    pub domain_type: String,
    /// '0' 主域名 / '1' 附加域名（缺省：该租户首个域名自动为主域名）
    #[serde(default)]
    pub is_primary: Option<String>,
    #[serde(default)]
    pub remark: Option<String>,
}

/// 域名启停 DTO
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = TenantDomainStatusDto)]
pub struct TenantDomainStatusDto {
    pub domain_id: i64,
    /// '0' 启用 / '1' 停用
    pub status: String,
}

/// 按域名 ID 定位 DTO（设为主域名）
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = TenantDomainIdDto)]
pub struct TenantDomainIdDto {
    pub domain_id: i64,
}

// ==================== Service ====================

/// 租户域名服务
#[derive(Clone)]
pub struct SysTenantDomainService {
    db: DatabaseConnection,
    redis: ConnectionManager,
    domain_repo: SysTenantDomainRepository,
    tenant_repo: SysTenantRepository,
    /// 全局配置（`[acme]` 证书需求输出集成点；默认 `off` ⇒ 不发任何出站请求）
    config: std::sync::Arc<crate::config::Settings>,
}

impl SysTenantDomainService {
    pub fn new(
        db: DatabaseConnection,
        redis: ConnectionManager,
        config: std::sync::Arc<crate::config::Settings>,
    ) -> Self {
        Self {
            domain_repo: SysTenantDomainRepository::new(db.clone()),
            tenant_repo: SysTenantRepository::new(db.clone()),
            db,
            redis,
            config,
        }
    }

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// 推送「证书需求」事件（`[acme]` 集成点，默认 `off` = 不发）。
    ///
    /// 只在**状态迁移**处调用（验证通过 ⇒ `cert.issue`；已验证域名被删 ⇒ `cert.remove`），
    /// 因此天然幂等、无需缓存去重。推送失败只打 WARN，**绝不影响**域名业务本身。
    async fn emit_cert_event(&self, event: &'static str, model: &DomainModel) {
        // 快速路径：`off`（默认）时连租户查询都省掉
        if self.config.acme.effective_webhook().is_none() {
            return;
        }
        let tenant_code = self
            .tenant_repo
            .find_by_id_any(model.tenant_id)
            .await
            .ok()
            .flatten()
            .map(|t| t.tenant_code);
        crate::service::acme_service::spawn_emit(
            self.config.acme.clone(),
            event,
            model.domain.clone(),
            model.tenant_id,
            tenant_code,
            model.verify_status.clone().unwrap_or_default(),
        );
    }

    /// 解析操作者的数据范围（**域名管理的唯一准入判据**）。
    ///
    /// - `operator_tid == 0`：平台操作者恒放行（不受能力位影响）；
    /// - `operator_tid != 0`：需该租户**有效能力集**（平台 `[features]` 天花板 ∩ 套餐
    ///   `features`）中 `tenant.domain_self_service` 非 `off`；否则 403（= 关闭态即现状）。
    ///
    /// 平台层未开启时，租户侧无论套餐怎么写都不生效（见 `FeatureSet::narrowed_by`），
    /// 因此本函数不构成新的越权面。
    async fn resolve_scope(&self, operator_tid: i64) -> Result<DomainScope, ServiceError> {
        if operator_tid == 0 {
            return Ok(DomainScope::Platform);
        }
        let features =
            crate::service::sys_tenant_service::tenant_features_conn(self.db(), operator_tid)
                .await?;
        scope_from_features(operator_tid, &features)
    }

    // ---------- 查询 ----------

    /// 域名列表（范围见 [`DomainScope`]）：
    /// - 平台操作者（tid=0）：可按 `tenant_id` 过滤，不过滤则全量；
    /// - 租户操作者（tid≠0，能力位开启）：**仅本租户**；显式传入他租户 id 一律 **403**
    ///   （显式越权不静默降级为"忽略参数"）；
    /// - 能力位关闭：租户操作者 **403**（不降级为"只读本租户"，避免域名清单成为
    ///   无授权信息面）。
    pub async fn list(
        &self,
        tenant_id: Option<i64>,
        operator_tid: i64,
    ) -> Result<Vec<TenantDomainVo>, ServiceError> {
        let effective = effective_list_filter(self.resolve_scope(operator_tid).await?, tenant_id)?;
        let rows = self.domain_repo.list(effective).await?;
        let ids: Vec<i64> = {
            let mut v: Vec<i64> = rows.iter().map(|r| r.tenant_id).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let name_map: HashMap<i64, String> = self
            .tenant_repo
            .find_name_map(&ids)
            .await?
            .into_iter()
            .collect();
        Ok(rows.into_iter().map(|m| to_vo(&m, &name_map)).collect())
    }

    // ---------- 写操作 ----------

    /// 新增域名绑定（范围见 [`DomainScope`]）
    ///
    /// 租户操作者额外两条守卫（缺一不可）：
    /// ① 归属租户必须等于自身（`dto.tenant_id` 由前端传入，不可信）；
    /// ② 只能新增**自定义域名**（`domain_type = '1'`）——子域名是平台分配的免验证类型，
    ///    放给租户等于允许其无验证占用任意主机名（host→tid 劫持）。
    pub async fn add(
        &self,
        dto: TenantDomainAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<TenantDomainVo, ServiceError> {
        let scope = self.resolve_scope(operator_tid).await?;

        let domain_type = dto.domain_type.trim();
        if domain_type != DOMAIN_TYPE_SUBDOMAIN && domain_type != DOMAIN_TYPE_CUSTOM {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.domain_invalid"
            )));
        }
        ensure_tenant_write_allowed(scope, dto.tenant_id, domain_type)?;

        // 归属租户必须存在且未删除
        let tenant = self
            .tenant_repo
            .find_active_by_id(dto.tenant_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.not_found")))?;

        let domain = normalize_domain(&dto.domain);
        validate_domain(&domain)?;

        // 全局唯一（含软删行：唯一索引不分软删，历史占用同样拦截）
        if self
            .domain_repo
            .find_by_domain_any(&domain)
            .await?
            .is_some()
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.domain_conflict"
            )));
        }

        let existing_primary = self
            .domain_repo
            .find_primary_by_tenant(dto.tenant_id)
            .await?;
        let is_primary = match dto.is_primary.as_deref() {
            Some("0") => {
                if existing_primary.is_some() {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.tenant.domain_primary_forbidden"
                    )));
                }
                "0".to_string()
            }
            Some("1") => "1".to_string(),
            Some(_) => {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.tenant.domain_invalid"
                )));
            }
            None => {
                if existing_primary.is_none() {
                    "0".to_string()
                } else {
                    "1".to_string()
                }
            }
        };

        // 子域名由平台分配、免 DNS 验证；自定义域名需 TXT 验证
        let (verify_status, verify_token, verified_at) = if domain_type == DOMAIN_TYPE_SUBDOMAIN {
            ("1".to_string(), None, Some(now_naive()))
        } else {
            (
                "0".to_string(),
                Some(uuid::Uuid::new_v4().simple().to_string()),
                None,
            )
        };

        let now = now_naive();
        let am = DomainActiveModel {
            domain_id: NotSet,
            tenant_id: Set(dto.tenant_id),
            domain: Set(domain.clone()),
            domain_type: Set(domain_type.to_string()),
            is_primary: Set(Some(is_primary)),
            verify_status: Set(Some(verify_status)),
            verify_token: Set(verify_token),
            verified_at: Set(verified_at),
            status: Set(Some("0".to_string())),
            del_flag: Set(Some("0".to_string())),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(dto.remark.filter(|s| !s.trim().is_empty())),
        };
        let model = self.domain_repo.insert(am).await?;

        let mut name_map = HashMap::new();
        name_map.insert(tenant.tenant_id, tenant.tenant_name);
        tracing::info!(
            tenant_id = dto.tenant_id,
            domain = %domain,
            domain_type,
            "租户域名绑定已创建"
        );
        Ok(to_vo(&model, &name_map))
    }

    /// DNS TXT 验证自定义域名（子域名/已验证域名幂等返回成功）
    pub async fn verify(
        &self,
        domain_id: i64,
        operator: &str,
        operator_tid: i64,
    ) -> Result<TenantDomainVerifyVo, ServiceError> {
        let scope = self.resolve_scope(operator_tid).await?;

        let model = self
            .domain_repo
            .find_by_id(domain_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.domain_not_found")))?;
        if !scope.allows(model.tenant_id) {
            return Err(cross_tenant_denied());
        }

        let txt_record = format!("_stepby-verify.{}", model.domain);

        // 子域名由平台分配免验证；已验证域名幂等返回
        if model.domain_type == DOMAIN_TYPE_SUBDOMAIN || model.verify_status.as_deref() == Some("1")
        {
            return Ok(TenantDomainVerifyVo {
                domain_id,
                tenant_id: model.tenant_id,
                domain: model.domain.clone(),
                verified: true,
                verify_status: "1".to_string(),
                txt_record,
                txt_value: model.verify_token.clone(),
                verified_at: model.verified_at,
            });
        }

        let token = model.verify_token.clone().ok_or_else(|| {
            ServiceError::bad_request(&crate::tr!("error.tenant.domain_verify_failed"))
        })?;

        // 真实 DNS TXT 查询（超时 / IO / 协议错误 → 按验证失败返回 400）
        let txt_values =
            dns_txt::lookup_txt(&txt_record, Duration::from_secs(DNS_TXT_TIMEOUT_SECS))
                .await
                .map_err(|e| {
                    if !matches!(e, DnsError::Rcode(3)) {
                        tracing::warn!(
                            domain = %model.domain,
                            error = %e,
                            "DNS TXT 查询失败，域名验证未通过"
                        );
                    }
                    ServiceError::bad_request(&crate::tr!("error.tenant.domain_verify_failed"))
                })?;

        let matched = txt_values.iter().any(|v| v.trim() == token);
        let now = now_naive();
        let new_status = if matched { "1" } else { "2" };
        let mut am: DomainActiveModel = model.clone().into();
        am.verify_status = Set(Some(new_status.to_string()));
        am.verified_at = Set(if matched { Some(now) } else { None });
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        self.domain_repo.update(am).await?;

        // 验证通过后该域名才可被解析 → 失效 host 缓存
        self.invalidate_domain_cache(&model.domain).await;

        if !matched {
            tracing::info!(
                domain = %model.domain,
                "DNS TXT 记录未匹配，域名验证失败（记录已置为验证失败）"
            );
        } else {
            // 状态迁移 `0/2 → '1'`（上方已早退拦截"本就已验证"的情形）⇒ 需要签发证书
            let mut verified = model.clone();
            verified.verify_status = Some(new_status.to_string());
            self.emit_cert_event(crate::service::acme_service::EVENT_CERT_ISSUE, &verified)
                .await;
        }
        Ok(TenantDomainVerifyVo {
            domain_id,
            tenant_id: model.tenant_id,
            domain: model.domain.clone(),
            verified: matched,
            verify_status: new_status.to_string(),
            txt_record,
            txt_value: Some(token),
            verified_at: if matched { Some(now) } else { None },
        })
    }

    /// 设为主域名（同租户原主域名自动降级为附加域名）
    pub async fn set_primary(
        &self,
        dto: TenantDomainIdDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<TenantDomainVo, ServiceError> {
        let scope = self.resolve_scope(operator_tid).await?;

        let model = self
            .domain_repo
            .find_by_id(dto.domain_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.domain_not_found")))?;
        if !scope.allows(model.tenant_id) {
            return Err(cross_tenant_denied());
        }

        // 只有已验证的域名才可作主域名（主域名承担租户默认入口）
        if model.verify_status.as_deref() != Some("1") {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.domain_not_verified"
            )));
        }

        let now = now_naive();
        let txn = self.db().begin().await?;

        // 同租户原主域名降级
        SysTenantDomain::update_many()
            .col_expr(DomainColumn::IsPrimary, Expr::value("1"))
            .col_expr(DomainColumn::UpdateBy, Expr::value(operator))
            .col_expr(DomainColumn::UpdateTime, Expr::value(now))
            .filter(DomainColumn::TenantId.eq(model.tenant_id))
            .filter(DomainColumn::IsPrimary.eq("0"))
            .filter(DomainColumn::DelFlag.eq("0"))
            .exec(&txn)
            .await?;

        // 目标域名设为主
        SysTenantDomain::update_many()
            .col_expr(DomainColumn::IsPrimary, Expr::value("0"))
            .col_expr(DomainColumn::UpdateBy, Expr::value(operator))
            .col_expr(DomainColumn::UpdateTime, Expr::value(now))
            .filter(DomainColumn::DomainId.eq(model.domain_id))
            .filter(DomainColumn::DelFlag.eq("0"))
            .exec(&txn)
            .await?;

        txn.commit().await?;

        let updated = self
            .domain_repo
            .find_by_id(model.domain_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.domain_not_found")))?;
        let name_map = self
            .tenant_repo
            .find_name_map(&[updated.tenant_id])
            .await?
            .into_iter()
            .collect();
        Ok(to_vo(&updated, &name_map))
    }

    /// 域名启停（停用后该域名不再参与 host→tid 解析）；返回目标租户 ID（审计）
    pub async fn change_status(
        &self,
        dto: TenantDomainStatusDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<i64, ServiceError> {
        let scope = self.resolve_scope(operator_tid).await?;

        let status = dto.status.trim();
        if status != "0" && status != "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.tenant.status_invalid",
                value = status
            )));
        }

        let model = self
            .domain_repo
            .find_by_id(dto.domain_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.domain_not_found")))?;
        if !scope.allows(model.tenant_id) {
            return Err(cross_tenant_denied());
        }

        let now = now_naive();
        let mut am: DomainActiveModel = model.clone().into();
        am.status = Set(Some(status.to_string()));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        self.domain_repo.update(am).await?;

        self.invalidate_domain_cache(&model.domain).await;
        Ok(model.tenant_id)
    }

    /// 删除域名绑定（软删；host 缓存失效）；返回目标租户 ID（审计）
    pub async fn remove(
        &self,
        domain_id: i64,
        operator: &str,
        operator_tid: i64,
    ) -> Result<i64, ServiceError> {
        let scope = self.resolve_scope(operator_tid).await?;

        let model = self
            .domain_repo
            .find_by_id(domain_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.tenant.domain_not_found")))?;
        if !scope.allows(model.tenant_id) {
            return Err(cross_tenant_denied());
        }

        self.domain_repo.soft_delete(domain_id, operator).await?;
        self.invalidate_domain_cache(&model.domain).await;
        // 状态迁移 `'1' → 已删`：该域名不再需要证书（接收端可据此吊销/清理）
        if model.verify_status.as_deref() == Some("1") {
            self.emit_cert_event(crate::service::acme_service::EVENT_CERT_REMOVE, &model)
                .await;
        }
        Ok(model.tenant_id)
    }

    // ---------- host→tid 解析（中间件复用） ----------

    /// 域名 → tid（cache-aside：`tenant:host:{domain}` TTL 300s，miss 回源后回填）
    ///
    /// 仅返回「未删除 + 启用 + 已验证」的绑定（见 `find_active_by_domain`）。
    /// Redis 异常降级为回源 DB（不阻断请求）。
    pub async fn resolve_tenant_id_by_domain(
        &self,
        domain: &str,
    ) -> Result<Option<i64>, ServiceError> {
        let domain = normalize_domain(domain);
        if domain.is_empty() {
            return Ok(None);
        }
        let key = domain_host_key(&domain);
        if let Some(raw) = self.redis_get(&key).await
            && let Ok(tid) = raw.parse::<i64>()
        {
            return Ok(Some(tid));
        }
        match self.domain_repo.find_active_by_domain(&domain).await? {
            Some(m) => {
                self.redis_setex(&key, DOMAIN_CACHE_TTL_SECS, &m.tenant_id.to_string())
                    .await;
                Ok(Some(m.tenant_id))
            }
            None => Ok(None),
        }
    }

    /// 失效域名 host 缓存（域名写路径调用）
    pub async fn invalidate_domain_cache(&self, domain: &str) {
        let domain = normalize_domain(domain);
        if domain.is_empty() {
            return;
        }
        self.redis_del(&domain_host_key(&domain)).await;
    }

    // ---------- Redis 工具（best-effort，异常降级） ----------

    async fn redis_get(&self, key: &str) -> Option<String> {
        let mut redis = self.redis.clone();
        match tokio::time::timeout(
            Duration::from_secs(crate::db::redis::REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("GET")
                .arg(key)
                .query_async::<Option<String>>(&mut redis),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::warn!(key, error = %e, "域名缓存读取失败（降级回源 DB）");
                None
            }
            Err(_) => {
                tracing::warn!(key, "域名缓存读取超时（降级回源 DB）");
                None
            }
        }
    }

    async fn redis_setex(&self, key: &str, ttl: i64, value: &str) {
        let mut redis = self.redis.clone();
        let _ = tokio::time::timeout(
            Duration::from_secs(crate::db::redis::REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("SETEX")
                .arg(key)
                .arg(ttl)
                .arg(value)
                .query_async::<()>(&mut redis),
        )
        .await;
    }

    async fn redis_del(&self, key: &str) {
        let mut redis = self.redis.clone();
        let _ = tokio::time::timeout(
            Duration::from_secs(crate::db::redis::REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("DEL").arg(key).query_async::<()>(&mut redis),
        )
        .await;
    }
}

/// Model → Vo
///
/// 调用点均已按 [`DomainScope`] 完成行级收窄（平台 = 全部 / 租户 = 仅本租户），
/// 故 `verify_token` 直接输出：租户拿到的是**本租户**域名的 token，正是其配置
/// `_stepby-verify.{domain}` TXT 记录所必需的信息。
fn to_vo(model: &DomainModel, name_map: &HashMap<i64, String>) -> TenantDomainVo {
    TenantDomainVo {
        domain_id: model.domain_id,
        tenant_id: model.tenant_id,
        tenant_name: name_map.get(&model.tenant_id).cloned(),
        domain: model.domain.clone(),
        domain_type: model.domain_type.clone(),
        is_primary: model.is_primary.clone(),
        verify_status: model.verify_status.clone(),
        verify_token: model.verify_token.clone(),
        verified_at: model.verified_at,
        status: model.status.clone(),
        create_by: model.create_by.clone(),
        create_time: model.create_time,
        update_by: model.update_by.clone(),
        update_time: model.update_time,
        remark: model.remark.clone(),
    }
}

/// 域名规范化：小写、去端口、去结尾点
pub fn normalize_domain(raw: &str) -> String {
    let mut s = raw.trim().to_ascii_lowercase();
    // IPv6 字面量 [::1]:8080 → ::1
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            s = s[1..end].to_string();
        }
    } else if let Some((host, port)) = s.rsplit_once(':') {
        // 仅当冒号后为纯数字端口时剥离（域名不含冒号）
        if !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            s = host.to_string();
        }
    }
    while s.ends_with('.') {
        s.pop();
    }
    s
}

/// 域名格式校验：长度 ≤ 253，≥2 个标签，每标签 1-63 位 `a-z0-9-` 且不以 `-` 开头/结尾
fn validate_domain(domain: &str) -> Result<(), ServiceError> {
    let invalid = || ServiceError::bad_request(&crate::tr!("error.tenant.domain_invalid"));
    if domain.is_empty() || domain.len() > 253 {
        return Err(invalid());
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(invalid());
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid());
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::features::FeatureSet;

    /// 能力位关闭态（默认）⇒ 租户操作者拿不到任何范围（403）；平台操作者不受影响
    #[test]
    fn test_scope_from_features_closed_is_tenant_denied() {
        let off = FeatureSet::default();
        assert_eq!(
            scope_from_features(0, &off).expect("平台操作者恒放行"),
            DomainScope::Platform,
            "平台操作者恒放行，不受能力位影响"
        );
        let err = scope_from_features(9, &off).expect_err("关闭态下租户必须 403");
        assert_eq!(err.code, 403, "关闭态即现状：租户一律 403");

        // 显式 off 与"未配置"同效（都不得放行）
        let explicit_off = FeatureSet::from_json(Some(r#"{"tenant.domain_self_service":"off"}"#));
        assert!(scope_from_features(9, &explicit_off).is_err());

        // 开启后租户获得**自己**的范围
        let on = FeatureSet::from_json(Some(r#"{"tenant.domain_self_service":"full"}"#));
        assert_eq!(
            scope_from_features(9, &on).expect("开启态下租户应获得本租户范围"),
            DomainScope::Tenant(9)
        );
        // 其它能力位不得顺带放行（白名单逐条匹配）
        let other = FeatureSet::from_json(Some(r#"{"nav.l3":"full"}"#));
        assert!(scope_from_features(9, &other).is_err());
    }

    /// 范围 → 行级归属判定（跨租户一律拒绝）
    #[test]
    fn test_domain_scope_allows() {
        assert!(DomainScope::Platform.allows(0));
        assert!(DomainScope::Platform.allows(7));
        assert!(DomainScope::Tenant(5).allows(5));
        assert!(!DomainScope::Tenant(5).allows(7), "跨租户资源必须拒绝");
        assert!(
            !DomainScope::Tenant(5).allows(0),
            "平台租户资源亦不得被租户触达"
        );
    }

    /// 列表过滤值：平台可自由过滤；租户被强制收窄，显式越权 403（**不静默降级**）
    #[test]
    fn test_effective_list_filter() {
        assert_eq!(
            effective_list_filter(DomainScope::Platform, None).expect("平台不过滤应放行"),
            None
        );
        assert_eq!(
            effective_list_filter(DomainScope::Platform, Some(7)).expect("平台按 tid 过滤应放行"),
            Some(7)
        );
        assert_eq!(
            effective_list_filter(DomainScope::Tenant(5), None).expect("租户应被收窄"),
            Some(5),
            "租户不传过滤也必须收窄到本租户"
        );
        assert_eq!(
            effective_list_filter(DomainScope::Tenant(5), Some(5)).expect("租户传自身 tid 应放行"),
            Some(5)
        );
        let err = effective_list_filter(DomainScope::Tenant(5), Some(7))
            .expect_err("显式传他租户 id 必须 403，而不是忽略参数返回空列表");
        assert_eq!(err.code, 403);
    }

    /// 写入守卫：租户只能写本租户 + 只能自定义域名（子域名由平台分配）
    #[test]
    fn test_ensure_tenant_write_allowed() {
        // 平台范围不受限
        assert!(
            ensure_tenant_write_allowed(DomainScope::Platform, 7, DOMAIN_TYPE_SUBDOMAIN).is_ok()
        );
        // 租户：本租户 + 自定义域名 ⇒ 放行
        assert!(ensure_tenant_write_allowed(DomainScope::Tenant(5), 5, DOMAIN_TYPE_CUSTOM).is_ok());
        // 租户：写他租户 ⇒ 403
        let err = ensure_tenant_write_allowed(DomainScope::Tenant(5), 7, DOMAIN_TYPE_CUSTOM)
            .expect_err("租户不得给其他租户绑定域名");
        assert_eq!(err.code, 403);
        // 租户：子域名（免验证类型）⇒ 400（否则可无验证占用任意主机名）
        let err = ensure_tenant_write_allowed(DomainScope::Tenant(5), 5, DOMAIN_TYPE_SUBDOMAIN)
            .expect_err("租户自助不得新增子域名");
        assert_eq!(err.code, 400);
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("  ACME.Stepby.COM  "), "acme.stepby.com");
        assert_eq!(
            normalize_domain("acme.example.com:8443"),
            "acme.example.com"
        );
        assert_eq!(normalize_domain("acme.example.com."), "acme.example.com");
        assert_eq!(normalize_domain("[::1]:8080"), "::1");
    }

    #[test]
    fn test_validate_domain() {
        assert!(validate_domain("acme.stepby.com").is_ok());
        assert!(validate_domain("a-b.example.io").is_ok());
        // 单标签拒绝
        assert!(validate_domain("localhost").is_err());
        // 非法字符拒绝
        assert!(validate_domain("acme_stepby.com").is_err());
        // 标签以 - 开头/结尾拒绝
        assert!(validate_domain("-acme.com").is_err());
        assert!(validate_domain("acme-.com").is_err());
        // 空标签拒绝
        assert!(validate_domain("acme..com").is_err());
    }
}
