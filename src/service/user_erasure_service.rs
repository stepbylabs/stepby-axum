//! GDPR 被遗忘权 / 用户匿名化 Service 层。
//!
//! # 定位
//!
//! 平台级**数据治理动作**：把某个租户用户的个人身份信息（PII）不可逆地置换为匿名占位，
//! 释放其全局唯一登录键，并吊销其全部会话 / PAT / SSO 令牌。审计留痕（`sys_oper_log`
//! / `sys_logininfor`）**保留**——匿名化只处理 `sys_user` 主体与其派生的活跃凭据，
//! 不物理删除审计（否则被遗忘权会变成"抹掉操作痕迹"）。
//!
//! # 能力位（三层开关，单一事实源 = `governance::FEATURES`）
//!
//! 键 `privacy.user_erasure`，档位 `off | precheck | full`（默认 `off`）：
//! - `off`：端点表现为 **404**（与 `[sso].introspection_enabled` 同口径，不暴露"存在但被关"）；
//! - `precheck`：仅允许只读预检（dry-run）；执行端点仍 404；
//! - `full`：允许真正执行。
//!
//! 本能力位**不向租户解锁任何 perm**（注册表 `unlocked = &[]`）：匿名化是平台治理动作，
//! 只有平台管理员（`tenant_id == 0`）可触发；两条路由复用既有 `system:user:remove` perm。
//!
//! # 守卫顺序（任一不满足立即返回，fail-closed）
//!
//! ① 能力位档位不足 ⇒ `404`；② 非平台操作者（`operator_tid != 0`）⇒ `404`；
//! ③ 目标用户不存在 ⇒ `404`；④ 目标属平台租户（`tenant_id == 0`）或超管（`user_id == 1`）
//! ⇒ `400`（防止把平台管理员匿名化）。
//!
//! # 幂等
//!
//! 目标已是匿名化态（`user_name == "deleted_{user_id}"`）⇒ 直接返回报告，不重复写、不报错。

use std::sync::Arc;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    Set, TransactionTrait,
};
use serde::Serialize;
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::constants::SUPER_ADMIN_USER_ID;
use crate::common::error::ServiceError;
use crate::common::features::{FeatureSet, mode_reaches};
use crate::config::Settings;
use crate::entity::sys_oauth_user::{Column as OAuthUserColumn, Entity as SysOauthUser};
use crate::entity::sys_pat::{Column as PatColumn, Entity as SysPat};
use crate::entity::sys_user::{ActiveModel as SysUserActiveModel, Model as SysUserModel};
use crate::repository::sys_user::SysUserRepository;
use crate::shared_store::SharedStore;

/// 能力位键（`governance::FEATURES` 单一事实源）。
pub const FEATURE_USER_ERASURE: &str = "privacy.user_erasure";
/// 预检所需最低档位。
pub const MODE_PRECHECK: &str = "precheck";
/// 执行所需最低档位。
pub const MODE_FULL: &str = "full";

/// 将被匿名化的字段清单（预检与执行共用的**单一事实源**）。
///
/// 逐条枚举：只置换 PII / 凭据 / 状态字段，**不动** `user_id` / `dept_id` / `tenant_id`
/// / `create_by` / `create_time` / `user_type` 等非 PII 的结构与审计字段。
pub const ERASURE_FIELDS: &[&str] = &[
    "userName",
    "nickName",
    "email",
    "phonenumber",
    "sex",
    "avatar",
    "remark",
    "loginIp",
    "password",
    "status",
    "delFlag",
    "updateBy",
    "updateTime",
];

/// 匿名化报告（预检与执行共用）。
#[derive(Debug, Clone, Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "UserErasureReport",
    export_to = "UserErasureReport.ts",
    rename_all = "camelCase"
)]
#[schema(as = UserErasureReport)]
pub struct UserErasureReport {
    /// 目标用户 ID
    pub user_id: i64,
    /// 目标用户当前登录名（预检 = 原值；执行后 = `deleted_{user_id}`）
    pub user_name: String,
    /// 目标是否已处于匿名化态（幂等命中时为 true）
    pub already_anonymized: bool,
    /// 将被 / 已被匿名化的字段清单（`ERASURE_FIELDS`）
    pub fields: Vec<String>,
    /// 受影响的有效 PAT 数（执行时将被吊销）
    pub pat_count: u64,
    /// 受影响的第三方登录绑定数（`sys_oauth_user`）
    pub sso_binding_count: u64,
    /// 受影响的 Redis 在线会话数（best-effort；取不到按 0）
    pub online_session_count: u64,
}

/// 用户匿名化 Service。
///
/// 依赖：`sys_user` 仓储、共享态存储（会话失效标记 + SSO 令牌全量吊销）、以及由
/// `config [features]` 净化解析出的**平台层能力集**（与启动注入同口径）。
///
/// b74 收口：原先还持有 `SsoService` 字段但**从不读取**（SSO 吊销早已收敛为
/// `store.revoke_all_for_user`），注释称"兼容既有构造方"而构造方只有 `state.rs` 一处
/// ⇒ 属假依赖，已删。
#[derive(Clone)]
pub struct UserErasureService {
    db: DatabaseConnection,
    store: Arc<dyn SharedStore>,
    user_repo: SysUserRepository,
    /// 平台层能力集（构造时按 `config.features` 净化解析；与 `initialize::init_feature_flags`
    /// 同源同口径，仅**不读进程级 OnceLock**，从而支持每实例（含集成测试）独立配置）。
    features: FeatureSet,
}

impl UserErasureService {
    pub fn new(db: DatabaseConnection, store: Arc<dyn SharedStore>, config: Arc<Settings>) -> Self {
        let features = FeatureSet::sanitized(config.features.0.clone());
        Self {
            user_repo: SysUserRepository::new(db.clone()),
            db,
            store,
            features,
        }
    }

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// 守卫①：能力位档位不足 ⇒ 404（端点表现为"不存在"，与关闭态/无此功能等价）。
    fn ensure_mode(&self, mode: &str) -> Result<(), ServiceError> {
        if mode_reaches(&self.features, FEATURE_USER_ERASURE, mode) {
            Ok(())
        } else {
            Err(ServiceError::not_found(&crate::tr!(
                "error.user.erasure_disabled"
            )))
        }
    }

    /// 守卫②：平台专属（复刻 `SysTenantService::ensure_platform_operator` 语义，
    /// 但按本能力的口径统一以 **404** 隐藏端点存在性）。
    fn ensure_platform_operator(operator_tid: i64) -> Result<(), ServiceError> {
        if operator_tid == 0 {
            Ok(())
        } else {
            Err(ServiceError::not_found(&crate::tr!(
                "error.user.erasure_platform_only"
            )))
        }
    }

    /// 守卫③④：加载目标用户并拒绝平台用户 / 超管。
    async fn load_target(&self, user_id: i64) -> Result<SysUserModel, ServiceError> {
        let target = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        // 平台用户（tenant_id == 0）或超管（user_id == 1）：拒绝（防止把平台管理员匿名化）
        if target.tenant_id == 0 || user_id == SUPER_ADMIN_USER_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.erasure_forbidden"
            )));
        }
        Ok(target)
    }

    /// 目标是否已处于匿名化态（`user_name == "deleted_{id}"`）。
    fn is_anonymized(target: &SysUserModel) -> bool {
        target.user_name == Self::anonymized_user_name(target.user_id)
    }

    fn anonymized_user_name(user_id: i64) -> String {
        format!("deleted_{user_id}")
    }

    /// 受影响的有效 PAT 数（status='0'）；查询失败按 0（best-effort）。
    ///
    /// **同时按 `tenant_id` 收窄**（纵深防御）：`user_id` 已全局唯一、仅此一条件即无跨租户泄漏，
    /// 但按项目约定「按 biz_id 查询必须带 tenant_id 过滤」（审计器 R1 亦以此为准），
    /// 且显式过滤可防"未来 `user_id` 语义变化"时的静默放大。
    async fn count_active_pats(&self, user_id: i64, tenant_id: i64) -> u64 {
        SysPat::find()
            .filter(PatColumn::UserId.eq(user_id))
            .filter(PatColumn::TenantId.eq(tenant_id))
            .filter(PatColumn::Status.eq("0"))
            .count(self.db())
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(user_id, tenant_id, error = %e, "匿名化预检：统计 PAT 失败（按 0 处理）");
                0
            })
    }

    /// 第三方登录绑定数（`sys_oauth_user`）；查询失败按 0（best-effort）。
    ///
    /// 同 [`Self::count_active_pats`]：并列 `tenant_id` 过滤（纵深防御 + 满足 R1 口径）。
    async fn count_sso_bindings(&self, user_id: i64, tenant_id: i64) -> u64 {
        SysOauthUser::find()
            .filter(OAuthUserColumn::UserId.eq(user_id))
            .filter(OAuthUserColumn::TenantId.eq(tenant_id))
            .count(self.db())
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(user_id, tenant_id, error = %e, "匿名化预检：统计第三方绑定失败（按 0 处理）");
                0
            })
    }

    /// 共享态存储在线会话数（SCAN `online:*` 全量 → 解析 `OnlineSession.user_id`）；取不到按 0。
    async fn count_online_sessions(&self, user_id: i64) -> u64 {
        let keys = match self.store.scan("online:*", None).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(user_id, error = %e, "匿名化预检：SCAN online:* 失败（按 0 处理）");
                return 0;
            }
        };
        if keys.is_empty() {
            return 0;
        }
        let values: Vec<Option<String>> = match self.store.get_many(&keys).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(user_id, error = %e, "匿名化预检：批量读取 online 失败（按 0 处理）");
                return 0;
            }
        };
        keys.iter()
            .zip(values.iter())
            .filter(|(_, v)| {
                v.as_deref()
                    .and_then(|j| {
                        serde_json::from_str::<crate::utils::crypto::OnlineSession>(j).ok()
                    })
                    .is_some_and(|s| s.user_id == user_id)
            })
            .count() as u64
    }

    /// 组装受影响关系计数。
    async fn collect_counts(&self, user_id: i64, tenant_id: i64) -> (u64, u64, u64) {
        let pat = self.count_active_pats(user_id, tenant_id).await;
        let sso = self.count_sso_bindings(user_id, tenant_id).await;
        let online = self.count_online_sessions(user_id).await;
        (pat, sso, online)
    }

    fn fields() -> Vec<String> {
        ERASURE_FIELDS.iter().map(|s| (*s).to_string()).collect()
    }

    /// **只读预检**（dry-run）：返回将被匿名化的字段清单 + 受影响关系计数，**不产生任何写入**。
    ///
    /// 档位要求：≥ `precheck`。
    pub async fn anonymize_precheck(
        &self,
        user_id: i64,
        operator_tid: i64,
    ) -> Result<UserErasureReport, ServiceError> {
        self.ensure_mode(MODE_PRECHECK)?;
        Self::ensure_platform_operator(operator_tid)?;
        let target = self.load_target(user_id).await?;
        let (pat_count, sso_binding_count, online_session_count) =
            self.collect_counts(user_id, target.tenant_id).await;
        Ok(UserErasureReport {
            user_id,
            user_name: target.user_name.clone(),
            already_anonymized: Self::is_anonymized(&target),
            fields: Self::fields(),
            pat_count,
            sso_binding_count,
            online_session_count,
        })
    }

    /// **执行匿名化**（不可逆）。
    ///
    /// 档位要求：== `full`。字段置换严格限定在 [`ERASURE_FIELDS`]；关联凭据吊销复用既有
    /// 吊销机制（`pwd_ver` 会话失效标记 + `SsoService::revoke_user_sso_tokens` + `sys_pat` 吊销）；
    /// 审计表不物理删除。幂等：目标已匿名化态 ⇒ 直接返回报告。
    pub async fn anonymize_user(
        &self,
        user_id: i64,
        operator: &str,
        operator_tid: i64,
    ) -> Result<UserErasureReport, ServiceError> {
        self.ensure_mode(MODE_FULL)?;
        Self::ensure_platform_operator(operator_tid)?;
        let target = self.load_target(user_id).await?;

        // 幂等：已是匿名化态 ⇒ 不重复写、不报错
        if Self::is_anonymized(&target) {
            let (pat_count, sso_binding_count, online_session_count) =
                self.collect_counts(user_id, target.tenant_id).await;
            return Ok(UserErasureReport {
                user_id,
                user_name: target.user_name.clone(),
                already_anonymized: true,
                fields: Self::fields(),
                pat_count,
                sso_binding_count,
                online_session_count,
            });
        }

        let (pat_count, sso_binding_count, online_session_count) =
            self.collect_counts(user_id, target.tenant_id).await;

        // ① 会话失效（复用 delete_user / change_status 的同一出口）：
        //    `store.revoke_credentials` = 递增 `pwd_ver`（使已签发 JWT 在 auth 中间件被拒）
        //    + 全量吊销该用户 SSO 令牌（userinfo 只认绑定、不校验 pwd_ver）。
        //    fail-closed：写入失败则中止（不留"密码已清空但旧会话仍可用"的窗口）。
        //    b104：两条腿必须都在**破坏性写入之前**完成——匿名化后用户行已被改写，
        //    任何"先匿名化再撤权、失败只记日志"的顺序都无法重放，且旧 AT 在 TTL 内仍可
        //    换到身份（GDPR 语境下这是实质缺陷，不是理论窗口）。
        self.store
            .revoke_credentials(&user_id.to_string())
            .await
            .map_err(|e| {
                tracing::error!(user_id, error = %e, "匿名化前会话吊销失败（fail-closed 中止）");
                ServiceError::internal(&crate::tr!("error.user.erasure_revoke_failed"))
            })?;

        // ②+④ 字段置换与 PAT 吊销同事务（b102）：原实现两次独立提交，用户行匿名化成功而
        // PAT 更新失败时仍返回成功报告，匿名化用户的 PAT 继续可用（越权面）。两者同在
        // 一个 DB 上，没有任何理由分开提交；SSO 吊销（外部共享态）留在事务之后。
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| ServiceError::internal(&format!("开启事务失败: {e}")))?;
        let now = crate::common::datetime::now_naive();
        let mut am: SysUserActiveModel = target.clone().into();
        am.user_name = Set(Self::anonymized_user_name(user_id));
        am.nick_name = Set("已注销用户".to_string());
        am.email = Set(None);
        am.phonenumber = Set(None);
        am.sex = Set(None);
        am.avatar = Set(None);
        am.remark = Set(None);
        am.login_ip = Set(None);
        am.password = Set(None);
        am.status = Set(Some("1".to_string()));
        am.del_flag = Set(Some("2".to_string()));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.update(&txn).await?;

        // 立即吊销该用户全部 PAT（status '0' → '1'）。与计数同一口径：并列 tenant_id 过滤
        // （纵深防御，防"未来 user_id 语义变化"时放大撤销面）。
        let pat_revoked = SysPat::update_many()
            .col_expr(PatColumn::Status, sea_orm::sea_query::Expr::value("1"))
            .filter(PatColumn::UserId.eq(user_id))
            .filter(PatColumn::TenantId.eq(target.tenant_id))
            .filter(PatColumn::Status.eq("0"))
            .exec(&txn)
            .await?
            .rows_affected;
        txn.commit()
            .await
            .map_err(|e| ServiceError::internal(&format!("提交事务失败: {e}")))?;
        if pat_revoked > 0 {
            tracing::info!(user_id, pat_revoked, "匿名化：PAT 已吊销");
        }

        tracing::warn!(
            user_id,
            operator,
            pat_count,
            sso_binding_count,
            online_session_count,
            "用户已匿名化（GDPR 被遗忘权；审计留痕保留）"
        );

        Ok(UserErasureReport {
            user_id,
            user_name: Self::anonymized_user_name(user_id),
            already_anonymized: false,
            fields: Self::fields(),
            pat_count,
            sso_binding_count,
            online_session_count,
        })
    }
}
