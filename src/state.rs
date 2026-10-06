// stepby-axum/src/state.rs
//! 应用全局共享状态。
//! 共享态存储双档改造：`redis: ConnectionManager` 字段切换为
//! `store: Arc<dyn SharedStore>`（`[cache].mode = local | redis`，
//! 方案 docs/optimization/ZERO-DEPENDENCY-DEPLOYMENT-PLAN-2026-10-01.md），
//! 调用点通过 trait 方法读写共享态，不再感知具体档位。

use crate::config::Settings;
use crate::handler::ws_handler::WsMessage;
use crate::observability::Observability;
use crate::repository::sys_logininfor::SysLogininforRepository;
use crate::scheduler::JobScheduler;
use crate::service::{
    AuthService, GenTableService, IpLocationService, MailerService, SsoService, SysAlertService,
    SysBackupService, SysConfigService, SysDeptService, SysDictService, SysFlowService,
    SysFrontendErrorService, SysHttpDebugService, SysJobService, SysLogininforService,
    SysMenuService, SysMsgService, SysNoticeService, SysOauthService, SysOperLogService,
    SysPatService, SysPostService, SysRateLimitService, SysReportService, SysRoleService,
    SysTaskService, SysTenantDomainService, SysTenantNavService, SysTenantService,
    SysUserPrefService, SysUserService, SysWebHookService, UserErasureService, WebauthnService,
};
use crate::utils::ip_location::IpLocator;
use sea_orm::DatabaseConnection;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::{broadcast, mpsc};

/// 应用全局共享状态
/// 通过 Axum State<Arc<AppState>> 注入到所有 handler
/// 注：AppState 本身无需 Clone，因始终通过 Arc<AppState> 共享
pub struct AppState {
    /// 数据库连接池
    pub db: DatabaseConnection,
    /// 共享态存储（`[cache].mode` 双档：local = 纯 SQL 承载 / redis = 现状 Redis 命令）。
    /// 业务代码经 `SharedStore` trait 方法读写，不直接触碰 Redis 连接。
    pub store: Arc<dyn crate::shared_store::SharedStore>,
    /// 仅供 `[rate_limit].mode = "redis"` 的 Lua 令牌桶使用的原生 Redis 连接。
    /// 该模式与 local 档互斥：local 档（或 Redis 未初始化）时为 None，
    /// 中间件对此 fail-closed（与 Redis 命令失败同口径返回 503）。
    pub redis_conn: Option<redis::aio::ConnectionManager>,
    /// 全局配置
    pub config: Arc<Settings>,
    /// 用户模块 Service
    pub user_service: SysUserService,
    /// GDPR 被遗忘权 / 用户匿名化 Service（能力位 `privacy.user_erasure` 门控）
    pub user_erasure_service: UserErasureService,
    /// WebAuthn / Passkey Service（能力位 `auth.webauthn` 门控；默认 off ⇒ 端点 404）
    pub webauthn_service: WebauthnService,
    /// 用户消息偏好 / 免打扰 Service
    pub user_pref_service: SysUserPrefService,
    /// 个人访问令牌（PAT）Service（Tier-S #3）
    pub pat_service: SysPatService,
    /// 角色模块 Service
    pub role_service: SysRoleService,
    /// 菜单模块 Service
    pub menu_service: SysMenuService,
    /// 通知公告模块 Service
    pub notice_service: SysNoticeService,
    /// 部门模块 Service
    pub dept_service: SysDeptService,
    pub tenant_service: SysTenantService,
    /// 租户域名绑定 Service（多租户 Phase 3 域名链路：DNS TXT 验证 + host→tid 解析）
    pub tenant_domain_service: SysTenantDomainService,
    /// 租户自建导航 L3 Service（批次 3：能力位 nav.l3 门控的导航结构 CRUD）
    pub tenant_nav_service: SysTenantNavService,
    /// 认证服务
    pub auth_service: AuthService,
    /// 定时任务 Service
    pub job_service: SysJobService,
    /// 字典模块 Service
    pub dict_service: SysDictService,
    /// 参数配置模块 Service
    pub config_service: SysConfigService,
    /// 岗位模块 Service
    pub post_service: SysPostService,
    /// 操作日志 Service
    pub oper_log_service: SysOperLogService,
    /// 审计合规域 Service（数据变更留痕查询 + 导出）
    pub audit_change_service: crate::service::sys_audit_change_service::SysAuditChangeService,
    pub frontend_error_service: SysFrontendErrorService,
    /// API 限流配置 Service
    pub rate_limit_service: SysRateLimitService,
    /// 告警规则引擎 Service（指标采集 / 评估 / 通知）
    pub alert_service: SysAlertService,
    /// 字段级权限 M2：角色字段权限矩阵服务（三层开关判定链单一入口）
    pub field_perm_service: crate::service::sys_role_field_perm_service::SysRoleFieldPermService,
    /// 登录日志 Service
    pub logininfor_service: SysLogininforService,
    /// 代码生成模块 Service
    pub gen_table_service: GenTableService,
    /// 数据备份 Service
    pub backup_service: SysBackupService,
    /// 任务进度 Service
    pub task_service: SysTaskService,
    /// 消息渠道与模板管理 Service
    pub msg_service: SysMsgService,
    /// 审批工作流 Service（方案 B′）
    pub flow_service: SysFlowService,
    /// 第三方登录（OAuth2/OIDC/SSO）Service
    pub oauth_service: SysOauthService,
    /// 单点登录 / OIDC Provider（本系统作为授权服务器）Service（Tier B）
    pub sso_service: SsoService,
    /// v5-D12：SCIM 2.0 用户目录同步 Service（外部 IdP provisioning）
    pub scim_service: crate::service::scim_service::ScimService,
    /// v5-D12 Group：SCIM Group 双映射联动引擎（组→角色集合 / 组→兼职部门）
    pub scim_group_service: crate::service::scim_group_service::ScimGroupService,
    /// 在线 HTTP 调试器 Service（服务端转发 + SSRF 防护）
    pub http_debug_service: SysHttpDebugService,
    /// 报表中心 + 定时订阅推送 Service
    pub report_service: SysReportService,
    /// 报表看板（配置化只读报表 v1；数据源白名单）
    pub report_board_service: crate::service::sys_report_board_service::SysReportBoardService,
    /// WebHook 事件订阅 Service（出站回调配置 + 投递记录 + 事件分发）
    pub web_hook_service: SysWebHookService,
    /// 邮件发送 Service（未启用时降级为 no-op）
    pub mailer_service: MailerService,
    /// 定时任务调度器
    pub job_scheduler: Arc<JobScheduler>,
    /// IP 归属地查询器（mmdb 文件不存在时所有查询返回空字符串）
    /// 通过 Arc 共享，支持后台管理触发热加载（reload 不重启服务）
    pub ip_locator: Arc<IpLocator>,
    /// IP 库管理 Service（下载/解压/校验/热加载/配置加解密）
    pub ip_location_service: IpLocationService,
    /// AI 助手运行时配置 Service（AI-01：sys.ai.* 双源热化 + api_key 信封加密）
    pub ai_config_service: Arc<crate::ai::config_service::AiConfigService>,
    /// G-11：OSS 存储配置运行时服务（sys.upload.s3.* 双源 + 后端指纹缓存）
    pub upload_config_service: Arc<crate::service::upload_config_service::UploadConfigService>,
    /// 文件存储后端（F1：local / s3，按 `upload.backend` 配置切换）
    pub storage: Arc<dyn crate::storage::StorageBackend>,
    /// WebSocket 全局广播通道（实时通知推送）
    pub ws_broadcast: broadcast::Sender<WsMessage>,
    /// WebSocket 按用户定向通道注册表（user_id → 该用户全部活跃连接的发送端）
    ///
    /// 安全设计（P0-2 越权广播修复）：`forceLogout`、`taskProgress` 等含他人会话/身份
    /// 信息的消息不再经全局广播推送给所有在线客户端，而是通过本注册表**定向**投递到
    /// 目标用户的连接。全局广播（`broadcast`）仅保留给公告等公开消息。
    ///
    /// 注意：本注册表为进程内内存结构，仅覆盖当前实例的连接；多实例部署时定向消息
    /// 只投递到本实例内的目标用户连接（与限流/调度器一致的单实例语义），跨实例扩展
    /// 可后续改为 Redis Pub/Sub。
    pub ws_users: RwLock<HashMap<i64, Vec<mpsc::UnboundedSender<WsMessage>>>>,
    /// 应用可观测性句柄（慢请求缓冲 / 错误聚合总线 / Prometheus 指标）
    ///
    /// 由 `observability::Observability::global()` 提供（进程级全局共享），
    /// 与 `/monitor/slow-sql/*`、`/monitor/error-log/*` handler 及 `/metrics` 输出共享同一底层实例。
    pub observability: Arc<Observability>,
}

impl AppState {
    /// 薄封装：向所有 WebSocket 客户端广播消息
    ///
    /// C9：原本 service / handler 层需直接调用 `crate::handler::ws_handler::broadcast(state, ...)`，
    /// 反向依赖 handler 层。这里在 AppState 上提供同名方法，业务层改为 `state.broadcast(...)`，
    /// 仅 1 处新增 + 调用点收敛，避免 service 层对 handler 层的硬依赖。
    ///
    /// 仅用于公开消息（系统公告、通知等）。含用户身份/会话信息的消息必须使用
    /// `broadcast_to_user` 定向投递，防止越权信息泄漏（P0-2）。
    pub fn broadcast(&self, msg_type: &str, data: serde_json::Value) {
        crate::handler::ws_handler::broadcast(self, msg_type, data);
    }

    /// 注册一个用户的 WebSocket 连接发送端（连接建立时调用）
    pub fn register_ws_user(&self, user_id: i64, tx: mpsc::UnboundedSender<WsMessage>) {
        // 锁中毒容错：与 broadcast_to_user 同款范式（unwrap_or_else into_inner），
        // 避免某线程 panic 污染锁后，WS 注册/注销链路被放大为进程级连锁 panic（W-6/5-3）
        let mut users = self.ws_users.write().unwrap_or_else(|e| e.into_inner());
        users.entry(user_id).or_default().push(tx);
    }

    /// 注销一个用户的 WebSocket 连接发送端（连接关闭时调用）
    pub fn unregister_ws_user(&self, user_id: i64, tx: &mpsc::UnboundedSender<WsMessage>) {
        let mut users = self.ws_users.write().unwrap_or_else(|e| e.into_inner());
        if let Some(conns) = users.get_mut(&user_id) {
            conns.retain(|t| !t.same_channel(tx));
            if conns.is_empty() {
                users.remove(&user_id);
            }
        }
    }

    /// 定向推送消息到指定用户的全部活跃 WebSocket 连接（P0-2）
    ///
    /// 与全局广播不同，仅目标用户的连接收到；用户不在线时静默丢弃。
    /// 用于 forceLogout（含 tokenHash/userId/userName）与 taskProgress 等
    /// 仅与特定用户相关的消息，杜绝跨用户信息泄漏。
    pub fn broadcast_to_user(&self, user_id: i64, msg_type: &str, data: serde_json::Value) {
        let msg = WsMessage::new(msg_type, data);
        // 锁中毒容错：与 scheduler/registry.rs 同款范式（unwrap_or_else into_inner），
        // 避免某线程 panic 污染锁后，所有发送方（含审批超时扫描任务）连锁 panic（V6-E6/5-3）
        let users = self.ws_users.read().unwrap_or_else(|e| e.into_inner());
        if let Some(conns) = users.get(&user_id) {
            for tx in conns {
                // 对端已关闭时 send 返回 Err，忽略（连接关闭时会走 unregister 清理）
                if tx.send(msg.clone()).is_err() {
                    tracing::debug!(user_id, "WebSocket 定向投递失败（连接已关闭）");
                }
            }
        }
    }

    /// 构建 AppState 时初始化全部 Service
    ///
    /// 保持同步函数签名，调度器在 AppInitializer::run 中提前异步创建后传入
    ///
    /// 修复 P0-R81-014：原本 AuthService::new(db) 内部重复实例化 user/role/menu service，
    /// 导致与 AppState 中的同名实例各自独立（15 个重复 Repository 实例）。
    /// 现在先实例化 user/role/menu service，再 clone 一份传入 AuthService::new，
    /// 同时也实例化 logininfor_repo / config_repo 传入，确保单实例共享。
    pub fn new(
        db: DatabaseConnection,
        store: Arc<dyn crate::shared_store::SharedStore>,
        redis_conn: Option<redis::aio::ConnectionManager>,
        config: Arc<Settings>,
        job_scheduler: Arc<JobScheduler>,
        ip_locator: Arc<IpLocator>,
        ip_location_service: IpLocationService,
        storage: Arc<dyn crate::storage::StorageBackend>,
    ) -> Self {
        // WebSocket 广播通道（容量 256，超出后旧消息被丢弃；客户端按需订阅）
        let (ws_broadcast, _) = broadcast::channel::<WsMessage>(256);

        // 先实例化 user/role/menu service，再 clone 一份注入 AuthService（共享底层 Repository 实例）
        // 三个 Service 均持有共享态存储句柄，用于权限缓存（cache-aside + 失效）
        let user_service = SysUserService::new(db.clone(), store.clone());
        let role_service = SysRoleService::new(db.clone(), store.clone());
        let menu_service = SysMenuService::new(db.clone(), store.clone());

        // H-4：config_service 提前实例化（持有共享态存储用于 cache-aside 缓存），
        // clone 一份注入 AuthService，使登录/注册流程的验证码开关、注册开关查询走缓存，
        // 减少每次登录 2 次 DB 查询（captchaEnabled + registerUser）。
        let config_service = SysConfigService::new(db.clone(), store.clone());
        // §5.39 AI-01：ai_config_service 需要在 config_service 被 move 进结构体前克隆
        let config_service_for_ai = config_service.clone();
        // G-11：upload_config_service 同样在 move 前克隆
        let config_service_for_upload = config_service.clone();

        // 字段级权限 M2：矩阵服务复用 config_service（第一层平台开关走 cache-aside 热加载）。
        // 提前实例化（Self{} 构造会 move config_service 原值）。
        let field_perm_service =
            crate::service::sys_role_field_perm_service::SysRoleFieldPermService::new(
                db.clone(),
                config_service.clone(),
            );

        // 多租户 Phase 3：tenant_service 提前实例化（登录闸门 + 运行时状态键 + 定向踢线），
        // clone 一份注入 AuthService，保证同一实例共享（避免重复 Repository）
        let tenant_service = SysTenantService::new(db.clone(), store.clone());

        // 多租户 Phase 3 域名链路：域名服务持有独立共享态存储（host 缓存 tenant:host:{domain}）
        // 批次 4：注入 config 以承载 `[acme]` 证书需求输出集成点（默认 off = 不发请求）
        let tenant_domain_service =
            SysTenantDomainService::new(db.clone(), store.clone(), config.clone());

        // 批次 3：L3 租户自建导航服务（能力位 nav.l3 门控；复用 menu_service 的菜单树口径）
        let tenant_nav_service =
            SysTenantNavService::new(db.clone(), menu_service.clone(), tenant_service.clone());

        // L3 导航仓储（`get_routers` 的加载期重组数据源，与 AuthService 共享同一 db）
        let tenant_menu_repo =
            crate::repository::sys_tenant_menu::SysTenantMenuRepository::new(db.clone());

        // AuthService 复用上述 Service 实例 + 单独实例化 logininfor_repo
        // REGRESS-007 说明：P0-R81-014 已消除 15 个重复 Repository。
        // 剩余 1 个 logininfor_repo 是 AuthService 直接调用 Repository 层 insert 方法，
        // Repository 实例仅持有 Arc<DatabaseConnection>，开销极低，保持当前设计。
        let auth_service = AuthService::new(
            user_service.clone(),
            menu_service.clone(),
            SysLogininforRepository::new(db.clone()),
            config_service.clone(),
            config.clone(),         // P0-4：TOTP secret 加解密需要 config_enc_key
            tenant_service.clone(), // Phase 3：登录闸门（sys_tenant 三态）+ 运行时键同步
            tenant_menu_repo,       // 批次 3：L3 导航加载期重组
        );

        // 用户匿名化 Service（能力位 `privacy.user_erasure` 门控）：
        // 复用同一个 SsoService 实例（`revoke_user_sso_tokens`），保证吊销口径单点。
        // 平台层能力集由 `config [features]` 净化解析（与启动注入同源），支持按实例独立配置。
        let sso_service = SsoService::new(
            db.clone(),
            config.config_enc_key.clone(),
            vec![config.jwt.audience.clone(), config.jwt.issuer.clone()],
        );
        let user_erasure_service = UserErasureService::new(
            db.clone(),
            store.clone(),
            sso_service.clone(),
            config.clone(),
        );

        // WebAuthn / Passkey Service（能力位 `auth.webauthn` 门控；默认 off ⇒ 端点 404）。
        // 复用同一 tenant_service：passkey 登录的租户闸门与密码登录口径单点。
        let webauthn_service = WebauthnService::new(
            db.clone(),
            store.clone(),
            tenant_service.clone(),
            config.clone(),
        );

        // 全局可观测性句柄：按配置文件注入慢请求阈值 / 缓冲容量（进程内生效）
        // 注意：Observability 为进程级全局单例，这里仅做一次配置；重复初始化以最后一次为准。
        let observability = Observability::global();
        observability
            .slow
            .configure(config.monitor.slow_request_ms, config.monitor.slow_capacity);
        observability
            .error_log
            .set_capacity(config.monitor.error_capacity);

        Self {
            user_service: user_service.clone(),
            user_erasure_service,
            webauthn_service,
            user_pref_service: SysUserPrefService::new(db.clone()),
            pat_service: SysPatService::new(db.clone(), menu_service.clone()),
            role_service,
            menu_service,
            notice_service: SysNoticeService::new(db.clone()),
            dept_service: SysDeptService::new(db.clone()),
            // 多租户 Phase 3：租户服务需要共享态存储（运行时状态键 + 定向会话吊销）
            tenant_service,
            tenant_domain_service,
            tenant_nav_service,
            auth_service,
            job_service: SysJobService::new(db.clone(), job_scheduler.clone()),
            dict_service: SysDictService::new(db.clone(), store.clone()),
            config_service,
            post_service: SysPostService::new(db.clone()),
            // 操作日志 Service：启用 HMAC 防篡改链（链密钥从 JWT secret 派生，不落盘）
            oper_log_service: SysOperLogService::with_chain(
                db.clone(),
                store.clone(),
                &config.jwt.secret,
            ),
            // 审计合规域：变更留痕 Service
            audit_change_service:
                crate::service::sys_audit_change_service::SysAuditChangeService::new(db.clone()),
            frontend_error_service: SysFrontendErrorService::new(db.clone()),
            rate_limit_service: SysRateLimitService::new(db.clone(), store.clone()),
            alert_service: SysAlertService::new(db.clone(), store.clone(), config.clone()),
            // 字段级权限 M2：矩阵服务（三层开关判定链单一入口）
            field_perm_service,
            logininfor_service: SysLogininforService::new(db.clone()),
            gen_table_service: GenTableService::new(db.clone()),
            backup_service: SysBackupService::new(db.clone(), config.clone()),
            task_service: SysTaskService::new(db.clone()),
            msg_service: SysMsgService::new(db.clone(), config.clone()),
            flow_service: SysFlowService::new(
                db.clone(),
                config.clone(),
                SysMsgService::new(db.clone(), config.clone()),
            ),
            oauth_service: SysOauthService::new(
                db.clone(),
                user_service.clone(),
                // v5-E6：provider secret / 第三方令牌信封加密
                config.config_enc_key.clone(),
            ),
            // v4 §1.3：动态保留字 = 平台 JWT 命名空间（audience/issuer），
            // 与静态 RESERVED_CLIENT_IDS 一并在 add_client 时比对（见上方创建处）
            sso_service,
            scim_service: crate::service::scim_service::ScimService::new(
                db.clone(),
                config.scim.tenant_id,
            ),
            scim_group_service: crate::service::scim_group_service::ScimGroupService::new(
                db.clone(),
                config.scim.tenant_id,
            ),
            http_debug_service: SysHttpDebugService::default(),
            report_service: SysReportService::new(db.clone(), config.clone()),
            report_board_service:
                crate::service::sys_report_board_service::SysReportBoardService::new(
                    db.clone(),
                    store.clone(),
                ),
            web_hook_service: SysWebHookService::new(db.clone(), config.config_enc_key.clone()),
            ai_config_service: Arc::new(crate::ai::config_service::AiConfigService::new(
                db.clone().into(),
                config_service_for_ai,
                config.ai.clone(),
                config.config_enc_key.clone(),
            )),
            upload_config_service: Arc::new(
                crate::service::upload_config_service::UploadConfigService::new(
                    db.clone().into(),
                    config_service_for_upload,
                    config.upload.s3.clone(),
                    config.upload.backend.clone(),
                    config.config_enc_key.clone(),
                ),
            ),
            mailer_service: MailerService::new(config.clone()),
            job_scheduler,
            db,
            store,
            redis_conn,
            config,
            ip_locator,
            ip_location_service,
            storage,
            ws_broadcast,
            ws_users: RwLock::new(HashMap::new()),
            observability,
        }
    }
}

/// G-11：上传链路存储后端运行时解析（统一入口）
///
/// - config.toml 档位 `local` 或无运行时覆盖 → 启动时构建的 `storage`（零行为变化）；
/// - 档位 `s3` 且 `sys.upload.s3.*` 运行时覆盖生效 → 指纹缓存的运行时后端
///   （配置未变复用实例，变更整实例替换，旧实例 Arc 存活至在途请求结束）。
///
/// 保存/读取/删除链路统一经本方法取后端，避免"写进新配置、删在旧配置"的撕裂。
impl AppState {
    pub async fn resolve_storage(
        &self,
    ) -> Result<std::sync::Arc<dyn crate::storage::StorageBackend>, crate::common::ServiceError>
    {
        self.upload_config_service
            .resolve_s3_backend(&self.storage)
            .await
    }
}
