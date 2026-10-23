// stepby-axum/src/initialize/mod.rs

use crate::config::Settings;
use crate::config::settings::CacheMode;
use crate::db;
use crate::logger;
use crate::scheduler::JobScheduler;
use crate::service::IpLocationService;
use crate::shared_store::SharedStore;
use crate::state::AppState;
use crate::utils::ip_location::IpLocator;
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};
use std::sync::Arc;

/// 初始化编排模块
pub struct AppInitializer;

/// 全新库检测 + 自动迁移：seaql_migrations 表不存在（空库）时执行 Migrator::up。
///
/// 背景：此前全新库初始化无自动化路径（deployment.md 的 `cd migration && cargo run` 已过时——
/// migration crate 无 bin target），空库直接启动会因缺基础表失败。本兜底使「拷贝配置 -> 启动后端」
/// 即可完成全新部署；存量库（seaql_migrations 存在）维持「启动不跑 Migrator::up」的架构约定不变。
async fn run_migrator_if_fresh_db(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let sql = match backend {
        DatabaseBackend::Sqlite => {
            "SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table' AND name='seaql_migrations'"
        }
        DatabaseBackend::Postgres => {
            "SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_name = 'seaql_migrations'"
        }
        DatabaseBackend::MySql => {
            "SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'seaql_migrations'"
        }
        _ => unreachable!("unknown backend"),
    };
    let row = db
        .query_one_raw(Statement::from_string(backend, sql.to_string()))
        .await
        .map_err(|e| anyhow::anyhow!("探测 seaql_migrations 失败: {}", e))?;
    let n = row
        .and_then(|r| r.try_get::<i64>("", "n").ok())
        .unwrap_or(0);
    if n > 0 {
        tracing::info!("检测到存量库（seaql_migrations 存在），跳过 Migrator::up（启动不跑迁移）");
        return Ok(());
    }
    tracing::info!("检测到全新库（无 seaql_migrations），执行 Migrator::up 全量建表 + 基础种子...");
    use migration::MigratorTrait;
    migration::Migrator::up(db, None)
        .await
        .map_err(|e| anyhow::anyhow!("全新库 Migrator::up 失败: {}", e))?;
    tracing::info!("全新库自动迁移完成");
    Ok(())
}

impl AppInitializer {
    /// 执行完整初始化流程，返回 AppState
    pub async fn run(config_path: &str) -> anyhow::Result<Arc<AppState>> {
        // 1. 加载配置（含 .env 环境变量覆盖）
        let settings = Arc::new(Settings::from_file(config_path)?);

        // 1.05 轮换过渡期旧密钥**紧跟配置加载**注入（批八十五 项 D）：crypto 侧原先自己
        // `env::var("CONFIG_ENC_KEY_PREVIOUS")`，于是配置文件里的 `config_enc_key_previous`
        // 永不参与解密（字段有、强度校验有、消费点没有）。现在与 Settings 单点对齐，
        // 且必须排在任何解密调用之前——OnceLock 首写优先，晚注入等于没注入。
        crate::utils::crypto::set_runtime_previous_key(settings.config_enc_key_previous.clone());

        // 1.1 零配置引导：data 目录自建（SQLite 落盘 / secret.key 引导密钥的宿主目录）。
        // 失败不阻断——SQLite 初始化会再报真实错误；有 config.toml 的存量部署目录已存在（幂等）。
        if let Err(e) = std::fs::create_dir_all("data") {
            tracing::debug!("data 目录创建失败（不阻断，交由后续真实 IO 报错）: {}", e);
        }
        // config.toml 路径 database.url 为 sqlite:// 且父目录不存在时统一自建（init 前兜底）
        ensure_sqlite_parent_dir(&settings.database.url);

        // 2. 初始化日志
        logger::init_logger(&settings.log);

        tracing::info!("=== stepby-axum 初始化中 ===");

        // 2.0 配置文件里**未被识别的条目**（段名拼错 = 整段静默回落默认值；b85 项 B 起
        // 还含已知段里拼错的子键 = 该旋钮静默回落默认值）⇒ 启动 WARN。
        // 必须排在日志初始化之后（否则这条告警落不进日志），且不改变任何行为（详见 helpers）。
        init_unknown_config_paths(&settings);

        // 2.1 能力位注入（三层开关的最外层：平台 config「能开什么」）。
        // 必须在任何服务/中间件读取 `common::features::platform_features()` **之前**完成，
        // 否则一律按"全关"处理——虽仍 fail-closed，但会让 `[features]` 里配置的开关静默失效。
        init_feature_flags(&settings);

        // 2.1b P2-33：HTTP 状态码约定（`[server].http_status_convention`）。
        // `IntoResponse` 是 trait 方法、签名不含应用状态 ⇒ 与能力位同法在启动期注入全局；
        // 必须在任何响应产生之前完成，否则前若干请求会按默认档（legacy）出报文。
        init_http_status_convention(&settings);

        // 2.2 ACME 证书需求输出姿态（`[acme]`）：默认 off；配了 webhook 但地址非法时告警，
        // 避免"以为会推送其实静默失效"（与 MT-4 反代白名单同类坑）。
        init_acme_output(&settings);

        // 2.3 出站领域事件姿态（`[events]`）：默认 off；配了 webhook 但地址非法时告警（同上）。
        init_events_output(&settings);

        // 2.4 WebAuthn / Passkey 姿态（`[features].auth.webauthn` + `[webauthn]`）：
        // 能力位开启但 rp_id/origin 未配置且无法推导/推导非法时打 **WARN**（拒绝静默失效）。
        init_webauthn_output(&settings);

        // 2.5 #10 出站 webhook 熔断（`[resilience].outbound_breaker`）：默认 off = 现状
        // （不判定/不记账/每次都尝试发送）；on 时对 `[acme]` / `[events]` 的出站推送生效。
        init_outbound_breaker(&settings);

        // 2.6 多实例部署 + 限流档位自检（与 WF-2 / §4.2「部署形态 vs 配置」同族）：
        // `[scheduler].replicas > 1` 且 `[rate_limit].mode = "local"` ⇒ 打 WARN——
        // 进程内令牌桶在多副本下各实例独立计数，攻击者轮询不同副本即可把配额放大 N 倍（M-8）。
        // 默认 `replicas = 1` 不触发，对存量单实例部署零行为变更。
        init_rate_limit_guards(&settings);

        // 3. 初始化数据库
        let db = db::init_database(&settings.database, settings.log.sql_logging).await?;

        // 3.0 全新库自动初始化：seaql_migrations 表不存在 => 空库 => 自动执行 Migrator::up
        // （建全部表 + 基础种子）。存量库跳过——架构约定启动不跑 Migrator::up，
        // 避免 seed 重跑主键冲突；存量库演进由下方 ensure_* 幂等兜底负责。
        run_migrator_if_fresh_db(&db)
            .await
            .map_err(|e| anyhow::anyhow!("全新库自动迁移失败: {}", e))?;

        // 3.1 G18：幂等确保 sys_user 含 country_code 列（存量库向后兼容，加列后才不会因实体新字段查询报错）
        ensure_user_country_code_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_user.country_code 列失败: {}", e))?;

        // 3.1.1 v5-N2 Phase 2：幂等确保 sys_user 含 tenant_id 列（登录 JWT tid 数据源；
        // 存量库启动不跑 Migrator::up，m20260924_000005 由 migration 负责全新库）
        ensure_user_tenant_id_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_user.tenant_id 列失败: {}", e))?;

        // 3.1.3 v5-D12：幂等确保 sys_user 含 scim_external_id 列（SCIM 用户目录同步；
        // m20260924_000006 由 migration 负责全新库）
        if !sso_has_column(&db, "sys_user", "scim_external_id").await? {
            db.execute_raw(Statement::from_string(
                db.get_database_backend(),
                "ALTER TABLE sys_user ADD COLUMN scim_external_id VARCHAR(255)".to_string(),
            ))
            .await?;
            tracing::info!("sys_user.scim_external_id 列已补建（存量库兜底）");
        }

        // 3.1.4 v5-D5：幂等确保 sys_oauth_client 含 sector_identifier_uri 列
        //（pairwise sector 聚合；m20260924_000007 由 migration 负责全新库）
        // ⚠️ 须先探测表存在：极老存量库（m20260922_sso_module 之前）无 SSO 表，
        // 无守卫时 ALTER 直接 no such table 启动崩（schema 等价性总锁实测发现）。
        if sso_table_exists(&db, "sys_oauth_client").await?
            && !sso_has_column(&db, "sys_oauth_client", "sector_identifier_uri").await?
        {
            db.execute_raw(Statement::from_string(
                db.get_database_backend(),
                "ALTER TABLE sys_oauth_client ADD COLUMN sector_identifier_uri VARCHAR(255)"
                    .to_string(),
            ))
            .await?;
            tracing::info!("sys_oauth_client.sector_identifier_uri 列已补建（存量库兜底）");
        }

        // 3.1.2 真实运行验证发现的存量库漂移：sys_dept 缺 leader_user_id 列导致
        //        登录链路 dept 查询 500（oper_log 部门名/在线列表）。幂等补列兜底。
        if sso_table_exists(&db, "sys_dept").await?
            && !sso_has_column(&db, "sys_dept", "leader_user_id").await?
        {
            db.execute_raw(Statement::from_string(
                db.get_database_backend(),
                "ALTER TABLE sys_dept ADD COLUMN leader_user_id BIGINT".to_string(),
            ))
            .await?;
            tracing::info!("sys_dept.leader_user_id 列已补建（存量库兜底）");
        }
        // 3.1.2b 主管回填（审批链前置条件）——仅补列不补值会让「部门主管审批」整链不可用：
        // `ApproverPolicy::DeptLeader` 解析 leader_user_id 为空即 400 error.flow.leader_missing，
        // 故存量库（列为历史 initialize 所加、从未回填）提交单据必然失败。
        // 迁移 m20260923_000002 的回填只在"列刚新建"时执行（has_column 即早退），覆盖不到该场景，
        // 因此这里做**每次启动都执行**的幂等回填。
        ensure_platform_dept_leaders(&db)
            .await
            .map_err(|e| anyhow::anyhow!("平台部门主管回填失败: {}", e))?;

        // 3.2 P0-2：幂等确保 sys_task 含 operator_id 列（存量库向后兼容）
        // 背景：m20260806_000002_add_task_operator_id 迁移负责全新库建表时带该列，
        // 但 AppInitializer 启动不跑 Migrator::up（避免对已有种子数据的存量库重跑 seed 导致主键冲突），
        // 故存量库需在此幂等补列，否则 /system/task/list 会因缺列报 500。
        ensure_task_operator_id_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_task.operator_id 列失败: {}", e))?;

        // 3.3 Tier-S #2：幂等确保 sys_oper_log 含 oper_diff 列（存量库向后兼容）
        // 背景：m20260822_000001_oper_log_diff 迁移负责全新库建表时带该列，但 AppInitializer
        // 启动不跑 Migrator::up，故存量库需在此幂等补列，否则操作日志查询/写入会因缺列报错。
        ensure_oper_log_diff_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_oper_log.oper_diff 列失败: {}", e))?;

        // 3.4 Tier-S #3：幂等确保 sys_pat 表存在（存量库向后兼容）
        // 背景：m20260823_000001_sys_pat 迁移负责全新库建表，但 AppInitializer 启动不跑
        // Migrator::up（避免对已有种子数据的存量库重跑 seed 导致主键冲突），故存量库需在此
        // 幂等建表，否则 PAT 鉴权查库与令牌管理接口会因缺表报错。
        ensure_data_rule_tables(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 data_rule 表失败: {}", e))?;
        ensure_sys_pat_table(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_pat 表失败: {}", e))?;

        // 3.5 Tier-S #3：幂等确保 PAT 管理菜单存在（存量库启动不跑 Migrator::up，
        // 与迁移 m20260823_000001_sys_pat 等价地登记 sys_menu，使 /monitor/pat 页面可进入）。
        ensure_sys_pat_menu(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 PAT 管理菜单失败: {}", e))?;

        // 3.5b 审批工作流模块（flow_module）存量库兜底：
        // 与迁移 m20260923_000002_flow_module 等价（启动不跑 Migrator::up）——
        // 三表 + 索引 + 菜单 3600 段 + 字典 70 段 + site 渠道与 flow_* 模板种子，全部幂等。
        // 缺此兜底时，存量库直接启动服务后审批 API 全部 500（表不存在）。
        ensure_flow_module(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化审批工作流模块失败: {}", e))?;

        // 3.5c v5-D12 Group + 多部门任职存量库兜底：
        // 与迁移 m20260924_000008_scim_groups / m20260924_000009_user_dept 等价
        // （启动不跑 Migrator::up）——SCIM Group 三表 + sys_user_dept 兼职表 +
        // sys_user_role.source 列 + 菜单 148/3620-3622，全部幂等。
        // 缺此兜底时（优先级最高的一项）：存量库 sys_user_role 实体 SELECT 带
        // source 列 → 登录后权限加载全站 500；用户编辑查 sys_user_dept → 500；
        // SCIM Group API → 500。
        ensure_scim_group_module(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SCIM Group 模块失败: {}", e))?;

        // 3.5d 多租户 Phase 2 存量库兜底：
        // 与迁移 m20260925_000001_multitenant_phase2 / m20260925_000002_tenant_module 等价
        // （启动不跑 Migrator::up）——27 张业务表幂等补 tenant_id 列 + tid 索引 +
        // 菜单 3700-3704 段登记。缺此兜底时（优先级最高的一项）：实体 SELECT 带
        // tenant_id → config/dict/job/task 等管理接口全站 500；调度器加载 sys_job 失败；
        // 租户管理页面无菜单入口。
        ensure_multitenant_module(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化多租户 Phase 2 模块失败: {}", e))?;

        // 3.5d-2 租户自助域名页面菜单（批次 1c）：与迁移
        // m20260926_000011_tenant_domain_self_service_menu 等价（启动不跑 Migrator::up）。
        // 缺此兜底时存量库无 3900 页面菜单 ⇒ 能力位开启后租户侧仍无入口（假功能）。
        ensure_domain_self_service_menu(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化租户自助域名菜单失败: {}", e))?;

        // 3.5d-3 备份权限粒度化菜单（批次 2）：与迁移
        // m20260926_000012_backup_permission_granularity 等价（启动不跑 Migrator::up）。
        // 缺此兜底时存量库无 3625/3626 按钮 ⇒ 能力位开启后"只读下载/数据包导出"无可授予
        // 的菜单载体，授权链断裂。
        ensure_backup_permission_menus(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化备份权限粒度化菜单失败: {}", e))?;

        // 3.5d-4 前端错误日志 device_type 列兜底（FCP-011）：与迁移
        // m20260928_000002_frontend_error_device_type 等价（启动不跑 Migrator::up）。
        // 缺此兜底时存量库实体 SELECT 带 device_type ⇒ /monitor/frontendError
        // 列表/上报全站 500。
        ensure_frontend_error_device_type(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化前端错误 device_type 列失败: {}", e))?;

        // 3.5d-5 数据看板菜单去重兜底：与迁移 m20260928_000003_dedupe_dashboard_menu
        // 等价（启动不跑 Migrator::up）。m20260801_000002 查重条件漏顶级 132 导致
        // 存量库出现两条「数据看板」菜单（132 顶级 + 系统管理下动态 id），菜单树
        // 渲染两个入口。此处幂等删除 parent_id=1 的重复行（保留顶级 132）。
        ensure_dashboard_menu_dedupe(&db)
            .await
            .map_err(|e| anyhow::anyhow!("数据看板菜单去重失败: {}", e))?;

        // 3.5d-6' 菜单-only 迁移兜底：135/3410/3550/3551 四行菜单（与迁移
        //      m20260818_000001 / m20260819_000002 / m20260819_000006 等价）。
        //      必须先于下方菜单结构优化兜底执行（后者只 UPDATE 既有行）。
        ensure_menu_only_migration_menus(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化菜单-only 迁移兜底失败: {}", e))?;

        // 3.5d-6 菜单信息架构优化兜底：与迁移 m20260928_000004_optimize_menu_structure
        // 等价（启动不跑 Migrator::up）——3950「租户服务」目录 + 自助页收编 +
        // order 重排（消除重复 order）+ icon 语义修正，全部幂等。
        ensure_menu_structure_optimize(&db)
            .await
            .map_err(|e| anyhow::anyhow!("菜单结构优化失败: {}", e))?;

        // 3.5d-8 AI 助手菜单（NL2SQL v4.1，menu_id 4100 顶级 C 菜单）：幂等登记。
        // 不授予 role 2（AI 为管理员按需授权：角色管理勾选 ai:chat）；超管 *:*:* 天然可用。
        // 缺此兜底时：能力位 + [ai].enabled 开启后管理员仍无侧边栏入口（假功能）。
        ensure_ai_menu(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 AI 助手菜单失败: {}", e))?;

        // 3.5d-4 租户自建导航 L3 页面菜单（批次 3）：与迁移
        // m20260926_000014_tenant_nav_menu 等价（启动不跑 Migrator::up）。
        // 缺此兜底时存量库无 3627 页面菜单 ⇒ 能力位开启后租户侧仍无入口（假功能）。
        ensure_tenant_nav_menu(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化租户自建导航菜单失败: {}", e))?;

        // 3.5e 多租户 Phase 3 存量库兜底：与迁移 m20260925_000003_tenant_phase3 等价
        // （启动不跑 Migrator::up）——5 张租户表族（sys_tenant / package / domain /
        // menu / migration_map）+ 默认套餐种子 + **tid remap（唯一不可逆点，§29.7）**。
        // 缺此兜底时：租户管理服务查 sys_tenant → 500；旧模型"dept 根部门 = 租户"
        // 的存量数据不会换源到独立 tenant_id 空间。
        ensure_tenant_phase3(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化多租户 Phase 3 模块失败: {}", e))?;

        // 3.5f 多租户 Phase 3 SaaS 治理存量库兜底：与迁移
        // m20260925_000004_tenant_saas_governance 等价（启动不跑 Migrator::up）——
        // sys_config 治理列（scope/tenant_editable/visible_to_tenant）+
        // sys_oper_log.target_tenant_id + 唯一域租户化 4 项 + config 治理元数据 seed。
        // 缺此兜底时：sys_config 实体 SELECT 带治理列 → 参数配置全站 500；
        // 旧单列唯一索引仍生效 → 租户无法自建同 key 覆盖行。
        ensure_tenant_saas_governance(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化多租户 Phase 3 SaaS 治理模块失败: {}", e))?;

        // 3.5f' 治理参数项缺行补齐（批次十四）：CONFIGS 注册表驱动 INSERT OR IGNORE——
        // 根治"G-11 八键从未 seed、UploadConfigService 纯 UPDATE 写入静默失效"
        // （详见 governance::CONFIG_DEFAULTS 头注）。幂等：行在零影响。
        ensure_governance_config_rows(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化治理参数项缺行补齐失败: {}", e))?;

        // 3.5g 多租户 Phase 3.5g 存量库兜底：与迁移
        // m20260925_000005_tenant_unique_scope 等价（启动不跑 Migrator::up）——
        // 剩余唯一域租户化 2 项（sys_flow_task 业务唯一、sys_scim_group.external_id）。
        // 缺此兜底时：不同租户使用相同业务键 / externalId 会互相顶撞（第二个租户写入失败）。
        ensure_tenant_unique_scope(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化多租户 Phase 3.5g 唯一域租户化模块失败: {}", e))?;

        // 3.5h 原为"租户角色菜单治理（一剔一补）"，**已下移到全部菜单兜底之后**
        // （见 4.5j 之后）——收回必须晚于发放，否则被兜底洗回。理由与实证写在彼处。
        //
        // 3.5i 存量库兜底：租户文件隔离前的**扁平**上传路径回填（幂等）——
        // 隔离前 `sys_user.avatar` 形如 `/uploads/avatar/{key}`（缺 {tid} 段），
        // 隔离后 `GET /uploads/*` 按 `{tid}/{kind}/{key}` 三段校验 → 段数不足直接 400，
        // 全站头像破图。此处改写为 `/{prefix}/{tid}/{key}` 并把遗留文件搬到租户目录。
        ensure_legacy_upload_paths(&db, &settings.upload)
            .await
            .map_err(|e| anyhow::anyhow!("初始化存量上传路径回填失败: {}", e))?;

        // 3.5j 台账 P0-2 存量库兜底：sys_role.is_system 列 + 平台 admin 角色标记。
        // 缺此兜底时：实体 SELECT 带 is_system 列 → 角色/菜单/权限链路全站 500；
        // 超管判定退化为"无一行满足" → 平台管理员失去全部菜单与权限。
        ensure_role_is_system_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_role.is_system 兜底失败: {}", e))?;

        // 3.5j-b 台账：sys_role.custom_sql 列（存量库兜底，等价迁移 m20260819_000005）。
        // 缺此兜底时：实体 SELECT 带 custom_sql → 角色列表/编辑/数据权限解析全站 500。
        ensure_role_custom_sql_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_role.custom_sql 兜底失败: {}", e))?;

        // 3.5k 台账 F-8 存量库兜底：sys_logininfor.user_id 列 + 索引 + 存量回填。
        // 缺此兜底时：实体 SELECT 带 user_id 列 → 登录日志列表查询 500。
        ensure_logininfor_user_id_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_logininfor.user_id 兜底失败: {}", e))?;

        // 3.5.5 台账（第八批）：代码生成列元数据的 Java 遗留命名 → Rust 命名
        //       （`gen_table_column.java_type/java_field` → `rust_type/rust_field`）。
        //       与迁移 m20260926_000009 等价（启动不跑 Migrator::up 的存量库兜底）；
        //       实体已用新列名，缺此兜底则 gen 列表/预览/导入全链 500（no such column）。
        ensure_gen_column_rust_naming(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 gen_table_column Rust 列名兜底失败: {}", e))?;

        // 3.5.6 台账（能力位批次 0）：`sys_tenant_package.features` 列（租户套餐能力位 JSON）。
        //        与迁移 m20260926_000010 等价（启动不跑 Migrator::up 的存量库兜底）；
        //        实体已带 features 字段，缺此兜底则套餐列表/详情/新建/编辑全链 500。
        ensure_tenant_package_features(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_tenant_package.features 兜底失败: {}", e))?;

        // 3.5.7 能力位 auth.webauthn：WebAuthn / Passkey 凭据表（存量库兜底，等价迁移
        //       m20260927_000002）。缺此兜底时：实体已声明该表，任何凭据查询/写入都会
        //       500（no such table），能力位开启后自助绑定与 passkey 登录全链不可用。
        ensure_sys_user_credential_table(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 sys_user_credential 表失败: {}", e))?;

        // 3.6 v4 加固：幂等确保 SSO 表新列（update_by/del_flag/consented_at/client_name_snapshot）
        // 与存量数据回填（同意时刻/客户端名快照/grant_types 修正/明文 id_token_secret 加密）。
        // 与迁移 m20260923_000001_sso_v4_hardening 等价（启动不跑 Migrator::up 的存量库兜底）。
        ensure_sso_v4_columns(&db, &settings.config_enc_key)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SSO v4 列失败: {}", e))?;

        // 3.7 v4 §1.3：SSO 启动自检（issuer https、client_id 与平台 JWT 命名空间碰撞告警）。
        // 仅告警不阻断（存量部署允许先启动后整改），新客户端已由 add_client 硬校验拦截。
        sso_startup_self_check(&db, &settings).await;

        // 3.8 台账 MT-4 / E-2（第十批）：域名链路「静默失效」启动自检。
        // 仅告警不阻断（同 3.7 口径）。
        let _ = tenant_host_chain_self_check(&db, &settings.server.trusted_proxies).await;

        // 3.9 共享态存储持久层兜底（存量库不跑 Migrator::up，迁移 m20261001_000001_shared_store
        //      由 migration 负责全新库）：三表幂等建表 + sys_user.password_version 列兜底。
        //      ⚠️ 必须先于步骤 4 的 store 构造——Redis 档的 bootstrap_from_db / R1 投影键
        //      重建都要读这些表/列（顺序颠倒会使存量库首次升级时回填静默失败）。
        ensure_shared_store_tables(&db).await?;
        ensure_user_password_version_column(&db).await?;
        // B4 强制首登改密兜底：must_change_pwd 列 + admin 标记 + 强改开关 config 种子
        ensure_user_must_change_pwd_column(&db).await?;
        // 批八十四 项 A：口令有效期事实列 + 两个热键种子（默认全关闭态 = 现状零变化）。
        // 排在 must_change_pwd 之后：同一张表、同一族能力，种子体由迁移侧单一事实源给出。
        ensure_user_pwd_expire_policy(&db).await?;

        // 3.10 批次十九链感知保留兜底：sys_log_archive_anchor 表 + F 按钮 9180/9181 种子
        //      （单一事实源 = 迁移 init_log_archive_anchor；存量库启动不跑 Migrator）
        migration::migrations::m20261008_000001_log_archive_anchor::init_log_archive_anchor(&db)
            .await?;
        tracing::info!("链感知保留：sys_log_archive_anchor 表与审计归档按钮已就绪（幂等兜底）");

        // 4. 初始化共享态存储（[cache].mode：auto 按 [redis].url 裁决；local 纯 SQL；redis 现状）
        let cache_mode = settings.cache.resolve_mode(&settings.redis.url);
        // 非法 mode 取值（resolve_mode 已回落 auto 裁决）在此 WARN——拒绝"配错静默生效"
        let mode_raw = settings.cache.mode.trim().to_ascii_lowercase();
        if !["", "auto", "local", "redis"].contains(&mode_raw.as_str()) {
            tracing::warn!(
                value = %settings.cache.mode,
                fallback = "auto",
                allowed = ?["auto", "local", "redis"],
                "配置 [cache].mode 取值非法，已回落 auto（按 [redis].url 裁决）"
            );
        }
        // Redis 档保留一条原生连接仅供 rate_limit 的 Lua 令牌桶使用（与 local 档互斥，None = fail-closed）
        let mut redis_conn: Option<redis::aio::ConnectionManager> = None;
        // 批三十八：命令超时配置化——启动期一次性注入（默认 3 = R8-CONC-013 原常量）。
        // 注入必须在 match 之前：auth 闸门超时包装器在 local 档同样生效（LocalStore 的
        // auth_gate_check 也被同一 timeout 包裹，批三十八实证 local 档超时源自 SQLite 负载尖峰）。
        db::redis::set_redis_cmd_timeout_secs(settings.redis.cmd_timeout_secs);
        let store: Arc<dyn SharedStore> = match cache_mode {
            CacheMode::Redis => {
                let conn = db::init_redis(&settings.redis).await?;
                let rs = crate::shared_store::RedisStore::new(conn.clone(), db.clone());
                redis_conn = Some(conn);
                // 启动期幂等回填：DB 吊销权威层（sys_token_revocation）→ Redis（档位切换无缝）
                rs.bootstrap_from_db(&db).await;
                // R1 启动兜底：全量重建租户运行时投影键（消除「键缺失 = Active」窗口）；
                // local 档直接查库求值，无需重建
                let rs_arc: Arc<dyn crate::shared_store::SharedStore> = Arc::new(rs);
                let tenant_svc = crate::service::SysTenantService::new(db.clone(), rs_arc.clone());
                tenant_svc.rebuild_all_runtime_keys().await;
                rs_arc
            }
            CacheMode::Local => {
                tracing::info!("共享态档位：local（业务同库承载，无 Redis 依赖）");
                Arc::new(crate::shared_store::LocalStore::new(db.clone()))
            }
            CacheMode::Auto => unreachable!("resolve_mode 已裁决"),
        };
        match cache_mode {
            CacheMode::Redis => tracing::info!("共享态档位：redis（安全态双写 DB 权威层）"),
            CacheMode::Local => {}
            CacheMode::Auto => unreachable!(),
        }

        // 4.0a §4.2 分级守卫：local 档 + 多实例 / 显式 local + Redis 配置被忽略 的启动告警
        init_cache_mode_guards(&db, &settings, cache_mode);

        // 4.1 v4 §13-F1：历史 JWT 型 SSO 访问令牌一次性转写吊销（幂等，详见函数注释）
        revoke_legacy_sso_at_tokens(&store).await;

        // 4.2 v5-S1：SSO/OIDC 公开端点限流分档（存量库兜底，幂等；与迁移
        //     m20260924_000001_sso_rate_limit_tiers 等价——启动不跑 Migrator::up）
        ensure_sso_rate_limit_tiers(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SSO 限流分档失败: {}", e))?;

        // 4.2a b72（AGENTS C.10）：敏感操作独立限流档位（改密/TOTP/WebAuthn/PAT AK 轮换/
        //      secret 轮换/会话吊销/备份恢复/匿名化/批量导入等）。此前这些写操作只有
        //      全局 `*`（100 突发 / 10·s⁻¹）兜底——那是"别打爆服务"的量级，不是
        //      "别把凭据爆破成功"的量级。幂等：只补缺失 route_pattern，不覆盖管理员调过的值。
        ensure_sensitive_rate_limit_tiers(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化敏感操作限流分档失败: {}", e))?;

        // 4.2b §5.17 启动期能力位授权收敛（幂等；**失败不阻断启动**）：
        //      平台层 `[features]` on→off（改配置重启）后，存量"曾经可授予"的角色菜单
        //      授权**无回收触发点**（收敛只在套餐变更时跑）——此处按有效能力集
        //      （平台天花板 ∩ 套餐）对全部绑定套餐的租户全量兜底回收，消除
        //      "菜单可见但请求 403"假入口的数据层残留（展示层由 getRouters
        //      `prune_capability_gated_menus` 兜底）。
        converge_tenant_grants_on_startup(&db, &store).await;

        // 4.2c b73：收敛「卡在 running」的备份日志（幂等；**失败不阻断启动**）。
        //      create_backup 先插 running 占位行、子进程结束后写终态；进程在子进程运行期间
        //      被杀（发布重启 / OOM）⇒ 该行永久停在 running，备份页显示一个"永远在跑"的备份，
        //      运维无从判断结局（dev 库实测 3 条，最早一条已挂 6 天）。阈值远大于子进程
        //      超时（2×300s+60s），故不会误判本进程的合法在途任务；只改状态不删行，保留可追溯。
        if let Err(e) = crate::service::SysBackupService::new(db.clone(), settings.clone())
            .reconcile_interrupted_backups()
            .await
        {
            tracing::warn!("启动期收敛中断备份日志失败（不阻断启动，下次启动重试）: {e}");
        }

        // 4.3 v5-E6：运行期敏感凭据存量明文回填（幂等；CONFIG_ENC_KEY 未配置时跳过，
        //     与 id_token_secret 迁移期 fail-open 策略一致）
        ensure_runtime_secrets_encrypted(&db, &settings.config_enc_key).await;

        // G-14：注入 EncryptedString 列类型的运行时密钥（加密通用层密钥源；
        // 首写优先，重复初始化 no-op）
        crate::utils::crypto::set_runtime_master_key(settings.config_enc_key.clone());
        // 轮换过渡期旧密钥的注入点在 1.05（必须早于任何解密调用），这里不再重复以免误读
        // "首写优先"的实际生效值。

        // 4.4 v5-E1：consent 组合唯一索引（存量库兜底：清软删行/去重/建索引，
        //     与迁移 m20260924_000002_sso_consent_unique 等价）
        ensure_sso_consent_unique(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SSO consent 唯一索引失败: {}", e))?;

        // 4.5 v5-D2：为存量 RS256 客户端补生成 RSA 私钥（rsa_private_key IS NULL 的行，
        //     PKCS#8 PEM 信封加密落库；CONFIG_ENC_KEY 未配置时明文，迁移期策略）
        ensure_sso_rs256_keys(&db, &settings.config_enc_key)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SSO RSA 密钥失败: {}", e))?;

        // 4.5b 台账 D9：sys_oauth_client.key_id 密钥版本列（存量库兜底，等价迁移
        //     m20260926_000004）。历史密钥留 NULL = 未登记版本，仅作轮换预备，不做轮换实现。
        ensure_oauth_client_key_id_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SSO key_id 列失败: {}", e))?;

        // 4.5c SSO D9：sys_oauth_client.previous_client_secret_hash 双密钥读取期列
        //      （存量库兜底，等价迁移 m20260927_000001）。存量行留 NULL = 无过渡期 = 行为不变。
        ensure_oauth_client_prev_secret_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 SSO 旧密钥列失败: {}", e))?;

        // 4.5c-b G-09：sys_job_log.duration_ms 独立耗时列（存量库兜底，等价迁移
        //      m20261007_000001）。存量行留 NULL = 无耗时数据 = 报表聚合跳过。
        ensure_job_log_duration_column(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 job 日志耗时列失败: {}", e))?;

        // 4.5c-c G-16：平台默认消息模板 seed（notice_email / report_push，幂等）。
        //      公告邮件与报表订阅站内信自此走 sys_msg_template 存储（管理页可改），
        //      模板缺失时代码回落内置默认（行为兜底，不是功能缺失）。
        ensure_msg_template_seeds(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化消息模板 seed 失败: {}", e))?;

        // 4.5c-d G-11：OSS 存储配置管理页菜单（存量库兜底，等价迁移
        //      m20261007_000002；幂等，menu_id 已存在即跳过）
        ensure_upload_config_menu(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 OSS 配置菜单失败: {}", e))?;

        // 4.5c-e G-01/G-02：flow_definition 表 + report_dataset/report_dashboard 两表
        //      + 流程/报表菜单权限承载（存量库兜底，等价迁移 m20261007_000003/000004/000005；
        //      幂等：表 EXISTS 跳过 / menu_id 已存在校验内容后跳过）
        ensure_flow_definition_table(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化流程定义表失败: {}", e))?;
        ensure_report_tables(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化报表数据集/大屏表失败: {}", e))?;
        ensure_flow_report_menus(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化流程/报表菜单失败: {}", e))?;
        // 4.5c-e G-01 M2：报表前端上线翻转菜单可见性（4146/4148，存量库兜底，
        //      等价迁移 m20261007_000008；幂等）
        ensure_report_menus_visible(&db)
            .await
            .map_err(|e| anyhow::anyhow!("翻转报表菜单可见性失败: {}", e))?;
        // 4.5c-g 批次三十一：「AI 问数历史」菜单脱离父级 C 页面（存量库兜底，
        //      等价迁移 m20261010_000001；幂等）——修复子页面永不渲染（显示父级大屏）
        ensure_ai_history_menu_parent(&db)
            .await
            .map_err(|e| anyhow::anyhow!("修复 AI 问数历史菜单父级失败: {}", e))?;
        // 4.5c-h 批五十六：归档按钮菜单补种（4180/4181，存量库兜底，
        //      等价迁移 m20261012_000001；幂等）——批次十九手工创建未登记种子的修复
        ensure_archive_menus(&db)
            .await
            .map_err(|e| anyhow::anyhow!("补种归档按钮菜单失败: {}", e))?;
        // 4.5c-i 批八十六：sideTheme 数据缺省/说明归一（历史字面量守卫；幂等，等价迁移 m20261022_000002）
        ensure_side_theme_defaults(&db)
            .await
            .map_err(|e| anyhow::anyhow!("归一侧边栏主题缺省失败: {}", e))?;
        // 4.5c-i' 批八十六：退役参数键死行清理（等价迁移 m20261022_000002；
        //      与 service 写入闸门配对，第一次启动后每轮影响 0 行——理由见函数文档）
        ensure_dead_config_keys_retired(&db)
            .await
            .map_err(|e| anyhow::anyhow!("清理退役参数键失败: {}", e))?;
        // 4.5c-j 批六十：菜单 4122（规则删除）终态收敛（等价迁移 m20261006_000002 种子；
        //      修复迁移登记前手工创建的畸形挂载——挂 4121 字段权限保存下）
        ensure_data_rule_menu_alignment(&db)
            .await
            .map_err(|e| anyhow::anyhow!("收敛数据权限规则菜单失败: {}", e))?;
        // 4.5c-f G-02 M3：流程定义设计器上线翻转菜单可见性（4140，存量库兜底，
        //      等价迁移 m20261007_000009；幂等）
        ensure_flow_designer_menu_visible(&db)
            .await
            .map_err(|e| anyhow::anyhow!("翻转流程设计器菜单可见性失败: {}", e))?;
        // 4.5c-k 批六十四：菜单软删标记归一（del_flag '1' → '2'，存量库兜底，
        //      等价迁移 m20261013_000001；幂等 UPDATE）
        ensure_menu_del_flag_normalized(&db)
            .await
            .map_err(|e| anyhow::anyhow!("归一菜单软删标记失败: {}", e))?;
        // 4.5c-f G-02 M2：sys_flow_task 动作矩阵扩展列（weight/threshold/delegate_from，
        //      存量库兜底，等价迁移 m20261007_000006；has_column 守卫幂等）
        ensure_flow_task_action_columns(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化审批任务扩展列失败: {}", e))?;
        // 4.5c-f' 批次十六：图驱动单据表（flow_graph_doc，存量库兜底，等价迁移
        //      m20261007_000012；逐列一致，IF NOT EXISTS 幂等）
        ensure_flow_graph_doc_table(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化图驱动单据表失败: {}", e))?;
        // 4.5c-g G-07 扩展：短信云运营商支撑列（sys_msg_template.sms_template_code /
        //      sys_msg_send_log.sms_params，存量库兜底，等价迁移 m20261007_000007；幂等）
        ensure_sms_cloud_columns(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化短信云运营商支撑列失败: {}", e))?;

        // 4.5d E2-a：性能索引兜底（存量库不跑 Migrator::up，等价迁移
        //      m20261002_000001_perf_indexes）：flow_demo_doc.tenant_id 与
        //      sys_web_hook_log 的 status/event_type 索引（三库方言感知幂等）。
        ensure_perf_indexes(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化性能索引兜底失败: {}", e))?;

        // 4.5e 审计合规域兜底（存量库不跑 Migrator::up，等价迁移
        //      m20261003_000001_audit_change）：sys_audit_change 建表 + 三索引 +
        //      sys_oper_log.chain_hash 列 + 菜单种子 4000-4002（幂等）。
        ensure_audit_change_tables(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化审计合规域兜底失败: {}", e))?;

        // 4.5f 开放域 Webhook 兜底（等价迁移 m20261003_000002_webhook_event）：
        //      sys_webhook_event 建表 + 16 个种子事件 + subscribed_events/source/
        //      access_key/secret_key 列 + uk_sys_pat_access_key + 菜单按钮 3562/3563。
        ensure_webhook_event_tables(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 Webhook 事件域兜底失败: {}", e))?;

        // 4.5g 告警规则兜底（等价迁移 m20261003_000003_alert_rule）：
        //      sys_alert_rule 建表 + enabled 索引 + 告警菜单种子 4110-4114。
        ensure_alert_rule_tables(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化告警规则兜底失败: {}", e))?;

        // 4.5h Webhook 订阅双轨收敛兜底（等价迁移 m20261003_000004_webhook_unify）：
        //      存量 event_types（逗号口径）幂等转换为 subscribed_events（JSON 数组）。
        ensure_webhook_subscription_unify(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化 Webhook 订阅收敛兜底失败: {}", e))?;

        // 4.5i 字段级权限 M2 兜底（等价迁移 m20261003_000005_role_field_perm）：
        //      sys_role_field_perm 建表 + 角色索引 + 菜单按钮 4120/4121 +
        //      sys_config 平台开关种子（默认 false = 关闭态零行为变化）。
        ensure_role_field_perm_tables(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化字段级权限 M2 兜底失败: {}", e))?;

        // 4.5j 报表看板兜底（等价迁移 m20261003_000006_report_board）：
        //      sys_report_board 建表 + 属主索引 + 菜单种子 4130/4131。
        ensure_report_board_tables(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化报表看板兜底失败: {}", e))?;

        // 4.5z 多租户 Phase 3.5h 存量库兜底：租户角色菜单治理（一剔一补）。
        // 剔除平台专属菜单（域名管理 / 代码生成 / 缓存监控 / 备份 / 告警规则 …）；
        // 补齐 config/dict 的 add/edit/remove 自助按钮。
        // 缺此兜底时：存量租户自建字典 / config 覆盖与自建键 403（链路断裂），
        // 且租户侧残留"菜单可见但请求 403"的假入口（仅补缺失授权、幂等）。
        //
        // **为什么必须位于全部 `ensure_*` 菜单兜底之后（批七十四 B3 结构修复）**：
        // 本步 ① 是**收回**（`DELETE … role_id = 2 OR tenant_id <> 0`），而
        // `ensure_alert_rule_tables`（发 `(2, 4110)`）、`ensure_archive_menus`、
        // `ensure_role_field_perm_tables`、`ensure_report_board_tables` 等在其**原位置之后**
        // 发放 `sys_role_menu`。留在原序（3.5h）即"先删后补"⇒ 平台专属菜单每次启动
        // 都被兜底洗回 role 2（role 2 是新建租户管理员的菜单模板源），注册表形同虚设。
        // 实证：登记 `monitor:alert:` 后按原序跑完整 initialize，4110 仍在 role 2。
        // 收回类治理必须拥有**最终决定权**——这是顺序不变式，由
        // `initialize::tests::governance_runs_after_all_menu_granting_fallbacks` 钉住。
        ensure_tenant_role_menu_governance(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化多租户 Phase 3.5h 租户角色菜单治理失败: {}", e))?;

        // 5. 提前创建 IP 归属地查询器和 IP 库管理 Service
        // 原因：scheduler 需要在闭包内调用 IpLocationService::update_now，
        // 而 IpLocator 又需要被 AppState 共享，故提前创建后同时注入 scheduler 和 AppState
        // 双库模式：若 xdb_enabled=true 且 xdb 文件存在，加载 xdb（国内 IP 优先查 xdb）
        let ip_locator = Arc::new(IpLocator::new_with_xdb(
            &settings.ip_location.mmdb_path,
            &settings.ip_location.xdb_path,
            settings.ip_location.xdb_enabled,
        ));
        let ip_location_service =
            IpLocationService::new(db.clone(), settings.clone(), ip_locator.clone());

        // 6. 创建调度器并加载任务（注入 ip_location_service 以支持 mmdb_auto_update 内置任务）
        tracing::info!("=== 初始化定时任务调度器 ===");
        let job_scheduler = Arc::new(
            JobScheduler::new(
                db.clone(),
                store.clone(),
                ip_location_service.clone(),
                settings.clone(),
            )
            .await?,
        );
        // 创建临时 Service 用于 load_from_db（需要 Repository）
        let temp_job_service =
            crate::service::SysJobService::new(db.clone(), job_scheduler.clone());
        if let Err(e) = job_scheduler
            .load_from_db(temp_job_service.job_repo())
            .await
        {
            tracing::warn!("定时任务加载失败（不阻断启动）: {}", e);
        }

        // 7. 构建文件存储后端（F1：local / s3，按 upload.backend 切换）
        let storage: Arc<dyn crate::storage::StorageBackend> =
            crate::storage::new_backend(&settings.upload)
                .map_err(|e| anyhow::anyhow!("存储后端初始化失败: {}", e.message))?;
        tracing::info!("存储后端已启用: {}", storage.kind());

        // 8. 构建 AppState（传入 scheduler + ip_locator + ip_location_service + storage）
        // 启动打印所需的监听地址（settings 的 Arc 即将移入 AppState，先取出）
        let (server_host, server_port) = (settings.server.host.clone(), settings.server.port);
        let state = Arc::new(AppState::new(
            db,
            store,
            redis_conn,
            settings,
            job_scheduler,
            ip_locator,
            ip_location_service,
            storage,
        ));

        tracing::info!("=== stepby-axum 初始化完成 ===");
        tracing::info!(
            "访问地址 http://{}:{} ｜ 默认账号 admin / admin123，请尽快登录后台修改密码",
            server_host,
            server_port
        );
        // G-11 第二档启动恢复：sys.upload.backend 持久化档位与出厂档不同时，
        // 重新装载热切换运行档（失败回落出厂档，不阻断启动）
        if let Some(hot) = state
            .upload_config_service
            .restore_backend_if_switched()
            .await
        {
            state.hot_storage.store(Some(std::sync::Arc::new(
                crate::state::HotStorageBackend::new(hot),
            )));
        }

        Ok(state)
    }
}

mod flow;
mod helpers;
mod ledger;
mod menu;
mod oauth_sso;
mod rate_limit;
// pub(crate)：shared_store::local_store 测试复用生产同源建表（ensure_shared_store_tables），
// 保证测试库 DDL 与启动兜底永不漂移（单一事实源）。
pub(crate) mod schema;
mod scim;
mod tenant;

#[cfg(test)]
mod tests;

pub(crate) use flow::*;
pub(crate) use helpers::*;
pub(crate) use ledger::*;
pub(crate) use menu::*;
pub(crate) use oauth_sso::*;
pub(crate) use rate_limit::*;
pub(crate) use schema::*;
pub(crate) use scim::*;
pub(crate) use tenant::*;
