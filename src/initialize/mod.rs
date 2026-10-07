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
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DbErr, Statement, TransactionTrait, Value,
};
use std::collections::HashMap;
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
        if !sso_has_column(&db, "sys_oauth_client", "sector_identifier_uri").await? {
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

        // 3.5g 多租户 Phase 3.5g 存量库兜底：与迁移
        // m20260925_000005_tenant_unique_scope 等价（启动不跑 Migrator::up）——
        // 剩余唯一域租户化 2 项（sys_flow_task 业务唯一、sys_scim_group.external_id）。
        // 缺此兜底时：不同租户使用相同业务键 / externalId 会互相顶撞（第二个租户写入失败）。
        ensure_tenant_unique_scope(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化多租户 Phase 3.5g 唯一域租户化模块失败: {}", e))?;

        // 3.5h 多租户 Phase 3.5h 存量库兜底：租户角色菜单治理（一剔一补）——
        // 剔除平台专属域名管理菜单；补齐 config/dict 的 add/edit/remove 自助按钮。
        // 缺此兜底时：存量租户自建字典 / config 覆盖与自建键 403（链路断裂），
        // 且租户侧残留"菜单可见但请求 403"的假入口（仅补缺失授权、幂等）。
        ensure_tenant_role_menu_governance(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化多租户 Phase 3.5h 租户角色菜单治理失败: {}", e))?;

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

        // 4.2b §5.17 启动期能力位授权收敛（幂等；**失败不阻断启动**）：
        //      平台层 `[features]` on→off（改配置重启）后，存量"曾经可授予"的角色菜单
        //      授权**无回收触发点**（收敛只在套餐变更时跑）——此处按有效能力集
        //      （平台天花板 ∩ 套餐）对全部绑定套餐的租户全量兜底回收，消除
        //      "菜单可见但请求 403"假入口的数据层残留（展示层由 getRouters
        //      `prune_capability_gated_menus` 兜底）。
        converge_tenant_grants_on_startup(&db, &store).await;

        // 4.3 v5-E6：运行期敏感凭据存量明文回填（幂等；CONFIG_ENC_KEY 未配置时跳过，
        //     与 id_token_secret 迁移期 fail-open 策略一致）
        ensure_runtime_secrets_encrypted(&db, &settings.config_enc_key).await;

        // G-14：注入 EncryptedString 列类型的运行时密钥（加密通用层密钥源；
        // 首写优先，重复初始化 no-op）
        crate::utils::crypto::set_runtime_master_key(settings.config_enc_key.clone());

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
        // 4.5c-f G-02 M2：sys_flow_task 动作矩阵扩展列（weight/threshold/delegate_from，
        //      存量库兜底，等价迁移 m20261007_000006；has_column 守卫幂等）
        ensure_flow_task_action_columns(&db)
            .await
            .map_err(|e| anyhow::anyhow!("初始化审批任务扩展列失败: {}", e))?;
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

/// §4.2 分级守卫：共享态档位与部署形态不匹配时的启动期告警（只告警不阻断）。
///
/// - local + `scheduler.replicas > 1`：SQLite 单写者（max_connections=1）高并发写会 busy 等待
///   ⇒ **WARN**；MySQL/PG 天然共享 ⇒ INFO（提示 WS 定向消息仍为单实例语义）。
/// - local + `scheduler.cluster_mode = "leader"`：整轮互斥走 `sys_shared_lock` CAS，语义成立 ⇒ INFO。
/// - 显式 `mode = "local"` 但 `[redis].url` 有效：Redis 配置被忽略 ⇒ **WARN**（防"配了不生效"误解）。
fn init_cache_mode_guards(db: &DatabaseConnection, settings: &Settings, mode: CacheMode) {
    if mode == CacheMode::Local {
        let replicas = settings.scheduler.replicas;
        let cluster_mode = settings.scheduler.cluster_mode.trim().to_ascii_lowercase();
        if replicas > 1 {
            match db.get_database_backend() {
                DatabaseBackend::Sqlite => tracing::warn!(
                    "local 档 + SQLite + 多实例：SQLite 为单写者（max_connections=1），\
                     高并发写将触发 busy 等待；建议切换 MySQL/PostgreSQL 或配置 [redis] 启用 redis 档"
                ),
                _ => tracing::info!(
                    "local 档（DB 共享）可支撑多实例；注意 WS 定向消息仅本实例可见（既有单实例语义）"
                ),
            }
        }
        if cluster_mode == "leader" {
            tracing::info!(
                "local 档 + scheduler.cluster_mode = leader：内置任务整轮互斥走 sys_shared_lock CAS，语义成立"
            );
        }
    }
    // 显式 local（原值小写比对，非法值/缺省不触发）但 Redis url 有效 ⇒ WARN
    if settings.cache.is_explicit_mode("local") {
        let url = &settings.redis.url;
        if !url.trim().is_empty() && !url.contains("CHANGE_ME") {
            tracing::warn!(
                "Redis 配置被忽略（cache.mode=local）；如需 redis 档请改 mode 为 auto/redis"
            );
        }
    }
}

/// 零配置/本地路径引导：`database.url` 为 `sqlite://` 时，解析出库文件父目录并幂等自建。
///
/// 统一覆盖两类场景：① from_env_only 的零配置默认（`sqlite://./data/stepby.db?mode=rwc`）；
/// ② 有 config.toml 但 SQLite 路径父目录尚未创建的存量/新部署。查询串（`?` 起）截除后取
/// parent；非 sqlite 前缀 / 无 parent / 建目录失败一律静默跳过（后续真实 IO 会报确切错误）。
fn ensure_sqlite_parent_dir(url: &str) {
    let Some(path) = url.strip_prefix("sqlite://") else {
        return;
    };
    let file_part = path.split('?').next().unwrap_or(path);
    let Some(parent) = std::path::Path::new(file_part).parent() else {
        return;
    };
    if let Err(e) = std::fs::create_dir_all(parent) {
        tracing::debug!("SQLite 父目录 {parent:?} 创建失败（不阻断，交由 init 报真实错误）: {e}");
    }
}

/// 共享态存储三表兜底（存量库不跑 Migrator::up，等价迁移 `m20261001_000001_shared_store`）。
///
/// 列定义与迁移**完全一致**（两处必须同步维护）：
/// - `sys_shared_kv`：S2 一次性/短期态（键值 + 可空过期时间戳 UTC 秒）；
/// - `sys_shared_lock`：调度锁（单语句 CAS）；
/// - `sys_token_revocation`：S1 吊销权威层（blacklist + 历史 SSO AT 阻断，source 区分）。
///
/// `CREATE TABLE IF NOT EXISTS` 三方言均合法；索引经 `ensure_tenant_index` 方言兜底
/// （MySQL 不支持 `IF NOT EXISTS` 子句，information_schema 判存在后建——与迁移
/// IndexDdlExt 容错思路一致）。全部幂等，重复执行无副作用。
async fn ensure_shared_store_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    // 主键为 VARCHAR：SQLite/MySQL 直接 PRIMARY KEY；PG VARCHAR PK 通用，无需自增列
    for ddl in [
        "CREATE TABLE IF NOT EXISTS sys_shared_kv (
            kv_key VARCHAR(255) NOT NULL PRIMARY KEY,
            kv_value TEXT NOT NULL,
            expire_at BIGINT NULL
        )",
        "CREATE TABLE IF NOT EXISTS sys_shared_lock (
            lock_key VARCHAR(255) NOT NULL PRIMARY KEY,
            lock_token VARCHAR(64) NOT NULL,
            expire_at BIGINT NOT NULL
        )",
        "CREATE TABLE IF NOT EXISTS sys_token_revocation (
            token_hash VARCHAR(128) NOT NULL PRIMARY KEY,
            expire_at BIGINT NOT NULL,
            source VARCHAR(32) NOT NULL DEFAULT 'logout'
        )",
    ] {
        db.execute_raw(Statement::from_string(backend, ddl.to_string()))
            .await?;
    }
    // 过期行 GC 扫描索引（与迁移同名；MySQL 方言差异由 ensure_tenant_index 收口）
    ensure_tenant_index(
        db,
        "sys_shared_kv",
        "idx_sys_shared_kv_expire_at",
        "expire_at",
        false,
    )
    .await?;
    ensure_tenant_index(
        db,
        "sys_token_revocation",
        "idx_sys_token_revocation_expire_at",
        "expire_at",
        false,
    )
    .await?;
    tracing::info!(
        "共享态存储三表已就绪（sys_shared_kv / sys_shared_lock / sys_token_revocation）"
    );

    // ===== AI 助手（AI-01/AI-02，§5.39）：ai_chat_history 表 + sys.ai.* 配置种子兜底 =====
    // 与 m20261006_000001 迁移同源（pub fn 单一事实源）；存量库启动不跑 Migrator 时由本段兜底。
    migration::migrations::m20261006_000001_ai_config_and_history::init_ai_config_and_history(db)
        .await?;
    tracing::info!(
        "AI 助手：ai_chat_history 表与 sys.ai.* 配置种子已就绪（幂等，管理页可改热生效）"
    );
    Ok(())
}

/// 幂等确保 `sys_user` 含 `password_version` 列（S1 密码版本号权威层；与
/// `ensure_user_tenant_id_column` 同范式：表存在检查 + 列存在检查 + ALTER 补列）。
/// `ALTER TABLE sys_user ADD COLUMN ... BIGINT NOT NULL DEFAULT 0` 三方言语法通用。
/// 缺此兜底时：存量库实体 SELECT 带 password_version ⇒ 登录/改密链路 500。
pub(crate) async fn ensure_user_password_version_column(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_user").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_user", "password_version").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_user ADD COLUMN password_version BIGINT NOT NULL DEFAULT 0".to_string(),
    ))
    .await?;
    tracing::info!("sys_user.password_version 列已补建（存量库兜底）");
    Ok(())
}

/// B4 强制首登改密兜底（等价迁移 `m20261004_000003_force_pwd_change`，幂等）：
/// 1. `sys_user.must_change_pwd CHAR(1) DEFAULT '0'`——列不存在时补建，**仅本次建列时**
///    回填 admin 标记（存量库重跑不误标已改密用户）；
/// 2. `sys_config` 强改开关种子 `sys.user.forceFirstLoginChangePwd='false'`
///    （幂等 INSERT，不 UPDATE——尊重管理员已改值）。
pub(crate) async fn ensure_user_must_change_pwd_column(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_user").await? {
        return Ok(());
    }
    let newly_added = !sso_has_column(db, "sys_user", "must_change_pwd").await?;
    if newly_added {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_user ADD COLUMN must_change_pwd CHAR(1) DEFAULT '0'".to_string(),
        ))
        .await?;
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "UPDATE sys_user SET must_change_pwd = '1' WHERE user_id = 1 AND must_change_pwd = '0'"
                .to_string(),
        ))
        .await?;
        tracing::info!("sys_user.must_change_pwd 列已补建并标记 admin（B4 存量库兜底）");
    }
    if sso_table_exists(db, "sys_config").await? {
        let now = flow_now(db);
        flow_insert(
            db,
            &format!(
                "sys_config (config_id, config_name, config_key, config_value, config_type, create_by, create_time, remark) VALUES \
                (9010, '用户首登强制改密开关', 'sys.user.forceFirstLoginChangePwd', 'false', 'Y', 'admin', {now}, '开启后初始密码/过期密码用户登录时被强制引导改密')"
            ),
        )
        .await?;
    }
    Ok(())
}

/// v5-N2 Phase 2（第一步）：幂等确保 `sys_user` 含 `tenant_id` 列（登录 JWT 的 tid
/// 数据源）。与 `ensure_user_country_code_column` 同源方案：表不存在跳过；列不存在
/// 则 `ALTER TABLE sys_user ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 0`。
async fn ensure_user_tenant_id_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_user").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_user", "tenant_id").await? {
        tracing::info!("sys_user.tenant_id 列已存在，无需 ALTER");
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_user ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 0".to_string(),
    ))
    .await?;
    tracing::info!("sys_user.tenant_id 列已补建（v5-N2 Phase 2 存量库兜底）");
    Ok(())
}

/// 幂等确保 `sys_user` 表含 `country_code` 列（方案 D，G18：手机号多地区化向后兼容）
///
/// 实体新增 `country_code` 字段后，存量 SQLite / Postgres / MySQL 数据库若无该列，
/// 查询会因缺列报错。启动初始化时按当前数据库方言检测列是否存在：
/// - 表不存在则跳过（由 migration 负责建表，下次启动再补列）
/// - 列不存在则执行 `ALTER TABLE sys_user ADD COLUMN country_code VARCHAR(8)`
async fn ensure_user_country_code_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // 1) 表是否存在（避免对尚未建表的空库误执行 ALTER）
    let table_exists = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='sys_user'",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_user' AND table_schema=current_schema()",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_user' AND table_schema=DATABASE()",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !table_exists {
        tracing::info!("sys_user 表尚未创建，跳过 country_code 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // 2) 列是否存在
    let has_column = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "PRAGMA table_info(sys_user)",
                ))
                .await?;
            rows.iter().any(|row| {
                row.try_get::<String>("", "name")
                    .map(|n| n.eq_ignore_ascii_case("country_code"))
                    .unwrap_or(false)
            })
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_user' AND column_name='country_code' AND table_schema=current_schema() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_user' AND column_name='country_code' AND table_schema=DATABASE() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !has_column {
        tracing::info!("sys_user 缺少 country_code 列，执行幂等 ALTER 添加");
        db.execute_raw(Statement::from_string(
            backend,
            "ALTER TABLE sys_user ADD COLUMN country_code VARCHAR(8)",
        ))
        .await?;
    } else {
        tracing::info!("sys_user.country_code 列已存在，无需 ALTER");
    }

    Ok(())
}

/// 幂等确保 `sys_task` 表含 `operator_id` 列（P0-2：taskProgress 定向推送目标 user_id）
///
/// 与 G18 `ensure_user_country_code_column` 同源方案：实体新增 `operator_id` 字段后，
/// 存量库若无该列，`/system/task/list` 等查询会因缺列报 500。启动初始化时按当前数据库方言
/// 检测列是否存在并幂等补列。m20260806_000002_add_task_operator_id 迁移负责全新库建表时带该列；
/// 此处兜底存量库（AppInitializer 启动不跑 Migrator::up，避免对已有种子数据重跑 seed 导致主键冲突）。
async fn ensure_task_operator_id_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // 1) 表是否存在（避免对尚未建表的空库误执行 ALTER）
    let table_exists = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='sys_task'",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_task' AND table_schema=current_schema()",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_task' AND table_schema=DATABASE()",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !table_exists {
        tracing::info!("sys_task 表尚未创建，跳过 operator_id 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // 2) 列是否存在
    let has_column = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "PRAGMA table_info(sys_task)",
                ))
                .await?;
            rows.iter().any(|row| {
                row.try_get::<String>("", "name")
                    .map(|n| n.eq_ignore_ascii_case("operator_id"))
                    .unwrap_or(false)
            })
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_task' AND column_name='operator_id' AND table_schema=current_schema() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_task' AND column_name='operator_id' AND table_schema=DATABASE() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !has_column {
        tracing::info!("sys_task 缺少 operator_id 列，执行幂等 ALTER 添加");
        db.execute_raw(Statement::from_string(
            backend,
            "ALTER TABLE sys_task ADD COLUMN operator_id BIGINT",
        ))
        .await?;
    } else {
        tracing::info!("sys_task.operator_id 列已存在，无需 ALTER");
    }

    Ok(())
}

/// 幂等确保 `sys_oper_log` 表含 `oper_diff` 列（Tier-S #2：字段级审计 diff）
///
/// 与 `ensure_task_operator_id_column` 同源方案：实体新增 `oper_diff` 字段后，存量库若无该列，
/// 操作日志的查询（SeaORM 显式列名 SELECT）与写入都会因缺列报错。m20260822_000001_oper_log_diff
/// 迁移负责全新库建表时带该列；此处兜底存量库（AppInitializer 启动不跑 Migrator::up）。
/// `ALTER TABLE ... ADD COLUMN oper_diff TEXT` 语法在 SQLite/MySQL/PostgreSQL 三方言下均合法。
async fn ensure_oper_log_diff_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // 1) 表是否存在（避免对尚未建表的空库误执行 ALTER）
    let table_exists = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='sys_oper_log'",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_oper_log' AND table_schema=current_schema()",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.tables WHERE table_name='sys_oper_log' AND table_schema=DATABASE()",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !table_exists {
        tracing::info!("sys_oper_log 表尚未创建，跳过 oper_diff 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // 2) 列是否存在
    let has_column = match backend {
        DatabaseBackend::Sqlite => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "PRAGMA table_info(sys_oper_log)",
                ))
                .await?;
            rows.iter().any(|row| {
                row.try_get::<String>("", "name")
                    .map(|n| n.eq_ignore_ascii_case("oper_diff"))
                    .unwrap_or(false)
            })
        }
        DatabaseBackend::Postgres => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_oper_log' AND column_name='oper_diff' AND table_schema=current_schema() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        DatabaseBackend::MySql => {
            let rows = db
                .query_all_raw(Statement::from_string(
                    backend,
                    "SELECT 1 FROM information_schema.columns WHERE table_name='sys_oper_log' AND column_name='oper_diff' AND table_schema=DATABASE() LIMIT 1",
                ))
                .await?;
            !rows.is_empty()
        }
        _ => unreachable!("unknown backend"),
    };

    if !has_column {
        tracing::info!("sys_oper_log 缺少 oper_diff 列，执行幂等 ALTER 添加");
        db.execute_raw(Statement::from_string(
            backend,
            "ALTER TABLE sys_oper_log ADD COLUMN oper_diff TEXT",
        ))
        .await?;
    } else {
        tracing::info!("sys_oper_log.oper_diff 列已存在，无需 ALTER");
    }

    Ok(())
}

// ==================== 审批工作流模块（flow_module）存量库兜底 ====================
// 与迁移 m20260923_000002_flow_module 等价：三表 + 索引 + 菜单/字典/渠道/模板种子。
// DDL 与种子 SQL 必须与迁移保持同步（双写惯例，参照 ensure_sys_pat_table）；
// 所有种子依赖主键/唯一键（menu_id/dict_code/channel_code/template_code UNIQUE）幂等，
// 每次启动重复执行不产生重复行。

/// 幂等执行一条 SQL（flow 双写内部用；错误向上传播由调用方统一 anyhow 包装）
async fn flow_exec(db: &DatabaseConnection, sql: impl Into<String>) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        sql.into(),
    ))
    .await
    .map(|_| ())
}

/// 三方言幂等 INSERT 前缀（对齐迁移 execute_idempotent_insert）
fn flow_insert_prefix(backend: DatabaseBackend) -> &'static str {
    match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        _ => "INSERT IGNORE INTO ",
    }
}

/// 三方言幂等 INSERT 后缀（仅 PostgreSQL 需要 ON CONFLICT）
fn flow_insert_suffix(backend: DatabaseBackend) -> &'static str {
    if backend == DatabaseBackend::Postgres {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    }
}

/// 幂等 INSERT（body 为 "表名 (列...) VALUES (...)" 形式，与迁移 execute_idempotent_insert 同构）
async fn flow_insert(db: &DatabaseConnection, body: &str) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let sql = format!(
        "{}{}{}",
        flow_insert_prefix(backend),
        body,
        flow_insert_suffix(backend)
    );
    flow_exec(db, sql).await
}

/// flow 种子用当前时间表达式（与迁移 now_expr 同构）
fn flow_now(db: &DatabaseConnection) -> String {
    if db.get_database_backend() == DatabaseBackend::Sqlite {
        format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
    } else {
        "NOW()".to_string()
    }
}

/// 幂等确保审批工作流三张表存在（三方言 DDL 与迁移逐字对齐）
async fn ensure_flow_tables(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let (id_task, id_log, id_doc) = match backend {
        DatabaseBackend::Sqlite => (
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "INTEGER PRIMARY KEY AUTOINCREMENT",
        ),
        DatabaseBackend::Postgres => (
            "BIGSERIAL PRIMARY KEY",
            "BIGSERIAL PRIMARY KEY",
            "BIGSERIAL PRIMARY KEY",
        ),
        _ => (
            "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        ),
    };
    let ts = match backend {
        DatabaseBackend::Postgres => "TIMESTAMP",
        _ => "DATETIME",
    };

    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_flow_task (\n\
             \x20 task_id        {id_task},\n\
             \x20 biz_type       VARCHAR(64) NOT NULL,\n\
             \x20 biz_id         BIGINT NOT NULL,\n\
             \x20 round_no       INTEGER NOT NULL DEFAULT 1,\n\
             \x20 node_seq       INTEGER NOT NULL,\n\
             \x20 node_name      VARCHAR(64),\n\
             \x20 assignee_id    BIGINT NOT NULL,\n\
             \x20 task_type      VARCHAR(16) NOT NULL DEFAULT 'single',\n\
             \x20 status         VARCHAR(16) NOT NULL DEFAULT 'pending',\n\
             \x20 title          VARCHAR(200),\n\
             \x20 applicant_id   BIGINT NOT NULL,\n\
             \x20 applicant_name VARCHAR(64),\n\
             \x20 comment        VARCHAR(500),\n\
             \x20 acted_at       {ts},\n\
             \x20 due_at         {ts},\n\
             \x20 last_reminded_at {ts},\n\
             \x20 tenant_id      BIGINT NOT NULL DEFAULT 0,\n\
             \x20 create_by      VARCHAR(64),\n\
             \x20 create_time    {ts},\n\
             \x20 update_by      VARCHAR(64),\n\
             \x20 update_time    {ts}\n\
             )"
        ),
    )
    .await?;

    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_flow_log (\n\
             \x20 log_id       {id_log},\n\
             \x20 biz_type     VARCHAR(64) NOT NULL,\n\
             \x20 biz_id       BIGINT NOT NULL,\n\
             \x20 round_no     INTEGER NOT NULL DEFAULT 1,\n\
             \x20 node_seq     INTEGER,\n\
             \x20 action       VARCHAR(24) NOT NULL,\n\
             \x20 from_status  VARCHAR(16),\n\
             \x20 to_status    VARCHAR(16),\n\
             \x20 operator_id  BIGINT,\n\
             \x20 to_user_id   BIGINT,\n\
             \x20 comment      VARCHAR(500),\n\
             \x20 acted_at     {ts},\n\
             \x20 tenant_id    BIGINT NOT NULL DEFAULT 0,\n\
             \x20 create_by    VARCHAR(64),\n\
             \x20 create_time  {ts},\n\
             \x20 update_by    VARCHAR(64),\n\
             \x20 update_time  {ts}\n\
             )"
        ),
    )
    .await?;

    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS flow_demo_doc (\n\
             \x20 doc_id           {id_doc},\n\
             \x20 title            VARCHAR(200) NOT NULL,\n\
             \x20 applicant_id     BIGINT NOT NULL,\n\
             \x20 applicant_name   VARCHAR(64),\n\
             \x20 dept_id          BIGINT,\n\
             \x20 leave_type       VARCHAR(16) NOT NULL DEFAULT 'annual',\n\
             \x20 days             INTEGER NOT NULL DEFAULT 1,\n\
             \x20 reason           VARCHAR(500),\n\
             \x20 flow_mode        VARCHAR(16) NOT NULL DEFAULT 'single',\n\
             \x20 status           VARCHAR(16) NOT NULL DEFAULT 'draft',\n\
             \x20 current_round    INTEGER NOT NULL DEFAULT 0,\n\
             \x20 current_node_seq INTEGER,\n\
             \x20 submitted_at     {ts},\n\
             \x20 finished_at      {ts},\n\
             \x20 tenant_id        BIGINT NOT NULL DEFAULT 0,\n\
             \x20 create_by        VARCHAR(64),\n\
             \x20 create_time      {ts},\n\
             \x20 update_by        VARCHAR(64),\n\
             \x20 update_time      {ts}\n\
             )"
        ),
    )
    .await
}

/// 幂等回填平台部门主管（`sys_dept.leader_user_id` → admin，审批链前置条件）
///
/// 作用域限定**平台部门（tenant_id = 0）**：租户部门的审批人应由租户自行指派，
/// 不可把平台 admin 注入为租户部门主管（跨租户越权审批风险）。
/// 返回受影响行数（0 = 已全部有主管，天然幂等）。列缺失时安全跳过。
pub(crate) async fn ensure_platform_dept_leaders(db: &DatabaseConnection) -> anyhow::Result<u64> {
    if !sso_has_column(db, "sys_dept", "leader_user_id").await? {
        return Ok(0);
    }
    let sql = if sso_has_column(db, "sys_dept", "tenant_id").await? {
        "UPDATE sys_dept SET leader_user_id = 1 WHERE leader_user_id IS NULL AND tenant_id = 0"
    } else {
        "UPDATE sys_dept SET leader_user_id = 1 WHERE leader_user_id IS NULL"
    };
    let res = db
        .execute_raw(Statement::from_string(
            db.get_database_backend(),
            sql.to_string(),
        ))
        .await?;
    if res.rows_affected() > 0 {
        tracing::info!(
            "平台部门主管回填完成（leader_user_id → 1，保证部门主管审批链可用）rows={}",
            res.rows_affected()
        );
    }
    Ok(res.rows_affected())
}

/// 幂等建 flow 索引（SQLite/PostgreSQL 支持 IF NOT EXISTS；MySQL 跳过交由迁移补齐，参照 ensure_sys_pat_table）
async fn ensure_flow_indexes(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    if backend == DatabaseBackend::MySql {
        tracing::debug!("flow 索引创建跳过（MySQL 无 IF NOT EXISTS，交由 migration）");
        return Ok(());
    }
    let indexes = [
        "CREATE UNIQUE INDEX IF NOT EXISTS uk_flow_task_biz ON sys_flow_task (biz_type, biz_id, round_no, node_seq, assignee_id)",
        "CREATE INDEX IF NOT EXISTS idx_flow_task_assignee ON sys_flow_task (assignee_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_flow_task_due ON sys_flow_task (status, due_at)",
        "CREATE INDEX IF NOT EXISTS idx_flow_log_biz ON sys_flow_log (biz_type, biz_id, round_no)",
        // W-12：已办视图（operator_id + acted_at）覆盖索引，避免全表扫描
        "CREATE INDEX IF NOT EXISTS idx_flow_log_operator ON sys_flow_log (operator_id, acted_at)",
        "CREATE INDEX IF NOT EXISTS idx_flow_doc_applicant ON flow_demo_doc (applicant_id, status)",
    ];
    for stmt in indexes {
        // 容错：个别存量库索引名冲突等异常不阻断启动（与 sys_pat 索引兜底同策略）
        if let Err(e) = flow_exec(db, stmt).await {
            tracing::debug!("flow 索引创建跳过（可能已存在）: {}", e);
        }
    }
    Ok(())
}

/// 幂等补种 flow 菜单（3600 段）/字典（70 段）/site 渠道/flow_* 模板
async fn ensure_flow_seeds(db: &DatabaseConnection) -> Result<(), DbErr> {
    // sys_menu 表存在性保护：全新空库未建系统表时跳过种子（交由 migration 初始种子负责），
    // 与 ensure_sys_pat_menu 同范式——否则空库启动会因种子 INSERT 失败而阻断（影响面回归修复）
    let sys_menu_exists = sso_table_exists(db, "sys_menu")
        .await
        .map_err(|e| DbErr::Custom(format!("flow 种子表存在性检查失败: {}", e)))?;
    if !sys_menu_exists {
        tracing::info!("flow 种子跳过（sys_menu 不存在，空库交由 migration 负责初始种子）");
        return Ok(());
    }
    let now = flow_now(db);

    // 菜单 3600/3601/3611 + role 2 授权（与迁移 4.1-4.3 同构；remark 亦对齐迁移）
    // 类型标注省略（11 元元组触发 clippy type_complexity，交给编译器推断）
    let menus = &[
        (
            3600,
            "审批中心",
            1,
            95,
            "flow",
            "ParentView",
            "M",
            "",
            "example",
            "审批工作流",
            "route.flow",
        ),
        (
            3601,
            "审批中心",
            3600,
            1,
            "todo",
            "system/flow/index",
            "C",
            "system:flow:list",
            "checkbox",
            "审批待办/我发起/全部单据",
            "route.flowTodo",
        ),
        (
            3611,
            "全部单据查询",
            3601,
            1,
            "",
            "",
            "F",
            "system:flow:list",
            "#",
            "",
            "",
        ),
    ];
    for (menu_id, name, parent, order, path, component, mtype, perms, icon, remark, i18n_key) in
        menus
    {
        // F 按钮（3611）无 i18n_key 列值，与其余 C/M 分支拼列
        if *mtype == "F" {
            flow_insert(
                db,
                &format!(
                    "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES \
                     ({menu_id}, '{name}', {parent}, {order}, '{path}', '{component}', '', '', '1', '0', '{mtype}', '0', '0', '{perms}', '{icon}', 'admin', {now}, '{remark}', '0')"
                ),
            )
            .await?;
        } else {
            flow_insert(
                db,
                &format!(
                    "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES \
                     ({menu_id}, '{name}', {parent}, {order}, '{path}', '{component}', '', '', '1', '0', '{mtype}', '0', '0', '{perms}', '{icon}', 'admin', {now}, '{remark}', '0', '{i18n_key}')"
                ),
            )
            .await?;
        }
        flow_insert(
            db,
            &format!("sys_role_menu (role_id, menu_id) VALUES (2, {menu_id})"),
        )
        .await?;
    }

    // 字典 70/71/72 段（与迁移 4.4-4.6 同构）
    let dict_types: &[(i64, &str, &str, &str)] = &[
        (70, "审批状态", "sys_flow_task_status", "审批任务与单据状态"),
        (71, "审批动作", "sys_flow_action", "审批流水动作"),
        (
            72,
            "请假类型",
            "sys_flow_leave_type",
            "示例审批单据-请假类型",
        ),
    ];
    for (dict_id, name, dtype, remark) in dict_types {
        flow_insert(
            db,
            &format!(
                "sys_dict_type (dict_id, dict_name, dict_type, status, create_by, create_time, remark, del_flag) VALUES \
                 ({dict_id}, '{name}', '{dtype}', '0', 'admin', {now}, '{remark}', '0')"
            ),
        )
        .await?;
    }
    let status_rows: &[(i64, &str, &str, &str, &str)] = &[
        (700, "待审批", "pending", "warning", "To Approve"),
        (701, "已通过", "approved", "success", "Approved"),
        (702, "已驳回", "rejected", "danger", "Rejected"),
        (703, "已取消", "cancelled", "info", "Cancelled"),
        (704, "已转办", "transferred", "info", "Transferred"),
        (705, "已撤回", "withdrawn", "info", "Withdrawn"),
        (706, "草稿", "draft", "info", "Draft"),
    ];
    for (code, label, value, css, label_en) in status_rows {
        flow_insert(
            db,
            &format!(
                "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                 ({code}, {code}, '{label}', '{value}', 'sys_flow_task_status', '', '{css}', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
            ),
        )
        .await?;
    }
    let action_rows: &[(i64, &str, &str, &str)] = &[
        (710, "提交", "submit", "To Submit"),
        (711, "同意", "approve", "Approve"),
        (712, "驳回", "reject", "Reject"),
        (713, "撤回", "withdraw", "Withdraw"),
        (714, "转办", "transfer", "Transfer"),
        (715, "超时提醒", "timeout_remind", "Timeout Remind"),
        (716, "自动通过", "auto_approve", "Auto Approve"),
    ];
    for (code, label, value, label_en) in action_rows {
        flow_insert(
            db,
            &format!(
                "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                 ({code}, {code}, '{label}', '{value}', 'sys_flow_action', '', 'info', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
            ),
        )
        .await?;
    }
    let leave_rows: &[(i64, &str, &str, &str)] = &[
        (720, "年假", "annual", "Annual Leave"),
        (721, "病假", "sick", "Sick Leave"),
        (722, "事假", "personal", "Personal Leave"),
    ];
    for (code, label, value, label_en) in leave_rows {
        flow_insert(
            db,
            &format!(
                "sys_dict_data (dict_code, dict_sort, dict_label, dict_value, dict_type, css_class, list_class, is_default, status, create_by, create_time, remark, del_flag, dict_label_en) VALUES \
                 ({code}, {code}, '{label}', '{value}', 'sys_flow_leave_type', '', 'primary', 'N', '0', 'admin', {now}, '', '0', '{label_en}')"
            ),
        )
        .await?;
    }

    // site 渠道 + flow_* 模板（与迁移 4.7/4.8 同构；channel_code/template_code UNIQUE 幂等）
    flow_insert(
        db,
        &format!(
            "sys_msg_channel (channel_name, channel_code, channel_type, config_json, status, remark, create_by, create_time, del_flag) VALUES \
             ('站内信', 'site', 'site', NULL, '0', '审批/系统站内提醒', 'admin', {now}, '0')"
        ),
    )
    .await?;
    let templates: &[(&str, &str, &str, &str)] = &[
        (
            "审批待办提醒",
            "flow_todo",
            "您有新的审批待办",
            "单据「{{{{title}}}}」等待您审批，请及时处理。",
        ),
        (
            "审批超时提醒",
            "flow_timeout",
            "审批待办已超时",
            "单据「{{{{title}}}}」已超过办理时限，请尽快处理。",
        ),
        (
            "审批驳回通知",
            "flow_reject",
            "您的单据已被驳回",
            "您提交的单据「{{{{title}}}}」已被驳回，请查看审批意见。",
        ),
    ];
    for (name, code, subject, content) in templates {
        flow_insert(
            db,
            &format!(
                "sys_msg_template (template_name, template_code, channel_code, template_subject, template_content, status, remark, create_by, create_time, del_flag) VALUES \
                 ('{name}', '{code}', 'site', '{subject}', '{content}', '0', '审批站内提醒', 'admin', {now}, '0')"
            ),
        )
        .await?;
    }
    Ok(())
}

/// 幂等确保审批工作流模块完整就绪（表 + 索引 + 种子；存量库向后兼容，与迁移等价）
async fn ensure_flow_module(db: &DatabaseConnection) -> anyhow::Result<()> {
    ensure_flow_tables(db)
        .await
        .map_err(|e| anyhow::anyhow!("flow 建表失败: {}", e))?;
    ensure_flow_indexes(db)
        .await
        .map_err(|e| anyhow::anyhow!("flow 索引创建失败: {}", e))?;
    // 存量库 leader_user_id 已由 AppInitializer 3.1.2 统一兜底（sys_dept 漂移修复），此处无需重复
    ensure_flow_seeds(db)
        .await
        .map_err(|e| anyhow::anyhow!("flow 种子补齐失败: {}", e))?;
    tracing::info!("审批工作流模块已就绪（幂等确保完成）");
    Ok(())
}

// ==================== SCIM Group + 多部门任职存量库兜底 ====================
// 与迁移 m20260924_000008_scim_groups / m20260924_000009_user_dept 等价：
// SCIM Group 三表 + sys_user_dept 兼职表 + sys_user_role.source 列 + 菜单 148/3620-3622。
// DDL 与种子 SQL 与迁移保持同步（双写惯例，参照 ensure_flow_module）；
// 全部幂等，每次启动重复执行不产生重复行。

/// 幂等确保 `sys_user_role` 含 `source` 列（授权来源两事实源分离）。
///
/// 实体带 source 字段后，存量库缺列会使所有 sys_user_role SELECT 失败——
/// 登录后权限加载、角色管理、SCIM 联动全站 500，优先级最高的兜底项。
/// 与迁移 m20260924_000008 §1.4 逐字对齐（存量行自动 'admin'）。
async fn ensure_user_role_source_column(db: &DatabaseConnection) -> Result<(), DbErr> {
    let exists = sso_table_exists(db, "sys_user_role")
        .await
        .map_err(|e| DbErr::Custom(format!("sys_user_role 存在性检查失败: {}", e)))?;
    if !exists {
        tracing::info!("sys_user_role 表尚未创建，跳过 source 列检查（由 migration 负责建表）");
        return Ok(());
    }
    let has_source = sso_has_column(db, "sys_user_role", "source")
        .await
        .map_err(|e| DbErr::Custom(format!("sys_user_role.source 列检查失败: {}", e)))?;
    if has_source {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_user_role ADD COLUMN source VARCHAR(64) NOT NULL DEFAULT 'admin'"
            .to_string(),
    ))
    .await?;
    tracing::info!("sys_user_role.source 列已补建（SCIM Group 存量库兜底）");
    Ok(())
}

/// 幂等确保 `sys_user_dept` 兼职中间表存在（多部门任职，DDL 与迁移 m20260924_000009 逐字对齐）。
///
/// CREATE TABLE IF NOT EXISTS 三方言幂等；索引 SQLite/PG 支持 IF NOT EXISTS，
/// MySQL 跳过交由 migration 补齐（与 ensure_sys_pat_table 同策略）。
async fn ensure_user_dept_table(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let (id_pk, bigint_type, dt_type) = match backend {
        DatabaseBackend::Sqlite => (
            "INTEGER PRIMARY KEY AUTOINCREMENT",
            "INTEGER NOT NULL",
            "DATETIME",
        ),
        DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "BIGINT NOT NULL", "TIMESTAMP"),
        _ => (
            "BIGINT PRIMARY KEY AUTO_INCREMENT",
            "INTEGER NOT NULL",
            "DATETIME",
        ),
    };
    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_user_dept (\n\
             \x20 id          {id_pk},\n\
             \x20 user_id     {bigint_type},\n\
             \x20 dept_id     {bigint_type},\n\
             \x20 source      VARCHAR(64) NOT NULL DEFAULT 'admin',\n\
             \x20 create_time {dt_type}\n\
             )"
        ),
    )
    .await?;
    if !matches!(backend, DatabaseBackend::MySql) {
        for ddl in [
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_user_dept ON sys_user_dept (user_id, dept_id)",
            "CREATE INDEX IF NOT EXISTS idx_user_dept_dept ON sys_user_dept (dept_id)",
        ] {
            if let Err(e) = flow_exec(db, ddl).await {
                tracing::debug!("sys_user_dept 索引创建跳过（可能已存在）: {}", e);
            }
        }
    }
    Ok(())
}

/// 幂等确保 SCIM Group 三表存在（DDL 与迁移 m20260924_000008 §1.1-1.3 逐字对齐）
async fn ensure_scim_group_tables(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let (id_pk, dt_type) = match backend {
        DatabaseBackend::Sqlite => ("INTEGER PRIMARY KEY AUTOINCREMENT", "DATETIME"),
        DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "TIMESTAMP"),
        _ => ("BIGINT PRIMARY KEY AUTO_INCREMENT", "DATETIME"),
    };
    let (tenant_type, bigint_type) = if backend == DatabaseBackend::Postgres {
        ("BIGINT NOT NULL DEFAULT 0", "BIGINT NOT NULL")
    } else {
        ("INTEGER NOT NULL DEFAULT 0", "INTEGER NOT NULL")
    };

    // 1.1 sys_scim_group 组实体（管理端不可建组——组权威在 IdP）
    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_scim_group (\n\
             \x20 group_id     {id_pk},\n\
             \x20 display_name VARCHAR(255) NOT NULL,\n\
             \x20 external_id  VARCHAR(255),\n\
             \x20 mapping_type VARCHAR(16) NOT NULL DEFAULT 'role',\n\
             \x20 del_flag     VARCHAR(1) NOT NULL DEFAULT '0',\n\
             \x20 tenant_id    {tenant_type},\n\
             \x20 create_by    VARCHAR(64) DEFAULT '',\n\
             \x20 create_time  {dt_type},\n\
             \x20 update_time  {dt_type}\n\
             )"
        ),
    )
    .await?;

    // 1.2 sys_scim_group_binding 组绑定目标（target_id 语义由组 mapping_type 决定）
    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_scim_group_binding (\n\
             \x20 id          {id_pk},\n\
             \x20 group_id    {bigint_type},\n\
             \x20 target_id   {bigint_type},\n\
             \x20 create_time {dt_type}\n\
             )"
        ),
    )
    .await?;

    // 1.3 sys_scim_group_member 组成员（复合 PK (group_id, user_id)）
    flow_exec(
        db,
        format!(
            "CREATE TABLE IF NOT EXISTS sys_scim_group_member (\n\
             \x20 group_id    {bigint_type},\n\
             \x20 user_id     {bigint_type},\n\
             \x20 create_time {dt_type},\n\
             \x20 PRIMARY KEY (group_id, user_id)\n\
             )"
        ),
    )
    .await?;

    // 索引：SQLite/PG 支持 IF NOT EXISTS；MySQL 跳过交由 migration（照 ensure_flow_indexes）
    if !matches!(backend, DatabaseBackend::MySql) {
        for ddl in [
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_scim_group_external_id ON sys_scim_group (external_id)",
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_scim_group_binding ON sys_scim_group_binding (group_id, target_id)",
        ] {
            if let Err(e) = flow_exec(db, ddl).await {
                tracing::debug!("SCIM Group 索引创建跳过（可能已存在）: {}", e);
            }
        }
    }
    Ok(())
}

/// 幂等补种 SCIM 组管理菜单（页 148 挂 145 SSO 目录 + 按钮 3620-3622 + role_menu(2)；
/// 与迁移 m20260924_000008 §2 逐字对齐，flow_insert 幂等——menu_id 主键防重）
async fn ensure_scim_group_menu(db: &DatabaseConnection) -> Result<(), DbErr> {
    // sys_menu 表存在性保护：全新空库未建系统表时跳过种子（交由 migration 负责初始种子）
    let sys_menu_exists = sso_table_exists(db, "sys_menu")
        .await
        .map_err(|e| DbErr::Custom(format!("SCIM 组菜单种子表存在性检查失败: {}", e)))?;
    if !sys_menu_exists {
        tracing::info!("SCIM 组菜单种子跳过（sys_menu 不存在，空库交由 migration 负责初始种子）");
        return Ok(());
    }
    let now = flow_now(db);
    let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag)";

    // 2.1 C 页面「SCIM 用户组」
    flow_insert(
        db,
        &format!(
            "{menu_cols} VALUES \
             (148, 'SCIM 用户组', 145, 3, 'scimGroup', 'system/scimGroup/index', '', '', '1', '0', 'C', '0', '0', 'system:scimgroup:list', 'peoples', 'admin', {now}, 'SCIM Group 组→角色/部门映射管理', '0')"
        ),
    )
    .await?;
    flow_insert(db, "sys_role_menu (role_id, menu_id) VALUES (2, 148)").await?;

    // 2.2 F 按钮权限
    let btn_rows: &[(&i64, &str, &str)] = &[
        (&3620, "组绑定编辑", "system:scimgroup:edit"),
        (&3621, "组删除", "system:scimgroup:remove"),
        (&3622, "组详情查询", "system:scimgroup:query"),
    ];
    for (menu_id, name, perms) in btn_rows {
        flow_insert(
            db,
            &format!(
                "{menu_cols} VALUES \
                 ({menu_id}, '{name}', 148, 1, '', '', '', '', '1', '0', 'F', '0', '0', '{perms}', '#', 'admin', {now}, '', '0')"
            ),
        )
        .await?;
        flow_insert(
            db,
            &format!("sys_role_menu (role_id, menu_id) VALUES (2, {menu_id})"),
        )
        .await?;
    }
    Ok(())
}

/// 幂等确保 AI 助手菜单就绪（NL2SQL v4.1，menu_id 4100 顶级 C 菜单，perms `ai:chat`）。
///
/// 不授予 role 2：AI 能力由管理员按需在角色管理里勾选 `ai:chat`（三层开关的角色层）；
/// 超管 `*:*:*` 天然可用。能力位 `ai.copilot` + `[ai].enabled` 双门控在 handler 校验。
async fn ensure_ai_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let insert_prefix = match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        DatabaseBackend::MySql => "INSERT IGNORE INTO ",
        _ => "INSERT INTO ",
    };
    let insert_suffix = if backend == DatabaseBackend::Postgres {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    };
    let now_expr = match backend {
        DatabaseBackend::Sqlite => {
            format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
        }
        _ => "NOW()".to_string(),
    };
    let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";
    db.execute_raw(
        Statement::from_string(
            backend,
            format!(
                "{insert_prefix}{menu_cols} VALUES (4100, 'AI助手', 0, 9, 'ai', 'ai/panel/index', '', '', '1', '0', 'C', '0', '0', 'ai:chat', 'chart', 'admin', {now_expr}, 'AI 数据查询助手（NL2SQL，受白名单与租户隔离约束）', '0', 'menu.ai'){insert_suffix}"
            ),
        ),
    )
    .await?;
    // 兜底修正：init.rs 基线 seed 先占位 menu_id=4100（无 i18n_key），INSERT OR IGNORE 跳过后
    // 增强列不会写入——UPDATE 幂等补齐（新库/存量库均安全，见 UX 真机核查的新旧库 diff 实证）
    db.execute_raw(Statement::from_string(
        backend,
        "UPDATE sys_menu SET i18n_key = 'menu.ai' WHERE menu_id = 4100 AND (i18n_key IS NULL OR i18n_key = '')".to_string(),
    ))
    .await?;
    Ok(())
}

/// 幂等确保 SCIM Group 模块与多部门任职完整就绪（列 + 表 + 索引 + 菜单；存量库向后兼容）
async fn ensure_scim_group_module(db: &DatabaseConnection) -> anyhow::Result<()> {
    ensure_user_role_source_column(db)
        .await
        .map_err(|e| anyhow::anyhow!("sys_user_role.source 列兜底失败: {}", e))?;
    ensure_user_dept_table(db)
        .await
        .map_err(|e| anyhow::anyhow!("sys_user_dept 建表失败: {}", e))?;
    ensure_scim_group_tables(db)
        .await
        .map_err(|e| anyhow::anyhow!("SCIM Group 三表建表失败: {}", e))?;
    ensure_scim_group_menu(db)
        .await
        .map_err(|e| anyhow::anyhow!("SCIM 组菜单种子补齐失败: {}", e))?;
    tracing::info!("SCIM Group 模块与多部门任职表已就绪（幂等确保完成）");
    Ok(())
}

/// 幂等确保 DP-01 数据权限规则两表存在（§5.53，等价迁移 `m20261006_000002`）
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而规则引擎
/// 管理端（/system/dataRule）与求值入口已接线——缺此兜底则存量库访问规则页/带规则
/// 查询全链路 `no such table: sys_data_rule`（500）。
///
/// 幂等：`CREATE TABLE IF NOT EXISTS` 三方言合法；菜单走 INSERT OR IGNORE/等价子句。
async fn ensure_data_rule_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let pk = match backend {
        DatabaseBackend::Sqlite => "rule_id INTEGER PRIMARY KEY AUTOINCREMENT",
        DatabaseBackend::MySql => "rule_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        DatabaseBackend::Postgres => "rule_id BIGSERIAL PRIMARY KEY",
        _ => unreachable!("unknown backend"),
    };
    let create_rule = format!(
        "CREATE TABLE IF NOT EXISTS sys_data_rule (
            {pk},
            rule_name VARCHAR(64) NOT NULL,
            table_name VARCHAR(64) NOT NULL,
            field_name VARCHAR(64) NOT NULL,
            op VARCHAR(8) NOT NULL,
            value_type VARCHAR(24) NOT NULL,
            rule_value VARCHAR(255) NULL,
            status VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag VARCHAR(1) NOT NULL DEFAULT '0',
            tenant_id BIGINT NOT NULL DEFAULT 0,
            create_by VARCHAR(64) NULL,
            create_time {ts} NULL,
            update_by VARCHAR(64) NULL,
            update_time {ts} NULL,
            remark VARCHAR(255) NULL
        )",
        ts = "DATETIME"
    );
    db.execute_raw(Statement::from_string(backend, create_rule))
        .await?;
    db.execute_raw(Statement::from_string(
        backend,
        "CREATE TABLE IF NOT EXISTS sys_role_data_rule (
            role_id BIGINT NOT NULL,
            rule_id BIGINT NOT NULL,
            PRIMARY KEY (role_id, rule_id)
        )"
        .to_string(),
    ))
    .await?;

    // 菜单幂等种子（与迁移 m20261006_000002 等价口径）
    let insert_prefix = match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        DatabaseBackend::MySql => "INSERT IGNORE INTO ",
        _ => "INSERT INTO ",
    };
    let insert_suffix = if backend == DatabaseBackend::Postgres {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    };
    let now_expr = match backend {
        DatabaseBackend::Sqlite => {
            format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
        }
        _ => "NOW()".to_string(),
    };
    let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag)";
    let menu_rows = format!(
        "(4117, '数据权限规则', 1, 15, 'dataRule', 'system/dataRule/index', '', '', '1', '0', 'C', '0', '0', 'system:dataRule:list', 'rule', 'admin', {now_expr}, 'DP-01 结构化数据权限规则', '0'), \
         (4118, '规则新增', 4117, 1, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:dataRule:add', '#', 'admin', {now_expr}, '', '0'), \
         (4119, '规则编辑', 4117, 2, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:dataRule:edit', '#', 'admin', {now_expr}, '', '0'), \
         (4122, '规则删除', 4117, 3, '#', '', '', '', '1', '0', 'F', '0', '0', 'system:dataRule:remove', '#', 'admin', {now_expr}, '', '0')"
    );
    db.execute_raw(Statement::from_string(
        backend,
        format!("{insert_prefix}{menu_cols} VALUES {menu_rows}{insert_suffix}"),
    ))
    .await?;
    // §5.57 token 观测列兜底（等价迁移 m20261006_000003）：存量库 ai_chat_history
    // 幂等补三列（SQLite 无 IF NOT EXISTS——按错误忽略，列已存在属正常情况）
    for col in ["prompt_tokens", "completion_tokens", "total_tokens"] {
        let ddl = format!("ALTER TABLE ai_chat_history ADD COLUMN {col} BIGINT NULL");
        if let Err(e) = db.execute_raw(Statement::from_string(backend, ddl)).await {
            tracing::debug!("ai_chat_history.{col} 列补建跳过（可能已存在）: {}", e);
        }
    }
    tracing::info!("data_rule 表/菜单已就绪（幂等确保完成）");
    Ok(())
}

/// 幂等确保 `sys_pat` 表存在（Tier-S #3：个人访问令牌）
///
/// `CREATE TABLE IF NOT EXISTS` 在 SQLite/PostgreSQL/MySQL 三方言下均合法且幂等。
/// 索引创建：SQLite/PostgreSQL 支持 `CREATE INDEX IF NOT EXISTS`，直接执行；MySQL 不支持该子句，
/// 交由 migration（seaorm `if_not_exists`）在支持 MySQL 的部署中补齐，此处对 MySQL 跳过。
/// 主键 `pat_id` 用 VARCHAR 由应用生成 uuid，规避自增列跨方言差异。
async fn ensure_sys_pat_table(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let dt = match backend {
        DatabaseBackend::Postgres => "TIMESTAMP",
        _ => "DATETIME",
    };
    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS sys_pat (
            pat_id       VARCHAR(64) NOT NULL PRIMARY KEY,
            user_id      BIGINT NOT NULL,
            name         VARCHAR(100) NOT NULL,
            token_hash   VARCHAR(64) NOT NULL,
            token_prefix VARCHAR(24) NOT NULL,
            scopes       TEXT NOT NULL,
            status       VARCHAR(1) NOT NULL DEFAULT '0',
            expires_at   {dt} NULL,
            last_used_at {dt} NULL,
            create_by    VARCHAR(64) DEFAULT '',
            create_time  {dt} NULL,
            update_time  {dt} NULL
        )"
    );
    db.execute_raw(Statement::from_string(backend, create_sql))
        .await?;

    if !matches!(backend, DatabaseBackend::MySql) {
        // token_hash 唯一索引 + user_id 普通索引（SQLite/PostgreSQL 支持 IF NOT EXISTS）
        for ddl in [
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_sys_pat_token_hash ON sys_pat(token_hash)",
            "CREATE INDEX IF NOT EXISTS idx_sys_pat_user_id ON sys_pat(user_id)",
        ] {
            // 并发/已存在时忽略失败（表与索引已由 migration 建好属正常情况）
            if let Err(e) = db
                .execute_raw(Statement::from_string(backend, ddl.to_string()))
                .await
            {
                tracing::debug!("sys_pat 索引创建跳过（可能已存在）: {}", e);
            }
        }
    }

    tracing::info!("sys_pat 表已就绪（幂等确保完成）");
    Ok(())
}

/// 台账（能力位 `auth.webauthn`，存量库兜底，等价迁移 `m20260927_000002`）：
/// WebAuthn / Passkey 凭据表 `sys_user_credential`。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已声明该表
/// ⇒ 缺此兜底则凭据查询/写入全链报 `no such table: sys_user_credential`（500），
/// 能力位开启后自助绑定与 passkey 登录不可用（假功能）。
///
/// 幂等：`CREATE TABLE IF NOT EXISTS` 三方言均合法；主键按方言声明自增（SQLite
/// `INTEGER PRIMARY KEY AUTOINCREMENT` / MySQL `BIGINT AUTO_INCREMENT` / PG `BIGSERIAL`）。
/// 索引：SQLite/PG 支持 `CREATE INDEX IF NOT EXISTS`，MySQL 不支持该子句，交由 migration 补齐。
async fn ensure_sys_user_credential_table(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let pk = match backend {
        DatabaseBackend::Sqlite => "cred_id INTEGER PRIMARY KEY AUTOINCREMENT",
        DatabaseBackend::MySql => "cred_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
        DatabaseBackend::Postgres => "cred_id BIGSERIAL PRIMARY KEY",
        _ => unreachable!("unknown backend"),
    };
    let dt = match backend {
        DatabaseBackend::Postgres => "TIMESTAMP",
        _ => "DATETIME",
    };
    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS sys_user_credential (
            {pk},
            user_id        BIGINT NOT NULL,
            tenant_id      BIGINT NOT NULL DEFAULT 0,
            credential_id  VARCHAR(512) NOT NULL,
            public_key     TEXT NOT NULL,
            name           VARCHAR(255) NOT NULL,
            sign_count     BIGINT NOT NULL DEFAULT 0,
            last_used_at   {dt} NULL,
            create_time    {dt} NULL,
            del_flag       VARCHAR(1) NOT NULL DEFAULT '0'
        )"
    );
    db.execute_raw(Statement::from_string(backend, create_sql))
        .await?;

    if !matches!(backend, DatabaseBackend::MySql) {
        for ddl in [
            "CREATE UNIQUE INDEX IF NOT EXISTS uk_sys_user_credential_credential_id ON sys_user_credential(credential_id)",
            "CREATE INDEX IF NOT EXISTS idx_sys_user_credential_user_id ON sys_user_credential(user_id)",
        ] {
            // 并发/已存在时忽略失败（表与索引已由 migration 建好属正常情况）
            if let Err(e) = db
                .execute_raw(Statement::from_string(backend, ddl.to_string()))
                .await
            {
                tracing::debug!("sys_user_credential 索引创建跳过（可能已存在）: {}", e);
            }
        }
    }

    tracing::info!("sys_user_credential 表已就绪（幂等确保完成）");
    Ok(())
}

/// 启动打印 **WebAuthn / Passkey** 的有效姿态（`[features].auth.webauthn` + `[webauthn]`）。
///
/// 治理意义与 `[acme]` / `[events]` 同源：能力位是"放开登录面能力"的唯一入口，
/// 且 `rp_id` / `origin` 是 WebAuthn 的**信任锚**，配错即认证恒失败。故：
/// - 能力位 `off`（默认）⇒ 打 INFO（端点表现为 404，不暴露"存在但被关"）；
/// - 能力位 `on` 且解析出有效 `rp_id` / `origin` ⇒ 打 INFO 列出实际信任锚；
/// - 能力位 `on` 但 `rp_id` / `origin` 未配置、无法从 `[server].cors_origins` 推导、
///   或推导结果非法 ⇒ 打 **WARN**（拒绝静默失效：请求期将返回 503 而非静默失败）。
fn init_webauthn_output(settings: &Settings) {
    use crate::common::features::FeatureSet;

    let on = FeatureSet::sanitized(settings.features.0.clone())
        .is_on(crate::service::webauthn_service::FEATURE_WEBAUTHN);

    match (on, settings.webauthn.resolved(&settings.server)) {
        (false, _) => {
            tracing::info!(
                "WebAuthn/Passkey：[features].auth.webauthn = off（默认；端点表现为 404）"
            );
        }
        (true, Some(r)) => {
            tracing::info!(
                rp_id = %r.rp_id,
                rp_name = %r.rp_name,
                origin = %r.origin,
                state_ttl_secs = r.state_ttl_secs,
                "WebAuthn/Passkey：已启用（rp_id / origin 为 WebAuthn 信任锚，配置变更后浏览器旧凭据将失效）"
            );
        }
        (true, None) => {
            tracing::warn!(
                rp_id = %settings.webauthn.rp_id,
                origin = %settings.webauthn.origin,
                "[features].auth.webauthn = on，但 [webauthn].rp_id / origin 未配置且无法从 \
                 [server].cors_origins 推导（或推导结果非法）⇒ passkey 注册/登录将返回 503\
                 （服务器未就绪）。请显式配置 [webauthn].rp_id 与 [webauthn].origin"
            );
        }
    }
}

/// 菜单信息架构优化兜底（与迁移 m20260928_000004_optimize_menu_structure 等价，全幂等）：
/// ① 新目录 3950「租户服务」并收编自助页 3900/3627（原游离顶层）；
/// ② 三个目录内 order 重排（消除 order=8/10/11 多处重复导致的显示顺序不稳定）；
/// ③ icon 语义修正（peoples/connection/documentation 等多处复用改贴切图标）。
/// 全部为幂等 UPDATE/INSERT，重复执行无副作用。
async fn ensure_menu_structure_optimize(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // ---- ① 3950 目录（幂等插入）----
    let exists: Option<i64> = match db
        .query_one_raw(Statement::from_string(
            backend,
            "SELECT menu_id FROM sys_menu WHERE menu_id = 3950".to_string(),
        ))
        .await
    {
        Ok(row) => row.and_then(|r| r.try_get_by_index::<i64>(0).ok()),
        Err(_) => None,
    };
    if exists.is_none() {
        let prefix = match backend {
            DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO",
            DatabaseBackend::MySql => "INSERT IGNORE INTO",
            DatabaseBackend::Postgres => "INSERT INTO",
            _ => unreachable!("unknown backend"),
        };
        let now = match backend {
            DatabaseBackend::Sqlite => "'2026-09-28 00:00:00'".to_string(),
            _ => "NOW()".to_string(),
        };
        db.execute_raw(Statement::from_string(
            backend,
            format!(
                "{} sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES (3950, '租户服务', 0, 5, 'tenant-space', NULL, '', '', '1', '0', 'M', '0', '0', '', 'shopping', 'admin', {}, '租户自助功能聚合（我的域名 / 导航设置）', '0', 'menu.tenantSpace')",
                prefix, now
            ),
        ))
        .await?;
        let rm_prefix = match backend {
            DatabaseBackend::Postgres => {
                "INSERT INTO sys_role_menu (role_id, menu_id) VALUES (2, 3950) ON CONFLICT DO NOTHING"
            }
            DatabaseBackend::Sqlite => {
                "INSERT OR IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, 3950)"
            }
            DatabaseBackend::MySql => {
                "INSERT IGNORE INTO sys_role_menu (role_id, menu_id) VALUES (2, 3950)"
            }
            _ => unreachable!("unknown backend"),
        };
        db.execute_raw(Statement::from_string(backend, rm_prefix.to_string()))
            .await?;
    }

    // ---- ② 自助页收编 + order 重排 + icon 修正（幂等 UPDATE 清单）----
    let updates: &[&str] = &[
        "UPDATE sys_menu SET menu_name = '域名管理' WHERE menu_id = 3900",
        "UPDATE sys_menu SET menu_name = '我的导航' WHERE menu_id = 3627",
        "UPDATE sys_menu SET parent_id = 3950 WHERE menu_id = 3900",
        "UPDATE sys_menu SET parent_id = 3950 WHERE menu_id = 3627",
        "UPDATE sys_menu SET parent_id = 3 WHERE menu_id = 3560",
        "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 3900",
        "UPDATE sys_menu SET order_num = 2 WHERE menu_id = 3627",
        // 顶层：工作台 0 / 数据看板 1 / 系统管理 2 / 系统监控 3 / 系统工具 4 / 租户服务 5 / 官网 6
        "UPDATE sys_menu SET order_num = 0 WHERE menu_id = 127",
        "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 132",
        "UPDATE sys_menu SET order_num = 2 WHERE menu_id = 1",
        "UPDATE sys_menu SET order_num = 3 WHERE menu_id = 2",
        "UPDATE sys_menu SET order_num = 4 WHERE menu_id = 3",
        "UPDATE sys_menu SET order_num = 5 WHERE menu_id = 3950",
        "UPDATE sys_menu SET order_num = 6 WHERE menu_id = 4",
        // 系统管理(1)
        "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 100",
        "UPDATE sys_menu SET order_num = 2 WHERE menu_id = 101",
        "UPDATE sys_menu SET order_num = 3 WHERE menu_id = 102",
        "UPDATE sys_menu SET order_num = 4 WHERE menu_id = 103",
        "UPDATE sys_menu SET order_num = 5 WHERE menu_id = 104",
        "UPDATE sys_menu SET order_num = 6 WHERE menu_id = 105",
        "UPDATE sys_menu SET order_num = 7 WHERE menu_id = 106",
        "UPDATE sys_menu SET order_num = 8 WHERE menu_id = 107",
        "UPDATE sys_menu SET order_num = 9 WHERE menu_id = 3700",
        "UPDATE sys_menu SET order_num = 10 WHERE menu_id = 108",
        "UPDATE sys_menu SET order_num = 11 WHERE menu_id = 125",
        "UPDATE sys_menu SET order_num = 12 WHERE menu_id = 134",
        "UPDATE sys_menu SET order_num = 13 WHERE menu_id = 140",
        "UPDATE sys_menu SET order_num = 14 WHERE menu_id = 151",
        "UPDATE sys_menu SET order_num = 15 WHERE menu_id = 3600",
        "UPDATE sys_menu SET order_num = 16 WHERE menu_id = 145",
        "UPDATE sys_menu SET order_num = 17 WHERE menu_id = 157",
        // 系统监控(2)
        "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 109",
        "UPDATE sys_menu SET order_num = 2 WHERE menu_id = 110",
        "UPDATE sys_menu SET order_num = 3 WHERE menu_id = 119",
        "UPDATE sys_menu SET order_num = 4 WHERE menu_id = 113",
        "UPDATE sys_menu SET order_num = 5 WHERE menu_id = 135",
        "UPDATE sys_menu SET order_num = 6 WHERE menu_id = 118",
        "UPDATE sys_menu SET order_num = 7 WHERE menu_id = 3550",
        "UPDATE sys_menu SET order_num = 8 WHERE menu_id = 133",
        "UPDATE sys_menu SET order_num = 9 WHERE menu_id = 121",
        "UPDATE sys_menu SET order_num = 10 WHERE menu_id = 122",
        "UPDATE sys_menu SET order_num = 11 WHERE menu_id = 120",
        "UPDATE sys_menu SET order_num = 12 WHERE menu_id = 160",
        "UPDATE sys_menu SET order_num = 13 WHERE menu_id = 501",
        // 系统工具(3)
        "UPDATE sys_menu SET order_num = 1 WHERE menu_id = 115",
        "UPDATE sys_menu SET order_num = 2 WHERE menu_id = 116",
        "UPDATE sys_menu SET order_num = 3 WHERE menu_id = 117",
        "UPDATE sys_menu SET order_num = 4 WHERE menu_id = 3410",
        "UPDATE sys_menu SET order_num = 5 WHERE menu_id = 3560",
        "UPDATE sys_menu SET order_num = 6 WHERE menu_id = 124",
        "UPDATE sys_menu SET order_num = 7 WHERE menu_id = 128",
        "UPDATE sys_menu SET order_num = 8 WHERE menu_id = 129",
        "UPDATE sys_menu SET order_num = 9 WHERE menu_id = 131",
        // icon 语义修正（第二批，语义直觉优先——同语义页面允许复用同图标）：
        "UPDATE sys_menu SET icon = 'message' WHERE menu_id = 107",
        "UPDATE sys_menu SET icon = 'email' WHERE menu_id = 140",
        "UPDATE sys_menu SET icon = 'log' WHERE menu_id = 135",
        "UPDATE sys_menu SET icon = 'druid' WHERE menu_id = 133",
        "UPDATE sys_menu SET icon = 'icon' WHERE menu_id = 124",
        "UPDATE sys_menu SET icon = 'switch' WHERE menu_id = 146",
        "UPDATE sys_menu SET icon = 'nested' WHERE menu_id = 3700",
        "UPDATE sys_menu SET icon = 'peoples' WHERE menu_id = 3950",
        "UPDATE sys_menu SET icon = 'clipboard' WHERE menu_id = 3560",
        "UPDATE sys_menu SET icon = 'drag' WHERE menu_id = 3627",
    ];
    for sql in updates {
        db.execute_raw(Statement::from_string(backend, sql.to_string()))
            .await?;
    }
    tracing::info!("菜单信息架构优化已应用（order 重排 / 自助页收编 3950 / icon 语义修正）");
    Ok(())
}

/// 数据看板菜单去重兜底（与迁移 m20260928_000003_dedupe_dashboard_menu 等价，全幂等）：
/// 删除「系统管理」下与顶级 132 重复的 dashboard 菜单（m20260801_000002 查重条件
/// 带 parent_id=1 漏判顶级 132 所致的重复注册）。重复执行为 no-op。
async fn ensure_dashboard_menu_dedupe(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let dedup_rows = db
        .execute_raw(Statement::from_string(
            backend,
            "DELETE FROM sys_role_menu WHERE menu_id IN (
                SELECT menu_id FROM sys_menu
                WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index'
            )",
        ))
        .await?;
    let deleted = db
        .execute_raw(Statement::from_string(
            backend,
            "DELETE FROM sys_menu WHERE path = 'dashboard' AND parent_id = 1 AND component = 'dashboard/index'",
        ))
        .await?;
    let rows = deleted.rows_affected() + dedup_rows.rows_affected();
    if rows > 0 {
        tracing::info!("数据看板重复菜单已清理 {} 行（存量库兜底）", rows);
    }
    Ok(())
}

/// 前端错误日志 device_type 列兜底（FCP-011，与迁移
/// m20260928_000002_frontend_error_device_type 等价，全幂等）：
/// `sys_frontend_error` 存量库补 `device_type VARCHAR(16) NULL`。
/// 缺此兜底时（优先级最高的一项）：实体 SELECT 带 device_type ⇒
/// /monitor/frontendError 列表/上报全站 500。
async fn ensure_frontend_error_device_type(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    if sso_table_exists(db, "sys_frontend_error").await?
        && !sso_has_column(db, "sys_frontend_error", "device_type").await?
    {
        db.execute_raw(Statement::from_string(
            backend,
            "ALTER TABLE sys_frontend_error ADD COLUMN device_type VARCHAR(16) NULL",
        ))
        .await?;
        tracing::info!("sys_frontend_error.device_type 列已补建（存量库兜底，FCP-011）");
    }
    Ok(())
}

/// 多租户 Phase 2 存量库兜底（与迁移 m20260925_000001/000002 等价，全幂等）：
/// 1) 27 张业务表补 tenant_id 列（BIGINT NOT NULL DEFAULT 0，存量归平台租户 0）
/// 2) tid 索引（3 张大表用 (tenant_id, 时间列) 组合索引，其余单列）
/// 3) 菜单 3700-3704 租户管理段 + role_menu（3700/3701 → role_id=2 只读）
async fn ensure_multitenant_module(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // ---- 1. 幂等补列 ----
    const TABLES: &[&str] = &[
        "sys_dept",
        "sys_role",
        "sys_post",
        "sys_config",
        "sys_dict_type",
        "sys_dict_data",
        "sys_notice",
        "sys_notice_read",
        "sys_pat",
        "sys_user_pref",
        "sys_oauth_consent",
        "sys_oauth_provider",
        "sys_oauth_user",
        "sys_msg_channel",
        "sys_msg_template",
        "sys_msg_send_log",
        "sys_web_hook",
        "sys_web_hook_log",
        "sys_report",
        "sys_report_sub",
        "sys_job",
        "sys_job_log",
        "sys_task",
        "sys_backup_log",
        "sys_oper_log",
        "sys_logininfor",
        "sys_frontend_error",
    ];
    let mut added = 0usize;
    for table in TABLES {
        if sso_table_exists(db, table).await? && !sso_has_column(db, table, "tenant_id").await? {
            db.execute_raw(Statement::from_string(
                backend,
                format!("ALTER TABLE {table} ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 0"),
            ))
            .await?;
            added += 1;
        }
    }
    if added > 0 {
        tracing::info!("多租户 tenant_id 列已补建 {added} 张表（存量库兜底）");
    }

    // ---- 2. 幂等建索引（三方言全覆盖：MySQL 经 information_schema 查存后建，不再跳过）----
    {
        let mut idx_defs: Vec<(String, String, String)> = Vec::new();
        // 大表组合索引（时间列名各异：oper_time/login_time/create_time）
        for (t, c) in [
            ("sys_oper_log", "oper_time"),
            ("sys_logininfor", "login_time"),
            ("sys_msg_send_log", "create_time"),
        ] {
            idx_defs.push((
                t.to_string(),
                format!("idx_{t}_tid_time"),
                format!("tenant_id, {c}"),
            ));
        }
        for t in TABLES {
            if !matches!(*t, "sys_oper_log" | "sys_logininfor" | "sys_msg_send_log") {
                idx_defs.push((
                    t.to_string(),
                    format!("idx_{t}_tid"),
                    "tenant_id".to_string(),
                ));
            }
        }
        for (table, index_name, columns) in &idx_defs {
            if let Err(e) = ensure_tenant_index(db, table, index_name, columns, false).await {
                tracing::debug!("租户索引 {index_name} 创建跳过: {}", e);
            }
        }
    }

    // ---- 3. 菜单 3700-3704 段幂等登记 + role_menu（对齐 m20260925_000002）----
    let insert_prefix = match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        DatabaseBackend::MySql => "INSERT IGNORE INTO ",
        _ => unreachable!("unknown backend"),
    };
    let insert_suffix = if backend == DatabaseBackend::Postgres {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    };
    let now_expr = match backend {
        DatabaseBackend::Sqlite => {
            format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
        }
        _ => "NOW()".to_string(),
    };
    let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";
    let body_rows = [
        format!(
            "{menu_cols} VALUES (3700, '租户管理', 1, 8, 'tenant', 'system/tenant/index', '', '', '1', '0', 'C', '0', '0', 'system:tenant:list', 'peoples', 'admin', {now_expr}, '多租户管理（dept 树根=租户）', '0', 'menu.tenant')"
        ),
        "sys_role_menu (role_id, menu_id) VALUES (2, 3700)".to_string(),
        format!(
            "{menu_cols} VALUES (3701, '租户查询', 3700, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:query', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        "sys_role_menu (role_id, menu_id) VALUES (2, 3701)".to_string(),
        format!(
            "{menu_cols} VALUES (3702, '租户新增', 3700, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:add', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3703, '租户修改', 3700, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:edit', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3704, '租户删除', 3700, 4, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:remove', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        // ---- 域名绑定（多租户 Phase 3 域名链路，menu_id 段位 3800-3804，父 3700）----
        // 授予约定与 3700/3701 一致：运维查看（list）与验证（verify）授予平台普通角色（role_id=2），
        // 新增/修改/删除仅平台操作者（operator_tid=0）可用，故不授予普通角色。
        format!(
            "{menu_cols} VALUES (3800, '域名查询', 3700, 5, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:list', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        "sys_role_menu (role_id, menu_id) VALUES (2, 3800)".to_string(),
        format!(
            "{menu_cols} VALUES (3801, '域名新增', 3700, 6, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:add', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3802, '域名验证', 3700, 7, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:verify', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        "sys_role_menu (role_id, menu_id) VALUES (2, 3802)".to_string(),
        format!(
            "{menu_cols} VALUES (3803, '域名修改', 3700, 8, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:edit', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3804, '域名删除', 3700, 9, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:remove', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
    ];
    for body in body_rows {
        db.execute_raw(Statement::from_string(
            backend,
            format!("{insert_prefix}{body}{insert_suffix}"),
        ))
        .await?;
    }

    tracing::info!("多租户 Phase 2 模块已就绪（幂等确保完成）");
    Ok(())
}

/// 租户自助域名页面菜单（批次 1c；与迁移
/// `m20260926_000011_tenant_domain_self_service_menu` **双写一致**，R4 为回归门禁）。
///
/// 新增 `menu-id-registry.md` §「新增大模块 3900 起」段位的一组自包含菜单：
/// - C 页面 3900「我的域名」（顶层菜单，`system/tenant/domain/index`，perms 复用
///   `system:tenant:domain:list`）；
/// - F 按钮 3901 新增 / 3902 验证 / 3903 修改 / 3904 删除。
///
/// **不授予任何角色**：能力位 `tenant.domain_self_service` 默认 `off`，
/// 授予与回收由 [`ensure_tenant_role_menu_governance`] 的 ①/①' 按能力位动态处理
/// （开启 ⇒ 回填给平台普通角色 role 2 作新建租户模板；关闭 ⇒ 收回）。
async fn ensure_domain_self_service_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    let insert_prefix = match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        DatabaseBackend::MySql => "INSERT IGNORE INTO ",
        _ => unreachable!("unknown backend"),
    };
    let insert_suffix = if backend == DatabaseBackend::Postgres {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    };
    let now_expr = match backend {
        DatabaseBackend::Sqlite => {
            format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
        }
        _ => "NOW()".to_string(),
    };
    let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";
    let body_rows = [
        format!(
            "{menu_cols} VALUES (3900, '我的域名', 0, 90, 'my-domain', 'system/tenant/domain/index', '', '', '1', '0', 'C', '0', '0', 'system:tenant:domain:list', 'link', 'admin', {now_expr}, '租户自助域名管理（需能力位 tenant.domain_self_service）', '0', 'menu.myDomain')"
        ),
        format!(
            "{menu_cols} VALUES (3901, '域名新增', 3900, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:add', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3902, '域名验证', 3900, 2, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:verify', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3903, '域名修改', 3900, 3, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:edit', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3904, '域名删除', 3900, 4, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenant:domain:remove', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
    ];
    for body in body_rows {
        db.execute_raw(Statement::from_string(
            backend,
            format!("{insert_prefix}{body}{insert_suffix}"),
        ))
        .await?;
    }
    tracing::info!("租户自助域名页面菜单已就绪（3900-3904，幂等确保完成）");
    Ok(())
}

/// 备份权限粒度化菜单（批次 2；与迁移
/// `m20260926_000012_backup_permission_granularity` **双写一致**，R4 为回归门禁）。
///
/// 新增两个 F 按钮（`menu-id-registry.md`「新增 C/F 页面按钮（小模块）3625 起」），
/// 挂在既有备份页 118 之下：
/// - 3625 `system:backup:download`（整库文件下载，原与 `query` 混用）
/// - 3626 `system:backup:export`（数据包导出：平台代导出 + 租户自助导出）
///
/// **不授予任何角色**：与 3900-3904 同理，授予/回收由
/// [`ensure_tenant_role_menu_governance`] 按能力位 **perms 粒度**动态处理。
async fn ensure_backup_permission_menus(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    let insert_prefix = match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        DatabaseBackend::MySql => "INSERT IGNORE INTO ",
        _ => unreachable!("unknown backend"),
    };
    let insert_suffix = if backend == DatabaseBackend::Postgres {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    };
    let now_expr = match backend {
        DatabaseBackend::Sqlite => {
            format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
        }
        _ => "NOW()".to_string(),
    };
    let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";
    let body_rows = [
        format!(
            "{menu_cols} VALUES (3625, '备份下载', 118, 5, '', '', '', '', '1', '0', 'F', '0', '0', 'system:backup:download', '#', 'admin', {now_expr}, '整库备份文件下载（批次 2 从 query 独立）', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3626, '数据包导出', 118, 6, '', '', '', '', '1', '0', 'F', '0', '0', 'system:backup:export', '#', 'admin', {now_expr}, '租户数据包导出（平台代导出 + 租户自助导出）', '0', NULL)"
        ),
    ];
    for body in body_rows {
        db.execute_raw(Statement::from_string(
            backend,
            format!("{insert_prefix}{body}{insert_suffix}"),
        ))
        .await?;
    }
    tracing::info!("备份权限粒度化菜单已就绪（3625-3626，幂等确保完成）");
    Ok(())
}

/// 租户自建导航 L3 页面菜单（批次 3；与迁移
/// `m20260926_000014_tenant_nav_menu` **双写一致**，R4 为回归门禁）。
///
/// 新增 `menu-id-registry.md` §「新增 C/F 页面按钮（小模块）3627 起」的一组菜单：
/// - C 页面 3627「导航设置」（顶层菜单，`system/tenant/nav/index`，
///   perms `system:tenantMenu:list`）；
/// - F 按钮 3628 新增 / 3629 修改 / 3630 删除。
///
/// **不授予任何角色**：能力位 `nav.l3` 默认 `off`，授予与回收由
/// [`ensure_tenant_role_menu_governance`] 的 ①/①' 按能力位 **perms 粒度 + 档位阈值**
/// 动态处理（`view_only` ⇒ 仅回填 3627；`full` ⇒ 追加回填 3628-3630）。
async fn ensure_tenant_nav_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    let insert_prefix = match backend {
        DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
        DatabaseBackend::Postgres => "INSERT INTO ",
        DatabaseBackend::MySql => "INSERT IGNORE INTO ",
        _ => unreachable!("unknown backend"),
    };
    let insert_suffix = if backend == DatabaseBackend::Postgres {
        " ON CONFLICT DO NOTHING"
    } else {
        ""
    };
    let now_expr = match backend {
        DatabaseBackend::Sqlite => {
            format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
        }
        _ => "NOW()".to_string(),
    };
    let menu_cols = "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key)";
    let body_rows = [
        format!(
            "{menu_cols} VALUES (3627, '导航设置', 0, 91, 'my-nav', 'system/tenant/nav/index', '', '', '1', '0', 'C', '0', '0', 'system:tenantMenu:list', 'tree-table', 'admin', {now_expr}, '租户自建导航 L3 配置（需能力位 nav.l3）', '0', 'menu.myNav')"
        ),
        format!(
            "{menu_cols} VALUES (3628, '导航新增', 3627, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenantMenu:add', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3629, '导航修改', 3627, 2, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenantMenu:edit', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
        format!(
            "{menu_cols} VALUES (3630, '导航删除', 3627, 3, '', '', '', '', '1', '0', 'F', '0', '0', 'system:tenantMenu:remove', '#', 'admin', {now_expr}, '', '0', NULL)"
        ),
    ];
    for body in body_rows {
        db.execute_raw(Statement::from_string(
            backend,
            format!("{insert_prefix}{body}{insert_suffix}"),
        ))
        .await?;
    }
    tracing::info!("租户自建导航页面菜单已就绪（3627-3630，幂等确保完成）");
    Ok(())
}

/// 承载租户归属的表清单（Phase 3 remap 改写范围；同时被
/// `service::sys_backup_service::export_tenant_package` 复用为「租户数据包」导出范围）：
/// = Phase 2 `ensure_multitenant_module::TABLES` 的 27 张 + `sys_user`（列由
/// m20260924_000005 / `ensure_user_tenant_id_column` 补）+ 后加却带 tenant_id
/// 的 5 张（oauth_client / flow_task / flow_log / scim_group / flow_demo_doc）。
/// **两处清单须同步维护**（R4 门禁解析的是 ensure_multitenant_module 内的字面量，
/// 故此处必须独立成表；实际改写前逐个探测列存在性，缺列则跳过）。
pub(crate) const TENANT_CARRYING_TABLES: &[&str] = &[
    "sys_dept",
    "sys_user",
    "sys_role",
    "sys_post",
    "sys_config",
    "sys_dict_type",
    "sys_dict_data",
    "sys_notice",
    "sys_notice_read",
    "sys_pat",
    "sys_user_pref",
    "sys_oauth_consent",
    "sys_oauth_provider",
    "sys_oauth_user",
    "sys_msg_channel",
    "sys_msg_template",
    "sys_msg_send_log",
    "sys_web_hook",
    "sys_web_hook_log",
    "sys_report",
    "sys_report_sub",
    "sys_job",
    "sys_job_log",
    "sys_task",
    "sys_backup_log",
    "sys_oper_log",
    "sys_logininfor",
    "sys_frontend_error",
    "sys_oauth_client",
    "sys_flow_task",
    "sys_flow_log",
    "sys_scim_group",
    "flow_demo_doc",
];

/// 多租户 Phase 3 存量库兜底（与迁移 m20260925_000003_tenant_phase3 等价，全幂等）：
///
/// 1) 幂等建 5 张租户表族（sys_tenant / sys_tenant_package / sys_tenant_domain /
///    sys_tenant_menu / sys_tenant_migration_map）+ 索引（三方言）；
/// 2) 默认套餐「标准版」种子（`menu_ids = NULL` = 不限制功能白名单）；
/// 3) **tid remap（唯一不可逆点，§29.7）**：旧模型"dept 树根 = 租户"（租户 tid 复用
///    根部门 dept_id）一次性换源为 `sys_tenant.tenant_id` 独立 id 空间：
///    - 扫 `sys_dept` 中 `parent_id = 0`、未删除、且非平台根（100）的根部门；
///    - 每根部门建一行 `sys_tenant`（`tenant_code = t{root_dept_id}` 确定性唯一、
///      `dept_id` = 该根部门）并**同事务**写 `sys_tenant_migration_map`
///      （`old_tid → new_tenant_id`，回滚唯一依赖，禁止清理）；
///    - 按映射把承载表的 `tenant_id` 由旧 tid 改写为新 tenant_id；
///    - 用 BFS 求租户子树，顺带修复子树内 `tenant_id = 0` 的后代部门与用户
///      （Phase 2 兜底把存量行统一归 0 导致的串号 bug）。
///
/// 一次性语义（幂等关键）：仅当 `sys_tenant` 与映射表**均为空**时执行 remap——
/// 首次启动换源后再次启动即跳过；此后新建租户由服务层落表（其根部门不会再被换源）。
async fn ensure_tenant_phase3(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let (id_pk, dt) = match backend {
        DatabaseBackend::Sqlite => ("INTEGER PRIMARY KEY AUTOINCREMENT", "DATETIME"),
        DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "TIMESTAMP"),
        _ => ("BIGINT PRIMARY KEY AUTO_INCREMENT", "DATETIME"),
    };
    let ph = |i: usize| -> String {
        if backend == DatabaseBackend::Postgres {
            format!("${i}")
        } else {
            "?".to_string()
        }
    };
    let now_expr = match backend {
        DatabaseBackend::Sqlite => {
            format!("'{}'", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))
        }
        _ => "NOW()".to_string(),
    };

    // ---- 1. 幂等建表（与迁移 m20260925_000003 DDL 逐列一致）----
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant (
            tenant_id     {id_pk},
            tenant_code   VARCHAR(64) NOT NULL,
            tenant_name   VARCHAR(64) NOT NULL,
            dept_id       BIGINT NULL,
            package_id    BIGINT NULL,
            contact_name  VARCHAR(64) NULL,
            contact_phone VARCHAR(20) NULL,
            contact_email VARCHAR(64) NULL,
            domain        VARCHAR(255) NULL,
            expire_time   {dt} NULL,
            account_count INT NOT NULL DEFAULT 0,
            status        VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag      VARCHAR(1) NOT NULL DEFAULT '0',
            create_by     VARCHAR(64) NULL,
            create_time   {dt} NULL,
            update_by     VARCHAR(64) NULL,
            update_time   {dt} NULL,
            remark        VARCHAR(500) NULL
        )"#
        ),
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_package (
            package_id            {id_pk},
            package_name          VARCHAR(64) NOT NULL,
            menu_ids              TEXT NULL,
            default_account_count INT NOT NULL DEFAULT 0,
            status                VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag              VARCHAR(1) NOT NULL DEFAULT '0',
            create_by             VARCHAR(64) NULL,
            create_time           {dt} NULL,
            update_by             VARCHAR(64) NULL,
            update_time           {dt} NULL,
            remark                VARCHAR(500) NULL
        )"#
        ),
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_domain (
            domain_id     {id_pk},
            tenant_id     BIGINT NOT NULL DEFAULT 0,
            domain        VARCHAR(255) NOT NULL,
            domain_type   VARCHAR(16) NOT NULL DEFAULT '1',
            is_primary    VARCHAR(1) NOT NULL DEFAULT '1',
            verify_status VARCHAR(1) NOT NULL DEFAULT '0',
            verify_token  VARCHAR(64) NULL,
            verified_at   {dt} NULL,
            status        VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag      VARCHAR(1) NOT NULL DEFAULT '0',
            create_by     VARCHAR(64) NULL,
            create_time   {dt} NULL,
            update_by     VARCHAR(64) NULL,
            update_time   {dt} NULL,
            remark        VARCHAR(500) NULL
        )"#
        ),
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_menu (
            l3_id       BIGINT NOT NULL PRIMARY KEY,
            tenant_id   BIGINT NOT NULL DEFAULT 0,
            ref_menu_id BIGINT NOT NULL DEFAULT 0,
            parent_id   BIGINT NOT NULL DEFAULT 0,
            order_num   INT NOT NULL DEFAULT 0,
            visible     VARCHAR(1) NOT NULL DEFAULT '0',
            status      VARCHAR(1) NOT NULL DEFAULT '0',
            del_flag    VARCHAR(1) NOT NULL DEFAULT '0',
            create_by   VARCHAR(64) NULL,
            create_time {dt} NULL,
            update_by   VARCHAR(64) NULL,
            update_time {dt} NULL
        )"#
        ),
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            r#"CREATE TABLE IF NOT EXISTS sys_tenant_migration_map (
            map_id        {id_pk},
            old_tid       BIGINT NOT NULL,
            new_tenant_id BIGINT NOT NULL,
            create_time   {dt} NULL,
            remark        VARCHAR(500) NULL
        )"#
        ),
    ))
    .await?;

    // 索引：失败只告警不阻断启动（与 Phase 2 兜底同策略；缺失仅影响性能与
    // 唯一约束强度，可在服务起来后由 migration 补齐）
    for (table, index, cols, unique) in [
        ("sys_tenant", "uk_sys_tenant_code", "tenant_code", true),
        ("sys_tenant", "idx_sys_tenant_dept", "dept_id", false),
        (
            "sys_tenant_package",
            "uk_sys_tenant_package_name",
            "package_name",
            true,
        ),
        (
            "sys_tenant_domain",
            "uk_sys_tenant_domain_domain",
            "domain",
            true,
        ),
        (
            "sys_tenant_domain",
            "idx_sys_tenant_domain_tid",
            "tenant_id",
            false,
        ),
        (
            "sys_tenant_menu",
            "uk_sys_tenant_menu",
            "tenant_id, ref_menu_id",
            true,
        ),
        (
            "sys_tenant_menu",
            "idx_sys_tenant_menu_tid",
            "tenant_id",
            false,
        ),
        (
            "sys_tenant_migration_map",
            "uk_sys_tenant_migration_map_old",
            "old_tid",
            true,
        ),
    ] {
        if let Err(e) = ensure_tenant_index(db, table, index, cols, unique).await {
            tracing::warn!("Phase 3 索引 {index} 创建失败（不阻断启动，请人工核查）: {e}");
        }
    }

    // ---- 1b. 存量库幂等补列：sys_tenant_domain 域名链路列（domain_type / verified_at）----
    // 域名链路（§27.7）：`domain_type` 决定验证策略（'0' 子域名平台分配免验证 / '1' 自定义需 DNS TXT），
    // `verified_at` 记录 TXT 验证通过时间。`CREATE TABLE IF NOT EXISTS` 对存量表不生效，故此处补列。
    if sso_table_exists(db, "sys_tenant_domain").await? {
        for (column, column_def) in [
            (
                "domain_type",
                "VARCHAR(16) NOT NULL DEFAULT '1'".to_string(),
            ),
            ("verified_at", format!("{dt} NULL")),
        ] {
            if sso_has_column(db, "sys_tenant_domain", column).await? {
                continue;
            }
            db.execute_raw(Statement::from_string(
                backend,
                format!("ALTER TABLE sys_tenant_domain ADD COLUMN {column} {column_def}"),
            ))
            .await?;
            tracing::info!("域名链路列 sys_tenant_domain.{column} 已补建（存量库兜底）");
        }
    }

    // ---- 2. 默认套餐种子（menu_ids = NULL = 不限制）----
    if tenant_scalar_count(db, "sys_tenant_package").await? == 0 {
        db.execute_raw(Statement::from_string(
            backend,
            format!(
                "INSERT INTO sys_tenant_package (package_name, menu_ids, default_account_count, status, del_flag, create_by, create_time, remark) \
                 VALUES ('标准版', NULL, 0, '0', '0', 'system', {now_expr}, 'Phase3 默认套餐：menu_ids 为空即不限制功能白名单')"
            ),
        ))
        .await?;
        tracing::info!("已种入默认租户套餐「标准版」（不限制功能白名单）");
    }

    // ---- 3. tid remap（唯一不可逆点）----
    let tenants = tenant_scalar_count(db, "sys_tenant").await?;
    let mapped = tenant_scalar_count(db, "sys_tenant_migration_map").await?;
    if tenants > 0 || mapped > 0 {
        tracing::debug!(
            "Phase 3 换源已完成（sys_tenant={tenants} 行 / 映射={mapped} 行），跳过一次性 remap"
        );
        return Ok(());
    }
    if !sso_table_exists(db, "sys_dept").await? {
        return Ok(());
    }
    let roots = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT dept_id, dept_name, status FROM sys_dept \
             WHERE parent_id = 0 AND del_flag = '0' AND dept_id <> 100 ORDER BY dept_id",
        ))
        .await?;
    if roots.is_empty() {
        tracing::info!(
            "Phase 3 换源：无旧模型租户根部门（parent_id=0 且 dept_id<>100），无需 remap"
        );
        return Ok(());
    }

    // 部门父子关系（BFS 求子树；不依赖 ancestors 字段，兼容 NULL/脏数据）
    let dept_rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT dept_id, parent_id FROM sys_dept",
        ))
        .await?;
    let mut children: HashMap<i64, Vec<i64>> = HashMap::new();
    for row in &dept_rows {
        let Ok(id) = row.try_get::<i64>("", "dept_id") else {
            continue;
        };
        if let Ok(Some(pid)) = row.try_get::<Option<i64>>("", "parent_id") {
            children.entry(pid).or_default().push(id);
        }
    }
    // 改写范围：逐个探测列存在性（极旧库后加表可能还没有 tenant_id 列）
    let mut remap_tables: Vec<&str> = Vec::new();
    for t in TENANT_CARRYING_TABLES {
        if sso_table_exists(db, t).await? && sso_has_column(db, t, "tenant_id").await? {
            remap_tables.push(t);
        }
    }
    let default_pkg: Option<i64> = db
        .query_one_raw(Statement::from_string(
            backend,
            "SELECT package_id FROM sys_tenant_package WHERE package_name = '标准版' AND del_flag = '0' \
             ORDER BY package_id LIMIT 1"
                .to_string(),
        ))
        .await?
        .and_then(|r| r.try_get::<i64>("", "package_id").ok());

    let txn = db.begin().await?;
    let mut migrated = 0usize;
    for root in &roots {
        let Ok(root_dept_id) = root.try_get::<i64>("", "dept_id") else {
            continue;
        };
        let dept_name = root
            .try_get::<Option<String>>("", "dept_name")
            .ok()
            .flatten()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("租户{root_dept_id}"));
        let status = root
            .try_get::<Option<String>>("", "status")
            .ok()
            .flatten()
            .unwrap_or_else(|| "0".to_string());
        let code = format!("t{root_dept_id}");
        let pkg_id: Value = match default_pkg {
            Some(v) => v.into(),
            None => Value::BigInt(None),
        };
        txn.execute_raw(Statement::from_sql_and_values(
            backend,
            format!(
                "INSERT INTO sys_tenant (tenant_code, tenant_name, dept_id, package_id, account_count, status, del_flag, create_by, create_time, remark) \
                 VALUES ({}, {}, {}, {}, 0, {}, '0', 'system', {now_expr}, {})",
                ph(1),
                ph(2),
                ph(3),
                ph(4),
                ph(5),
                ph(6)
            ),
            [
                code.clone().into(),
                dept_name.clone().into(),
                root_dept_id.into(),
                pkg_id,
                status.into(),
                "Phase3 存量换源：旧模型租户根部门（dept 树根）→ 独立 tenant_id 空间".into(),
            ],
        ))
        .await?;
        let new_tid = txn
            .query_one_raw(Statement::from_sql_and_values(
                backend,
                format!(
                    "SELECT tenant_id FROM sys_tenant WHERE tenant_code = {}",
                    ph(1)
                ),
                [code.clone().into()],
            ))
            .await?
            .and_then(|r| r.try_get::<i64>("", "tenant_id").ok())
            .filter(|v| *v > 0)
            .ok_or_else(|| {
                anyhow::anyhow!("Phase 3 换源失败：tenant_code={code} 插入后回读 tenant_id 为空")
            })?;
        // 映射表与业务改写同事务写入（回滚唯一依赖，禁止清理）
        txn.execute_raw(Statement::from_sql_and_values(
            backend,
            format!(
                "INSERT INTO sys_tenant_migration_map (old_tid, new_tenant_id, create_time, remark) \
                 VALUES ({}, {}, {now_expr}, {})",
                ph(1),
                ph(2),
                ph(3)
            ),
            [
                root_dept_id.into(),
                new_tid.into(),
                "Phase3 remap：旧 tid（租户根 dept_id）→ 新 tenant_id（回滚=反向 UPDATE）".into(),
            ],
        ))
        .await?;

        // 子树 BFS（含软删部门）：顺带修复子树内 tenant_id = 0 的后代部门
        let mut subtree = vec![root_dept_id];
        let mut cursor = 0usize;
        while cursor < subtree.len() {
            let cur = subtree[cursor];
            cursor += 1;
            if let Some(kids) = children.get(&cur) {
                for k in kids {
                    if !subtree.contains(k) {
                        subtree.push(*k);
                    }
                }
            }
        }
        for chunk in subtree.chunks(200) {
            let list = chunk
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            txn.execute_raw(Statement::from_string(
                backend,
                format!("UPDATE sys_dept SET tenant_id = {new_tid} WHERE dept_id IN ({list})"),
            ))
            .await?;
            // 子树内用户：tenant_id 仍为旧 tid，或 0（Phase 2 统一归平台）→ 新 tenant_id
            txn.execute_raw(Statement::from_string(
                backend,
                format!(
                    "UPDATE sys_user SET tenant_id = {new_tid} \
                     WHERE tenant_id = {root_dept_id} OR (tenant_id = 0 AND dept_id IN ({list}))"
                ),
            ))
            .await?;
        }
        // 其余承载表（含 sys_dept / sys_user 的子树外遗留行）：旧 tid → 新 tenant_id
        for table in &remap_tables {
            txn.execute_raw(Statement::from_string(
                backend,
                format!(
                    "UPDATE {table} SET tenant_id = {new_tid} WHERE tenant_id = {root_dept_id}"
                ),
            ))
            .await?;
        }
        migrated += 1;
        tracing::info!(
            "Phase 3 换源：租户根部门 {root_dept_id}（{dept_name}）→ tenant_id={new_tid}（映射已持久化，回滚依赖）"
        );
    }
    txn.commit().await?;
    tracing::info!(
        "多租户 Phase 3 换源完成：共迁移 {migrated} 个存量租户；sys_tenant_migration_map 为回滚唯一依赖，禁止清理"
    );
    Ok(())
}

/// 多租户 Phase 3.5f 存量库兜底（与迁移 m20260925_000004_tenant_saas_governance
/// 等价，全幂等；列定义须与迁移逐列一致）：
///
/// 1) `sys_config` 增治理列 `scope` / `tenant_editable` / `visible_to_tenant`；
/// 2) `sys_oper_log` 增 `target_tenant_id`（审计目标租户列，只建列不写数据）；
/// 3) **唯一域租户化 4 项**：先幂等删旧单列唯一索引，再建 `(tenant_id, <列>)`
///    复合唯一索引；**建索引失败只告警不阻断启动**（存量数据可能存在同租户重复 key）；
/// 4) config 治理元数据 seed（幂等 UPDATE，只改治理列，不动 config_value）。
///
/// 缺此兜底时：sys_config 实体 SELECT 带治理列 → 参数配置全站 500；
/// 旧单列唯一索引仍生效 → 租户无法自建同 key 覆盖行。
async fn ensure_tenant_saas_governance(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();

    // ---- 1. 幂等补列（列名/类型/默认值须与迁移 m20260925_000004 逐列一致）----
    for (table, column, column_def) in [
        (
            "sys_config",
            "scope",
            "VARCHAR(32) NOT NULL DEFAULT 'platform_only'",
        ),
        (
            "sys_config",
            "tenant_editable",
            "VARCHAR(1) NOT NULL DEFAULT '0'",
        ),
        (
            "sys_config",
            "visible_to_tenant",
            "VARCHAR(1) NOT NULL DEFAULT '0'",
        ),
        ("sys_oper_log", "target_tenant_id", "BIGINT NULL"),
    ] {
        if !sso_table_exists(db, table).await? || sso_has_column(db, table, column).await? {
            continue;
        }
        db.execute_raw(Statement::from_string(
            backend,
            format!("ALTER TABLE {table} ADD COLUMN {column} {column_def}"),
        ))
        .await?;
        tracing::info!("多租户 SaaS 治理列 {table}.{column} 已补建（存量库兜底）");
    }

    // ---- 2. 唯一域租户化 4 项（先删旧单列唯一，再建复合唯一）----
    for (table, old_index, new_index, columns) in [
        (
            "sys_role",
            "uk_sys_role_key",
            "uk_sys_role_tenant_key",
            "tenant_id, role_key",
        ),
        (
            "sys_user",
            "idx_sys_user_scim_external_id",
            "uk_sys_user_tenant_scim",
            "tenant_id, scim_external_id",
        ),
        (
            "sys_config",
            "uk_sys_config_key",
            "uk_sys_config_tenant_key",
            "tenant_id, config_key",
        ),
        (
            "sys_dict_type",
            "uk_sys_dict_type",
            "uk_sys_dict_type_tenant",
            "tenant_id, dict_type",
        ),
    ] {
        if !sso_table_exists(db, table).await? {
            continue;
        }
        drop_tenant_index(db, table, old_index).await?;
        if let Err(e) = ensure_tenant_index(db, table, new_index, columns, true).await {
            tracing::warn!(
                "Phase 3.5f 唯一索引 {new_index} 创建失败（存量数据可能存在同租户重复 key，不阻断启动，请人工核查）: {e}"
            );
        }
    }

    // ---- 3. config 治理元数据 seed（幂等 UPDATE，只改治理列）----
    if sso_table_exists(db, "sys_config").await? {
        // 按覆盖策略分组做幂等 UPDATE：每组的 (scope, tenant_editable, visible_to_tenant)
        // 三元组由共享注册表的 `Coverage` 单一事实源给出 ⇒ **新增治理域无需改本函数**
        // （此前是两个硬编码 SQL 分支，新增一档就要再来一个分支）。
        // 只改治理列，**绝不动 `config_value`**：平台运维已调过的值不被启动流程覆盖。
        for coverage in [
            governance::Coverage::Locked,
            governance::Coverage::Free,
            governance::Coverage::Ceiling,
            governance::Coverage::Private,
        ] {
            let keys: Vec<String> = governance::keys_with_coverage(coverage)
                .map(|k| format!("'{k}'"))
                .collect();
            if keys.is_empty() {
                continue;
            }
            db.execute_raw(Statement::from_string(
                backend,
                format!(
                    "UPDATE sys_config SET scope = '{}', tenant_editable = '{}', \
                     visible_to_tenant = '{}' WHERE config_key IN ({})",
                    coverage.scope(),
                    coverage.tenant_editable(),
                    coverage.visible_to_tenant(),
                    keys.join(", ")
                ),
            ))
            .await?;
        }
    }

    tracing::info!("多租户 Phase 3 SaaS 治理模块已就绪（幂等确保完成）");
    Ok(())
}

/// 3.5g 多租户 Phase 3.5g 存量库兜底：与迁移 `m20260925_000005_tenant_unique_scope`
/// 等价（**双写关系，修改时必须两处同步**——启动不跑 `Migrator::up`）。
///
/// 剩余唯一域租户化 2 项（先删旧单列唯一，再建含 tenant_id 的复合唯一）：
/// - `sys_flow_task`：业务键唯一（biz_type/biz_id/...）改为租户内唯一；
/// - `sys_scim_group`：`external_id`（IdP 标识）改为租户内唯一。
///
/// 缺此兜底时：不同租户使用相同业务键 / externalId 会互相顶撞（第二个租户写入失败）。
async fn ensure_tenant_unique_scope(db: &DatabaseConnection) -> anyhow::Result<()> {
    for (table, old_index, new_index, columns) in [
        (
            "sys_flow_task",
            "uk_flow_task_biz",
            "uk_flow_task_tenant_biz",
            "tenant_id, biz_type, biz_id, round_no, node_seq, assignee_id",
        ),
        (
            "sys_scim_group",
            "uk_scim_group_external_id",
            "uk_scim_group_tenant_external",
            "tenant_id, external_id",
        ),
    ] {
        if !sso_table_exists(db, table).await? {
            continue;
        }
        drop_tenant_index(db, table, old_index).await?;
        if let Err(e) = ensure_tenant_index(db, table, new_index, columns, true).await {
            tracing::warn!(
                "Phase 3.5g 唯一索引 {new_index} 创建失败（存量数据可能存在同租户重复键，不阻断启动，请人工核查）: {e}"
            );
        }
    }
    tracing::info!("多租户 Phase 3.5g 唯一域租户化模块已就绪（幂等确保完成）");
    Ok(())
}

/// Phase 3.5h 租户角色菜单治理回填（存量库兜底，幂等）：**一剔一补**。
///
/// ① **剔除**平台专属菜单：除能力位已解锁者外，全部平台专属前缀
///    （`system:tenant:domain:*` / `tool:gen:*` / `monitor:cache:*` …）整体为平台专属
///    （服务层对租户一律 403），存量租户管理员角色因继承平台普通角色而持有
///    `domain:list` / `domain:verify` → "菜单可见但请求一律 403"的假入口，
///    此处从非平台租户角色中移除该前缀菜单授权（幂等，重复执行为 0 行）。
///
///    **能力位感知（2026-09-26 批次 1c，批次 2 升级为 perms 粒度）**：剔除条件 =
///    命中 `PLATFORM_ONLY_PERM_PREFIXES` **且** 不在
///    `common::features::unlocked_capability_perms` 内。否则平台开启
///    `tenant.domain_self_service` 并授出域名菜单后，**每次重启都会把授权收回**，
///    能力位形同虚设。默认（全关）下解锁清单为空 ⇒ 剔除清单 = 全量 ⇒ 与改造前逐条等价。
///
///    必须 **perms 粒度**而非前缀粒度：`system:backup:` 是部分解锁前缀
///    （只读 3 条 + 导出 1 条可下放，创建/恢复/删除仍平台专属），按前缀粒度会把这些
///    危险菜单一并"免剔 + 回填"给 role 2，重造假入口（见 `unlocked_capability_perms` 文档）。
///
///    ①' **回填**（与①严格对称）：把**解锁清单内**的 perms 对应菜单重新授予
///    **平台普通角色（role_id=2）**——role 2 是"新建租户默认管理员角色"的
///    菜单模板（见 `sys_tenant_service::tenant_role_menu_ids`），缺它则能力位开启后
///    新建租户仍拿不到租户自助页面。**只回填 role 2**，不回填存量租户角色
///    （那等于静默给存量租户扩权；存量租户的授权由管理员按需授予）。
///
/// ② **补齐**租户自助能力按钮：租户默认管理员角色的菜单 = 平台普通角色菜单 ∩ 套餐白名单，
///    而平台普通角色只有 config/dict 的 list/query，缺 add/edit/remove 按钮 perms →
///    存量租户自建字典类型 / 覆盖 `platform_default` 键 / 自建 `tenant_private` 键的
///    写入链路一律 403（链路断裂）。新建租户已由 `SysTenantService::add` 并入
///    [`TENANT_SELF_SERVICE_PERMS`]，存量租户在此回填：
///    - **最小补齐**：仅补缺失授权，不回收①以外的任何已有授权；
///    - 候选角色 = 非平台租户（`tenant_id <> 0`）、未删除、且已持有 dict/config
///      **列表**菜单的"管理型角色"（只读角色不会因此获得写权限）；
///    - 受套餐白名单约束（`menu_ids` 为空 = 不限制；非空则仅补白名单内菜单）。
///
/// 无迁移孪生：纯数据治理修复（依赖 sys_menu 实时 perms 集合与租户角色现状），非 schema 变更。
async fn ensure_tenant_role_menu_governance(db: &DatabaseConnection) -> anyhow::Result<()> {
    let self_service_perms = crate::service::sys_tenant_service::TENANT_SELF_SERVICE_PERMS;
    // 台账 F-4/F-5（原则 B）：平台专属能力 perms 前缀统一清单。
    // 剔除 = 命中前缀 **且** 不在解锁清单内；回填 = 在解锁清单内（二者的唯一事实源，
    // 见 `common::features::unlocked_capability_perms` 的文档）。
    let platform_features = crate::common::features::platform_features();
    let unlocked_perms = crate::common::features::unlocked_capability_perms(platform_features);
    let platform_only_prefixes = crate::common::tenant::PLATFORM_ONLY_PERM_PREFIXES;
    const LIST_PERMS: [&str; 2] = ["system:config:list", "system:dict:list"];

    if !sso_table_exists(db, "sys_role_menu").await?
        || !sso_table_exists(db, "sys_role").await?
        || !sso_table_exists(db, "sys_menu").await?
    {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let ph = |i: usize| -> String {
        if backend == DatabaseBackend::Postgres {
            format!("${i}")
        } else {
            "?".to_string()
        }
    };

    // ---- ① 剔除平台专属菜单（域名管理 / 代码生成 / 缓存监控 / 备份 / …）----
    // 目标角色：平台普通角色（role_id=2，只读白名单曾保底授予）+ 存量租户自建角色
    // （tenant_id <> 0，初始化时复制了平台普通角色菜单 ⇒ 残留假入口）。
    // 集中生成 LIKE 子句（**含 `perms LIKE` 列名**）：见 `common::tenant::perms_like_clause`
    // 的文档——原实现只拼裸占位符（`? OR ? …`），使本段 SQL 恒为假、DELETE 影响 0 行，
    // 导致**存量库的平台专属菜单治理从未生效**（2026-09-26 实测 role2 仍持 13 个，含 3800/3802）。
    //
    // 能力位感知（perms 粒度）：命中前缀 **且** 不在解锁清单内才剔除；
    // 解锁清单为空（默认全关）时 `NOT IN` 子句省略 ⇒ 与改造前逐条等价。
    {
        let like_clause = crate::common::tenant::perms_like_clause(platform_only_prefixes, ph);
        let mut like_values: Vec<Value> = platform_only_prefixes
            .iter()
            .map(|p| format!("{p}%").into())
            .collect();
        // 占位符编号**续接** LIKE 子句：Postgres 用 `$n`（需绝对序号），其余方言是 `?`
        // （`ph` 忽略入参，位置由 values 顺序决定）。
        let like_len = like_values.len();
        let not_in_clause =
            crate::common::features::perms_not_in_clause(&unlocked_perms, |i| ph(like_len + i))
                .map(|c| format!(" AND {c}"))
                .unwrap_or_default();
        like_values.extend(unlocked_perms.iter().map(|p| (*p).into()));
        let removed = db
            .execute_raw(Statement::from_sql_and_values(
                backend,
                format!(
                    "DELETE FROM sys_role_menu WHERE menu_id IN (\
                       SELECT menu_id FROM sys_menu WHERE ({like_clause}){not_in_clause}) \
                     AND (role_id = 2 OR role_id IN (\
                       SELECT role_id FROM sys_role WHERE tenant_id <> 0 AND del_flag = '0'))"
                ),
                like_values,
            ))
            .await?;
        if removed.rows_affected() > 0 {
            tracing::info!(
                removed = removed.rows_affected(),
                prefixes = platform_only_prefixes.len(),
                unlocked_perms = unlocked_perms.len(),
                "Phase 3.5h 已剔除平台专属菜单授权（剔除条件已按能力位 perms 粒度收窄）"
            );
        }
    }

    // ---- ①' 回填：解锁清单内的 perms → 重新授予平台普通角色（role_id=2）----
    // 与①严格对称：①剔的是"平台专属且未被能力位解锁"的面，①'补的是"已被能力位解锁"的面。
    // 只补 role 2（新建租户默认管理员角色的菜单模板），不回填存量租户角色。
    // 幂等：SQLite/MySQL 用 `INSERT OR IGNORE` / `INSERT IGNORE`，Postgres 用
    // `ON CONFLICT DO NOTHING`，配合 `sys_role_menu` 的 (role_id, menu_id) 主键，
    // 重复执行 0 行。
    if !unlocked_perms.is_empty() {
        let ph_list = (1..=unlocked_perms.len())
            .map(ph)
            .collect::<Vec<_>>()
            .join(", ");
        let insert_prefix = match backend {
            DatabaseBackend::Sqlite => "INSERT OR IGNORE INTO ",
            DatabaseBackend::Postgres => "INSERT INTO ",
            DatabaseBackend::MySql => "INSERT IGNORE INTO ",
            _ => unreachable!("unknown backend"),
        };
        let conflict_suffix = if backend == DatabaseBackend::Postgres {
            " ON CONFLICT DO NOTHING"
        } else {
            ""
        };
        let granted = db
            .execute_raw(Statement::from_sql_and_values(
                backend,
                format!(
                    "{insert_prefix}sys_role_menu (role_id, menu_id) \
                     SELECT 2, menu_id FROM sys_menu \
                     WHERE del_flag = '0' AND perms IN ({ph_list})\
                     {conflict_suffix}"
                ),
                unlocked_perms
                    .iter()
                    .map(|p| (*p).into())
                    .collect::<Vec<Value>>(),
            ))
            .await?;
        tracing::info!(
            granted = granted.rows_affected(),
            perms = %unlocked_perms.join(","),
            "Phase 3.5h 已按能力位回填平台普通角色的已解锁菜单授权（perms 粒度）"
        );
    }

    // 1) 目标 perms → menu_id（仅启用、未删除；缺菜单的 perms 跳过，不阻断启动）
    let wanted: Vec<&str> = self_service_perms
        .iter()
        .chain(LIST_PERMS.iter())
        .copied()
        .collect();
    let placeholders = (1..=wanted.len()).map(ph).collect::<Vec<_>>().join(", ");
    let menu_rows = db
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            format!(
                "SELECT menu_id, perms FROM sys_menu WHERE status = '0' AND del_flag = '0' AND perms IN ({placeholders})"
            ),
            wanted.iter().map(|p| (*p).into()).collect::<Vec<Value>>(),
        ))
        .await?;
    let mut perm_menu: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for row in &menu_rows {
        let menu_id = row.try_get::<i64>("", "menu_id").ok();
        let perms = row.try_get::<Option<String>>("", "perms").ok().flatten();
        if let (Some(menu_id), Some(perms)) = (menu_id, perms) {
            perm_menu.entry(perms).or_insert(menu_id);
        }
    }
    let mut targets: Vec<i64> = self_service_perms
        .iter()
        .filter_map(|p| perm_menu.get(*p).copied())
        .collect();
    targets.sort_unstable();
    targets.dedup();
    if targets.is_empty() {
        tracing::info!("Phase 3.5h 自助能力菜单不存在，跳过权限回填");
        return Ok(());
    }
    let list_menu_ids: Vec<i64> = LIST_PERMS
        .iter()
        .filter_map(|p| perm_menu.get(*p).copied())
        .collect();
    if list_menu_ids.is_empty() {
        tracing::info!("Phase 3.5h 未找到 dict/config 列表菜单，跳过权限回填");
        return Ok(());
    }

    // 2) 候选角色：非平台、未删除、已持有列表菜单
    let list_ph = (1..=list_menu_ids.len())
        .map(ph)
        .collect::<Vec<_>>()
        .join(", ");
    let role_rows = db
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            format!(
                "SELECT DISTINCT rm.role_id AS role_id, r.tenant_id AS tenant_id \
                 FROM sys_role_menu rm \
                 JOIN sys_role r ON r.role_id = rm.role_id \
                 WHERE r.tenant_id <> 0 AND r.del_flag = '0' AND rm.menu_id IN ({list_ph})"
            ),
            list_menu_ids
                .iter()
                .map(|id| (*id).into())
                .collect::<Vec<Value>>(),
        ))
        .await?;
    if role_rows.is_empty() {
        // 无候选角色（无租户角色 / 无持有 config·dict 列表菜单的管理型角色）：
        // 属正常幂等路径（新租户建租时已并入自助 perms，无需回填），
        // 但仍打日志，避免"回填是否执行过"不可观测。
        tracing::info!("Phase 3.5h 无待回填的租户管理型角色（候选为空，跳过自助权限补齐）");
        return Ok(());
    }

    // 3) 套餐白名单（None = 不限制）
    let pkg_rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT t.tenant_id AS tenant_id, p.menu_ids AS menu_ids \
             FROM sys_tenant t LEFT JOIN sys_tenant_package p ON p.package_id = t.package_id"
                .to_string(),
        ))
        .await?;
    let mut whitelist: std::collections::HashMap<i64, Option<std::collections::HashSet<i64>>> =
        std::collections::HashMap::new();
    for row in &pkg_rows {
        let Some(tid) = row.try_get::<i64>("", "tenant_id").ok() else {
            continue;
        };
        let raw = row.try_get::<Option<String>>("", "menu_ids").ok().flatten();
        // 复用服务层解析口径（空/NULL = 不限制），避免两处语义漂移
        let parsed = crate::service::sys_tenant_service::parse_menu_ids(&raw)
            .map(|ids| ids.into_iter().collect::<std::collections::HashSet<i64>>());
        whitelist.insert(tid, parsed);
    }

    // 4) 现有授权 → 差集插入
    let mut candidates: Vec<(i64, i64)> = Vec::new();
    for row in &role_rows {
        let role_id = row.try_get::<i64>("", "role_id").ok();
        let tenant_id = row.try_get::<i64>("", "tenant_id").ok();
        if let (Some(role_id), Some(tenant_id)) = (role_id, tenant_id) {
            candidates.push((role_id, tenant_id));
        }
    }
    let role_ph = (1..=candidates.len())
        .map(ph)
        .collect::<Vec<_>>()
        .join(", ");
    let granted_rows = db
        .query_all_raw(Statement::from_sql_and_values(
            backend,
            format!("SELECT role_id, menu_id FROM sys_role_menu WHERE role_id IN ({role_ph})"),
            candidates
                .iter()
                .map(|(rid, _)| (*rid).into())
                .collect::<Vec<Value>>(),
        ))
        .await?;
    let mut granted: std::collections::HashMap<i64, std::collections::HashSet<i64>> =
        std::collections::HashMap::new();
    for row in &granted_rows {
        let role_id = row.try_get::<i64>("", "role_id").ok();
        let menu_id = row.try_get::<i64>("", "menu_id").ok();
        if let (Some(role_id), Some(menu_id)) = (role_id, menu_id) {
            granted.entry(role_id).or_default().insert(menu_id);
        }
    }

    let mut inserted = 0u64;
    for (role_id, tenant_id) in candidates {
        let allowed = match whitelist.get(&tenant_id) {
            Some(Some(set)) => targets
                .iter()
                .copied()
                .filter(|id| set.contains(id))
                .collect::<Vec<i64>>(),
            // 无套餐限制（或租户行缺失）：全量补齐
            _ => targets.clone(),
        };
        for menu_id in allowed {
            if granted.get(&role_id).is_some_and(|s| s.contains(&menu_id)) {
                continue;
            }
            db.execute_raw(Statement::from_sql_and_values(
                backend,
                format!(
                    "INSERT INTO sys_role_menu (role_id, menu_id) VALUES ({}, {})",
                    ph(1),
                    ph(2)
                ),
                [role_id.into(), menu_id.into()],
            ))
            .await?;
            inserted += 1;
        }
    }
    tracing::info!(
        inserted,
        roles = granted.len(),
        "多租户 Phase 3.5h 租户角色菜单治理完成（幂等：剔除平台专属菜单 + 补齐自助按钮授权）"
    );
    Ok(())
}

/// 存量上传路径回填（3.5i，幂等）：把租户文件隔离**之前**写入的扁平引用改为租户维度。
///
/// 隔离前：文件落在 `uploads/{kind}/{key}`，DB 存 `/uploads/{kind}/{key}`；
/// 隔离后：文件落在 `uploads/{tid}/{kind}/{key}`，URL 为 `/{prefix}/{tid}/{key}`，
/// 且 `GET /uploads/*` 严格按三段解析（`{tid}/{kind}/{key}`）——旧引用段数不足会被判
/// 路径非法 → **400**（表现为全站头像破图、附件预览失败）。
///
/// 处置（逐行、幂等）：
/// - 第二段已是数字（`/uploads/{tid}/...`）→ 跳过；
/// - 目标文件已就位 → 只改写 DB 引用；
/// - 遗留文件存在而目标缺失 → 迁移文件（同盘 rename，跨盘回退 copy+delete）后改写 DB；
/// - 两侧文件都不存在 → 打 `warn` 跳过该行（改写引用只会把 400 变成 404，无收益）。
///
/// 仅 `local` 后端执行：`s3` 后端不存在扁平历史布局（对象键自隔离上线即为租户维度）。
/// 扫描列：`sys_user.avatar`（全库扫描确认唯一存在活引用的列为该列）。
async fn ensure_legacy_upload_paths(
    db: &DatabaseConnection,
    upload_cfg: &crate::config::UploadConfig,
) -> anyhow::Result<()> {
    if upload_cfg.backend != "local" {
        return Ok(());
    }
    if !sso_table_exists(db, "sys_user").await? || !sso_has_column(db, "sys_user", "avatar").await?
    {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let ph = |i: usize| -> String {
        if backend == DatabaseBackend::Postgres {
            format!("${i}")
        } else {
            "?".to_string()
        }
    };
    let rows = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT user_id, tenant_id, avatar FROM sys_user WHERE avatar LIKE '/uploads/%'"
                .to_string(),
        ))
        .await?;

    let (mut migrated, mut moved, mut skipped) = (0u64, 0u64, 0u64);
    for row in &rows {
        let Some(user_id) = row.try_get::<i64>("", "user_id").ok() else {
            continue;
        };
        let tenant_id = row.try_get::<i64>("", "tenant_id").ok().unwrap_or(0);
        let Some(avatar) = row.try_get::<Option<String>>("", "avatar").ok().flatten() else {
            continue;
        };
        let segs: Vec<&str> = avatar.trim_matches('/').split('/').collect();
        // 仅处理扁平旧式引用；其余形态（已是租户维度 / 外部 URL / 段数异常）不动
        if segs.len() != 3 || segs[0] != "uploads" || segs[1].parse::<i64>().is_ok() {
            continue;
        }
        let (kind, key) = (segs[1], segs[2]);
        let Some(dir) = crate::common::upload::resolve_kind_dir(upload_cfg, kind) else {
            tracing::warn!(user_id, avatar = %avatar, "存量上传路径回填：未知文件类别，跳过");
            skipped += 1;
            continue;
        };
        let url_prefix = if kind == "avatar" {
            upload_cfg.avatar_url_prefix.as_str()
        } else {
            upload_cfg.common_url_prefix.as_str()
        };
        if !crate::storage::valid_key(key) {
            tracing::warn!(user_id, avatar = %avatar, "存量上传路径回填：文件名非法，跳过");
            skipped += 1;
            continue;
        }

        let legacy_path = crate::common::upload::resolve_upload_dir(&dir)
            .await
            .join(key);
        let target_dir = crate::storage::dir_path(&dir, tenant_id).await;
        let target_path = target_dir.join(key);
        let (lp, td, tp) = (
            legacy_path.to_string_lossy().to_string(),
            target_dir.to_string_lossy().to_string(),
            target_path.to_string_lossy().to_string(),
        );
        let outcome = tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
            let (legacy, target) = (std::path::Path::new(&lp), std::path::Path::new(&tp));
            if target.exists() {
                return Ok(false); // 文件已就位，无需搬动
            }
            if !legacy.exists() {
                return Ok(false);
            }
            std::fs::create_dir_all(&td)?;
            if std::fs::rename(legacy, target).is_err() {
                std::fs::copy(legacy, target)?;
                std::fs::remove_file(legacy)?;
            }
            Ok(true)
        })
        .await
        .map_err(|e| anyhow::anyhow!("存量上传路径回填任务失败: {e}"))?;

        match outcome {
            Ok(did_move) => {
                if !did_move && !target_path.exists() {
                    tracing::warn!(
                        user_id,
                        avatar = %avatar,
                        "存量上传路径回填：遗留文件与目标文件均不存在，保留原引用待人工处置"
                    );
                    skipped += 1;
                    continue;
                }
                if did_move {
                    moved += 1;
                }
                let new_url = format!(
                    "{}/{}",
                    crate::storage::tenant_scoped_path(url_prefix, tenant_id).trim_end_matches('/'),
                    key
                );
                db.execute_raw(Statement::from_sql_and_values(
                    backend,
                    format!(
                        "UPDATE sys_user SET avatar = {} WHERE user_id = {}",
                        ph(1),
                        ph(2)
                    ),
                    [new_url.into(), user_id.into()],
                ))
                .await?;
                migrated += 1;
            }
            Err(e) => {
                tracing::warn!(user_id, avatar = %avatar, error = %e, "存量上传路径回填：文件迁移失败，跳过该行");
                skipped += 1;
            }
        }
    }

    tracing::info!(
        migrated,
        moved,
        skipped,
        scanned = rows.len(),
        "存量上传路径回填完成（幂等：扁平 uploads/kind/key → prefix/tid/key，缺 tid 段的历史引用已租户化）"
    );
    Ok(())
}

/// 方言感知的幂等删索引：SQLite/PostgreSQL 用 `DROP INDEX IF EXISTS`；
/// MySQL 无该从句，先查 information_schema.statistics 判存在再 `DROP INDEX ... ON table`。
async fn drop_tenant_index(
    db: &DatabaseConnection,
    table: &str,
    index_name: &str,
) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    match backend {
        DatabaseBackend::MySql => {
            let exists = db
                .query_all_raw(Statement::from_string(
                    backend,
                    format!(
                        "SELECT 1 FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='{table}' AND index_name='{index_name}' LIMIT 1"
                    ),
                ))
                .await?;
            if !exists.is_empty() {
                db.execute_raw(Statement::from_string(
                    backend,
                    format!("DROP INDEX {index_name} ON {table}"),
                ))
                .await?;
            }
            Ok(())
        }
        _ => {
            db.execute_raw(Statement::from_string(
                backend,
                format!("DROP INDEX IF EXISTS {index_name}"),
            ))
            .await?;
            Ok(())
        }
    }
}

/// 标量计数（三方言；表不存在时返回 0，供幂等探测用）
async fn tenant_scalar_count(db: &DatabaseConnection, table: &str) -> anyhow::Result<i64> {
    if !sso_table_exists(db, table).await? {
        return Ok(0);
    }
    let backend = db.get_database_backend();
    let row = db
        .query_one_raw(Statement::from_string(
            backend,
            format!("SELECT COUNT(*) AS c FROM {table}"),
        ))
        .await?;
    Ok(row
        .and_then(|r| r.try_get::<i64>("", "c").ok())
        .unwrap_or(0))
}

/// 方言感知的幂等索引创建：SQLite/PostgreSQL 直接 `CREATE INDEX IF NOT EXISTS`；
/// MySQL 不支持该子句，先查 information_schema.statistics 判存在，缺失才建
/// （补齐此前"MySQL 跳过、依赖 migration 补齐"的方言缺口——存量库不跑 migration）。
/// `unique = true` 时建 `CREATE UNIQUE INDEX`。
async fn ensure_tenant_index(
    db: &DatabaseConnection,
    table: &str,
    index_name: &str,
    columns: &str,
    unique: bool,
) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    let kind = if unique { "UNIQUE " } else { "" };
    match backend {
        DatabaseBackend::MySql => {
            let exists = db
                .query_all_raw(Statement::from_string(
                    backend,
                    format!(
                        "SELECT 1 FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='{table}' AND index_name='{index_name}' LIMIT 1"
                    ),
                ))
                .await?;
            if !exists.is_empty() {
                return Ok(());
            }
            db.execute_raw(Statement::from_string(
                backend,
                format!("CREATE {kind}INDEX {index_name} ON {table} ({columns})"),
            ))
            .await?;
            Ok(())
        }
        _ => {
            db.execute_raw(Statement::from_string(
                backend,
                format!("CREATE {kind}INDEX IF NOT EXISTS {index_name} ON {table} ({columns})"),
            ))
            .await?;
            Ok(())
        }
    }
}

/// E2-a 性能索引兜底（等价迁移 `m20261002_000001_perf_indexes` + `m20261004_000001_alert_rule_index`，幂等）：
/// - `idx_flow_doc_tenant ON flow_demo_doc (tenant_id)`
/// - `idx_web_hook_log_status ON sys_web_hook_log (status)`
/// - `idx_web_hook_log_event_type ON sys_web_hook_log (event_type)`
/// - `idx_alert_rule_enabled ON sys_alert_rule (enabled)`
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，缺索引仅影响
/// 查询性能（列表分页/过滤全表扫描），故创建失败只告警不阻断（与 Phase 3 索引兜底
/// 同策略）。表不存在时（如对应模块建表迁移未应用过的极老存量库）跳过对应索引。
/// 方言：经 `ensure_tenant_index` 收敛——SQLite/PG 直接 `CREATE INDEX IF NOT EXISTS`，
/// MySQL 先查 information_schema 判存在，缺失才建。
async fn ensure_perf_indexes(db: &DatabaseConnection) -> anyhow::Result<()> {
    let targets: &[(&str, &str, &str)] = &[
        ("flow_demo_doc", "idx_flow_doc_tenant", "tenant_id"),
        ("sys_web_hook_log", "idx_web_hook_log_status", "status"),
        (
            "sys_web_hook_log",
            "idx_web_hook_log_event_type",
            "event_type",
        ),
        ("sys_alert_rule", "idx_alert_rule_enabled", "enabled"),
    ];
    for (table, index, cols) in targets {
        if !sso_table_exists(db, table).await? {
            tracing::debug!("性能索引 {index} 跳过（表 {table} 不存在）");
            continue;
        }
        if let Err(e) = ensure_tenant_index(db, table, index, cols, false).await {
            tracing::warn!("性能索引 {index} 创建失败（不阻断启动，请人工核查）: {e}");
        }
    }
    tracing::info!("性能索引兜底完成（flow_demo_doc / sys_web_hook_log / sys_alert_rule，幂等）");
    Ok(())
}

/// 幂等检查表是否存在（三方言）
pub(crate) async fn sso_table_exists(db: &DatabaseConnection, table: &str) -> anyhow::Result<bool> {
    let backend = db.get_database_backend();

    let sql = match backend {
        DatabaseBackend::Sqlite => {
            format!("SELECT 1 FROM sqlite_master WHERE type='table' AND name='{table}'")
        }
        DatabaseBackend::Postgres => format!(
            "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema=current_schema() LIMIT 1"
        ),
        DatabaseBackend::MySql => format!(
            "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema=DATABASE() LIMIT 1"
        ),
        _ => unreachable!("unknown backend"),
    };
    Ok(!db
        .query_all_raw(Statement::from_string(backend, sql))
        .await?
        .is_empty())
}

/// 幂等检查列是否存在（三方言）
pub(crate) async fn sso_has_column(
    db: &DatabaseConnection,
    table: &str,
    column: &str,
) -> anyhow::Result<bool> {
    let backend = db.get_database_backend();
    let rows = match backend {
        DatabaseBackend::Sqlite => {
            db.query_all_raw(Statement::from_string(
                backend,
                format!("PRAGMA table_info({table})"),
            ))
            .await?
        }
        _ => {
            let schema = if backend == DatabaseBackend::Postgres {
                "table_schema=current_schema()"
            } else {
                "table_schema=DATABASE()"
            };
            db.query_all_raw(Statement::from_string(
                backend,
                format!("SELECT 1 FROM information_schema.columns WHERE table_name='{table}' AND column_name='{column}' AND {schema} LIMIT 1"),
            ))
            .await?
        }
    };
    if backend == DatabaseBackend::Sqlite {
        Ok(rows.iter().any(|row| {
            row.try_get::<String>("", "name")
                .map(|n| n.eq_ignore_ascii_case(column))
                .unwrap_or(false)
        }))
    } else {
        Ok(!rows.is_empty())
    }
}

/// v4 加固：幂等确保 SSO 表新列与存量数据回填（等价 m20260923_000001_sso_v4_hardening）
///
/// - sys_oauth_client：+ update_by / + del_flag（客户端软删，v2-K7/P1-5）
/// - sys_oauth_consent：auth_time → consented_at 更名（v4-R4 语义修正）、
///   + client_name_snapshot（v4-R6 名称快照）、+ del_flag（撤销=软删，v2-I7）
/// - 存量回填：consented_at ← create_time；client_name_snapshot ← 当前客户端名；
///   grant_types 去除未实现的 refresh_token（v4 §1.2）
/// - 存量明文 id_token_secret 以 `CONFIG_ENC_KEY` 加密（v3-P1'-4，读到一条加密一条）
///
/// 第九批（D10）：主密钥改为**由调用方传入**（`settings.config_enc_key`），
/// 不再在本函数内 `std::env::var("CONFIG_ENC_KEY")` 直读 —— 收敛为 Settings 单一入口，
/// 未来接 KMS/HSM 只需改配置层一处（原实现绕过配置层，是密钥读取点分散的最后一处）。
async fn ensure_sso_v4_columns(
    db: &DatabaseConnection,
    config_enc_key: &str,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_client").await?
        || !sso_table_exists(db, "sys_oauth_consent").await?
    {
        tracing::info!("SSO 表尚未创建，跳过 v4 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // ---- sys_oauth_client ----
    if !sso_has_column(db, "sys_oauth_client", "update_by").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN update_by VARCHAR(64) DEFAULT ''",
        ))
        .await?;
    }
    if !sso_has_column(db, "sys_oauth_client", "del_flag").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN del_flag VARCHAR(1) NOT NULL DEFAULT '0'",
        ))
        .await?;
    }

    // ---- sys_oauth_consent：auth_time → consented_at ----
    let has_consented_at = sso_has_column(db, "sys_oauth_consent", "consented_at").await?;
    let has_auth_time = sso_has_column(db, "sys_oauth_consent", "auth_time").await?;
    if !has_consented_at && has_auth_time {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent RENAME COLUMN auth_time TO consented_at",
        ))
        .await?;
        tracing::info!("sys_oauth_consent.auth_time 已更名为 consented_at（v4-R4）");
    } else if !has_consented_at && !has_auth_time {
        // 极旧结构缺列：直接补（无可迁移数据）
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent ADD COLUMN consented_at DATETIME",
        ))
        .await?;
    }
    if !sso_has_column(db, "sys_oauth_consent", "client_name_snapshot").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent ADD COLUMN client_name_snapshot VARCHAR(128) NOT NULL DEFAULT ''",
        ))
        .await?;
    }
    if !sso_has_column(db, "sys_oauth_consent", "del_flag").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent ADD COLUMN del_flag VARCHAR(1) NOT NULL DEFAULT '0'",
        ))
        .await?;
    }

    // ---- 存量回填 ----
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_oauth_consent SET consented_at = create_time WHERE consented_at IS NULL",
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_oauth_consent SET client_name_snapshot = COALESCE(\
            (SELECT c.client_name FROM sys_oauth_client c WHERE c.client_id = sys_oauth_consent.client_id), '') \
         WHERE client_name_snapshot = ''",
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_oauth_client SET grant_types = '[\"authorization_code\"]' \
         WHERE grant_types LIKE '%refresh_token%'",
    ))
    .await?;

    // ---- 存量明文 id_token_secret 加密（fail-open：主密钥未配置时跳过，留待配置后回填）----
    //
    // ⚠️ 双重加密防线（第八批修复，P0）：
    // 原实现有**两个叠加缺陷**，导致每次启动把已加密值**再加密一次**（base64 膨胀 ×4/3），
    // 实测把 `id_token_secret` 单字段涨到 743 MB、全表 4.5 GB（启动缓慢如挂死），
    // 且 HS256 签名密钥被套娃加密 N 层（原密钥不可直接使用）：
    //   ① SQL 判据 `NOT LIKE 'enc:%'` **认不出 `enc2:`**（本函数的写入格式就是 `enc2:`，
    //      见 `crypto::ENCRYPTED_PREFIX_V2`）⇒ 每次启动都把这些行重新选出来；
    //   ② 加密调用用的是**无防重守卫**的 `encrypt_config_value`（`seal_sensitive_value`
    //      才有前缀守卫）⇒ 选出来就真加密一次。
    // 修复：① 判据由**共享常量**拼出（两个前缀都排除，杜绝再次漂移）；
    //       ② 写入改用带守卫的 `seal_sensitive_value`；③ 循环内再用
    //       `crypto::is_encrypted` 做一次 Rust 侧权威判定（纵深防御）。
    let backend = db.get_database_backend();
    let (p1, p2) = (
        crate::utils::crypto::ENCRYPTED_PREFIX,
        crate::utils::crypto::ENCRYPTED_PREFIX_V2,
    );
    let rows = db
        .query_all_raw(Statement::from_string(
            backend,
            format!(
                "SELECT sso_client_id, id_token_secret FROM sys_oauth_client \
                 WHERE id_token_secret != '' \
                   AND id_token_secret NOT LIKE '{p1}%' \
                   AND id_token_secret NOT LIKE '{p2}%'"
            ),
        ))
        .await?;
    if rows.is_empty() {
        return Ok(());
    }
    let enc_key = config_enc_key.to_string();
    if enc_key.is_empty() {
        tracing::warn!(
            "检测到 {} 条明文 id_token_secret，但 CONFIG_ENC_KEY 未配置，跳过加密（fail-open，与配置层策略一致）",
            rows.len()
        );
        return Ok(());
    }
    let mut encrypted = 0usize;
    let (ph_enc, ph_pk) = if backend == DatabaseBackend::Postgres {
        ("$1", "$2")
    } else {
        ("?", "?")
    };
    for row in rows {
        let Ok(pk) = row.try_get::<i64>("", "sso_client_id") else {
            continue;
        };
        let Ok(plain) = row.try_get::<String>("", "id_token_secret") else {
            continue;
        };
        // Rust 侧权威判定：已加密（enc:/enc2:）一律跳过，避免任何 SQL 判据漂移导致双重加密
        if crate::utils::crypto::is_encrypted(&plain) {
            continue;
        }
        match crate::utils::crypto::seal_sensitive_value(&plain, &enc_key) {
            Ok(enc) => {
                db.execute_raw(Statement::from_sql_and_values(
                    backend,
                    format!(
                        "UPDATE sys_oauth_client SET id_token_secret = {ph_enc} WHERE sso_client_id = {ph_pk}"
                    ),
                    [enc.into(), pk.into()],
                ))
                .await?;
                encrypted += 1;
            }
            Err(e) => tracing::error!("id_token_secret 回填加密失败 sso_client_id={pk}: {e}"),
        }
    }
    if encrypted > 0 {
        tracing::info!("已加密存量明文 id_token_secret {encrypted} 条（v3-P1'-4）");
    }
    Ok(())
}

/// v4 §1.3 / §10：SSO 启动自检（仅告警，不阻断启动）
///
/// 1. SSO 启用时 issuer 必须为 https（本机回环豁免，validate_secrets 已硬校验，此处兜底告警）；
/// 2. 存量 client_id 与平台 JWT 命名空间（audience/issuer）碰撞 → 告警（新客户端已被
///    add_client 保留字校验拦截，存量只提示管理员整改）。
async fn sso_startup_self_check(db: &DatabaseConnection, settings: &Settings) {
    if !settings.sso.enabled {
        return;
    }
    if !sso_table_exists(db, "sys_oauth_client")
        .await
        .unwrap_or(false)
    {
        return;
    }
    let issuer = settings.sso.issuer.trim();
    if issuer.is_empty() {
        tracing::warn!("SSO 启动自检：issuer 未配置（SSO_ISSUER），发现文档将回退请求 base_url");
    }
    let audience = settings.jwt.audience.trim();
    let jwt_issuer = settings.jwt.issuer.trim();
    let backend = db.get_database_backend();
    for reserved in [audience, jwt_issuer] {
        if reserved.is_empty() {
            continue;
        }
        let sql =
            format!("SELECT COUNT(*) AS c FROM sys_oauth_client WHERE client_id = '{reserved}'");
        if let Ok(Some(row)) = db.query_one_raw(Statement::from_string(backend, sql)).await {
            let count = row.try_get::<i64>("", "c").unwrap_or(0);
            if count > 0 {
                tracing::warn!(
                    "SSO 启动自检：存在与平台 JWT 命名空间撞名的 client_id='{reserved}'，请尽快整改（v4 §1.3）"
                );
            }
        }
    }
}

/// 台账 MT-4 / E-2（第十批）：域名链路「**静默失效**」启动自检。
///
/// ## 为什么需要它
/// `middleware/tenant_host.rs` 仅在**直连 peer ∈ `server.trusted_proxies`** 时采信
/// `X-Tenant-Code` / `Host`；若生产反代未把网关 IP 段写入该白名单，域名链路会
/// **静默退化**为 `HostTenant(None)`（无异常、无日志、页面照常）——排障成本极高。
///
/// ## 判据（只报"确定不一致"的组合）
/// `trusted_proxies` 为空 **且** `sys_tenant_domain` 存在启用中的绑定行
/// ⇒ 已配置租户域名却永不生效。此组合在开发/单机环境属**正常**
/// （未部署反代、无域名绑定），故仅在"确有域名绑定"时才告警，避免噪音。
///
/// ## 边界
/// - **仅告警不阻断**（与 3.7 SSO 自检同口径：存量部署允许先启动后整改）；
/// - 数据隔离**不因此失效**：JWT `tid` 经 `common::tenant::tenant_scope` 仍强制过滤，
///   降级仅失去"按 host 判定租户 / host×tid 一致性校验"，不产生跨租户数据泄漏；
/// - 表缺失 / 查询失败一律静默返回（本函数绝不影响启动）。
///
/// 返回值：**已告警时**返回可解析的域名绑定数（`Some(count)`），否则 `None`。
/// "可解析"口径与 `find_active_by_domain` 一致（`del_flag='0' + status='0' + verify_status='1'`）。
/// 之所以把"是否告警"作为返回值暴露，是为了让本自检**可被断言**（见
/// `tenant_host_chain_self_check_tests`）——只写日志的检查无法证伪。
async fn tenant_host_chain_self_check(
    db: &DatabaseConnection,
    trusted_proxies: &[String],
) -> Option<i64> {
    if !trusted_proxies.is_empty() {
        return None;
    }
    if !sso_table_exists(db, "sys_tenant_domain")
        .await
        .unwrap_or(false)
    {
        return None;
    }
    // 口径与真实的 host→tid 解析源严格一致（`SysTenantDomainRepository::find_active_by_domain`：
    // del_flag='0' + status='0' + verify_status='1'）——只有"**可解析**的绑定"配合空白名单
    // 才是**确定**的静默失效；未验证/已停用的绑定不参与解析，不应产生误报。
    let sql = "SELECT COUNT(*) AS c FROM sys_tenant_domain \
               WHERE del_flag = '0' AND status = '0' AND verify_status = '1'";
    if let Ok(Some(row)) = db
        .query_one_raw(Statement::from_string(db.get_database_backend(), sql))
        .await
    {
        let count = row.try_get::<i64>("", "c").unwrap_or(0);
        if count > 0 {
            tracing::warn!(
                active_domains = count,
                "域名链路自检：server.trusted_proxies 为空但已存在 {count} 条**可解析**的租户域名绑定\
                 （启用 + 已校验）⇒ host→租户 解析将**静默失效**（header 一律不采信）。请在生产反代\
                 环境中把网关 IP 段写入 server.trusted_proxies（台账 MT-4 / E-2；数据隔离不受影响，\
                 仅失去 host 维度）。"
            );
            return Some(count);
        }
    }
    None
}

/// v5-D2：为存量 RS256 客户端补生成 RSA-2048 私钥（幂等：仅处理 rsa_private_key 为
/// NULL 且 id_token_alg='RS256' 的行）。PKCS#8 PEM 按 CONFIG_ENC_KEY 信封加密落库
/// （key 未配置时明文，迁移期策略与 v5-E6 一致）；CONFIG_ENC_KEY 未配置时整体跳过。
async fn ensure_sso_rs256_keys(db: &DatabaseConnection, enc_key: &str) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_client").await? {
        return Ok(());
    }
    // v5-D2/D5：存量库启动不跑 Migrator::up——先幂等补列（id_token_alg/rsa_private_key/
    // subject_type），否则下方查询因缺列直接失败（真实运行验证发现的启动阻断）
    if !sso_has_column(db, "sys_oauth_client", "id_token_alg").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN id_token_alg VARCHAR(8) NOT NULL DEFAULT 'RS256'"
                .to_string(),
        ))
        .await?;
        tracing::info!("sys_oauth_client.id_token_alg 列已补建（v5-D2 存量库兜底）");
    }
    if !sso_has_column(db, "sys_oauth_client", "rsa_private_key").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN rsa_private_key TEXT".to_string(),
        ))
        .await?;
        tracing::info!("sys_oauth_client.rsa_private_key 列已补建（v5-D2 存量库兜底）");
    }
    if !sso_has_column(db, "sys_oauth_client", "subject_type").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN subject_type VARCHAR(8) NOT NULL DEFAULT 'public'"
                .to_string(),
        ))
        .await?;
        tracing::info!("sys_oauth_client.subject_type 列已补建（v5-D5 存量库兜底）");
    }
    if enc_key.is_empty() {
        tracing::warn!("CONFIG_ENC_KEY 未配置：跳过 RS256 密钥生成（v5-D2，下次启动重试）");
        return Ok(());
    }
    let backend = db.get_database_backend();
    let select_sql = "SELECT sso_client_id AS pk, client_id AS cid FROM sys_oauth_client \
                      WHERE rsa_private_key IS NULL AND id_token_alg = 'RS256'";
    let rows = db
        .query_all_raw(Statement::from_string(backend, select_sql))
        .await?;
    for row in rows {
        let pk = row.try_get::<i64>("", "pk").unwrap_or(0);
        let cid = row.try_get::<String>("", "cid").unwrap_or_default();
        // v5-D2 修正：keygen 在专用大栈线程执行（tokio 栈上 stack overflow 硬崩，
        // 与 sso_service::generate_rsa_private_pem 同款防护）
        let pem = match tokio::task::spawn_blocking(|| {
            crate::service::sso_service::generate_rsa_private_pem()
        })
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                tracing::error!("v5-D2 RSA 生成失败 client_id={cid}: {}", e);
                continue;
            }
            Err(e) => {
                tracing::error!("v5-D2 RSA keygen 任务失败 client_id={cid}: {}", e);
                continue;
            }
        };
        let sealed = match crate::utils::crypto::seal_sensitive_value(&pem, enc_key) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("v5-D2 RSA 私钥加密失败 client_id={cid}: {}", e);
                continue;
            }
        };
        let update_sql = format!(
            "UPDATE sys_oauth_client SET rsa_private_key = '{}' WHERE sso_client_id = {pk}",
            sealed.replace('\'', "''")
        );
        db.execute_raw(Statement::from_string(backend, update_sql))
            .await?;
        tracing::info!("v5-D2 已为存量客户端生成 RS256 密钥 client_id={cid}");
    }
    Ok(())
}

/// v5-E1：consent 组合唯一索引兜底（幂等）——清软删行、同 (user_id, client_id)
/// 去重（保留最早）、建唯一索引 uq_sso_consent_user_client。与迁移
/// m20260924_000002_sso_consent_unique 等价；索引已存在时容错跳过。
async fn ensure_sso_consent_unique(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_consent").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    // 去重 DELETE：MySQL 不允许 DELETE 目标表同时出现在子查询 FROM（1093），
    // 派生表包裹（物化）后三方言等价，与迁移侧 SQL 一致
    let dedup_sql = "DELETE FROM sys_oauth_consent WHERE consent_id NOT IN (\
         SELECT keep_id FROM (\
         SELECT MIN(consent_id) AS keep_id FROM sys_oauth_consent GROUP BY user_id, client_id\
         ) keep_rows)";
    let stmts = [
        "DELETE FROM sys_oauth_consent WHERE del_flag = '2'",
        dedup_sql,
    ];
    for sql in stmts {
        db.execute_raw(Statement::from_string(backend, sql.to_string()))
            .await?;
    }
    // 唯一索引：MySQL 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属子句），
    // 剥离子句后执行并容错"索引已存在"（1061 Duplicate key name / 42P07 / already exists）
    let idx_sql = match backend {
        DatabaseBackend::MySql => {
            "CREATE UNIQUE INDEX uq_sso_consent_user_client \
             ON sys_oauth_consent (user_id, client_id)"
        }
        _ => {
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_sso_consent_user_client \
             ON sys_oauth_consent (user_id, client_id)"
        }
    };
    if let Err(e) = db
        .execute_raw(Statement::from_string(backend, idx_sql.to_string()))
        .await
    {
        let msg = e.to_string();
        if !(msg.contains("Duplicate key name")
            || msg.contains("42P07")
            || msg.contains("already exists"))
        {
            return Err(e.into());
        }
        tracing::debug!("uq_sso_consent_user_client 已存在，跳过");
    }
    Ok(())
}

/// v5-E6：运行期敏感凭据存量明文回填（幂等）。
///
/// 范围（四组明文落库的敏感列，与 id_token_secret 同标准信封加密）：
/// - `sys_oauth_provider.client_secret`（第三方 OAuth 客户端密钥）
/// - `sys_oauth_user.access_token` / `refresh_token`（第三方用户令牌）
/// - `sys_msg_channel.config_json`（渠道配置，含 SMTP 凭据）
/// - `sys_web_hook.secret`（回调 HMAC 签名密钥）
///
/// 规则：CONFIG_ENC_KEY 未配置 → 跳过（fail-open，下次启动重试）；
/// 值已带 `enc3:` 前缀 → 跳过（已是当前格式，幂等）；`enc2:`/`enc:` 存量 →
/// 解密后以 v3 信封 re-encrypt（G-14 密钥轮换格式迁移，解密失败保持原值下轮重试）；
/// 明文/空值 → `seal_sensitive_value` 加密 UPDATE（逐行，幂等：回填后即带前缀）。
async fn ensure_runtime_secrets_encrypted(db: &DatabaseConnection, enc_key: &str) {
    if enc_key.is_empty() {
        tracing::warn!("CONFIG_ENC_KEY 未配置：跳过运行期敏感凭据存量明文回填（v5-E6）");
        return;
    }
    // (表, 主键列, 敏感列)
    const TARGETS: &[(&str, &str, &str)] = &[
        ("sys_oauth_provider", "provider_id", "client_secret"),
        ("sys_oauth_user", "oauth_id", "access_token"),
        ("sys_oauth_user", "oauth_id", "refresh_token"),
        ("sys_msg_channel", "channel_id", "config_json"),
        ("sys_web_hook", "id", "secret"),
    ];
    let backend = db.get_database_backend();
    let mut sealed_total = 0usize;
    let mut reencrypted_total = 0usize;
    for (table, pk, col) in TARGETS {
        let select_sql = format!(
            "SELECT {pk} AS pk, {col} AS val FROM {table} WHERE {col} IS NOT NULL AND {col} != ''"
        );
        let rows = match db
            .query_all_raw(Statement::from_string(backend, select_sql))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // 表可能不存在（极旧存量库），warn 并继续下一目标
                tracing::warn!("v5-E6 回填读取 {table}.{col} 失败（跳过）: {}", e);
                continue;
            }
        };
        for row in rows {
            let pk_val = match row.try_get::<i64>("", "pk") {
                Ok(v) => v,
                Err(_) => continue,
            };
            let val = match row.try_get::<String>("", "val") {
                Ok(v) => v,
                Err(_) => continue,
            };
            // G-14：已是 v3（enc3:）→ 跳过（幂等）；v1/v2（enc:/enc2:）→ unseal 后
            // 以 v3 信封 re-encrypt（密钥轮换迁移期）；明文 → seal（enc3）
            if val.starts_with("enc3:") {
                continue;
            }
            let is_legacy = val.starts_with("enc2:") || val.starts_with("enc:");
            let sealed = if is_legacy {
                // 格式迁移：解出明文再重加密（解密失败=密钥不匹配/数据损坏，
                // 保持原值不动并告警，下轮启动重试——不"修"坏数据）
                match crate::utils::crypto::decrypt_config_value(&val, enc_key)
                    .and_then(|plain| crate::utils::crypto::encrypt_config_value(&plain, enc_key))
                {
                    Ok(s) => {
                        reencrypted_total += 1;
                        s
                    }
                    Err(e) => {
                        tracing::warn!(
                            "v5-E6 存量 v1/v2 密文迁移失败（保持原值，下轮重试） {table}.{col} pk={pk_val}: {}",
                            e
                        );
                        continue;
                    }
                }
            } else {
                match crate::utils::crypto::seal_sensitive_value(&val, enc_key) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("v5-E6 回填加密失败 {table}.{col} pk={pk_val}: {}", e);
                        continue;
                    }
                }
            };
            let update_sql = format!(
                "UPDATE {table} SET {col} = '{}' WHERE {pk} = {pk_val}",
                sealed.replace('\'', "''")
            );
            if let Err(e) = db
                .execute_raw(Statement::from_string(backend, update_sql))
                .await
            {
                tracing::error!("v5-E6 回填更新失败 {table}.{col} pk={pk_val}: {}", e);
                continue;
            }
            if !is_legacy {
                sealed_total += 1;
            }
        }
    }
    if sealed_total > 0 {
        tracing::info!("v5-E6 已加密回填运行期敏感凭据 {sealed_total} 条（v5-E6）");
    }
    if reencrypted_total > 0 {
        tracing::info!(
            "G-14 密钥轮换格式迁移：v1/v2 信封已 re-encrypt 为 v3（enc3:k1）共 {reencrypted_total} 条"
        );
    }
}

/// v5-S1：SSO/OIDC 公开端点限流分档（存量库兜底，幂等）。
///
/// 与迁移 m20260924_000001_sso_rate_limit_tiers 等价：rate_limit 中间件先按
/// route_pattern 精确匹配、未命中回退 '*'；此处为不跑 Migrator::up 的存量库
/// 以「查存在 → 缺则 INSERT」补齐五条分档（应用层判存，跨 SQLite/PG/MySQL 稳定）。
/// 已有同 pattern 行（运维自调）不覆盖。生效时机：下次启动或 Redis 配置缓存过期。
async fn ensure_sso_rate_limit_tiers(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_rate_limit").await? {
        return Ok(()); // 极旧存量库无限流表（理论不可达，防御性跳过）
    }
    const TIERS: &[(&str, u32, f64, &str)] = &[
        (
            "/sso/token",
            30,
            0.5,
            "SSO 令牌兑换（机器对机器，严档防暴力试 secret）",
        ),
        (
            "/sso/authorize",
            60,
            1.0,
            "SSO 授权端点（浏览器导航，中档）",
        ),
        ("/sso/logout", 30, 0.5, "SSO 登出（低频严档）"),
        (
            "/sso/userinfo",
            120,
            2.0,
            "SSO 用户信息（RP 高频会话校验，宽档）",
        ),
        (
            "/.well-known/openid-configuration",
            60,
            1.0,
            "OIDC 发现文档（RP 启动期拉取，中档）",
        ),
    ];
    let backend = db.get_database_backend();
    for (pattern, capacity, refill, description) in TIERS {
        let count_sql =
            format!("SELECT COUNT(*) AS c FROM sys_rate_limit WHERE route_pattern = '{pattern}'");
        let exists = match db
            .query_one_raw(Statement::from_string(backend, count_sql))
            .await?
        {
            Some(row) => row.try_get::<i64>("", "c").unwrap_or(0) > 0,
            None => false,
        };
        if exists {
            continue;
        }
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let insert_sql = format!(
            "INSERT INTO sys_rate_limit (route_pattern, capacity, refill_per_second, enabled, description, create_by, create_time, update_by, update_time) \
             VALUES ('{pattern}', {capacity}, {refill}, TRUE, '{description}', 'admin', '{now}', 'admin', '{now}')"
        );
        db.execute_raw(Statement::from_string(backend, insert_sql))
            .await?;
        tracing::info!("已插入 SSO 限流分档 route_pattern={pattern}");
    }
    Ok(())
}

/// 读取一条 `SELECT COUNT(*) AS c ...` 的结果（跨方言返回 i64）。
async fn count_scalar(db: &DatabaseConnection, sql: String) -> anyhow::Result<i64> {
    let backend = db.get_database_backend();
    let row = db
        .query_one_raw(Statement::from_string(backend, sql))
        .await?;
    match row {
        Some(r) => Ok(r.try_get::<i64>("", "c").unwrap_or(0)),
        None => Ok(0),
    }
}

/// v4 §13-F1：历史 JWT 型 SSO 访问令牌一次性转写吊销（幂等 + 精准识别）。
///
/// 背景：P0-A 修复前 SSO access_token 是平台 JWT（可横扫全站业务 API），仅靠
/// auth 中间件的「`sso:at:{hash}` 绑定命中 → 拒绝」过渡阻断止血。但绑定 TTL（1h 量级）
/// 短于历史 JWT 本体 TTL（最长 24h）——绑定过期后历史 JWT 失去唯一标识，剩余窗口内
/// 仍可通行业务路由，**止血动作自毁止血范围**。
///
/// 定案（转写而非清除）：把存量 `sso:at:*` 绑定转写为
/// `blacklist:{hash}`（TTL = max(剩余TTL, 24h)）并删除原绑定 → 历史 JWT 立即全量吊销。
///
/// **精准识别（v5 核查修正）**：绑定 value 含 `access_token_hash` 字段即 A 形态
/// （不透明 AT）活跃绑定，**跳过不转写**——仅转写无该字段的历史 JWT 型绑定。
/// 消除两类误杀：① P0-A 已部署实例（6a60528）升级到本版时，存量绑定是不透明 AT；
/// ② Redis 清空导致标记丢失后重跑。
///
/// 幂等：`sso:v4_legacy_at_migrated` SETNX 标记；已标记即跳过。
/// Redis 故障时跳过转写并告警（下次启动重试）。
/// §5.17 启动期能力位授权收敛（幂等；**任何失败都不阻断启动**）。
///
/// ## 背景（为何需要启动期兜底）
///
/// 授权回收（`converge_tenant_role_menus_conn`）此前只在**套餐变更**时触发；平台层
/// `[features]` on→off（改配置重启）后，租户的"曾经可授予"授权行残留——有效能力集
/// （平台天花板 ∩ 套餐）已把该能力钳为 off，但 `sys_role_menu` 行还在 ⇒
/// "菜单可见但请求 403"的假入口数据层残留。
///
/// ## 语义
///
/// - 遍历**全部绑定套餐**的未删除租户，逐个按其套餐跑收敛核心（幂等：无收敛面零删除）；
/// - 单租户失败 WARN continue（数据清理任务，非启动必需；下次启动自然重试）；
/// - 总删除 > 0 ⇒ best-effort 失效全部 `perm:user:*` 权限缓存（授权集合已变化）；
/// - **WARN 级汇总日志**：授权行被删属不可自动回滚操作（重开能力位后需重新授权），
///   运维必须能看到本次启动删了什么。
///
/// 测试策略：核心收敛语义（回收 + 幂等）由 `integration_tests::capability_features`
/// 直驱 `converge_tenant_role_menus_conn` 覆盖；本函数为**薄编排**（查询 + 循环 +
/// 缓存失效），且全表遍历在并行共享库测试下有跨用例污染风险，故不直测。
async fn converge_tenant_grants_on_startup(db: &DatabaseConnection, store: &Arc<dyn SharedStore>) {
    use crate::entity::{sys_tenant, sys_tenant_package};
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use std::collections::HashMap;

    // 套餐小表全量载入内存（pkg_id → Model），避免逐租户回查
    let packages: Vec<sys_tenant_package::Model> = match sys_tenant_package::Entity::find()
        .filter(sys_tenant_package::Column::DelFlag.eq("0"))
        .all(db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("启动期授权收敛：查询套餐表失败（跳过，下次启动重试）: {e}");
            return;
        }
    };
    if packages.is_empty() {
        return;
    }
    let pkg_map: HashMap<i64, sys_tenant_package::Model> =
        packages.into_iter().map(|p| (p.package_id, p)).collect();

    let tenants: Vec<sys_tenant::Model> = match sys_tenant::Entity::find()
        .filter(sys_tenant::Column::DelFlag.eq("0"))
        .filter(sys_tenant::Column::PackageId.is_not_null())
        .all(db)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("启动期授权收敛：查询租户表失败（跳过，下次启动重试）: {e}");
            return;
        }
    };
    if tenants.is_empty() {
        tracing::info!("启动期授权收敛：无绑定套餐的租户，跳过");
        return;
    }

    let mut total_removed: u64 = 0;
    let mut failed: usize = 0;
    for t in &tenants {
        let Some(pkg_id) = t.package_id else { continue };
        let Some(pkg) = pkg_map.get(&pkg_id) else {
            tracing::warn!(
                tenant_id = t.tenant_id,
                package_id = pkg_id,
                "启动期授权收敛：租户绑定的套餐不存在/已删除，跳过该租户"
            );
            continue;
        };
        match crate::service::sys_tenant_service::converge_tenant_role_menus_conn(
            db,
            t.tenant_id,
            pkg,
        )
        .await
        {
            Ok(removed) => total_removed += removed,
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    tenant_id = t.tenant_id,
                    error = %e,
                    "启动期授权收敛失败（跳过该租户，不阻断启动）"
                );
            }
        }
    }

    if total_removed > 0 {
        // 授权集合已变化 ⇒ perm cache 必须失效（best-effort，对齐 menu_service 同名语义）
        let pattern = format!("{}*", crate::common::constants::PERM_CACHE_PREFIX);
        if let Ok(keys) = store.scan(&pattern, None).await
            && !keys.is_empty()
        {
            let _ = store.del(&keys).await;
        }
        tracing::warn!(
            tenants = tenants.len(),
            removed = total_removed,
            failed,
            "启动期授权收敛：回收了平台层能力位/套餐收敛面之外的角色菜单授权。\
             授权行删除不可自动回滚——重开能力位/扩白名单后需重新授权"
        );
    } else {
        tracing::info!(
            tenants = tenants.len(),
            failed,
            "启动期授权收敛：无残留不可授予授权（幂等零删除）"
        );
    }
}

pub(crate) async fn revoke_legacy_sso_at_tokens(store: &Arc<dyn SharedStore>) {
    const LEGACY_MARKER: &str = "sso:v4_legacy_at_migrated";
    const LEGACY_AT_PREFIX: &str = "sso:at:";
    /// 历史 JWT 型 SSO AT 的最大剩余寿命 = 平台 JWT TTL 上限（expire_hours ≤ 24h）
    const LEGACY_TTL_FLOOR_SECS: u64 = 86_400;
    /// 幂等标记 TTL。原实现为无 TTL 的永久 SETNX；trait 的 NX 语义统一带 TTL，
    /// 取 10 年近似"永久"（标记丢失的最坏后果 = 重跑一次幂等转写，无害）。
    const MARKER_TTL_SECS: u64 = 10 * 365 * 24 * 3600;

    // 幂等标记（SETNX；已标记即跳过转写）。store 内部已管超时/事务，无需 cmd_timeout 包裹。
    match store.set_nx_ex(LEGACY_MARKER, "1", MARKER_TTL_SECS).await {
        Err(e) => {
            tracing::warn!("v4-F1 存量转写跳过（共享态存储不可达，下次启动重试）: {e}");
            return;
        }
        Ok(false) => return, // 已标记：转写已完成
        Ok(true) => {}
    }

    // 全量扫描 sso:at:*（安全吊销必须扫到尾，禁用截断版）
    let keys = match store.scan(&format!("{LEGACY_AT_PREFIX}*"), None).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "v4-F1 存量转写 SCAN 失败（已置标记，可用 DEL {LEGACY_MARKER} 重跑）: {e}"
            );
            return;
        }
    };

    let mut migrated = 0usize;
    let mut skipped = 0usize;
    for key in &keys {
        let Some(hash) = key.strip_prefix(LEGACY_AT_PREFIX) else {
            continue;
        };
        if hash.is_empty() {
            continue;
        }
        // v5 核查：A 形态活跃绑定（value 含 access_token_hash）不转写，防误杀
        let is_legacy = store
            .get(key)
            .await
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok())
            .map(|json| !json.get("access_token_hash").is_some());
        match is_legacy {
            Some(false) => {
                skipped += 1;
                continue;
            }
            None => {
                // 读取/解析失败（key 已过期或 value 异常）→ 按过期清理处理
            }
            _ => {}
        }
        // TTL 语义：原实现 effective_ttl = max(剩余TTL, 24h) ≥ 24h；trait 未暴露 TTL 读数，
        // 统一取下界 24h（对已失效/不存在键多吊销一段 hash 属 fail-safe，无越权风险）。
        let effective_ttl = LEGACY_TTL_FLOOR_SECS;
        let expire_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
            + effective_ttl as i64;
        // blacklist 登记（redis 档 = SETEX + DB 权威层双写；local 档 = INSERT 权威层）
        let set = store.revocation_add(hash, expire_at, "sso_legacy_at").await;
        match set {
            Ok(()) => {
                // 绑定转写成功后删除原 key：userinfo（只认绑定）与业务路由（认 blacklist）
                // 双路径同时立即 401
                let _ = store.del(std::slice::from_ref(key)).await;
                migrated += 1;
            }
            Err(e) => {
                tracing::warn!("v4-F1 绑定 {} 转写失败（跳过，下次启动重试）: {e}", key);
            }
        }
    }
    if migrated > 0 {
        tracing::info!(
            "v4-F1 已转写吊销历史 JWT 型 SSO 访问令牌 {migrated} 条（blacklist，TTL≥24h）"
        );
    }
    if skipped > 0 {
        tracing::info!("v4-F1 跳过 A 形态活跃绑定 {skipped} 条（含 access_token_hash，不转写）");
    }
}

/// 幂等确保 PAT 管理菜单存在（Tier-S #3）
///
/// 背景同 `ensure_sys_pat_table`：存量库启动不跑 Migrator::up，m20260823_000001_sys_pat
/// 迁移登记的 sys_menu（页 3560 + 按钮 3561）不会落到已有库。此处以等价的检查-后-插入补齐，
/// 使管理员页 /monitor/pat 在存量库上同样可经"系统监控"菜单进入并被 E2E 覆盖。
/// 超管用户可见全部菜单（不依赖 sys_role_menu），role_id=2 的授权仅为与普通角色对齐。
async fn ensure_sys_pat_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
    let backend = db.get_database_backend();
    // sys_menu 表存在性保护：空库未建表时跳过，交由 migration 负责初始种子
    let exists_sql = match backend {
        DatabaseBackend::Sqlite => {
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sys_menu'".to_string()
        }
        DatabaseBackend::Postgres => {
            "SELECT 1 FROM information_schema.tables WHERE table_name='sys_menu' AND table_schema=current_schema() LIMIT 1".to_string()
        }
        DatabaseBackend::MySql => {
            "SELECT 1 FROM information_schema.tables WHERE table_name='sys_menu' AND table_schema=DATABASE() LIMIT 1".to_string()
        }
        _ => unreachable!("unknown backend"),
    };
    if !db
        .query_all_raw(Statement::from_string(backend, exists_sql))
        .await?
        .is_empty()
    {
        let ts = crate::common::datetime::now_naive()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        // 页菜单 3560
        if count_scalar(
            db,
            "SELECT COUNT(*) AS c FROM sys_menu WHERE menu_id=3560".to_string(),
        )
        .await?
            == 0
        {
            db.execute_raw(Statement::from_string(
                backend,
                format!(
                    "INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) \
                     VALUES (3560, 'API 令牌', 2, 11, 'pat', 'monitor/pat/index', '', '', '1', '0', 'C', '0', '0', 'monitor:pat:list', 'key', 'admin', '{ts}', '个人访问令牌统一管理', '0', 'menu.pat')"
                ),
            ))
            .await?;
            tracing::info!("已登记 PAT 管理页菜单 (menu_id=3560)");
        }

        // 按钮 3561
        if count_scalar(
            db,
            "SELECT COUNT(*) AS c FROM sys_menu WHERE menu_id=3561".to_string(),
        )
        .await?
            == 0
        {
            db.execute_raw(Statement::from_string(
                backend,
                format!(
                    "INSERT INTO sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) \
                     VALUES (3561, '吊销', 3560, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'monitor:pat:revoke', 'delete', 'admin', '{ts}', '吊销指定用户的访问令牌', '0', '')"
                ),
            ))
            .await?;
            tracing::info!("已登记 PAT 吊销按钮 (menu_id=3561)");
        }

        // role_id=2（普通角色）授权，与迁移对齐；超管无需授权即可见全部菜单
        for mid in [3560i64, 3561] {
            if count_scalar(
                db,
                format!(
                    "SELECT COUNT(*) AS c FROM sys_role_menu WHERE role_id=2 AND menu_id={mid}"
                ),
            )
            .await?
                == 0
            {
                db.execute_raw(Statement::from_string(
                    backend,
                    format!("INSERT INTO sys_role_menu (role_id, menu_id) VALUES (2, {mid})"),
                ))
                .await?;
            }
        }
    }
    Ok(())
}

/// 台账 P0-2（存量库兜底，等价迁移 m20260926_000001）：`sys_role.is_system` 列 +
/// 平台 admin 角色标记。
///
/// 超管判定已改为 `is_system && tenant_id == 0`（`entity/sys_role.rs`），实体 SELECT
/// 会带 `is_system` 列 ⇒ 存量库缺列时角色/菜单/权限接口全站 500。
/// 回填为**不变量**（每次启动收敛）：平台租户（tid=0）的 `admin` 角色必须为系统角色。
async fn ensure_role_is_system_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_role").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    // boolean 字面量按方言书写：PG 不接受 0/1 作为 boolean 默认值
    let (false_lit, true_lit) = if backend == DatabaseBackend::Postgres {
        ("FALSE", "TRUE")
    } else {
        ("0", "1")
    };
    if !sso_has_column(db, "sys_role", "is_system").await? {
        db.execute_raw(Statement::from_string(
            backend,
            format!(
                "ALTER TABLE sys_role ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT {false_lit}"
            ),
        ))
        .await?;
        tracing::info!("sys_role.is_system 列已补建（台账 P0-2 存量库兜底）");
    }
    let updated = db
        .execute_raw(Statement::from_string(
            backend,
            format!(
                "UPDATE sys_role SET is_system = {true_lit} \
                 WHERE tenant_id = 0 AND role_key = 'admin' AND del_flag = '0'"
            ),
        ))
        .await?;
    if updated.rows_affected() > 0 {
        tracing::info!(
            rows = updated.rows_affected(),
            "平台 admin 角色已标记为系统角色（is_system=1）"
        );
    }
    Ok(())
}

/// 台账 F-8（存量库兜底，等价迁移 m20260926_000003）：`sys_logininfor.user_id` 列 +
/// 索引 + 按 user_name 精确回填（未匹配置 0；user_name 全局唯一 ⇒ 回填无歧义）。
///
/// 列定义 `BIGINT NOT NULL DEFAULT 0`：0 为"无对应用户"的唯一缺省表示（与 `tenant_id` 同款）。
/// 回填仅在**列刚补建**时执行一次（迁移库已回填；避免每次启动全表扫描）。
async fn ensure_logininfor_user_id_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_logininfor").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    if sso_has_column(db, "sys_logininfor", "user_id").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        backend,
        "ALTER TABLE sys_logininfor ADD COLUMN user_id BIGINT NOT NULL DEFAULT 0".to_string(),
    ))
    .await?;
    if let Err(e) = db
        .execute_raw(Statement::from_string(
            backend,
            "CREATE INDEX idx_sys_logininfor_user ON sys_logininfor (user_id)".to_string(),
        ))
        .await
    {
        // 索引已存在（MySQL 1061 / PG 42P07 / SQLite already exists）不影响后续
        tracing::warn!("sys_logininfor user_id 索引创建跳过: {}", e);
    }
    let updated = db
        .execute_raw(Statement::from_string(
            backend,
            "UPDATE sys_logininfor SET user_id = COALESCE(\
               (SELECT MIN(u.user_id) FROM sys_user u WHERE u.user_name = sys_logininfor.user_name)\
               , 0) WHERE user_name IS NOT NULL"
                .to_string(),
        ))
        .await?;
    tracing::info!(
        rows = updated.rows_affected(),
        "sys_logininfor.user_id 列已补建并完成存量回填（台账 F-8 存量库兜底）"
    );
    Ok(())
}

/// 台账 D9（存量库兜底，等价迁移 m20260926_000004）：`sys_oauth_client.key_id`
/// 密钥版本列（RS256 密钥轮换预备；历史密钥留 NULL = 未登记版本）。
async fn ensure_oauth_client_key_id_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_client").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_oauth_client", "key_id").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_oauth_client ADD COLUMN key_id VARCHAR(64) NULL".to_string(),
    ))
    .await?;
    tracing::info!("sys_oauth_client.key_id 列已补建（台账 D9 存量库兜底）");
    Ok(())
}

/// SSO D9（存量库兜底，等价迁移 `m20260927_000001`）：`sys_oauth_client.previous_client_secret_hash`
/// —— `client_secret` 零停机轮换的"双密钥读取期"列。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已声明该列
/// ⇒ 缺此兜底则客户端列表/详情/令牌端点鉴权全链报 `no such column: previous_client_secret_hash`（500）。
/// 幂等：列已存在或表不存在时安全返回；存量行留 `NULL` = 无过渡期 = 行为与改造前逐字节一致。
async fn ensure_oauth_client_prev_secret_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_client").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_oauth_client", "previous_client_secret_hash").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_oauth_client ADD COLUMN previous_client_secret_hash VARCHAR(64) NULL"
            .to_string(),
    ))
    .await?;
    tracing::info!("sys_oauth_client.previous_client_secret_hash 列已补建（SSO D9 存量库兜底）");
    Ok(())
}

/// G-09（存量库兜底，等价迁移 `m20261007_000001`）：`sys_job_log.duration_ms`
/// 独立耗时列——定时任务运行统计报表的聚合基础。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已声明该列
/// ⇒ 缺此兜底则调度日志写入/查询全链报 `no such column: duration_ms`（500）。
/// 幂等：列已存在或表不存在时安全返回；存量行留 `NULL` = 无耗时数据，报表聚合跳过。
async fn ensure_job_log_duration_column(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_job_log").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_job_log", "duration_ms").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_job_log ADD COLUMN duration_ms BIGINT NULL".to_string(),
    ))
    .await?;
    tracing::info!("sys_job_log.duration_ms 列已补建（G-09 存量库兜底）");
    Ok(())
}

/// G-16（平台默认消息模板 seed，幂等；UNIQUE(template_code) 冲突即忽略）
///
/// - `notice_email`：通知公告邮件正文骨架（channel_code='email' 仅表达用途；
///   公告邮件有自带的用户枚举/偏好过滤/批量投递链路，不经过 send() 的渠道查找）。
///   变量 {{title}}/{{content}}/{{footer}} 均由调用方 html_escape 后注入。
/// - `report_push`：报表订阅站内信模板（site 渠道，经 SysMsgService::send 统一
///   投递内核——尊重用户消息偏好/免打扰 + 失败进重试链）。
///
/// 表不存在（极旧存量库）时跳过；与代码侧"模板缺失回落内置默认"双保险。
async fn ensure_msg_template_seeds(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_msg_template").await? {
        return Ok(());
    }
    let now = flow_now(db);
    // 公告邮件正文骨架（与 sys_notice_service 内置回落内容保持一致）
    let notice_email_content = "<div style=\"font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px;\">\
<h2 style=\"color: #409EFF; border-bottom: 2px solid #409EFF; padding-bottom: 10px;\">{{title}}</h2>\
<div style=\"margin: 20px 0;\">{{content}}</div>\
<hr style=\"border: none; border-top: 1px solid #ddd; margin: 20px 0;\"/>\
<p style=\"color: #999; font-size: 12px;\">{{footer}}</p>\
</div>";
    let seeds: &[(&str, &str, &str, &str, &str, &str)] = &[
        (
            "通知公告邮件",
            "notice_email",
            "email",
            "{{title}}",
            notice_email_content,
            "G-16 公告邮件正文骨架（变量已由后端转义）",
        ),
        (
            "报表订阅推送",
            "report_push",
            "site",
            "报表推送：{{report_name}}",
            "{{content}}",
            "G-16 报表订阅站内信模板（site 渠道统一投递）",
        ),
    ];
    for (name, code, channel, subject, content, remark) in seeds {
        flow_insert(
            db,
            &format!(
                "sys_msg_template (template_name, template_code, channel_code, template_subject, template_content, status, remark, create_by, create_time, del_flag) VALUES \
                 ('{name}', '{code}', '{channel}', '{subject}', '{content}', '0', '{remark}', 'admin', {now}, '0')"
            ),
        )
        .await?;
    }
    tracing::info!("平台默认消息模板 seed 完成（notice_email / report_push，G-16）");
    Ok(())
}

/// G-11（存量库兜底，等价迁移 `m20261007_000002`）：OSS 存储配置管理页菜单
/// （menu_id 4103，platform-only，perms `system:uploadConfig:edit`）。
///
/// 菜单缺失不产生 500（仅 getRouters 少一个入口），但为"权限齐备、入口可见"
/// 的完整性兜底（避免"超管有 perms 却无菜单入口"）；幂等：menu_id 已存在跳过。
async fn ensure_upload_config_menu(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let occupied = db
        .query_all_raw(Statement::from_string(
            backend,
            "SELECT component, path AS comp_path FROM sys_menu WHERE menu_id = 4103".to_string(),
        ))
        .await?;
    if !occupied.is_empty() {
        // G-14 批次五加固：4103 已存在时**校验内容**而非盲目跳过——
        // 若被非目标菜单占位（如历史 e2e 孤儿残留），OR IGNORE 会静默失效
        // 且无任何日志（实测缺陷：孤儿 test-menu-* 占位导致 OSS 菜单从未落库，
        // uploadConfig 页面入口丢失）。此处显性化冲突，交由人工/测试侧清理重建。
        let existing = occupied
            .first()
            .and_then(|r| r.try_get::<String>("", "component").ok());
        if existing.as_deref() == Some("system/uploadConfig/index") {
            return Ok(());
        }
        tracing::warn!(
            "menu_id=4103 已被其他菜单占用（component={:?}）——OSS 存储配置菜单补建跳过；\
             请清理占位菜单后重启，或将 G-11 菜单迁移至其他 menu_id",
            existing
        );
        return Ok(());
    }
    let now = flow_now(db);
    flow_insert(
        db,
        &format!(
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES              (4103, 'OSS 存储配置', 1, 15, 'uploadConfig', 'system/uploadConfig/index', '', '', '1', '0', 'C', '0', '0', 'system:uploadConfig:edit', 'upload', 'admin', {now}, 'OSS 凭据动态化管理（平台专属；仅 backend=s3 档生效）', '0')"
        ),
    )
    .await?;
    tracing::info!("OSS 存储配置菜单已补建（menu_id=4103，G-11 存量库兜底）");
    Ok(())
}

/// 台账（G-02 M1，存量库兜底，等价迁移 `m20261007_000003`）：flow_definition 表。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而
/// `flow_definition_service` 已读写该表 ⇒ 缺此兜底则流程定义 CRUD/发布全链 500。
/// 幂等：表存在即跳过；唯一索引容错"已存在"；demo_v2 种子 WHERE NOT EXISTS。
async fn ensure_flow_definition_table(db: &DatabaseConnection) -> anyhow::Result<()> {
    if sso_table_exists(db, "flow_definition").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let (pk, text_type) = match backend {
        DatabaseBackend::Sqlite => ("INTEGER PRIMARY KEY AUTOINCREMENT", "TEXT"),
        DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "TEXT"),
        _ => ("BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY", "LONGTEXT"),
    };
    let create_sql = format!(
        "CREATE TABLE IF NOT EXISTS flow_definition (\
         flow_id {pk},\
         tenant_id BIGINT NOT NULL DEFAULT 0,\
         flow_code VARCHAR(64) NOT NULL,\
         flow_name VARCHAR(128) NOT NULL,\
         graph_json {text_type} NOT NULL,\
         version INT NOT NULL DEFAULT 1,\
         is_latest CHAR(1) NOT NULL DEFAULT '1',\
         status CHAR(1) NOT NULL DEFAULT '0',\
         create_by VARCHAR(64),\
         create_time DATETIME,\
         update_by VARCHAR(64),\
         update_time DATETIME,\
         remark VARCHAR(500),\
         del_flag CHAR(1) DEFAULT '0')"
    );
    db.execute_raw(Statement::from_string(backend, create_sql))
        .await?;
    // 唯一索引 (tenant_id, flow_code, version)：MySQL 不支持 IF NOT EXISTS，容错"已存在"
    let idx_sql = match backend {
        DatabaseBackend::MySql => {
            "CREATE UNIQUE INDEX uq_flow_def_code_ver ON flow_definition (tenant_id, flow_code, version)"
        }
        _ => {
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_flow_def_code_ver ON flow_definition (tenant_id, flow_code, version)"
        }
    };
    if let Err(e) = db
        .execute_raw(Statement::from_string(backend, idx_sql.to_string()))
        .await
    {
        let msg = e.to_string();
        if !(msg.contains("Duplicate key name")
            || msg.contains("42P07")
            || msg.contains("already exists"))
        {
            return Err(e.into());
        }
    }
    // demo_v2 种子（与迁移同构，幂等）
    let graph = r#"{"nodes":[{"id":"start","type":"start"},{"id":"a1","type":"approve","name":"部门主管审批","assignees":["dept_leader"],"quorum":"any"},{"id":"a2","type":"approve","name":"管理员审批","assignees":["role:admin"],"quorum":"any"},{"id":"end","type":"end"}],"edges":[{"from":"start","to":"a1"},{"from":"a1","to":"a2"},{"from":"a2","to":"end"}]}"#;
    let now = flow_now(db);
    db.execute_raw(Statement::from_string(
        backend,
        format!(
            "INSERT INTO flow_definition (tenant_id, flow_code, flow_name, graph_json, version, is_latest, status, create_by, create_time, remark, del_flag) \
             SELECT 0, 'demo_v2', '可配置演示审批流', '{graph}', 1, '1', '0', 'admin', {now}, 'G-02 M1 种子：两级单审（对齐 demo single 模式）', '0' \
             WHERE NOT EXISTS (SELECT 1 FROM flow_definition WHERE tenant_id = 0 AND flow_code = 'demo_v2')"
        ),
    ))
    .await?;
    tracing::info!("flow_definition 表已补建（G-02 存量库兜底）");
    Ok(())
}

/// 台账（G-01 M1，存量库兜底，等价迁移 `m20261007_000004`）：
/// report_dataset / report_dashboard 两表。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而
/// `report_dataset_service` 已读写两表 ⇒ 缺此兜底则数据集 CRUD/试跑/大屏存取全链 500。
/// 幂等：表存在即跳过；唯一索引容错"已存在"。
async fn ensure_report_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    if sso_table_exists(db, "report_dataset").await?
        && sso_table_exists(db, "report_dashboard").await?
    {
        return Ok(());
    }
    let backend = db.get_database_backend();
    let (pk, text_type) = match backend {
        DatabaseBackend::Sqlite => ("INTEGER PRIMARY KEY AUTOINCREMENT", "TEXT"),
        DatabaseBackend::Postgres => ("BIGSERIAL PRIMARY KEY", "TEXT"),
        _ => ("BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY", "LONGTEXT"),
    };
    let dataset_sql = format!(
        "CREATE TABLE IF NOT EXISTS report_dataset (\
         dataset_id {pk},\
         tenant_id BIGINT NOT NULL DEFAULT 0,\
         dataset_code VARCHAR(64) NOT NULL,\
         dataset_name VARCHAR(128) NOT NULL,\
         sql_template {text_type} NOT NULL,\
         params_schema {text_type},\
         columns_meta {text_type},\
         status CHAR(1) NOT NULL DEFAULT '0',\
         remark VARCHAR(500),\
         create_by VARCHAR(64),\
         create_time DATETIME,\
         update_by VARCHAR(64),\
         update_time DATETIME,\
         del_flag CHAR(1) DEFAULT '0')"
    );
    db.execute_raw(Statement::from_string(backend, dataset_sql))
        .await?;
    let dashboard_sql = format!(
        "CREATE TABLE IF NOT EXISTS report_dashboard (\
         dashboard_id {pk},\
         tenant_id BIGINT NOT NULL DEFAULT 0,\
         dashboard_code VARCHAR(64) NOT NULL,\
         dashboard_name VARCHAR(128) NOT NULL,\
         layout_json {text_type} NOT NULL,\
         schema_version INT NOT NULL DEFAULT 1,\
         status CHAR(1) NOT NULL DEFAULT '0',\
         remark VARCHAR(500),\
         create_by VARCHAR(64),\
         create_time DATETIME,\
         update_by VARCHAR(64),\
         update_time DATETIME,\
         del_flag CHAR(1) DEFAULT '0')"
    );
    db.execute_raw(Statement::from_string(backend, dashboard_sql))
        .await?;
    // 唯一索引：MySQL 不支持 IF NOT EXISTS，容错"已存在"
    for (idx_name, table, cols) in [
        (
            "uq_report_dataset_code",
            "report_dataset",
            "(tenant_id, dataset_code)",
        ),
        (
            "uq_report_dashboard_code",
            "report_dashboard",
            "(tenant_id, dashboard_code)",
        ),
    ] {
        let idx_sql = match backend {
            DatabaseBackend::MySql => {
                format!("CREATE UNIQUE INDEX {idx_name} ON {table} {cols}")
            }
            _ => format!("CREATE UNIQUE INDEX IF NOT EXISTS {idx_name} ON {table} {cols}"),
        };
        if let Err(e) = db
            .execute_raw(Statement::from_string(backend, idx_sql))
            .await
        {
            let msg = e.to_string();
            if !(msg.contains("Duplicate key name")
                || msg.contains("42P07")
                || msg.contains("already exists"))
            {
                return Err(e.into());
            }
        }
    }
    tracing::info!("report_dataset / report_dashboard 表已补建（G-01 存量库兜底）");
    Ok(())
}

/// 台账（G-01/G-02 M1，存量库兜底，等价迁移 `m20261007_000005`）：
/// 流程定义与报表数据集/大屏的菜单权限承载（menu_id 4140-4148）。
///
/// 契约测试 `menu_perm_contract` 要求后端 PERM_ROUTE_TABLE 每个权限键 ⊆ sys_menu.perms，
/// 存量库缺菜单行则普通角色永远无法被授予这些能力。页面菜单 `visible='1'`（隐藏，
/// M2 前端上线时翻转可见性）。幂等 + E6 加固：menu_id 已存在时**校验 perms 内容**，
/// 被其他菜单占位则显性 warn（不盲目跳过、不覆盖）。
async fn ensure_flow_report_menus(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    /// 菜单 seed 行（与迁移 m20261007_000005 的 MENUS 同构）
    struct MenuSeedRow {
        menu_id: i64,
        menu_name: &'static str,
        parent_id: i64,
        order_num: i64,
        menu_type: &'static str,
        path: &'static str,
        component: &'static str,
        perms: &'static str,
        icon: &'static str,
    }
    const MENUS: &[MenuSeedRow] = &[
        MenuSeedRow {
            menu_id: 4140,
            menu_name: "流程定义",
            parent_id: 1,
            order_num: 16,
            menu_type: "C",
            path: "flowDefinition",
            component: "flow/designer/index",
            perms: "flow:definition:list",
            icon: "form",
        },
        MenuSeedRow {
            menu_id: 4141,
            menu_name: "流程定义查询",
            parent_id: 4140,
            order_num: 1,
            menu_type: "F",
            path: "",
            component: "",
            perms: "flow:definition:query",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4142,
            menu_name: "流程定义新增",
            parent_id: 4140,
            order_num: 2,
            menu_type: "F",
            path: "",
            component: "",
            perms: "flow:definition:add",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4143,
            menu_name: "流程定义编辑",
            parent_id: 4140,
            order_num: 3,
            menu_type: "F",
            path: "",
            component: "",
            perms: "flow:definition:edit",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4144,
            menu_name: "流程定义发布",
            parent_id: 4140,
            order_num: 4,
            menu_type: "F",
            path: "",
            component: "",
            perms: "flow:definition:publish",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4145,
            menu_name: "流程定义删除",
            parent_id: 4140,
            order_num: 5,
            menu_type: "F",
            path: "",
            component: "",
            perms: "flow:definition:remove",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4146,
            menu_name: "报表数据集",
            parent_id: 1,
            order_num: 17,
            menu_type: "C",
            path: "reportDataset",
            component: "report/dataset/index",
            perms: "report:dataset:list",
            icon: "chart",
        },
        MenuSeedRow {
            menu_id: 4147,
            menu_name: "数据集编辑",
            parent_id: 4146,
            order_num: 1,
            menu_type: "F",
            path: "",
            component: "",
            perms: "report:dataset:edit",
            icon: "#",
        },
        MenuSeedRow {
            menu_id: 4148,
            menu_name: "大屏管理",
            parent_id: 1,
            order_num: 18,
            menu_type: "C",
            path: "reportDashboard",
            component: "report/view/index",
            perms: "report:dashboard:view",
            icon: "dashboard",
        },
    ];
    let backend = db.get_database_backend();
    for m in MENUS {
        let occupied = db
            .query_all_raw(Statement::from_string(
                backend,
                format!("SELECT perms FROM sys_menu WHERE menu_id = {}", m.menu_id),
            ))
            .await?;
        if let Some(row) = occupied.first() {
            let existing = row.try_get::<String>("", "perms").ok();
            if existing.as_deref() == Some(m.perms) {
                continue;
            }
            tracing::warn!(
                "menu_id={} 已被其他菜单占用（perms={existing:?}）——G-01/G-02 菜单 \
                 （预期 perms={}）补建跳过；请清理占位菜单后重启",
                m.menu_id,
                m.perms,
            );
            continue;
        }
        let now = flow_now(db);
        flow_insert(
            db,
            &format!(
                "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, \
                 route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, \
                 create_by, create_time, remark, del_flag) VALUES \
                 ({}, '{}', {}, {}, '{}', '{}', '', '', \
                 '1', '0', '{}', '1', '0', '{}', '{}', 'admin', {}, \
                 'G-01/G-02 菜单权限承载（存量库兜底）', '0')",
                m.menu_id,
                m.menu_name,
                m.parent_id,
                m.order_num,
                m.path,
                m.component,
                m.menu_type,
                m.perms,
                m.icon,
                now
            ),
        )
        .await?;
    }
    tracing::info!("流程/报表菜单已补建（4140-4148，G-01/G-02 存量库兜底）");
    Ok(())
}

/// 台账（G-01 M2，存量库兜底，等价迁移 `m20261007_000008`）：
/// 报表前端三页上线，翻转菜单 4146（报表数据集）/4148（大屏管理）可见性。
/// **仅翻这两行**——4140-4145（G-02 流程定义）属 M3 前端，继续隐藏。
/// 幂等：仅当 visible='1' 时置 '0'，可重复执行；表/行不存在零影响。
async fn ensure_report_menus_visible(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_menu").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_menu SET visible = '0' WHERE menu_id IN (4146, 4148) AND visible = '1'"
            .to_string(),
    ))
    .await?;
    Ok(())
}

/// 台账（G-02 M2，存量库兜底，等价迁移 `m20261007_000006`）：
/// sys_flow_task 动作矩阵扩展列——`weight`（加权票快照，DEFAULT 1）、
/// `threshold`（weighted 节点门槛快照）、`delegate_from`（委派转出人）。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而
/// 引擎加权/委派链路已读写新列 ⇒ 缺此兜底则 or_sign/weighted/delegate 全链 500。
/// 幂等：has_column 守卫逐列判定；表不存在时安全返回。
async fn ensure_flow_task_action_columns(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_flow_task").await? {
        return Ok(());
    }
    let adds: [(&str, &str); 3] = [
        ("weight", "INT NOT NULL DEFAULT 1"),
        ("threshold", "INT NULL"),
        ("delegate_from", "BIGINT NULL"),
    ];
    for (col, ddl) in adds {
        if sso_has_column(db, "sys_flow_task", col).await? {
            continue;
        }
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            format!("ALTER TABLE sys_flow_task ADD COLUMN {col} {ddl}"),
        ))
        .await?;
        tracing::info!("sys_flow_task.{col} 已补列（G-02 M2 存量库兜底）");
    }
    Ok(())
}

/// 台账（G-07 扩展，存量库兜底，等价迁移 `m20261007_000007`）：
/// `sys_msg_template.sms_template_code`（云厂商短信模板 code）与
/// `sys_msg_send_log.sms_params`（原始渲染参数 JSON 快照，重试还原用）。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已带
/// 新字段 ⇒ 缺此兜底则模板/发送日志读写全链 500。幂等：has_column 守卫逐列判定。
async fn ensure_sms_cloud_columns(db: &DatabaseConnection) -> anyhow::Result<()> {
    let adds: [(&str, &str, &str); 2] = [
        ("sys_msg_template", "sms_template_code", "VARCHAR(64) NULL"),
        ("sys_msg_send_log", "sms_params", "TEXT NULL"),
    ];
    for (table, col, ddl) in adds {
        if !sso_table_exists(db, table).await? {
            continue;
        }
        if sso_has_column(db, table, col).await? {
            continue;
        }
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            format!("ALTER TABLE {table} ADD COLUMN {col} {ddl}"),
        ))
        .await?;
        tracing::info!("{table}.{col} 已补列（G-07 扩展存量库兜底）");
    }
    Ok(())
}

/// 台账（第八批，存量库兜底，等价迁移 `m20260926_000009`）：代码生成列元数据的
/// **Java 遗留命名 → Rust 命名** —— `gen_table_column.java_type/java_field`
/// → `rust_type/rust_field`。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已改用新列名
/// ⇒ 缺此兜底则 gen 列表/详情/预览/导入全链报 `no such column: rust_type`（500）。
/// 幂等：仅当**旧列存在且新列不存在**时执行 `RENAME COLUMN`；表不存在时安全返回。
async fn ensure_gen_column_rust_naming(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "gen_table_column").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    for (old, new) in [("java_type", "rust_type"), ("java_field", "rust_field")] {
        if !sso_has_column(db, "gen_table_column", old).await?
            || sso_has_column(db, "gen_table_column", new).await?
        {
            continue;
        }
        db.execute_raw(Statement::from_string(
            backend,
            format!("ALTER TABLE gen_table_column RENAME COLUMN {old} TO {new}"),
        ))
        .await?;
        tracing::info!("gen_table_column.{old} 已重命名为 {new}（台账第八批 Java 遗留命名收口）");
    }
    Ok(())
}

/// 台账（能力位批次 0，存量库兜底，等价迁移 `m20260926_000010`）：
/// `sys_tenant_package.features` 列（租户套餐能力位 JSON）。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已带
/// `features` 字段 ⇒ 缺此兜底则套餐列表/详情/新建/编辑全链报 `no such column: features`（500）。
/// 列可空（NULL = 全默认 = **全部关闭**），**不回填任何值**（关闭态即安全态）。
async fn ensure_tenant_package_features(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_tenant_package").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_tenant_package", "features").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_tenant_package ADD COLUMN features TEXT NULL".to_string(),
    ))
    .await?;
    tracing::info!("sys_tenant_package.features 列已补建（能力位批次 0 存量库兜底）");
    Ok(())
}

/// P2-33：把 `[server].http_status_convention` 注入全局档位，并在 `restful` 档打一行 INFO
/// （便于运维确认"业务失败不再返回 200"这一取向已生效；`legacy` 为默认档，静默）。
fn init_http_status_convention(settings: &Settings) {
    use crate::common::http_status::{HttpStatusConvention, set_convention};

    let convention = HttpStatusConvention::parse(&settings.server.http_status_convention);
    set_convention(convention);
    if convention == HttpStatusConvention::Restful {
        tracing::info!(
            "HTTP 状态码约定 = restful：业务失败不再返回 200（未归类业务码按 400 归类）；\
             标准码与 legacy 档一致"
        );
    }
}

/// #10：把 `[resilience]` 的出站熔断参数注入全局（默认 `off` = 现状：每次都尝试发送）。
///
/// 治理意义：熔断会**改变出站发送行为**（打开期间直接跳过推送），必须让运维一眼看到本实例
/// 是否启用、阈值与冷却（由 [`crate::common::breaker::init`] 打 INFO）；`off` 档不判定、
/// 不记账 ⇒ 与改造前逐字节等价。非法档位在解析时 WARN 并回落 `off`（fail-safe）。
fn init_outbound_breaker(settings: &Settings) {
    let cfg = crate::common::breaker::BreakerConfig::from_settings(settings);
    crate::common::breaker::init(cfg);
}

/// 注入平台层能力位并做**启动治理打印**（幂等：重复调用只保留首次注入）。
///
/// 治理意义：能力位是"放开高危能力"的唯一入口，必须让运维一眼看到本实例放开了什么——
/// 默认全关只打一行 INFO；一旦有开启项则打 WARN 并逐条列出（含模式），避免"隐形放开"。
fn init_feature_flags(settings: &Settings) {
    use crate::common::features::{self, FeatureSet, KNOWN_FEATURES};

    // 净化：未登记键 / 非法模式在此被剔除并告警（fail-closed）
    let effective =
        features::init_platform_features(FeatureSet::sanitized(settings.features.0.clone()));

    let enabled: Vec<String> = KNOWN_FEATURES
        .iter()
        .filter(|def| effective.is_on(def.key))
        .map(|def| format!("{}={}", def.key, effective.mode(def.key)))
        .collect();

    if enabled.is_empty() {
        tracing::info!("能力位：平台层全部关闭（默认安全姿态；租户套餐亦需显式开启）");
    } else {
        tracing::warn!(
            enabled = %enabled.join(", "),
            "能力位：平台层已放开以下能力（租户套餐需同时开启，权限才可下放）。\
             已放开项的服务层必须按 tenant_id 收窄 —— 逐条核对 \
             governance crate 的解锁清单（`governance::Item::unlocked`）的守卫要求"
        );
    }

    // UI 展示策略姿态（`[ui]` 段）：属展示层（非安全边界），无条件打 INFO，
    // 非法取值已在解析时 WARN 并回落 auto。供运维一眼确认"归属列是否只对平台可见"。
    let tenant_column = crate::config::TenantColumnMode::parse(&settings.ui.show_tenant_column);
    tracing::info!(
        mode = tenant_column.as_str(),
        "UI 展示策略：[ui].show_tenant_column（auto = 仅平台操作者可见归属列 ⇒ 历史行为）"
    );

    // 单机模式一致性自检（§5.22）：management=false 时部分配置**会被强制覆盖**，
    // 在此显式 WARN 消除"配了没生效"的运维困惑（拒绝静默失效准则）。
    if !settings.tenant.management {
        // ① [ui] 租户展示配置：单机模式强制隐藏（auth_service 布场门控）
        if tenant_column.as_str() != "never"
            || crate::config::TenantFilterMode::parse(&settings.ui.tenant_filter).as_str() != "off"
        {
            tracing::warn!(
                show_tenant_column = tenant_column.as_str(),
                tenant_filter = %settings.ui.tenant_filter,
                "单机模式（[tenant].management=false）：[ui] 段的租户展示配置将被强制隐藏\
                 （showTenantColumn/showTenantFilter 恒 false）——如需保留请切回多租户模式"
            );
        }
        // ② 租户域能力位：单机模式下端点 403 + 菜单剪除 ⇒ 配置空转
        let tenant_domain_keys = ["nav.l3", "tenant.domain_self_service"];
        let active_tenant_keys: Vec<&str> = tenant_domain_keys
            .iter()
            .filter(|k| effective.is_on(k))
            .copied()
            .collect();
        if !active_tenant_keys.is_empty() {
            tracing::warn!(
                keys = %active_tenant_keys.join(", "),
                "单机模式（[tenant].management=false）：租户域能力位不生效\
                 （端点 403 + 菜单剪除）——如需启用请切回多租户模式"
            );
        }
    }
}

/// 启动打印 ACME 证书需求输出的**有效姿态**（`[acme]` 段）。
///
/// 治理意义与能力位同理：这是"把租户域名清单推出本进程"的唯一出口，必须让运维一眼看到
/// 本实例**是否会**发请求、发到哪。默认 `off` 打 INFO；`mode = webhook` 但地址缺失/非法时
/// 打 **WARN**——否则会静默失效（"以为配了其实没生效"，与 MT-4 反代白名单同类坑）。
fn init_acme_output(settings: &Settings) {
    use crate::config::settings::AcmeMode;

    let cfg = &settings.acme;
    match (cfg.mode(), cfg.effective_webhook()) {
        (AcmeMode::Off, _) => {
            tracing::info!("ACME 证书需求输出：[acme].mode = off（默认，不发任何出站请求）");
        }
        (AcmeMode::Webhook, Some(url)) => {
            tracing::info!(
                url = %url,
                signed = cfg.secret.as_deref().is_some_and(|s| !s.is_empty()),
                timeout_secs = cfg.timeout().as_secs(),
                "ACME 证书需求输出：已启用 webhook（域名验证通过 / 已验证域名删除时推送）"
            );
        }
        (AcmeMode::Webhook, None) => {
            tracing::warn!(
                webhook_url = ?cfg.webhook_url,
                "[acme].mode = webhook 但 webhook_url 缺失或非 http(s) ⇒ 本次运行**不会**推送\
                 （按 off 处理）。请补全 [acme].webhook_url，否则证书需求清单会静默丢失"
            );
        }
    }
}

/// 启动打印**出站领域事件**的**有效姿态**（`[events]` 段）。
///
/// 与 `[acme]` 同源治理逻辑：这是"把领域事件推出本进程"的唯一出口，必须让运维一眼看到
/// 本实例**是否会**发请求、发到哪、推送哪些事件。默认 `off` 打 INFO；
/// `outbound = webhook` 但地址缺失/非法时打 **WARN**——否则会静默失效。
fn init_events_output(settings: &Settings) {
    use crate::config::settings::EventsOutboundMode;

    let cfg = &settings.events;
    match (cfg.mode(), cfg.effective_webhook()) {
        (EventsOutboundMode::Off, _) => {
            tracing::info!(
                "领域事件输出：[events].outbound = off（默认，不发任何出站请求）\
                 —— 需要对接 MQ / 通知 / 数仓时置 webhook 并配置 webhook_url"
            );
        }
        (EventsOutboundMode::Webhook, Some(url)) => {
            tracing::info!(
                url = %url,
                signed = cfg.secret.as_deref().is_some_and(|s| !s.is_empty()),
                timeout_secs = cfg.timeout().as_secs(),
                events = ?crate::service::event_outbox_service::ALL_EVENTS,
                "领域事件输出：已启用 webhook（租户创建 / 启停 / 删除 / 恢复时推送）"
            );
        }
        (EventsOutboundMode::Webhook, None) => {
            tracing::warn!(
                webhook_url = ?cfg.webhook_url,
                "[events].outbound = webhook 但 webhook_url 缺失或非 http(s) ⇒ 本次运行**不会**推送\
                 （按 off 处理）。请补全 [events].webhook_url，否则领域事件会静默丢失"
            );
        }
    }
}

// ==================== 2026-10-03 三迁移兜底（audit_change / webhook_event / alert_rule） ====================
// 存量库不跑 `Migrator::up`，以下三个兜底函数与迁移共享**单一事实源**：
// 建表 SQL / 索引清单 / 加列 DDL / 种子数据全部抽在各迁移文件导出的 pub 常量与函数中，
// 本侧仅引用（原手抄 DDL/种子副本已删除，漂移物理不可能）。
// 全部幂等：建表 IF NOT EXISTS、索引经 ensure_tenant_index（MySQL 查 statistics 判存在）、
// 加列前 sso_has_column 检查、种子走 flow_insert（三方言 INSERT OR IGNORE / ON CONFLICT / IGNORE）。

/// 审计合规域兜底（等价迁移 `m20261003_000001_audit_change`）：
/// - 建表 `sys_audit_change`（业务数据变更留痕，三方言幂等）
/// - 三个审计查询索引（row / time / tenant）
/// - `sys_oper_log.chain_hash` 列存在性检查加列（操作日志 HMAC-SHA256 防篡改链；
///   NULL = 未入链，校验接口跳过 NULL 行不误报）
/// - 菜单种子幂等：变更留痕页面 4000 + 按钮 4001/4002 + role_menu(role_id=2)
pub(crate) async fn ensure_audit_change_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    // 单一事实源：迁移文件导出的建表 SQL / 索引 / 加列 DDL / 菜单种子
    use migration::m20261003_000001_audit_change as mig;

    let backend = db.get_database_backend();

    // 1) 建表（引用迁移 create_table_sql，三方言分支收敛于迁移文件）
    flow_exec(db, mig::create_table_sql(backend)).await?;

    // 2) 三个审计查询索引（引用迁移 AUDIT_INDEXES；ensure_tenant_index 内部三方言幂等：
    //    MySQL 先查 information_schema.statistics 判存在，PG/SQLite 直接 IF NOT EXISTS）
    for (name, table, cols) in mig::AUDIT_INDEXES {
        ensure_tenant_index(db, table, name, cols, false).await?;
    }

    // 3) sys_oper_log.chain_hash 列（DDL 片段引用迁移常量；表已存在才检查，
    //    极老空库由 migration 负责建表）
    if sso_table_exists(db, "sys_oper_log").await?
        && !sso_has_column(db, "sys_oper_log", "chain_hash").await?
    {
        tracing::info!("sys_oper_log 缺少 chain_hash 列，执行幂等 ALTER 添加");
        flow_exec(
            db,
            format!(
                "ALTER TABLE sys_oper_log ADD COLUMN {}",
                mig::OPER_LOG_CHAIN_HASH_DDL
            ),
        )
        .await?;
    }

    // 4) 菜单种子（引用迁移 audit_menu_seed_bodies；flow_insert 拼幂等前缀，
    //    与迁移 execute_idempotent_insert 语义等价）
    let now = flow_now(db);
    for body in mig::audit_menu_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    tracing::info!("审计合规域兜底完成（sys_audit_change / chain_hash / 菜单 4000-4002，幂等）");
    Ok(())
}

/// 开放域集成兜底（等价迁移 `m20261003_000002_webhook_event`）：
/// - 建表 `sys_webhook_event`（事件目录）+ event_key 唯一索引
/// - 16 个种子事件幂等 INSERT
/// - 加列（存在性检查）：sys_web_hook.subscribed_events / sys_web_hook_log.source /
///   sys_pat.access_key + secret_key（AK/SK 开放 API 凭据，SK 信封加密存 VARCHAR(255)）
/// - `uk_sys_pat_access_key` 唯一索引（AK 鉴权查库）
/// - 菜单按钮种子：事件目录 3562 / 测试发送 3563（挂回调配置页面 158，授予 role_id=2）
pub(crate) async fn ensure_webhook_event_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    // 单一事实源：迁移文件导出的建表 SQL / 索引 / 加列 DDL / 种子事件 / 菜单按钮
    // （原本地 WEBHOOK_SEED_EVENTS 手抄副本已删除；sys_web_hook_service.rs 侧不受影响）
    use migration::m20261003_000002_webhook_event as mig;
    use migration::m20261004_000002_webhook_event_edit as mig_edit;

    let backend = db.get_database_backend();

    // 1) 建表（引用迁移 create_table_sql）
    flow_exec(db, mig::create_table_sql(backend)).await?;

    // 2) 加列（DDL 片段引用迁移常量，表存在才检查；存量行 NULL 兼容）
    if sso_table_exists(db, "sys_web_hook").await?
        && !sso_has_column(db, "sys_web_hook", "subscribed_events").await?
    {
        flow_exec(
            db,
            format!(
                "ALTER TABLE sys_web_hook ADD COLUMN {}",
                mig::WEB_HOOK_SUBSCRIBED_EVENTS_DDL
            ),
        )
        .await?;
    }
    if sso_table_exists(db, "sys_web_hook_log").await?
        && !sso_has_column(db, "sys_web_hook_log", "source").await?
    {
        flow_exec(
            db,
            format!(
                "ALTER TABLE sys_web_hook_log ADD COLUMN {}",
                mig::WEB_HOOK_LOG_SOURCE_DDL
            ),
        )
        .await?;
    }
    if sso_table_exists(db, "sys_pat").await? {
        if !sso_has_column(db, "sys_pat", "access_key").await? {
            flow_exec(
                db,
                format!("ALTER TABLE sys_pat ADD COLUMN {}", mig::PAT_ACCESS_KEY_DDL),
            )
            .await?;
        }
        if !sso_has_column(db, "sys_pat", "secret_key").await? {
            flow_exec(
                db,
                format!("ALTER TABLE sys_pat ADD COLUMN {}", mig::PAT_SECRET_KEY_DDL),
            )
            .await?;
        }
    }

    // 3) 索引（引用迁移 WEBHOOK_INDEXES；在加列之后执行——uk_sys_pat_access_key
    //    依赖 access_key 列已存在。ensure_tenant_index 三方言幂等）
    for (name, table, cols, unique) in mig::WEBHOOK_INDEXES {
        if !sso_table_exists(db, table).await? {
            continue;
        }
        ensure_tenant_index(db, table, name, cols, *unique).await?;
    }

    // 4) 种子事件（引用迁移 webhook_event_seed_bodies；flow_insert 拼幂等前缀）
    let now = flow_now(db);
    for body in mig::webhook_event_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    // 5) 菜单按钮权限（引用迁移 webhook_menu_seed_bodies；
    //    挂「回调配置」页面 menu_id=158 下，授予超管角色 role_id=2）
    for body in mig::webhook_menu_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    // 6) 目录停用/启用按钮（引用迁移 webhook_event_edit_menu_bodies，m20261004_000002；
    //    同挂 menu_id=158 下，授予超管角色 role_id=2）
    for body in mig_edit::webhook_event_edit_menu_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    tracing::info!("Webhook 事件域兜底完成（sys_webhook_event / AK/SK 列 / 菜单 3562-3564，幂等）");
    Ok(())
}

/// Webhook 订阅双轨收敛兜底（等价迁移 `m20261003_000004_webhook_unify`）：
/// 存量 `event_types`（逗号口径）幂等转换为 `subscribed_events`（JSON 数组口径），
/// 仅处理 `subscribed_events IS NULL` 且 `event_types` 非空的行；事件名映射与
/// SQL 单一来源 = 迁移文件 `build_unify_update_sql`（与 service 的 LEGACY_EVENT_KEY_MAP
/// 由集成测试双向断言防漂移）。
pub(crate) async fn ensure_webhook_subscription_unify(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    // 表未建（极老空库）或缺列（迁移未跑过加列）时跳过——由迁移负责全新库
    if !sso_table_exists(db, "sys_web_hook").await? {
        tracing::info!("sys_web_hook 表不存在，跳过订阅收敛（由迁移负责全新库）");
        return Ok(());
    }
    if !sso_has_column(db, "sys_web_hook", "subscribed_events").await?
        || !sso_has_column(db, "sys_web_hook", "event_types").await?
    {
        tracing::info!("sys_web_hook 缺少 subscribed_events/event_types 列，跳过订阅收敛");
        return Ok(());
    }
    let backend = db.get_database_backend();
    let sql = migration::m20261003_000004_webhook_unify::build_unify_update_sql(backend);
    flow_exec(db, &sql).await?;
    tracing::info!("Webhook 订阅收敛完成（存量 event_types → subscribed_events，幂等）");
    Ok(())
}

/// 告警规则引擎兜底（等价迁移 `m20261003_000003_alert_rule`）：
/// - 建表 `sys_alert_rule`（三方言幂等；metric/comparator 白名单在 service 层校验）
/// - `idx_alert_rule_enabled` 索引（评估轮询按 enabled 过滤）
/// - 告警菜单种子：页面 4110（挂系统监控目录 2）+ 按钮 4111-4114（与
///   PERM_ROUTE_TABLE 对齐），页面对通用角色 role_id=2 可见
pub(crate) async fn ensure_alert_rule_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    // 单一事实源：迁移文件导出的建表 SQL / 索引 / 菜单种子
    use migration::m20261003_000003_alert_rule as mig;

    let backend = db.get_database_backend();

    // 1) 建表（引用迁移 create_table_sql）
    flow_exec(db, mig::create_table_sql(backend)).await?;

    // 2) enabled 过滤索引（引用迁移 ALERT_INDEXES；评估轮询用，三方言幂等）
    for (name, table, cols, unique) in mig::ALERT_INDEXES {
        ensure_tenant_index(db, table, name, cols, *unique).await?;
    }

    // 3) 菜单元数据（引用迁移 alert_menu_seed_bodies；perms 与 PERM_ROUTE_TABLE 对齐）
    let now = flow_now(db);
    for body in mig::alert_menu_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    tracing::info!("告警规则兜底完成（sys_alert_rule / enabled 索引 / 菜单 4110-4114，幂等）");
    Ok(())
}

/// 字段级权限 M2 兜底（等价迁移 `m20261003_000005_role_field_perm`）：
/// - 建表 `sys_role_field_perm`（角色字段权限矩阵，UNIQUE(role_id, table_key, field_key)）
/// - 角色查询索引 idx_role_field_perm_role
/// - 菜单种子幂等：角色管理按钮 4120（system:role:fieldPerm）/ 4121（fieldPermSave）
///   + role_menu(role_id=1)
/// - sys_config 种子幂等：平台开关 `sys.fieldPerm.enabled`（默认 'false' = 关闭态即安全态）
pub(crate) async fn ensure_role_field_perm_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    // 单一事实源：迁移文件导出的建表 SQL / 索引 / 菜单种子 / config 种子
    use migration::m20261003_000005_role_field_perm as mig;

    let backend = db.get_database_backend();

    // 1) 建表（引用迁移 create_table_sql；UNIQUE 约束随 IF NOT EXISTS 建表幂等）
    flow_exec(db, mig::create_table_sql(backend)).await?;

    // 2) 角色查询索引（引用迁移 ROLE_FIELD_PERM_INDEXES；ensure_tenant_index 三方言幂等）
    for (name, table, cols) in mig::ROLE_FIELD_PERM_INDEXES {
        ensure_tenant_index(db, table, name, cols, false).await?;
    }

    // 3) 菜单种子（引用迁移 field_perm_menu_seed_bodies；perms 与 PERM_ROUTE_TABLE 对齐）
    let now = flow_now(db);
    for body in mig::field_perm_menu_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    // 4) sys_config 平台开关种子（默认 'false'；幂等冲突忽略 = 保留运维已改的值）
    flow_insert(db, &mig::field_perm_config_seed_body(&now)).await?;

    tracing::info!(
        "字段级权限 M2 兜底完成（sys_role_field_perm / 菜单 4120-4121 / sys.fieldPerm.enabled，幂等）"
    );
    Ok(())
}

/// 报表看板兜底（等价迁移 `m20261003_000006_report_board`）：
/// - 建表 `sys_report_board`（配置化只读报表看板，UNIQUE(user_id, name)）
/// - 属主查询索引 idx_report_board_user
/// - 菜单种子幂等：系统工具目录 C 页面 4130（tool:reportBoard:list）/
///   F 按钮 4131（tool:reportBoard:save）+ role_menu(role_id=2)
pub(crate) async fn ensure_report_board_tables(db: &DatabaseConnection) -> anyhow::Result<()> {
    // 单一事实源：迁移文件导出的建表 SQL / 索引 / 菜单种子
    use migration::m20261003_000006_report_board as mig;

    let backend = db.get_database_backend();

    // 1) 建表（引用迁移 create_table_sql；UNIQUE 约束随 IF NOT EXISTS 建表幂等）
    flow_exec(db, mig::create_table_sql(backend)).await?;

    // 2) 属主查询索引（引用迁移 REPORT_BOARD_INDEXES；ensure_tenant_index 三方言幂等）
    for (name, table, cols) in mig::REPORT_BOARD_INDEXES {
        ensure_tenant_index(db, table, name, cols, false).await?;
    }

    // 3) 菜单种子（引用迁移 report_board_menu_seed_bodies；perms 与 PERM_ROUTE_TABLE 对齐）
    let now = flow_now(db);
    for body in mig::report_board_menu_seed_bodies(&now) {
        flow_insert(db, &body).await?;
    }

    tracing::info!("报表看板兜底完成（sys_report_board / 菜单 4130-4131，幂等）");
    Ok(())
}

#[cfg(test)]
mod single_source_sql_tests {
    //! 「迁移 ↔ initialize 兜底」单一事实源回归锁：
    //! 断言迁移文件导出的建表 SQL / 种子集合与重构前两侧手抄的 DDL/种子
    //! **逐字段等价**（期望值取自重构前 git 基线的手抄字面量）。
    //! 兜底函数与本测试引用同一导出项——迁移侧产出与兜底侧产出天然恒等；
    //! 若有人改动列定义/种子内容而未同步期望值，本模块必红。
    use migration::m20261003_000001_audit_change as audit_mig;
    use migration::m20261003_000002_webhook_event as webhook_mig;
    use migration::m20261003_000003_alert_rule as alert_mig;
    use sea_orm::DatabaseBackend;

    /// sys_audit_change 建表 SQL：三方言列清单/类型/约束与重构前手抄 DDL 逐字段等价
    #[test]
    fn audit_create_table_sql_matches_legacy_ddl() {
        for (backend, id_col, operated_at) in [
            (
                DatabaseBackend::Sqlite,
                "id INTEGER PRIMARY KEY AUTOINCREMENT",
                "TIMESTAMP NOT NULL",
            ),
            (
                DatabaseBackend::Postgres,
                "id BIGSERIAL PRIMARY KEY",
                "TIMESTAMP NOT NULL",
            ),
            (
                DatabaseBackend::MySql,
                "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
                "DATETIME NOT NULL",
            ),
        ] {
            let sql = audit_mig::create_table_sql(backend);
            assert!(
                sql.starts_with("CREATE TABLE IF NOT EXISTS sys_audit_change"),
                "{backend:?} 建表语句前缀不符: {sql}"
            );
            // 方言差异列
            assert!(sql.contains(id_col), "{backend:?} id 列不符: {sql}");
            assert!(
                sql.contains(&format!("operated_at     {operated_at}")),
                "{backend:?} operated_at 列不符: {sql}"
            );
            // 三方言共享列（含对齐空格，锁定列名/类型/约束不被漂移）
            for frag in [
                "tenant_id       BIGINT NOT NULL DEFAULT 0",
                "table_name      VARCHAR(64) NOT NULL",
                "row_pk          VARCHAR(64) NOT NULL",
                "action          VARCHAR(16) NOT NULL",
                "changed_fields  TEXT NOT NULL",
                "before_data     TEXT,",
                "after_data      TEXT,",
                "operator_id     BIGINT,",
                "operator_name   VARCHAR(64),",
            ] {
                assert!(sql.contains(frag), "{backend:?} 缺列片段 [{frag}]: {sql}");
            }
        }
    }

    /// 审计菜单种子：语句体与重构前手抄 SQL 逐字符等价（NOW() 形态下）
    #[test]
    fn audit_menu_seed_bodies_match_legacy_sql() {
        let bodies = audit_mig::audit_menu_seed_bodies("NOW()");
        assert_eq!(bodies.len(), 6, "3 菜单行 + 3 role_menu 行");
        assert_eq!(
            bodies[0],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES (4000, '变更留痕', 108, 4, 'auditChange', 'system/auditChange/index', '', '', '1', '0', 'C', '0', '0', 'system:audit-change:list', 'log', 'admin', NOW(), '业务数据变更留痕审计（前后快照 + 字段差异）', '0', 'menu.audit_change')"
        );
        assert_eq!(
            bodies[1],
            "sys_role_menu (role_id, menu_id) VALUES (2, 4000)"
        );
        assert_eq!(
            bodies[2],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES (4001, '变更查询', 4000, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:audit-change:query', '#', 'admin', NOW(), '', '0', NULL)"
        );
        assert_eq!(
            bodies[3],
            "sys_role_menu (role_id, menu_id) VALUES (2, 4001)"
        );
        assert_eq!(
            bodies[4],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag, i18n_key) VALUES (4002, '变更导出', 4000, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:audit-change:export', '#', 'admin', NOW(), '', '0', NULL)"
        );
        assert_eq!(
            bodies[5],
            "sys_role_menu (role_id, menu_id) VALUES (2, 4002)"
        );
    }

    /// sys_webhook_event 建表 SQL：三方言与重构前手抄 DDL 等价
    #[test]
    fn webhook_create_table_sql_matches_legacy_ddl() {
        for (backend, id_col) in [
            (
                DatabaseBackend::Sqlite,
                "id INTEGER PRIMARY KEY AUTOINCREMENT",
            ),
            (DatabaseBackend::Postgres, "id BIGSERIAL PRIMARY KEY"),
            (
                DatabaseBackend::MySql,
                "id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            ),
        ] {
            let sql = webhook_mig::create_table_sql(backend);
            assert!(sql.starts_with("CREATE TABLE IF NOT EXISTS sys_webhook_event"));
            assert!(sql.contains(id_col));
            for frag in [
                "event_key       VARCHAR(64) NOT NULL",
                "name            VARCHAR(64) NOT NULL",
                "description     VARCHAR(255) NULL",
                "payload_example TEXT NULL",
                "enabled         CHAR(1) NOT NULL DEFAULT '1'",
                "created_at      TIMESTAMP NULL,",
                "updated_at      TIMESTAMP NULL",
            ] {
                assert!(sql.contains(frag), "{backend:?} 缺列片段 [{frag}]: {sql}");
            }
        }
    }

    /// sys_alert_rule 建表 SQL：三方言与重构前手抄 DDL 等价
    /// （threshold：PG 为 DOUBLE PRECISION，其余 DOUBLE；时间列：PG TIMESTAMP，其余 DATETIME）
    #[test]
    fn alert_create_table_sql_matches_legacy_ddl() {
        for (backend, threshold, last_fired, created, updated) in [
            (
                DatabaseBackend::Sqlite,
                "DOUBLE NOT NULL",
                "last_fired_at      DATETIME,",
                "created_at         DATETIME,",
                "updated_at         DATETIME",
            ),
            (
                DatabaseBackend::MySql,
                "DOUBLE NOT NULL",
                "last_fired_at      DATETIME NULL,",
                "created_at         DATETIME,",
                "updated_at         DATETIME",
            ),
            (
                DatabaseBackend::Postgres,
                "DOUBLE PRECISION NOT NULL",
                "last_fired_at      TIMESTAMP,",
                "created_at         TIMESTAMP,",
                "updated_at         TIMESTAMP",
            ),
        ] {
            let sql = alert_mig::create_table_sql(backend);
            assert!(sql.starts_with("CREATE TABLE IF NOT EXISTS sys_alert_rule"));
            assert!(sql.contains(&format!("threshold          {threshold}")));
            assert!(sql.contains(last_fired), "{backend:?} last_fired_at 不符");
            assert!(sql.contains(created), "{backend:?} created_at 不符");
            assert!(sql.contains(updated), "{backend:?} updated_at 不符");
            for frag in [
                "name               VARCHAR(64) NOT NULL",
                "metric             VARCHAR(64) NOT NULL",
                "comparator         VARCHAR(2) NOT NULL",
                "silent_minutes     INT NOT NULL DEFAULT 30",
                "notify_channel_id  BIGINT",
                "notify_template_id BIGINT",
                "enabled            CHAR(1) DEFAULT '1'",
            ] {
                assert!(sql.contains(frag), "{backend:?} 缺列片段 [{frag}]: {sql}");
            }
        }
    }

    /// webhook 种子事件：16 个事件键集合与重构前手抄 WEBHOOK_SEED_EVENTS 一致
    #[test]
    fn webhook_seed_events_match_legacy_set() {
        const LEGACY_KEYS: &[&str] = &[
            "user.created",
            "user.updated",
            "user.deleted",
            "role.created",
            "role.updated",
            "role.deleted",
            "login.success",
            "login.failed",
            "tenant.created",
            "tenant.disabled",
            "config.updated",
            "dict.updated",
            "notice.published",
            "job.executed",
            "job.failed",
            "webhook.test",
        ];
        let events = webhook_mig::WEBHOOK_SEED_EVENTS;
        assert_eq!(events.len(), 16, "种子事件应为 16 个");
        for (i, key) in LEGACY_KEYS.iter().enumerate() {
            assert_eq!(&events[i].0, key, "第 {i} 个事件键漂移");
        }
        // 语句体：转义 + NOW() 形态 + enabled '1' 与重构前手抄一致
        let bodies = webhook_mig::webhook_event_seed_bodies("NOW()");
        assert_eq!(bodies.len(), 16);
        assert_eq!(
            bodies[0],
            "sys_webhook_event (event_key, name, description, payload_example, enabled, created_at, updated_at) VALUES ('user.created', '用户创建', '新用户创建成功后触发（sys_user 新增事务提交后）', '{\"userId\":1,\"userName\":\"admin\",\"nickName\":\"超级管理员\",\"tenantId\":0,\"time\":\"2026-10-03 00:00:00\"}', '1', NOW(), NOW())"
        );
        for body in &bodies {
            assert!(body.contains(", '1', NOW(), NOW())"), "语句体尾部形态漂移");
        }
    }

    /// webhook 菜单按钮：3562/3563 + role_menu(2,·)，语句体与重构前手抄逐字符等价
    #[test]
    fn webhook_menu_seed_bodies_match_legacy_sql() {
        let bodies = webhook_mig::webhook_menu_seed_bodies("NOW()");
        assert_eq!(bodies.len(), 4);
        assert_eq!(
            bodies[0],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES (3562, '事件目录', 158, 1, '', '', '', '', '1', '0', 'F', '0', '0', 'system:webhook:event:list', 'list', 'admin', NOW(), 'WebHook 事件目录查询', '0')"
        );
        assert_eq!(
            bodies[1],
            "sys_role_menu (role_id, menu_id) VALUES (2, 3562)"
        );
        assert_eq!(
            bodies[2],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES (3563, '测试发送', 158, 2, '', '', '', '', '1', '0', 'F', '0', '0', 'system:webhook:test-send', 'message', 'admin', NOW(), '按事件样例构造真实测试发送', '0')"
        );
        assert_eq!(
            bodies[3],
            "sys_role_menu (role_id, menu_id) VALUES (2, 3563)"
        );
    }

    /// 告警菜单种子：4110-4114 集合一致；仅页面 4110 授予 role_menu(2,·)
    #[test]
    fn alert_menu_seed_bodies_match_legacy_sql() {
        let bodies = alert_mig::alert_menu_seed_bodies("NOW()");
        assert_eq!(bodies.len(), 6, "页面 role_menu + 5 菜单行");
        assert_eq!(
            bodies[0],
            "sys_menu (menu_id, menu_name, parent_id, order_num, path, component, query, route_name, is_frame, is_cache, menu_type, visible, status, perms, icon, create_by, create_time, remark, del_flag) VALUES (4110, '告警规则', 2, 60, 'alert', 'monitor/alert/index', '', '', '1', '0', 'C', '0', '0', 'monitor:alert:list', 'alert', 'admin', NOW(), '告警规则引擎菜单', '0')"
        );
        assert_eq!(
            bodies[1],
            "sys_role_menu (role_id, menu_id) VALUES (2, 4110)"
        );
        // 按钮 4111-4114 不授予 role_menu（与迁移/兜底原行为一致）
        let joined = bodies.join("\n");
        for (id, perms) in [
            (4111, "monitor:alert:query"),
            (4112, "monitor:alert:add"),
            (4113, "monitor:alert:edit"),
            (4114, "monitor:alert:remove"),
        ] {
            assert!(
                joined.contains(&format!("VALUES ({id}, '告警")),
                "按钮 {id} 缺失"
            );
            assert!(joined.contains(perms), "按钮 {id} perms 漂移");
        }
        assert_eq!(
            joined.matches("sys_role_menu").count(),
            1,
            "仅页面 4110 有 role_menu"
        );
    }

    /// 索引单一事实源：迁移导出的索引清单与重构前两侧手抄一致
    #[test]
    fn index_consts_match_legacy_sets() {
        assert_eq!(
            audit_mig::AUDIT_INDEXES,
            &[
                (
                    "idx_audit_change_row",
                    "sys_audit_change",
                    "table_name, row_pk"
                ),
                ("idx_audit_change_time", "sys_audit_change", "operated_at"),
                ("idx_audit_change_tenant", "sys_audit_change", "tenant_id"),
            ]
        );
        assert_eq!(
            webhook_mig::WEBHOOK_INDEXES,
            &[
                (
                    "uk_sys_webhook_event_key",
                    "sys_webhook_event",
                    "event_key",
                    true
                ),
                ("uk_sys_pat_access_key", "sys_pat", "access_key", true),
            ]
        );
        assert_eq!(
            alert_mig::ALERT_INDEXES,
            &[("idx_alert_rule_enabled", "sys_alert_rule", "enabled", false)]
        );
    }
}

#[cfg(test)]
mod flow_backfill_tests {
    use super::*;
    use sea_orm::Database;

    /// 依赖表最小 DDL（种子写入目标：sys_menu/sys_role_menu/sys_dict_type/sys_dict_data/
    /// sys_msg_channel/sys_msg_template；列结构对齐各自迁移，仅保留种子涉及列 + 唯一键）
    const MIN_SEED_TABLES: &[&str] = &[
        "CREATE TABLE sys_menu (menu_id INTEGER PRIMARY KEY, menu_name VARCHAR(64), parent_id INTEGER, order_num INTEGER, path VARCHAR(64), component VARCHAR(64), query VARCHAR(64), route_name VARCHAR(64), is_frame VARCHAR(2), is_cache VARCHAR(2), menu_type VARCHAR(2), visible VARCHAR(2), status VARCHAR(2), perms VARCHAR(64), icon VARCHAR(64), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1), i18n_key VARCHAR(64))",
        "CREATE TABLE sys_role_menu (role_id BIGINT, menu_id BIGINT, PRIMARY KEY (role_id, menu_id))",
        "CREATE TABLE sys_dict_type (dict_id INTEGER PRIMARY KEY, dict_name VARCHAR(64), dict_type VARCHAR(64) UNIQUE, status VARCHAR(2), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1))",
        "CREATE TABLE sys_dict_data (dict_code INTEGER PRIMARY KEY, dict_sort INTEGER, dict_label VARCHAR(64), dict_value VARCHAR(64), dict_type VARCHAR(64), css_class VARCHAR(64), list_class VARCHAR(64), is_default VARCHAR(2), status VARCHAR(2), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1), dict_label_en VARCHAR(64))",
        "CREATE TABLE sys_msg_channel (channel_id INTEGER PRIMARY KEY AUTOINCREMENT, channel_name VARCHAR(64), channel_code VARCHAR(64) UNIQUE, channel_type VARCHAR(32), config_json TEXT, status VARCHAR(2), remark VARCHAR(500), create_by VARCHAR(64), create_time DATETIME, del_flag VARCHAR(1))",
        "CREATE TABLE sys_msg_template (template_id INTEGER PRIMARY KEY AUTOINCREMENT, template_name VARCHAR(64), template_code VARCHAR(64) UNIQUE, channel_code VARCHAR(64), template_subject VARCHAR(200), template_content TEXT, status VARCHAR(2), remark VARCHAR(500), create_by VARCHAR(64), create_time DATETIME, del_flag VARCHAR(1))",
    ];

    /// 场景 1：全新空库（连 sys_menu 都没有）→ 三表兜底建出、种子安全跳过、不阻断启动
    #[tokio::test]
    async fn flow_backfill_on_empty_db_creates_tables_and_skips_seeds() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        ensure_flow_module(&db).await.unwrap();
        let tables = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('sys_flow_task','sys_flow_log','flow_demo_doc')".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(tables.len(), 3, "空库应兜底建出三张 flow 表");
    }

    /// 场景 2：存量库（有 sys_menu 等系统表）→ 种子落库 + 重复调用幂等（不报错、不重复行）
    #[tokio::test]
    async fn flow_backfill_is_idempotent_on_existing_db() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        for ddl in MIN_SEED_TABLES {
            db.execute_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                ddl.to_string(),
            ))
            .await
            .unwrap();
        }
        // 首次调用：种子落库
        ensure_flow_module(&db).await.unwrap();
        // 重复调用（模拟每次启动）：幂等不报错
        ensure_flow_module(&db).await.unwrap();

        let count_menu: u64 = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_menu WHERE menu_id = 3600".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap() as u64;
        assert_eq!(count_menu, 1, "menu 3600 应恰一条（幂等防重）");

        let count_tpl: u64 = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_msg_template WHERE template_code IN ('flow_todo','flow_timeout','flow_reject')".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap() as u64;
        assert_eq!(count_tpl, 3, "三条 flow 模板应恰各一条（UNIQUE 幂等）");

        let count_dict: u64 = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_dict_data WHERE dict_type = 'sys_flow_task_status'"
                    .to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap() as u64;
        assert_eq!(count_dict, 7, "审批状态字典应恰 7 条");
    }
}

#[cfg(test)]
mod tenant_host_chain_self_check_tests {
    use super::*;

    /// 台账 MT-4 / E-2（第十批）：域名链路「静默失效」自检的**可证伪**回归锁。
    ///
    /// 语义：`trusted_proxies` 为空 **且** 存在启用中的 `sys_tenant_domain` 行
    /// ⇒ 域名链路必然静默失效，自检必须"报出来"（返回告警计数）。
    ///
    /// 三条断言分别锁住：① 该组合**确实触发**（不是恒 None 的死检查）；
    /// ② 配了白名单即**不再告警**（避免噪音）；③ 无域名绑定即**不告警**
    /// （开发/单机环境的正常态）。任一条件被写反/写漏，本测试即红。
    #[tokio::test]
    async fn warns_only_when_proxies_empty_and_domain_bound() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("建库失败");
        let backend = db.get_database_backend();

        // 干净起点：清空域名表（迁移可能已带入种子，避免依赖其数量）
        db.execute_raw(Statement::from_string(
            backend,
            "DELETE FROM sys_tenant_domain".to_string(),
        ))
        .await
        .expect("清空 sys_tenant_domain 失败");

        let empty: Vec<String> = vec![];
        let non_empty = vec!["127.0.0.1".to_string()];

        // ③ 无域名绑定 + 白名单为空 ⇒ 不告警（开发/单机正常态）
        assert_eq!(
            tenant_host_chain_self_check(&db, &empty).await,
            None,
            "无启用域名绑定时不应告警"
        );

        // 插入 1 条启用中的绑定 + 1 条已停用（不应计入）
        db.execute_raw(Statement::from_string(
            backend,
            "INSERT INTO sys_tenant_domain (tenant_id, domain, domain_type, is_primary, \
             verify_status, status, del_flag) \
             VALUES (9030, 'mt4-active.test', '0', '0', '1', '0', '0')"
                .to_string(),
        ))
        .await
        .expect("插入启用域名失败");
        db.execute_raw(Statement::from_string(
            backend,
            "INSERT INTO sys_tenant_domain (tenant_id, domain, domain_type, is_primary, \
             verify_status, status, del_flag) \
             VALUES (9030, 'mt4-disabled.test', '0', '1', '1', '1', '0')"
                .to_string(),
        ))
        .await
        .expect("插入停用域名失败");
        // 启用但**未验证**：不参与 host→tid 解析（`find_active_by_domain` 要求 verify_status='1'），
        // 故不应计入告警数——锁住"自检口径 == 真实解析口径"，避免未验证绑定引发误报。
        db.execute_raw(Statement::from_string(
            backend,
            "INSERT INTO sys_tenant_domain (tenant_id, domain, domain_type, is_primary, \
             verify_status, status, del_flag) \
             VALUES (9030, 'mt4-unverified.test', '0', '1', '0', '0', '0')"
                .to_string(),
        ))
        .await
        .expect("插入未验证域名失败");

        // ① 白名单为空 + 有可解析域名 ⇒ 必须告警，且计数只含"可解析"行（=1：启用+已验证）
        assert_eq!(
            tenant_host_chain_self_check(&db, &empty).await,
            Some(1),
            "trusted_proxies 为空且存在**可解析**域名绑定时应告警，且计数仅含 \
             status='0' AND verify_status='1' 的行（停用/未验证行不得计入）"
        );

        // ② 配了白名单 ⇒ 不告警（域名链路可用，无需提示）
        assert_eq!(
            tenant_host_chain_self_check(&db, &non_empty).await,
            None,
            "已配置 trusted_proxies 时不应告警"
        );

        // 清理
        db.execute_raw(Statement::from_string(
            backend,
            "DELETE FROM sys_tenant_domain WHERE domain LIKE 'mt4-%'".to_string(),
        ))
        .await
        .expect("清理域名样本失败");
    }
}

#[cfg(test)]
mod dept_leader_backfill_tests {
    use super::*;
    use sea_orm::Database;

    /// 平台部门主管回填：作用域正确 + 可证伪 + 幂等
    ///
    /// 背景（P0 业务阻断）：`ApproverPolicy::DeptLeader` 依赖 `sys_dept.leader_user_id`。
    /// 迁移 `m20260923_000002` 的回填只在「列刚新建」时执行（`has_column` 即早退），
    /// 存量库（列为历史 initialize 所加）会全部为 NULL ⇒ 提交单据必然 400
    /// `error.flow.leader_missing`，部门主管审批整链不可用。故 `initialize` 增加
    /// 每次启动都执行的幂等回填。本测试**主动构造存量库漂移**（主管全部置 NULL），
    /// 因此能真正证伪：若回填函数被移除、作用域写错（漏 `tenant_id = 0`）或失去幂等性，
    /// 断言必红。（不放集成测试：集成库会跑 `Migrator::up`，迁移自身已回填 ⇒ 不可证伪。）
    #[tokio::test]
    async fn ensure_platform_dept_leaders_backfills_platform_only_and_is_idempotent() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("建库失败");
        let backend = db.get_database_backend();

        // 构造两个确定性样本：平台部门（tenant_id=0）与租户部门（tenant_id=7）
        db.execute_raw(Statement::from_string(
            backend,
            "INSERT INTO sys_dept (tenant_id, dept_id, dept_name, leader_user_id, status, del_flag) \
             VALUES (0, 910001, '回填测试-平台部门', NULL, '0', '0')"
                .to_string(),
        ))
        .await
        .expect("插入平台样本部门失败");
        db.execute_raw(Statement::from_string(
            backend,
            "INSERT INTO sys_dept (tenant_id, dept_id, dept_name, leader_user_id, status, del_flag) \
             VALUES (7, 910002, '回填测试-租户部门', NULL, '0', '0')"
                .to_string(),
        ))
        .await
        .expect("插入租户样本部门失败");

        // 模拟存量库漂移：全部主管置空
        db.execute_raw(Statement::from_string(
            backend,
            "UPDATE sys_dept SET leader_user_id = NULL".to_string(),
        ))
        .await
        .expect("模拟漂移失败");

        // 首次调用：平台部门应被回填
        let first = ensure_platform_dept_leaders(&db)
            .await
            .expect("平台部门主管回填失败");
        assert!(first >= 1, "存量库应至少回填 1 个平台部门，实际 {first}");
        assert_eq!(
            dept_leader(&db, 910001).await,
            Some(1),
            "平台部门主管应回填为 admin(1)"
        );
        assert_eq!(
            dept_leader(&db, 910002).await,
            None,
            "租户部门不得被平台回填（否则构成跨租户越权审批）"
        );
        let null_platform = scalar(
            &db,
            "SELECT COUNT(*) AS c FROM sys_dept WHERE tenant_id = 0 AND leader_user_id IS NULL",
        )
        .await;
        assert_eq!(null_platform, 0, "平台部门不得残留无主管");

        // 二次调用：天然幂等（0 行受影响）
        let second = ensure_platform_dept_leaders(&db)
            .await
            .expect("二次回填失败");
        assert_eq!(second, 0, "重复调用应无副作用（幂等）");
    }

    /// 列缺失时安全跳过（老库尚未补列不应报错中断启动）
    #[tokio::test]
    async fn ensure_platform_dept_leaders_skips_when_table_missing() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let rows = ensure_platform_dept_leaders(&db).await.unwrap();
        assert_eq!(rows, 0, "无 sys_dept 表时应安全返回 0 而非报错");
    }

    /// 读取某部门的主管（None = 未设置）
    async fn dept_leader(db: &DatabaseConnection, dept_id: i64) -> Option<i64> {
        let row = db
            .query_one_raw(Statement::from_string(
                db.get_database_backend(),
                format!("SELECT leader_user_id FROM sys_dept WHERE dept_id = {dept_id}"),
            ))
            .await
            .expect("查询部门主管失败")
            .expect("样本部门不存在");
        row.try_get::<Option<i64>>("", "leader_user_id")
            .expect("读取 leader_user_id 失败")
    }

    /// 单列单行标量查询（列须 `AS c` 别名）
    async fn scalar(db: &DatabaseConnection, sql: &str) -> i64 {
        db.query_one_raw(Statement::from_string(
            db.get_database_backend(),
            sql.to_string(),
        ))
        .await
        .expect("查询失败")
        .expect("无结果行")
        .try_get::<i64>("", "c")
        .expect("读取标量失败")
    }
}

#[cfg(test)]
mod scim_group_backfill_tests {
    use super::*;
    use sea_orm::Database;

    /// 存量库最小 DDL（sys_user_role **无 source 列**——模拟迁移 000008 之前的存量结构）
    const MIN_EXISTING_TABLES: &[&str] = &[
        "CREATE TABLE sys_user_role (user_id BIGINT, role_id BIGINT, PRIMARY KEY (user_id, role_id))",
        "CREATE TABLE sys_menu (menu_id INTEGER PRIMARY KEY, menu_name VARCHAR(64), parent_id INTEGER, order_num INTEGER, path VARCHAR(64), component VARCHAR(64), query VARCHAR(64), route_name VARCHAR(64), is_frame VARCHAR(2), is_cache VARCHAR(2), menu_type VARCHAR(2), visible VARCHAR(2), status VARCHAR(2), perms VARCHAR(64), icon VARCHAR(64), create_by VARCHAR(64), create_time DATETIME, remark VARCHAR(500), del_flag VARCHAR(1))",
        "CREATE TABLE sys_role_menu (role_id BIGINT, menu_id BIGINT, PRIMARY KEY (role_id, menu_id))",
    ];

    /// 场景 1：全新空库（连 sys_user_role/sys_menu 都没有）→ 三表 + 兼职表兜底建出、
    /// source 列检查与种子安全跳过、不阻断启动
    #[tokio::test]
    async fn scim_group_backfill_on_empty_db_creates_tables_and_skips_seeds() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        ensure_scim_group_module(&db).await.unwrap();
        let tables = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('sys_scim_group','sys_scim_group_binding','sys_scim_group_member','sys_user_dept')".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(tables.len(), 4, "空库应兜底建出 SCIM 三表 + 兼职表");
        // 空库无 sys_menu：菜单种子应跳过
        let menu = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sqlite_master WHERE type='table' AND name='sys_menu'"
                    .to_string(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            menu.try_get::<i64>("", "c").unwrap(),
            0,
            "空库不应凭空建出 sys_menu"
        );
    }

    /// 场景 2：存量库（sys_user_role 无 source 列 + 有 sys_menu 等系统表）→
    /// source 列补上 + 菜单种子落库 + 重复调用幂等（不报错、不重复行）
    #[tokio::test]
    async fn scim_group_backfill_is_idempotent_on_existing_db() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        for ddl in MIN_EXISTING_TABLES {
            db.execute_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                ddl.to_string(),
            ))
            .await
            .unwrap();
        }
        // 首次调用：source 列补建 + 种子落库
        ensure_scim_group_module(&db).await.unwrap();
        // 重复调用（模拟每次启动）：幂等不报错
        ensure_scim_group_module(&db).await.unwrap();

        // source 列已存在
        assert!(
            sso_has_column(&db, "sys_user_role", "source")
                .await
                .unwrap(),
            "存量库 sys_user_role 应补出 source 列"
        );

        // 菜单 148 + 3 按钮幂等防重（各恰一条）
        for menu_id in [148i64, 3620, 3621, 3622] {
            let count: i64 = db
                .query_one_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("SELECT COUNT(*) AS c FROM sys_menu WHERE menu_id = {menu_id}"),
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get::<i64>("", "c")
                .unwrap();
            assert_eq!(count, 1, "menu {menu_id} 应恰一条（幂等防重）");
        }
        let role_menu: i64 = db
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) AS c FROM sys_role_menu WHERE role_id = 2 AND menu_id IN (148,3620,3621,3622)".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "c")
            .unwrap();
        assert_eq!(role_menu, 4, "role_menu 授权应恰 4 条");
    }
}
