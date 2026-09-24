//! OpenAPI 文档定义（基于 utoipa）
//!
//! 通过 `#[derive(OpenApi)]` 自动生成 OpenAPI 3.0 规范，
//! 并提供 Swagger UI 可视化界面。
//!
//! 访问路径：
//! - Swagger UI: `/swagger-ui`
//! - OpenAPI JSON: `/api-docs/openapi.json`
//! - Swagger UI 静态资源: `/swagger-ui-static/*`（本地自托管，无 CDN 依赖）

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use rust_embed::RustEmbed;
use std::sync::OnceLock;
use utoipa::OpenApi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme};

/// 嵌入的 Swagger UI 静态资源（本地自托管，替代 unpkg CDN）
///
/// 优点：
/// - 无需外网访问，中国大陆用户不再受 unpkg.com CDN 慢速影响
/// - 资源随二进制分发，单可执行文件部署一致
/// - 完整性由编译期保证，无需 SRI 校验
#[derive(RustEmbed)]
#[folder = "static/swagger-ui/"]
struct SwaggerAssets;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Yebot Axum Backend API",
        version = "1.0.0",
        description = "基于 Axum 0.8 + SeaORM 1.1 的 Yebot 后端 API",
        license(name = "MIT", identifier = "MIT"),
    ),
    paths(
        // ==================== 认证模块 ====================
        crate::handler::auth_handler::login,
        crate::handler::auth_handler::logout,
        crate::handler::auth_handler::get_info,
        crate::handler::auth_handler::captcha,
        // ==================== 用户管理 ====================
        crate::handler::sys_user_handler::list,
        crate::handler::sys_user_handler::get_info_by_id,
        crate::handler::sys_user_handler::add,
        crate::handler::sys_user_handler::edit,
        crate::handler::sys_user_handler::remove,
        crate::handler::sys_user_handler::import_template,
        crate::handler::sys_user_handler::import_data,
        // ==================== SCIM 组管理（v5-D12 Group） ====================
        crate::handler::sys_scim_group_handler::list,
        crate::handler::sys_scim_group_handler::get_info,
        crate::handler::sys_scim_group_handler::edit,
        crate::handler::sys_scim_group_handler::remove,
        // ==================== 角色管理 ====================
        crate::handler::sys_role_handler::list,
        crate::handler::sys_role_handler::get_info_by_id,
        crate::handler::sys_role_handler::add,
        crate::handler::sys_role_handler::edit,
        crate::handler::sys_role_handler::remove,
        crate::handler::sys_role_handler::change_status,
        crate::handler::sys_role_handler::data_scope,
        crate::handler::sys_role_handler::dept_tree_select,
        crate::handler::sys_role_handler::export,
        // ==================== 菜单管理 ====================
        crate::handler::sys_menu_handler::list,
        crate::handler::sys_menu_handler::treeselect,
        crate::handler::sys_menu_handler::role_menu_treeselect,
        crate::handler::sys_menu_handler::get_info_by_id,
        crate::handler::sys_menu_handler::add,
        crate::handler::sys_menu_handler::edit,
        crate::handler::sys_menu_handler::update_sort,
        crate::handler::sys_menu_handler::remove,
        // ==================== 部门管理 ====================
        crate::handler::sys_dept_handler::list,
        crate::handler::sys_dept_handler::list_exclude,
        crate::handler::sys_dept_handler::treeselect,
        crate::handler::sys_dept_handler::get_info,
        crate::handler::sys_dept_handler::add,
        crate::handler::sys_dept_handler::edit,
        crate::handler::sys_dept_handler::update_sort,
        crate::handler::sys_dept_handler::remove,
        // ==================== 岗位管理 ====================
        crate::handler::sys_post_handler::list,
        crate::handler::sys_post_handler::optionselect,
        crate::handler::sys_post_handler::get_info,
        crate::handler::sys_post_handler::add,
        crate::handler::sys_post_handler::edit,
        crate::handler::sys_post_handler::remove,
        crate::handler::sys_post_handler::export,
        // ==================== 参数配置 ====================
        crate::handler::sys_config_handler::list,
        crate::handler::sys_config_handler::get_config_by_key,
        crate::handler::sys_config_handler::get_info,
        crate::handler::sys_config_handler::add,
        crate::handler::sys_config_handler::edit,
        crate::handler::sys_config_handler::remove,
        crate::handler::sys_config_handler::refresh_cache,
        crate::handler::sys_config_handler::export,
        // ==================== 通知公告 ====================
        crate::handler::sys_notice_handler::list,
        crate::handler::sys_notice_handler::get_info,
        crate::handler::sys_notice_handler::add,
        crate::handler::sys_notice_handler::edit,
        crate::handler::sys_notice_handler::remove,
        // ==================== 字典管理 ====================
        crate::handler::sys_dict_handler::dict_type_list,
        crate::handler::sys_dict_handler::dict_type_optionselect,
        crate::handler::sys_dict_handler::dict_type_refresh_cache,
        crate::handler::sys_dict_handler::dict_type_export,
        crate::handler::sys_dict_handler::dict_type_get_info,
        crate::handler::sys_dict_handler::dict_type_add,
        crate::handler::sys_dict_handler::dict_type_edit,
        crate::handler::sys_dict_handler::dict_type_remove,
        crate::handler::sys_dict_handler::dict_data_list,
        crate::handler::sys_dict_handler::dict_data_by_type,
        crate::handler::sys_dict_handler::dict_data_get_info,
        crate::handler::sys_dict_handler::dict_data_add,
        crate::handler::sys_dict_handler::dict_data_edit,
        crate::handler::sys_dict_handler::dict_data_remove,
        // ==================== 定时任务 ====================
        crate::handler::sys_job_handler::list,
        crate::handler::sys_job_handler::get_info_by_id,
        crate::handler::sys_job_handler::add,
        crate::handler::sys_job_handler::edit,
        crate::handler::sys_job_handler::remove,
        crate::handler::sys_job_handler::change_status,
        crate::handler::sys_job_handler::run,
        crate::handler::sys_job_handler::export,
        // ==================== 任务日志 ====================
        crate::handler::sys_job_log_handler::list,
        crate::handler::sys_job_log_handler::remove,
        crate::handler::sys_job_log_handler::clean,
        crate::handler::sys_job_log_handler::export,
        // ==================== 登录日志 ====================
        crate::handler::sys_logininfor_handler::list,
        crate::handler::sys_logininfor_handler::remove,
        crate::handler::sys_logininfor_handler::unlock,
        crate::handler::sys_logininfor_handler::clean,
        crate::handler::sys_logininfor_handler::export,
        // ==================== 操作日志 ====================
        crate::handler::sys_oper_log_handler::list,
        crate::handler::sys_oper_log_handler::remove,
        crate::handler::sys_oper_log_handler::clean,
        crate::handler::sys_oper_log_handler::export,
        crate::handler::sys_oper_log_handler::stats,
        crate::handler::sys_oper_log_handler::stats_by_type,
        crate::handler::sys_oper_log_handler::alarm_status,
        crate::handler::sys_oper_log_handler::compliance_report,
        // ==================== 前端异常监控（Tier-S #1）====================
        crate::handler::sys_frontend_error_handler::report,
        crate::handler::sys_frontend_error_handler::list,
        crate::handler::sys_frontend_error_handler::info,
        crate::handler::sys_frontend_error_handler::remove,
        crate::handler::sys_frontend_error_handler::clean,
        crate::handler::sys_frontend_error_handler::stats,
        // ==================== 缓存监控 ====================
        crate::handler::monitor_cache_handler::get_cache,
        crate::handler::monitor_cache_handler::get_names,
        crate::handler::monitor_cache_handler::get_keys,
        crate::handler::monitor_cache_handler::get_value,
        crate::handler::monitor_cache_handler::clear_cache_name,
        crate::handler::monitor_cache_handler::clear_cache_key,
        crate::handler::monitor_cache_handler::clear_cache_all,
        // ==================== 在线用户 ====================
        crate::handler::monitor_online_handler::list,
        crate::handler::monitor_online_handler::force_logout,
        // ==================== 服务器监控 ====================
        crate::handler::monitor_server_handler::get_server,
        // ==================== 通用接口 ====================
        crate::handler::common_handler::upload,
        crate::handler::common_handler::download,
        crate::handler::common_handler::download_resource,
        // ==================== 代码生成（补充） ====================
        crate::handler::tool_gen_handler::batch_gen_code,
        // ==================== 报表中心 + 定时订阅推送 ====================
        crate::handler::sys_report_handler::report_list,
        crate::handler::sys_report_handler::report_info,
        crate::handler::sys_report_handler::report_add,
        crate::handler::sys_report_handler::report_edit,
        crate::handler::sys_report_handler::report_remove,
        crate::handler::sys_report_handler::report_status,
        crate::handler::sys_report_handler::report_preview,
        crate::handler::sys_report_handler::sub_list,
        crate::handler::sys_report_handler::sub_info,
        crate::handler::sys_report_handler::sub_add,
        crate::handler::sys_report_handler::sub_edit,
        crate::handler::sys_report_handler::sub_remove,
        crate::handler::sys_report_handler::sub_status,
        crate::handler::sys_report_handler::sub_run,
        // ==================== 个人访问令牌（PAT，Tier-S #3）====================
        crate::handler::sys_pat_handler::list_mine,
        crate::handler::sys_pat_handler::scope_options,
        crate::handler::sys_pat_handler::create,
        crate::handler::sys_pat_handler::revoke_mine,
        crate::handler::sys_pat_handler::list_all,
        crate::handler::sys_pat_handler::revoke_by_admin,
    ),
    components(
        schemas(
            // ==================== 实体 ====================
            crate::entity::sys_user::Model,
            crate::entity::sys_role::Model,
            crate::entity::sys_menu::Model,
            crate::entity::sys_dept::Model,
            crate::entity::sys_post::Model,
            crate::entity::sys_config::Model,
            crate::entity::sys_dict_data::Model,
            crate::entity::sys_dict_type::Model,
            crate::entity::sys_job::Model,
            crate::entity::sys_job_log::Model,
            crate::entity::sys_logininfor::Model,
            crate::entity::sys_notice::Model,
            crate::entity::sys_oper_log::Model,
            crate::entity::sys_frontend_error::Model,
            // ==================== SCIM Group（v5-D12 Group） ====================
            crate::service::scim_group_service::ScimGroupAdminRow,
            crate::service::scim_group_service::ScimGroupAdminDetail,
            crate::service::scim_group_service::ScimGroupAdminMember,
            crate::handler::sys_scim_group_handler::ScimGroupAdminUpsertDto,
            // ==================== DTO ====================
            // 认证
            crate::service::auth_service::LoginDto,
            // 用户
            crate::service::sys_user_service::UserAddDto,
            crate::service::sys_user_service::UserEditDto,
            crate::service::sys_user_service::UserQueryDto,
            // 角色
            crate::service::sys_role_service::RoleAddDto,
            crate::service::sys_role_service::RoleEditDto,
            crate::service::sys_role_service::DataScopeDto,
            crate::handler::sys_role_handler::RoleStatusDto,
            // 菜单
            crate::service::sys_menu_service::MenuAddDto,
            crate::service::sys_menu_service::MenuEditDto,
            crate::service::sys_menu_service::MenuSortDto,
            // 部门
            crate::service::sys_dept_service::DeptAddDto,
            crate::service::sys_tenant_service::TenantVo,
            crate::service::sys_tenant_service::TenantQueryDto,
            crate::service::sys_tenant_service::TenantAddDto,
            crate::service::sys_tenant_service::TenantEditDto,
            crate::service::sys_tenant_service::TenantStatusDto,
            crate::service::sys_dept_service::DeptEditDto,
            // 岗位
            crate::service::sys_post_service::PostAddDto,
            crate::service::sys_post_service::PostEditDto,
            // 参数配置
            crate::service::sys_config_service::ConfigAddDto,
            crate::service::sys_config_service::ConfigEditDto,
            // 通知公告
            crate::service::sys_notice_service::NoticeAddDto,
            crate::service::sys_notice_service::NoticeEditDto,
            // 字典
            crate::service::sys_dict_service::DictTypeAddDto,
            crate::service::sys_dict_service::DictTypeEditDto,
            crate::service::sys_dict_service::DictDataAddDto,
            crate::service::sys_dict_service::DictDataEditDto,
            // 定时任务
            crate::service::sys_job_service::JobAddDto,
            crate::service::sys_job_service::JobEditDto,
            crate::service::sys_job_service::JobStatusDto,
            crate::service::sys_job_service::JobRunDto,
            // ==================== Vo ====================
            crate::service::sys_user_service::UserVo,
            crate::service::sys_role_service::RoleVo,
            crate::service::sys_job_service::JobVo,
            // 审计合规报告
            crate::service::sys_oper_log_service::AuditStatsVo,
            crate::service::sys_oper_log_service::AuditSummary,
            crate::service::sys_oper_log_service::AuditBusinessTypeStat,
            crate::service::sys_oper_log_service::AuditOperatorStat,
            crate::service::sys_oper_log_service::AuditDailyStat,
            crate::service::sys_oper_log_service::ComplianceReportVo,
            crate::service::sys_oper_log_service::OperLogAnomaly,
            // 前端异常监控（Tier-S #1）
            crate::service::sys_frontend_error_service::FrontendErrorItem,
            crate::service::sys_frontend_error_service::FrontendReportDto,
            crate::service::sys_frontend_error_service::FrontendErrorQueryDto,
            crate::service::sys_frontend_error_service::FrontendErrorStatsVo,
            crate::service::sys_frontend_error_service::SourceCount,
            crate::service::sys_frontend_error_service::DailyErrorCount,
            // ==================== Handler 响应类型 ====================
            // 认证
            crate::handler::auth_handler::CaptchaResult,
            crate::handler::auth_handler::LoginResult,
            crate::handler::auth_handler::GetInfoResult,
            // 用户
            crate::handler::sys_user_handler::UserFormResult,
            crate::handler::sys_user_handler::ProfileResult,
            crate::handler::sys_user_handler::AuthRoleResult,
            crate::handler::sys_user_handler::AvatarUploadResult,
            // 角色
            crate::handler::sys_role_handler::RoleDeptTreeResult,
            // 菜单
            crate::handler::sys_menu_handler::RoleMenuTreeResult,
            // 缓存监控
            crate::handler::monitor_cache_handler::CacheOverview,
            crate::handler::monitor_cache_handler::CommandStat,
            crate::handler::monitor_cache_handler::SysCache,
            // 在线用户
            crate::handler::monitor_online_handler::SysUserOnline,
            // 服务器监控
            crate::handler::monitor_server_handler::ServerInfo,
            crate::handler::monitor_server_handler::CpuInfo,
            crate::handler::monitor_server_handler::MemInfo,
            crate::handler::monitor_server_handler::JvmInfo,
            crate::handler::monitor_server_handler::SysInfo,
            crate::handler::monitor_server_handler::SysFileInfo,
            // ==================== 通用响应包装 ====================
            crate::common::TreeSelectVo,
            // ==================== 通用接口 ====================
            crate::handler::common_handler::CommonUploadResult,
            // ==================== 个人访问令牌（PAT） ====================
            crate::service::sys_pat_service::PatVo,
            crate::service::sys_pat_service::CreatePatDto,
            crate::service::sys_pat_service::CreatePatResult,
        ),
    ),
    tags(
        (name = "auth", description = "认证管理"),
        (name = "system-user", description = "用户管理"),
        (name = "system-role", description = "角色管理"),
        (name = "system-menu", description = "菜单管理"),
        (name = "system-dept", description = "部门管理"),
        (name = "system-post", description = "岗位管理"),
        (name = "system-config", description = "参数配置"),
        (name = "system-notice", description = "通知公告"),
        (name = "system-dict", description = "字典管理"),
        (name = "monitor-job", description = "定时任务"),
        (name = "monitor-joblog", description = "任务日志"),
        (name = "monitor-logininfor", description = "登录日志"),
        (name = "monitor-operlog", description = "操作日志"),
        (name = "monitor-cache", description = "缓存监控"),
        (name = "monitor-online", description = "在线用户"),
        (name = "monitor-server", description = "服务器监控"),
        (name = "common", description = "通用接口"),
        (name = "tool-gen", description = "代码生成"),
        (name = "pat", description = "个人访问令牌（PAT）"),
    ),
)]
pub struct ApiDoc;

/// 构建完整 OpenAPI 规范：在 `ApiDoc::openapi()` 基础上注入全局 bearer 认证方案。
///
/// utoipa 的 derive 未声明任何 securityScheme，导致 Swagger UI 的 "Authorize" 按钮无效。
/// 这里以编程方式注册名为 `bearerAuth` 的 HTTP Bearer(JWT) 方案，并设为全局默认要求，
/// 使所有业务接口默认需要 `Authorization: Bearer <JWT 或 PAT>`；
/// 公开接口（/login、/captchaImage）通过各自 `#[utoipa::path(security(()))]` 覆盖为免鉴权。
/// PAT 与 JWT 走同一 bearer 头，故文档描述同时注明两种令牌。
fn openapi_spec() -> utoipa::openapi::OpenApi {
    let mut doc = ApiDoc::openapi();
    let components = doc.components.get_or_insert_with(Default::default);
    components.add_security_scheme(
        "bearerAuth",
        SecurityScheme::Http(
            HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("JWT")
                .description(Some(
                    "登录后签发的 JWT，或个人访问令牌（PAT，前缀 ybt_）。填入裸令牌字符串即可，无需 \"Bearer \" 前缀。",
                ))
                .build(),
        ),
    );
    doc.security = Some(vec![SecurityRequirement::new(
        "bearerAuth",
        Vec::<String>::new(),
    )]);
    doc
}

/// 缓存的 OpenAPI JSON（首次访问时生成，后续直接返回）
///
/// `ApiDoc::openapi()` 需要遍历所有 #[derive(OpenApi)] 标注的 handlers/schemas，
/// 生成完整的 OpenAPI 3.0 规范，开销较大（~10ms）。使用 OnceLock 缓存避免重复计算。
static OPENAPI_JSON_CACHE: OnceLock<String> = OnceLock::new();
/// OpenAPI 序列化失败标记（P2：失败不缓存，避免持续返回 500 内容；下次请求重试）
static OPENAPI_SERIALIZE_FAILED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// GET /api-docs/openapi.json
/// 返回 OpenAPI 3.0 JSON 规范
///
/// 递归类型（TreeSelectVo、sys_menu::Model）通过 `#[schema(no_recursion)]` 属性
/// 让 utoipa 生成 `$ref` 自引用打破递归，`ApiDoc::openapi()` 可正常生成完整文档。
///
/// 性能优化：使用 OnceLock 缓存序列化结果，避免每次请求都重新生成 + 序列化。
pub async fn openapi_json() -> impl IntoResponse {
    // P2 修复：序列化失败时置失败标记且不缓存结果；已缓存过则直接复用，
    // 失败路径下次请求重试（OnceLock 无法回滚，用 AtomicBool 标记 + 请求级兜底）
    if !OPENAPI_SERIALIZE_FAILED.load(std::sync::atomic::Ordering::Relaxed) {
        let json =
            OPENAPI_JSON_CACHE.get_or_init(|| match serde_json::to_string(&openapi_spec()) {
                Ok(json) => json,
                Err(e) => {
                    tracing::error!(
                        "OpenAPI 序列化失败（不缓存错误结果，后续请求将重试）: {}",
                        e
                    );
                    OPENAPI_SERIALIZE_FAILED.store(true, std::sync::atomic::Ordering::Relaxed);
                    "{\"error\":\"Failed to serialize OpenAPI\"}".to_string()
                }
            });
        // 克隆 String 转为 Vec<u8> 以构建响应（OnceLock 持有引用，需克隆数据）
        return (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static(crate::common::constants::CACHE_SWAGGER_SECS),
                ),
            ],
            json.clone(),
        );
    }
    // 上次序列化失败：本次重试生成（不再返回缓存错误串）
    match serde_json::to_string(&openapi_spec()) {
        Ok(json) => (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static(crate::common::constants::CACHE_SWAGGER_SECS),
                ),
            ],
            json,
        ),
        Err(e) => {
            tracing::error!("OpenAPI 序列化重试失败: {}", e);
            (
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    ),
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static(crate::common::constants::CACHE_SWAGGER_SECS),
                    ),
                ],
                "{\"error\":\"Failed to serialize OpenAPI\"}".to_string(),
            )
        }
    }
}

/// GET /swagger-ui
/// 返回 Swagger UI HTML 页面（本地自托管资源，无 CDN 依赖）
pub async fn swagger_ui() -> Html<&'static str> {
    Html(SWAGGER_UI_HTML)
}

/// GET /swagger-ui-static/:filename
/// 服务 Swagger UI 静态资源（CSS/JS），从 rust-embed 嵌入资源读取
///
/// 路径参数 `filename` 应为 `swagger-ui.css`、`swagger-ui-bundle.js` 等
pub async fn swagger_assets(
    axum::extract::Path(filename): axum::extract::Path<String>,
) -> Response {
    // 安全校验：拒绝路径穿越攻击（如 ../../../etc/passwd）
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return (StatusCode::BAD_REQUEST, "Invalid filename").into_response();
    }

    match SwaggerAssets::get(&filename) {
        Some(file) => {
            let mime = mime_guess::from_path(&filename)
                .first_or_octet_stream()
                .essence_str()
                .to_string();
            (
                StatusCode::OK,
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_str(&mime)
                            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
                    ),
                    // 静态资源 immutable 缓存（文件名含版本号，更新时路径变化）
                    (
                        header::CACHE_CONTROL,
                        HeaderValue::from_static(crate::common::constants::CACHE_IMMUTABLE_SECS),
                    ),
                ],
                file.data,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "Asset not found").into_response(),
    }
}

/// Swagger UI HTML 模板（本地自托管 swagger-ui-dist@5.32.8 资源）
///
/// 资源通过 `/swagger-ui-static/*` 路径从后端嵌入资源读取，
/// 不再依赖 unpkg.com CDN，彻底解决中国大陆 CDN 慢速问题。
///
/// 路径说明：
/// - iframe 加载 `/dev-api/swagger-ui/index.html`（前端 vite 代理到后端 `/swagger-ui`）
/// - 静态资源使用 `../swagger-ui-static/xxx`（相对路径上一级），
///   解析为 `/dev-api/swagger-ui-static/xxx`（vite 代理到后端 `/swagger-ui-static/xxx`）
/// - OpenAPI JSON 使用 `../api-docs/openapi.json`（同理）
const SWAGGER_UI_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>Yebot Axum Backend API - Swagger UI</title>
    <link rel="stylesheet" href="../swagger-ui-static/swagger-ui.css">
    <style>
        body { margin: 0; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="../swagger-ui-static/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function () {
            window.ui = SwaggerUIBundle({
                url: '../api-docs/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [SwaggerUIBundle.presets.apis],
                layout: 'BaseLayout',
            });
        };
    </script>
</body>
</html>"#;
