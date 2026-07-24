//! IP 归属地库管理 Handler（Axum 原生实现）
//!
//! 接口路径：
//! - GET    /system/ipLocation/status        查询 IP 库当前状态（文件/加载/双库）
//! - GET    /system/ipLocation/config        读取 IP 库管理配置（脱敏）
//! - PUT    /system/ipLocation/config        保存 IP 库管理配置（License Key 加密存储）
//! - POST   /system/ipLocation/update        立即触发 IP 库更新（下载+解压+校验+热加载）
//! - POST   /system/ipLocation/reload        仅热加载现有 mmdb 文件（不下载）
//!
//! 权限标识：monitor:iplocation:* （归属"系统监控"目录，parent_id=2）
//!
//! 安全：
//! - License Key / Account ID 通过 AES-256-GCM 加密后存入 sys_config
//! - GET /config 返回脱敏值（仅告知是否已配置，不返回明文）
//! - 写操作经 oper_log_middleware 自动记录到 sys_oper_log

use std::sync::Arc;

use axum::extract::State;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use garde::Validate;

use crate::common::{AjaxResult, AppError, ValidatedJson};
use crate::middleware::Operator;
use crate::service::ip_location_service::{
    IpLocationConfig, IpLocationStatus, UpdateResult,
};
use crate::state::AppState;

/// 保存 IP 库管理配置的请求 DTO
///
/// - license_key / account_id 字段为空表示"不修改"（保留原值）
/// - 非空表示"用新值覆盖"（前端不展示原值，故无法回填；保留原值需读取后再保存）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SaveConfigDto {
    /// 更新源：maxmind / p3terx
    #[garde(length(max = 20))]
    pub update_source: String,
    /// MaxMind Account ID（空字符串表示清空 / 不配置）
    ///
    /// 注：前端不展示已存储的原值，仅在用户输入新值时提交。
    /// 若用户希望保留原值，应先 GET /config 获取（但 GET 仅返回是否已配置），
    /// 故前端实际策略：表单显示空输入框，提交时若为空则保留原值（由 service 层实现）。
    #[garde(length(max = 100))]
    pub maxmind_account_id: String,
    /// MaxMind License Key（同上）
    #[garde(length(max = 200))]
    pub maxmind_license_key: String,
    /// 是否启用定时自动更新
    #[garde(skip)]
    pub auto_update_enabled: bool,
    /// 是否清空已存储的 Account ID / License Key
    ///
    /// true：清空（适合从 maxmind 切换到 p3terx 时）
    /// false：保留（若对应字段为空字符串，则不修改原值）
    #[serde(default)]
    #[garde(skip)]
    pub clear_credentials: bool,
}

/// IP 库管理配置响应（脱敏，仅告知是否已配置）
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigVo {
    pub update_source: String,
    /// Account ID 是否已配置（不返回明文）
    pub maxmind_account_id_configured: bool,
    /// License Key 是否已配置（不返回明文）
    pub maxmind_license_key_configured: bool,
    pub auto_update_enabled: bool,
}

impl From<IpLocationConfig> for ConfigVo {
    fn from(cfg: IpLocationConfig) -> Self {
        Self {
            update_source: cfg.update_source,
            maxmind_account_id_configured: !cfg.maxmind_account_id.is_empty(),
            maxmind_license_key_configured: !cfg.maxmind_license_key.is_empty(),
            auto_update_enabled: cfg.auto_update_enabled,
        }
    }
}

/// GET /system/ipLocation/status
/// 查询 IP 库当前状态
#[utoipa::path(
    get,
    path = "/system/ipLocation/status",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<IpLocationStatus>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-ip-location"
)]
pub async fn status(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<IpLocationStatus>, AppError> {
    let vo = state.ip_location_service.get_status().await?;
    Ok(AjaxResult::success(vo))
}

/// GET /system/ipLocation/config
/// 读取 IP 库管理配置（脱敏）
#[utoipa::path(
    get,
    path = "/system/ipLocation/config",
    responses(
        (status = 200, description = "查询成功", body = AjaxResult<ConfigVo>),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-ip-location"
)]
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<AjaxResult<ConfigVo>, AppError> {
    let cfg = state.ip_location_service.read_config().await?;
    Ok(AjaxResult::success(ConfigVo::from(cfg)))
}

/// PUT /system/ipLocation/config
/// 保存 IP 库管理配置（License Key 自动加密存储）
///
/// 行为：
/// - update_source / auto_update_enabled：直接覆盖
/// - maxmind_account_id / maxmind_license_key：
///   - clear_credentials=true：清空已存储值
///   - 字段非空：用新值覆盖（加密存储）
///   - 字段为空且 clear_credentials=false：保留原值
#[utoipa::path(
    put,
    path = "/system/ipLocation/config",
    request_body = SaveConfigDto,
    responses(
        (status = 200, description = "保存成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "参数错误"),
        (status = 500, description = "服务器错误"),
    ),
    tag = "system-ip-location"
)]
pub async fn save_config(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<SaveConfigDto>,
) -> Result<AjaxResult<()>, AppError> {
    // 校验 update_source 合法性
    let source = dto.update_source.to_lowercase();
    if source != "maxmind" && source != "p3terx" {
        return Err(AppError::bad_request("更新源必须为 maxmind 或 p3terx"));
    }

    // 读取现有配置，以决定是"保留原值"还是"覆盖"
    let existing = state.ip_location_service.read_config().await?;

    let (final_account_id, final_license_key) = if dto.clear_credentials {
        (String::new(), String::new())
    } else {
        // 字段为空 → 保留原值；字段非空 → 用新值覆盖
        let aid = if dto.maxmind_account_id.is_empty() {
            existing.maxmind_account_id
        } else {
            dto.maxmind_account_id.clone()
        };
        let lkey = if dto.maxmind_license_key.is_empty() {
            existing.maxmind_license_key
        } else {
            dto.maxmind_license_key.clone()
        };
        (aid, lkey)
    };

    // 切换到 maxmind 时必须有凭据
    if source == "maxmind" && (final_account_id.is_empty() || final_license_key.is_empty()) {
        return Err(AppError::bad_request(
            "切换到 maxmind 源需配置 Account ID 和 License Key",
        ));
    }

    state
        .ip_location_service
        .save_config(
            &source,
            &final_account_id,
            &final_license_key,
            dto.auto_update_enabled,
        )
        .await?;

    tracing::info!(
        "IP 库管理配置已更新：operator={}, source={}, auto_update={}",
        operator.username(),
        source,
        dto.auto_update_enabled
    );

    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.save")))
}

/// POST /system/ipLocation/update
/// 立即触发 IP 库更新（下载+解压+校验+热加载）
///
/// 可选 query 参数 `source`：强制指定更新源（不传则使用配置中的默认源）
#[utoipa::path(
    post,
    path = "/system/ipLocation/update",
    params(
        ("source" = Option<String>, Query, description = "强制指定更新源：maxmind / p3terx（不传则使用配置默认值）")
    ),
    responses(
        (status = 200, description = "更新成功", body = AjaxResult<UpdateResult>),
        (status = 400, description = "参数错误或缺少凭据"),
        (status = 500, description = "更新失败"),
    ),
    tag = "system-ip-location"
)]
pub async fn update_now(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    axum::extract::Query(query): axum::extract::Query<UpdateSourceQuery>,
) -> Result<AjaxResult<UpdateResult>, AppError> {
    let force_source = query.source.filter(|s| !s.is_empty());

    tracing::info!(
        "IP 库更新触发：operator={}, force_source={:?}",
        operator.username(),
        force_source
    );

    let result = state
        .ip_location_service
        .update_now(force_source.as_deref())
        .await?;

    Ok(AjaxResult::success(result))
}

/// POST /system/ipLocation/reload
/// 仅热加载现有 mmdb 文件（不下载，用于手动替换文件后触发）
#[utoipa::path(
    post,
    path = "/system/ipLocation/reload",
    responses(
        (status = 200, description = "热加载成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "mmdb 文件不存在或无效"),
    ),
    tag = "system-ip-location"
)]
pub async fn reload(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<()>, AppError> {
    tracing::info!("IP 库热加载触发：operator={}", operator.username());
    state.ip_location_service.reload().await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.reload")))
}

/// POST /system/ipLocation/reloadXdb
/// 仅热加载 ip2region xdb 文件（用于手动替换 xdb 文件后触发）
#[utoipa::path(
    post,
    path = "/system/ipLocation/reloadXdb",
    responses(
        (status = 200, description = "xdb 热加载成功", body = AjaxResult<serde_json::Value>),
        (status = 400, description = "xdb 文件不存在或无效"),
    ),
    tag = "system-ip-location"
)]
pub async fn reload_xdb(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<()>, AppError> {
    tracing::info!("ip2region xdb 热加载触发：operator={}", operator.username());
    state.ip_location_service.reload_xdb().await?;
    Ok(AjaxResult::success_msg(&crate::tr!("msg.success.reload")))
}

/// 用于 update_now 接口的 query 参数提取
#[derive(Debug, Deserialize)]
pub struct UpdateSourceQuery {
    #[serde(default)]
    pub source: Option<String>,
}
