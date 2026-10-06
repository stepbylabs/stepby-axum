// stepby-axum/src/handler/upload_config_handler.rs
//! OSS 存储配置管理 Handler（G-11 第一档，对齐 sys.ai.* 平台专属范式）
//!
//! - GET  /system/uploadConfig       读有效配置（access_key/secret_key 掩码回显）
//! - PUT  /system/uploadConfig       更新配置（secret_key 传空保留原值；SSRF 校验
//!   endpoint；写后 refreshCache 热生效）
//! - POST /system/uploadConfig/test  连通性测试（ListObjectsV2 探活）
//!
//! 平台专属：三个端点均在 handler 内 `tenant_id == 0` 门控（对齐 sys.ai.*）；
//! perms 契约：`system:uploadConfig:edit`（菜单 4103，迁移 m20261007_000002）。

use std::sync::Arc;

use axum::extract::State;

use crate::common::{AjaxResult, AppError, ValidatedJson};
use crate::middleware::auth::Operator;
use crate::service::upload_config_service::{UploadConfigMaskedVo, UploadConfigUpdateDto};
use crate::state::AppState;
use crate::tr;

/// 平台专属门控（对齐 ai/handler 的 ensure_platform）
fn ensure_platform(operator: &Operator) -> Result<(), AppError> {
    if operator.tenant_id() != 0 {
        return Err(AppError::forbidden(&tr!("error.common.forbidden")));
    }
    Ok(())
}

/// GET /system/uploadConfig —— 读有效配置（敏感字段掩码，永不返回明文）
pub async fn get_config(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<UploadConfigMaskedVo>, AppError> {
    ensure_platform(&operator)?;
    Ok(AjaxResult::success(
        state.upload_config_service.masked().await?,
    ))
}

/// PUT /system/uploadConfig —— 更新配置（敏感字段传空保留原值；SSRF 校验 endpoint；
/// 写后 refreshCache 热生效 + 后端缓存重置）
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<UploadConfigUpdateDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    ensure_platform(&operator)?;
    let operator_name = operator.user_id();
    state.upload_config_service.update(&dto).await?;
    tracing::info!(operator = %operator_name, "OSS 存储配置已由平台管理员更新");
    Ok(AjaxResult::success_msg(&tr!("msg.success.operation")))
}

/// POST /system/uploadConfig/test —— 连通性测试（ListObjectsV2 探活）
pub async fn test_config(
    State(state): State<Arc<AppState>>,
    operator: Operator,
) -> Result<AjaxResult<String>, AppError> {
    ensure_platform(&operator)?;
    let message = state.upload_config_service.test_connectivity().await?;
    Ok(AjaxResult::success(message))
}
