// stepby-axum/src/handler/upload_config_handler.rs
//! OSS 存储配置管理 Handler（G-11 第一档，对齐 sys.ai.* 平台专属范式）
//!
//! - GET  /system/uploadConfig       读有效配置（access_key/secret_key 掩码回显）
//! - PUT  /system/uploadConfig       更新配置（secret_key 传空保留原值；SSRF 校验
//!   endpoint；写后 refreshCache 热生效）
//! - POST /system/uploadConfig/test  连通性测试（ListObjectsV2 探活；入参=屏上草稿，
//!   空对象=测已存配置）
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

/// POST /system/uploadConfig/switchBackend —— backend 档位热切换（G-11 第二档）
///
/// 构建新档后端（fail-closed：s3 档配置不完整则拒绝切换）→ ArcSwap 整指针替换
/// （在途请求由旧实例 Arc 存活，无撕裂）→ 持久化 sys.upload.backend（重启后由
/// 启动恢复逻辑重新装载）。切到与当前生效档相同的档位 = 幂等（重装后端）。
#[derive(Debug, serde::Deserialize, garde::Validate, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SwitchBackendDto {
    /// 目标档位（local / s3）
    #[garde(length(min = 4, max = 8))]
    pub mode: String,
}

pub async fn switch_backend(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<SwitchBackendDto>,
) -> Result<AjaxResult<serde_json::Value>, AppError> {
    ensure_platform(&operator)?;
    let mode = dto.mode.trim().to_lowercase();
    if mode != "local" && mode != "s3" {
        return Err(AppError::bad_request(&format!(
            "不支持的存储档位: {mode}（可选 local / s3）"
        )));
    }
    let backend = state
        .upload_config_service
        .build_backend_for_mode(&mode)
        .await?;
    // ArcSwap 整指针替换（读侧无锁；在途请求持旧 Arc 至自然结束）
    state.hot_storage.store(Some(std::sync::Arc::new(
        crate::state::HotStorageBackend::new(backend),
    )));
    state
        .upload_config_service
        .persist_backend_mode(&mode)
        .await?;
    tracing::info!(
        operator = %operator.user_id(),
        mode = %mode,
        "OSS 存储档位已热切换（无需重启，即时生效）"
    );
    Ok(AjaxResult::success(serde_json::json!({
        "mode": mode,
        "message": format!("存储档位已切换为 {mode}，立即生效")
    })))
}

/// POST /system/uploadConfig/test —— 连通性测试（ListObjectsV2 探活）
///
/// **入参 = 屏上那份草稿**（与 PUT 同一个 DTO，字段集合因此不可能与保存路径漂开）：
/// - 空对象 `{}` ⇒ 所有字段缺省 ⇒ 叠加后等于**当前有效配置**，即"测已存的配置"，
///   与改造前逐字节等价（`/health` 的存储探针走的仍是 `test_connectivity`，不受影响）；
/// - 填了哪个字段 ⇒ 用该字段探活（未填的沿用有效值，`secret_key` 传空 = 保留原凭据）。
///
/// 立项原因（AGENTS 67(a) 同族）：改造前这个按钮**只能**测已存配置，管理员改完
/// endpoint/bucket 点"测试"拿到的是旧值的结果 —— 于是"测通了、保存后上传全挂"
/// 与"测失败了、但改的其实是对的"两种误导都无解。屏上那句话必须有判据支撑。
pub async fn test_config(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    ValidatedJson(dto): ValidatedJson<UploadConfigUpdateDto>,
) -> Result<AjaxResult<String>, AppError> {
    ensure_platform(&operator)?;
    let message = state
        .upload_config_service
        .test_connectivity_draft(&dto)
        .await?;
    Ok(AjaxResult::success(message))
}
