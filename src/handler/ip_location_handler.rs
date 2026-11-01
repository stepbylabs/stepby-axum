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
use garde::Validate;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::{AjaxResult, AppError, ValidatedJson};
use crate::middleware::Operator;
use crate::service::ip_location_service::{IpLocationConfig, IpLocationStatus, UpdateResult};
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
    /// Account ID 是否已配置且可用（不返回明文）
    pub maxmind_account_id_configured: bool,
    /// License Key 是否已配置且可用（不返回明文）
    pub maxmind_license_key_configured: bool,
    pub auto_update_enabled: bool,
    /// 库里**有** Account ID 密文（b145 · N-144-I）
    pub account_id_present: bool,
    /// Account ID 有密文但解不开 ⇒ 界面必须说"无法解密，请重新保存"，而不是"未配置"
    pub account_id_unreadable: bool,
    /// 库里**有** License Key 密文
    pub license_key_present: bool,
    /// License Key 有密文但解不开
    pub license_key_unreadable: bool,
}

impl From<IpLocationConfig> for ConfigVo {
    fn from(cfg: IpLocationConfig) -> Self {
        Self {
            update_source: cfg.update_source,
            maxmind_account_id_configured: !cfg.maxmind_account_id.is_empty(),
            maxmind_license_key_configured: !cfg.maxmind_license_key.is_empty(),
            auto_update_enabled: cfg.auto_update_enabled,
            account_id_present: cfg.account_id_present,
            account_id_unreadable: cfg.account_id_unreadable,
            license_key_present: cfg.license_key_present,
            license_key_unreadable: cfg.license_key_unreadable,
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
        return Err(AppError::bad_request(&crate::tr!(
            "error.ip_location.source_invalid"
        )));
    }

    // 读取现有配置，以决定"这一列不动"还是"覆盖/清空"
    let existing = state.ip_location_service.read_config().await?;

    // b145（N-144-I 的写侧断面）：**空字段 = 不碰那一列**，不是"用读回来的值再写一遍"。
    // 改造前读侧交回的是解密后的明文，密文解不开时那是空串，于是"留空即沿用原值"这句话
    // 兑现不了——一次与凭据无关的保存（只翻自动更新开关）会把唯一还能救的密文覆盖成空，
    // 即"读失败驱动了一次写"（AGENTS b133 ①）。现在不碰就是不写这一列，结构上不可能丢；
    // 因此也**不再需要**"解不开就不许保存"那道 400——它当时拦的正是本可以安全完成的无关保存。
    let account_id = credential_write(&dto.maxmind_account_id, dto.clear_credentials);
    let license_key = credential_write(&dto.maxmind_license_key, dto.clear_credentials);

    // 切到 maxmind 时"凭据到底可用吗"：写新值看新值，不写则看库里的存量。
    // 存量分两种坏法——没存过（要"去填"）与存了但解不开（要"重填或清空"）——理由不同，
    // 文案必须不同：照着"请填写凭据"去重填一个库里本来就有的凭据，是把人支使去重复做一件事。
    if let Some(gap) = maxmind_credential_error(
        &source,
        account_id,
        license_key,
        CredentialFacts {
            account_present: existing.account_id_present,
            account_unreadable: existing.account_id_unreadable,
            license_present: existing.license_key_present,
            license_unreadable: existing.license_key_unreadable,
        },
    ) {
        return Err(AppError::bad_request(&gap_message(gap)));
    }

    state
        .ip_location_service
        .save_config(&source, account_id, license_key, dto.auto_update_enabled)
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

    // 入参闸门排在抢锁与下载之前（b82，两处都是实测缺陷）：
    // ① 非法 `source` 原先一路送进 service 的 `anyhow` ⇒ HTTP 500「系统内部错误，请联系管理员」，
    //    而兄弟端点 `PUT /config` 对同一个值给的是 400 + 可读文案——同一个参数两套契约，
    //    运维看到 500 会去翻服务端日志，而不是改自己写错的 URL（违反 C.8 错误响应契约统一）；
    // ② `maxmind` 缺凭据属"配置没填"这一类调用方可自行修复的前置条件，同样不该以 500 呈现，
    //    更不该为一次注定失败的请求先抢走 10 分钟的更新锁。
    // 归一化口径与 `save_config` 一致（小写比较），避免"配置认得、更新不认"的分裂行为。
    let cfg = state.ip_location_service.read_config().await?;
    let effective_source = match force_source.as_deref() {
        Some(raw) => {
            let norm = raw.to_lowercase();
            if norm != "maxmind" && norm != "p3terx" {
                return Err(AppError::bad_request(&crate::tr!(
                    "error.ip_location.source_invalid"
                )));
            }
            norm
        }
        None => cfg.update_source.clone(),
    };
    if effective_source == "maxmind"
        && (cfg.maxmind_account_id.is_empty() || cfg.maxmind_license_key.is_empty())
    {
        // b145：分"存了但解不开"与"根本没存"——前者要的是"重新保存凭据"，
        // 后者要的是"去填凭据"，给同一条提示会让运维重复做一件已经做过的事
        if cfg.any_credential_unreadable() {
            return Err(AppError::bad_request(&crate::tr!(
                "error.ip_location.credentials_unreadable"
            )));
        }
        return Err(AppError::bad_request(&crate::tr!(
            "error.ip_location.maxmind_credentials_required"
        )));
    }
    // 仅在需要覆盖默认源时把归一化后的值传下去（缺省仍由 service 读配置，行为不变）
    let force_source = if force_source.is_some() {
        Some(effective_source.as_str())
    } else {
        None
    };

    tracing::info!(
        "IP 库更新触发：operator={}, force_source={:?}",
        operator.username(),
        force_source
    );

    // P2 修复：并发/重复触发锁（10 分钟 TTL），防止连续点击重复执行
    // "下载+解压+热加载"既浪费带宽又可能造成 mmdb 文件与热加载竞态。
    // 原 SET NX EX + UUID value + EVAL CAS 释放 → 收敛为 `store.lock_acquire/lock_release`
    // （UUID fencing token 由实现内置）。
    let lock_key = "ip_location:update:lock";
    let lock_handle = state.store.lock_acquire(lock_key, 600).await.map_err(|e| {
        tracing::error!(error = %e, "IP 库更新锁写入失败（fail-closed 拒绝）");
        AppError::new(503, crate::tr!("error.ip_location.update_unavailable"))
    })?;
    let Some(lock_handle) = lock_handle else {
        return Err(AppError::bad_request(&crate::tr!(
            "error.ip_location.update_in_progress"
        )));
    };
    // b141：RAII 持有——handler future 被丢弃时写在 await 之后的 release 永不执行，
    // 锁会挂满 TTL（恢复锁同款修复，见 common::held_lock 模块文档）。
    let mut update_lock = crate::common::held_lock::HeldLock::new(state.store.clone(), lock_handle);

    let result = state.ip_location_service.update_now(force_source).await;

    // 正常路径显式释放（CAS：仅当 fencing token 匹配时删除；best-effort）
    update_lock.release().await;

    Ok(AjaxResult::success(result?))
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
    // "文件不存在"是运维状态而不是服务内部故障：本端点的 utoipa 契约早就声明了 400，
    // 原实现却把 anyhow 的错误串洗成 500「系统内部错误，请联系管理员」——客户端拿不到
    // 可执行的下一步，后端日志还平白多一条 ERROR 噪声（本轮 e2e 功能18/19 实测形状）。
    // 具体路径只进日志，不进响应体（C.9 最小暴露；页面上的状态接口本就展示 xdbPath/mmdbPath）。
    let mmdb_path = state.config.ip_location.mmdb_path.clone();
    if !std::path::Path::new(&mmdb_path).exists() {
        tracing::warn!(
            path = %mmdb_path,
            operator = %operator.username(),
            "mmdb 热加载被拒：文件不存在"
        );
        return Err(AppError::bad_request(&crate::tr!("error.ip.mmdb_missing")));
    }
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
    // 与 reload（mmdb）同口径：缺文件 ⇒ 显式 400 + 可读文案，路径仅入日志。
    let xdb_path = state.config.ip_location.xdb_path.clone();
    if !std::path::Path::new(&xdb_path).exists() {
        tracing::warn!(
            path = %xdb_path,
            operator = %operator.username(),
            "ip2region xdb 热加载被拒：文件不存在"
        );
        return Err(AppError::bad_request(&crate::tr!("error.ip.xdb_missing")));
    }
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

/// 管理端提交的凭据字段折算成"写入意图"。
///
/// 三档而不是布尔，因为调用方有三种不同意图（详见 `IpLocationService::save_config` 的同款注释）：
/// 勾了清空 ⇒ `Some("")`（真的写空）；留空 ⇒ `None`（这一列一个字都不动）；填了 ⇒ `Some(新值)`。
/// 改造前"留空"与"清空"在写侧是同一条路径（都写空串），于是"只改更新源"会顺手抹掉凭据。
fn credential_write(incoming: &str, clear_credentials: bool) -> Option<&str> {
    if clear_credentials {
        return Some("");
    }
    (!incoming.is_empty()).then_some(incoming)
}

/// 库里凭据的既成事实（读侧交回的三态，不含明文）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CredentialFacts {
    account_present: bool,
    account_unreadable: bool,
    license_present: bool,
    license_unreadable: bool,
}

/// 切到 maxmind 时凭据不可用的两种坏法。
///
/// 必须是两个变体而不是"一条通用文案"：`NotStored` 要的是"去填"，`Unreadable` 要的是
/// "重填或清空"——给同一条提示会让运维重复填一个库里本来就有的凭据（⑨：错误提示把人支使去
/// 把事实签反）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialGap {
    /// 这一列压根没有值
    NotStored,
    /// 有值但解不开（主密钥缺失/轮换过，或密文损坏）
    Unreadable,
}

/// 两种坏法 → 两条文案。
///
/// 刻意做成函数而不是在调用点内联 `match`：判据要**调用它取返回值**才能判"两条理由是否真的
/// 不同"，而扫本文件文本的 needle 对"两个分支被并成同一条"结构上不敏感——同一个键名在
/// `update_now` 里也在用，文本永远命中（b145 盘上变异实测：并键后文本锁照常绿）。
/// `tr!` 的键必须是字面量（编译期展开，变量形式会静默把键名当文案返回），所以两个分支各写一条。
fn gap_message(gap: CredentialGap) -> String {
    match gap {
        CredentialGap::NotStored => crate::tr!("error.ip_location.maxmind_credentials_required"),
        CredentialGap::Unreadable => crate::tr!("error.ip_location.credentials_unreadable"),
    }
}

/// 目标源为 maxmind 时，凭据到底可不可用；不可用则给出是哪一种坏法。
///
/// 返回 `None` 表示可以保存。
fn maxmind_credential_error(
    source: &str,
    account_id: Option<&str>,
    license_key: Option<&str>,
    facts: CredentialFacts,
) -> Option<CredentialGap> {
    if source != "maxmind" {
        return None;
    }
    // `Some(v)`：本次就要写 v（空串意味着清空 ⇒ 不可用）；`None`：沿用库里那一列的存量。
    let usable = |incoming: Option<&str>, present: bool, unreadable: bool| match incoming {
        Some(v) => !v.is_empty(),
        None => present && !unreadable,
    };
    let broken = |incoming: Option<&str>, present: bool, unreadable: bool| match incoming {
        Some(_) => false,
        None => present && unreadable,
    };
    let aid_ok = usable(account_id, facts.account_present, facts.account_unreadable);
    let lic_ok = usable(license_key, facts.license_present, facts.license_unreadable);
    if aid_ok && lic_ok {
        return None;
    }
    Some(
        if broken(account_id, facts.account_present, facts.account_unreadable)
            || broken(license_key, facts.license_present, facts.license_unreadable)
        {
            CredentialGap::Unreadable
        } else {
            CredentialGap::NotStored
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_GOOD: CredentialFacts = CredentialFacts {
        account_present: true,
        account_unreadable: false,
        license_present: true,
        license_unreadable: false,
    };
    const NONE_STORED: CredentialFacts = CredentialFacts {
        account_present: false,
        account_unreadable: false,
        license_present: false,
        license_unreadable: false,
    };

    #[test]
    fn blank_field_never_writes_the_column() {
        // 三种意图各自一个形状：留空 ⇒ 不动、清空 ⇒ 写空、填了 ⇒ 覆盖
        assert_eq!(credential_write("", false), None);
        assert_eq!(credential_write("  ", false), Some("  "));
        assert_eq!(credential_write("abc", false), Some("abc"));
        assert_eq!(credential_write("", true), Some(""));
        // 勾了清空时，即便表单里还留着值也必须以清空为准（否则前端漏清一个字段就变成"又写回去"）
        assert_eq!(credential_write("abc", true), Some(""));
    }

    #[test]
    fn maxmind_source_requires_usable_credentials_of_some_kind() {
        // 库里两个都好 + 本次不写 ⇒ 放行（这正是"只翻自动更新开关"那一类保存）
        assert_eq!(
            maxmind_credential_error("maxmind", None, None, ALL_GOOD),
            None
        );
        // 库里没存过 ⇒ "去填"
        assert_eq!(
            maxmind_credential_error("maxmind", None, None, NONE_STORED),
            Some(CredentialGap::NotStored)
        );
        // 一个本次新填、一个存量可用 ⇒ 放行
        assert_eq!(
            maxmind_credential_error(
                "maxmind",
                Some("new-id"),
                None,
                CredentialFacts {
                    account_present: false,
                    account_unreadable: false,
                    license_present: true,
                    license_unreadable: false,
                }
            ),
            None
        );
        // 非 maxmind 一律放行（镜像源不需要凭据）
        assert_eq!(
            maxmind_credential_error("p3terx", None, None, NONE_STORED),
            None
        );
    }

    #[test]
    fn unreadable_credential_is_named_as_unreadable_not_missing() {
        // 存了但解不开 ⇒ 点名"无法解密"，而不是"请填写凭据"
        let broken = CredentialFacts {
            account_present: true,
            account_unreadable: true,
            license_present: true,
            license_unreadable: false,
        };
        assert_eq!(
            maxmind_credential_error("maxmind", None, None, broken),
            Some(CredentialGap::Unreadable)
        );
        // 本次重新填了坏的那一列 ⇒ 新值可用，放行（"重填即修好"必须是可走通的路径）
        assert_eq!(
            maxmind_credential_error("maxmind", Some("id"), None, broken),
            None
        );
        // 显式清空（Some("")）意味着这一列将被写空 ⇒ 仍不可用，且理由是"没填"而非"解不开"
        assert_eq!(
            maxmind_credential_error("maxmind", Some(""), Some(""), ALL_GOOD),
            Some(CredentialGap::NotStored)
        );
        // 两列坏法并存 ⇒ 仍然报"解不开"（更可操作的那一条优先）
        assert_eq!(
            maxmind_credential_error(
                "maxmind",
                None,
                None,
                CredentialFacts {
                    account_present: true,
                    account_unreadable: true,
                    license_present: false,
                    license_unreadable: false,
                }
            ),
            Some(CredentialGap::Unreadable)
        );
    }

    /// 两条坏法必须各自给出**一条不同的**文案（判据调用 `gap_message` 取返回值）。
    ///
    /// 为什么不扫文本：本批第一版就是这么写的，而盘上变异把 `Unreadable` 分支改成与
    /// `NotStored` 同一个键之后**照常绿**——同一个键名在本文件的 `update_now` 里也在用，
    /// needle 永远命中（㉔/㊴"正向 needle 会被别处的合法字面量洗绿"的第三次复发）。
    /// 现在判的是产出：两个变体各调一次，结果必须非空且互不相等。
    /// 键能否在 zh/en 双语解析，由既有总锁 `every_i18n_key_literal_resolves_in_all_locales`
    /// 负责（它扫 `tr!` 字面量），本条不重复判、也不因此放松"必须不同"这一判据。
    #[test]
    fn the_two_gaps_render_two_distinct_messages() {
        let not_stored = gap_message(CredentialGap::NotStored);
        let unreadable = gap_message(CredentialGap::Unreadable);
        assert!(!not_stored.trim().is_empty(), "『没存过』的文案为空");
        assert!(!unreadable.trim().is_empty(), "『解不开』的文案为空");
        assert_ne!(
            not_stored, unreadable,
            "两条坏法被并成一条 ⇒ 运维会照着『请填写凭据』去重填一个库里本来就有的凭据\
             （not_stored={not_stored} unreadable={unreadable}）"
        );
    }
}
