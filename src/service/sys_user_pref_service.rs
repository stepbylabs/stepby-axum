//! 用户消息偏好 + 免打扰模块 Service 层
//!
//! 职责：
//! - 查询当前用户的消息偏好（无记录时返回默认值：全量接收、免打扰关闭）
//! - 更新当前用户的消息偏好 / 免打扰（幂等 upsert，取值与时间格式严格校验）
//! - 投递 enforcement：向投递路径（通知公告邮件、站内信）提供「是否应通知某用户」的判定，
//!   未配置偏好（缺省行）一律视为全量接收，保证默认行为不被破坏
//!
//! 分层约束：不依赖任何 Web 框架类型（axum / tower / tower-http），
//! 数据访问委托 Repository 层，状态/错误使用 ServiceError。

use garde::Validate;
use sea_orm::DatabaseConnection;
use serde::Deserialize;
use std::collections::HashSet;
use utoipa::ToSchema;

use crate::common::error::ServiceError;
use crate::entity::sys_user_pref::Model as PrefModel;
use crate::repository::sys_user_pref::SysUserPrefRepository;

/// 通知渠道 / 类型分类（用于 enforcement 判定）
///
/// 各渠道对应的偏好开关：
/// - Sysmsg   ：站内信 → 由 sysmsg_notify 控制
/// - Announce ：系统通知/公告 → 由 announce_notify 控制
/// - Email    ：公告邮件（批量投递）→ 由 email_notify 且 announce_notify 共同控制
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefChannel {
    Sysmsg,
    Announce,
    Email,
}

impl PrefChannel {
    fn allows(&self, p: &PrefModel) -> bool {
        match self {
            PrefChannel::Sysmsg => p.sysmsg_notify == "1",
            PrefChannel::Announce => p.announce_notify == "1",
            PrefChannel::Email => p.email_notify == "1" && p.announce_notify == "1",
        }
    }
}

/// 消息偏好出参 VO
#[derive(Debug, Clone, serde::Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrefVo {
    pub user_id: i64,
    /// 是否接收公告邮件（'1' 是，默认；'0' 否）
    pub email_notify: String,
    /// 是否接收站内信通知（'1' 是，默认；'0' 否）
    pub sysmsg_notify: String,
    /// 是否接收通知公告（'1' 是，默认；'0' 否）
    pub announce_notify: String,
    /// 是否启用免打扰（'0' 否，默认；'1' 是）
    pub dnd_enabled: String,
    /// 免打扰开始时间（HH:MM）
    pub dnd_start: String,
    /// 免打扰结束时间（HH:MM）
    pub dnd_end: String,
}

impl PrefVo {
    /// 缺省偏好（无记录时使用：全量接收、免打扰关闭）
    fn defaults(user_id: i64) -> Self {
        Self {
            user_id,
            email_notify: "1".to_string(),
            sysmsg_notify: "1".to_string(),
            announce_notify: "1".to_string(),
            dnd_enabled: "0".to_string(),
            dnd_start: String::new(),
            dnd_end: String::new(),
        }
    }

    fn from_model(m: &PrefModel) -> Self {
        Self {
            user_id: m.user_id,
            email_notify: m.email_notify.clone(),
            sysmsg_notify: m.sysmsg_notify.clone(),
            announce_notify: m.announce_notify.clone(),
            dnd_enabled: m.dnd_enabled.clone(),
            dnd_start: m.dnd_start.clone(),
            dnd_end: m.dnd_end.clone(),
        }
    }
}

/// 消息偏好更新 DTO
///
/// 字段均可选（部分更新）：未提供的字段沿用现有值（无记录时沿用默认值）。
/// 取值约束：notify 与 dnd_enabled 必须是 '0' 或 '1'；dnd_start/end 必须为合法 HH:MM。
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PrefUpdateDto {
    #[garde(skip)]
    pub email_notify: Option<String>,
    #[garde(skip)]
    pub sysmsg_notify: Option<String>,
    #[garde(skip)]
    pub announce_notify: Option<String>,
    #[garde(skip)]
    pub dnd_enabled: Option<String>,
    #[garde(length(max = 5))]
    pub dnd_start: Option<String>,
    #[garde(length(max = 5))]
    pub dnd_end: Option<String>,
}

// ==================== Service ====================

/// 用户消息偏好模块 Service
pub struct SysUserPrefService {
    pref_repo: SysUserPrefRepository,
}

impl SysUserPrefService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            pref_repo: SysUserPrefRepository::new(db),
        }
    }

    /// 查询当前用户偏好（无记录返回默认值：全量接收、免打扰关闭）
    pub async fn get(&self, user_id: i64) -> Result<PrefVo, ServiceError> {
        match self.pref_repo.find_by_user_id(user_id).await? {
            Some(m) => Ok(PrefVo::from_model(&m)),
            None => Ok(PrefVo::defaults(user_id)),
        }
    }

    /// 更新当前用户偏好（幂等 upsert）
    ///
    /// 校验通过后写入。部分更新字段沿用现有值（无记录时沿用默认值）。
    pub async fn update(&self, user_id: i64, dto: PrefUpdateDto) -> Result<PrefVo, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        Self::validate_dto(&dto)?;

        let existing = self.pref_repo.find_by_user_id(user_id).await?;

        // 取「合并后」的各字段值：显式给定则用之，否则沿用现有（缺省则用默认）
        let base = existing
            .as_ref()
            .map(PrefVo::from_model)
            .unwrap_or_else(|| PrefVo::defaults(user_id));
        let vo = PrefVo {
            user_id,
            email_notify: dto.email_notify.clone().unwrap_or(base.email_notify),
            sysmsg_notify: dto.sysmsg_notify.clone().unwrap_or(base.sysmsg_notify),
            announce_notify: dto.announce_notify.clone().unwrap_or(base.announce_notify),
            dnd_enabled: dto.dnd_enabled.clone().unwrap_or(base.dnd_enabled),
            dnd_start: dto.dnd_start.clone().unwrap_or(base.dnd_start),
            dnd_end: dto.dnd_end.clone().unwrap_or(base.dnd_end),
        };

        self.pref_repo.upsert(user_id, &vo_to_model(&vo)).await?;
        Ok(vo)
    }

    /// 校验更新 DTO 的取值与时间格式
    fn validate_dto(dto: &PrefUpdateDto) -> Result<(), ServiceError> {
        for (field, name) in [
            (&dto.email_notify, "email_notify"),
            (&dto.sysmsg_notify, "sysmsg_notify"),
            (&dto.announce_notify, "announce_notify"),
            (&dto.dnd_enabled, "dnd_enabled"),
        ] {
            if let Some(v) = field
                && v != "0"
                && v != "1"
            {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.pref.value_invalid",
                    field = name
                )));
            }
        }
        for (field, name) in [(&dto.dnd_start, "dnd_start"), (&dto.dnd_end, "dnd_end")] {
            if let Some(v) = field
                && !v.is_empty()
                && parse_hm(v).is_none()
            {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.pref.time_invalid",
                    field = name,
                    value = v
                )));
            }
        }
        Ok(())
    }

    // ==================== Enforcement 判定 ====================

    /// 判定某用户当前是否应接收指定渠道的通知（结合免打扰窗口）
    ///
    /// 无偏好记录（缺省行）一律视为可接收（全量开启），保证默认行为不被破坏。
    /// 未启用免打扰或启用了但当前不在时间窗内 → 判定为可接收。
    pub async fn can_receive(
        &self,
        user_id: i64,
        channel: PrefChannel,
    ) -> Result<bool, ServiceError> {
        let row = self.pref_repo.find_by_user_id(user_id).await?;
        Ok(match row {
            None => true,
            Some(p) => channel.allows(&p) && !Self::dnd_active(&p),
        })
    }

    /// 批量判定：返回其中「应接收」的 user_id 集合（含无偏好记录的缺省允许）
    ///
    /// 供管理员批量为大量用户投递（如公告邮件）时一次查询判断，避免逐用户 N 次查询。
    pub async fn filter_receivable(
        &self,
        user_ids: &[i64],
        channel: PrefChannel,
    ) -> Result<HashSet<i64>, ServiceError> {
        let rows = self.pref_repo.find_by_user_ids(user_ids).await?;
        let mut allowed: HashSet<i64> = user_ids.iter().copied().collect();
        for p in &rows {
            if !channel.allows(p) || Self::dnd_active(p) {
                allowed.remove(&p.user_id);
            }
        }
        Ok(allowed)
    }

    /// 免打扰窗口当前是否生效（dnd_enabled='1' 且当前时刻落在 [start, end) 内）
    fn dnd_active(p: &PrefModel) -> bool {
        p.dnd_enabled == "1"
            && !p.dnd_start.is_empty()
            && !p.dnd_end.is_empty()
            && is_in_dnd_window(&p.dnd_start, &p.dnd_end, &now_hm_str())
    }
}

// ==================== 纯函数辅助 ====================

/// 解析 `HH:MM` 为「当日第几分钟」，非法输入返回 None
fn parse_hm(s: &str) -> Option<i32> {
    let bytes: Vec<&str> = s.split(':').collect();
    let [h, m] = bytes.as_slice() else {
        return None;
    };
    // 要求严格 `HH:MM`（时/分均为两位十进制）
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let h: i32 = h.parse().ok()?;
    let m: i32 = m.parse().ok()?;
    if !(0..=23).contains(&h) || !(0..=59).contains(&m) {
        return None;
    }
    Some(h * 60 + m)
}

/// 当前时刻（服务器本地时区）的 `HH:MM`
pub fn now_hm_str() -> String {
    chrono::Local::now().format("%H:%M").to_string()
}

/// 投递判定纯函数：结合渠道开关与免打扰窗口，判断该偏好是否允许当前投递
///
/// 供各投递路径（通知公告邮件、站内信）直接复用，避免在多处重复实现 DND 判定。
/// `now_hm` 形如 `"HH:MM"`（如需服务器当前时刻可用 [`now_hm_str`]）。
pub fn allows_delivery(channel: PrefChannel, p: &PrefModel, now_hm: &str) -> bool {
    channel.allows(p)
        && !(p.dnd_enabled == "1"
            && !p.dnd_start.is_empty()
            && !p.dnd_end.is_empty()
            && is_in_dnd_window(&p.dnd_start, &p.dnd_end, now_hm))
}

/// 判断时刻 `now` 是否落在免打扰窗口 [start, end) 内
///
/// - 同天窗口（start <= end）：`now` 在 [start, end) 内即命中
/// - 跨天窗口（start > end，如 22:00 → 06:00）：落在 [start, 24:00) 或 [00:00, end) 内即命中
/// - 任一参数非法（非 HH:MM）→ 返回 false（保守地视为不在窗口内）
pub fn is_in_dnd_window(start: &str, end: &str, now: &str) -> bool {
    let (Some(s), Some(e), Some(n)) = (parse_hm(start), parse_hm(end), parse_hm(now)) else {
        return false;
    };
    if s <= e {
        n >= s && n < e
    } else {
        n >= s || n < e
    }
}

/// 将 PrefVo 转换为可写入库的 Model
fn vo_to_model(vo: &PrefVo) -> PrefModel {
    PrefModel {
        user_id: vo.user_id,
        email_notify: vo.email_notify.clone(),
        sysmsg_notify: vo.sysmsg_notify.clone(),
        announce_notify: vo.announce_notify.clone(),
        dnd_enabled: vo.dnd_enabled.clone(),
        dnd_start: vo.dnd_start.clone(),
        dnd_end: vo.dnd_end.clone(),
        extra: None,
        update_time: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hm() {
        assert_eq!(parse_hm("00:00"), Some(0));
        assert_eq!(parse_hm("08:30"), Some(510));
        assert_eq!(parse_hm("23:59"), Some(1439));
        assert_eq!(parse_hm("24:00"), None);
        assert_eq!(parse_hm("08:60"), None);
        assert_eq!(parse_hm("8:30"), None);
        assert_eq!(parse_hm("abc"), None);
        assert_eq!(parse_hm(""), None);
        assert_eq!(parse_hm("08"), None);
    }

    #[test]
    fn test_is_in_dnd_window_same_day() {
        // 08:00 – 18:00，正常窗口
        assert!(is_in_dnd_window("08:00", "18:00", "10:00"));
        assert!(is_in_dnd_window("08:00", "18:00", "08:00")); // 含起点
        assert!(!is_in_dnd_window("08:00", "18:00", "18:00")); // 不含终点
        assert!(!is_in_dnd_window("08:00", "18:00", "07:59"));
        assert!(!is_in_dnd_window("08:00", "18:00", "23:00"));
    }

    #[test]
    fn test_is_in_dnd_window_overnight_wrap() {
        // 22:00 – 06:00 跨天
        assert!(is_in_dnd_window("22:00", "06:00", "23:30"));
        assert!(is_in_dnd_window("22:00", "06:00", "00:30"));
        assert!(is_in_dnd_window("22:00", "06:00", "22:00"));
        assert!(!is_in_dnd_window("22:00", "06:00", "06:00"));
        assert!(!is_in_dnd_window("22:00", "06:00", "12:00"));
        assert!(!is_in_dnd_window("22:00", "06:00", "21:59"));
    }

    #[test]
    fn test_is_in_dnd_window_invalid_returns_false() {
        assert!(!is_in_dnd_window("", "", "10:00"));
        assert!(!is_in_dnd_window("08:00", "bad", "10:00"));
        assert!(!is_in_dnd_window("08:00", "18:00", "bad"));
        assert!(!is_in_dnd_window("08:00", "18:00", ""));
    }

    #[test]
    fn test_channel_allows() {
        let mut p = PrefModel {
            user_id: 1,
            email_notify: "1".into(),
            sysmsg_notify: "1".into(),
            announce_notify: "1".into(),
            dnd_enabled: "0".into(),
            dnd_start: String::new(),
            dnd_end: String::new(),
            extra: None,
            update_time: None,
        };
        assert!(PrefChannel::Sysmsg.allows(&p));
        assert!(PrefChannel::Announce.allows(&p));
        assert!(PrefChannel::Email.allows(&p)); // email 需 announce 同时开启

        p.announce_notify = "0".into();
        assert!(PrefChannel::Sysmsg.allows(&p));
        assert!(!PrefChannel::Announce.allows(&p));
        assert!(!PrefChannel::Email.allows(&p)); // announce 关闭则公告邮件也关闭

        p.sysmsg_notify = "0".into();
        assert!(!PrefChannel::Sysmsg.allows(&p));
    }

    #[test]
    fn test_validate_dto_rejects_bad_flag() {
        let dto = PrefUpdateDto {
            email_notify: Some("5".into()),
            sysmsg_notify: None,
            announce_notify: None,
            dnd_enabled: None,
            dnd_start: None,
            dnd_end: None,
        };
        let err = SysUserPrefService::validate_dto(&dto).unwrap_err();
        assert_eq!(err.code, 400);
    }

    #[test]
    fn test_validate_dto_rejects_bad_time() {
        let dto = PrefUpdateDto {
            email_notify: None,
            sysmsg_notify: None,
            announce_notify: None,
            dnd_enabled: Some("1".into()),
            dnd_start: Some("25:00".into()),
            dnd_end: None,
        };
        let err = SysUserPrefService::validate_dto(&dto).unwrap_err();
        assert_eq!(err.code, 400);
    }

    #[test]
    fn test_validate_dto_accepts_valid() {
        let dto = PrefUpdateDto {
            email_notify: Some("0".into()),
            sysmsg_notify: Some("1".into()),
            announce_notify: Some("1".into()),
            dnd_enabled: Some("1".into()),
            dnd_start: Some("22:00".into()),
            dnd_end: Some("06:00".into()),
        };
        assert!(SysUserPrefService::validate_dto(&dto).is_ok());
    }
}
