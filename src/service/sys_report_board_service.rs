// stepby-axum/src/service/sys_report_board_service.rs
//! 报表看板（配置化只读报表 v1）Service 层
//!
//! 职责：
//! - 看板 CRUD（v1 仅本人：list/get/save/delete 均按 user_id 过滤，404 语义防探测）
//! - 看板配置强类型校验（ReportBoardConfig：卡片数组，chartType 枚举 + 尺寸约束）
//! - 数据源白名单：sourceKey 只允许命中 [`SOURCES`] 中登记的 6 个既有统计口径，
//!   每个 sourceKey 一条独立实现函数（复用既有服务层聚合，非通用 SQL 执行器——杜绝注入面）
//! - 数据端点：GET /tool/report-board/data/{sourceKey}?range=7d|30d
//!
//! 数据源清单（全部复用既有聚合函数/口径，见各自实现函数注释）：
//! - login_trend        登录趋势（每日成功+失败总次数）    ← SysLogininforService::daily_stats
//! - login_fail_trend   登录失败趋势（每日失败次数）        ← SysLogininforService::daily_stats
//! - user_growth        用户增长（每日新增用户数）          ← dashboard 用户统计同口径（sys_user 聚合）
//! - online_count       当前在线用户数                      ← Redis online:* SCAN（与 dashboard 同口径）
//! - today_anomaly_ips  今日登录失败不重复 IP 数            ← SysLogininforService::count_today_failed_ips
//! - msg_delivery       消息投递状态分布（成功/失败/待重试）← sys_msg_send_log 状态计数（报表快照同口径）
//!
//! 分层约束：不依赖任何 Web 框架类型（axum / tower / tower-http），
//! 数据访问委托 Repository 层，状态/错误使用 ServiceError。

use std::sync::Arc;

use chrono::{Duration, NaiveTime};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QuerySelect,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::common::error::ServiceError;
use crate::entity::sys_msg_send_log::{Column as MsgLogColumn, Entity as SysMsgSendLog};
use crate::entity::sys_user::{Column as UserColumn, Entity as SysUser};
use crate::repository::sys_report_board::SysReportBoardRepository;
use crate::service::sys_logininfor_service::SysLogininforService;
use crate::shared_store::SharedStore;

/// 看板卡片数量上限（防配置膨胀；大屏路线 v1 的合理上界）
pub const MAX_CARDS: usize = 24;
/// 看板名称长度上限（与表列 VARCHAR(64) 对齐）
pub const MAX_NAME_LEN: usize = 64;
/// 卡片 ID / 标题长度上限
const MAX_CARD_FIELD_LEN: usize = 64;

// ==================== 配置强类型 ====================

/// 图表类型（serde 小写：line / bar / pie）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ChartType {
    /// 折线图
    Line,
    /// 柱状图
    Bar,
    /// 饼图
    Pie,
}

/// 卡片网格尺寸（单位：网格格数，取值 1-2）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CardSize {
    /// 宽（1=半行，2=整行）
    pub w: u8,
    /// 高（1=半高，2=全高）
    pub h: u8,
}

/// 看板卡片
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportCard {
    /// 卡片 ID（用户内唯一，前端生成的短标识）
    pub id: String,
    /// 卡片标题
    pub title: String,
    /// 图表类型
    pub chart_type: ChartType,
    /// 数据源标识（必须命中 [`SOURCES`] 白名单）
    pub source_key: String,
    /// 网格尺寸
    pub size: CardSize,
}

/// 看板配置（config 列 JSON 的强类型形态）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReportBoardConfig {
    /// 卡片数组（默认空看板）
    #[serde(default)]
    pub cards: Vec<ReportCard>,
}

// ==================== 数据源白名单 ====================

/// 可用数据源白名单（sourceKey, 中文名, 英文名）
///
/// **新增数据源的唯一入口**：在此登记后实现对应的 `src_*` 函数，
/// /sources 端点与配置校验自动生效。白名单外 sourceKey 一律 400。
/// 名称不走 tr!（动态 key 不受宏支持），用静态双语表 + i18n::pick。
pub const SOURCES: &[(&str, &str, &str)] = &[
    ("login_trend", "登录趋势", "Login Trend"),
    ("login_fail_trend", "登录失败趋势", "Login Failures"),
    ("user_growth", "用户增长", "User Growth"),
    ("online_count", "当前在线数", "Online Users"),
    ("today_anomaly_ips", "今日异常 IP", "Today's Anomaly IPs"),
    ("msg_delivery", "消息投递分布", "Message Delivery"),
];

/// sourceKey 是否在白名单内
pub fn is_source_allowed(source_key: &str) -> bool {
    SOURCES.iter().any(|(k, _, _)| *k == source_key)
}

/// 数据源元数据出参（/sources 端点行）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceMetaVo {
    pub source_key: String,
    pub name: String,
}

/// 数据点（统一单序列形态：label 为横轴/扇区名，value 为数值）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourcePoint {
    pub label: String,
    pub value: i64,
}

/// 数据源数据出参（/data/{sourceKey} 端点）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceDataVo {
    pub source_key: String,
    pub items: Vec<SourcePoint>,
}

/// 消息投递状态扇区标签（zh / en）
const MSG_STATUS_LABELS: [(&str, &str); 3] = [
    ("成功", "Success"),
    ("失败", "Failed"),
    ("待重试", "Pending Retry"),
];

// ==================== CRUD DTO / VO ====================

/// 看板创建 DTO（config 为原始 JSON，服务层反序列化为强类型并校验）
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BoardCreateDto {
    pub name: String,
    pub config: Value,
    /// 启用状态（'1'=启用 '0'=停用，缺省 '1'）
    #[serde(default = "default_enabled")]
    pub enabled: String,
}

/// 看板更新 DTO（字段可选，未提供的沿用现有值；config 至少提供一项变更）
#[derive(Debug, Deserialize, ToSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct BoardUpdateDto {
    pub name: Option<String>,
    pub config: Option<Value>,
    pub enabled: Option<String>,
}

fn default_enabled() -> String {
    "1".to_string()
}

/// 看板出参 VO
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct BoardVo {
    pub id: i64,
    pub name: String,
    /// 看板配置（强类型后回传，保证前端拿到的即校验通过的形态）
    pub config: ReportBoardConfig,
    pub enabled: String,
    pub create_time: Option<String>,
    pub update_time: Option<String>,
}

// ==================== 纯函数辅助（可单测） ====================

/// 解析 config JSON 为强类型 `ReportBoardConfig`（serde 反序列化失败 → 400）
pub fn parse_config_value(v: &Value) -> Result<ReportBoardConfig, ServiceError> {
    serde_json::from_value::<ReportBoardConfig>(v.clone()).map_err(|e| {
        ServiceError::bad_request(&crate::tr!(
            "error.report_board.config_invalid",
            reason = e.to_string()
        ))
    })
}

/// 校验看板配置业务规则：
/// - 卡片数 ≤ [`MAX_CARDS`]
/// - 卡片 id 非空、长度 ≤ 上限且用户内唯一
/// - 标题非空且长度 ≤ 上限
/// - 尺寸 w/h ∈ 1..=2
/// - sourceKey 必须命中 [`SOURCES`] 白名单（白名单外 → 400，防任意 URL/SQL 注入面）
pub fn validate_config(config: &ReportBoardConfig) -> Result<(), ServiceError> {
    if config.cards.len() > MAX_CARDS {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.report_board.config_invalid",
            reason = format!("cards count > {MAX_CARDS}")
        )));
    }
    let mut seen_ids = std::collections::HashSet::new();
    for card in &config.cards {
        if card.id.is_empty()
            || card.id.len() > MAX_CARD_FIELD_LEN
            || !seen_ids.insert(card.id.as_str())
        {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report_board.config_invalid",
                reason = format!("card id invalid: {:?}", card.id)
            )));
        }
        if card.title.is_empty() || card.title.chars().count() > MAX_CARD_FIELD_LEN {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report_board.config_invalid",
                reason = format!("card title invalid: {:?}", card.title)
            )));
        }
        if !(1..=2).contains(&card.size.w) || !(1..=2).contains(&card.size.h) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report_board.config_invalid",
                reason = format!("card size invalid: w={}, h={}", card.size.w, card.size.h)
            )));
        }
        if !is_source_allowed(&card.source_key) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report_board.source_unknown",
                key = card.source_key.clone()
            )));
        }
    }
    Ok(())
}

/// 解析时间范围参数（7d → 7 天，30d → 30 天，其余 → 400）
pub fn parse_range_days(range: &str) -> Result<i64, ServiceError> {
    match range {
        "7d" => Ok(7),
        "30d" => Ok(30),
        _ => Err(ServiceError::bad_request(&crate::tr!(
            "error.report_board.range_invalid"
        ))),
    }
}

/// 校验看板名称（1-64 字符）
fn validate_name(name: &str) -> Result<(), ServiceError> {
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.report_board.name_invalid"
        )));
    }
    Ok(())
}

/// 校验启用状态（'0'/'1'）
fn validate_enabled(enabled: &str) -> Result<(), ServiceError> {
    if enabled != "0" && enabled != "1" {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.report_board.enabled_invalid"
        )));
    }
    Ok(())
}

// ==================== Service ====================

/// 报表看板 Service
pub struct SysReportBoardService {
    repo: SysReportBoardRepository,
    logininfor_service: SysLogininforService,
    db: DatabaseConnection,
    store: Arc<dyn SharedStore>,
}

impl SysReportBoardService {
    pub fn new(db: DatabaseConnection, store: Arc<dyn SharedStore>) -> Self {
        Self {
            repo: SysReportBoardRepository::new(db.clone()),
            logininfor_service: SysLogininforService::new(db.clone()),
            db,
            store,
        }
    }

    // ==================== CRUD（v1 仅本人） ====================

    /// 查询本人看板清单
    pub async fn list(&self, user_id: i64) -> Result<Vec<BoardVo>, ServiceError> {
        let rows = self.repo.find_by_user_id(user_id).await?;
        Ok(rows.iter().map(board_vo_from_model).collect())
    }

    /// 查询本人单个看板（他人/不存在 → 404 语义，不区分两者防 ID 探测）
    pub async fn get(&self, id: i64, user_id: i64) -> Result<BoardVo, ServiceError> {
        let m = self
            .repo
            .find_by_id_and_user(id, user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.report_board.not_found")))?;
        Ok(board_vo_from_model(&m))
    }

    /// 创建看板（同名预检 → 400；config 强类型校验 → 400）
    pub async fn create(
        &self,
        user_id: i64,
        tenant_id: i64,
        dto: BoardCreateDto,
    ) -> Result<BoardVo, ServiceError> {
        validate_name(&dto.name)?;
        validate_enabled(&dto.enabled)?;
        let config = parse_config_value(&dto.config)?;
        validate_config(&config)?;

        if self.repo.name_exists(user_id, &dto.name, None).await? {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report_board.name_exists"
            )));
        }

        let model = crate::entity::sys_report_board::Model {
            tenant_id,
            id: 0,
            user_id,
            name: dto.name.clone(),
            config: serde_json::to_string(&config).unwrap_or_else(|_| "{}".to_string()),
            enabled: dto.enabled.clone(),
            create_time: None,
            update_time: None,
        };
        let id = self.repo.insert(model).await?;
        Ok(BoardVo {
            id,
            name: dto.name,
            config,
            enabled: dto.enabled,
            create_time: None,
            update_time: None,
        })
    }

    /// 更新看板（按属主过滤；0 行受影响 → 404 语义）
    pub async fn update(
        &self,
        id: i64,
        user_id: i64,
        dto: BoardUpdateDto,
    ) -> Result<BoardVo, ServiceError> {
        // 归属校验（404 语义）
        let existing = self
            .repo
            .find_by_id_and_user(id, user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.report_board.not_found")))?;

        let name = match &dto.name {
            Some(n) => {
                validate_name(n)?;
                n.clone()
            }
            None => existing.name.clone(),
        };
        let enabled = match &dto.enabled {
            Some(e) => {
                validate_enabled(e)?;
                e.clone()
            }
            None => existing.enabled.clone(),
        };
        // config：提供则强类型校验并覆盖；未提供沿用现有
        let config = match &dto.config {
            Some(v) => {
                let c = parse_config_value(v)?;
                validate_config(&c)?;
                c
            }
            None => serde_json::from_str::<ReportBoardConfig>(&existing.config).unwrap_or_default(),
        };

        // 同名预检（排除自身）
        if self.repo.name_exists(user_id, &name, Some(id)).await? {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report_board.name_exists"
            )));
        }

        let rows = self
            .repo
            .update_by_id_and_user(
                id,
                user_id,
                dto.name.map(|_| name.clone()),
                dto.config
                    .map(|_| serde_json::to_string(&config).unwrap_or_else(|_| "{}".to_string())),
                dto.enabled.map(|_| enabled.clone()),
            )
            .await?;
        if rows == 0 {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.report_board.not_found"
            )));
        }
        Ok(BoardVo {
            id,
            name,
            config,
            enabled,
            create_time: None,
            update_time: None,
        })
    }

    /// 删除看板（按属主过滤；0 行受影响 → 404 语义）
    pub async fn delete(&self, id: i64, user_id: i64) -> Result<(), ServiceError> {
        let rows = self.repo.delete_by_id_and_user(id, user_id).await?;
        if rows == 0 {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.report_board.not_found"
            )));
        }
        Ok(())
    }

    // ==================== 数据源白名单端点 ====================

    /// 可用数据源清单（[/SOURCES] 白名单 + 按 locale 的双语名称）
    pub fn available_sources(&self) -> Vec<SourceMetaVo> {
        SOURCES
            .iter()
            .map(|(key, zh, en)| SourceMetaVo {
                source_key: (*key).to_string(),
                name: crate::common::i18n::pick(zh, en).to_string(),
            })
            .collect()
    }

    /// 拉取指定数据源数据（白名单外 → 400；租户隔离随 operator 租户）
    ///
    /// range 仅对趋势类数据源生效（7d/30d）；时点类数据源（online_count /
    /// today_anomaly_ips / msg_delivery）忽略 range。
    pub async fn resolve_source(
        &self,
        source_key: &str,
        range_days: i64,
        operator_tid: i64,
    ) -> Result<SourceDataVo, ServiceError> {
        if !is_source_allowed(source_key) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.report_board.source_unknown",
                key = source_key.to_string()
            )));
        }
        // 租户维度：None = 平台操作者（不过滤），Some(tid) = 仅本租户
        let tenant = crate::common::tenant::tenant_scope(operator_tid);
        // b71 吞错治理：本族 5 个数据源里 4 个原先把 DB 故障折叠成空数组/0（`unwrap_or_default`
        // / `unwrap_or(0)`），看板因此把"数据库挂了"渲染成"用户零增长/零消息"——真实故障与
        // 数据下滑不可区分，且零日志线索。现在故障一律上抛（`resolve_source` 本就返回 Result，
        // 调用方与前端错误通道不变）。`online_count` 保留既有"Redis 故障降级为 0 + WARN"设计：
        // 它不是静默，是显式记录在案的降级。
        let items = match source_key {
            "login_trend" => self.src_login_trend(range_days, tenant, true).await?,
            "login_fail_trend" => self.src_login_trend(range_days, tenant, false).await?,
            "user_growth" => self.src_user_growth(range_days, tenant).await?,
            "online_count" => self.src_online_count(tenant).await,
            "today_anomaly_ips" => {
                let (_, zh, en) = SOURCES
                    .iter()
                    .find(|(k, _, _)| *k == "today_anomaly_ips")
                    .copied()
                    .unwrap_or(("", "", ""));
                vec![SourcePoint {
                    label: crate::common::i18n::pick(zh, en).to_string(),
                    value: self
                        .logininfor_service
                        .count_today_failed_ips(tenant)
                        .await?,
                }]
            }
            "msg_delivery" => self.src_msg_delivery(tenant).await?,
            other => {
                // 白名单已挡住，理论不可达；不可达时显式报错而非静默返回空数据
                return Err(ServiceError::internal(&format!(
                    "数据源 {other} 未接入实现"
                )));
            }
        };
        Ok(SourceDataVo {
            source_key: source_key.to_string(),
            items,
        })
    }

    /// 登录趋势（复用 [`SysLogininforService::daily_stats`] 单条 GROUP BY 聚合）：
    /// `sum_only=true` 返回每日成功+失败总次数，否则仅失败次数
    async fn src_login_trend(
        &self,
        days: i64,
        tenant: Option<i64>,
        sum_only: bool,
    ) -> Result<Vec<SourcePoint>, ServiceError> {
        Ok(self
            .logininfor_service
            .daily_stats(days, tenant)
            .await?
            .into_iter()
            .map(|d| {
                let value = if sum_only { d.success + d.fail } else { d.fail };
                SourcePoint {
                    label: d.date,
                    value,
                }
            })
            .collect())
    }

    /// 用户增长（每日新增用户数；与 dashboard/报表快照 user_stats 同口径：
    /// del_flag != '2' 的 sys_user 按 create_time 日期分组，缺数日期补 0）
    async fn src_user_growth(
        &self,
        days: i64,
        tenant: Option<i64>,
    ) -> Result<Vec<SourcePoint>, ServiceError> {
        let today = crate::common::datetime::today_utc();
        let start_date = today - Duration::days(days - 1);
        let begin = start_date.and_time(NaiveTime::MIN);

        let mut query = SysUser::find()
            .filter(UserColumn::DelFlag.ne("2"))
            .filter(UserColumn::CreateTime.gte(begin));
        if let Some(tid) = tenant {
            query = query.filter(UserColumn::TenantId.eq(tid));
        }
        let rows = query.all(&self.db).await?;

        let mut map: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        for u in &rows {
            if let Some(ct) = u.create_time {
                *map.entry(ct.format("%Y-%m-%d").to_string()).or_insert(0) += 1;
            }
        }
        Ok((0..days)
            .map(|i| {
                let key = (start_date + Duration::days(i))
                    .format("%Y-%m-%d")
                    .to_string();
                SourcePoint {
                    value: map.get(&key).copied().unwrap_or(0),
                    label: key,
                }
            })
            .collect())
    }

    /// 当前在线用户数（与 dashboard `count_online_sessions` 同口径：
    /// Redis SCAN online:*；租户操作者解析 OnlineSession 仅计本租户，
    /// 旧会话按 sys_user.tenant_id 回查兜底；Redis 故障降级为 0）
    async fn src_online_count(&self, tenant: Option<i64>) -> Vec<SourcePoint> {
        let keys = match self.store.scan("online:*", Some(5000)).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!("Redis SCAN online:* 失败，看板在线数降级为 0: {}", e);
                return Vec::new();
            }
        };
        let Some(operator_tid) = tenant else {
            let (_, zh, en) = SOURCES
                .iter()
                .find(|(k, _, _)| *k == "online_count")
                .copied()
                .unwrap_or(("", "", ""));
            return vec![SourcePoint {
                label: crate::common::i18n::pick(zh, en).to_string(),
                value: keys.len() as i64,
            }];
        };
        if keys.is_empty() {
            return Vec::new();
        }
        let values: Vec<Option<String>> = match self.store.get_many(&keys).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Redis MGET online 失败，看板在线数降级为 0: {}", e);
                return Vec::new();
            }
        };
        let sessions: Vec<crate::utils::crypto::OnlineSession> = values
            .iter()
            .flatten()
            .filter_map(|json| {
                serde_json::from_str::<crate::utils::crypto::OnlineSession>(json).ok()
            })
            .collect();

        // 旧会话兜底：tenant_id=0 的会话按 user_id 回查 sys_user.tenant_id
        let legacy_user_ids: Vec<i64> = sessions
            .iter()
            .filter(|s| s.tenant_id == 0 && s.user_id > 0)
            .map(|s| s.user_id)
            .collect();
        let mut legacy_map: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
        if !legacy_user_ids.is_empty()
            && let Ok(rows) = SysUser::find()
                .filter(UserColumn::UserId.is_in(legacy_user_ids))
                .select_only()
                .column(UserColumn::UserId)
                .column(UserColumn::TenantId)
                .into_tuple::<(i64, i64)>()
                .all(&self.db)
                .await
        {
            for (uid, tid) in rows {
                legacy_map.insert(uid, tid);
            }
        }

        let count = sessions
            .iter()
            .filter(|s| {
                let session_tid = if s.tenant_id != 0 {
                    s.tenant_id
                } else {
                    legacy_map.get(&s.user_id).copied().unwrap_or(0)
                };
                session_tid == operator_tid
            })
            .count() as i64;
        let (_, zh, en) = SOURCES
            .iter()
            .find(|(k, _, _)| *k == "online_count")
            .copied()
            .unwrap_or(("", "", ""));
        vec![SourcePoint {
            label: crate::common::i18n::pick(zh, en).to_string(),
            value: count,
        }]
    }

    /// 消息投递状态分布（与报表快照 msg_stats 同口径：sys_msg_send_log 按
    /// status 计数——0=成功 1=失败 2=待重试；出租户不过滤）
    async fn src_msg_delivery(
        &self,
        tenant: Option<i64>,
    ) -> Result<Vec<SourcePoint>, ServiceError> {
        let count_by = |status: &'static str| {
            let mut q = SysMsgSendLog::find();
            if let Some(tid) = tenant {
                q = q.filter(MsgLogColumn::TenantId.eq(tid));
            }
            q.filter(MsgLogColumn::Status.eq(status)).count(&self.db)
        };
        let (success, failed, pending) = (
            count_by("0").await? as i64,
            count_by("1").await? as i64,
            count_by("2").await? as i64,
        );
        let label =
            |i: usize| crate::common::i18n::pick(MSG_STATUS_LABELS[i].0, MSG_STATUS_LABELS[i].1);
        Ok(vec![
            SourcePoint {
                label: label(0).to_string(),
                value: success,
            },
            SourcePoint {
                label: label(1).to_string(),
                value: failed,
            },
            SourcePoint {
                label: label(2).to_string(),
                value: pending,
            },
        ])
    }
}

/// Model → VO（config 强类型回传）
fn board_vo_from_model(m: &crate::entity::sys_report_board::Model) -> BoardVo {
    BoardVo {
        id: m.id,
        name: m.name.clone(),
        config: serde_json::from_str::<ReportBoardConfig>(&m.config).unwrap_or_default(),
        enabled: m.enabled.clone(),
        create_time: m
            .create_time
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()),
        update_time: m
            .update_time
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== parse_config_value ====================

    #[test]
    fn parse_config_valid() {
        let v = serde_json::json!({
            "cards": [
                { "id": "c1", "title": "登录趋势", "chartType": "line",
                  "sourceKey": "login_trend", "size": { "w": 2, "h": 1 } }
            ]
        });
        let cfg = parse_config_value(&v).expect("合法配置应解析成功");
        assert_eq!(cfg.cards.len(), 1);
        assert_eq!(cfg.cards[0].chart_type, ChartType::Line);
        assert_eq!(cfg.cards[0].size, CardSize { w: 2, h: 1 });
    }

    #[test]
    fn parse_config_empty_is_default() {
        let cfg = parse_config_value(&serde_json::json!({})).expect("空对象应解析为默认空看板");
        assert!(cfg.cards.is_empty());
    }

    #[test]
    fn parse_config_rejects_bad_chart_type() {
        let v = serde_json::json!({
            "cards": [
                { "id": "c1", "title": "x", "chartType": "gauge",
                  "sourceKey": "login_trend", "size": { "w": 1, "h": 1 } }
            ]
        });
        assert!(parse_config_value(&v).is_err(), "非法 chartType 应被拒绝");
    }

    // ==================== validate_config（白名单/业务规则） ====================

    fn card(id: &str, source_key: &str, w: u8, h: u8) -> ReportCard {
        ReportCard {
            id: id.to_string(),
            title: "卡片".to_string(),
            chart_type: ChartType::Bar,
            source_key: source_key.to_string(),
            size: CardSize { w, h },
        }
    }

    #[test]
    fn validate_config_rejects_unknown_source() {
        let cfg = ReportBoardConfig {
            cards: vec![card("c1", "http://evil.example.com", 1, 1)],
        };
        let err = validate_config(&cfg).unwrap_err();
        assert_eq!(err.code, 400, "白名单外 sourceKey 必须 400");
    }

    #[test]
    fn validate_config_rejects_sql_like_source() {
        let cfg = ReportBoardConfig {
            cards: vec![card("c1", "SELECT 1; DROP TABLE users", 1, 1)],
        };
        assert_eq!(validate_config(&cfg).unwrap_err().code, 400);
    }

    #[test]
    fn validate_config_accepts_all_whitelisted_sources() {
        for (key, _, _) in SOURCES {
            let cfg = ReportBoardConfig {
                cards: vec![card("c1", key, 1, 1)],
            };
            assert!(validate_config(&cfg).is_ok(), "白名单源 {key} 应通过");
        }
    }

    #[test]
    fn validate_config_rejects_duplicate_ids() {
        let cfg = ReportBoardConfig {
            cards: vec![
                card("c1", "login_trend", 1, 1),
                card("c1", "user_growth", 1, 1),
            ],
        };
        assert!(validate_config(&cfg).is_err(), "重复 id 应被拒绝");
    }

    #[test]
    fn validate_config_rejects_bad_size() {
        let cfg = ReportBoardConfig {
            cards: vec![card("c1", "login_trend", 3, 1)],
        };
        assert!(validate_config(&cfg).is_err(), "尺寸 w>2 应被拒绝");
        let cfg = ReportBoardConfig {
            cards: vec![card("c1", "login_trend", 1, 0)],
        };
        assert!(validate_config(&cfg).is_err(), "尺寸 h=0 应被拒绝");
    }

    #[test]
    fn validate_config_rejects_empty_title() {
        let mut c = card("c1", "login_trend", 1, 1);
        c.title = String::new();
        let cfg = ReportBoardConfig { cards: vec![c] };
        assert!(validate_config(&cfg).is_err(), "空标题应被拒绝");
    }

    #[test]
    fn validate_config_rejects_too_many_cards() {
        let cards: Vec<ReportCard> = (0..(MAX_CARDS + 1))
            .map(|i| card(&format!("c{i}"), "login_trend", 1, 1))
            .collect();
        let cfg = ReportBoardConfig { cards };
        assert!(validate_config(&cfg).is_err(), "超过上限卡片数应被拒绝");
    }

    // ==================== parse_range_days ====================

    #[test]
    fn parse_range_valid() {
        assert_eq!(parse_range_days("7d").unwrap(), 7);
        assert_eq!(parse_range_days("30d").unwrap(), 30);
    }

    #[test]
    fn parse_range_rejects_others() {
        for bad in ["", "1d", "90d", "7", "DROP TABLE", "7d;--"] {
            assert_eq!(
                parse_range_days(bad).unwrap_err().code,
                400,
                "range={bad:?} 应 400"
            );
        }
    }

    // ==================== is_source_allowed ====================

    #[test]
    fn source_whitelist_membership() {
        assert!(is_source_allowed("login_trend"));
        assert!(!is_source_allowed(""));
        assert!(!is_source_allowed("LOGIN_TREND"), "大小写敏感");
        assert!(!is_source_allowed("../etc/passwd"));
    }

    // ==================== validate_name / validate_enabled ====================

    #[test]
    fn validate_name_bounds() {
        assert!(validate_name("我的看板").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN)).is_ok());
    }

    #[test]
    fn validate_enabled_bounds() {
        assert!(validate_enabled("0").is_ok());
        assert!(validate_enabled("1").is_ok());
        assert!(validate_enabled("2").is_err());
        assert!(validate_enabled("").is_err());
    }
}
