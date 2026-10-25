// stepby-axum/src/service/sys_alert_service.rs
//! 告警规则引擎 Service 层
//!
//! 职责：
//! - 告警规则 CRUD（metric / comparator 白名单校验）
//! - 指标采集（真实数据源，见 [`SysAlertService::metric_value`] 逐项说明）
//! - 评估引擎 `evaluate_all`：遍历启用规则 → 取指标 → 比较 → 静默期判定 →
//!   抢占触发权 → 消息中心发送 → 记录 last_fired_at
//!   （存量库表结构兜底由 `initialize/mod.rs::ensure_alert_rule_tables` 负责，
//!   单一事实源为迁移 `m20261003_000003_alert_rule`，本层不再重复持有 DDL）
//!
//! 幂等与并发语义（多实例安全）：
//! - 触发权经 `repository::claim_fire` 的条件 UPDATE 抢占
//!   （`last_fired_at IS NULL OR last_fired_at < now - silent_minutes`），
//!   仅抢占成功方发送通知；并发/多实例重复评估不会重复发送。
//! - 指标采集为纯读操作，可任意重入。
//!
//! 通知发送（真实调用链）：规则配置了 `notify_channel_id` + `notify_template_id`
//! 时，按模板 ID 解析 template_code，收件人按渠道类型落地：
//! - `site`（站内信）→ to_addr = 管理员用户 id "1"
//! - `email` → to_addr = 管理员用户（user_id=1）的邮箱（为空则跳过发送并记日志）
//!
//! 渠道/模板缺失或停用时跳过发送但照常更新 last_fired_at（告警事实不丢，日志可见）。

use std::sync::Arc;

use garde::Validate;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::config::Settings;
use crate::entity::sys_alert_rule::{
    ActiveModel as AlertRuleActiveModel, Column as AlertRuleColumn, Entity as SysAlertRule,
    Model as AlertRuleModel,
};
use crate::entity::sys_job_log;
use crate::entity::sys_logininfor;
use crate::entity::sys_msg_template;
use crate::entity::sys_user;
use crate::repository::sys_alert_rule::SysAlertRuleRepository;
use crate::service::sys_msg_service::{SendDto, SysMsgService};
use crate::shared_store::SharedStore;

/// 管理员用户主键（站内信/邮箱收件人约定，与种子数据 admin 一致）
const ADMIN_USER_ID: i64 = 1;

// ==================== 白名单 ====================

/// 支持的指标清单（白名单，创建/更新时校验）
pub const VALID_METRICS: &[&str] = &[
    "login_failed_5m",
    "http_5xx_5m",
    "job_failed_24h",
    "online_users",
    "cpu_usage",
    "mem_usage",
    "disk_usage",
];

/// 支持的比较器清单（白名单，创建/更新时校验）
pub const VALID_COMPARATORS: &[&str] = &["gt", "lt", "ge", "le"];

/// 允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖规则业务展示列；`notify_channel_id` / `notify_template_id` 等内部列不开放动态排序。
const SORTABLE_COLUMNS: &[(&str, AlertRuleColumn)] = &[
    ("name", AlertRuleColumn::Name),
    ("metric", AlertRuleColumn::Metric),
    ("enabled", AlertRuleColumn::Enabled),
    ("last_fired_at", AlertRuleColumn::LastFiredAt),
    ("id", AlertRuleColumn::Id),
    ("created_at", AlertRuleColumn::CreatedAt),
];

// ==================== DTO ====================

/// 告警规则分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
    /// 规则名称模糊过滤
    pub name: Option<String>,
    /// 指标精确过滤
    pub metric: Option<String>,
    /// 启用状态过滤（'1' 启用 / '0' 停用）
    pub enabled: Option<String>,
}

impl From<&AlertRuleQueryDto> for PageDomain {
    fn from(dto: &AlertRuleQueryDto) -> Self {
        // 动态排序透传：先 sanitize（格式白名单），列级白名单在 service 查询时解析
        let mut page = PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: dto.order_by_column.clone(),
            is_asc: dto.is_asc.clone(),
        };
        page.sanitize_order_fields();
        page
    }
}

/// 新增告警规则 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleAddDto {
    #[garde(length(min = 1, max = 64))]
    pub name: String,
    #[garde(length(min = 1, max = 64))]
    pub metric: String,
    #[garde(length(min = 1, max = 2))]
    pub comparator: String,
    #[garde(skip)]
    pub threshold: f64,
    #[serde(default = "default_silent_minutes")]
    #[garde(range(min = 0, max = 14400))]
    pub silent_minutes: i32,
    #[garde(skip)]
    pub notify_channel_id: Option<i64>,
    #[garde(skip)]
    pub notify_template_id: Option<i64>,
    #[serde(default = "default_enabled")]
    #[garde(skip)]
    pub enabled: String,
}

/// 修改告警规则 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleEditDto {
    #[garde(skip)]
    pub id: i64,
    #[garde(length(min = 1, max = 64))]
    pub name: String,
    #[garde(length(min = 1, max = 64))]
    pub metric: String,
    #[garde(length(min = 1, max = 2))]
    pub comparator: String,
    #[garde(skip)]
    pub threshold: f64,
    #[serde(default = "default_silent_minutes")]
    #[garde(range(min = 0, max = 14400))]
    pub silent_minutes: i32,
    #[garde(skip)]
    pub notify_channel_id: Option<i64>,
    #[garde(skip)]
    pub notify_template_id: Option<i64>,
    #[serde(default = "default_enabled")]
    #[garde(skip)]
    pub enabled: String,
}

/// 启用/停用切换 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertRuleEnabledDto {
    #[garde(skip)]
    pub id: i64,
    /// 目标状态（'1' 启用 / '0' 停用）
    #[garde(length(min = 1, max = 1))]
    pub enabled: String,
}

/// 手动评估结果
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AlertEvaluateResult {
    /// 指标当前值
    pub metric_value: f64,
    /// 是否命中阈值并触发（抢占触发权成功）
    pub fired: bool,
    /// 结果说明（i18n）
    pub reason: String,
}

fn default_silent_minutes() -> i32 {
    30
}

fn default_enabled() -> String {
    "1".to_string()
}

// ==================== Service ====================

/// 告警规则 Service
pub struct SysAlertService {
    repo: SysAlertRuleRepository,
    db: DatabaseConnection,
    store: Arc<dyn SharedStore>,
    msg_service: SysMsgService,
}

impl SysAlertService {
    pub fn new(db: DatabaseConnection, store: Arc<dyn SharedStore>, config: Arc<Settings>) -> Self {
        Self {
            repo: SysAlertRuleRepository::new(db.clone()),
            msg_service: SysMsgService::new(db.clone(), config),
            db,
            store,
        }
    }

    // ==================== CRUD ====================

    /// 分页查询告警规则（name 模糊 / metric 精确 / enabled 精确 + 动态排序）
    pub async fn list(
        &self,
        query: AlertRuleQueryDto,
    ) -> Result<(Vec<AlertRuleModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<SysAlertRule>(prop, SORTABLE_COLUMNS)
                .map(|col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())))
        });

        let (rows, total) = self
            .repo
            .find_page_filtered(
                offset,
                limit,
                query.name.as_deref(),
                query.metric.as_deref(),
                query.enabled.as_deref(),
                sort,
            )
            .await?;
        Ok((rows, total))
    }

    /// 导出全量告警规则（同 list 过滤口径，受 EXPORT_MAX_ROWS 限制，
    /// 绕过 PageDomain 分页截断——对齐 sys_audit_change_service.export_changes 范式；
    /// 修复：此前 export 复用 list 分页逻辑，外部直调不传 pageSize 时仅导出前 10 行）
    pub async fn export_rules(
        &self,
        query: AlertRuleQueryDto,
    ) -> Result<Vec<AlertRuleModel>, ServiceError> {
        let rows = self
            .repo
            .find_all_filtered(
                crate::common::page::EXPORT_MAX_ROWS,
                query.name.as_deref(),
                query.metric.as_deref(),
                query.enabled.as_deref(),
            )
            .await?;
        Ok(rows)
    }

    /// 按 id 查询告警规则详情
    pub async fn get_by_id(&self, id: i64) -> Result<AlertRuleModel, ServiceError> {
        self.repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.alert.rule_not_found")))
    }

    /// 新增告警规则（metric / comparator 白名单校验）
    pub async fn add(
        &self,
        dto: AlertRuleAddDto,
        operator: &str,
    ) -> Result<AlertRuleModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        Self::validate_metric(&dto.metric)?;
        Self::validate_comparator(&dto.comparator)?;
        Self::validate_enabled(&dto.enabled)?;

        let am = AlertRuleActiveModel {
            name: Set(dto.name),
            metric: Set(dto.metric),
            comparator: Set(dto.comparator),
            threshold: Set(dto.threshold),
            silent_minutes: Set(dto.silent_minutes),
            notify_channel_id: Set(dto.notify_channel_id),
            notify_template_id: Set(dto.notify_template_id),
            enabled: Set(Some(dto.enabled)),
            // 运行期产物：归平台租户（告警规则为平台运维面，配合 platform_only_guard）
            last_fired_at: Set(None),
            created_at: Set(Some(crate::common::datetime::now_naive())),
            updated_at: Set(Some(crate::common::datetime::now_naive())),
            ..Default::default()
        };
        tracing::info!("新增告警规则 operator={}", operator);
        Ok(self.repo.insert(am).await?)
    }

    /// 修改告警规则（metric / comparator 白名单校验）
    pub async fn edit(
        &self,
        dto: AlertRuleEditDto,
        operator: &str,
    ) -> Result<AlertRuleModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;
        Self::validate_metric(&dto.metric)?;
        Self::validate_comparator(&dto.comparator)?;
        Self::validate_enabled(&dto.enabled)?;

        let existed = self.get_by_id(dto.id).await?;
        let am = AlertRuleActiveModel {
            id: Set(existed.id),
            name: Set(dto.name),
            metric: Set(dto.metric),
            comparator: Set(dto.comparator),
            threshold: Set(dto.threshold),
            silent_minutes: Set(dto.silent_minutes),
            notify_channel_id: Set(dto.notify_channel_id),
            notify_template_id: Set(dto.notify_template_id),
            enabled: Set(Some(dto.enabled)),
            // last_fired_at 不在编辑面（评估引擎维护）；updated_at 由 before_save 刷新
            last_fired_at: Set(existed.last_fired_at),
            created_at: Set(existed.created_at),
            updated_at: Set(Some(crate::common::datetime::now_naive())),
        };
        tracing::info!("修改告警规则 id={} operator={}", existed.id, operator);
        Ok(self.repo.update(am).await?)
    }

    /// 切换启用/停用
    pub async fn change_enabled(
        &self,
        dto: AlertRuleEnabledDto,
        operator: &str,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;
        Self::validate_enabled(&dto.enabled)?;

        let existed = self.get_by_id(dto.id).await?;
        let am = AlertRuleActiveModel {
            id: Set(existed.id),
            enabled: Set(Some(dto.enabled)),
            updated_at: Set(Some(crate::common::datetime::now_naive())),
            ..Default::default()
        };
        self.repo.update(am).await?;
        tracing::info!(
            "切换告警规则状态 id={} enabled={} operator={}",
            existed.id,
            existed.enabled.as_deref().unwrap_or(""),
            operator
        );
        Ok(())
    }

    /// 批量删除告警规则（物理删除）
    pub async fn remove(&self, ids: Vec<i64>) -> Result<(), ServiceError> {
        if ids.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.common.id_invalid"
            )));
        }
        self.repo.delete_by_ids(ids).await?;
        Ok(())
    }

    // ==================== 评估引擎 ====================

    /// 评估全部启用规则（定时任务每 60s 调用一次；幂等可重入）
    ///
    /// 单条规则评估失败（指标采集/DB 错误）只记日志并继续，不影响其余规则——
    /// 评估循环整体不向上传播错误（调度器语义：任务失败写 job_log 即可）。
    /// 返回 (评估规则数, 触发规则数)。
    pub async fn evaluate_all(&self) -> Result<(usize, usize), ServiceError> {
        let rules = self.repo.find_enabled().await?;
        let mut fired_count = 0usize;
        for rule in &rules {
            match self.evaluate_rule(rule).await {
                Ok(EvaluateOutcome::Fired) => fired_count += 1,
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(
                        "告警规则评估失败 id={} metric={}: {}",
                        rule.id,
                        rule.metric,
                        e.message
                    );
                }
            }
        }
        Ok((rules.len(), fired_count))
    }

    /// 评估单条规则并返回结果明细（手动评估端点用）
    ///
    /// 与 `evaluate_all` 共用同一触发权抢占路径（claim_fire），手动评估与定时评估
    /// 并发到达时同样只触发一次通知。
    pub async fn evaluate_one(&self, id: i64) -> Result<AlertEvaluateResult, ServiceError> {
        let rule = self.get_by_id(id).await?;
        self.evaluate_rule_detailed(&rule).await
    }

    /// 单规则评估（内部统一入口），返回粗粒度结果
    async fn evaluate_rule(&self, rule: &AlertRuleModel) -> Result<EvaluateOutcome, ServiceError> {
        self.evaluate_rule_detailed(rule).await.map(|r| {
            if r.fired {
                EvaluateOutcome::Fired
            } else {
                EvaluateOutcome::Skipped
            }
        })
    }

    /// 单规则评估（完整明细）：
    /// 取指标 → 比较 → 未命中直接返回；命中后抢占触发权（静默期判定）→
    /// 抢占成功发送通知（无渠道配置时跳过发送）→ 返回结果。
    async fn evaluate_rule_detailed(
        &self,
        rule: &AlertRuleModel,
    ) -> Result<AlertEvaluateResult, ServiceError> {
        let value = self.metric_value(&rule.metric).await?;
        let hit = compare(rule.comparator.as_str(), value, rule.threshold);

        if !hit {
            return Ok(AlertEvaluateResult {
                metric_value: value,
                fired: false,
                reason: crate::tr!(
                    "alert.evaluate.not_fired",
                    metric = rule.metric,
                    value = format_value(value),
                    threshold = format_value(rule.threshold),
                    comparator = rule.comparator
                ),
            });
        }

        // 命中阈值：抢占触发权（静默期判定在同一 UPDATE 内原子完成）
        let now = crate::common::datetime::now_naive();
        let silence_before = now - chrono::Duration::minutes(i64::from(rule.silent_minutes.max(0)));
        let claimed = self.repo.claim_fire(rule.id, silence_before, now).await?;

        if claimed == 0 {
            // 已有并发评估方触发过（静默期内），本方跳过
            tracing::debug!(
                "告警规则 id={} 在静默期内（silent_minutes={}），跳过通知",
                rule.id,
                rule.silent_minutes
            );
            return Ok(AlertEvaluateResult {
                metric_value: value,
                fired: false,
                reason: crate::tr!("alert.evaluate.silent", minutes = rule.silent_minutes),
            });
        }

        // 抢占成功：发送通知（无渠道配置时跳过发送——last_fired_at 已更新，日志留痕）
        let notify_note = self.notify(rule, value).await;

        Ok(AlertEvaluateResult {
            metric_value: value,
            fired: true,
            reason: notify_note.unwrap_or_else(|| {
                crate::tr!(
                    "alert.evaluate.fired",
                    metric = rule.metric,
                    value = format_value(value),
                    threshold = format_value(rule.threshold),
                    comparator = rule.comparator
                )
            }),
        })
    }

    /// 按规则配置发送通知（真实调用消息中心）
    ///
    /// 返回 Some(reason) 表示发送链路有值得反馈给调用方的说明（渠道缺失/收件人为空）；
    /// 返回 None 表示通知已正常发出（或无模板参数场景，均以发送日志为准）。
    async fn notify(&self, rule: &AlertRuleModel, value: f64) -> Option<String> {
        // 未配置渠道/模板：跳过发送，仅日志留痕（last_fired_at 已在 claim_fire 中更新）
        let (channel_id, template_id) = match (rule.notify_channel_id, rule.notify_template_id) {
            (Some(c), Some(t)) => (c, t),
            _ => {
                tracing::info!(
                    "告警规则 id={}（{}）命中阈值 {}，未配置通知渠道，仅记录触发不发送",
                    rule.id,
                    rule.name,
                    format_value(value)
                );
                return Some(crate::tr!("alert.evaluate.no_channel"));
            }
        };

        // 按模板 ID 解析 template_code（SysMsgService::send 以编码为入参）
        let template = match sys_msg_template::Entity::find_by_id(template_id)
            .one(&self.db)
            .await
        {
            Ok(Some(t)) => t.template_code,
            Ok(None) => {
                tracing::warn!(
                    "告警规则 id={} 通知模板 {template_id} 不存在，跳过发送（last_fired_at 已更新）",
                    rule.id
                );
                return Some(crate::tr!("alert.evaluate.no_channel"));
            }
            Err(e) => {
                tracing::error!("告警规则 id={} 查询通知模板失败: {}", rule.id, e);
                return Some(crate::tr!("alert.evaluate.no_channel"));
            }
        };

        // 解析渠道类型 → 收件人（site: 管理员站内信 / email: 管理员邮箱）
        let to_addr = match Self::resolve_recipient(&self.db, channel_id).await {
            Ok(addr) => addr,
            Err(e) => {
                tracing::warn!(
                    "告警规则 id={} 解析通知收件人失败: {}（last_fired_at 已更新，不发送）",
                    rule.id,
                    e.message
                );
                return Some(crate::tr!("alert.evaluate.no_channel"));
            }
        };

        let params = [
            ("rule_name".to_string(), rule.name.clone()),
            ("metric".to_string(), rule.metric.clone()),
            ("value".to_string(), format_value(value)),
            ("threshold".to_string(), format_value(rule.threshold)),
            ("comparator".to_string(), rule.comparator.clone()),
        ]
        .into_iter()
        .collect();

        let dto = SendDto {
            template_code: template,
            channel_code: None, // 缺省使用模板默认渠道
            to_addr,
            params,
        };
        match self.msg_service.send(dto, "alert-engine", 0).await {
            Ok(log) => {
                tracing::info!(
                    "告警规则 id={}（{}）触发通知已发送 template={:?} status={:?}",
                    rule.id,
                    rule.name,
                    log.template_code,
                    log.status
                );
                None
            }
            Err(e) => {
                tracing::error!(
                    "告警规则 id={} 通知发送失败: {}（last_fired_at 已更新，由消息重试机制兜底）",
                    rule.id,
                    e.message
                );
                Some(crate::tr!("alert.evaluate.no_channel"))
            }
        }
    }

    // ==================== 指标采集（真实数据源） ====================

    /// 采集指标当前值
    ///
    /// 数据源说明（全部真实查询，无造假数据）：
    /// - `login_failed_5m`：sys_logininfor 最近 5 分钟 status='1'（失败）计数
    /// - `http_5xx_5m`：进程内 MetricsRegistry 5xx 环形窗口计数
    ///   （monitoring_middleware 每请求记录真实响应状态，重启清零、单实例口径）
    /// - `job_failed_24h`：sys_job_log 最近 24h status='1'（失败）计数
    /// - `online_users`：共享态存储 `online:*` 键计数（登录会话真实登记）
    /// - `cpu_usage` / `mem_usage` / `disk_usage`：sysinfo 采集（0-100，百分比；
    ///   disk_usage 取全部挂载点中的最大已用百分比）
    pub async fn metric_value(&self, metric: &str) -> Result<f64, ServiceError> {
        match metric {
            "login_failed_5m" => {
                let since = crate::common::datetime::now_naive() - chrono::Duration::minutes(5);
                let count = sys_logininfor::Entity::find()
                    .filter(sys_logininfor::Column::Status.eq("1"))
                    .filter(sys_logininfor::Column::LoginTime.gte(since))
                    .count(&self.db)
                    .await?;
                Ok(count as f64)
            }
            "http_5xx_5m" => {
                // 进程内 5xx 窗口计数（metrics.rs：monitoring_middleware 真实记录）
                Ok(crate::observability::metrics::MetricsRegistry::global()
                    .count_recent_5xx(std::time::Duration::from_secs(300))
                    as f64)
            }
            "job_failed_24h" => {
                let since = crate::common::datetime::now_naive() - chrono::Duration::hours(24);
                let count = sys_job_log::Entity::find()
                    .filter(sys_job_log::Column::Status.eq("1"))
                    .filter(sys_job_log::Column::CreateTime.gte(since))
                    .count(&self.db)
                    .await?;
                Ok(count as f64)
            }
            "online_users" => {
                // 复用在线会话统计口径（monitor_online_handler 同款 SCAN 上限 5000）
                let keys = self.store.scan("online:*", Some(5000)).await.map_err(|e| {
                    tracing::error!("online_users 指标采集失败（scan online:*）: {e}");
                    ServiceError::internal(&crate::tr!("error.alert.metric_fetch_failed"))
                })?;
                Ok(keys.len() as f64)
            }
            "cpu_usage" | "mem_usage" | "disk_usage" => {
                // sysinfo 采集为同步阻塞操作，spawn_blocking 包裹（monitor_server_handler 同款）
                let metric = metric.to_string();
                tokio::task::spawn_blocking(move || collect_system_metric(&metric))
                    .await
                    .map_err(|e| {
                        tracing::error!("系统资源指标采集失败（sysinfo）: {e}");
                        ServiceError::internal(&crate::tr!("error.alert.metric_fetch_failed"))
                    })?
            }
            _ => Err(ServiceError::bad_request(&crate::tr!(
                "error.alert.metric_invalid"
            ))),
        }
    }

    // ==================== 校验助手 ====================

    fn validate_metric(metric: &str) -> Result<(), ServiceError> {
        if VALID_METRICS.contains(&metric) {
            Ok(())
        } else {
            Err(ServiceError::bad_request(&crate::tr!(
                "error.alert.metric_invalid"
            )))
        }
    }

    fn validate_comparator(comparator: &str) -> Result<(), ServiceError> {
        if VALID_COMPARATORS.contains(&comparator) {
            Ok(())
        } else {
            Err(ServiceError::bad_request(&crate::tr!(
                "error.alert.comparator_invalid"
            )))
        }
    }

    fn validate_enabled(enabled: &str) -> Result<(), ServiceError> {
        match enabled {
            "0" | "1" => Ok(()),
            _ => Err(ServiceError::bad_request(&crate::tr!(
                "error.alert.enabled_invalid"
            ))),
        }
    }

    /// 解析通知收件人：按渠道 ID 取渠道类型
    /// - `site` → 管理员用户 id（站内信 to_addr 约定）
    /// - `email` → 管理员用户邮箱（为空则报错，由调用方跳过发送）
    async fn resolve_recipient(
        db: &DatabaseConnection,
        channel_id: i64,
    ) -> Result<String, ServiceError> {
        let channel = crate::entity::sys_msg_channel::Entity::find_by_id(channel_id)
            .one(db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.msg.channel_not_found")))?;

        match channel.channel_type.as_str() {
            "site" => Ok(ADMIN_USER_ID.to_string()),
            "email" => {
                let email = sys_user::Entity::find_by_id(ADMIN_USER_ID)
                    .one(db)
                    .await?
                    .and_then(|u| u.email)
                    .filter(|e| !e.trim().is_empty())
                    .ok_or_else(|| {
                        ServiceError::bad_request(&crate::tr!("error.alert.no_recipient"))
                    })?;
                Ok(email)
            }
            "sms" => Err(ServiceError::bad_request(&crate::tr!(
                "error.alert.channel_unsupported"
            ))),
            // 批次十八：IM 群机器人——群即收件人（to_addr 占位空串，dispatch 分支忽略）
            "wecom_robot" | "dingtalk_robot" => Ok(String::new()),
            _ => Err(ServiceError::bad_request(&crate::tr!(
                "error.msg.channel_type_invalid",
                channel_type = channel.channel_type.as_str()
            ))),
        }
    }
}

/// 单规则评估粗粒度结果
enum EvaluateOutcome {
    Fired,
    Skipped,
}

/// 比较器求值：gt/lt/ge/le（白名单外的比较器视为不命中，防御式处理）
fn compare(comparator: &str, value: f64, threshold: f64) -> bool {
    match comparator {
        "gt" => value > threshold,
        "lt" => value < threshold,
        "ge" => value >= threshold,
        "le" => value <= threshold,
        _ => false,
    }
}

/// 数值展示：整数省小数位，其余保留两位
fn format_value(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e9 {
        format!("{}", v as i64)
    } else {
        format!("{v:.2}")
    }
}

/// sysinfo 系统指标采集（同步阻塞，须在 spawn_blocking 中调用）
///
/// - cpu_usage：全局 CPU 使用率（两次采样取间隔均值，间隔 200ms）
/// - mem_usage：物理内存使用率
/// - disk_usage：全部挂载点中最大已用百分比
fn collect_system_metric(metric: &str) -> Result<f64, ServiceError> {
    use sysinfo::{Disks, System};

    match metric {
        "cpu_usage" => {
            let mut sys = System::new();
            sys.refresh_cpu_usage();
            std::thread::sleep(std::time::Duration::from_millis(200));
            sys.refresh_cpu_usage();
            Ok(sys.global_cpu_usage() as f64)
        }
        "mem_usage" => {
            let mut sys = System::new();
            sys.refresh_memory();
            let total = sys.total_memory();
            if total == 0 {
                return Ok(0.0);
            }
            Ok(sys.used_memory() as f64 / total as f64 * 100.0)
        }
        "disk_usage" => {
            let disks = Disks::new_with_refreshed_list();
            let mut max_usage = 0.0f64;
            for disk in disks.list() {
                let total = disk.total_space();
                if total == 0 {
                    continue;
                }
                let used = total.saturating_sub(disk.available_space());
                let usage = used as f64 / total as f64 * 100.0;
                if usage > max_usage {
                    max_usage = usage;
                }
            }
            Ok(max_usage)
        }
        _ => Err(ServiceError::bad_request(&crate::tr!(
            "error.alert.metric_invalid"
        ))),
    }
}

// ==================== 调度任务函数（scheduler 挂载用） ====================

/// 执行一轮告警规则评估（调度器任务函数，cron 建议每 60s 一次）
///
/// 供 `scheduler/mod.rs` 内置 cron 任务闭包与 registry 任务函数复用
/// （挂载片段见任务报告——scheduler/mod.rs 为禁改公共注册文件，由主线程集成）。
/// 错误类型为 `Box<dyn Error + Send + Sync>`，与 `registry::TaskFn` 签名对齐
/// （R5-TYPE-19）；评估内部已逐规则容错，此处仅整体不可恢复错误（如启用规则
/// 列表查询失败）上抛，由调度器写入 job_log。
pub async fn alert_eval_once(
    db: DatabaseConnection,
    store: Arc<dyn SharedStore>,
    config: Arc<Settings>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // b92 N-90-2：调度器与 registry 手动执行都走这里，必须与单条手动评估共用同一把闸。
    // 闸满 ⇒ 本轮跳过（下一分钟重试，规则不丢），但 WARN + 决策指标都要留痕——
    // 静默跳过会让"告警为什么没触发"永远查不到成因。
    let _gate = match crate::common::resource_gate::try_enter(
        crate::common::resource_gate::HeavyEntry::AlertEvaluate,
    ) {
        Ok(permit) => permit,
        Err(err) => {
            tracing::warn!(
                entry = crate::common::resource_gate::HeavyEntry::AlertEvaluate.label(),
                action = "alert_eval_once",
                code = err.code,
                error = %err.message,
                "告警评估闸已满：本轮跳过，下一轮重试（规则不丢）"
            );
            return Ok(alert_eval_busy_summary().to_string());
        }
    };
    let service = SysAlertService::new(db, store, config);
    let (evaluated, fired) = service.evaluate_all().await?;
    if evaluated == 0 {
        return Ok("无启用告警规则，本轮评估跳过".to_string());
    }
    Ok(format!("评估告警规则 {evaluated} 条，触发 {fired} 条"))
}

/// 闸满时的可行动文案（单测钉住：必须点名入口、说明会重试、并保证规则不丢）。
fn alert_eval_busy_summary() -> &'static str {
    "告警评估闸已满（alert:evaluate）：本轮跳过，下一轮重试（规则不丢）"
}

/// 注册 registry 任务函数（invoke_target = `alertEvalTask.run`）
///
/// 由 `scheduler/mod.rs::register_builtin_tasks` 调用（挂载片段见任务报告）；
/// 注册后可在「定时任务」管理页以 invoke_target 手动执行/验证。
/// 范式对齐 `cleanup_expired_logs`（db/config clone 进闭包，registry 覆盖式注册）。
pub fn register_alert_eval_task(
    db: DatabaseConnection,
    store: Arc<dyn SharedStore>,
    config: Arc<Settings>,
) {
    crate::scheduler::registry::register_task(
        "alertEvalTask.run",
        Arc::new(move || {
            let db = db.clone();
            let store = store.clone();
            let config = config.clone();
            Box::pin(async move { alert_eval_once(db, store, config).await })
        }),
    );
    tracing::info!("任务函数已注册: alertEvalTask.run（告警规则评估）");
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::{alert_eval_busy_summary, compare};

    #[test]
    fn comparator_gt_lt() {
        assert!(compare("gt", 5.0, 4.0));
        assert!(!compare("gt", 4.0, 4.0), "gt 为严格大于");
        assert!(compare("lt", 3.0, 4.0));
        assert!(!compare("lt", 4.0, 4.0));
    }

    #[test]
    fn comparator_ge_le() {
        assert!(compare("ge", 4.0, 4.0), "ge 含等号边界");
        assert!(compare("le", 4.0, 4.0), "le 含等号边界");
        assert!(!compare("ge", 3.9, 4.0));
        assert!(!compare("le", 4.1, 4.0));
    }

    #[test]
    fn comparator_unknown_is_fail_closed() {
        // 非法比较器一律不命中（创建/更新入口另有白名单校验，此处为纵深防御）
        assert!(!compare("==", 5.0, 4.0));
        assert!(!compare("", 5.0, 4.0));
    }

    /// b92 N-90-2：定时/registry 评估必须与手动评估共用 `alert:evaluate` 闸，
    /// 且取闸要排在真正评估之前（否则"闸满时整表评估照常开始"）。
    #[test]
    fn alert_eval_once_takes_the_gate_before_evaluating() {
        fn gate_before_work(src: &str) -> bool {
            match (src.find("try_enter("), src.find("service.evaluate_all()")) {
                (Some(gate), Some(work)) => gate < work,
                _ => false,
            }
        }

        let text = crate::common::prod_scan::prod_file(
            "src/service/sys_alert_service.rs",
            &crate::common::prod_scan::Scan::default(),
        )
        .text();
        let start = text
            .find("pub async fn alert_eval_once(")
            .expect("alert_eval_once 被删了 ⇒ 定时告警评估链路断裂");
        let body = &text[start..];
        let body = &body[..body
            .find("\n}\n")
            .expect("alert_eval_once 函数体边界找不到（本锁的对照失效）")];

        assert!(
            body.contains("try_enter(") && body.contains("HeavyEntry::AlertEvaluate"),
            "评估入口必须取 alert:evaluate 闸"
        );
        assert!(
            body.contains("let _gate ="),
            "许可必须在整个评估轮次内持有（`let _ =` 会立即释放，等于没限流）"
        );
        assert!(
            gate_before_work(body),
            "取闸必须排在 service.evaluate_all() 之前，否则闸满时整表评估已经开始"
        );
        // 顺序反例必须能被同一条纯函数抓到
        assert!(
            !gate_before_work("service.evaluate_all().await; try_enter(AlertEvaluate);"),
            "顺序反例不得被误判为合规"
        );

        let summary = alert_eval_busy_summary();
        assert!(
            summary.contains("alert:evaluate")
                && summary.contains("下一轮")
                && summary.contains("规则不丢"),
            "闸满文案必须可行动（点名入口 + 重试时机 + 不丢规则），实际: {summary}"
        );
    }
}
