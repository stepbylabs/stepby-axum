// stepby-axum/src/entity/sys_alert_rule.rs
//! sys_alert_rule 实体定义（告警规则表）
//!
//! 表由迁移 m20261003_000003_alert_rule 创建（存量库由
//! `initialize/mod.rs::ensure_alert_rule_tables` 幂等兜底，DDL 单一事实源在该迁移文件）。
//!
//! 字段语义：
//! - `metric`：指标标识，白名单见 `service/sys_alert_service.rs::VALID_METRICS`
//! - `comparator`：比较器 gt/lt/ge/le，白名单见 `VALID_COMPARATORS`
//! - `enabled`：'1' 启用 / '0' 停用（CHAR(1)，对齐 sys_menu.visible 风格）
//! - `last_fired_at`：上次触发时间（NULL = 从未触发；静默期判定的基准）
//! - 时间列为 created_at / updated_at（与 sys_msg_* 等 2026 新表命名对齐），
//!   不复用 create_time/update_time 宏，`ActiveModelBehavior` 在下方自行实现。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_alert_rule")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysAlertRule",
    export_to = "SysAlertRule.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysAlertRule)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 规则名称
    pub name: String,
    /// 指标标识（login_failed_5m / http_5xx_5m / job_failed_24h / online_users /
    /// cpu_usage / mem_usage / disk_usage）
    pub metric: String,
    /// 比较器（gt/lt/ge/le）
    pub comparator: String,
    /// 阈值
    pub threshold: f64,
    /// 静默期（分钟）：触发后在该窗口内不重复通知
    pub silent_minutes: i32,
    /// 通知渠道 ID（sys_msg_channel.channel_id；空 = 仅记录不发送）
    pub notify_channel_id: Option<i64>,
    /// 通知模板 ID（sys_msg_template.template_id；发送时按其解析 template_code）
    pub notify_template_id: Option<i64>,
    /// 是否启用（'1' 启用 / '0' 停用）
    pub enabled: Option<String>,
    /// 上次触发时间（NULL = 从未触发）
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub last_fired_at: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub created_at: Option<NaiveDateTime>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

/// 时间戳填充：insert 时写 created_at + updated_at，update 时仅刷 updated_at。
/// （表列名为 created_at/updated_at，与 `impl_timestamped_active_model!` 宏的
/// create_time/update_time 固定列名不匹配，故自行实现。）
#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: sea_orm::ConnectionTrait,
    {
        let now = crate::common::datetime::now_naive();
        let mut this = self;
        if insert {
            this.created_at = Set(Some(now));
        }
        this.updated_at = Set(Some(now));
        Ok(this)
    }
}
