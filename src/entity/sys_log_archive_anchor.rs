//! sys_log_archive_anchor 实体定义（操作日志删除锚点——链感知保留，批次十九）
//!
//! 背景：防篡改 HMAC 链跨行串联，任何物理删除（保留期清理 / 手动按区间清理）
//! 都会让 verify-chain 的"链首起验"失效。锚点行在删除前登记被删区间内**最后一个
//! 链行**（chain_hash 非 NULL）的边界与 hash，verify 重算时用它作 prev 种子续接，
//! 使链校验在"存在清理缺口"时仍可整体重算（valid_with_gap），只有真篡改才报 broken。
//!
//! 多租户：链跨租户全局串联 ⇒ 锚点是全局链缺口登记，**无租户维度**；删除路径的
//! 租户语义由调用方保持（cleanup 平台视角 / 手动 clean 带 tenant_scope 过滤）。

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, DeriveEntityModel, Serialize, Deserialize, ToSchema)]
#[sea_orm(table_name = "sys_log_archive_anchor")]
#[serde(rename_all = "camelCase")]
pub struct Model {
    /// 锚点 ID（自增）
    #[sea_orm(primary_key)]
    pub anchor_id: i64,
    /// 被删区间内首个链行 oper_id（chain_hash 非 NULL）
    pub first_oper_id: i64,
    /// 被删区间内最后一个链行 oper_id
    pub last_oper_id: i64,
    /// 被删段内最后一个链行的 chain_hash（= 幸存续接行的真实前驱）
    pub last_chain_hash: String,
    /// 被删全行数（含 chain_hash 为 NULL 的行，统计口径）
    pub deleted_count: i64,
    /// 删除模式：delete（直接删）/ archive（导出后删）
    pub mode: String,
    /// archive 模式导出对象在存储后端的 key（平台租户 0 归属；NULL = 未归档）
    pub archive_object_key: Option<String>,
    /// 删除执行时刻——verify 种子判定：行 oper_time 早于它 ⇒ 行在删除前已存在
    /// （真实前驱是被删尾行）；晚于它 ⇒ 行在删除后写入（写侧已续接幸存前驱）
    pub deleted_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
