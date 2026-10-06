//! sys_web_hook 实体定义（WebHook 回调配置表）
//!
//! event_types: 逗号分隔的事件类型（如 "login,report_pushed,user.created"），空串表示匹配全部
//! target_url:  出站投递目标 URL（http/https，经 SSRF 校验放行）
//! secret:      签名密钥（非空时出站请求携带 `X-Stepby-Signature: sha256=<hmac>` 供接收方验签）
//! content_type: json（默认）/ form-urlencoded
//! status:       "0"=启用 "1"=停用

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_web_hook")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysWebHook",
    export_to = "SysWebHook.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysWebHook)]
pub struct Model {
    /// 多租户归属（Phase 2 立项铺开，迁移 m20260925_000001；0=平台租户）
    pub tenant_id: i64,
    #[sea_orm(primary_key)]
    pub id: i64,
    /// 回调名称
    pub hook_name: String,
    /// 订阅的事件类型（逗号分隔；空串匹配全部）
    pub event_types: String,
    /// 订阅的事件目录键（JSON 数组字符串，如 `["user.created","login.success"]`；
    /// NULL 或空 = 订阅全部事件（兼容存量行为）。emit_event 派发按本列过滤。
    pub subscribed_events: Option<String>,
    /// 出站目标 URL
    pub target_url: String,
    /// 签名密钥（可选；G-14 通用层：EncryptedString 列类型，取存自动加解密
    /// ——enc3 信封，密钥源 runtime_master_key；密文列不可 LIKE/等值查询）
    pub secret: Option<crate::common::encrypted_value::EncryptedString>,
    /// 请求体格式：json / form-urlencoded
    pub content_type: String,
    /// 超时秒数
    pub timeout_secs: i32,
    /// 状态（0=启用 1=停用）
    pub status: String,
    pub remark: Option<String>,
    pub create_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub create_time: Option<NaiveDateTime>,
    pub update_by: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub update_time: Option<NaiveDateTime>,
    pub del_flag: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();
