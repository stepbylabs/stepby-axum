//! sys_tenant_domain 实体定义（租户域名绑定，多租户 Phase 3）
//!
//! 域名链路（文档 §27.7 / §29.6）：TLS 与 host 路由交 Nginx/网关，反代注入
//! 内部 `X-Tenant-Code`；后端仅信任反代来源，并按域名表校验绑定关系。
//!
//! `domain` **全局唯一**（同一域名不可绑定到两个租户）——唯一域含 tenant_id 无意义，
//! 故本表用单列唯一索引 `uk_sys_tenant_domain_domain`。

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_tenant_domain")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysTenantDomain",
    export_to = "SysTenantDomain.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysTenantDomain)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub domain_id: i64,
    /// 归属租户（sys_tenant.tenant_id）
    pub tenant_id: i64,
    /// 绑定的域名（小写、去端口；全局唯一）
    #[sea_orm(unique)]
    pub domain: String,
    /// 域名类型：'0' 子域名（平台分配，免 DNS 验证）/ '1' 自定义域名（需 DNS TXT 验证）
    pub domain_type: String,
    /// '0' 主域名 / '1' 附加域名
    pub is_primary: Option<String>,
    /// '0' 待验证 / '1' 已验证 / '2' 验证失败（DNS TXT 校验）
    pub verify_status: Option<String>,
    /// DNS TXT 校验 token（verify_status='1' 后保留以免重复绑定时被复用）
    pub verify_token: Option<String>,
    /// DNS TXT 验证通过时间（未验证 / 子域名免验证时为 NULL）
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub verified_at: Option<NaiveDateTime>,
    /// '0' 启用 / '1' 停用
    pub status: Option<String>,
    pub del_flag: Option<String>,
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
    pub remark: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();