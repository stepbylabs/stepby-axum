// stepby-axum/src/service/scim_group_service.rs
//! v5-D12 Group：SCIM 2.0 Group 资源 + 双映射联动引擎（RFC 7644 §4.2）。
//!
//! 拍板方案（福哥 2026-09-24，方案一全做）：
//! - **A 组→角色集合映射**（mapping_type='role'，默认）：组绑定一组角色
//!   （sys_scim_group_binding，target_id=role_id），成员变更自动联动
//!   sys_user_role 授权增删，来源标记 source='scim:{group_id}'——与管理员
//!   手授（source='admin'）两个事实源分离，消除回写抖动。
//! - **B 组→兼职部门同步**（mapping_type='dept'）：组绑定一个部门
//!   （target_id=dept_id），成员变更联动 sys_user_dept 兼职记录
//!   （source='scim:{group_id}'）。主部门永远人工管理（IdP 不决定主部门）。
//!
//! 生命周期语义（§23 §3 + §24 第二轮核查补充）：
//! 1. **成员 diff 幂等**：PUT/replace members 全量 diff；重放同一列表零副作用
//!    （授权行存在且 source 相同 → 跳过）。
//! 2. **组删除**：软删组 + 物理清成员/绑定 + 撤销**仅 source='scim:{gid}'**
//!    的授权与兼职记录（管理员手授的不动）。
//! 3. **用户 deprovision**：清理该用户全部组成员记录 + 撤 scim 来源授权/兼职。
//! 4. **组 rename 无影响**：绑定按 group_id 持久化，displayName 纯展示字段。
//! 5. **mapping_type 变更前置**：必须先清空绑定（服务层强制），防 target 语义混淆。
//! 6. **授权优先级**：目标行已存在（admin 或其它组来源）→ 不覆盖不重复插入；
//!    撤销只删本组 source 行。

use crate::entity::sys_scim_group::{
    ActiveModel as GroupAM, Column as GroupCol, Entity as ScimGroup, Model as GroupModel,
};
use crate::entity::sys_scim_group_binding::{
    ActiveModel as BindingAM, Column as BindingCol, Entity as GroupBinding,
};
use crate::entity::sys_scim_group_member::{
    ActiveModel as MemberAM, Column as MemberCol, Entity as GroupMember,
};
use crate::entity::sys_user;
use crate::entity::sys_user_dept::{
    ActiveModel as UserDeptAM, Column as UserDeptCol, Entity as SysUserDept,
};
use crate::entity::sys_user_role::{
    ActiveModel as UserRoleAM, Column as UserRoleCol, Entity as SysUserRole,
};
use crate::service::scim_service::ScimError;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    DatabaseTransaction, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set,
    TransactionTrait, Value,
};

const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const MAPPING_ROLE: &str = "role";
pub const MAPPING_DEPT: &str = "dept";

/// source 标记格式：'scim:{group_id}'
fn scim_source(group_id: i64) -> String {
    format!("scim:{group_id}")
}

/// SCIM Group 资源（响应体，RFC 7644 §4.2）
#[derive(Debug, serde::Serialize)]
pub struct ScimGroupResource {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<ScimGroupMemberRef>,
    pub meta: crate::service::scim_service::ScimMeta,
}

#[derive(Debug, serde::Serialize)]
pub struct ScimGroupMemberRef {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "String::is_empty")]
    pub ref_: String,
    #[serde(rename = "display", skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// SCIM Group ListResponse 信封（resources 与 Users 列表类型不同，独立结构）
#[derive(Debug, serde::Serialize)]
pub struct ScimGroupListResponse {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: u64,
    #[serde(rename = "startIndex")]
    pub start_index: u64,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: u64,
    #[serde(rename = "Resources")]
    pub resources: Vec<ScimGroupResource>,
}

/// 管理端：组详情出参
#[derive(Debug, serde::Serialize, ts_rs::TS, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    export_to = "ScimGroupAdminDetail.ts",
    rename_all = "camelCase"
)]
#[schema(as = ScimGroupAdminDetail)]
pub struct ScimGroupAdminDetail {
    pub group_id: i64,
    pub display_name: String,
    pub external_id: Option<String>,
    pub mapping_type: String,
    /// 成员（只读——权威在 IdP）
    pub members: Vec<ScimGroupAdminMember>,
    /// 绑定目标 id 列表（role→role_id / dept→dept_id，按 mapping_type 语义）
    pub binding_target_ids: Vec<i64>,
    pub create_time: Option<String>,
}

#[derive(Debug, serde::Serialize, ts_rs::TS, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    export_to = "ScimGroupAdminMember.ts",
    rename_all = "camelCase"
)]
#[schema(as = ScimGroupAdminMember)]
pub struct ScimGroupAdminMember {
    pub user_id: i64,
    pub user_name: String,
    pub nick_name: String,
}

pub struct ScimGroupService {
    db: DatabaseConnection,
    /// v5-N2 Phase 3：SCIM 凭据归属租户。该凭据 provisioning 出的组归属此租户，
    /// 读路径亦按此租户过滤（0 = 平台租户，读不过滤 + 写归属平台 0）。
    tenant_id: i64,
}

impl ScimGroupService {
    pub fn new(db: DatabaseConnection, tenant_id: i64) -> Self {
        Self { db, tenant_id }
    }

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    // ==================== SCIM 端（RFC 7644 §4.2） ====================

    /// 组 Model → SCIM Group 资源（members 展开用户 display）
    async fn to_scim_group(
        &self,
        m: &GroupModel,
        base_url: &str,
    ) -> Result<ScimGroupResource, ScimError> {
        let member_rows = GroupMember::find()
            .filter(MemberCol::GroupId.eq(m.group_id))
            .all(self.db())
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?;
        let mut members = Vec::with_capacity(member_rows.len());
        for mr in member_rows {
            let display = sys_user::Entity::find_by_id(mr.user_id)
                .one(self.db())
                .await
                .ok()
                .flatten()
                .map(|u| u.nick_name);
            members.push(ScimGroupMemberRef {
                value: mr.user_id.to_string(),
                ref_: format!("{base_url}/scim/v2/Users/{}", mr.user_id),
                display,
            });
        }
        Ok(ScimGroupResource {
            schemas: vec![SCIM_GROUP_SCHEMA.to_string()],
            id: m.group_id.to_string(),
            external_id: m.external_id.clone(),
            display_name: m.display_name.clone(),
            members,
            meta: crate::service::scim_service::ScimMeta {
                resource_type: "Group".to_string(),
                location: format!("{base_url}/scim/v2/Groups/{}", m.group_id),
            },
        })
    }

    /// filter 白名单：displayName eq / externalId eq（同 Users 语义）
    /// 返回 (列名, 原始值)；值由调用方参数化绑定（不再做字符串转义）。
    fn parse_group_filter(filter: &str) -> Option<(&'static str, String)> {
        let parts: Vec<&str> = filter.split_whitespace().collect();
        if parts.len() != 3 || !parts[1].eq_ignore_ascii_case("eq") {
            return None;
        }
        let val = parts[2].trim_matches('\'').trim_matches('"');
        if parts[0].eq_ignore_ascii_case("displayName") {
            Some(("display_name", val.to_string()))
        } else if parts[0].eq_ignore_ascii_case("externalId") {
            Some(("external_id", val.to_string()))
        } else {
            None
        }
    }

    /// GET /Groups：分页 + filter
    pub async fn list_groups(
        &self,
        start_index: u64,
        count: u64,
        filter: Option<&str>,
        base_url: &str,
    ) -> Result<ScimGroupListResponse, ScimError> {
        use sea_orm::Statement;
        let backend = self.db().get_database_backend();
        let start = start_index.max(1);
        let count = count.clamp(1, 200);
        // Postgres 需 $n 占位符，Sqlite/MySQL 用 ?（值均参数化绑定，杜绝拼接注入）
        let ph = |i: usize| -> String {
            if backend == DatabaseBackend::Postgres {
                format!("${i}")
            } else {
                "?".to_string()
            }
        };
        let mut where_clause = String::from("del_flag <> '2'");
        let mut values: Vec<Value> = Vec::new();
        // v5-N2 Phase 3：按 SCIM 凭据归属租户过滤（0 = 平台租户，全量可见）
        if let Some(tid) = crate::common::tenant::tenant_scope(self.tenant_id) {
            where_clause.push_str(&format!(" AND tenant_id = {}", ph(values.len() + 1)));
            values.push(tid.into());
        }
        if let Some(f) = filter {
            match Self::parse_group_filter(f) {
                Some((col, val)) => {
                    where_clause.push_str(&format!(" AND {col} = {}", ph(values.len() + 1)));
                    values.push(val.into());
                }
                None => {
                    return Err(ScimError::new(
                        400,
                        "unsupported filter（仅支持 displayName eq / externalId eq \"<value>\"）",
                    ));
                }
            }
        }
        let count_sql = format!("SELECT COUNT(*) AS c FROM sys_scim_group WHERE {where_clause}");
        let total = self
            .db()
            .query_one(Statement::from_sql_and_values(
                backend,
                count_sql,
                values.clone(),
            ))
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?
            .and_then(|r| r.try_get::<i64>("", "c").ok())
            .unwrap_or(0) as u64;
        let list_sql = format!(
            "SELECT group_id FROM sys_scim_group WHERE {where_clause} ORDER BY group_id LIMIT {count} OFFSET {}",
            start - 1
        );
        let rows = self
            .db()
            .query_all(Statement::from_sql_and_values(backend, list_sql, values))
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?;
        let mut resources = Vec::with_capacity(rows.len());
        for row in rows {
            let gid = row.try_get::<i64>("", "group_id").unwrap_or(0);
            if let Ok(Some(m)) = ScimGroup::find_by_id(gid).one(self.db()).await {
                resources.push(self.to_scim_group(&m, base_url).await?);
            }
        }
        Ok(ScimGroupListResponse {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
            total_results: total,
            start_index: start,
            items_per_page: resources.len() as u64,
            resources,
        })
    }

    /// GET /Groups/{id}
    pub async fn get_group(&self, id: i64, base_url: &str) -> Result<ScimGroupResource, ScimError> {
        let m = self.find_active(id).await?;
        self.to_scim_group(&m, base_url).await
    }

    /// 解析 members[].value → user_id 列表（去重；校验用户存在且未软删 → 400）
    async fn parse_member_ids(&self, body: &serde_json::Value) -> Result<Vec<i64>, ScimError> {
        let raw = body
            .get("members")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut ids = Vec::with_capacity(raw.len());
        for item in raw {
            let val = item
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ScimError::new(400, "members[].value is required"))?;
            let uid: i64 = val
                .parse()
                .map_err(|_| ScimError::new(400, format!("invalid member value: {val}")))?;
            if !ids.contains(&uid) {
                ids.push(uid);
            }
        }
        for uid in &ids {
            let exists = sys_user::Entity::find_by_id(*uid)
                .one(self.db())
                .await
                .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?
                .filter(|u| u.del_flag.as_deref() != Some("2"));
            if exists.is_none() {
                return Err(ScimError::new(400, format!("member user not found: {uid}")));
            }
        }
        Ok(ids)
    }

    /// POST /Groups：建组 + 成员 + 联动授权（mapping_type 默认 role；
    /// externalId 唯一校验防 IdP 重复推送）
    ///
    /// v5-N2 Phase 3：SCIM 端点由身份凭据的归属租户（`scim.tenant_id`）确定建组归属，
    /// 取代先前硬编码平台租户 0（与 `scim_service::create_user` 同源语义）。
    pub async fn create_group(
        &self,
        body: &serde_json::Value,
        base_url: &str,
    ) -> Result<ScimGroupResource, ScimError> {
        let display_name = body
            .get("displayName")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ScimError::new(400, "displayName is required"))?
            .to_string();
        if display_name.len() > 255 {
            return Err(ScimError::new(400, "displayName 长度须 ≤255"));
        }
        let external_id = body
            .get("externalId")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        if let Some(ext) = &external_id {
            if ext.len() > 255 {
                return Err(ScimError::new(400, "externalId 长度须 ≤255"));
            }
            if ScimGroup::find()
                .filter(GroupCol::ExternalId.eq(ext))
                .one(self.db())
                .await
                .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?
                .is_some()
            {
                return Err(ScimError::new(409, "externalId 已存在"));
            }
        }
        let member_ids = self.parse_member_ids(body).await?;
        let now = crate::common::datetime::now_naive();
        // v5-N2 Phase 3：归属 SCIM 凭据所属租户（0 = 平台租户）；取代先前硬编码 Set(0)
        let tenant_id = self.tenant_id;

        let saved = self
            .db()
            .transaction::<_, GroupModel, ScimError>(|txn| {
                Box::pin(async move {
                    let am = GroupAM {
                        display_name: Set(display_name.clone()),
                        external_id: Set(external_id.clone()),
                        mapping_type: Set(MAPPING_ROLE.to_string()),
                        del_flag: Set(Some("0".to_string())),
                        tenant_id: Set(tenant_id),
                        create_by: Set(Some("scim".to_string())),
                        create_time: Set(Some(now)),
                        update_time: Set(Some(now)),
                        ..Default::default()
                    };
                    let group = am.insert(txn).await.map_err(db_err_500)?;
                    for uid in &member_ids {
                        insert_member(txn, group.group_id, *uid, now).await?;
                    }
                    // role 组：按当前绑定（空）授权——新建组无绑定，仅落成员关系。
                    Ok(group)
                })
            })
            .await;
        let group = saved?;
        let resource = self.to_scim_group(&group, base_url).await?;
        Ok(resource)
    }

    /// PUT /Groups/{id}：displayName + members 全量 diff。
    /// externalId 保守处理：携带则校验唯一并更新，未携带保留（不做全量置空——
    /// externalId 是 IdP 关联键，误清会导致后续同步重复建组）。
    pub async fn put_group(
        &self,
        id: i64,
        body: &serde_json::Value,
        base_url: &str,
    ) -> Result<ScimGroupResource, ScimError> {
        let m = self.find_active(id).await?;
        let display_name = body
            .get("displayName")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&m.display_name)
            .to_string();
        if display_name.len() > 255 {
            return Err(ScimError::new(400, "displayName 长度须 ≤255"));
        }
        let external_id = match body
            .get("externalId")
            .and_then(|v| v.as_str())
            .map(str::trim)
        {
            Some(ext) if !ext.is_empty() => {
                if ext.len() > 255 {
                    return Err(ScimError::new(400, "externalId 长度须 ≤255"));
                }
                if ScimGroup::find()
                    .filter(GroupCol::TenantId.eq(m.tenant_id))
                    .filter(GroupCol::ExternalId.eq(ext))
                    .one(self.db())
                    .await
                    .map_err(db_err_500)?
                    .filter(|g| g.group_id != id)
                    .is_some()
                {
                    return Err(ScimError::new(409, "externalId 已存在"));
                }
                Some(ext.to_string())
            }
            _ => m.external_id.clone(),
        };
        let member_ids = self.parse_member_ids(body).await?;
        let now = crate::common::datetime::now_naive();

        let updated = self
            .db()
            .transaction::<_, GroupModel, ScimError>(|txn| {
                Box::pin(async move {
                    let mut am: GroupAM = m.clone().into();
                    am.display_name = Set(display_name.clone());
                    am.external_id = Set(external_id.clone());
                    am.update_time = Set(Some(now));
                    let group = am.update(txn).await.map_err(db_err_500)?;
                    diff_members(txn, group.group_id, &group.mapping_type, &member_ids, now)
                        .await?;
                    Ok(group)
                })
            })
            .await;
        let group = updated?;
        self.to_scim_group(&group, base_url).await
    }

    /// PATCH /Groups/{id}（RFC 7644 §3.5.2）：
    /// - add path=members：逐成员授权（幂等）
    /// - remove path=members：逐成员撤销（仅本组 source）
    /// - replace path=displayName / 无 path（含 displayName/members 对象）
    /// - replace path=members：全量 diff
    pub async fn patch_group(
        &self,
        id: i64,
        body: &serde_json::Value,
        base_url: &str,
    ) -> Result<ScimGroupResource, ScimError> {
        let m = self.find_active(id).await?;
        let ops = body
            .get("Operations")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ScimError::new(400, "Operations is required"))?
            .clone();

        // 解析目标状态（在同一事务内按序应用）
        let updated = self
            .db()
            .transaction::<_, GroupModel, ScimError>(|txn| {
                Box::pin(async move {
                    let mut current: GroupModel = m.clone();
                    let now = crate::common::datetime::now_naive();
                    for op in &ops {
                        let op_name = op
                            .get("op")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_ascii_lowercase();
                        let path = op
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let value = op.get("value").cloned().unwrap_or(serde_json::Value::Null);
                        match (op_name.as_str(), path.as_str()) {
                            ("add", "members") => {
                                for uid in parse_member_values(&value)? {
                                    validate_member(txn, uid).await?;
                                    insert_member(txn, current.group_id, uid, now).await?;
                                    grant_member(txn, current.group_id, &current.mapping_type, uid)
                                        .await?;
                                }
                            }
                            ("remove", "members") => {
                                for uid in parse_member_values(&value)? {
                                    delete_member(txn, current.group_id, uid).await?;
                                    revoke_member(txn, current.group_id, uid).await?;
                                }
                            }
                            ("replace", "members") => {
                                let ids = parse_member_values(&value)?;
                                for uid in &ids {
                                    validate_member(txn, *uid).await?;
                                }
                                diff_members(
                                    txn,
                                    current.group_id,
                                    &current.mapping_type,
                                    &ids,
                                    now,
                                )
                                .await?;
                            }
                            ("replace", "displayName") => {
                                let dn = value
                                    .as_str()
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                    .ok_or_else(|| {
                                        ScimError::new(400, "displayName 值必须为非空字符串")
                                    })?;
                                if dn.len() > 255 {
                                    return Err(ScimError::new(400, "displayName 长度须 ≤255"));
                                }
                                current.display_name = dn.to_string();
                            }
                            ("replace", "") => {
                                if let Some(dn) = value.get("displayName").and_then(|v| v.as_str())
                                {
                                    let dn = dn.trim();
                                    if dn.is_empty() || dn.len() > 255 {
                                        return Err(ScimError::new(
                                            400,
                                            "displayName 长度须 1-255",
                                        ));
                                    }
                                    current.display_name = dn.to_string();
                                }
                                if let Some(mv) = value.get("members") {
                                    let ids = parse_member_values(mv)?;
                                    for uid in &ids {
                                        validate_member(txn, *uid).await?;
                                    }
                                    diff_members(
                                        txn,
                                        current.group_id,
                                        &current.mapping_type,
                                        &ids,
                                        now,
                                    )
                                    .await?;
                                }
                            }
                            _ => {
                                return Err(ScimError::new(
                                    400,
                                    format!("不支持的 PATCH op/path: {op_name} {path}"),
                                ));
                            }
                        }
                    }
                    let mut am: GroupAM = current.clone().into();
                    am.update_time = Set(Some(now));
                    let group = am.update(txn).await.map_err(db_err_500)?;
                    Ok(group)
                })
            })
            .await;
        let group = updated?;
        self.to_scim_group(&group, base_url).await
    }

    /// DELETE /Groups/{id}：软删 + 清成员/绑定 + 撤销仅本组 source 的授权与兼职。
    pub async fn delete_group(&self, id: i64) -> Result<(), ScimError> {
        let m = self.find_active(id).await?;
        self.teardown(m.group_id).await
    }

    // ==================== 管理端（JWT 鉴权 /system/scim-groups） ====================

    /// 管理端列表（分页 + display_name 模糊 + mapping_type 精确），带成员/绑定计数。
    /// v5-N2 Phase 3：按操作者租户过滤（operator_tid=0 平台管理员不过滤）。
    pub async fn admin_list(
        &self,
        operator_tid: i64,
        page: u64,
        page_size: u64,
        display_name: Option<&str>,
        mapping_type: Option<&str>,
    ) -> Result<(Vec<ScimGroupAdminRow>, u64), ScimError> {
        let mut q = ScimGroup::find().filter(GroupCol::DelFlag.ne("2"));
        if let Some(tid) = crate::common::tenant::tenant_scope(operator_tid) {
            q = q.filter(GroupCol::TenantId.eq(tid));
        }
        if let Some(n) = display_name {
            q = q.filter(GroupCol::DisplayName.contains(n));
        }
        if let Some(t) = mapping_type {
            q = q.filter(GroupCol::MappingType.eq(t));
        }
        let total = q.clone().count(self.db()).await.map_err(db_err_500)?;
        let rows = q
            .order_by_asc(GroupCol::GroupId)
            .offset((page.saturating_sub(1)) * page_size)
            .limit(page_size)
            .all(self.db())
            .await
            .map_err(db_err_500)?;
        let mut out = Vec::with_capacity(rows.len());
        for g in rows {
            let member_count = GroupMember::find()
                .filter(MemberCol::GroupId.eq(g.group_id))
                .count(self.db())
                .await
                .map_err(db_err_500)?;
            let binding_count = GroupBinding::find()
                .filter(BindingCol::GroupId.eq(g.group_id))
                .count(self.db())
                .await
                .map_err(db_err_500)?;
            out.push(ScimGroupAdminRow {
                group_id: g.group_id,
                display_name: g.display_name,
                external_id: g.external_id,
                mapping_type: g.mapping_type,
                member_count,
                binding_count,
                create_time: g.create_time.map(|t| t.to_string()),
            });
        }
        Ok((out, total))
    }

    /// 管理端详情（成员展开用户名 + 绑定 id 列表）。
    /// v5-N2 Phase 3：按操作者租户过滤（operator_tid=0 平台管理员不过滤）。
    pub async fn admin_detail(
        &self,
        id: i64,
        operator_tid: i64,
    ) -> Result<ScimGroupAdminDetail, ScimError> {
        let m = self.find_active_scoped(id, operator_tid).await?;
        let member_rows = GroupMember::find()
            .filter(MemberCol::GroupId.eq(id))
            .all(self.db())
            .await
            .map_err(db_err_500)?;
        let mut members = Vec::with_capacity(member_rows.len());
        for mr in member_rows {
            let u = sys_user::Entity::find_by_id(mr.user_id)
                .one(self.db())
                .await
                .map_err(db_err_500)?
                .ok_or_else(|| ScimError::new(404, format!("成员用户不存在: {}", mr.user_id)))?;
            members.push(ScimGroupAdminMember {
                user_id: u.user_id,
                user_name: u.user_name,
                nick_name: u.nick_name,
            });
        }
        let bindings = GroupBinding::find()
            .filter(BindingCol::GroupId.eq(id))
            .all(self.db())
            .await
            .map_err(db_err_500)?;
        Ok(ScimGroupAdminDetail {
            group_id: m.group_id,
            display_name: m.display_name,
            external_id: m.external_id,
            mapping_type: m.mapping_type,
            members,
            binding_target_ids: bindings.iter().map(|b| b.target_id).collect(),
            create_time: m.create_time.map(|t| t.to_string()),
        })
    }

    /// 管理端更新：mappingType 与/或绑定集合（全量替换 + 全成员联动 diff）。
    /// - mapping_type 变更前置：当前绑定必须为空（否则 400，先清空再换）。
    /// - 绑定目标必须存在（role 未删 / dept 存在）。
    /// - 绑定替换 diff：新增目标 × 全成员 grant；移除目标 × 全成员 revoke。
    pub async fn admin_update(
        &self,
        id: i64,
        operator_tid: i64,
        mapping_type: Option<String>,
        binding_target_ids: Option<Vec<i64>>,
    ) -> Result<ScimGroupAdminDetail, ScimError> {
        let m = self.find_active_scoped(id, operator_tid).await?;
        if let Some(mt) = &mapping_type {
            if mt != MAPPING_ROLE && mt != MAPPING_DEPT {
                return Err(ScimError::new(400, "mappingType 仅支持 role / dept"));
            }
            if *mt != m.mapping_type {
                let has_binding = GroupBinding::find()
                    .filter(BindingCol::GroupId.eq(id))
                    .one(self.db())
                    .await
                    .map_err(db_err_500)?
                    .is_some();
                if has_binding {
                    return Err(ScimError::new(400, "mappingType 变更前必须先清空绑定目标"));
                }
            }
        }
        // 绑定目标存在性校验
        if let Some(targets) = &binding_target_ids {
            let effective_type = mapping_type.as_deref().unwrap_or(&m.mapping_type);
            for t in targets {
                match effective_type {
                    MAPPING_ROLE => {
                        let role = crate::entity::sys_role::Entity::find_by_id(*t)
                            .one(self.db())
                            .await
                            .map_err(db_err_500)?
                            .filter(|r| r.del_flag.as_deref() != Some("2"));
                        let Some(role) = role else {
                            return Err(ScimError::new(400, format!("角色不存在: {t}")));
                        };
                        // 越权防护（2026-09-26 复核发现并修复）：绑定目标必须属于操作者租户
                        // （`tenant_allowed` 对平台操作者 tid=0 放行）。否则租户操作者可将组绑定到
                        // **平台角色**（`tenant_id=0`，携带平台专属菜单）或**他租户角色**，从而把该
                        // 角色的菜单授权间接授予本租户用户，绕过租户边界
                        // （`system:scimgroup:*` 在过滤矩阵中为 Covered ⇒ 租户管理员可持有该权限）。
                        if !crate::common::tenant::tenant_allowed(operator_tid, role.tenant_id) {
                            return Err(ScimError::new(403, format!("角色不属于当前租户: {t}")));
                        }
                    }
                    MAPPING_DEPT => {
                        let dept = crate::entity::sys_dept::Entity::find_by_id(*t)
                            .one(self.db())
                            .await
                            .map_err(db_err_500)?;
                        let Some(dept) = dept else {
                            return Err(ScimError::new(400, format!("部门不存在: {t}")));
                        };
                        // 同理：跨租户部门绑定同样是越权（组→部门映射会改本租户用户的兼职归属）
                        if !crate::common::tenant::tenant_allowed(operator_tid, dept.tenant_id) {
                            return Err(ScimError::new(403, format!("部门不属于当前租户: {t}")));
                        }
                    }
                    other => {
                        return Err(ScimError::new(400, format!("未知 mappingType: {other}")));
                    }
                }
            }
        }
        let now = crate::common::datetime::now_naive();
        self.db()
            .transaction::<_, (), ScimError>(|txn| {
                Box::pin(async move {
                    if let Some(mt) = &mapping_type {
                        let mut am: GroupAM = m.clone().into();
                        am.mapping_type = Set(mt.clone());
                        am.update_time = Set(Some(now));
                        am.update(txn).await.map_err(db_err_500)?;
                    }
                    if let Some(targets) = &binding_target_ids {
                        let gid = m.group_id;
                        let mt = mapping_type
                            .as_deref()
                            .unwrap_or(&m.mapping_type)
                            .to_string();
                        apply_bindings_diff(txn, gid, &mt, targets, now).await?;
                    }
                    Ok(())
                })
            })
            .await?;
        self.admin_detail(id, operator_tid).await
    }

    /// 管理端删除 = SCIM delete_group 同语义。
    /// v5-N2 Phase 3：按操作者租户校验（operator_tid=0 平台管理员不过滤）。
    pub async fn admin_delete(&self, id: i64, operator_tid: i64) -> Result<(), ScimError> {
        let m = self.find_active_scoped(id, operator_tid).await?;
        self.teardown(m.group_id).await
    }

    /// 组 teardown 公共实现（软删 + 清成员/绑定 + 撤仅本组 source 的授权与兼职）
    async fn teardown(&self, group_id: i64) -> Result<(), ScimError> {
        self.db()
            .transaction::<_, (), ScimError>(|txn| {
                Box::pin(async move {
                    teardown_group(txn, group_id).await?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    // ==================== 用户侧联动 ====================

    /// 用户 deprovision / 删除联动：清该用户全部组成员记录 + 撤全部 scim 来源
    /// 授权与兼职记录（admin 手授保留）。
    pub async fn cleanup_user_membership(&self, user_id: i64) -> Result<(), ScimError> {
        self.db()
            .transaction::<_, (), ScimError>(|txn| {
                Box::pin(async move {
                    GroupMember::delete_many()
                        .filter(MemberCol::UserId.eq(user_id))
                        .exec(txn)
                        .await
                        .map_err(db_err_500)?;
                    SysUserRole::delete_many()
                        .filter(UserRoleCol::UserId.eq(user_id))
                        .filter(UserRoleCol::Source.starts_with("scim:"))
                        .exec(txn)
                        .await
                        .map_err(db_err_500)?;
                    SysUserDept::delete_many()
                        .filter(UserDeptCol::UserId.eq(user_id))
                        .filter(UserDeptCol::Source.starts_with("scim:"))
                        .exec(txn)
                        .await
                        .map_err(db_err_500)?;
                    Ok(())
                })
            })
            .await?;
        Ok(())
    }

    async fn find_active(&self, id: i64) -> Result<GroupModel, ScimError> {
        self.find_active_scoped(id, self.tenant_id).await
    }

    /// 按指定租户上下文读取活跃组（scope_tid=0 放行任意租户；否则须同租户）
    async fn find_active_scoped(&self, id: i64, scope_tid: i64) -> Result<GroupModel, ScimError> {
        ScimGroup::find_by_id(id)
            .one(self.db())
            .await
            .map_err(db_err_500)?
            .filter(|g| {
                g.del_flag.as_deref() != Some("2")
                    && crate::common::tenant::tenant_allowed(scope_tid, g.tenant_id)
            })
            .ok_or_else(|| ScimError::new(404, "Group not found"))
    }
}

// ==================== 管理端行结构 ====================

/// 管理端列表行（ts-rs 导出供前端）
#[derive(Debug, serde::Serialize, ts_rs::TS, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "ScimGroupAdminRow.ts", rename_all = "camelCase")]
#[schema(as = ScimGroupAdminRow)]
pub struct ScimGroupAdminRow {
    pub group_id: i64,
    pub display_name: String,
    pub external_id: Option<String>,
    pub mapping_type: String,
    pub member_count: u64,
    pub binding_count: u64,
    pub create_time: Option<String>,
}

// ==================== 事务内联动引擎（free fn，便于测试与复用） ====================

fn db_err_500(e: sea_orm::DbErr) -> ScimError {
    ScimError::new(500, format!("数据库错误: {e}"))
}

/// 解析 members value（PATCH value 形态：[{value:"1"}] 或 ["1"]）
fn parse_member_values(value: &serde_json::Value) -> Result<Vec<i64>, ScimError> {
    let mut ids = Vec::new();
    match value {
        serde_json::Value::Array(arr) => {
            for item in arr {
                let v = match item {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Object(_) => item
                        .get("value")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ScimError::new(400, "members[].value is required"))?
                        .to_string(),
                    _ => return Err(ScimError::new(400, "members 值格式不合法")),
                };
                let uid: i64 = v
                    .parse()
                    .map_err(|_| ScimError::new(400, format!("invalid member value: {v}")))?;
                if !ids.contains(&uid) {
                    ids.push(uid);
                }
            }
        }
        serde_json::Value::Object(_) => {
            return parse_member_values(&serde_json::Value::Array(vec![value.clone()]));
        }
        serde_json::Value::Null => {}
        _ => return Err(ScimError::new(400, "members 值格式不合法")),
    }
    Ok(ids)
}

/// 校验成员用户存在且未软删（fail-fast，IdP 重试语义）
async fn validate_member<C: ConnectionTrait>(txn: &C, user_id: i64) -> Result<(), ScimError> {
    let exists = sys_user::Entity::find_by_id(user_id)
        .one(txn)
        .await
        .map_err(db_err_500)?
        .filter(|u| u.del_flag.as_deref() != Some("2"));
    if exists.is_none() {
        return Err(ScimError::new(
            400,
            format!("member user not found: {user_id}"),
        ));
    }
    Ok(())
}

/// 插入成员记录（唯一约束兜底防重——重复插入视为幂等成功）
async fn insert_member<C: ConnectionTrait>(
    txn: &C,
    group_id: i64,
    user_id: i64,
    now: chrono::NaiveDateTime,
) -> Result<(), ScimError> {
    let am = MemberAM {
        group_id: Set(group_id),
        user_id: Set(user_id),
        create_time: Set(Some(now)),
    };
    match GroupMember::insert(am).exec(txn).await {
        Ok(_) => Ok(()),
        Err(e) if is_unique_violation(&e) => Ok(()),
        Err(e) => Err(db_err_500(e)),
    }
}

/// 删除成员记录
async fn delete_member<C: ConnectionTrait>(
    txn: &C,
    group_id: i64,
    user_id: i64,
) -> Result<(), ScimError> {
    GroupMember::delete_many()
        .filter(MemberCol::GroupId.eq(group_id))
        .filter(MemberCol::UserId.eq(user_id))
        .exec(txn)
        .await
        .map_err(db_err_500)?;
    Ok(())
}

/// 唯一约束冲突识别（sqlite/mysql/postgres 关键词粗匹配——插入前已业务判重，
/// 此处仅兜底并发窗口）
fn is_unique_violation(e: &sea_orm::DbErr) -> bool {
    let s = e.to_string();
    s.contains("UNIQUE")
        || s.contains("unique")
        || s.contains("duplicate")
        || s.contains("Duplicate")
}

/// 组成员 grant（联动引擎核心）：
/// - role 组：绑定角色逐个 upsert sys_user_role(source='scim:{gid}')；
///   行已存在（admin/其它组来源）→ 跳过（不覆盖）
/// - dept 组：绑定部门 upsert sys_user_dept(source='scim:{gid}')；已有
///   admin 行同部门 → 跳过（人工优先）
async fn grant_member<C: ConnectionTrait>(
    txn: &C,
    group_id: i64,
    mapping_type: &str,
    user_id: i64,
) -> Result<(), ScimError> {
    let bindings = GroupBinding::find()
        .filter(BindingCol::GroupId.eq(group_id))
        .all(txn)
        .await
        .map_err(db_err_500)?;
    let src = scim_source(group_id);
    for b in bindings {
        match mapping_type {
            MAPPING_ROLE => {
                let exists = SysUserRole::find()
                    .filter(UserRoleCol::UserId.eq(user_id))
                    .filter(UserRoleCol::RoleId.eq(b.target_id))
                    .one(txn)
                    .await
                    .map_err(db_err_500)?;
                if exists.is_none() {
                    let am = UserRoleAM {
                        user_id: Set(user_id),
                        role_id: Set(b.target_id),
                        source: Set(src.clone()),
                    };
                    if let Err(e) = SysUserRole::insert(am).exec(txn).await
                        && !is_unique_violation(&e)
                    {
                        return Err(db_err_500(e));
                    }
                }
            }
            MAPPING_DEPT => {
                let exists = SysUserDept::find()
                    .filter(UserDeptCol::UserId.eq(user_id))
                    .filter(UserDeptCol::DeptId.eq(b.target_id))
                    .one(txn)
                    .await
                    .map_err(db_err_500)?;
                if exists.is_none() {
                    let am = UserDeptAM {
                        id: sea_orm::NotSet,
                        user_id: Set(user_id),
                        dept_id: Set(b.target_id),
                        source: Set(src.clone()),
                        create_time: Set(Some(crate::common::datetime::now_naive())),
                    };
                    if let Err(e) = SysUserDept::insert(am).exec(txn).await
                        && !is_unique_violation(&e)
                    {
                        return Err(db_err_500(e));
                    }
                }
            }
            other => {
                return Err(ScimError::new(500, format!("未知 mappingType: {other}")));
            }
        }
    }
    Ok(())
}

/// 组成员 revoke（只撤本组 source 行；admin 手授与其它组来源不动）
async fn revoke_member<C: ConnectionTrait>(
    txn: &C,
    group_id: i64,
    user_id: i64,
) -> Result<(), ScimError> {
    let src = scim_source(group_id);
    SysUserRole::delete_many()
        .filter(UserRoleCol::UserId.eq(user_id))
        .filter(UserRoleCol::Source.eq(&src))
        .exec(txn)
        .await
        .map_err(db_err_500)?;
    SysUserDept::delete_many()
        .filter(UserDeptCol::UserId.eq(user_id))
        .filter(UserDeptCol::Source.eq(&src))
        .exec(txn)
        .await
        .map_err(db_err_500)?;
    Ok(())
}

/// 成员全量 diff（PUT / replace members 语义）：重放同一列表零副作用。
/// added → 成员记录 + grant；removed → 撤销（仅本组 source）+ 成员记录删除。
async fn diff_members<C: ConnectionTrait>(
    txn: &C,
    group_id: i64,
    mapping_type: &str,
    new_members: &[i64],
    now: chrono::NaiveDateTime,
) -> Result<(), ScimError> {
    let current = GroupMember::find()
        .filter(MemberCol::GroupId.eq(group_id))
        .all(txn)
        .await
        .map_err(db_err_500)?;
    let current_ids: Vec<i64> = current.iter().map(|m| m.user_id).collect();
    for uid in new_members {
        if !current_ids.contains(uid) {
            insert_member(txn, group_id, *uid, now).await?;
            grant_member(txn, group_id, mapping_type, *uid).await?;
        }
    }
    for uid in &current_ids {
        if !new_members.contains(uid) {
            delete_member(txn, group_id, *uid).await?;
            revoke_member(txn, group_id, *uid).await?;
        }
    }
    Ok(())
}

/// 绑定集合全量 diff（管理端改绑定）：对全组成员按新绑定集合联动。
/// added 目标 × 全成员 grant；removed 目标 × 全成员 revoke（仅本组 source 行）。
async fn apply_bindings_diff<C: ConnectionTrait>(
    txn: &C,
    group_id: i64,
    mapping_type: &str,
    new_targets: &[i64],
    _now: chrono::NaiveDateTime,
) -> Result<(), ScimError> {
    let current = GroupBinding::find()
        .filter(BindingCol::GroupId.eq(group_id))
        .all(txn)
        .await
        .map_err(db_err_500)?;
    let current_ids: Vec<i64> = current.iter().map(|b| b.target_id).collect();
    let members = GroupMember::find()
        .filter(MemberCol::GroupId.eq(group_id))
        .all(txn)
        .await
        .map_err(db_err_500)?;
    // 新增目标：插入绑定 + 全成员 grant
    for t in new_targets {
        if !current_ids.contains(t) {
            let am = BindingAM {
                id: sea_orm::NotSet,
                group_id: Set(group_id),
                target_id: Set(*t),
                create_time: Set(Some(crate::common::datetime::now_naive())),
            };
            if let Err(e) = GroupBinding::insert(am).exec(txn).await
                && !is_unique_violation(&e)
            {
                return Err(db_err_500(e));
            }
            for m in &members {
                grant_single(txn, group_id, mapping_type, m.user_id, *t).await?;
            }
        }
    }
    // 移除目标：全成员 revoke 该目标（仅本组 source）+ 删绑定
    for t in &current_ids {
        if !new_targets.contains(t) {
            let src = scim_source(group_id);
            match mapping_type {
                MAPPING_ROLE => {
                    SysUserRole::delete_many()
                        .filter(UserRoleCol::RoleId.eq(*t))
                        .filter(UserRoleCol::Source.eq(&src))
                        .exec(txn)
                        .await
                        .map_err(db_err_500)?;
                }
                MAPPING_DEPT => {
                    SysUserDept::delete_many()
                        .filter(UserDeptCol::DeptId.eq(*t))
                        .filter(UserDeptCol::Source.eq(&src))
                        .exec(txn)
                        .await
                        .map_err(db_err_500)?;
                }
                _ => {}
            }
            GroupBinding::delete_many()
                .filter(BindingCol::GroupId.eq(group_id))
                .filter(BindingCol::TargetId.eq(*t))
                .exec(txn)
                .await
                .map_err(db_err_500)?;
        }
    }
    Ok(())
}

/// 单目标 grant（绑定 diff 专用；与 grant_member 同语义但限定单 target）
async fn grant_single<C: ConnectionTrait>(
    txn: &C,
    group_id: i64,
    mapping_type: &str,
    user_id: i64,
    target_id: i64,
) -> Result<(), ScimError> {
    let src = scim_source(group_id);
    match mapping_type {
        MAPPING_ROLE => {
            let exists = SysUserRole::find()
                .filter(UserRoleCol::UserId.eq(user_id))
                .filter(UserRoleCol::RoleId.eq(target_id))
                .one(txn)
                .await
                .map_err(db_err_500)?;
            if exists.is_none() {
                let am = UserRoleAM {
                    user_id: Set(user_id),
                    role_id: Set(target_id),
                    source: Set(src),
                };
                if let Err(e) = SysUserRole::insert(am).exec(txn).await
                    && !is_unique_violation(&e)
                {
                    return Err(db_err_500(e));
                }
            }
        }
        MAPPING_DEPT => {
            let exists = SysUserDept::find()
                .filter(UserDeptCol::UserId.eq(user_id))
                .filter(UserDeptCol::DeptId.eq(target_id))
                .one(txn)
                .await
                .map_err(db_err_500)?;
            if exists.is_none() {
                let am = UserDeptAM {
                    id: sea_orm::NotSet,
                    user_id: Set(user_id),
                    dept_id: Set(target_id),
                    source: Set(src),
                    create_time: Set(Some(crate::common::datetime::now_naive())),
                };
                if let Err(e) = SysUserDept::insert(am).exec(txn).await
                    && !is_unique_violation(&e)
                {
                    return Err(db_err_500(e));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// 组删除 teardown：软删组 + 清成员/绑定 + 撤仅本组 source 的授权与兼职
async fn teardown_group(txn: &DatabaseTransaction, group_id: i64) -> Result<(), ScimError> {
    let now = crate::common::datetime::now_naive();
    let src = scim_source(group_id);
    // 撤销授权/兼职（仅本组来源）
    SysUserRole::delete_many()
        .filter(UserRoleCol::Source.eq(&src))
        .exec(txn)
        .await
        .map_err(db_err_500)?;
    SysUserDept::delete_many()
        .filter(UserDeptCol::Source.eq(&src))
        .exec(txn)
        .await
        .map_err(db_err_500)?;
    // 清成员/绑定
    GroupMember::delete_many()
        .filter(MemberCol::GroupId.eq(group_id))
        .exec(txn)
        .await
        .map_err(db_err_500)?;
    GroupBinding::delete_many()
        .filter(BindingCol::GroupId.eq(group_id))
        .exec(txn)
        .await
        .map_err(db_err_500)?;
    // 组软删（审计保留）
    if let Some(g) = ScimGroup::find_by_id(group_id)
        .one(txn)
        .await
        .map_err(db_err_500)?
    {
        let mut am: GroupAM = g.into();
        am.del_flag = Set(Some("2".to_string()));
        am.update_time = Set(Some(now));
        am.update(txn).await.map_err(db_err_500)?;
    }
    Ok(())
}
