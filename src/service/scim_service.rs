// axum-backend/src/service/scim_service.rs
//! v5-D12：SCIM 2.0 用户目录同步（RFC 7644 最小可用子集）。
//!
//! 面向外部 IdP（Okta / Microsoft Entra ID / Google Workspace）的 provisioning
//! 服务器对服务器调用，鉴权为独立 Bearer Token（`scim.bearer_token`，与用户
//! JWT 完全无关）。覆盖 IdP connector 的核心用法：
//! - `GET  /scim/v2/Users`                 分页 + `filter=userName eq "xxx"`
//! - `GET  /scim/v2/Users/{id}`            读取
//! - `POST /scim/v2/Users`                 provision 创建（随机不可知密码）
//! - `PUT  /scim/v2/Users/{id}`            全量更新（字段映射见 to_scim_user）
//! - `PATCH /scim/v2/Users/{id}`           局部更新（op=replace：active/emails/name）
//! - `DELETE /scim/v2/Users/{id}`          deprovision = **停用**（status='1'），
//!   不物理删——审计与外键引用保留，与 sys_user 软删规范一致。
//!
//! 字段映射：userName ↔ user_name（关联键，IdP 保证唯一）；displayName ↔
//! nick_name；emails[0].value ↔ email；active ↔ status('0'/'1')。
//! externalId 不落库：IdP 侧以 userName 关联（避免为单一集成加列）。

use crate::entity::sys_user;
use crate::repository::sys_user::SysUserRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    Set,
};

/// SCIM User 资源（响应体）
#[derive(Debug, serde::Serialize)]
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: String,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub name: ScimName,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,
    pub active: bool,
    pub meta: ScimMeta,
}

#[derive(Debug, serde::Serialize)]
pub struct ScimName {
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, serde::Serialize)]
pub struct ScimEmail {
    pub value: String,
    pub primary: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct ScimMeta {
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    pub location: String,
}

/// SCIM ListResponse 信封（RFC 7644 §3.4.2）
#[derive(Debug, serde::Serialize)]
pub struct ScimListResponse {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: u64,
    #[serde(rename = "startIndex")]
    pub start_index: u64,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: u64,
    #[serde(rename = "Resources")]
    pub resources: Vec<ScimUser>,
}

/// SCIM 错误体（RFC 7644 §3.12）
#[derive(Debug, serde::Serialize)]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub status: String,
    pub detail: String,
}

impl ScimError {
    pub fn new(status: u16, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
            status: status.to_string(),
            detail: detail.into(),
        }
    }
}

const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

pub struct ScimService {
    user_repo: SysUserRepository,
}

impl ScimService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            user_repo: SysUserRepository::new(db),
        }
    }

    fn db(&self) -> &DatabaseConnection {
        self.user_repo.base().db()
    }

    /// Model → SCIM User（location 由调用方传入 base_url）
    fn to_scim_user(&self, m: &sys_user::Model, base_url: &str) -> ScimUser {
        let mut emails = Vec::new();
        // let-chains 合并（clippy collapsible_if；项目已在用 let-chains 语法）
        if let Some(v) = &m.email
            && !v.is_empty()
        {
            emails.push(ScimEmail {
                value: v.clone(),
                primary: true,
            });
        }
        ScimUser {
            schemas: vec![SCIM_USER_SCHEMA.to_string()],
            id: m.user_id.to_string(),
            external_id: None,
            user_name: m.user_name.clone(),
            name: ScimName {
                display_name: m.nick_name.clone(),
            },
            emails,
            active: m.status.as_deref() == Some("0"),
            meta: ScimMeta {
                resource_type: "User".to_string(),
                location: format!("{base_url}/scim/v2/Users/{}", m.user_id),
            },
        }
    }

    /// GET /Users：分页 + `filter=userName eq "xxx"`（最小 filter 实现，
    /// 覆盖 Okta/Entra connector 精确查找用法；其它属性 filter 返回 invalidFilter）
    pub async fn list_users(
        &self,
        start_index: u64,
        count: u64,
        filter: Option<&str>,
        base_url: &str,
    ) -> Result<ScimListResponse, ScimError> {
        use sea_orm::Statement;
        let backend = self.db().get_database_backend();
        let start = start_index.max(1);
        let count = count.clamp(1, 200);
        let mut where_clause = String::from("del_flag <> '2'");
        if let Some(f) = filter {
            let f = f.trim();
            let cap = f.split_whitespace().map(str::to_string).collect::<Vec<_>>();
            // 仅支持：userName eq "<value>"（值允许单/双引号包裹）
            if cap.len() == 3
                && cap[0].eq_ignore_ascii_case("userName")
                && cap[1].eq_ignore_ascii_case("eq")
            {
                let val = cap[2].trim_matches('\'').trim_matches('"');
                let val_esc = val.replace('\'', "''");
                where_clause.push_str(&format!(" AND user_name = '{val_esc}'"));
            } else {
                return Err(ScimError::new(
                    400,
                    "unsupported filter（仅支持 userName eq \"<value>\"）",
                ));
            }
        }
        // 计数 + 分页（两方言参数化差异大，此处值均已转义/白名单，拼接安全）
        let count_sql = format!("SELECT COUNT(*) AS c FROM sys_user WHERE {where_clause}");
        let total = self
            .db()
            .query_one(Statement::from_string(backend, count_sql))
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?
            .and_then(|r| r.try_get::<i64>("", "c").ok())
            .unwrap_or(0) as u64;
        let list_sql = format!(
            "SELECT user_id FROM sys_user WHERE {where_clause} ORDER BY user_id LIMIT {count} OFFSET {}",
            start - 1
        );
        let rows = self
            .db()
            .query_all(Statement::from_string(backend, list_sql))
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?;
        let mut resources = Vec::with_capacity(rows.len());
        for row in rows {
            let uid = row.try_get::<i64>("", "user_id").unwrap_or(0);
            if let Ok(Some(m)) = sys_user::Entity::find_by_id(uid).one(self.db()).await {
                resources.push(self.to_scim_user(&m, base_url));
            }
        }
        Ok(ScimListResponse {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
            total_results: total,
            start_index: start,
            items_per_page: resources.len() as u64,
            resources,
        })
    }

    /// GET /Users/{id}
    pub async fn get_user(&self, id: i64, base_url: &str) -> Result<ScimUser, ScimError> {
        let m = sys_user::Entity::find_by_id(id)
            .one(self.db())
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?
            .filter(|u| u.del_flag.as_deref() != Some("2"))
            .ok_or_else(|| ScimError::new(404, "User not found"))?;
        Ok(self.to_scim_user(&m, base_url))
    }

    /// POST /Users：provision 创建。密码为随机不可知值（IdP 管理凭据，
    /// 本地登录走找回流程）；userName 冲突 → 409 conflict。
    pub async fn create_user(
        &self,
        body: &serde_json::Value,
        base_url: &str,
    ) -> Result<ScimUser, ScimError> {
        let user_name = body
            .get("userName")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ScimError::new(400, "userName is required"))?
            .to_string();
        if user_name.len() < 2 || user_name.len() > 30 {
            return Err(ScimError::new(400, "userName 长度须在 2-30 之间"));
        }
        // 唯一性（含软删占用，client_id 同款语义 v2-K4）
        if sys_user::Entity::find()
            .filter(sys_user::Column::UserName.eq(&user_name))
            .one(self.db())
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?
            .is_some()
        {
            return Err(ScimError::new(409, "userName 已存在"));
        }
        let display = body
            .pointer("/name/displayName")
            .and_then(|v| v.as_str())
            .unwrap_or(&user_name)
            .to_string();
        let email = body
            .pointer("/emails/0/value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let active = body.get("active").and_then(|v| v.as_bool()).unwrap_or(true);
        // 随机 32B 密码（base64url）——不可知，IdP provisioning 场景本地登录走找回
        let random_pwd = crate::service::sso_service::random_urlsafe_pub(24);
        let hashed = crate::utils::password::encrypt_password(&random_pwd)
            .map_err(|e| ScimError::new(500, format!("密码哈希失败: {e}")))?;
        let now = crate::common::datetime::now_naive();
        let am = sys_user::ActiveModel {
            user_name: Set(user_name.clone()),
            nick_name: Set(display),
            email: Set(if email.is_empty() { None } else { Some(email) }),
            password: Set(Some(hashed)),
            status: Set(Some(if active { "0" } else { "1" }.to_string())),
            del_flag: Set(Some("0".to_string())),
            user_type: Set(Some("00".to_string())),
            country_code: Set(Some("CN".to_string())),
            create_by: Set(Some("scim".to_string())),
            update_by: Set(Some("scim".to_string())),
            create_time: Set(Some(now)),
            update_time: Set(Some(now)),
            ..Default::default()
        };
        let saved = am.insert(self.db()).await.map_err(|e| match e {
            sea_orm::DbErr::RecordNotInserted => ScimError::new(409, "userName 已存在"),
            other => ScimError::new(500, format!("数据库错误: {other}")),
        })?;
        Ok(self.to_scim_user(&saved, base_url))
    }

    /// PUT /Users/{id}：全量更新（userName 不可变；未提供的可选字段置空）
    pub async fn put_user(
        &self,
        id: i64,
        body: &serde_json::Value,
        base_url: &str,
    ) -> Result<ScimUser, ScimError> {
        let m = self.find_active(id).await?;
        if let Some(un) = body.get("userName").and_then(|v| v.as_str())
            && un.trim() != m.user_name
        {
            return Err(ScimError::new(400, "userName 不可变更"));
        }
        let mut am: sys_user::ActiveModel = m.into();
        am.nick_name = Set(body
            .pointer("/name/displayName")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string());
        let email = body.pointer("/emails/0/value").and_then(|v| v.as_str());
        am.email = Set(email.map(str::to_string).filter(|s| !s.is_empty()));
        am.status = Set(Some(
            if body.get("active").and_then(|v| v.as_bool()).unwrap_or(true) {
                "0"
            } else {
                "1"
            }
            .to_string(),
        ));
        am.update_time = Set(Some(crate::common::datetime::now_naive()));
        am.update_by = Set(Some("scim".to_string()));
        let saved = am
            .update(self.db())
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?;
        Ok(self.to_scim_user(&saved, base_url))
    }

    /// PATCH /Users/{id}：局部更新（RFC 7644 §3.5.2）——仅支持 op=replace，
    /// path ∈ {active, name.displayName, emails} 或 value 内含对应字段。
    pub async fn patch_user(
        &self,
        id: i64,
        body: &serde_json::Value,
        base_url: &str,
    ) -> Result<ScimUser, ScimError> {
        let m = self.find_active(id).await?;
        let mut am: sys_user::ActiveModel = m.into();
        let ops = body
            .get("Operations")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ScimError::new(400, "Operations is required"))?;
        for op in ops {
            let op_name = op.get("op").and_then(|v| v.as_str()).unwrap_or_default();
            if !op_name.eq_ignore_ascii_case("replace") {
                return Err(ScimError::new(
                    400,
                    "仅支持 op=replace（add/remove 不适用本映射）",
                ));
            }
            let value = op.get("value").cloned().unwrap_or(serde_json::Value::Null);
            let path = op.get("path").and_then(|v| v.as_str()).unwrap_or_default();
            match path {
                "active" => {
                    let act = value
                        .as_bool()
                        .ok_or_else(|| ScimError::new(400, "active 值必须为布尔"))?;
                    am.status = Set(Some(if act { "0" } else { "1" }.to_string()));
                }
                "name.displayName" => {
                    am.nick_name = Set(value.as_str().unwrap_or_default().to_string());
                }
                "emails" => {
                    let ev = value
                        .pointer("/0/value")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    am.email = Set(if ev.is_empty() { None } else { Some(ev) });
                }
                "" => {
                    // 无 path 的 replace：value 是含字段的对象
                    if let Some(act) = value.get("active").and_then(|v| v.as_bool()) {
                        am.status = Set(Some(if act { "0" } else { "1" }.to_string()));
                    }
                    if let Some(dn) = value.pointer("/name/displayName").and_then(|v| v.as_str()) {
                        am.nick_name = Set(dn.to_string());
                    }
                    if let Some(ev) = value.pointer("/emails/0/value").and_then(|v| v.as_str()) {
                        am.email = Set(if ev.is_empty() {
                            None
                        } else {
                            Some(ev.to_string())
                        });
                    }
                }
                other => {
                    return Err(ScimError::new(400, format!("不支持的 path: {other}")));
                }
            }
        }
        am.update_time = Set(Some(crate::common::datetime::now_naive()));
        am.update_by = Set(Some("scim".to_string()));
        let saved = am
            .update(self.db())
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?;
        Ok(self.to_scim_user(&saved, base_url))
    }

    /// DELETE /Users/{id}：deprovision = 停用（status='1'），不物理删（审计保留）。
    /// RFC 7644 要求 204 No Content。
    pub async fn delete_user(&self, id: i64) -> Result<(), ScimError> {
        let m = self.find_active(id).await?;
        let mut am: sys_user::ActiveModel = m.into();
        am.status = Set(Some("1".to_string()));
        am.update_time = Set(Some(crate::common::datetime::now_naive()));
        am.update_by = Set(Some("scim".to_string()));
        am.update(self.db())
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?;
        Ok(())
    }

    async fn find_active(&self, id: i64) -> Result<sys_user::Model, ScimError> {
        sys_user::Entity::find_by_id(id)
            .one(self.db())
            .await
            .map_err(|e| ScimError::new(500, format!("数据库错误: {e}")))?
            .filter(|u| u.del_flag.as_deref() != Some("2"))
            .ok_or_else(|| ScimError::new(404, "User not found"))
    }
}
