//! 全局搜索服务（跨白名单实体的 LIKE 检索）
//!
//! 设计要点：
//! - 白名单实体（列名取自 src/entity 真实定义，非臆测）：
//!   user(sys_user: user_name,nick_name) / dept(sys_dept: dept_name) /
//!   tenant(sys_tenant: tenant_name) / role(sys_role: role_name) /
//!   menu(sys_menu: menu_name) / job(sys_job: job_name) /
//!   config(sys_config: config_key,config_name) / notice(sys_notice: notice_title) /
//!   task(sys_task: task_name) / template(sys_msg_template: template_name)
//! - 租户隔离：所有含 tenant_id 列的实体按 `tenant_scope` 注入条件
//!   （None = 平台操作者不过滤，Some(tid) = 仅本租户），与 dashboard_stats 口径一致；
//!   sys_menu 为全局菜单无租户列，不做过滤。
//! - 逻辑删除过滤：实体带 del_flag 列的统一排除 '2'（已删除）。
//! - 性能安全：每域 cap 硬顶（sea-orm limit），q 中通配符（% _）剥离防 LIKE 注入放大扫描。
//! - 排序：前缀命中优先（Rust 侧排序），域内次序按各实体主键/创建序稳定输出。

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Serialize;
use utoipa::ToSchema;

use crate::entity::{
    sys_config, sys_dept, sys_job, sys_menu, sys_msg_template, sys_notice, sys_role, sys_task,
    sys_tenant, sys_user,
};

/// 每个搜索域的最大返回条数（硬顶，防单域刷屏）
pub const PER_DOMAIN_CAP: u64 = 5;

/// 全局搜索单条结果项（对齐前端契约：type/id/title/subtitle/url）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct GlobalSearchItem {
    /// 搜索域类型（user/dept/tenant/role/menu/job/config/notice/task/template）
    #[serde(rename = "type")]
    pub item_type: String,
    /// 记录主键
    pub id: i64,
    /// 主标题（用于展示的名称）
    pub title: String,
    /// 副标题（补充信息，可为空串）
    pub subtitle: String,
    /// 前端路由路径（真实有效，供跳转）
    pub url: String,
}

/// 搜索域枚举（handler 按操作者权限逐域启用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchDomain {
    User,
    Dept,
    Tenant,
    Role,
    Menu,
    Job,
    Config,
    Notice,
    Task,
    Template,
}

/// 清洗搜索词：剥离 LIKE 通配符（% _）与首尾空白，防止通配符放大全表扫描
fn sanitize_q(q: &str) -> String {
    q.trim().replace(['%', '_'], "").trim().to_string()
}

/// 域内排序：前缀命中（大小写不敏感）优先，其余保持原序
fn sort_prefix_first(items: &mut [GlobalSearchItem], q: &str) {
    let ql = q.to_lowercase();
    items.sort_by_key(|i| !i.title.to_lowercase().starts_with(&ql));
}

/// 执行全局搜索
///
/// `domains`：本次允许检索的域（由 handler 按操作者权限计算）；
/// `tenant_scope`：租户过滤（None = 平台操作者）；
/// `q`：已通过最短长度校验的原始搜索词（本函数负责通配符清洗）。
pub async fn global_search(
    db: &sea_orm::DatabaseConnection,
    domains: &[SearchDomain],
    tenant_scope: Option<i64>,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    let q = sanitize_q(q);
    let mut out: Vec<GlobalSearchItem> = Vec::new();
    for &domain in domains {
        let mut items = match domain {
            SearchDomain::User => search_user(db, tenant_scope, &q).await?,
            SearchDomain::Dept => search_dept(db, tenant_scope, &q).await?,
            SearchDomain::Tenant => search_tenant(db, tenant_scope, &q).await?,
            SearchDomain::Role => search_role(db, tenant_scope, &q).await?,
            SearchDomain::Menu => search_menu(db, &q).await?,
            SearchDomain::Job => search_job(db, tenant_scope, &q).await?,
            SearchDomain::Config => search_config(db, tenant_scope, &q).await?,
            SearchDomain::Notice => search_notice(db, tenant_scope, &q).await?,
            SearchDomain::Task => search_task(db, tenant_scope, &q).await?,
            SearchDomain::Template => search_template(db, tenant_scope, &q).await?,
        };
        sort_prefix_first(&mut items, &q);
        out.extend(items);
    }
    Ok(out)
}

/// 用户域：sys_user（user_name / nick_name）
async fn search_user(
    db: &sea_orm::DatabaseConnection,
    tenant_scope: Option<i64>,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    use sys_user::Column as Col;
    let mut query = sys_user::Entity::find()
        .filter(Col::DelFlag.ne("2"))
        .filter(
            sea_orm::Condition::any()
                .add(Col::UserName.contains(q))
                .add(Col::NickName.contains(q)),
        );
    if let Some(tid) = tenant_scope {
        query = query.filter(Col::TenantId.eq(tid));
    }
    let rows = query
        .order_by_asc(Col::UserId)
        .limit(PER_DOMAIN_CAP)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|m| GlobalSearchItem {
            item_type: "user".to_string(),
            id: m.user_id,
            title: m.user_name,
            subtitle: m.nick_name,
            url: "/system/user".to_string(),
        })
        .collect())
}

/// 部门域：sys_dept（dept_name）
async fn search_dept(
    db: &sea_orm::DatabaseConnection,
    tenant_scope: Option<i64>,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    use sys_dept::Column as Col;
    let mut query = sys_dept::Entity::find()
        .filter(Col::DelFlag.ne("2"))
        .filter(Col::DeptName.contains(q));
    if let Some(tid) = tenant_scope {
        query = query.filter(Col::TenantId.eq(tid));
    }
    let rows = query
        .order_by_asc(Col::DeptId)
        .limit(PER_DOMAIN_CAP)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|m| GlobalSearchItem {
            item_type: "dept".to_string(),
            id: m.dept_id,
            title: m.dept_name,
            subtitle: m.leader.unwrap_or_default(),
            url: "/system/dept".to_string(),
        })
        .collect())
}

/// 租户域：sys_tenant（tenant_name）
async fn search_tenant(
    db: &sea_orm::DatabaseConnection,
    tenant_scope: Option<i64>,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    use sys_tenant::Column as Col;
    let mut query = sys_tenant::Entity::find()
        .filter(Col::DelFlag.ne("2"))
        .filter(Col::TenantName.contains(q));
    if let Some(tid) = tenant_scope {
        query = query.filter(Col::TenantId.eq(tid));
    }
    let rows = query
        .order_by_asc(Col::TenantId)
        .limit(PER_DOMAIN_CAP)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|m| GlobalSearchItem {
            item_type: "tenant".to_string(),
            id: m.tenant_id,
            title: m.tenant_name,
            subtitle: m.tenant_code,
            url: "/system/tenant".to_string(),
        })
        .collect())
}

/// 角色域：sys_role（role_name）
async fn search_role(
    db: &sea_orm::DatabaseConnection,
    tenant_scope: Option<i64>,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    use sys_role::Column as Col;
    let mut query = sys_role::Entity::find()
        .filter(Col::DelFlag.ne("2"))
        .filter(Col::RoleName.contains(q));
    if let Some(tid) = tenant_scope {
        query = query.filter(Col::TenantId.eq(tid));
    }
    let rows = query
        .order_by_asc(Col::RoleId)
        .limit(PER_DOMAIN_CAP)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|m| GlobalSearchItem {
            item_type: "role".to_string(),
            id: m.role_id,
            title: m.role_name,
            subtitle: m.role_key,
            url: "/system/role".to_string(),
        })
        .collect())
}

/// 菜单域：sys_menu（menu_name）
///
/// sys_menu 为全局菜单表，无 tenant_id 列，不做租户过滤。
async fn search_menu(
    db: &sea_orm::DatabaseConnection,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    use sys_menu::Column as Col;
    let rows = sys_menu::Entity::find()
        .filter(Col::DelFlag.ne("2"))
        .filter(Col::MenuName.contains(q))
        .order_by_asc(Col::MenuId)
        .limit(PER_DOMAIN_CAP)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|m| GlobalSearchItem {
            item_type: "menu".to_string(),
            id: m.menu_id,
            title: m.menu_name,
            subtitle: m.path.unwrap_or_default(),
            url: "/system/menu".to_string(),
        })
        .collect())
}

/// 定时任务域：sys_job（job_name）
async fn search_job(
    db: &sea_orm::DatabaseConnection,
    tenant_scope: Option<i64>,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    use sys_job::Column as Col;
    let mut query = sys_job::Entity::find()
        .filter(Col::DelFlag.ne("2"))
        .filter(Col::JobName.contains(q));
    if let Some(tid) = tenant_scope {
        query = query.filter(Col::TenantId.eq(tid));
    }
    let rows = query
        .order_by_asc(Col::JobId)
        .limit(PER_DOMAIN_CAP)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|m| GlobalSearchItem {
            item_type: "job".to_string(),
            id: m.job_id,
            title: m.job_name,
            subtitle: m.job_group,
            url: "/monitor/job".to_string(),
        })
        .collect())
}

/// 参数配置域：sys_config（config_key / config_name）
///
/// sys_config 无 del_flag 列，仅做租户过滤。
async fn search_config(
    db: &sea_orm::DatabaseConnection,
    tenant_scope: Option<i64>,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    use sys_config::Column as Col;
    let mut query = sys_config::Entity::find().filter(
        sea_orm::Condition::any()
            .add(Col::ConfigKey.contains(q))
            .add(Col::ConfigName.contains(q)),
    );
    if let Some(tid) = tenant_scope {
        query = query.filter(Col::TenantId.eq(tid));
    }
    let rows = query
        .order_by_asc(Col::ConfigId)
        .limit(PER_DOMAIN_CAP)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|m| GlobalSearchItem {
            item_type: "config".to_string(),
            id: m.config_id,
            title: m.config_key,
            subtitle: m.config_name.unwrap_or_default(),
            url: "/system/config".to_string(),
        })
        .collect())
}

/// 通知公告域：sys_notice（notice_title）
///
/// sys_notice 无 del_flag 列，仅做租户过滤。
async fn search_notice(
    db: &sea_orm::DatabaseConnection,
    tenant_scope: Option<i64>,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    use sys_notice::Column as Col;
    let mut query = sys_notice::Entity::find().filter(Col::NoticeTitle.contains(q));
    if let Some(tid) = tenant_scope {
        query = query.filter(Col::TenantId.eq(tid));
    }
    let rows = query
        .order_by_asc(Col::NoticeId)
        .limit(PER_DOMAIN_CAP)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|m| GlobalSearchItem {
            item_type: "notice".to_string(),
            id: m.notice_id,
            title: m.notice_title,
            subtitle: m.notice_type,
            url: "/system/notice".to_string(),
        })
        .collect())
}

/// 任务域：sys_task（task_name）
///
/// sys_task 无 del_flag 列，仅做租户过滤。
async fn search_task(
    db: &sea_orm::DatabaseConnection,
    tenant_scope: Option<i64>,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    use sys_task::Column as Col;
    let mut query = sys_task::Entity::find().filter(Col::TaskName.contains(q));
    if let Some(tid) = tenant_scope {
        query = query.filter(Col::TenantId.eq(tid));
    }
    let rows = query
        .order_by_asc(Col::TaskId)
        .limit(PER_DOMAIN_CAP)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|m| GlobalSearchItem {
            item_type: "task".to_string(),
            id: m.task_id,
            title: m.task_name,
            subtitle: m.task_type,
            url: "/system/task".to_string(),
        })
        .collect())
}

/// 消息模板域：sys_msg_template（template_name）
async fn search_template(
    db: &sea_orm::DatabaseConnection,
    tenant_scope: Option<i64>,
    q: &str,
) -> Result<Vec<GlobalSearchItem>, sea_orm::DbErr> {
    use sys_msg_template::Column as Col;
    let mut query = sys_msg_template::Entity::find()
        .filter(Col::DelFlag.ne("2"))
        .filter(Col::TemplateName.contains(q));
    if let Some(tid) = tenant_scope {
        query = query.filter(Col::TenantId.eq(tid));
    }
    let rows = query
        .order_by_asc(Col::TemplateId)
        .limit(PER_DOMAIN_CAP)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|m| GlobalSearchItem {
            item_type: "template".to_string(),
            id: m.template_id,
            title: m.template_name,
            subtitle: m.template_code,
            url: "/system/msg/template".to_string(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(title: &str) -> GlobalSearchItem {
        GlobalSearchItem {
            item_type: "user".to_string(),
            id: 1,
            title: title.to_string(),
            subtitle: String::new(),
            url: "/x".to_string(),
        }
    }

    /// LIKE 通配符剥离（防"一个 `%` 打穿全表扫描"）+ 首尾空白归一。
    #[test]
    fn sanitize_q_strips_like_wildcards_and_whitespace() {
        assert_eq!(sanitize_q("  zhang san "), "zhang san");
        assert_eq!(sanitize_q("%"), "");
        assert_eq!(sanitize_q("%%%"), "");
        assert_eq!(sanitize_q("_"), "");
        // 通配符在中间也被剥离（否则 `a%b` 会命中 aXb 这类非预期行）
        assert_eq!(sanitize_q("a%b_c"), "abc");
        // 内部空白保留（搜索词本身可以含空格）
        assert_eq!(sanitize_q("zhang  san"), "zhang  san");
        assert_eq!(sanitize_q(""), "");
    }

    /// 前缀命中优先，且大小写不敏感；非前缀项保持原有相对次序。
    #[test]
    fn sort_prefix_first_puts_exact_prefix_hits_first_case_insensitively() {
        let mut items = vec![item("张三研发"), item("abc"), item("ABCd"), item("zzz")];
        sort_prefix_first(&mut items, "abc");
        assert_eq!(
            items.iter().map(|i| i.title.as_str()).collect::<Vec<_>>(),
            vec!["abc", "ABCd", "张三研发", "zzz"],
            "前缀命中（含大小写变体）应前置，其余保持原序"
        );
    }

    /// 空结果与全不命中都必须稳定（排序是稳定语义的一部分，不能重排乱序）。
    #[test]
    fn sort_prefix_first_is_stable_when_nothing_matches() {
        let mut items = vec![item("x1"), item("x2"), item("x3")];
        sort_prefix_first(&mut items, "nomatch");
        assert_eq!(
            items.iter().map(|i| i.title.as_str()).collect::<Vec<_>>(),
            vec!["x1", "x2", "x3"]
        );
        let mut empty: Vec<GlobalSearchItem> = Vec::new();
        sort_prefix_first(&mut empty, "abc");
        assert!(empty.is_empty());
    }
}
