//! 用户模块 Service 层
//!
//! 职责：
//! - 用户 CRUD、密码加密校验、用户角色分配、状态启停
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 多表操作使用 SeaORM 事务保证一致性
//! - 参数校验使用 garde crate（经 common::i18n::validate 统一入口）
//! - 数据访问通过 Repository 层委托

use chrono::NaiveDateTime;
use futures::future::FutureExt;
use redis::aio::ConnectionManager;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set, TransactionTrait};
use serde::Deserialize;
use std::sync::LazyLock;
use regex::Regex;
use ts_rs::TS;
use utoipa::{IntoParams, ToSchema};
use garde::Validate;

use crate::common::constants::SUPER_ADMIN_USER_ID;
use crate::common::error::ServiceError;
use crate::common::page::{default_page_num, default_page_size, PageDomain};
use crate::common::TreeSelectVo;
use crate::entity::sys_dept::Model as SysDeptModel;
use crate::entity::sys_post::Model as SysPostModel;
use crate::entity::sys_role::Model as SysRoleModel;
use crate::entity::sys_user::{
    ActiveModel as SysUserActiveModel, Model as SysUserModel,
};
use crate::entity::sys_user_role::ActiveModel as SysUserRoleActiveModel;
use crate::entity::sys_user_post::ActiveModel as SysUserPostActiveModel;
use crate::entity::sys_notice_read::{Column as NoticeReadColumn, Entity as SysNoticeRead};
use crate::repository::sys_dept::SysDeptRepository;
use crate::repository::sys_post::SysPostRepository;
use crate::repository::sys_role::SysRoleRepository;
use crate::repository::sys_role_dept::SysRoleDeptRepository;
use crate::repository::sys_user::SysUserRepository;
use crate::repository::sys_user_post::SysUserPostRepository;
use crate::repository::sys_user_role::SysUserRoleRepository;
use crate::utils::password::{
    encrypt_password, validate_password_complexity, verify_password_with_upgrade_hint,
};

// 部门树组装函数抽取至 service/mod.rs，避免与 sys_role_service 重复
use super::build_dept_tree_select;


// ==================== DTO 定义 ====================

/// 新增用户 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserAddDto {
    #[garde(skip)]
    pub dept_id: Option<i64>,
    #[garde(length(min = 2, max = 30))]
    pub user_name: String,
    #[garde(length(min = 2, max = 30))]
    pub nick_name: String,
    #[garde(email)]
    pub email: Option<String>,
    // 手机号校验改为按地区（方案 D，G18）：移除固定中国号段正则，改由 validate_phone_by_region 统一校验
    #[garde(skip)]
    pub phonenumber: Option<String>,
    /// 手机号国家/地区代码（ISO 3166-1 alpha-2，如 CN/HK/US）。None 回退 CN。
    #[garde(skip)]
    pub country_code: Option<String>,
    #[garde(skip)]
    pub sex: Option<String>,
    #[garde(length(min = 5, max = 20))]
    pub password: String,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(skip)]
    pub role_ids: Option<Vec<i64>>,
    /// 岗位 ID 列表（None 不绑定，Some(vec![]) 清空）
    #[garde(skip)]
    pub post_ids: Option<Vec<i64>>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 修改用户 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserEditDto {
    #[garde(skip)]
    pub user_id: i64,
    #[garde(skip)]
    pub dept_id: Option<i64>,
    #[garde(length(min = 2, max = 30))]
    pub nick_name: Option<String>,
    #[garde(email)]
    pub email: Option<String>,
    #[garde(skip)]
    pub phonenumber: Option<String>,
    /// 手机号国家/地区代码（ISO 3166-1 alpha-2，如 CN/HK/US）。None 回退 CN。
    #[garde(skip)]
    pub country_code: Option<String>,
    #[garde(skip)]
    pub sex: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    /// None 不修改角色绑定，Some(vec![]) 清空角色绑定
    #[garde(skip)]
    pub role_ids: Option<Vec<i64>>,
    /// None 不修改岗位绑定，Some(vec![]) 清空岗位绑定
    #[garde(skip)]
    pub post_ids: Option<Vec<i64>>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 管理员重置密码 DTO
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UserPwdResetDto {
    #[garde(skip)]
    pub user_id: i64,
    #[garde(length(min = 5, max = 20))]
    pub password: String,
}

/// 个人中心改密 DTO
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UserPwdUpdateDto {
    #[garde(length(min = 5, max = 20))]
    pub old_password: String,
    #[garde(length(min = 5, max = 20))]
    pub new_password: String,
}

/// 个人信息修改 DTO（对齐前端 PUT /system/user/profile）
///
/// 前端 userInfo.vue 提交 { nickName, phonenumber, email, sex }，
/// 所有字段可选，仅更新提供的字段。
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct ProfileUpdateDto {
    #[garde(length(min = 2, max = 30))]
    pub nick_name: Option<String>,
    #[garde(email)]
    pub email: Option<String>,
    // 手机号校验改为按地区（方案 D，G18）
    #[garde(skip)]
    pub phonenumber: Option<String>,
    /// 手机号国家/地区代码（ISO 3166-1 alpha-2，如 CN/HK/US）。None 回退 CN。
    #[garde(skip)]
    pub country_code: Option<String>,
    #[garde(skip)]
    pub sex: Option<String>,
}

/// 常见国家/地区手机号正则分流表（方案 D 回退用，覆盖 phonenumber crate 解析失败或地区未识别的场景）
///
/// 仅作为 phonenumber crate 的兜底，保证真实可用：
/// - CN：中国大陆 1[3-9] 开头 11 位
/// - HK：中国香港 5-9 开头 8 位
/// - US：美国/加拿大 10 位数字
/// - MO：中国澳门 6 开头 8 位
/// - TW：中国台湾 09 开头 10 位
/// - GB：英国 1-9 开头 10 位（不含国际前缀）
/// - JP：日本 070/080/090 开头 11 位
static REGION_PHONE_PATTERNS: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    vec![
        ("CN", r"^1[3-9]\d{9}$"),
        ("HK", r"^([5-9]\d{7})$"),
        ("US", r"^\d{10}$"),
        ("MO", r"^6\d{7}$"),
        ("TW", r"^09\d{8}$"),
        ("GB", r"^[1-9]\d{9}$"),
        ("JP", r"^0[789]0\d{8}$"),
    ]
});

/// 按国家/地区校验手机号（方案 D，G18：多地区化）
///
/// - `phone` 为 None 时不校验（允许留空）
/// - `country` 为 None 时回退 CN
///
/// 优先使用 `phonenumber` crate（google-libphonenumber Rust 移植），
/// 当 crate 解析失败或地区未识别时，回退到上方正则分流表，保证真实可用。
pub fn validate_phone_by_region(
    phone: &Option<String>,
    country: &Option<String>,
) -> Result<(), ServiceError> {
    let Some(phone) = phone else { return Ok(()); };
    let country = country.as_deref().unwrap_or("CN").to_uppercase();
    if !is_valid_phone(phone, &country) {
        return Err(ServiceError::bad_request(&crate::tr!(
            "error.user.phone_invalid"
        )));
    }
    Ok(())
}

/// 单个手机号是否对给定地区合法（phonenumber crate 优先，正则表兜底）
fn is_valid_phone(phone: &str, country: &str) -> bool {
    // 1) 优先 phonenumber crate（google-libphonenumber）
    if let Ok(region) = country.parse::<phonenumber::country::Id>()
        && let Ok(num) = phonenumber::parse(Some(region), phone)
    {
        return num.is_valid();
    }
    // 2) 回退正则分流表（覆盖常见地区，crate 解析失败或地区未识别时仍可用）
    for (cc, pat) in REGION_PHONE_PATTERNS.iter() {
        if *cc == country && let Ok(re) = Regex::new(pat) {
            return re.is_match(phone);
        }
    }
    false
}

/// 用户分页查询 DTO
#[derive(Debug, Clone, Deserialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct UserQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub dept_id: Option<i64>,
    pub user_name: Option<String>,
    pub phonenumber: Option<String>,
    pub status: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&UserQueryDto> for PageDomain {
    fn from(dto: &UserQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 用户视图对象（含角色 ID 列表 + 部门信息）
#[derive(Debug, Clone, serde::Serialize, TS, ToSchema)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename_all = "camelCase")]
pub struct UserVo {
    #[serde(flatten)]
    #[ts(flatten)]
    pub user: SysUserModel,
    pub role_ids: Vec<i64>,
    /// 部门信息（对齐前端 prop="dept.deptName"）
    pub dept: Option<SysDeptModel>,
}

/// 用户授权角色视图对象（对齐前端 UserAuthRoleResult）
#[derive(Debug, Clone, serde::Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename_all = "camelCase")]
pub struct UserAuthRoleVo {
    pub user: SysUserModel,
    pub roles: Vec<SysRoleModel>,
}

/// 个人信息视图对象（对齐前端 GET /system/user/profile 响应）
///
/// - roleGroup: 用户所属角色名称列表，逗号拼接（如 "管理员,普通用户"）
/// - postGroup: 用户所属岗位名称列表，逗号拼接
/// - user: 用户信息
#[derive(Debug, Clone, serde::Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename_all = "camelCase")]
pub struct ProfileVo {
    pub role_group: String,
    pub post_group: String,
    pub user: SysUserModel,
}

/// 用户表单数据视图对象（对齐前端 UserFormDataResult）
///
/// 字段挂在响应根对象上（非 data 内）：
/// - data: 用户信息（新增时为 None）
/// - post_ids: 用户已绑定的岗位 ID 列表（新增时为空）
/// - role_ids: 用户已绑定的角色 ID 列表（新增时为空）
/// - roles: 全部可用角色列表（下拉选择用）
/// - posts: 全部可用岗位列表（下拉选择用）
#[derive(Debug, Clone, serde::Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename_all = "camelCase")]
pub struct UserFormVo {
    #[ts(optional)]
    pub data: Option<SysUserModel>,
    pub post_ids: Vec<i64>,
    pub role_ids: Vec<i64>,
    pub roles: Vec<SysRoleModel>,
    pub posts: Vec<SysPostModel>,
}

// ==================== 辅助函数 ====================

/// 解析时间字符串（%Y-%m-%d 格式），失败返回 ServiceError
fn parse_time(s: &str) -> Result<NaiveDateTime, ServiceError> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| ServiceError::bad_request(&crate::tr!("error.common.time_format_invalid", s = s)))
}

// ==================== Service 实现 ====================

/// 权限缓存 key 前缀（与 sys_menu_service 保持一致）
const PERM_CACHE_PREFIX: &str = "perm:user:";

/// 用户模块 Service
///
/// 数据访问通过 Repository 层委托：
/// - user_repo: sys_user 表 CRUD
/// - user_role_repo: sys_user_role 关联表 CRUD
/// - user_post_repo: sys_user_post 关联表 CRUD
/// - dept_repo: sys_dept 表查询（部门树）
/// - post_repo: sys_post 表查询（岗位下拉）
/// - role_repo: sys_role 表查询（角色下拉）
/// - redis: Redis 连接管理器，用于权限缓存失效
/// - 事务通过 user_repo.base().db() 获取连接
#[derive(Clone)]
pub struct SysUserService {
    user_repo: SysUserRepository,
    user_role_repo: SysUserRoleRepository,
    user_post_repo: SysUserPostRepository,
    dept_repo: SysDeptRepository,
    post_repo: SysPostRepository,
    role_repo: SysRoleRepository,
    role_dept_repo: SysRoleDeptRepository,
    /// Redis 连接管理器（权限缓存失效）
    redis: ConnectionManager,
}

impl SysUserService {
    pub fn new(db: DatabaseConnection, redis: ConnectionManager) -> Self {
        Self {
            user_repo: SysUserRepository::new(db.clone()),
            user_role_repo: SysUserRoleRepository::new(db.clone()),
            user_post_repo: SysUserPostRepository::new(db.clone()),
            dept_repo: SysDeptRepository::new(db.clone()),
            post_repo: SysPostRepository::new(db.clone()),
            role_repo: SysRoleRepository::new(db.clone()),
            role_dept_repo: SysRoleDeptRepository::new(db),
            redis,
        }
    }

    /// 获取数据库连接引用（用于事务）
    fn db(&self) -> &DatabaseConnection {
        self.user_repo.base().db()
    }

    // ==================== 权限缓存失效 ====================

    /// 失效指定用户的权限缓存（best-effort，失败仅记日志不阻断业务）
    pub async fn invalidate_perm_cache(&self, user_id: i64) {
        let key = format!("{}{}", PERM_CACHE_PREFIX, user_id);
        let mut conn = self.redis.clone();
        if let Err(e) = redis::cmd("DEL")
            .arg(&key)
            .query_async::<()>(&mut conn)
            .await
        {
            tracing::warn!("失效权限缓存 {} 失败: {}", key, e);
        }
    }

    /// 垂直越权校验：基于 operator 拥有的角色与目标角色集合的层级关系（P0-R81-005 / REGRESS-002）
    ///
    /// 规则：
    /// - 超管（user_id==1）豁免
    /// - 其他 operator：取 operator 角色中最小 role_sort（最高优先级）
    ///   取目标角色集合中最小 role_sort（最高优先级）
    ///   若 目标最小 role_sort < operator 最小 role_sort（即目标含更高优先级角色），拒绝 403
    ///
    /// 目标角色为空时不拒绝（删除关联等场景）。
    async fn check_vertical_auth_by_role_ids(
        &self,
        operator_user_id: i64,
        target_role_ids: &[i64],
    ) -> Result<(), ServiceError> {
        if operator_user_id == SUPER_ADMIN_USER_ID || target_role_ids.is_empty() {
            return Ok(());
        }
        let op_roles = self.role_repo.find_by_user_id(operator_user_id).await?;
        let op_min_sort = op_roles.iter().map(|r| r.role_sort).min();

        // 垂直越权 safe-fail（P1）：operator 自身无任何角色时，不允许分配/管理任何角色
        // （target 非空），防止无角色操作者越权提权。仅清空角色（target 为空）时允许。
        if op_min_sort.is_none() && !target_role_ids.is_empty() {
            return Err(ServiceError::new(
                403,
                crate::tr!("error.user.higher_role_forbidden"),
            ));
        }

        let target_roles = self.role_repo.find_by_ids(target_role_ids).await?;
        let target_min_sort = target_roles.iter().map(|r| r.role_sort).min();

        if let (Some(target_min), Some(op_min)) = (target_min_sort, op_min_sort)
            && target_min < op_min
        {
            return Err(ServiceError::new(
                403,
                crate::tr!("error.user.higher_role_forbidden"),
            ));
        }
        Ok(())
    }

    /// 垂直越权校验：基于目标用户当前绑定的角色（REGRESS-002）
    ///
    /// 用于 edit_user/delete_user/reset_user_pwd/update_user_status：
    /// 取目标用户当前绑定的角色集合，复用 check_vertical_auth_by_role_ids 逻辑。
    async fn check_vertical_auth_by_user_id(
        &self,
        operator_user_id: i64,
        target_user_id: i64,
    ) -> Result<(), ServiceError> {
        if operator_user_id == SUPER_ADMIN_USER_ID {
            return Ok(());
        }
        let target_roles = self.role_repo.find_by_user_id(target_user_id).await?;
        let target_role_ids: Vec<i64> = target_roles.iter().map(|r| r.role_id).collect();
        self.check_vertical_auth_by_role_ids(operator_user_id, &target_role_ids)
            .await
    }

    /// 分页查询用户（仅未删除）
    ///
    /// 使用批量查询优化 N+1 问题：
    /// 1. 查询用户列表（1 次 DB）
    /// 2. 批量查询所有用户的角色关联（1 次 DB）
    /// 3. 批量查询所有部门信息（1 次 DB）
    /// 4. 在内存中组装 UserVo
    ///
    /// 数据权限（P0-R81-004）：当传入 operator_user_id 时，按 operator 角色的 data_scope 过滤：
    /// - data_scope=1（全部）：不过滤
    /// - data_scope=2（自定义）：filter by sys_role_dept 中角色绑定的 dept_ids
    /// - data_scope=3（本部门）：filter by operator.dept_id
    /// - data_scope=4（本部门及以下）：filter by operator.dept_id 及其所有后代部门
    /// - data_scope=5（仅本人）：filter by operator_user_id
    ///
    /// 取 operator 所有角色中 data_scope 值最小者（最宽松）生效。
    /// 超管（user_id==1）短路：直接返回全部。
    pub async fn get_user_page(
        &self,
        query: UserQueryDto,
        operator_user_id: Option<i64>,
    ) -> Result<(Vec<UserVo>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };

        // 数据权限过滤参数（C10：抽取到 resolve_data_scope，保持行为一致）
        let (scope_dept_ids, scope_user_id) = self.resolve_data_scope(operator_user_id).await?;

        let scope_dept_ref = scope_dept_ids.as_deref();
        let (rows, total) = self
            .user_repo
            .find_page_with_data_scope(
                offset,
                limit,
                query.user_name.as_deref(),
                query.phonenumber.as_deref(),
                query.status.as_deref(),
                query.dept_id,
                scope_dept_ref,
                scope_user_id,
                begin,
                end,
            )
            .await?;

        // 2. 收集所有 user_id，批量查询角色关联（1 次 DB 查询）
        let user_ids: Vec<i64> = rows.iter().map(|u| u.user_id).collect();
        let role_ids_map = self
            .user_role_repo
            .find_role_ids_by_user_ids(&user_ids)
            .await?;

        // 3. 收集所有 dept_id，批量查询部门信息（1 次 DB 查询）
        let dept_ids: Vec<i64> = rows
            .iter()
            .filter_map(|u| u.dept_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let depts = self.dept_repo.find_by_ids(dept_ids).await?;
        let dept_map: std::collections::HashMap<i64, SysDeptModel> =
            depts.into_iter().map(|d| (d.dept_id, d)).collect();

        // 4. 在内存中组装 UserVo
        let mut vos = Vec::with_capacity(rows.len());
        for user in rows {
            let role_ids = role_ids_map
                .get(&user.user_id)
                .cloned()
                .unwrap_or_default();
            let dept = user
                .dept_id
                .and_then(|did| dept_map.get(&did).cloned());
            vos.push(UserVo { user, role_ids, dept });
        }
        Ok((vos, total))
    }

    /// 解析数据权限过滤参数（C10：从 get_user_page / export_users 抽出的公共方法）
    ///
    /// 返回 `(scope_dept_ids, scope_user_id)`：
    /// - `scope_dept_ids`：按部门过滤的部门 ID 集合（None = 不过滤）
    /// - `scope_user_id`：仅本人过滤（Some(uid)；None = 不过滤）
    ///
    /// 规则与两个调用方完全一致：
    /// - 超管（user_id==1）短路，直接返回 (None, None)（全部数据）
    /// - 取 operator 所有角色中 data_scope 值最小者（最宽松）生效
    /// - 无角色 / data_scope 缺失 / 未知值：安全失败，限定为本人
    async fn resolve_data_scope(
        &self,
        op_uid: Option<i64>,
    ) -> Result<(Option<Vec<i64>>, Option<i64>), ServiceError> {
        let mut scope_dept_ids: Option<Vec<i64>> = None;
        let mut scope_user_id: Option<i64> = None;

        if let Some(op_uid) = op_uid {
            // 超管短路
            if op_uid != SUPER_ADMIN_USER_ID {
                // 查询 operator 的角色，取最小 data_scope（最宽松）
                let op_roles = self.role_repo.find_by_user_id(op_uid).await?;
                let min_scope = op_roles
                    .iter()
                    .filter_map(|r| r.data_scope.as_deref())
                    .filter_map(|s| s.parse::<i32>().ok())
                    .min();

                if let Some(scope) = min_scope {
                    match scope {
                        1 => {
                            // 全部数据：不追加过滤
                        }
                        2 => {
                            // 自定义：聚合 operator 所有角色的 sys_role_dept 部门
                            let role_ids: Vec<i64> = op_roles
                                .iter()
                                .filter(|r| r.data_scope.as_deref() == Some("2"))
                                .map(|r| r.role_id)
                                .collect();
                            let rids = self.role_dept_repo.find_by_role_ids(&role_ids).await?;
                            scope_dept_ids =
                                Some(rids.into_iter().map(|rd| rd.dept_id).collect());
                        }
                        3 => {
                            // 本部门：filter by operator.dept_id
                            let op_user = self.user_repo.base().find_by_id(op_uid).await?;
                            if let Some(u) = op_user {
                                if let Some(did) = u.dept_id {
                                    scope_dept_ids = Some(vec![did]);
                                } else {
                                    // 无部门 → 不可见任何用户
                                    scope_dept_ids = Some(vec![]);
                                }
                            } else {
                                scope_dept_ids = Some(vec![]);
                            }
                        }
                        4 => {
                            // 本部门及以下：operator.dept_id + 所有后代部门
                            let op_user = self.user_repo.base().find_by_id(op_uid).await?;
                            let op_dept_id = op_user.and_then(|u| u.dept_id).unwrap_or(0);
                            let descendant_ids =
                                self.dept_repo.find_descendant_ids(op_dept_id).await?;
                            scope_dept_ids = Some(descendant_ids);
                        }
                        5 => {
                            // 仅本人
                            scope_user_id = Some(op_uid);
                        }
                        _ => {
                            // 未知 data_scope 值，安全失败：限定为本人
                            scope_user_id = Some(op_uid);
                        }
                    }
                } else {
                    // operator 无角色或 data_scope 缺失：安全失败，仅本人
                    scope_user_id = Some(op_uid);
                }
            }
        }

        Ok((scope_dept_ids, scope_user_id))
    }

    /// 导出用户列表（受 EXPORT_MAX_ROWS 限制，绕过 PageDomain 的 100 行截断）
    ///
    /// 与 `get_user_page` 的差异：使用 EXPORT_MAX_ROWS 作为 limit，
    /// 而非 PageDomain.limit()（受 MAX_PAGE_SIZE=100 限制），避免静默截断导出数据。
    pub async fn export_users(
        &self,
        query: UserQueryDto,
        operator_user_id: Option<i64>,
    ) -> Result<Vec<UserVo>, ServiceError> {
        let offset = 0u64;
        let limit = crate::common::page::EXPORT_MAX_ROWS;

        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };

        // P0-1 修复：导出接口需应用与 list 相同的数据权限过滤，防止越权导出
        //（C10：抽取到 resolve_data_scope，保持行为一致）
        let (scope_dept_ids, scope_user_id) = self.resolve_data_scope(operator_user_id).await?;

        // 1. 通过 Repository 多条件查询用户列表（受 EXPORT_MAX_ROWS 限制 + 数据权限过滤）
        let (rows, _) = self
            .user_repo
            .find_page_with_data_scope(
                offset,
                limit,
                query.user_name.as_deref(),
                query.phonenumber.as_deref(),
                query.status.as_deref(),
                query.dept_id,
                scope_dept_ids.as_deref(),
                scope_user_id,
                begin,
                end,
            )
            .await?;

        // 2. 批量查询角色关联 + 部门信息（与 get_user_page 同款优化）
        let user_ids: Vec<i64> = rows.iter().map(|u| u.user_id).collect();
        let role_ids_map = self
            .user_role_repo
            .find_role_ids_by_user_ids(&user_ids)
            .await?;

        let dept_ids: Vec<i64> = rows
            .iter()
            .filter_map(|u| u.dept_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let depts = self.dept_repo.find_by_ids(dept_ids).await?;
        let dept_map: std::collections::HashMap<i64, SysDeptModel> =
            depts.into_iter().map(|d| (d.dept_id, d)).collect();

        // 3. 组装 UserVo
        let mut vos = Vec::with_capacity(rows.len());
        for user in rows {
            let role_ids = role_ids_map
                .get(&user.user_id)
                .cloned()
                .unwrap_or_default();
            let dept = user
                .dept_id
                .and_then(|did| dept_map.get(&did).cloned());
            vos.push(UserVo { user, role_ids, dept });
        }
        Ok(vos)
    }

    /// 查询用户详情（含 role_ids）
    pub async fn get_user_by_id(&self, user_id: i64) -> Result<UserVo, ServiceError> {
        let user = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;

        if user.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        let role_ids = self.get_role_ids_by_user_id(user_id).await?;
        // 查询部门信息
        let dept = if let Some(dept_id) = user.dept_id {
            self.dept_repo.base().find_by_id(dept_id).await.map_err(|e| {
                tracing::warn!("查询用户部门信息失败（不阻断主流程）: {}", e);
                e
            }).ok().flatten()
        } else {
            None
        };
        Ok(UserVo { user, role_ids, dept })
    }

    /// 查询个人信息（对齐前端 GET /system/user/profile）
    ///
    /// 返回用户信息 + roleGroup（角色名称逗号拼接）+ postGroup（岗位名称逗号拼接）
    pub async fn get_profile(&self, user_id: i64) -> Result<ProfileVo, ServiceError> {
        let user = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if user.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 查询用户角色列表（通过 Repository），拼接 roleGroup
        let roles = self.role_repo.find_by_user_id(user_id).await?;
        let role_group = roles
            .iter()
            .map(|r| r.role_name.clone())
            .collect::<Vec<_>>()
            .join(",");

        // 查询用户岗位 ID 列表，再查岗位详情，拼接 postGroup
        let post_ids = self.get_post_ids_by_user_id(user_id).await?;
        let posts = self.post_repo.find_by_ids(post_ids).await?;
        let post_group = posts
            .iter()
            .map(|p| p.post_name.clone())
            .collect::<Vec<_>>()
            .join(",");

        Ok(ProfileVo {
            role_group,
            post_group,
            user,
        })
    }

    /// 修改个人信息（对齐前端 PUT /system/user/profile）
    ///
    /// 仅更新提供的字段（nick_name / email / phonenumber / sex），
    /// 不允许通过此接口修改密码、角色、部门等敏感字段。
    pub async fn update_profile(
        &self,
        user_id: i64,
        dto: ProfileUpdateDto,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // G18：按国家/地区校验手机号（方案 D 多地区化）
        validate_phone_by_region(&dto.phonenumber, &dto.country_code)?;

        let existing = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // L-5：若所有提交值与现有值完全相同，跳过无意义的 UPDATE（减少 DB 写入与 binlog 噪声）
        //      None 字段视为"不修改"，不参与比较；仅当所有提交字段都等于现值时短路返回。
        let nick_same = dto
            .nick_name
            .as_deref()
            .is_none_or(|v| existing.nick_name == v);
        let email_same = dto
            .email
            .as_deref()
            .is_none_or(|v| existing.email.as_deref() == Some(v));
        let phone_same = dto
            .phonenumber
            .as_deref()
            .is_none_or(|v| existing.phonenumber.as_deref() == Some(v));
        let country_same = dto
            .country_code
            .as_deref()
            .is_none_or(|v| existing.country_code.as_deref() == Some(v));
        let sex_same = dto
            .sex
            .as_deref()
            .is_none_or(|v| existing.sex.as_deref() == Some(v));
        if nick_same && email_same && phone_same && country_same && sex_same {
            return Ok(());
        }

        let now = crate::common::datetime::now_naive();
        let mut am: SysUserActiveModel = existing.into();
        if let Some(ref nick) = dto.nick_name {
            am.nick_name = Set(nick.clone());
        }
        if let Some(ref email) = dto.email {
            am.email = Set(Some(email.clone()));
        }
        if let Some(ref phone) = dto.phonenumber {
            am.phonenumber = Set(Some(phone.clone()));
        }
        if let Some(ref cc) = dto.country_code {
            am.country_code = Set(Some(cc.clone()));
        }
        if let Some(ref sex) = dto.sex {
            am.sex = Set(Some(sex.clone()));
        }
        am.update_by = Set(Some(user_id.to_string()));
        am.update_time = Set(Some(now));
        self.user_repo.update(am).await?;

        Ok(())
    }

    /// 查询用户表单数据（对齐前端 UserFormDataResult）
    ///
    /// 返回用户信息 + 用户已绑定角色/岗位 ID + 全部角色/岗位列表（下拉选择用）。
    /// 用于新增/编辑用户表单回显。
    pub async fn get_user_form_data(&self, user_id: Option<i64>) -> Result<UserFormVo, ServiceError> {
        // 查询全部可用角色（通过 Repository）
        let all_roles: Vec<SysRoleModel> = self.role_repo.find_active_all().await?;
        // 查询全部可用岗位
        let all_posts: Vec<SysPostModel> = self.post_repo.find_active_all().await?;

        // 若 user_id 为 None（新增场景），返回空 role_ids/post_ids 和 None 的 data
        let (user, role_ids, post_ids) = match user_id {
            None => (None, vec![], vec![]),
            Some(uid) => {
                let user_model = self.user_repo.base().find_by_id(uid).await?
                    .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
                if user_model.del_flag.as_deref() == Some("2") {
                    return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
                }
                let rids = self.get_role_ids_by_user_id(uid).await?;
                let pids = self.get_post_ids_by_user_id(uid).await?;
                (Some(user_model), rids, pids)
            }
        };

        Ok(UserFormVo {
            data: user,
            post_ids,
            role_ids,
            roles: all_roles,
            posts: all_posts,
        })
    }

    /// 新增用户（事务：插入用户 + 批量插入角色关联）
    pub async fn add_user(
        &self,
        dto: UserAddDto,
        operator: &str,
    ) -> Result<SysUserModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // G18：按国家/地区校验手机号（方案 D 多地区化）
        validate_phone_by_region(&dto.phonenumber, &dto.country_code)?;

        // R19-1.3：密码复杂度校验（拦截纯数字/纯字母等弱口令）
        validate_password_complexity(&dto.password).map_err(|e| ServiceError::bad_request(&e))?;

        // 用户名查重（含已软删除的，避免恢复后冲突）
        let exists = self.user_repo.find_by_user_name(&dto.user_name).await?;
        if exists.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!("error.user.name_duplicate")));
        }

        // Argon2 hash 是 CPU 密集型同步操作，用 spawn_blocking 包裹避免阻塞 Tokio runtime（P0-31）
        let password_for_hash = dto.password.clone();
        let hashed = tokio::task::spawn_blocking(move || encrypt_password(&password_for_hash))
            .await
            .map_err(|e| {
                tracing::error!("密码加密 spawn_blocking 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.password_encrypt_failed"))
            })??;
        let user_repo = self.user_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let user_post_repo = self.user_post_repo.clone();
        let result = self
            .db()
            .transaction::<_, SysUserModel, sea_orm::DbErr>(|txn| {
                let now = crate::common::datetime::now_naive();
                let mut user_am = SysUserActiveModel {
                    ..Default::default()
                };
                user_am.dept_id = Set(dto.dept_id);
                user_am.user_name = Set(dto.user_name.clone());
                user_am.nick_name = Set(dto.nick_name.clone());
                user_am.email = Set(dto.email.clone());
                user_am.phonenumber = Set(dto.phonenumber.clone());
                user_am.country_code = Set(dto.country_code.clone());
                user_am.sex = Set(dto.sex.clone());
                user_am.password = Set(Some(hashed.clone()));
                user_am.status = Set(dto.status.clone().or_else(|| Some("0".to_string())));
                user_am.del_flag = Set(Some("0".to_string()));
                user_am.create_by = Set(Some(operator.to_string()));
                user_am.create_time = Set(Some(now));
                user_am.update_by = Set(Some(operator.to_string()));
                user_am.update_time = Set(Some(now));
                user_am.remark = Set(dto.remark.clone());

                let role_ids = dto.role_ids.clone();
                let post_ids = dto.post_ids.clone();
                async move {
                    // 1. 插入 sys_user（通过 Repository）
                    let new_user = user_repo.base().insert_conn(txn, user_am).await?;

                    // 2. 若 role_ids 非空，批量插入 sys_user_role（通过 Repository）
                    if let Some(ids) = role_ids
                        && !ids.is_empty()
                    {
                        let models: Vec<SysUserRoleActiveModel> = ids
                            .into_iter()
                            .map(|rid| SysUserRoleActiveModel {
                                user_id: Set(new_user.user_id),
                                role_id: Set(rid),
                            })
                            .collect();
                        user_role_repo.insert_many_conn(txn, models).await?;
                    }

                    // 3. 若 post_ids 非空，批量插入 sys_user_post（通过 Repository）
                    // SEC-005：补全用户-岗位关联写操作，与角色关联同事务保证原子性
                    if let Some(ids) = post_ids
                        && !ids.is_empty()
                    {
                        let models: Vec<SysUserPostActiveModel> = ids
                            .into_iter()
                            .map(|pid| SysUserPostActiveModel {
                                user_id: Set(new_user.user_id),
                                post_id: Set(pid),
                            })
                            .collect();
                        user_post_repo.insert_many_conn(txn, models).await?;
                    }
                    Ok(new_user)
                }
                .boxed()
            })
            .await?;

        Ok(result)
    }

    /// 修改用户（事务：更新用户 + 重分配角色）
    ///
    /// 安全校验（REGRESS-002）：垂直越权防护
    /// - 超管保护：user_id==1 不允许停用、不允许修改角色绑定
    /// - 其他 operator：若修改角色绑定，校验待分配角色是否比 operator 自己角色更高
    ///   若目标用户当前角色比 operator 更高，拒绝（避免低权限者修改高权限者信息）
    pub async fn edit_user(
        &self,
        dto: UserEditDto,
        operator: &str,
        operator_user_id: i64,
    ) -> Result<SysUserModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // G18：按国家/地区校验手机号（方案 D 多地区化）
        validate_phone_by_region(&dto.phonenumber, &dto.country_code)?;

        // 查询用户是否存在
        let existing = self.user_repo.base().find_by_id(dto.user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 超管保护：user_id==1 不允许停用、不允许修改角色绑定
        if dto.user_id == SUPER_ADMIN_USER_ID {
            if let Some(ref status) = dto.status
                && status == "1"
            {
                return Err(ServiceError::bad_request(&crate::tr!("error.user.admin_disable_forbidden")));
            }
            if dto.role_ids.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!("error.user.admin_role_forbidden")));
            }
            if dto.post_ids.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!("error.user.admin_post_forbidden")));
            }
        }

        // 垂直越权校验（REGRESS-002）
        // 1. 校验目标用户当前角色层级
        self.check_vertical_auth_by_user_id(operator_user_id, dto.user_id)
            .await?;
        // 2. 若修改角色绑定，校验待分配角色层级
        if let Some(ref ids) = dto.role_ids {
            self.check_vertical_auth_by_role_ids(operator_user_id, ids)
                .await?;
        }

        let user_repo = self.user_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let user_post_repo = self.user_post_repo.clone();
        let result = self
            .db()
            .transaction::<_, SysUserModel, sea_orm::DbErr>(|txn| {
                let now = crate::common::datetime::now_naive();
                let mut am: SysUserActiveModel = existing.into();
                if let Some(dept_id) = dto.dept_id {
                    am.dept_id = Set(Some(dept_id));
                }
                if let Some(ref nick) = dto.nick_name {
                    am.nick_name = Set(nick.clone());
                }
                if let Some(ref email) = dto.email {
                    am.email = Set(Some(email.clone()));
                }
                if let Some(ref phone) = dto.phonenumber {
                    am.phonenumber = Set(Some(phone.clone()));
                }
                if let Some(ref cc) = dto.country_code {
                    am.country_code = Set(Some(cc.clone()));
                }
                if let Some(ref sex) = dto.sex {
                    am.sex = Set(Some(sex.clone()));
                }
                if let Some(ref status) = dto.status {
                    am.status = Set(Some(status.clone()));
                }
                if let Some(ref remark) = dto.remark {
                    am.remark = Set(Some(remark.clone()));
                }
                am.update_by = Set(Some(operator.to_string()));
                am.update_time = Set(Some(now));

                let role_ids = dto.role_ids.clone();
                let post_ids = dto.post_ids.clone();
                let user_id = dto.user_id;
                async move {
                    // 1. 更新 sys_user（通过 Repository）
                    let updated = user_repo.base().update_conn(txn, am).await?;

                    // 2. 若 role_ids 为 Some（非 None），重分配角色（通过 Repository）
                    if let Some(ids) = role_ids {
                        // 先删除旧关联
                        user_role_repo.delete_by_user_id_conn(txn, user_id).await?;
                        // 若非空，再插入新关联
                        if !ids.is_empty() {
                            let models: Vec<SysUserRoleActiveModel> = ids
                                .into_iter()
                                .map(|rid| SysUserRoleActiveModel {
                                    user_id: Set(user_id),
                                    role_id: Set(rid),
                                })
                                .collect();
                            user_role_repo.insert_many_conn(txn, models).await?;
                        }
                    }

                    // 3. 若 post_ids 为 Some（非 None），重分配岗位（通过 Repository）
                    // SEC-005：补全用户-岗位关联写操作，与角色关联同事务保证原子性
                    if let Some(ids) = post_ids {
                        // 先删除旧关联
                        user_post_repo.delete_by_user_id_conn(txn, user_id).await?;
                        // 若非空，再插入新关联
                        if !ids.is_empty() {
                            let models: Vec<SysUserPostActiveModel> = ids
                                .into_iter()
                                .map(|pid| SysUserPostActiveModel {
                                    user_id: Set(user_id),
                                    post_id: Set(pid),
                                })
                                .collect();
                            user_post_repo.insert_many_conn(txn, models).await?;
                        }
                    }
                    Ok(updated)
                }
                .boxed()
            })
            .await?;
        // 用户角色绑定变更时，失效该用户的权限缓存
        if dto.role_ids.is_some() {
            self.invalidate_perm_cache(dto.user_id).await;
        }

        Ok(result)
    }

    /// 删除用户（事务：软删除用户 + 物理删除角色关联）
    ///
    /// 安全校验（REGRESS-002）：垂直越权防护
    /// - 超管保护：禁止删除超级管理员
    /// - 其他 operator：若目标用户当前角色比 operator 更高，拒绝
    pub async fn delete_user(
        &self,
        user_id: i64,
        operator_user_id: i64,
    ) -> Result<(), ServiceError> {
        // 超管保护
        if user_id == SUPER_ADMIN_USER_ID {
            return Err(ServiceError::bad_request(&crate::tr!("error.user.admin_delete_forbidden")));
        }

        let existing = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 垂直越权校验（REGRESS-002）
        self.check_vertical_auth_by_user_id(operator_user_id, user_id)
            .await?;

        // 释放唯一字段值，避免软删除后唯一索引冲突（uk_sys_user_name）
        // 软删除记录仍占用 user_name 唯一索引，导致无法重新创建同名用户
        let deleted_user_name = format!("{}_deleted_{}", existing.user_name, user_id);

        let user_repo = self.user_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let user_post_repo = self.user_post_repo.clone();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                async move {
                    // 1. 软删除 sys_user（通过 Repository）
                    let mut am: SysUserActiveModel = existing.into();
                    am.del_flag = Set(Some("2".to_string()));
                    am.user_name = Set(deleted_user_name);
                    user_repo.base().update_conn(txn, am).await?;

                    // 2. 物理删除 sys_user_role 关联（通过 Repository）
                    user_role_repo.delete_by_user_id_conn(txn, user_id).await?;

                    // 3. 物理删除 sys_user_post 关联（SEC-005：补全孤儿记录清理）
                    user_post_repo.delete_by_user_id_conn(txn, user_id).await?;

                    // 4. 物理删除 sys_notice_read 关联（清理已读记录，避免已读列表显示已删除用户）
                    SysNoticeRead::delete_many()
                        .filter(NoticeReadColumn::UserId.eq(user_id))
                        .exec(txn)
                        .await?;
                    Ok(())
                }
                .boxed()
            })
            .await?;
        // 用户删除后失效其权限缓存（清理缓存条目）
        self.invalidate_perm_cache(user_id).await;

        Ok(())
    }

    /// 批量删除用户（原子事务，R8-API-002 + R8-API-008）
    ///
    /// 所有用户删除操作包装在单个事务中：
    /// - 任一用户校验失败（超管保护/垂直越权/不存在）→ 整个事务回滚，无任何用户被删除
    /// - 任一 DB 操作失败 → 整个事务回滚
    ///
    /// 对比 handler 层 for 循环调用 delete_user：
    /// - 旧方案：第 2 个用户删除失败时第 1 个已删，第 3 个未删，数据状态不一致
    /// - 新方案：全部成功才提交，部分失败回滚到操作前状态
    ///
    /// 注意：垂直越权校验基于现有角色数据，事务内不会重新检查（与 delete_user 的
    /// check_vertical_auth_by_user_id 一致），依赖 sys_user_role 的外键约束保证一致性。
    pub async fn delete_users(
        &self,
        user_ids: Vec<i64>,
        operator_user_id: i64,
    ) -> Result<(), ServiceError> {
        // 预校验：超管保护（事务外快速失败，避免无效事务开销）
        if user_ids.contains(&SUPER_ADMIN_USER_ID) {
            return Err(ServiceError::bad_request(&crate::tr!("error.user.admin_delete_forbidden")));
        }

        // 单个 ID 直接走 delete_user（保持原有事务行为，避免嵌套事务开销）
        if user_ids.len() == 1 {
            return self.delete_user(user_ids[0], operator_user_id).await;
        }

        // C-2：批量垂直越权校验（事务前统一执行，全部通过后才进入事务）
        //      与 delete_user 的 check_vertical_auth_by_user_id 行为一致，
        //      避免 handler 层 for 循环调用 delete_user 时漏校验的安全漏洞。
        for target_user_id in &user_ids {
            self.check_vertical_auth_by_user_id(operator_user_id, *target_user_id)
                .await?;
        }

        // 批量删除：单个事务包装所有操作
        let user_repo = self.user_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let user_post_repo = self.user_post_repo.clone();
        let db = self.db().clone();

        db.transaction::<_, (), sea_orm::DbErr>(|txn| {
                async move {
                    for user_id in user_ids {
                        // 1. 查询用户存在性（事务内，防止 TOCTOU）
                        let existing = user_repo.base().find_by_id_conn(txn, user_id).await?
                            .ok_or_else(|| sea_orm::DbErr::Custom(format!("{}: {}", crate::tr!("error.user.not_found"), user_id)))?;
                        if existing.del_flag.as_deref() == Some("2") {
                            return Err(sea_orm::DbErr::Custom(format!("{}: {}", crate::tr!("error.user.not_found"), user_id)));
                        }

                        // 2. 垂直越权校验已在事务前完成（见上方 C-2 修复），
                        //    事务内不再重复校验，依赖 sys_user_role 的外键约束保证一致性。

                        // 3. 释放唯一字段值（避免软删除后唯一索引冲突）
                        let deleted_user_name = format!("{}_deleted_{}", existing.user_name, user_id);

                        // 4. 软删除 sys_user
                        let mut am: SysUserActiveModel = existing.into();
                        am.del_flag = Set(Some("2".to_string()));
                        am.user_name = Set(deleted_user_name);
                        user_repo.base().update_conn(txn, am).await?;

                        // 5. 物理删除 sys_user_role 关联
                        user_role_repo.delete_by_user_id_conn(txn, user_id).await?;

                        // 6. 物理删除 sys_user_post 关联（SEC-005：补全孤儿记录清理）
                        user_post_repo.delete_by_user_id_conn(txn, user_id).await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await?;

        Ok(())
    }

    /// 管理员重置密码（无需校验旧密码）
    ///
    /// 安全校验（REGRESS-002）：垂直越权防护
    /// - 超管保护：禁止重置超级管理员密码
    /// - 其他 operator：若目标用户当前角色比 operator 更高，拒绝
    pub async fn reset_user_pwd(
        &self,
        dto: UserPwdResetDto,
        _operator: &str,
        operator_user_id: i64,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // R19-1.3：密码复杂度校验（拦截纯数字/纯字母等弱口令）
        validate_password_complexity(&dto.password).map_err(|e| ServiceError::bad_request(&e))?;

        // 超管保护：禁止重置超级管理员密码
        if dto.user_id == SUPER_ADMIN_USER_ID {
            return Err(ServiceError::bad_request(&crate::tr!("error.user.admin_pwd_forbidden")));
        }

        let existing = self.user_repo.base().find_by_id(dto.user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 垂直越权校验（REGRESS-002）
        self.check_vertical_auth_by_user_id(operator_user_id, dto.user_id)
            .await?;

        // Argon2 hash 是 CPU 密集型同步操作，用 spawn_blocking 包裹避免阻塞 Tokio runtime（P0-31）
        let password_for_hash = dto.password.clone();
        let hashed = tokio::task::spawn_blocking(move || encrypt_password(&password_for_hash))
            .await
            .map_err(|e| {
                tracing::error!("密码加密 spawn_blocking 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.password_encrypt_failed"))
            })??;
        let mut am: SysUserActiveModel = existing.into();
        am.password = Set(Some(hashed));
        self.user_repo.update(am).await?;

        Ok(())
    }

    /// 个人中心改密（需校验旧密码，支持 MD5→Argon2 自动升级）
    pub async fn update_user_password(
        &self,
        user_id: i64,
        dto: UserPwdUpdateDto,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // R19-1.3：密码复杂度校验（拦截纯数字/纯字母等弱口令）
        validate_password_complexity(&dto.new_password).map_err(|e| ServiceError::bad_request(&e))?;

        // 新旧密码不能相同
        if dto.old_password == dto.new_password {
            return Err(ServiceError::bad_request(&crate::tr!("error.user.same_password")));
        }

        let existing = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 校验旧密码（支持 MD5→Argon2 自动升级）
        // Argon2 verify 是 CPU 密集型同步操作，用 spawn_blocking 包裹避免阻塞 Tokio runtime（P0-31）
        let old_hashed = existing
            .password
            .as_deref()
            .ok_or_else(|| ServiceError::internal(&crate::tr!("error.user.password_missing")))?
            .to_string();
        let old_password_for_verify = dto.old_password.clone();
        let verify_result = tokio::task::spawn_blocking(move || {
            verify_password_with_upgrade_hint(&old_password_for_verify, &old_hashed)
        })
        .await
        .map_err(|e| {
            tracing::error!("密码验证 spawn_blocking 失败: {}", e);
            ServiceError::internal(&crate::tr!("error.auth.password_verify_failed"))
        })?;
        if !verify_result.is_valid {
            return Err(ServiceError::bad_request(&crate::tr!("error.auth.old_password_wrong")));
        }

        // Argon2 hash 是 CPU 密集型同步操作，用 spawn_blocking 包裹（P0-31）
        let new_password_for_hash = dto.new_password.clone();
        let hashed = tokio::task::spawn_blocking(move || encrypt_password(&new_password_for_hash))
            .await
            .map_err(|e| {
                tracing::error!("密码加密 spawn_blocking 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.password_encrypt_failed"))
            })??;
        let mut am: SysUserActiveModel = existing.into();
        am.password = Set(Some(hashed));
        self.user_repo.update(am).await?;

        Ok(())
    }

    /// 启停用户
    ///
    /// 安全校验（REGRESS-002）：垂直越权防护
    /// - 超管保护：不允许停用超级管理员
    /// - 其他 operator：若目标用户当前角色比 operator 更高，拒绝
    pub async fn update_user_status(
        &self,
        user_id: i64,
        status: &str,
        operator: &str,
        operator_user_id: i64,
    ) -> Result<(), ServiceError> {
        // 超管保护
        if user_id == SUPER_ADMIN_USER_ID && status == "1" {
            return Err(ServiceError::bad_request(&crate::tr!("error.user.admin_disable_forbidden")));
        }

        let existing = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 垂直越权校验（REGRESS-002）
        self.check_vertical_auth_by_user_id(operator_user_id, user_id)
            .await?;

        let now = crate::common::datetime::now_naive();
        let mut am: SysUserActiveModel = existing.into();
        am.status = Set(Some(status.to_string()));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        self.user_repo.update(am).await?;

        Ok(())
    }

    /// 分配用户角色（事务：先清空再插入，全量覆盖）
    ///
    /// 安全校验（P0-R81-005）：垂直越权防护
    /// - 超管（user_id==1）豁免
    /// - 其他 operator：校验待分配角色是否比 operator 自己角色更高（REGRESS-002：复用通用辅助方法）
    /// - 同时校验目标用户当前角色是否比 operator 更高（P0-H3：防止降级高权限用户）
    pub async fn assign_user_roles(
        &self,
        user_id: i64,
        role_ids: Vec<i64>,
        operator_user_id: i64,
    ) -> Result<(), ServiceError> {
        // 超管保护：禁止修改超级管理员角色绑定
        if user_id == SUPER_ADMIN_USER_ID {
            return Err(ServiceError::bad_request(&crate::tr!("error.user.admin_role_forbidden")));
        }

        // 垂直越权校验（P0-R81-005 / REGRESS-002）：待分配角色不得高于 operator
        self.check_vertical_auth_by_role_ids(operator_user_id, &role_ids)
            .await?;

        // 垂直越权校验（P0-H3）：目标用户当前角色不得高于 operator，防止降级高权限用户
        self.check_vertical_auth_by_user_id(operator_user_id, user_id)
            .await?;

        let existing = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        let user_role_repo = self.user_role_repo.clone();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let role_ids = role_ids.clone();
                async move {
                    // 先删除旧关联（通过 Repository）
                    user_role_repo.delete_by_user_id_conn(txn, user_id).await?;
                    // 若非空，再插入新关联（通过 Repository）
                    if !role_ids.is_empty() {
                        let models: Vec<SysUserRoleActiveModel> = role_ids
                            .into_iter()
                            .map(|rid| SysUserRoleActiveModel {
                                user_id: Set(user_id),
                                role_id: Set(rid),
                            })
                            .collect();
                        user_role_repo.insert_many_conn(txn, models).await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await?;
        // 用户角色绑定变更，失效该用户的权限缓存
        self.invalidate_perm_cache(user_id).await;

        Ok(())
    }

    /// 登录认证用：按用户名查询（不过滤 del_flag）
    ///
    /// Handler 层根据返回的 del_flag / status 字段判断登录场景：
    /// - None → "用户不存在"
    /// - del_flag == "2" → "账号已删除，请联系管理员"
    /// - status == "1" → "账号已停用，请联系管理员"
    /// - 其他 → 正常进入密码校验
    pub async fn get_user_by_username(
        &self,
        user_name: &str,
    ) -> Result<Option<SysUserModel>, ServiceError> {
        let user = self.user_repo.find_by_user_name(user_name).await?;
        Ok(user)
    }

    /// 登录认证用：按用户名查询未删除用户（del_flag = '0'）
    ///
    /// H-2：登录流程使用此方法，Repository 层已过滤 del_flag='0'，
    /// 调用方无需再判断 `del_flag == "2"`，避免冗余检查。
    /// 返回 None 包含两种语义：用户不存在 / 用户已软删除（统一对外返回"用户名或密码错误"）。
    pub async fn get_active_user_by_username(
        &self,
        user_name: &str,
    ) -> Result<Option<SysUserModel>, ServiceError> {
        let user = self.user_repo.find_active_by_user_name(user_name).await?;
        Ok(user)
    }

    /// 更新登录信息（login_ip / login_date）
    pub async fn update_login_info(
        &self,
        user_id: i64,
        login_ip: &str,
    ) -> Result<(), ServiceError> {
        self.user_repo.update_login_info(user_id, login_ip).await?;
        Ok(())
    }

    /// 升级密码哈希（MD5→Argon2 迁移用，登录时若检测到旧哈希则自动升级）
    ///
    /// 仅在密码验证成功且 needs_upgrade=true 时调用。
    /// 失败不阻断登录（best-effort），仅记日志。
    pub async fn upgrade_password_hash(
        &self,
        user_id: i64,
        new_hashed: &str,
    ) -> Result<(), ServiceError> {
        let existing = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        let mut am: SysUserActiveModel = existing.into();
        am.password = Set(Some(new_hashed.to_string()));
        self.user_repo.update(am).await?;
        Ok(())
    }

    /// 更新用户头像
    ///
    /// 将头像文件路径写入 sys_user.avatar 字段
    pub async fn update_avatar(
        &self,
        user_id: i64,
        avatar_path: &str,
    ) -> Result<Option<String>, ServiceError> {
        let existing = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        // P2 修复: 保存旧 avatar 路径，供 handler 删除旧文件，避免文件系统泄漏
        let old_avatar = existing.avatar.clone();
        let mut am: SysUserActiveModel = existing.into();
        am.avatar = Set(Some(avatar_path.to_string()));
        self.user_repo.update(am).await?;
        Ok(old_avatar)
    }

    /// 查询部门下拉树（全部未删除部门，组装为 TreeSelect 格式）
    pub async fn get_dept_tree(&self) -> Result<Vec<TreeSelectVo>, ServiceError> {
        let depts = self.dept_repo.find_active_all().await?;
        let tree = build_dept_tree_select(&depts, 0);
        Ok(tree)
    }

    /// 根据 user_id 查询用户所属部门名称（用于在线会话填充 dept_name）
    ///
    /// 流程：sys_user.dept_id → sys_dept.dept_name
    /// 用户或部门不存在/已删除时返回空字符串（不阻断登录流程）
    pub async fn get_dept_name_by_user_id(
        &self,
        user_id: i64,
    ) -> Result<String, ServiceError> {
        let user = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        let Some(dept_id) = user.dept_id else {
            return Ok(String::new());
        };
        let dept = self.dept_repo.base().find_by_id(dept_id).await?;
        match dept {
            Some(d) if d.del_flag.as_deref() != Some("2") => Ok(d.dept_name),
            _ => Ok(String::new()),
        }
    }

    /// 查询用户授权角色信息（对齐前端 UserAuthRoleResult）
    ///
    /// 返回用户信息 + 全部可用角色列表（前端用于勾选用户已绑定的角色）
    pub async fn get_auth_role(
        &self,
        user_id: i64,
        operator_user_id: i64,
    ) -> Result<UserAuthRoleVo, ServiceError> {
        // 超管用户保护：禁止查看超管用户的授权信息（防止信息收集）
        if user_id == SUPER_ADMIN_USER_ID && operator_user_id != SUPER_ADMIN_USER_ID {
            return Err(ServiceError::bad_request(
                &crate::tr!("error.user.admin_role_forbidden"),
            ));
        }

        // 垂直越权校验：operator 不得查看比自己更高优先级用户的授权信息
        self.check_vertical_auth_by_user_id(operator_user_id, user_id)
            .await?;

        let user = self.user_repo.base().find_by_id(user_id).await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if user.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 查询全部未删除角色（通过 Repository，前端根据 user.roleIds 自行标记已勾选）
        let all_roles: Vec<SysRoleModel> = self.role_repo.find_active_all().await?;

        Ok(UserAuthRoleVo {
            user,
            roles: all_roles,
        })
    }

    // ==================== 内部辅助方法 ====================

    /// 查询用户的角色 ID 列表
    async fn get_role_ids_by_user_id(&self, user_id: i64) -> Result<Vec<i64>, ServiceError> {
        let user_roles = self.user_role_repo.find_by_user_id(user_id).await?;
        let role_ids: Vec<i64> = user_roles.into_iter().map(|ur| ur.role_id).collect();
        Ok(role_ids)
    }

    /// 查询用户的岗位 ID 列表
    async fn get_post_ids_by_user_id(&self, user_id: i64) -> Result<Vec<i64>, ServiceError> {
        let user_posts = self.user_post_repo.find_by_user_id(user_id).await?;
        let post_ids: Vec<i64> = user_posts.into_iter().map(|up| up.post_id).collect();
        Ok(post_ids)
    }
}
