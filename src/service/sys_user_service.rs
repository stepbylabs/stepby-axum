//! 用户模块 Service 层
//!
//! 职责：
//! - 用户 CRUD、密码加密校验、用户角色分配、状态启停
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 多表操作使用 SeaORM 事务保证一致性
//! - 参数校验使用 garde crate（经 common::i18n::validate 统一入口）
//! - 数据访问通过 Repository 层委托

use futures::future::FutureExt;
use garde::Validate;
use regex::Regex;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, Set, Statement,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};
use ts_rs::TS;
use utoipa::{IntoParams, ToSchema};

use crate::common::constants::SUPER_ADMIN_USER_ID;
use crate::common::custom_scope::{self, CustomCondition};
use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::common::sort::{self, SortOrder};
use crate::entity::sys_dept::Model as SysDeptModel;
use crate::entity::sys_notice_read::{Column as NoticeReadColumn, Entity as SysNoticeRead};
use crate::entity::sys_oauth_user::{Column as OauthUserColumn, Entity as SysOauthUser};
use crate::entity::sys_pat::{Column as PatColumn, Entity as SysPat};
use crate::entity::sys_post::Model as SysPostModel;
use crate::entity::sys_role::Model as SysRoleModel;
use crate::entity::sys_user::{ActiveModel as SysUserActiveModel, Column as UserColumn, Model as SysUserModel};
use crate::entity::sys_user_credential::{Column as UserCredentialColumn, Entity as SysUserCredential};
use crate::entity::sys_user_pref::{Column as UserPrefColumn, Entity as SysUserPref};
use crate::entity::sys_user_post::ActiveModel as SysUserPostActiveModel;
use crate::repository::sys_dept::SysDeptRepository;
use crate::repository::sys_post::SysPostRepository;
use crate::repository::sys_role::SysRoleRepository;
use crate::repository::sys_role_dept::SysRoleDeptRepository;
use crate::repository::sys_user::SysUserRepository;
use crate::repository::sys_user_dept::SysUserDeptRepository;
use crate::repository::sys_user_post::SysUserPostRepository;
use crate::repository::sys_user_role::SysUserRoleRepository;
use crate::shared_store::SharedStore;
use crate::utils::masking;
use crate::utils::password::{
    encrypt_password, validate_password_complexity, verify_password_with_upgrade_hint,
};

// ==================== 字段级权限 M1：PII 掩码（phonenumber / email） ====================
//
// 口径（三口径，详见 AGENTS.md C9 日志脱敏强制与 masking 模块 rustdoc）：
// 1. 本人查自己（operator == 目标 user）：原值（看自己的手机号不应被掩码）；
// 2. 超管（user_id==1 或权限列表含 `*:*:*`，同源判定见 `is_super_viewer`）：原值
//    （管理员运维需要全值）；
// 3. 其它 operator：任何用户的 mobile/email 均掩码。
//
// 掩码值带可识别形态（含 `****`），编辑回显场景前端未改动直接回传时，
// `edit_user` 依据 `masking::is_masked` 识别并跳过该字段，防止掩码串覆盖真实值。

/// 三口径判定（纯函数，可单测）：返回 `true` 表示需要对目标用户的 PII 字段掩码。
///
/// - `operator_user_id`：当前操作者；`None` 表示无操作者上下文（fail-closed，一律掩码）；
/// - `operator_is_super`：操作者是否超管视角（`is_super_viewer` 的结果，由调用方
///   每次请求计算一次，避免列表逐行重复查询）。
///
/// `pub(crate)`：M1 脱敏影响面补齐（字段级权限 M2 登记）——公告已读用户列表
/// （`sys_notice_service`）的 phonenumber 出口复用同一三口径判定，杜绝口径漂移。
pub(crate) fn should_mask_pii(
    operator_user_id: Option<i64>,
    target_user_id: i64,
    operator_is_super: bool,
) -> bool {
    // 口径 2：超管看任何人都原值
    if operator_is_super {
        return false;
    }
    // 口径 1：本人查自己原值；口径 3：其余一律掩码
    operator_user_id != Some(target_user_id)
}

/// 判定 operator 是否为「超管视角」（可看 PII 原值）（纯函数，可单测）。
///
/// 判定口径与 `sys_menu_service::get_permissions_by_user_id` 的超管短路（`*:*:*`
/// 的唯一来源）同源：
/// - `user_id == SUPER_ADMIN_USER_ID`（内置 admin）；
/// - 或 operator 拥有平台超管角色（`is_system && tenant_id == 0`，即
///   `SysRoleModel::is_platform_super_admin`）——该角色在权限解析中被直接授予
///   `*:*:*` 通配权限。
fn is_super_viewer(operator_user_id: i64, operator_roles: &[SysRoleModel]) -> bool {
    operator_user_id == SUPER_ADMIN_USER_ID
        || operator_roles.iter().any(|r| r.is_platform_super_admin())
}

/// 就地对 `SysUserModel` 的 PII 字段（phonenumber / email）做展示型掩码（纯函数，可单测）。
///
/// 使用 `utils::masking` 的业务展示口径：手机号 `138****5678`、邮箱 `a****@example.com`。
/// 掩码值必然含 `*`，与 `masking::is_masked` 的编辑回显识别约定配套。
fn mask_user_pii_in_place(model: &mut SysUserModel) {
    if let Some(phone) = model.phonenumber.as_deref() {
        model.phonenumber = Some(masking::mask_phone(phone));
    }
    if let Some(email) = model.email.as_deref() {
        model.email = Some(masking::mask_email(email));
    }
}

/// M2 字段级权限：对单行 `SysUserModel` 应用「隐藏列优先」的展示策略（纯函数，可单测）。
///
/// - hidden 集合内的字段直接置 `None`（**优先级高于掩码**：隐藏 = 数据整体不可见，
///   而非掩码形态——掩码串仍保留形态信息，隐藏连形态都不给）；
/// - 未隐藏字段走 M1 三口径掩码（`should_mask` 为 true 时）。
///
/// 关闭态：`hidden` 为空集合且 `should_mask` 为 false ⇒ 零变化（可证伪单测锁死）。
/// `pub(crate)`：字段级权限服务（sys_role_field_perm_service）的单测复用同一实现。
pub(crate) fn apply_field_perm_and_mask(
    model: &mut SysUserModel,
    hidden: &std::collections::HashSet<String>,
    should_mask: bool,
) {
    let hide_phone = hidden.contains("phonenumber");
    let hide_email = hidden.contains("email");
    if hide_phone {
        model.phonenumber = None;
    }
    if hide_email {
        model.email = None;
    }
    if should_mask {
        if !hide_phone
            && let Some(phone) = model.phonenumber.as_deref()
        {
            model.phonenumber = Some(masking::mask_phone(phone));
        }
        if !hide_email
            && let Some(email) = model.email.as_deref()
        {
            model.email = Some(masking::mask_email(email));
        }
    }
}

/// M2：hidden 字段集合 → repository 列裁剪枚举（封闭白名单映射，纯函数）。
///
/// 集合内未知的字段名被静默忽略（白名单外字段本就不参与裁剪，fail-closed 不放大）。
pub(crate) fn hidden_field_set_to_omit_columns(
    hidden: &std::collections::HashSet<String>,
) -> Vec<crate::repository::sys_user::UserOmitColumn> {
    let mut out = Vec::new();
    if hidden.contains("phonenumber") {
        out.push(crate::repository::sys_user::UserOmitColumn::Phonenumber);
    }
    if hidden.contains("email") {
        out.push(crate::repository::sys_user::UserOmitColumn::Email);
    }
    out
}

// ==================== 可选枚举字段归一化（R6-VAL-16 / R6-VAL-17） ====================

/// 归一化 + 校验用户「性别」：`None` / 空串 / 纯空白 ⇒ `None`（视为"未提供"）；
/// 仅允许 `"0"`(男) / `"1"`(女) / `"2"`(未知)。
///
/// # 为什么在 Service 层收口
///
/// `sex` 在 DTO 上是 `#[garde(skip)]` 的**自由字符串**，历史实现把 `dto.sex` 原样 `Set(...)`
/// 写库，导致两个真实问题（R6-VAL-16）：
/// 1. **枚举不受约束**：`"9"` / `"male"` 等非法值可直接落库，后续按 `sex='0'/'1'` 统计或
///    前端映射时口径分裂；
/// 2. **空串与 NULL 混用**：`""` 与 `NULL` 是两种"未设置"表示，任何 `WHERE sex IS NULL`
///    之类的判断都会漏掉一半数据。
///
/// 写入口不止一处（管理面表单 `add_user`/`edit_user`、个人中心 `update_profile`），
/// 且项目分层约定「参数校验归 Service 层」，故在此统一收口，保证**任何入口**都无法绕过。
fn normalize_sex(value: Option<String>) -> Result<Option<String>, ServiceError> {
    match value.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(v) if matches!(v, "0" | "1" | "2") => Ok(Some(v.to_string())),
        Some(_) => Err(ServiceError::bad_request(&crate::tr!(
            "error.user.sex_invalid"
        ))),
    }
}

/// 归一化 + 校验用户「状态」：`None` / 空串 / 纯空白 ⇒ `None`（视为"未提供"）；
/// 仅允许 `"0"`(正常) / `"1"`(停用)。
///
/// 与 [`normalize_sex`] 同源缺陷（R6-VAL-17）：`status` 亦为 `#[garde(skip)]` 自由字符串。
/// 注意 `None` 的语义按调用点区分——新增时回落默认启用态，编辑时表示"不修改"。
fn normalize_user_status(value: Option<String>) -> Result<Option<String>, ServiceError> {
    match value.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(v) if matches!(v, "0" | "1") => Ok(Some(v.to_string())),
        Some(_) => Err(ServiceError::bad_request(&crate::tr!(
            "error.user.status_invalid"
        ))),
    }
}

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
    /// 兼职部门 ID 列表（多部门任职最小侵入版：主部门=dept_id，本列表=兼职；
    /// None 不绑定，Some(vec![]) 清空兼职；服务层自动排除与 dept_id 重复项）
    #[garde(skip)]
    pub dept_ids: Option<Vec<i64>>,
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
    /// 兼职部门 ID 列表（None 不修改兼职绑定，Some(vec![]) 全量替换 admin 来源兼职；
    /// SCIM 同步的兼职记录（source='scim:{gid}'）不受影响）
    #[garde(skip)]
    pub dept_ids: Option<Vec<i64>>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

// ==================== 批量导入（B3） ====================

/// 导入用户行（模板列：登录名称* / 用户姓名* / 部门名称 / 手机号码 / 邮箱 / 性别 / 状态）
#[derive(Debug, Clone)]
pub struct ImportUserRow {
    pub row_num: u32,
    pub login_name: String,
    pub nick_name: String,
    pub dept_name: Option<String>,
    pub phonenumber: Option<String>,
    pub email: Option<String>,
    /// 性别：男→0 / 女→1 / 空→2（未知）
    pub sex: Option<String>,
    /// 状态：正常→0 / 停用→1，默认 0
    pub status: String,
}

/// 导入结果项（回显前端：行号 + 错误信息）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImportErrorItem {
    pub row_num: u32,
    pub error: String,
}

/// 导入结果 VO
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImportResultVo {
    /// 本次导入新增/更新的用户数
    pub success: u32,
    /// 校验失败、被跳过的行
    pub error_list: Vec<ImportErrorItem>,
}

/// 管理员重置密码 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
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
#[derive(Debug, Deserialize, Validate, ToSchema)]
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
    let Some(phone) = phone else {
        return Ok(());
    };
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
        if *cc == country
            && let Ok(re) = Regex::new(pat)
        {
            return re.is_match(phone);
        }
    }
    false
}

// ==================== 批量导入纯函数（B3，可独立单测） ====================

/// 导入列位置（与模板列顺序一致）
const COL_LOGIN: usize = 0;
const COL_NICK: usize = 1;
const COL_DEPT: usize = 2;
const COL_PHONE: usize = 3;
const COL_EMAIL: usize = 4;
const COL_SEX: usize = 5;
const COL_STATUS: usize = 6;

fn cell_str(row: &[String], idx: usize) -> Option<String> {
    row.get(idx)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// 解析 xlsx 行矩阵为导入行对象（第 1 行为表头，跳过；空行跳过）
pub fn parse_import_rows(rows: &[Vec<String>]) -> Vec<ImportUserRow> {
    if rows.len() < 2 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, row) in rows.iter().enumerate().skip(1) {
        if row.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let sex = match cell_str(row, COL_SEX).as_deref() {
            Some("男") | Some("0") => Some("0".to_string()),
            Some("女") | Some("1") => Some("1".to_string()),
            _ => Some("2".to_string()),
        };
        let status = match cell_str(row, COL_STATUS).as_deref() {
            Some("停用") | Some("1") => "1".to_string(),
            _ => "0".to_string(),
        };
        out.push(ImportUserRow {
            row_num: (i + 1) as u32,
            login_name: cell_str(row, COL_LOGIN).unwrap_or_default(),
            nick_name: cell_str(row, COL_NICK).unwrap_or_default(),
            dept_name: cell_str(row, COL_DEPT),
            phonenumber: cell_str(row, COL_PHONE).map(|e| e.trim().to_string().trim().to_string()),
            email: cell_str(row, COL_EMAIL),
            sex,
            status,
        });
    }
    out
}

/// 结构级校验（纯函数，不触库）；返回 Err(错误文案) 表示该行不通过
pub fn validate_import_row(row: &ImportUserRow) -> Result<(), String> {
    let login = row.login_name.trim();
    if login.is_empty() {
        return Err(crate::tr!("error.user.import_login_required").to_string());
    }
    if login.len() < 2 || login.len() > 30 {
        return Err(crate::tr!("error.user.import_login_length").to_string());
    }
    let login_re = Regex::new(r"^[a-zA-Z0-9_]+$").expect("登录名正则编译失败");
    if !login_re.is_match(login) {
        return Err(crate::tr!("error.user.import_login_format").to_string());
    }
    if row.nick_name.trim().is_empty() {
        return Err(crate::tr!("error.user.import_nick_required").to_string());
    }
    if let Some(p) = row.phonenumber.as_deref().filter(|p| !p.trim().is_empty())
        && let Err(e) = validate_phone_by_region(&Some(p.to_string()), &None)
    {
        return Err(e.message);
    }
    if let Some(e) = row.email.as_deref().filter(|e| !e.trim().is_empty())
        && !is_valid_email(e.trim())
    {
        return Err(crate::tr!("error.user.email_invalid").to_string());
    }
    Ok(())
}

/// 简单邮箱格式校验（与 garde email 规则一致的宽松校验）
/// W9（NL2SQL v4 升格项）：LIKE 查询参数约束
///
/// - 截断到 50 字符：防"超长 LIKE 模式逐行回溯"的 CPU 消耗（无索引 LIKE 全表扫描，扫描行数不受分页限制）
/// - trim：去除首尾空白，避免"全空格"这类无意义模式
/// - 不做字符集黑名单：`like_escape` 已在 repository 层处理通配符转义，此处不重复
fn clamp_like_param(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().chars().take(50).collect())
}

fn is_valid_email(s: &str) -> bool {
    let at = s.find('@');
    let Some(at) = at else { return false };
    if at == 0 || at == s.len() - 1 {
        return false;
    }
    let local = &s[..at];
    let domain = &s[at + 1..];
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

/// 用户分页查询 DTO
#[derive(Debug, Clone, Deserialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct UserQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    /// 排序字段（前端表头 prop，camelCase/snake_case 均可；经列白名单映射后生效，
    /// 未命中白名单回退默认排序，绝不透传任意列）
    #[serde(default)]
    pub order_by_column: Option<String>,
    /// 排序方向 asc / ascending / desc / descending（缺省 desc）
    #[serde(default)]
    pub is_asc: Option<String>,
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
    /// 游标（keyset 深分页）：上一页最后一条 user_id。存在时启用深分页（PK < last_id），
    /// 不存在时沿用 pageNum/pageSize 的 OFFSET 分页，向后兼容。
    pub last_id: Option<i64>,
    /// 显式「按租户筛选」（`[ui].tenant_filter` 决定前端是否给出入口）。
    ///
    /// 服务层把它与 `tenant_scope` **相与**（AND）⇒ 只能收窄、永不放宽：
    /// 租户操作者即便手工传他租户 id，结果集也只是空集，不存在越权读面。
    pub tenant_id: Option<i64>,
}

impl From<&UserQueryDto> for PageDomain {
    fn from(dto: &UserQueryDto) -> Self {
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
    /// v5-E4：是否已绑定第三方登录身份（sys_oauth_user 存在该 user_id 的绑定；
    /// 管理员识别账号来源，绑定明细见用户个人中心的"第三方绑定"页签）
    #[serde(default)]
    pub oauth_bound: bool,
    /// 多部门任职（最小侵入版）：兼职部门 ID 列表（sys_user_dept 全部行；
    /// 主部门 = dept_id 不在此列）
    #[serde(default)]
    pub dept_ids: Vec<i64>,
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
    /// 多部门任职：兼职部门 ID 列表（**仅 admin 来源**，编辑可改）
    pub dept_ids: Vec<i64>,
    /// v5-D12 Group：SCIM 组联动角色 id 集合（source like 'scim:%'）——前端
    /// 角色树上禁选并标记"来自组"，提交不包含（防止误转 admin 行）
    pub scim_role_ids: Vec<i64>,
    /// v5-D12 Group：SCIM 组同步兼职部门 id 集合（只读标记，提交不包含）
    pub scim_dept_ids: Vec<i64>,
}

// ==================== 辅助函数 ====================

// ==================== Service 实现 ====================

/// 允许排序的列白名单（数据库列名 snake_case；前端 prop 经 camel_to_snake 归一后匹配）。
///
/// 覆盖用户业务展示列；`password`（凭据哈希）、`login_ip`（审计）、`tenant_id`、
/// `scim_external_id` 等内部/敏感列一律不开放动态排序。
const SORTABLE_COLUMNS: &[(&str, UserColumn)] = &[
    ("user_id", UserColumn::UserId),
    ("dept_id", UserColumn::DeptId),
    ("user_name", UserColumn::UserName),
    ("nick_name", UserColumn::NickName),
    ("email", UserColumn::Email),
    ("phonenumber", UserColumn::Phonenumber),
    ("status", UserColumn::Status),
    ("create_time", UserColumn::CreateTime),
    ("login_date", UserColumn::LoginDate),
];

/// 权限缓存 key 前缀（单一事实源 = `common::constants::PERM_CACHE_PREFIX`）
use crate::common::constants::PERM_CACHE_PREFIX;

/// 用户模块 Service
///
/// 数据访问通过 Repository 层委托：
/// - user_repo: sys_user 表 CRUD
/// - user_role_repo: sys_user_role 关联表 CRUD
/// - user_post_repo: sys_user_post 关联表 CRUD
/// - dept_repo: sys_dept 表查询（部门树）
/// - post_repo: sys_post 表查询（岗位下拉）
/// - role_repo: sys_role 表查询（角色下拉）
/// - store: 共享态存储（SharedStore），用于权限缓存失效
/// - 事务通过 user_repo.base().db() 获取连接
#[derive(Clone)]
pub struct SysUserService {
    user_repo: SysUserRepository,
    user_role_repo: SysUserRoleRepository,
    user_post_repo: SysUserPostRepository,
    user_dept_repo: SysUserDeptRepository,
    dept_repo: SysDeptRepository,
    post_repo: SysPostRepository,
    role_repo: SysRoleRepository,
    role_dept_repo: SysRoleDeptRepository,
    /// 租户套餐/配额服务（多租户 §27.1 决策 10：账号配额校验）
    tenant_service: crate::service::SysTenantService,
    /// 共享态存储（权限缓存失效）
    store: Arc<dyn SharedStore>,
}

impl SysUserService {
    pub fn new(db: DatabaseConnection, store: Arc<dyn SharedStore>) -> Self {
        Self {
            user_repo: SysUserRepository::new(db.clone()),
            user_role_repo: SysUserRoleRepository::new(db.clone()),
            user_post_repo: SysUserPostRepository::new(db.clone()),
            user_dept_repo: SysUserDeptRepository::new(db.clone()),
            dept_repo: SysDeptRepository::new(db.clone()),
            post_repo: SysPostRepository::new(db.clone()),
            role_repo: SysRoleRepository::new(db.clone()),
            tenant_service: crate::service::SysTenantService::new(db.clone(), store.clone()),
            role_dept_repo: SysRoleDeptRepository::new(db),
            store,
        }
    }

    /// 账号配额校验（事务内权威版本，§27.1 决策 10）：所有插入 `sys_user` 的写路径
    /// （新增用户 / OAuth 自动建号 / SCIM 预置）必须在自己事务内调用本方法。
    pub async fn ensure_account_quota_txn<C: sea_orm::ConnectionTrait>(
        &self,
        txn: &C,
        tenant_id: i64,
    ) -> Result<(), sea_orm::DbErr> {
        self.tenant_service
            .ensure_account_quota_txn(txn, tenant_id)
            .await
    }

    /// 获取数据库连接引用（用于事务）
    fn db(&self) -> &DatabaseConnection {
        self.user_repo.base().db()
    }

    // ==================== 权限缓存失效 ====================

    /// 失效指定用户的权限缓存（best-effort，失败仅记日志不阻断业务）
    pub async fn invalidate_perm_cache(&self, user_id: i64) {
        let key = format!("{}{}", PERM_CACHE_PREFIX, user_id);
        if let Err(e) = self.store.del(std::slice::from_ref(&key)).await {
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

    /// M1 字段级权限：operator 是否为「超管视角」（可看 PII 原值）。
    ///
    /// 查询 operator 的角色集合后交由纯函数 [`is_super_viewer`] 判定
    /// （user_id==1 或拥有平台超管角色 ⇒ 权限列表含 `*:*:*`）。
    /// 查询失败时 fail-closed（视为非超管，PII 掩码）。
    async fn viewer_is_super(&self, operator_user_id: i64) -> bool {
        match self.role_repo.find_by_user_id(operator_user_id).await {
            Ok(roles) => is_super_viewer(operator_user_id, &roles),
            Err(e) => {
                tracing::warn!(
                    operator_user_id,
                    "PII 掩码判定：查询 operator 角色失败，fail-closed 按非超管处理: {}",
                    e
                );
                false
            }
        }
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
    ///
    /// M2 字段级权限：`hidden_user_fields` 为裁剪判定单一入口
    /// （`SysRoleFieldPermService::hidden_fields`）的判定结果，作用于列表/展示面：
    /// - repository 层按集合做列裁剪（隐藏字段不参与 SELECT，数据在查询层即不外泄）；
    /// - VO 组装层「隐藏列优先」叠加 M1 掩码（隐藏字段直接 None，掩码只对未隐藏字段生效）。
    ///
    /// 关闭态（空集合）时两者均零行为变化。编辑回显 `get_user_form_data` **不裁剪**
    /// （登记口径：字段级权限只作用于列表/展示，编辑走独立数据范围校验）。
    pub async fn get_user_page(
        &self,
        mut query: UserQueryDto,
        operator_user_id: Option<i64>,
        tenant_scope: Option<i64>,
        hidden_user_fields: &std::collections::HashSet<String>,
    ) -> Result<(Vec<UserVo>, u64), ServiceError> {
        // W9（现存 P1）：LIKE 查询参数约束 —— 截断超长输入，防"超长 LIKE 模式逐行回溯"的 CPU 消耗
        // （MAX_PAGE_SIZE 只限返回行数，不限扫描行数；like_escape 已防注入，此处补长度与字符整洁）
        query.user_name = clamp_like_param(query.user_name);
        query.phonenumber = clamp_like_param(query.phonenumber);
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();
        // 动态排序：白名单命中才生效，未命中/缺省由 repository 回退默认排序
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_user::Entity>(prop, SORTABLE_COLUMNS).map(
                |col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())),
            )
        });

        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        // 数据权限过滤参数（C10：抽取到 resolve_data_scope，保持行为一致）
        let (scope_dept_ids, scope_user_id, custom_conds) =
            self.resolve_data_scope(operator_user_id).await?;

        let scope_dept_ref = scope_dept_ids.as_deref();
        let custom_ref = custom_conds.as_deref();
        // M2 字段级权限：hidden 集合 → repository 列裁剪枚举（封闭白名单映射）
        let omit_columns = hidden_field_set_to_omit_columns(hidden_user_fields);
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
                custom_ref,
                begin,
                end,
                query.last_id,
                tenant_scope,
                query.tenant_id,
                sort,
                &omit_columns,
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

        // 3.5 v5-E4：批量查询第三方登录绑定集合（1 次 DB 查询；账号来源标识）
        let oauth_bound_set = self.oauth_bound_user_ids(&user_ids).await;

        // 3.6 多部门任职：批量查询兼职部门映射（1 次 DB 查询）
        let dept_ids_map = self
            .user_dept_repo
            .find_dept_ids_by_user_ids(&user_ids)
            .await?;

        // M1 字段级权限：每次请求计算一次超管视角（避免逐行重复查角色），
        // None = 无操作者上下文，fail-closed 按非超管处理（掩码）
        let op_is_super = match operator_user_id {
            Some(op) => self.viewer_is_super(op).await,
            None => false,
        };

        // 4. 在内存中组装 UserVo
        let mut vos = Vec::with_capacity(rows.len());
        for user in rows {
            let role_ids = role_ids_map.get(&user.user_id).cloned().unwrap_or_default();
            let dept = user.dept_id.and_then(|did| dept_map.get(&did).cloned());
            let oauth_bound = oauth_bound_set.contains(&user.user_id);
            let dept_ids = dept_ids_map.get(&user.user_id).cloned().unwrap_or_default();
            // M2 隐藏列优先 + M1 三口径掩码叠加：本人查自己 / 超管 → 原值；
            // 隐藏字段直接 None（优先级高于掩码）；未隐藏字段非本人非超管 → 掩码
            let mut user = user;
            let should_mask = should_mask_pii(operator_user_id, user.user_id, op_is_super);
            apply_field_perm_and_mask(&mut user, hidden_user_fields, should_mask);
            vos.push(UserVo {
                user,
                role_ids,
                dept,
                oauth_bound,
                dept_ids,
            });
        }
        Ok((vos, total))
    }

    /// v5-E4：查询一批 user_id 中已绑定第三方登录身份（sys_oauth_user 存在记录）的集合。
    /// 查询失败时返回空集合并记 warn（标记降级为未绑定，不阻断列表主流程）。
    async fn oauth_bound_user_ids(&self, user_ids: &[i64]) -> std::collections::HashSet<i64> {
        if user_ids.is_empty() {
            return std::collections::HashSet::new();
        }
        let id_list = user_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("SELECT DISTINCT user_id FROM sys_oauth_user WHERE user_id IN ({id_list})");
        let backend = self.db().get_database_backend();
        match self
            .db()
            .query_all_raw(Statement::from_string(backend, sql))
            .await
        {
            Ok(rows) => rows
                .iter()
                .filter_map(|r| r.try_get::<i64>("", "user_id").ok())
                .collect(),
            Err(e) => {
                tracing::warn!("查询第三方绑定集合失败（标记降级为未绑定）: {}", e);
                std::collections::HashSet::new()
            }
        }
    }

    /// 解析数据权限过滤参数（C10：从 get_user_page / export_users 抽出的公共方法）
    ///
    /// 返回 `(scope_dept_ids, scope_user_id, custom_conds)`：
    /// - `scope_dept_ids`：按部门过滤的部门 ID 集合（None = 不过滤）
    /// - `scope_user_id`：仅本人过滤（Some(uid)；None = 不过滤）
    /// - `custom_conds`：data_scope=2（自定义）角色带来的 `custom_sql` 白名单条件
    ///   （None = 无；此项与 dept_ids 是「与」关系：自定义模式仍先按部门限定，再叠加字段过滤）
    ///
    /// 规则与两个调用方完全一致：
    /// - 超管（user_id==1）短路，直接返回 (None, None, None)（全部数据）
    /// - 取 operator 所有角色中 data_scope 值最小者（最宽松）生效
    /// - 无角色 / data_scope 缺失 / 未知值：安全失败，限定为本人
    async fn resolve_data_scope(
        &self,
        op_uid: Option<i64>,
    ) -> Result<(Option<Vec<i64>>, Option<i64>, Option<Vec<CustomCondition>>), ServiceError> {
        let mut scope_dept_ids: Option<Vec<i64>> = None;
        let mut scope_user_id: Option<i64> = None;
        let mut custom_conds: Option<Vec<CustomCondition>> = None;

        if let Some(op_uid) = op_uid {
            // 超管短路
            if op_uid != SUPER_ADMIN_USER_ID {
                // 查询 operator 的角色，取最小 data_scope（最宽松）
                let op_roles = self.role_repo.find_by_user_id(op_uid).await?;
                let min_scope = crate::common::data_scope::min_data_scope(&op_roles);

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
                            scope_dept_ids = Some(rids.into_iter().map(|rd| rd.dept_id).collect());
                            // 自定义模式下额外附加 custom_sql 白名单条件；
                            // 解析失败 → 拒绝本次请求（fail-closed，5-1 修复）
                            custom_conds = custom_scope::derive_user_custom_conditions(&op_roles)
                                .map_err(|e| {
                                ServiceError::bad_request(&format!(
                                    "custom_sql 解析失败，已拒绝本次请求: {}",
                                    e
                                ))
                            })?;
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

        Ok((scope_dept_ids, scope_user_id, custom_conds))
    }

    /// 导出用户列表（受 EXPORT_MAX_ROWS 限制，绕过 PageDomain 的 100 行截断）
    ///
    /// 与 `get_user_page` 的差异：使用 EXPORT_MAX_ROWS 作为 limit，
    /// 而非 PageDomain.limit()（受 MAX_PAGE_SIZE=100 限制），避免静默截断导出数据。
    ///
    /// M2 字段级权限：导出与列表**同口径**裁剪（`hidden_user_fields` 来自同一判定入口）。
    /// 导出是比列表更宽的数据出口，绝不能比列表宽松（否则形成"列表隐藏、导出可见"的绕行口子）。
    pub async fn export_users(
        &self,
        mut query: UserQueryDto,
        operator_user_id: Option<i64>,
        tenant_scope: Option<i64>,
        hidden_user_fields: &std::collections::HashSet<String>,
    ) -> Result<Vec<UserVo>, ServiceError> {
        // W9：同 get_user_page，导出入口同样约束 LIKE 参数（导出扫描行数更大，更需防护）
        query.user_name = clamp_like_param(query.user_name);
        query.phonenumber = clamp_like_param(query.phonenumber);
        let offset = 0u64;
        let limit = crate::common::page::EXPORT_MAX_ROWS;
        // 导出与页面列表同序：动态排序白名单解析口径一致
        let page = PageDomain::from(&query);
        let sort = page.order_by_column.as_deref().and_then(|prop| {
            sort::resolve_column::<crate::entity::sys_user::Entity>(prop, SORTABLE_COLUMNS).map(
                |col| SortOrder::new(col, sort::parse_direction(page.is_asc.as_deref())),
            )
        });

        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(crate::common::datetime::parse_query_date(s)?),
            _ => None,
        };

        // P0-1 修复：导出接口需应用与 list 相同的数据权限过滤，防止越权导出
        //（C10：抽取到 resolve_data_scope，保持行为一致）
        let (scope_dept_ids, scope_user_id, custom_conds) =
            self.resolve_data_scope(operator_user_id).await?;

        // 1. 通过 Repository 多条件查询用户列表（受 EXPORT_MAX_ROWS 限制 + 数据权限过滤）
        let omit_columns = hidden_field_set_to_omit_columns(hidden_user_fields);
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
                custom_conds.as_deref(),
                begin,
                end,
                None, // 导出固定走 OFFSET 全量路径，不走 keyset
                tenant_scope,
                query.tenant_id,
                sort,
                &omit_columns,
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

        // 3. 组装 UserVo（v5-E4：绑定标记随导出/列表一致）
        let oauth_bound_set = self.oauth_bound_user_ids(&user_ids).await;
        // 多部门任职：批量查询兼职部门映射
        let dept_ids_map = self
            .user_dept_repo
            .find_dept_ids_by_user_ids(&user_ids)
            .await?;
        // M1 字段级权限：导出与列表同口径（超管/本人 → 原值，其它 → 掩码）
        let op_is_super = match operator_user_id {
            Some(op) => self.viewer_is_super(op).await,
            None => false,
        };
        let mut vos = Vec::with_capacity(rows.len());
        for user in rows {
            let role_ids = role_ids_map.get(&user.user_id).cloned().unwrap_or_default();
            let dept = user.dept_id.and_then(|did| dept_map.get(&did).cloned());
            let oauth_bound = oauth_bound_set.contains(&user.user_id);
            let dept_ids = dept_ids_map.get(&user.user_id).cloned().unwrap_or_default();
            // M2 隐藏列优先 + M1 三口径掩码叠加（与列表同口径）
            let mut user = user;
            let should_mask = should_mask_pii(operator_user_id, user.user_id, op_is_super);
            apply_field_perm_and_mask(&mut user, hidden_user_fields, should_mask);
            vos.push(UserVo {
                user,
                role_ids,
                dept,
                oauth_bound,
                dept_ids,
            });
        }
        Ok(vos)
    }

    /// 查询用户详情（含 role_ids）
    pub async fn get_user_by_id(&self, user_id: i64) -> Result<UserVo, ServiceError> {
        let user = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;

        if user.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        let role_ids = self.get_role_ids_by_user_id(user_id).await?;
        // 查询部门信息
        let dept = if let Some(dept_id) = user.dept_id {
            self.dept_repo
                .base()
                .find_by_id(dept_id)
                .await
                .map_err(|e| {
                    tracing::warn!("查询用户部门信息失败（不阻断主流程）: {}", e);
                    e
                })
                .ok()
                .flatten()
        } else {
            None
        };
        let oauth_bound_set = self
            .oauth_bound_user_ids(std::slice::from_ref(&user_id))
            .await;
        // 多部门任职：兼职部门列表
        let dept_ids = self
            .user_dept_repo
            .find_by_user_id(user_id)
            .await?
            .into_iter()
            .map(|ud| ud.dept_id)
            .collect();
        Ok(UserVo {
            user,
            role_ids,
            dept,
            oauth_bound: oauth_bound_set.contains(&user_id),
            dept_ids,
        })
    }

    /// 查询个人信息（对齐前端 GET /system/user/profile）
    ///
    /// 返回用户信息 + roleGroup（角色名称逗号拼接）+ postGroup（岗位名称逗号拼接）
    pub async fn get_profile(&self, user_id: i64) -> Result<ProfileVo, ServiceError> {
        let user = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
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

        // R6-VAL-16：性别归一化 + 枚举校验（空串/空白 ⇒ 视为未提供，不修改）
        let normalized_sex = normalize_sex(dto.sex.clone())?;

        let existing = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
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
        let sex_same = normalized_sex
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
        if let Some(sex) = normalized_sex {
            am.sex = Set(Some(sex));
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
    /// 用户表单数据（新增/编辑共用）
    ///
    /// P0-6：`operator_user_id` 传入且目标用户存在时，校验目标用户是否在操作人数据范围内，
    /// 不在则返回 404（防止低权限管理员越权读取他人 PII；此前与 list 的数据范围不一致）。
    /// 多租户：`tenant_scope` 透传至角色/岗位下拉查询，避免跨租户枚举。
    pub async fn get_user_form_data(
        &self,
        user_id: Option<i64>,
        operator_user_id: Option<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<UserFormVo, ServiceError> {
        // 查询全部可用角色（通过 Repository，按租户过滤）
        let all_roles: Vec<SysRoleModel> = self.role_repo.find_active_all(tenant_scope).await?;
        // 查询全部可用岗位（通过 Repository，按租户过滤）
        let all_posts: Vec<SysPostModel> = self.post_repo.find_active_all(tenant_scope).await?;

        // 若 user_id 为 None（新增场景），返回空 role_ids/post_ids/dept_ids 和 None 的 data
        // M1 字段级权限：每次请求计算一次超管视角；None = 无操作者上下文，
        // fail-closed 按非超管处理（掩码）
        let op_is_super = match operator_user_id {
            Some(op) => self.viewer_is_super(op).await,
            None => false,
        };
        let (user, role_ids, post_ids, dept_ids, scim_role_ids, scim_dept_ids) = match user_id {
            None => (None, vec![], vec![], vec![], vec![], vec![]),
            Some(uid) => {
                let user_model = self
                    .user_repo
                    .base()
                    .find_by_id(uid)
                    .await?
                    .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
                if user_model.del_flag.as_deref() == Some("2") {
                    return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
                }
                // P0-6 数据范围校验（超管短路由 resolve_data_scope 处理）
                if let Some(op_uid) = operator_user_id {
                    let (scope_dept_ids, scope_user_id, _custom) =
                        self.resolve_data_scope(Some(op_uid)).await?;
                    let visible = match (scope_dept_ids, scope_user_id) {
                        (None, None) => true,                           // 全部数据
                        (Some(_), Some(scope_uid)) => uid == scope_uid, // 仅本人
                        (Some(dept_ids), None) => match user_model.dept_id {
                            Some(did) => dept_ids.contains(&did),
                            None => false,
                        },
                        (None, Some(scope_uid)) => uid == scope_uid, // 仅本人
                    };
                    if !visible {
                        return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
                    }
                }
                // M1 三口径：本人查自己（编辑回显自己资料）/ 超管 → 原值；
                // 其它 operator 查他人 → 掩码（掩码值含 `****`，edit_user
                // 会识别未改动的掩码值并跳过写库）
                let mut user_model = user_model;
                if should_mask_pii(operator_user_id, uid, op_is_super) {
                    mask_user_pii_in_place(&mut user_model);
                }
                let rids = self.get_role_ids_by_user_id(uid).await?;
                let pids = self.get_post_ids_by_user_id(uid).await?;
                // 编辑回显语义：dept_ids 仅 admin 来源（可改）；scim 来源单独只读标记
                let dids = self
                    .user_dept_repo
                    .find_dept_ids_by_user_and_source(uid, "admin")
                    .await?;
                let scim_dids = self
                    .user_dept_repo
                    .find_dept_ids_by_user_and_source(uid, "scim:")
                    .await;
                // scim 来源前缀查询（scim:{gid}）：用 like 兜底（source='scim:' 精确
                // 匹配不命中），走 repo find_by_user_id 后内存过滤更简单
                let scim_dids = match scim_dids {
                    Ok(v) if !v.is_empty() => v,
                    _ => self
                        .user_dept_repo
                        .find_by_user_id(uid)
                        .await?
                        .into_iter()
                        .filter(|ud| ud.source.starts_with("scim:"))
                        .map(|ud| ud.dept_id)
                        .collect(),
                };
                let scim_rids = self
                    .user_role_repo
                    .find_by_user_id(uid)
                    .await?
                    .into_iter()
                    .filter(|ur| ur.source.starts_with("scim:"))
                    .map(|ur| ur.role_id)
                    .collect();
                (Some(user_model), rids, pids, dids, scim_rids, scim_dids)
            }
        };

        Ok(UserFormVo {
            data: user,
            post_ids,
            role_ids,
            roles: all_roles,
            posts: all_posts,
            dept_ids,
            scim_role_ids,
            scim_dept_ids,
        })
    }

    /// 新增用户（事务：插入用户 + 批量插入角色关联）
    /// 多租户 Phase 2：租户归属单一来源 = `sys_dept.tenant_id`
    /// - 无主部门 → 平台租户 0（平台用户）；
    /// - 有主部门 → 直接取该部门 `tenant_id`（0 即平台租户/平台用户）。
    pub async fn resolve_user_tenant(&self, dept_id: Option<i64>) -> Result<i64, ServiceError> {
        let Some(dept_id) = dept_id else {
            return Ok(0);
        };
        let dept = self
            .dept_repo
            .base()
            .find_by_id(dept_id)
            .await?
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.dept.not_found")))?;
        Ok(dept.tenant_id)
    }

    /// 批量 user_id → tenant_id（在线会话旧 JSON 缺 `tenant_id` 时的兜底回填，
    /// §27.13.2 分层视图与租户踢线共用同一口径）
    pub async fn tenant_ids_by_user_ids(
        &self,
        user_ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, i64>, ServiceError> {
        let rows = self.user_repo.find_tenant_ids_by_user_ids(user_ids).await?;
        Ok(rows.into_iter().collect())
    }

    /// 批量 user_name → tenant_id（Redis 降级路径的租户过滤）
    pub async fn tenant_ids_by_user_names(
        &self,
        user_names: &[String],
    ) -> Result<std::collections::HashMap<String, i64>, ServiceError> {
        let rows = self
            .user_repo
            .find_tenant_ids_by_user_names(user_names)
            .await?;
        Ok(rows.into_iter().collect())
    }

    /// 越权防护：批量角色 ID 必须与 operator 同租户（operator_tid=0 平台管理员放行）
    async fn ensure_roles_tenant_allowed(
        &self,
        operator_tid: i64,
        role_ids: Option<&[i64]>,
    ) -> Result<(), ServiceError> {
        let Some(ids) = role_ids else {
            return Ok(());
        };
        for role_id in ids {
            let Some(role) = self.role_repo.base().find_by_id(*role_id).await? else {
                continue;
            };
            if !crate::common::tenant::tenant_allowed(operator_tid, role.tenant_id) {
                return Err(ServiceError::forbidden(&crate::tr!(
                    "error.common.forbidden"
                )));
            }
        }
        Ok(())
    }

    /// 越权防护：批量部门 ID（主/兼职）必须与 operator 同租户（operator_tid=0 平台管理员放行）
    async fn ensure_depts_tenant_allowed(
        &self,
        operator_tid: i64,
        dept_ids: Option<&[i64]>,
    ) -> Result<(), ServiceError> {
        let Some(ids) = dept_ids else {
            return Ok(());
        };
        for dept_id in ids {
            let Some(dept) = self.dept_repo.base().find_by_id(*dept_id).await? else {
                continue;
            };
            if !crate::common::tenant::tenant_allowed(operator_tid, dept.tenant_id) {
                return Err(ServiceError::forbidden(&crate::tr!(
                    "error.common.forbidden"
                )));
            }
        }
        Ok(())
    }

    /// 越权防护：批量岗位 ID 必须与 operator 同租户（operator_tid=0 平台管理员放行）
    ///
    /// 第十批（MT-2 复核发现）：`sys_user_post` 是**无 `tenant_id` 的关联表**，
    /// §27.13.1 对其"依赖父表 JOIN 安全"的前提是**写入时校验父资源归属**；
    /// 角色 / 部门已有该校验（`ensure_roles_tenant_allowed` / `ensure_depts_tenant_allowed`），
    /// **岗位漏了** ⇒ 租户操作者可在 add/edit 用户时绑定**他租户或平台岗位**：
    /// ① 用户详情/列表的 `postGroup` 会**回显他租户岗位名**（跨租户信息泄漏）；
    /// ② 形成跨租户外键引用（数据完整性破坏）。
    async fn ensure_posts_tenant_allowed(
        &self,
        operator_tid: i64,
        post_ids: Option<&[i64]>,
    ) -> Result<(), ServiceError> {
        let Some(ids) = post_ids else {
            return Ok(());
        };
        for post_id in ids {
            let Some(post) = self.post_repo.base().find_by_id(*post_id).await? else {
                continue;
            };
            if !crate::common::tenant::tenant_allowed(operator_tid, post.tenant_id) {
                return Err(ServiceError::forbidden(&crate::tr!(
                    "error.common.forbidden"
                )));
            }
        }
        Ok(())
    }

    pub async fn add_user(
        &self,
        dto: UserAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysUserModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // G18：按国家/地区校验手机号（方案 D 多地区化）
        validate_phone_by_region(&dto.phonenumber, &dto.country_code)?;

        // R6-VAL-16/17：性别 / 状态（DTO 上为 garde(skip) 自由字符串）必须归一化 + 枚举校验，
        // 否则 `"9"` / `""` 会直接落库（空串与 NULL 混用、非法枚举破坏后续口径）。
        let normalized_sex = normalize_sex(dto.sex.clone())?;
        let normalized_status = normalize_user_status(dto.status.clone())?;

        // R19-1.3：密码复杂度校验（拦截纯数字/纯字母等弱口令）
        validate_password_complexity(&dto.password).map_err(|e| ServiceError::bad_request(&e))?;

        // 用户名查重（含已软删除的，避免恢复后冲突）
        let exists = self.user_repo.find_by_user_name(&dto.user_name).await?;
        if exists.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.name_duplicate"
            )));
        }

        // Argon2 hash 是 CPU 密集型同步操作，用 spawn_blocking 包裹避免阻塞 Tokio runtime（P0-31）
        let password_for_hash = dto.password.clone();
        let hashed = tokio::task::spawn_blocking(move || encrypt_password(&password_for_hash))
            .await
            .map_err(|e| {
                tracing::error!("密码加密 spawn_blocking 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.password_encrypt_failed"))
            })??;
        // 多租户 Phase 2：tenant_id 随主部门自动解析（dept 树根=租户）
        let user_tenant_id = self.resolve_user_tenant(dto.dept_id).await?;
        // 越权防护：租户管理员不得把用户建到其它租户的部门下
        if !crate::common::tenant::tenant_allowed(operator_tid, user_tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        // 越权防护：不允许跨租户授角色 / 绑定兼职部门 / 绑定岗位
        self.ensure_roles_tenant_allowed(operator_tid, dto.role_ids.as_deref())
            .await?;
        self.ensure_depts_tenant_allowed(operator_tid, dto.dept_ids.as_deref())
            .await?;
        self.ensure_posts_tenant_allowed(operator_tid, dto.post_ids.as_deref())
            .await?;
        let user_repo = self.user_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let user_post_repo = self.user_post_repo.clone();
        let user_dept_repo = self.user_dept_repo.clone();
        let tenant_service = self.tenant_service.clone();
        let txn_result = self
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
                // R6-VAL-16/17：已归一化 + 枚举校验（见函数头部 helper）
                user_am.sex = Set(normalized_sex.clone());
                user_am.password = Set(Some(hashed.clone()));
                // B4 一致化（§5.23）：管理员经表单设置初始密码 ⇒ 标记首登待改——
                // 与导入路径（L2301）同口径；开关 forceFirstLoginChangePwd=false 时
                // 仅软提示（mustChangePassword 布场 false），开启则强改。
                user_am.must_change_pwd = Set(Some("1".to_string()));
                user_am.status = Set(normalized_status.clone().or_else(|| Some("0".to_string())));
                user_am.del_flag = Set(Some("0".to_string()));
                user_am.create_by = Set(Some(operator.to_string()));
                user_am.create_time = Set(Some(now));
                user_am.update_by = Set(Some(operator.to_string()));
                user_am.update_time = Set(Some(now));
                user_am.remark = Set(dto.remark.clone());
                // 多租户 Phase 2：tenant_id 随主部门自动解析（闭包外已算好）
                user_am.tenant_id = Set(user_tenant_id);

                let role_ids = dto.role_ids.clone();
                let post_ids = dto.post_ids.clone();
                let dept_ids = dto.dept_ids.clone().map(|ids| {
                    // 兼职部门：排除与主部门重复项（主部门唯一事实源 = dept_id）
                    match dto.dept_id {
                        Some(main) => ids.into_iter().filter(|d| *d != main).collect::<Vec<_>>(),
                        None => ids,
                    }
                });
                // 审计留痕块为 boxed()（需 'static），operator 为 &str 引用生命周期不足，
                // 克隆为 owned String 移入 async move 块
                let operator_owned = operator.to_string();
                async move {
                    // 0. 多租户 §27.1 决策 10：账号配额（事务内锁租户行 → 计数 → 插入），
                    //    口径：含停用用户、不含软删、含管理员；account_count<=0 不限
                    tenant_service
                        .ensure_account_quota_txn(txn, user_tenant_id)
                        .await?;

                    // 1. 插入 sys_user（通过 Repository）
                    let new_user = user_repo.base().insert_conn(txn, user_am).await?;

                    // 1.5 审计合规域：INSERT 变更留痕（同事务提交/回滚，失败令业务一并回滚；
                    //     敏感列 password 由 record_change 内部统一打码）
                    let after =
                        serde_json::to_value(&new_user).unwrap_or(serde_json::Value::Null);
                    let audit_operator = crate::service::sys_audit_change_service::resolve_operator(
                        txn,
                        None, // add_user 签名仅携带操作人用户名，ID 由回查补齐
                        Some(operator_owned.as_str()),
                    )
                    .await;
                    crate::service::sys_audit_change_service::record_change(
                        txn,
                        "sys_user",
                        &new_user.user_id.to_string(),
                        crate::service::sys_audit_change_service::ACTION_INSERT,
                        None,
                        Some(after),
                        audit_operator,
                    )
                    .await?;

                    // 2. 角色授权（幂等抢占式：无行插 admin 行；scim 行抢占为 admin；admin 行跳过，
                    //    防止管理员勾选 SCIM 已授角色时撞 UNIQUE(user_id, role_id)）
                    if let Some(ids) = role_ids {
                        user_role_repo
                            .upsert_admin_grants_conn(txn, new_user.user_id, ids)
                            .await?;
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

                    // 4. 多部门任职（幂等抢占式：防与 SCIM 组兼职绑定撞 UNIQUE(user_id, dept_id)）
                    if let Some(ids) = dept_ids {
                        user_dept_repo
                            .upsert_admin_depts_conn(txn, new_user.user_id, ids)
                            .await?;
                    }
                    Ok(new_user)
                }
                .boxed()
            })
            .await;

        // 配额/租户不可用业务标记 → 带状态的 ServiceError；其余（真实 DB 错误）走通用转换
        let result = match txn_result {
            Ok(user) => user,
            Err(sea_orm::TransactionError::Transaction(db_err)) => {
                match crate::service::SysTenantService::quota_violation_to_service_error(&db_err) {
                    Some(service_err) => return Err(service_err),
                    None => {
                        return Err(ServiceError::from(sea_orm::TransactionError::Transaction(
                            db_err,
                        )));
                    }
                }
            }
            Err(other) => return Err(ServiceError::from(other)),
        };

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
        operator_tid: i64,
    ) -> Result<SysUserModel, ServiceError> {
        // M1 字段级权限连带：非超管 operator 编辑他人时，详情/编辑回显返回的
        // phonenumber/email 是掩码值（含 `****`）。前端未改动直接回传时必须视为
        // "不修改该字段"，否则掩码串会覆盖真实值；且手机号掩码含 `*` 无法通过
        // 号码格式校验，故必须在校验之前剥离（掩码识别见 `utils::masking::is_masked`）。
        let mut dto = dto;
        if dto.phonenumber.as_deref().is_some_and(masking::is_masked) {
            dto.phonenumber = None;
        }
        if dto.email.as_deref().is_some_and(masking::is_masked) {
            dto.email = None;
        }

        crate::common::i18n::validate(&dto)?;

        // G18：按国家/地区校验手机号（方案 D 多地区化）
        validate_phone_by_region(&dto.phonenumber, &dto.country_code)?;

        // R6-VAL-16/17：性别 / 状态归一化 + 枚举校验（`None` = 不修改，空串视为未提供）
        let normalized_sex = normalize_sex(dto.sex.clone())?;
        let normalized_status = normalize_user_status(dto.status.clone())?;

        // 查询用户是否存在
        let existing = self
            .user_repo
            .base()
            .find_by_id(dto.user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 越权防护：租户管理员不得跨租户修改用户
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        // 超管保护：user_id==1 不允许停用、不允许修改角色绑定
        if dto.user_id == SUPER_ADMIN_USER_ID {
            if let Some(ref status) = dto.status
                && status == "1"
            {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.user.admin_disable_forbidden"
                )));
            }
            if dto.role_ids.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.user.admin_role_forbidden"
                )));
            }
            if dto.post_ids.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.user.admin_post_forbidden"
                )));
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

        // 多租户 Phase 2：主部门变更时 tenant_id 联动重算（dept 树根=租户）
        let new_tenant_id = self.resolve_user_tenant(dto.dept_id).await?;
        // 越权防护：主部门变更后的新归属必须与 operator 同租户
        if dto.dept_id.is_some()
            && !crate::common::tenant::tenant_allowed(operator_tid, new_tenant_id)
        {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }
        // 越权防护：不允许跨租户授角色 / 绑定兼职部门 / 绑定岗位
        self.ensure_roles_tenant_allowed(operator_tid, dto.role_ids.as_deref())
            .await?;
        self.ensure_depts_tenant_allowed(operator_tid, dto.dept_ids.as_deref())
            .await?;
        self.ensure_posts_tenant_allowed(operator_tid, dto.post_ids.as_deref())
            .await?;
        // 审计合规域：变更前快照（必须在 existing 被 move 进事务闭包之前计算）
        let before_snapshot =
            serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);
        let user_repo = self.user_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let user_post_repo = self.user_post_repo.clone();
        let result = self
            .db()
            .transaction::<_, SysUserModel, sea_orm::DbErr>(|txn| {
                let now = crate::common::datetime::now_naive();
                let mut am: SysUserActiveModel = existing.into();
                // 多租户 Phase 2：主部门变更时 tenant_id 联动重算（闭包外已算好）
                if let Some(dept_id) = dto.dept_id {
                    am.dept_id = Set(Some(dept_id));
                    am.tenant_id = Set(new_tenant_id);
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
                if let Some(sex) = normalized_sex.clone() {
                    am.sex = Set(Some(sex));
                }
                if let Some(status) = normalized_status.clone() {
                    am.status = Set(Some(status));
                }
                if let Some(ref remark) = dto.remark {
                    am.remark = Set(Some(remark.clone()));
                }
                am.update_by = Set(Some(operator.to_string()));
                am.update_time = Set(Some(now));

                let role_ids = dto.role_ids.clone();
                let post_ids = dto.post_ids.clone();
                let dept_ids = dto.dept_ids.clone().map(|ids| {
                    // 兼职部门：排除与主部门重复项
                    match dto.dept_id {
                        Some(main) => ids.into_iter().filter(|d| *d != main).collect::<Vec<_>>(),
                        None => ids,
                    }
                });
                let user_dept_repo = self.user_dept_repo.clone();
                let user_id = dto.user_id;
                // 审计留痕块为 boxed()（需 'static），operator 为 &str 引用生命周期不足，
                // 克隆为 owned String 移入 async move 块
                let operator_owned = operator.to_string();
                async move {
                    // 1. 更新 sys_user（通过 Repository）
                    let updated = user_repo.base().update_conn(txn, am).await?;

                    // 2. 若 role_ids 为 Some（非 None），重分配角色（幂等抢占式插入）
                    if let Some(ids) = role_ids {
                        // 先删除旧关联（v5-D12 Group：仅删管理员手授行，保留
                        // SCIM 组联动行 source='scim:{gid}'——消除回写抖动）
                        user_role_repo
                            .delete_admin_by_user_id_conn(txn, user_id)
                            .await?;
                        // 再写入新关联（scim 已有行抢占为 admin，防撞唯一约束）
                        user_role_repo
                            .upsert_admin_grants_conn(txn, user_id, ids)
                            .await?;
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

                    // 4. 多部门任职：dept_ids 为 Some（非 None）时全量替换 admin 来源
                    // 兼职记录（SCIM 同步行 source='scim:{gid}' 不受影响；幂等抢占式插入）
                    if let Some(ids) = dept_ids {
                        user_dept_repo
                            .delete_admin_by_user_id_conn(txn, user_id)
                            .await?;
                        user_dept_repo
                            .upsert_admin_depts_conn(txn, user_id, ids)
                            .await?;
                    }

                    // 5. 审计合规域：UPDATE 变更留痕（同事务提交/回滚，失败令业务一并回滚；
                    //     敏感列 password 由 record_change 内部统一打码）
                    let after =
                        serde_json::to_value(&updated).unwrap_or(serde_json::Value::Null);
                    let audit_operator =
                        crate::service::sys_audit_change_service::resolve_operator(
                            txn,
                            Some(operator_user_id),
                            Some(operator_owned.as_str()),
                        )
                        .await;
                    crate::service::sys_audit_change_service::record_change(
                        txn,
                        "sys_user",
                        &updated.user_id.to_string(),
                        crate::service::sys_audit_change_service::ACTION_UPDATE,
                        Some(before_snapshot),
                        Some(after),
                        audit_operator,
                    )
                    .await?;
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
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        // 超管保护
        if user_id == SUPER_ADMIN_USER_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.admin_delete_forbidden"
            )));
        }

        let existing = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 越权防护：租户管理员不得跨租户删除用户
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        // 垂直越权校验（REGRESS-002）
        self.check_vertical_auth_by_user_id(operator_user_id, user_id)
            .await?;

        // 释放唯一字段值，避免软删除后唯一索引冲突（uk_sys_user_name）
        // 软删除记录仍占用 user_name 唯一索引，导致无法重新创建同名用户
        let deleted_user_name = format!("{}_deleted_{}", existing.user_name, user_id);

        // 审计合规域：变更前快照（必须在 existing 被 move 进事务闭包之前计算）
        let before_snapshot =
            serde_json::to_value(&existing).unwrap_or(serde_json::Value::Null);
        let user_repo = self.user_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let user_post_repo = self.user_post_repo.clone();
        let user_dept_repo = self.user_dept_repo.clone();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                async move {
                    // 1. 软删除 sys_user（通过 Repository）
                    let mut am: SysUserActiveModel = existing.into();
                    am.del_flag = Set(Some("2".to_string()));
                    am.user_name = Set(deleted_user_name);
                    user_repo.base().update_conn(txn, am).await?;

                    // 1.5 审计合规域：DELETE 变更留痕（同事务提交/回滚，失败令业务一并回滚；
                    //     after 传 None 表示行已删除；敏感列 password 由内部统一打码）
                    let audit_operator =
                        crate::service::sys_audit_change_service::resolve_operator(
                            txn,
                            Some(operator_user_id),
                            None, // delete_user 签名仅携带操作人 ID，用户名由回查补齐
                        )
                        .await;
                    crate::service::sys_audit_change_service::record_change(
                        txn,
                        "sys_user",
                        &user_id.to_string(),
                        crate::service::sys_audit_change_service::ACTION_DELETE,
                        Some(before_snapshot),
                        None,
                        audit_operator,
                    )
                    .await?;

                    // 2. 物理删除 sys_user_role 关联（通过 Repository）
                    user_role_repo.delete_by_user_id_conn(txn, user_id).await?;

                    // 3. 物理删除 sys_user_post 关联（SEC-005：补全孤儿记录清理）
                    user_post_repo.delete_by_user_id_conn(txn, user_id).await?;

                    // 3.5 多部门任职：物理删除兼职部门关联（孤儿记录清理）
                    user_dept_repo.delete_by_user_id_conn(txn, user_id).await?;

                    // 4. 物理删除 sys_notice_read 关联（清理已读记录，避免已读列表显示已删除用户）
                    SysNoticeRead::delete_many()
                        .filter(NoticeReadColumn::UserId.eq(user_id))
                        .exec(txn)
                        .await?;

                    // 5. E1-a：物理删除该用户全部 PAT（sys_pat 无 del_flag，硬删与同事务
                    //    既有清理风格一致；配合 verify_token 属主回查构成纵深防御，
                    //    杜绝被删用户的 PAT 仍可作为长期凭据访问 API）
                    SysPat::delete_many()
                        .filter(PatColumn::UserId.eq(user_id))
                        .exec(txn)
                        .await?;

                    // 6. E1-b：清理软删遗留——登录凭据（sys_user_credential，该表删除
                    //    惯例为物理删除）、消息偏好（sys_user_pref 无 del_flag）、
                    //    第三方身份绑定（sys_oauth_user 为硬删表）
                    SysUserCredential::delete_many()
                        .filter(UserCredentialColumn::UserId.eq(user_id))
                        .exec(txn)
                        .await?;
                    SysUserPref::delete_many()
                        .filter(UserPrefColumn::UserId.eq(user_id))
                        .exec(txn)
                        .await?;
                    SysOauthUser::delete_many()
                        .filter(OauthUserColumn::UserId.eq(user_id))
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
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        // 预校验：超管保护（事务外快速失败，避免无效事务开销）
        if user_ids.contains(&SUPER_ADMIN_USER_ID) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.admin_delete_forbidden"
            )));
        }

        // 单个 ID 直接走 delete_user（保持原有事务行为，避免嵌套事务开销）
        if user_ids.len() == 1 {
            return self
                .delete_user(user_ids[0], operator_user_id, operator_tid)
                .await;
        }

        // C-2：批量垂直越权校验（事务前统一执行，全部通过后才进入事务）
        //      与 delete_user 的 check_vertical_auth_by_user_id 行为一致，
        //      避免 handler 层 for 循环调用 delete_user 时漏校验的安全漏洞。
        for target_user_id in &user_ids {
            self.check_vertical_auth_by_user_id(operator_user_id, *target_user_id)
                .await?;
            // 越权防护：租户管理员不得跨租户删除用户（按 id 列表删除必须逐个收敛归属）
            if let Some(target) = self.user_repo.base().find_by_id(*target_user_id).await?
                && !crate::common::tenant::tenant_allowed(operator_tid, target.tenant_id)
            {
                return Err(ServiceError::forbidden(&crate::tr!(
                    "error.common.forbidden"
                )));
            }
        }

        // 批量删除：单个事务包装所有操作
        let user_repo = self.user_repo.clone();
        let user_role_repo = self.user_role_repo.clone();
        let user_post_repo = self.user_post_repo.clone();
        let user_dept_repo = self.user_dept_repo.clone();
        let db = self.db().clone();

        db.transaction::<_, (), sea_orm::DbErr>(|txn| {
            async move {
                for user_id in user_ids {
                    // 1. 查询用户存在性（事务内，防止 TOCTOU）
                    let existing = user_repo
                        .base()
                        .find_by_id_conn(txn, user_id)
                        .await?
                        .ok_or_else(|| {
                            sea_orm::DbErr::Custom(format!(
                                "{}: {}",
                                crate::tr!("error.user.not_found"),
                                user_id
                            ))
                        })?;
                    if existing.del_flag.as_deref() == Some("2") {
                        return Err(sea_orm::DbErr::Custom(format!(
                            "{}: {}",
                            crate::tr!("error.user.not_found"),
                            user_id
                        )));
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

                    // 7. 多部门任职：物理删除兼职部门关联（孤儿记录清理）
                    user_dept_repo.delete_by_user_id_conn(txn, user_id).await?;

                    // 8. E1-a/E1-b：与 delete_user 同口径清理——PAT（无 del_flag 硬删）、
                    //    登录凭据、消息偏好、第三方绑定、公告已读记录
                    SysPat::delete_many()
                        .filter(PatColumn::UserId.eq(user_id))
                        .exec(txn)
                        .await?;
                    SysUserCredential::delete_many()
                        .filter(UserCredentialColumn::UserId.eq(user_id))
                        .exec(txn)
                        .await?;
                    SysUserPref::delete_many()
                        .filter(UserPrefColumn::UserId.eq(user_id))
                        .exec(txn)
                        .await?;
                    SysOauthUser::delete_many()
                        .filter(OauthUserColumn::UserId.eq(user_id))
                        .exec(txn)
                        .await?;
                    SysNoticeRead::delete_many()
                        .filter(NoticeReadColumn::UserId.eq(user_id))
                        .exec(txn)
                        .await?;
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
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // R19-1.3：密码复杂度校验（拦截纯数字/纯字母等弱口令）
        validate_password_complexity(&dto.password).map_err(|e| ServiceError::bad_request(&e))?;

        // 超管保护：禁止重置超级管理员密码
        if dto.user_id == SUPER_ADMIN_USER_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.admin_pwd_forbidden"
            )));
        }

        let existing = self
            .user_repo
            .base()
            .find_by_id(dto.user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 越权防护：租户管理员不得跨租户重置用户密码
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
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
        // B4（m20261004_000003）：管理员重置密码 = 下发新初始密码，
        // 标志置回 '1'（用户下次登录被强制改密——开关开启时）
        am.must_change_pwd = Set(Some("1".to_string()));
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
        validate_password_complexity(&dto.new_password)
            .map_err(|e| ServiceError::bad_request(&e))?;

        // 新旧密码不能相同
        if dto.old_password == dto.new_password {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.same_password"
            )));
        }

        let existing = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
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
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.auth.old_password_wrong"
            )));
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
        // B4（m20261004_000003）：个人改密成功即清除强制首登改密标志
        // （所有个人改密路径统一经由本函数，标志自然收敛）
        am.must_change_pwd = Set(Some("0".to_string()));
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
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        // R6-VAL-17：状态必须为已登记枚举（"0"=正常 / "1"=停用）。
        // 该接口的 status 直接来自请求体字符串，此前**原样写库**——非法值（如 "9"）会让
        // 「按 status 判定账号可用性」的既有口径失效（登录、列表过滤、统计各判一套）。
        // 注意：本接口是「显式设置状态」，故空串同样属非法（不能像表单那样当作"未提供"）。
        let status = normalize_user_status(Some(status.to_string()))?
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.user.status_invalid")))?;
        let status = status.as_str();

        // 超管保护
        if user_id == SUPER_ADMIN_USER_ID && status == "1" {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.admin_disable_forbidden"
            )));
        }

        let existing = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 越权防护：租户管理员不得跨租户启停用户
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
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
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        // 超管保护：禁止修改超级管理员角色绑定
        if user_id == SUPER_ADMIN_USER_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.admin_role_forbidden"
            )));
        }

        // 垂直越权校验（P0-R81-005 / REGRESS-002）：待分配角色不得高于 operator
        self.check_vertical_auth_by_role_ids(operator_user_id, &role_ids)
            .await?;

        // 垂直越权校验（P0-H3）：目标用户当前角色不得高于 operator，防止降级高权限用户
        self.check_vertical_auth_by_user_id(operator_user_id, user_id)
            .await?;

        let existing = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 越权防护：租户管理员不得跨租户为用户分配角色
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        // 越权防护（第十批 MT-2 复核发现）：**被授角色本身**也须与 operator 同租户。
        // 原先只校验"目标用户归属"（上一段），漏校验"角色归属"——而 `add_user`/`edit_user`
        // 两条同类路径都已校验（`ensure_roles_tenant_allowed`）⇒ 本路径是唯一缺口：
        // 租户操作者可借此把**平台角色或他租户角色**授给本租户用户，该用户随即按该角色的
        // `sys_role_menu` 获得授权面（跨租户提权 / 越界可见）。
        self.ensure_roles_tenant_allowed(operator_tid, Some(&role_ids))
            .await?;

        let user_role_repo = self.user_role_repo.clone();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let role_ids = role_ids.clone();
                async move {
                    // 先删除旧关联（通过 Repository；v5-D12 Group：仅删管理员手授行
                    // source='admin'，保留 SCIM 组联动行——消除回写抖动）
                    user_role_repo
                        .delete_admin_by_user_id_conn(txn, user_id)
                        .await?;
                    // 再写入新关联（幂等抢占式：scim 已有行抢占为 admin，防撞唯一约束）
                    user_role_repo
                        .upsert_admin_grants_conn(txn, user_id, role_ids)
                        .await?;
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

    /// 按用户 ID 查询未删除用户（del_flag = '0'），OAuth 绑定校验用
    ///
    /// 返回 None 包含两种语义：用户不存在 / 用户已软删除。
    pub async fn get_active_user_by_username_by_id(
        &self,
        user_id: i64,
    ) -> Result<Option<SysUserModel>, ServiceError> {
        let user = self.user_repo.find_active_by_user_id(user_id).await?;
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
        let existing = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
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
        let existing = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        // P2 修复: 保存旧 avatar 路径，供 handler 删除旧文件，避免文件系统泄漏
        let old_avatar = existing.avatar.clone();
        let mut am: SysUserActiveModel = existing.into();
        am.avatar = Set(Some(avatar_path.to_string()));
        self.user_repo.update(am).await?;
        Ok(old_avatar)
    }

    /// 根据 user_id 查询用户所属部门名称（用于在线会话填充 dept_name）
    ///
    /// 流程：sys_user.dept_id → sys_dept.dept_name
    /// 用户或部门不存在/已删除时返回空字符串（不阻断登录流程）
    pub async fn get_dept_name_by_user_id(&self, user_id: i64) -> Result<String, ServiceError> {
        let user = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
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
    /// 多租户：`tenant_scope` 透传至角色查询，避免跨租户枚举他人角色。
    pub async fn get_auth_role(
        &self,
        user_id: i64,
        operator_user_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<UserAuthRoleVo, ServiceError> {
        // 超管用户保护：禁止查看超管用户的授权信息（防止信息收集）
        if user_id == SUPER_ADMIN_USER_ID && operator_user_id != SUPER_ADMIN_USER_ID {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.user.admin_role_forbidden"
            )));
        }

        // 垂直越权校验：operator 不得查看比自己更高优先级用户的授权信息
        self.check_vertical_auth_by_user_id(operator_user_id, user_id)
            .await?;

        let user = self
            .user_repo
            .base()
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.user.not_found")))?;
        if user.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.user.not_found")));
        }

        // 查询全部未删除角色（通过 Repository，按租户过滤；前端根据 user.roleIds 自行标记已勾选）
        let all_roles: Vec<SysRoleModel> = self.role_repo.find_active_all(tenant_scope).await?;

        // M1 脱敏影响面补齐（字段级权限 M2 登记）：authRole VO 内嵌 user 的
        // phonenumber/email 按三口径掩码（本人查自己 / 超管 → 原值；其它 → 掩码）。
        // 口径与 get_user_form_data 一致：本接口是**编辑回显面**（前端勾选角色时
        // 带出用户信息），不参与 M2 列表裁剪，但掩码必须补齐——此前该出口裸奔原值。
        let mut user = user;
        let op_is_super = self.viewer_is_super(operator_user_id).await;
        if should_mask_pii(Some(operator_user_id), user.user_id, op_is_super) {
            mask_user_pii_in_place(&mut user);
        }

        Ok(UserAuthRoleVo {
            user,
            roles: all_roles,
        })
    }

    // ==================== 内部辅助方法 ====================

    /// 批量导入用户（B3）
    ///
    /// 流程：解析 xlsx → 逐行结构校验（纯函数）→ 唯一性 / 部门存在性校验
    /// → 事务内批量写入。任一行失败不中断整批，仅将该行计入 error_list 回显前端。
    pub async fn import_users(
        &self,
        xlsx_bytes: Vec<u8>,
        update_support: bool,
        operator: &str,
        operator_tid: i64,
        default_password: &str,
    ) -> Result<ImportResultVo, ServiceError> {
        use crate::common::excel::read_xlsx_rows;
        use std::collections::{HashMap, HashSet};

        let raw_rows =
            read_xlsx_rows(&xlsx_bytes).map_err(|e| ServiceError::bad_request(&e.message))?;
        let parsed = parse_import_rows(&raw_rows);

        let mut error_list: Vec<ImportErrorItem> = Vec::new();
        let mut valid_rows: Vec<ImportUserRow> = Vec::new();

        // 阶段 1：结构校验（纯函数，不触库）
        for row in parsed {
            if let Err(e) = validate_import_row(&row) {
                error_list.push(ImportErrorItem {
                    row_num: row.row_num,
                    error: e,
                });
            } else {
                valid_rows.push(row);
            }
        }
        if valid_rows.is_empty() {
            return Ok(ImportResultVo {
                success: 0,
                error_list,
            });
        }

        // 阶段 2：批量收集需要查询的部门名 / 登录名，一次性读取减少 RTT
        let dept_names: HashSet<String> = valid_rows
            .iter()
            .filter_map(|r| r.dept_name.as_deref().map(str::trim))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let login_names: HashSet<String> = valid_rows
            .iter()
            .map(|r| r.login_name.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // 部门名(trim) → (dept_id, tenant_id)（仅取未删除且精确同名）
        // 多租户 Phase 2：租户归属单一来源 = sys_dept.tenant_id，随部门一次读回避免逐行查库
        let mut dept_map: HashMap<String, (i64, i64)> = HashMap::new();
        for name in &dept_names {
            if let Some(dept) = self
                .dept_repo
                .find_by_name_like(name)
                .await?
                .into_iter()
                .find(|d| d.dept_name.trim() == name.trim() && d.del_flag.as_deref() != Some("2"))
            {
                dept_map.insert(name.clone(), (dept.dept_id, dept.tenant_id));
            }
        }

        // 登录名 → 是否已存在（复用既有的"含软删除"查询，避免恢复后冲突）
        let mut existing_users: HashMap<String, SysUserModel> = HashMap::new();
        for name in &login_names {
            if let Some(u) = self.user_repo.find_active_by_user_name(name).await? {
                existing_users.insert(u.user_name.clone(), u);
            }
        }

        // 阶段 3：逐行做唯一性/部门/状态解析，生成待插入 DTO 或累积错误
        // update_support=true 时，已存在的用户走更新（仅更新资料字段，不重置密码/角色）
        #[derive(Clone)]
        struct PendingInsert {
            row_num: u32,
            dept_id: Option<i64>,
            tenant_id: i64,
            user_name: String,
            nick_name: String,
            phonenumber: Option<String>,
            email: Option<String>,
            sex: Option<String>,
            status: String,
        }
        let mut to_insert: Vec<PendingInsert> = Vec::new();
        let mut to_update: Vec<(i64, PendingInsert)> = Vec::new();
        let mut seen_login: HashSet<String> = HashSet::new();

        for row in valid_rows {
            let login = row.login_name.trim().to_string();
            // 批内重复登录名：仅保留首行，其余报错
            if !seen_login.insert(login.clone()) {
                error_list.push(ImportErrorItem {
                    row_num: row.row_num,
                    error: crate::tr!("error.user.import_duplicate_in_file"),
                });
                continue;
            }
            let (dept_id, row_tenant_id) = match row
                .dept_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(name) => match dept_map.get(name) {
                    Some((id, tid)) => (Some(*id), *tid),
                    None => {
                        error_list.push(ImportErrorItem {
                            row_num: row.row_num,
                            error: crate::tr!("error.user.import_dept_not_found", name = name),
                        });
                        continue;
                    }
                },
                // 无部门 → 平台租户 0（平台用户）
                None => (None, 0),
            };
            // 越权防护：该行归属租户必须与 operator 同租户，否则仅该行失败、不中断整批
            if !crate::common::tenant::tenant_allowed(operator_tid, row_tenant_id) {
                error_list.push(ImportErrorItem {
                    row_num: row.row_num,
                    error: crate::tr!("error.common.forbidden"),
                });
                continue;
            }

            let pending = PendingInsert {
                row_num: row.row_num,
                dept_id,
                tenant_id: row_tenant_id,
                user_name: login.clone(),
                nick_name: row.nick_name.trim().to_string(),
                phonenumber: row
                    .phonenumber
                    .as_deref()
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty()),
                email: row
                    .email
                    .as_deref()
                    .map(|e| e.trim().to_string())
                    .filter(|e| !e.is_empty()),
                sex: row.sex,
                status: row.status,
            };

            if let Some(existing) = existing_users.get(&login) {
                if update_support {
                    // 跨租户更新防护：已存在用户归属租户必须与本行目标租户一致，
                    // 否则拒绝该行（禁止借批量导入把其它租户的用户"搬运"到本租户）
                    if existing.tenant_id != row_tenant_id {
                        error_list.push(ImportErrorItem {
                            row_num: row.row_num,
                            error: crate::tr!("error.user.name_duplicate"),
                        });
                        continue;
                    }
                    to_update.push((existing.user_id, pending));
                } else {
                    error_list.push(ImportErrorItem {
                        row_num: row.row_num,
                        error: crate::tr!("error.user.name_duplicate"),
                    });
                }
            } else {
                to_insert.push(pending);
            }
        }

        // 阶段 4：事务内批量写入（插入新用户 + 更新已存在用户资料）
        // 密码 hash 为 CPU 密集型同步操作，先行一次阿甘 hash 经 spawn_blocking 完成，
        // 结果在事务内复用（所有新用户共享同一初始密码 hash），避免阻塞 Tokio worker。
        let password_for_hash = default_password.to_string();
        let hashed = tokio::task::spawn_blocking(move || encrypt_password(&password_for_hash))
            .await
            .map_err(|e| {
                tracing::error!("密码加密 spawn_blocking 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.password_encrypt_failed"))
            })??;
        let inserted_count = {
            let user_repo = self.user_repo.clone();
            let tenant_service = self.tenant_service.clone();
            let now = crate::common::datetime::now_naive();
            let created_by = operator.to_string();
            self.db()
                .transaction::<_, (i64, Vec<ImportErrorItem>), sea_orm::DbErr>(|txn| {
                    let to_insert = to_insert.clone();
                    let mut to_update = to_update.clone();
                    let hashed = hashed.clone();
                    async move {
                        let mut count = 0i64;
                        let mut quota_errors: Vec<ImportErrorItem> = Vec::new();

                        // 多租户配额（§27.4）：按租户分组，每组仅加锁/计数一次；
                        // 超限行不落库、逐行回显错误（不中断整批导入）。
                        let mut groups: Vec<(i64, Vec<PendingInsert>)> = Vec::new();
                        for p in to_insert {
                            match groups.iter_mut().find(|(tid, _)| *tid == p.tenant_id) {
                                Some((_, rows)) => rows.push(p),
                                None => groups.push((p.tenant_id, vec![p])),
                            }
                        }

                        for (tid, rows) in groups {
                            let availability = tenant_service
                                .lock_and_available_quota_txn(txn, tid)
                                .await?;
                            let (remaining, limit, unavailable) = match availability {
                                crate::service::sys_tenant_service::TenantQuotaAvailability::Unlimited => {
                                    (usize::MAX, 0u64, false)
                                }
                                crate::service::sys_tenant_service::TenantQuotaAvailability::Limited {
                                    limit,
                                    remaining,
                                } => (remaining as usize, limit, false),
                                crate::service::sys_tenant_service::TenantQuotaAvailability::Unavailable => {
                                    (0, 0, true)
                                }
                            };
                            for (idx, p) in rows.into_iter().enumerate() {
                                if unavailable {
                                    quota_errors.push(ImportErrorItem {
                                        row_num: p.row_num,
                                        error: crate::tr!("error.tenant.disabled"),
                                    });
                                    continue;
                                }
                                if idx >= remaining {
                                    quota_errors.push(ImportErrorItem {
                                        row_num: p.row_num,
                                        error: crate::tr!(
                                            "error.tenant.account_quota_exceeded",
                                            max = limit
                                        ),
                                    });
                                    continue;
                                }
                                let am = SysUserActiveModel {
                                    dept_id: Set(p.dept_id),
                                    tenant_id: Set(p.tenant_id),
                                    user_name: Set(p.user_name),
                                    nick_name: Set(p.nick_name),
                                    phonenumber: Set(p.phonenumber),
                                    email: Set(p.email),
                                    sex: Set(p.sex),
                                    password: Set(Some(hashed.clone())),
                                    status: Set(Some(p.status)),
                                    del_flag: Set(Some("0".to_string())),
                                    create_by: Set(Some(created_by.clone())),
                                    create_time: Set(Some(now)),
                                    update_by: Set(Some(created_by.clone())),
                                    update_time: Set(Some(now)),
                                    ..Default::default()
                                };
                                user_repo.base().insert_conn(txn, am).await?;
                                count += 1;
                            }
                        }
                        for (user_id, p) in to_update.drain(..) {
                            let am = SysUserActiveModel {
                                user_id: Set(user_id),
                                dept_id: Set(p.dept_id),
                                tenant_id: Set(p.tenant_id),
                                nick_name: Set(p.nick_name),
                                phonenumber: Set(p.phonenumber),
                                email: Set(p.email),
                                sex: Set(p.sex),
                                status: Set(Some(p.status)),
                                update_by: Set(Some(created_by.clone())),
                                update_time: Set(Some(now)),
                                ..Default::default()
                            };
                            user_repo.base().update_conn(txn, am).await?;
                            count += 1;
                        }
                        Ok((count, quota_errors))
                    }
                    .boxed()
                })
                .await?
        };
        let (inserted_count, quota_errors) = inserted_count;
        error_list.extend(quota_errors);

        Ok(ImportResultVo {
            success: inserted_count as u32,
            error_list,
        })
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- R6-VAL-16 / R6-VAL-17：性别 / 状态归一化 + 枚举校验 ----------
    //
    // 可证伪性：修复前 `dto.sex` / `dto.status` 是 `#[garde(skip)]` 自由字符串并被**原样写库**，
    // 故下列"非法值必须 400"的断言在旧实现下不可能通过（旧实现没有这条校验路径）。

    #[test]
    fn test_normalize_sex_accepts_registered_enum_only() {
        for ok in ["0", "1", "2"] {
            assert_eq!(
                normalize_sex(Some(ok.to_string())).expect("已登记取值应放行"),
                Some(ok.to_string())
            );
        }
        // 空 / 纯空白 / None ⇒ 视为"未提供"（不写库）
        assert_eq!(normalize_sex(None).unwrap(), None);
        assert_eq!(normalize_sex(Some(String::new())).unwrap(), None);
        assert_eq!(normalize_sex(Some("   ".to_string())).unwrap(), None);
        // 两端空白应被 trim 后判定（" 1 " ⇒ Some("1")）
        assert_eq!(
            normalize_sex(Some(" 1 ".to_string())).unwrap(),
            Some("1".to_string())
        );
        // 非法取值一律 400
        for bad in ["9", "male", "M", "男", "-1", "0.0"] {
            let err = normalize_sex(Some(bad.to_string()))
                .expect_err(&format!("{bad:?} 非法取值必须被拒绝"));
            assert_eq!(err.code, 400, "{bad:?} 应返回 400");
        }
    }

    /// R6-VAL-13 复核：`nick_name` 是 `Option<String>` 且带 `#[garde(length(min = 2, max = 30))]`，
    /// 而 garde 对 `Option<T>` 的规则作用于**内层值**（`impl<T: Validate> Validate for Option<T>` 委托内层）
    /// ⇒ `Some("")` 会被 `length(min = 2)` 拦下（400），**并不会**"空串直接入库"。
    /// 本用例把该语义固化为可证伪断言（若未来有人误把规则改成只校验外层，这条会变红）。
    #[test]
    fn test_user_dto_rejects_empty_nick_name() {
        let dto = UserAddDto {
            dept_id: None,
            user_name: "it_nick_check".to_string(),
            nick_name: String::new(),
            email: None,
            phonenumber: None,
            country_code: None,
            sex: Some("0".to_string()),
            password: "Abcd1234".to_string(),
            status: Some("0".to_string()),
            role_ids: None,
            post_ids: None,
            dept_ids: None,
            remark: None,
        };
        assert!(
            crate::common::i18n::validate(&dto).is_err(),
            "nick_name 传空串必须被 garde 拒绝（Option 规则作用于内层值）"
        );
    }

    #[test]
    fn test_normalize_user_status_accepts_registered_enum_only() {
        for ok in ["0", "1"] {
            assert_eq!(
                normalize_user_status(Some(ok.to_string())).expect("已登记取值应放行"),
                Some(ok.to_string())
            );
        }
        assert_eq!(normalize_user_status(None).unwrap(), None);
        assert_eq!(normalize_user_status(Some("".to_string())).unwrap(), None);
        for bad in ["2", "9", "enabled", "正常", "-1"] {
            let err = normalize_user_status(Some(bad.to_string()))
                .expect_err(&format!("{bad:?} 非法取值必须被拒绝"));
            assert_eq!(err.code, 400, "{bad:?} 应返回 400");
        }
    }

    fn row(
        login: &str,
        nick: &str,
        dept: &str,
        phone: &str,
        email: &str,
        sex: &str,
        status: &str,
    ) -> ImportUserRow {
        ImportUserRow {
            row_num: 1,
            login_name: login.to_string(),
            nick_name: nick.to_string(),
            dept_name: (!dept.is_empty()).then(|| dept.to_string()),
            phonenumber: (!phone.is_empty()).then(|| phone.to_string()),
            email: (!email.is_empty()).then(|| email.to_string()),
            sex: Some(sex.to_string()),
            status: status.to_string(),
        }
    }

    #[test]
    fn parse_import_rows_skips_header_and_blanks() {
        let rows = vec![
            vec!["登录名称".to_string(), "用户姓名".to_string()],
            vec!["zhangsan".to_string(), "张三".to_string()],
            vec!["".to_string(), "".to_string()], // 空行应跳过
            vec!["lisi".to_string(), "李四".to_string()],
        ];
        let parsed = parse_import_rows(&rows);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].login_name, "zhangsan");
        // row_num 为物理行号（含表头行）：表头=1，张三=2，跳过空行，李四=4
        assert_eq!(parsed[1].row_num, 4);
    }

    #[test]
    fn parse_import_rows_maps_sex_and_status() {
        let rows = vec![
            vec![
                "登录名称".to_string(),
                "用户姓名".to_string(),
                "部门".to_string(),
                "手机".to_string(),
                "邮箱".to_string(),
                "性别".to_string(),
                "状态".to_string(),
            ],
            vec![
                "a".to_string(),
                "A".to_string(),
                "研发部".to_string(),
                "13800138000".to_string(),
                "a@x.com".to_string(),
                "男".to_string(),
                "停用".to_string(),
            ],
            vec![
                "b".to_string(),
                "B".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "0".to_string(),
                "1".to_string(),
            ],
        ];
        let parsed = parse_import_rows(&rows);
        assert_eq!(parsed[0].sex.as_deref(), Some("0"));
        assert_eq!(parsed[0].status, "1");
        assert_eq!(parsed[0].dept_name.as_deref(), Some("研发部"));
        // 数字 "0" / "1" 同样被识别
        assert_eq!(parsed[1].sex.as_deref(), Some("0"));
        assert_eq!(parsed[1].status, "1");
        assert_eq!(parsed[1].dept_name, None);
    }

    #[test]
    fn validate_import_row_rejects_bad_login_and_missing_nick() {
        let cases: &[(&str, &str)] = &[
            ("", "张三"),        // 空登录名
            ("a", "张三"),       // 过短
            ("合法_名", "张三"), // 含非法字符（中文/点）
        ];
        for (login, nick) in cases {
            let r = row(login, nick, "", "", "", "", "");
            assert!(validate_import_row(&r).is_err(), "应拒绝 login={login}");
        }
        // 缺昵称
        let r = row("zhangsan", "", "", "", "", "", "");
        assert!(validate_import_row(&r).is_err());
    }

    #[test]
    fn validate_import_row_accepts_valid_and_rejects_bad_phone_email() {
        let ok = row(
            "zhangsan",
            "张三",
            "研发部",
            "13800138000",
            "a@example.com",
            "男",
            "0",
        );
        assert!(validate_import_row(&ok).is_ok());

        let bad_phone = row("lisi", "李四", "", "not-a-phone", "", "", "0");
        assert!(validate_import_row(&bad_phone).is_err());

        let bad_email = row("wangwu", "王五", "", "", "not-an-email", "", "0");
        assert!(validate_import_row(&bad_email).is_err());
    }

    // ---------- 字段级权限 M1：PII 掩码三口径（纯函数单测） ----------

    /// 口径 1：本人查自己 → 原值（不掩码）
    #[test]
    fn should_mask_pii_self_view_is_plain() {
        assert!(!should_mask_pii(Some(9001), 9001, false));
    }

    /// 口径 2：超管（含 user_id==1 与 `*:*:*` 角色两种来源）看任何人都原值
    #[test]
    fn should_mask_pii_super_view_is_plain() {
        assert!(!should_mask_pii(Some(9002), 9001, true));
        // user_id==1 在 is_super_viewer 中短路为超管，此处验证标志位路径
        assert!(!should_mask_pii(Some(SUPER_ADMIN_USER_ID), 9999, true));
    }

    /// 口径 3：其它 operator 查任何人都掩码；无操作者上下文 fail-closed 也掩码
    #[test]
    fn should_mask_pii_other_and_missing_operator_are_masked() {
        assert!(should_mask_pii(Some(9002), 9001, false));
        assert!(should_mask_pii(None, 9001, false));
        // 注：(None, _, true) 组合在真实调用中不可能出现——op_is_super 仅在
        // operator_user_id 为 Some 时才可能为 true，此处不为其固化行为
    }

    /// is_super_viewer：user_id==1 短路 + 平台超管角色（is_system && tid==0）
    /// 判定与非平台超管角色（is_system 但 tid!=0、或 tid==0 但非 is_system）不误判
    #[test]
    fn is_super_viewer_matches_role_source_of_wildcard_perm() {
        // user_id==1（内置 admin）：无条件超管视角
        assert!(is_super_viewer(SUPER_ADMIN_USER_ID, &[]));

        // 平台超管角色：is_system=true 且 tenant_id==0（*:*:* 的唯一角色来源）
        let mut platform_super = minimal_role();
        platform_super.is_system = true;
        platform_super.tenant_id = 0;
        assert!(is_super_viewer(9001, &[platform_super.clone()]));

        // is_system 但非平台租户：不构成超管视角
        let mut system_other_tenant = minimal_role();
        system_other_tenant.is_system = true;
        system_other_tenant.tenant_id = 9010;
        assert!(!is_super_viewer(9001, &[system_other_tenant]));

        // 平台租户但非 is_system：不构成超管视角
        let mut platform_normal = minimal_role();
        platform_normal.is_system = false;
        platform_normal.tenant_id = 0;
        assert!(!is_super_viewer(9001, &[platform_normal]));
    }

    /// 构造最小可用 SysRoleModel（其余字段取工程默认语义的安全值）
    fn minimal_role() -> SysRoleModel {
        SysRoleModel {
            tenant_id: 0,
            role_id: 9001,
            role_name: "it_role".to_string(),
            role_key: "it_role_key".to_string(),
            role_sort: 0,
            data_scope: Some("1".to_string()),
            custom_sql: None,
            menu_check_strictly: None,
            dept_check_strictly: None,
            status: "0".to_string(),
            is_system: false,
            del_flag: Some("0".to_string()),
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
        }
    }

    /// 构造最小可用 SysUserModel（与 entity 单测同款完整构造，Model 未派生 Default）
    fn minimal_user(user_id: i64) -> SysUserModel {
        SysUserModel {
            user_id,
            dept_id: None,
            user_name: format!("it_user_{user_id}"),
            nick_name: "IT".to_string(),
            user_type: None,
            email: None,
            phonenumber: None,
            country_code: None,
            sex: None,
            avatar: None,
            password: None,
            status: Some("0".to_string()),
            del_flag: Some("0".to_string()),
            must_change_pwd: Some("0".to_string()),
            login_ip: None,
            login_date: None,
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
            tenant_id: 0,
            scim_external_id: None,
        }
    }

    /// 掩码应用：phonenumber/email 就地变为掩码形态（含 `*`），None 字段保持 None
    #[test]
    fn mask_user_pii_in_place_masks_phone_and_email_only() {
        let mut model = minimal_user(9001);
        model.email = Some("alice@example.com".to_string());
        model.phonenumber = Some("13812345678".to_string());
        mask_user_pii_in_place(&mut model);
        assert_eq!(model.phonenumber.as_deref(), Some("138****5678"));
        assert_eq!(model.email.as_deref(), Some("a****@example.com"));
        // 其余字段不受影响
        assert_eq!(model.user_name, "it_user_9001");

        // None 字段：保持 None，不产生空串掩码
        let mut empty = minimal_user(9002);
        mask_user_pii_in_place(&mut empty);
        assert!(empty.phonenumber.is_none());
        assert!(empty.email.is_none());
    }

    /// 掩码形态值可被 is_masked 识别（edit_user 剥离逻辑的判据）
    #[test]
    fn masked_values_are_recognizable_for_edit_skip() {
        assert!(masking::is_masked("138****5678"));
        assert!(masking::is_masked("a****@example.com"));
        // 真实值不含 *：不会误伤正常提交
        assert!(!masking::is_masked("13812345678"));
        assert!(!masking::is_masked("alice@example.com"));
    }
}

