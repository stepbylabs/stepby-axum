//! sys_user 实体定义（用户信息表）

use std::fmt;

use chrono::NaiveDateTime;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

/// 注意：不 derive(Debug)，改用手动实现以脱敏 password 字段
#[derive(Clone, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_user")]
#[serde(rename_all = "camelCase")]
#[ts(
    export,
    rename = "SysUser",
    export_to = "SysUser.ts",
    rename_all = "camelCase"
)]
#[schema(as = SysUser)]
pub struct Model {
    #[sea_orm(primary_key)]
    pub user_id: i64,
    pub dept_id: Option<i64>,
    #[sea_orm(unique)]
    pub user_name: String,
    pub nick_name: String,
    pub user_type: Option<String>,
    pub email: Option<String>,
    pub phonenumber: Option<String>,
    /// 手机号国家/地区代码（ISO 3166-1 alpha-2，如 CN/HK/US）。
    /// 方案 D（G18）手机号多地区化：None 视为回退 CN。
    pub country_code: Option<String>,
    pub sex: Option<String>,
    pub avatar: Option<String>,
    #[serde(skip_serializing)]
    #[ts(skip)]
    pub password: Option<String>,
    pub status: Option<String>,
    pub del_flag: Option<String>,
    /// 强制首登改密标志（B4，m20261004_000003）：'1' = 初始密码未修改；
    /// 个人中心改密成功即清除；仅当 config 开关 `sys.user.forceFirstLoginChangePwd`
    /// 开启时驱动前端强制改密流程（标志计算见 auth_service.is_default_modify_pwd）
    pub must_change_pwd: Option<String>,
    /// 口令**最后一次真实变更**的时刻（批八十四 项 A，迁移 `m20261022_000001`）。
    ///
    /// 为什么不能复用 `update_time`：`impl_timestamped_active_model!` 在**任何**更新上刷新它
    /// （改昵称、传头像、软删都动），拿它当口令年龄等于"改一次资料就把过期时钟归零"。
    /// 写入路径见 `service::pwd_policy::PWD_UPDATE_TIME_WRITE_SITES`；
    /// `upgrade_password_hash`（MD5→Argon2 静默换哈希、口令未变）**刻意不刷新**。
    /// 对外不下发（与 `password` 同口径 `skip_serializing`）：过期判定由服务端在 `/getInfo`
    /// 算成 `isPasswordExpired` / `mustChangePassword` 两个布尔后下发，前端只消费不推断。
    #[serde(skip_serializing, deserialize_with = "datetime::deserialize_opt")]
    #[ts(skip)]
    pub pwd_update_time: Option<NaiveDateTime>,
    pub login_ip: Option<String>,
    #[serde(
        serialize_with = "datetime::serialize_opt",
        deserialize_with = "datetime::deserialize_opt"
    )]
    #[ts(as = "Option<String>")]
    pub login_date: Option<NaiveDateTime>,
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
    /// v5-N2 Phase 2（第一步）：租户 ID（登录 JWT 的 tid 数据源；默认 0 = 平台单租户，
    /// 多租户立项后由租户管理功能维护；Phase 2 后续：Repository 过滤层按 tid 注入条件）
    #[serde(default)]
    pub tenant_id: i64,
    /// v5-D12：SCIM externalId（IdP 侧用户唯一标识；NULL = 非 SCIM provision）。
    ///
    /// 唯一性由迁移 `m20260925_000004` 的复合唯一索引
    /// `uk_sys_user_tenant_scim (tenant_id, scim_external_id)` 承担（同租户内唯一），
    /// 已取代旧的全局单列索引 `idx_sys_user_scim_external_id`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scim_external_id: Option<String>,
}

/// 手动实现 Debug 以脱敏 password 字段，防止密码哈希泄漏到日志
impl fmt::Debug for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("sys_user::Model")
            .field("user_id", &self.user_id)
            .field("dept_id", &self.dept_id)
            .field("user_name", &self.user_name)
            .field("nick_name", &self.nick_name)
            .field("user_type", &self.user_type)
            .field("email", &self.email)
            .field("phonenumber", &self.phonenumber)
            .field("country_code", &self.country_code)
            .field("sex", &self.sex)
            .field("avatar", &self.avatar)
            .field("password", &"<redacted>")
            .field("status", &self.status)
            .field("del_flag", &self.del_flag)
            // 强改密姿态两字段进 Debug（排障要判"为什么这个人被拦"）：只打印标志与时刻，
            // 不含口令任何派生物；哈希仍由上一行的 <redacted> 通道守住。
            .field("must_change_pwd", &self.must_change_pwd)
            .field("pwd_update_time", &self.pwd_update_time)
            .field("login_ip", &self.login_ip)
            .field("login_date", &self.login_date)
            .field("create_by", &self.create_by)
            .field("create_time", &self.create_time)
            .field("update_by", &self.update_by)
            .field("update_time", &self.update_time)
            .field("remark", &self.remark)
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

crate::impl_timestamped_active_model!();

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 sys_user::Model Debug 输出不泄漏 password 哈希
    #[test]
    fn test_user_model_debug_redacts_password() {
        let user = Model {
            user_id: 1,
            dept_id: Some(100),
            user_name: "admin".to_string(),
            nick_name: "Administrator".to_string(),
            user_type: Some("00".to_string()),
            email: Some("admin@example.com".to_string()),
            phonenumber: Some("13800138000".to_string()),
            country_code: None,
            sex: Some("0".to_string()),
            avatar: Some("/avatar/admin.png".to_string()),
            password: Some("$argon2id$v=19$m=65536,t=3,p=4$abc123hash".to_string()),
            status: Some("0".to_string()),
            del_flag: Some("0".to_string()),
            must_change_pwd: Some("0".to_string()),
            pwd_update_time: None,
            login_ip: Some("127.0.0.1".to_string()),
            login_date: None,
            create_by: Some("admin".to_string()),
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
            tenant_id: 0,
            scim_external_id: None,
        };

        let debug_str = format!("{:?}", user);

        // 密码哈希不应出现在 Debug 输出中
        assert!(
            !debug_str.contains("argon2id"),
            "Password hash leaked in Debug output"
        );
        assert!(
            !debug_str.contains("abc123hash"),
            "Password hash salt leaked in Debug output"
        );

        // 脱敏标记应存在
        assert!(
            debug_str.contains("<redacted>"),
            "Redacted marker missing for password field"
        );

        // 非敏感字段应正常输出
        assert!(
            debug_str.contains("admin"),
            "Non-sensitive username should be visible"
        );
        assert!(
            debug_str.contains("Administrator"),
            "Non-sensitive nick_name should be visible"
        );
    }
}
