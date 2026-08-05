//! sys_user 实体定义（用户信息表）

use std::fmt;

use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;
use sea_orm::Set;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use utoipa::ToSchema;

use crate::common::datetime;

/// 注意：不 derive(Debug)，改用手动实现以脱敏 password 字段
#[derive(Clone, PartialEq, DeriveEntityModel, Serialize, Deserialize, TS, ToSchema)]
#[sea_orm(table_name = "sys_user")]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "SysUser.ts", rename_all = "camelCase")]
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
            .field("login_ip", &self.login_ip)
            .field("login_date", &self.login_date)
            .field("create_by", &self.create_by)
            .field("create_time", &self.create_time)
            .field("update_by", &self.update_by)
            .field("update_time", &self.update_time)
            .field("remark", &self.remark)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    /// 保存前自动维护 create_time / update_time
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        let now = crate::common::datetime::now_naive();
        if insert {
            self.create_time = Set(Some(now));
        }
        self.update_time = Set(Some(now));
        Ok(self)
    }
}

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
            login_ip: Some("127.0.0.1".to_string()),
            login_date: None,
            create_by: Some("admin".to_string()),
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
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
        assert!(debug_str.contains("admin"), "Non-sensitive username should be visible");
        assert!(debug_str.contains("Administrator"), "Non-sensitive nick_name should be visible");
    }
}
