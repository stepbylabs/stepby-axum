// axum-backend/src/repository/sys_user.rs
//! sys_user 数据访问层
//!
//! 继承 BaseRepository 通用 CRUD，扩展用户特有查询：
//! - 按用户名查询（登录认证）
//! - 软删除过滤（del_flag = '0'）
//! - 软删除操作（del_flag = '2'）
//! - 按部门查询

use chrono::NaiveDateTime;
use sea_orm::*;
use sea_orm::sea_query::Expr;

use crate::common::like_escape;
use crate::entity::sys_user::{ActiveModel, Column, Entity as SysUser, Model};
use crate::repository::base::BaseRepository;

/// 用户 Repository
#[derive(Clone)]
pub struct SysUserRepository {
    base: BaseRepository<SysUser>,
}

impl SysUserRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    /// 获取基础 Repository（用于通用 CRUD）
    pub fn base(&self) -> &BaseRepository<SysUser> {
        &self.base
    }

    /// 按用户名查询（不过滤 del_flag）
    ///
    /// 调用方：
    /// - 用户名查重（add_user / register）：需包含已软删除用户名以防恢复后冲突
    /// - 解锁登录失败计数（unlock）：需要识别超管身份（超管不会被软删除）
    pub async fn find_by_user_name(&self, user_name: &str) -> Result<Option<Model>, DbErr> {
        SysUser::find()
            .filter(Column::UserName.eq(user_name))
            .one(self.base.db())
            .await
    }

    /// 按用户名查询未删除用户（del_flag = '0'），登录认证用
    ///
    /// H-2：登录认证场景需在 Repository 层过滤 del_flag，与 find_active_all 保持一致。
    /// 调用方（AuthService::verify_user_credentials）不再需要在 Service 层重复判断
    /// `del_flag == "2"`，避免遗漏过滤导致已删除用户进入密码校验流程。
    pub async fn find_active_by_user_name(&self, user_name: &str) -> Result<Option<Model>, DbErr> {
        SysUser::find()
            .filter(Column::UserName.eq(user_name))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 查询所有未删除用户（del_flag = '0'）
    pub async fn find_active_all(&self) -> Result<Vec<Model>, DbErr> {
        SysUser::find()
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 软删除（设置 del_flag = '2'）
    pub async fn soft_delete(&self, user_id: i64) -> Result<UpdateResult, DbErr> {
        SysUser::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::UserId.eq(user_id))
            .exec(self.base.db())
            .await
    }

    /// 更新最后登录信息
    pub async fn update_login_info(
        &self,
        user_id: i64,
        login_ip: &str,
    ) -> Result<UpdateResult, DbErr> {
        let now = crate::common::datetime::now_naive();
        SysUser::update_many()
            .col_expr(Column::LoginIp, Expr::value(login_ip))
            .col_expr(Column::LoginDate, Expr::value(now))
            .filter(Column::UserId.eq(user_id))
            .exec(self.base.db())
            .await
    }

    /// 插入用户
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新用户
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }

    /// 多条件分页查询（user_name 模糊，phonenumber 模糊，status 精确，dept_id 精确，时间范围）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        user_name: Option<&str>,
        phonenumber: Option<&str>,
        status: Option<&str>,
        dept_id: Option<i64>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysUser::find().filter(Column::DelFlag.eq("0"));
        if let Some(name) = user_name {
            query = query.filter(Column::UserName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(phone) = phonenumber {
            query = query.filter(Column::Phonenumber.like(format!("%{}%", like_escape(phone))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        if let Some(did) = dept_id {
            query = query.filter(Column::DeptId.eq(did));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 多条件分页查询 + data_scope 数据权限过滤（P0-R81-004）
    ///
    /// 在 find_page_filtered 基础上追加两类数据权限过滤：
    /// - scope_dept_ids: Some 时限定 user.dept_id 必须在此集合内
    ///   - None: 不追加 dept_id 过滤
    ///   - Some(空): 不可见任何部门 → 返回空结果
    ///   - Some(非空): 限定 dept_id IN 集合
    /// - scope_user_id: Some 时限定 user_id = 此值（用于 data_scope=5 仅本人）
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_with_data_scope(
        &self,
        offset: u64,
        limit: u64,
        user_name: Option<&str>,
        phonenumber: Option<&str>,
        status: Option<&str>,
        dept_id: Option<i64>,
        scope_dept_ids: Option<&[i64]>,
        scope_user_id: Option<i64>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysUser::find().filter(Column::DelFlag.eq("0"));
        if let Some(name) = user_name {
            query = query.filter(Column::UserName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(phone) = phonenumber {
            query = query.filter(Column::Phonenumber.like(format!("%{}%", like_escape(phone))));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        if let Some(did) = dept_id {
            query = query.filter(Column::DeptId.eq(did));
        }
        match scope_dept_ids {
            Some([]) => {
                // 空集合：无可见部门，返回空结果（用永假条件）
                query = query.filter(Column::UserId.eq(-1_i64));
            }
            Some(ids) => {
                query = query.filter(Column::DeptId.is_in(ids.to_vec()));
            }
            None => {}
        }
        if let Some(uid) = scope_user_id {
            query = query.filter(Column::UserId.eq(uid));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 分页查询指定 user_id 集合内的用户（角色已授权用户列表，支持 user_name/phonenumber 模糊）
    pub async fn find_page_in_ids(
        &self,
        offset: u64,
        limit: u64,
        user_ids: Vec<i64>,
        user_name: Option<&str>,
        phonenumber: Option<&str>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysUser::find()
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::UserId.is_in(user_ids));
        if let Some(name) = user_name {
            query = query.filter(Column::UserName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(phone) = phonenumber {
            query = query.filter(Column::Phonenumber.like(format!("%{}%", like_escape(phone))));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 分页查询不在指定 user_id 集合内的用户（角色未授权用户列表，支持 user_name/phonenumber 模糊）
    pub async fn find_page_not_in_ids(
        &self,
        offset: u64,
        limit: u64,
        exclude_ids: Vec<i64>,
        user_name: Option<&str>,
        phonenumber: Option<&str>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysUser::find().filter(Column::DelFlag.eq("0"));
        if !exclude_ids.is_empty() {
            query = query.filter(Column::UserId.is_not_in(exclude_ids));
        }
        if let Some(name) = user_name {
            query = query.filter(Column::UserName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(phone) = phonenumber {
            query = query.filter(Column::Phonenumber.like(format!("%{}%", like_escape(phone))));
        }

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }
}
