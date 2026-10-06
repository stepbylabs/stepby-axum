// stepby-axum/src/repository/sys_user_role.rs
//! sys_user_role 数据访问层（用户角色关联表，复合主键）
//!
//! 继承 BaseRepository 通用 CRUD，扩展关联特有查询：
//! - 按用户 ID 查询关联角色
//! - 按角色 ID 查询关联用户
//! - 按用户 ID / 角色 ID 删除关联

use sea_orm::*;

use crate::entity::sys_user_role::{ActiveModel, Column, Entity as SysUserRole, Model};
use crate::repository::base::BaseRepository;

/// 用户角色关联 Repository
#[derive(Clone)]
pub struct SysUserRoleRepository {
    base: BaseRepository<SysUserRole>,
}

impl SysUserRoleRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysUserRole> {
        &self.base
    }

    /// 按用户 ID 查询所有角色关联
    pub async fn find_by_user_id(&self, user_id: i64) -> Result<Vec<Model>, DbErr> {
        SysUserRole::find()
            .filter(Column::UserId.eq(user_id))
            .all(self.base.db())
            .await
    }

    /// 批量查询多个用户的角色关联（用于用户分页 N+1 优化）
    ///
    /// 一次性查询所有指定用户的角色关联，返回 user_id → role_ids 的映射。
    /// 相比逐用户查询，将 N 次数据库调用合并为 1 次。
    pub async fn find_role_ids_by_user_ids(
        &self,
        user_ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, Vec<i64>>, DbErr> {
        if user_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = SysUserRole::find()
            .filter(Column::UserId.is_in(user_ids.to_vec()))
            .all(self.base.db())
            .await?;
        let mut map: std::collections::HashMap<i64, Vec<i64>> =
            std::collections::HashMap::with_capacity(user_ids.len());
        for ur in rows {
            map.entry(ur.user_id).or_default().push(ur.role_id);
        }
        Ok(map)
    }

    /// 按角色 ID 查询所有用户关联
    pub async fn find_by_role_id(&self, role_id: i64) -> Result<Vec<Model>, DbErr> {
        SysUserRole::find()
            .filter(Column::RoleId.eq(role_id))
            .all(self.base.db())
            .await
    }

    /// 删除某用户的所有角色关联（用户删除/重分配角色时调用）
    pub async fn delete_by_user_id(&self, user_id: i64) -> Result<DeleteResult, DbErr> {
        SysUserRole::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(self.base.db())
            .await
    }

    /// 删除某用户的**管理员手授**（source='admin'）角色关联——v5-D12 Group：
    /// 管理员编辑/授权用户时保留 SCIM 组联动行（source='scim:{gid}'），
    /// 消除"管理员取消勾选 → 下次组同步又加回来"的回写抖动。
    pub async fn delete_admin_by_user_id(&self, user_id: i64) -> Result<DeleteResult, DbErr> {
        SysUserRole::delete_many()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Source.eq("admin"))
            .exec(self.base.db())
            .await
    }

    /// 删除某角色的所有用户关联（角色删除时调用）
    pub async fn delete_by_role_id(&self, role_id: i64) -> Result<DeleteResult, DbErr> {
        SysUserRole::delete_many()
            .filter(Column::RoleId.eq(role_id))
            .exec(self.base.db())
            .await
    }

    /// 插入关联
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 批量插入关联
    pub async fn insert_many(
        &self,
        models: Vec<ActiveModel>,
    ) -> Result<u64, DbErr> {
        let n = models.len() as u64;
        SysUserRole::insert_many(models).exec(self.base.db()).await?;
        Ok(n)
    }

    /// 删除指定用户+角色的单条关联（取消单个授权）
    pub async fn delete_by_user_and_role(
        &self,
        user_id: i64,
        role_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysUserRole::delete_many()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::RoleId.eq(role_id))
            .exec(self.base.db())
            .await
    }

    /// 删除某角色下多个用户的关联（批量取消授权）
    pub async fn delete_by_role_and_users(
        &self,
        role_id: i64,
        user_ids: Vec<i64>,
    ) -> Result<DeleteResult, DbErr> {
        SysUserRole::delete_many()
            .filter(Column::RoleId.eq(role_id))
            .filter(Column::UserId.is_in(user_ids))
            .exec(self.base.db())
            .await
    }

    /// 查询某角色下指定用户集合的关联记录（用于去重判断）
    pub async fn find_by_role_and_users(
        &self,
        role_id: i64,
        user_ids: Vec<i64>,
    ) -> Result<Vec<Model>, DbErr> {
        SysUserRole::find()
            .filter(Column::RoleId.eq(role_id))
            .filter(Column::UserId.is_in(user_ids))
            .all(self.base.db())
            .await
    }

    /// 统计某角色关联的用户数（级联删除校验用）
    pub async fn count_by_role_id(&self, role_id: i64) -> Result<u64, DbErr> {
        SysUserRole::find()
            .filter(Column::RoleId.eq(role_id))
            .count(self.base.db())
            .await
    }

    // ==================== 事务上下文方法（_conn 系列） ====================

    /// 删除某用户的所有角色关联（使用指定连接，用于事务内调用）
    pub async fn delete_by_user_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        user_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysUserRole::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(conn)
            .await
    }

    /// 删除某用户的**管理员手授**角色关联（事务内；v5-D12 Group——保留
    /// source='scim:{gid}' 行，授权来源两事实源分离）
    pub async fn delete_admin_by_user_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        user_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysUserRole::delete_many()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Source.eq("admin"))
            .exec(conn)
            .await
    }

    /// 删除某角色的所有用户关联（使用指定连接，用于事务内调用）
    pub async fn delete_by_role_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        role_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysUserRole::delete_many()
            .filter(Column::RoleId.eq(role_id))
            .exec(conn)
            .await
    }

    /// 统计某角色关联的用户数（使用指定连接，用于事务内调用）（M-1 Major TOCTOU 修复）
    ///
    /// 用于在事务内重新检查用户关联，避免事务外预检查后被其他事务插入新关联（TOCTOU）。
    pub async fn count_by_role_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        role_id: i64,
    ) -> Result<u64, DbErr> {
        SysUserRole::find()
            .filter(Column::RoleId.eq(role_id))
            .count(conn)
            .await
    }

    /// 批量插入关联（使用指定连接，用于事务内调用）
    pub async fn insert_many_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        models: Vec<ActiveModel>,
    ) -> Result<u64, DbErr> {
        let n = models.len() as u64; let _res = SysUserRole::insert_many(models).exec(conn).await?; Ok(n)
    }

    /// 管理员侧幂等授权（事务内；UNIQUE(user_id, role_id) 语义安全写入）：
    /// - 目标角色无行 → 插入 source='admin' 行
    /// - 已有 admin 行 → 幂等跳过
    /// - 已有 scim:{gid} 行 → 抢占改写为 source='admin'
    ///   （管理员显式授权优先；组撤销只删本组 source 行，被抢占角色不受影响）
    ///
    /// 管理端 add_user / update_user / auth_role 统一走此方法，替代裸 INSERT，
    /// 防止管理员勾选 SCIM 组已授角色时撞唯一约束（500）。
    /// 与 scim_group_service::grant_single 的"目标行已存在不覆盖"对称成完整闭环。
    pub async fn upsert_admin_grants_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        user_id: i64,
        role_ids: Vec<i64>,
    ) -> Result<(), DbErr> {
        if role_ids.is_empty() {
            return Ok(());
        }
        let existing = SysUserRole::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::RoleId.is_in(role_ids.clone()))
            .all(conn)
            .await?;
        let mut preempt: Vec<i64> = Vec::new();
        let mut admin_held: std::collections::HashSet<i64> = std::collections::HashSet::new();
        for row in existing {
            if row.source == "admin" {
                admin_held.insert(row.role_id);
            } else {
                preempt.push(row.role_id);
            }
        }
        let to_insert: Vec<ActiveModel> = role_ids
            .iter()
            .filter(|rid| !admin_held.contains(rid) && !preempt.contains(rid))
            .map(|rid| ActiveModel {
                user_id: sea_orm::Set(user_id),
                role_id: sea_orm::Set(*rid),
                source: sea_orm::Set("admin".to_owned()),
            })
            .collect();
        if !to_insert.is_empty() {
            SysUserRole::insert_many(to_insert).exec(conn).await?;
        }
        for rid in preempt {
            SysUserRole::update_many()
                .col_expr(Column::Source, sea_query::Expr::value("admin".to_owned()))
                .filter(Column::UserId.eq(user_id))
                .filter(Column::RoleId.eq(rid))
                .exec(conn)
                .await?;
        }
        Ok(())
    }
}
