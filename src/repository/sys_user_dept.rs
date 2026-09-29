// stepby-axum/src/repository/sys_user_dept.rs
//! sys_user_dept 数据访问层（用户兼职部门关联，多部门任职最小侵入版）
//!
//! 语义约定：本表只存**兼职**部门（主部门唯一事实源 = sys_user.dept_id）；
//! source：'admin'（人工配置）| 'scim:{group_id}'（组→兼职部门同步）。

use sea_orm::*;

use crate::entity::sys_user_dept::{ActiveModel, Column, Entity as SysUserDept, Model};
use crate::repository::base::BaseRepository;

/// 用户兼职部门 Repository
#[derive(Clone)]
pub struct SysUserDeptRepository {
    base: BaseRepository<SysUserDept>,
}

impl SysUserDeptRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysUserDept> {
        &self.base
    }

    /// 批量查询多个用户的兼职部门（返回 user_id → dept_ids 映射，列表 N+1 优化）
    pub async fn find_dept_ids_by_user_ids(
        &self,
        user_ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, Vec<i64>>, DbErr> {
        if user_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = SysUserDept::find()
            .filter(Column::UserId.is_in(user_ids.to_vec()))
            .all(self.base.db())
            .await?;
        let mut map: std::collections::HashMap<i64, Vec<i64>> =
            std::collections::HashMap::with_capacity(user_ids.len());
        for ud in rows {
            map.entry(ud.user_id).or_default().push(ud.dept_id);
        }
        Ok(map)
    }

    /// 查询某用户全部兼职部门
    pub async fn find_by_user_id(&self, user_id: i64) -> Result<Vec<Model>, DbErr> {
        SysUserDept::find()
            .filter(Column::UserId.eq(user_id))
            .all(self.base.db())
            .await
    }

    /// 查询某用户指定来源的兼职部门 id（admin 编辑回显 vs scim 只读标记区分用）
    pub async fn find_dept_ids_by_user_and_source(
        &self,
        user_id: i64,
        source: &str,
    ) -> Result<Vec<i64>, DbErr> {
        let rows = SysUserDept::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Source.eq(source))
            .all(self.base.db())
            .await?;
        Ok(rows.into_iter().map(|ud| ud.dept_id).collect())
    }

    /// 删除某用户**管理员手授**的兼职记录（事务内；保留 scim 来源行）
    pub async fn delete_admin_by_user_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        user_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysUserDept::delete_many()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Source.eq("admin"))
            .exec(conn)
            .await
    }

    /// 删除某用户全部兼职记录（事务内；用户删除场景）
    pub async fn delete_by_user_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        user_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysUserDept::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(conn)
            .await
    }

    /// 删除某部门的全部兼职记录（事务内；部门删除联动）
    pub async fn delete_by_dept_id_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        dept_id: i64,
    ) -> Result<DeleteResult, DbErr> {
        SysUserDept::delete_many()
            .filter(Column::DeptId.eq(dept_id))
            .exec(conn)
            .await
    }

    /// 批量插入（事务内）
    pub async fn insert_many_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        models: Vec<ActiveModel>,
    ) -> Result<InsertResult<ActiveModel>, DbErr> {
        SysUserDept::insert_many(models).exec(conn).await
    }

    /// 管理员侧幂等兼职写入（事务内；UNIQUE(user_id, dept_id) 语义安全写入）：
    /// - 目标部门无行 → 插入 source='admin' 行（create_time=当前时间）
    /// - 已有 admin 行 → 幂等跳过
    /// - 已有 scim:{gid} 行 → 抢占改写为 source='admin'
    ///   （管理员显式配置优先；组撤销只删本组 source 行，被抢占兼职不受影响）
    ///
    /// 管理端 add_user / update_user 的兼职部门写入统一走此方法，
    /// 防止管理员勾选 SCIM 组已绑部门时撞唯一约束（500）。
    /// 与 scim_group_service::grant_single 的"目标行已存在不覆盖"对称成完整闭环。
    pub async fn upsert_admin_depts_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        user_id: i64,
        dept_ids: Vec<i64>,
    ) -> Result<(), DbErr> {
        if dept_ids.is_empty() {
            return Ok(());
        }
        let existing = SysUserDept::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::DeptId.is_in(dept_ids.clone()))
            .all(conn)
            .await?;
        let mut preempt: Vec<i64> = Vec::new();
        let mut admin_held: std::collections::HashSet<i64> = std::collections::HashSet::new();
        for row in existing {
            if row.source == "admin" {
                admin_held.insert(row.dept_id);
            } else {
                preempt.push(row.dept_id);
            }
        }
        let now = crate::common::datetime::now_naive();
        let to_insert: Vec<ActiveModel> = dept_ids
            .iter()
            .filter(|did| !admin_held.contains(did) && !preempt.contains(did))
            .map(|did| ActiveModel {
                user_id: sea_orm::Set(user_id),
                dept_id: sea_orm::Set(*did),
                source: sea_orm::Set("admin".to_owned()),
                create_time: sea_orm::Set(Some(now)),
                ..Default::default()
            })
            .collect();
        if !to_insert.is_empty() {
            SysUserDept::insert_many(to_insert).exec(conn).await?;
        }
        for did in preempt {
            SysUserDept::update_many()
                .col_expr(Column::Source, sea_query::Expr::value("admin".to_owned()))
                .filter(Column::UserId.eq(user_id))
                .filter(Column::DeptId.eq(did))
                .exec(conn)
                .await?;
        }
        Ok(())
    }
}
