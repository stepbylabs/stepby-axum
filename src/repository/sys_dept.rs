// axum-backend/src/repository/sys_dept.rs
//! sys_dept 数据访问层
//!
//! 继承 BaseRepository 通用 CRUD，扩展部门特有查询：
//! - 软删除过滤（del_flag = '0'）
//! - 按状态查询
//! - 查询全部未删除部门（树形结构组装用）

use sea_orm::*;
use sea_orm::sea_query::Expr;

use crate::common::like_escape;
use crate::entity::sys_dept::{ActiveModel, Column, Entity as SysDept, Model};
use crate::repository::base::BaseRepository;

/// 部门 Repository
#[derive(Clone)]
pub struct SysDeptRepository {
    base: BaseRepository<SysDept>,
}

impl SysDeptRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysDept> {
        &self.base
    }

    /// 查询所有未删除部门（del_flag = '0'）
    pub async fn find_active_all(&self) -> Result<Vec<Model>, DbErr> {
        SysDept::find()
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 查询部门的所有后代部门 ID（含自身），使用递归 CTE（P0-R81-004 暂缓项）
    ///
    /// 替代原"加载全部部门到内存后过滤 ancestors CSV"的 O(n) 全表扫描实现，
    /// 改为数据库原生递归查询，仅返回所需后代 ID。
    /// PostgreSQL 17 / MySQL 8.0+ / SQLite 均原生支持 WITH RECURSIVE。
    ///
    /// 占位符差异：MySQL 使用 `?`，PostgreSQL/SQLite 使用 `$1`。
    pub async fn find_descendant_ids(&self, dept_id: i64) -> Result<Vec<i64>, DbErr> {
        let backend = self.base.db().get_database_backend();
        let sql = match backend {
            DatabaseBackend::MySql => r#"WITH RECURSIVE dept_tree AS (
                SELECT dept_id FROM sys_dept WHERE dept_id = ? AND del_flag = '0'
                UNION ALL
                SELECT d.dept_id FROM sys_dept d
                INNER JOIN dept_tree t ON d.parent_id = t.dept_id
                WHERE d.del_flag = '0'
            ) SELECT dept_id FROM dept_tree"#,
            _ => r#"WITH RECURSIVE dept_tree AS (
                SELECT dept_id FROM sys_dept WHERE dept_id = $1 AND del_flag = '0'
                UNION ALL
                SELECT d.dept_id FROM sys_dept d
                INNER JOIN dept_tree t ON d.parent_id = t.dept_id
                WHERE d.del_flag = '0'
            ) SELECT dept_id FROM dept_tree"#,
        };
        let stmt = Statement::from_sql_and_values(backend, sql, [dept_id.into()]);
        let rows = self.base.db().query_all(stmt).await?;
        Ok(rows
            .into_iter()
            .filter_map(|r| r.try_get_by_index::<i64>(0).ok())
            .collect())
    }

    /// 按 dept_id 列表批量查询未删除部门（用于用户分页 N+1 优化）
    ///
    /// 一次性查询所有指定 ID 的部门信息，避免逐条查询。
    pub async fn find_by_ids(&self, dept_ids: Vec<i64>) -> Result<Vec<Model>, DbErr> {
        if dept_ids.is_empty() {
            return Ok(vec![]);
        }
        SysDept::find()
            .filter(Column::DeptId.is_in(dept_ids))
            .filter(Column::DelFlag.eq("0"))
            .all(self.base.db())
            .await
    }

    /// 按状态查询未删除部门
    pub async fn find_by_status(&self, status: &str) -> Result<Vec<Model>, DbErr> {
        SysDept::find()
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::Status.eq(status))
            .all(self.base.db())
            .await
    }

    /// 按部门名称查询（模糊）
    pub async fn find_by_name_like(&self, name: &str) -> Result<Vec<Model>, DbErr> {
        SysDept::find()
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::DeptName.like(format!("%{}%", like_escape(name))))
            .all(self.base.db())
            .await
    }

    /// 软删除部门
    pub async fn soft_delete(&self, dept_id: i64) -> Result<UpdateResult, DbErr> {
        SysDept::update_many()
            .col_expr(Column::DelFlag, Expr::value("2"))
            .filter(Column::DeptId.eq(dept_id))
            .exec(self.base.db())
            .await
    }

    /// 插入部门
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新部门
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
