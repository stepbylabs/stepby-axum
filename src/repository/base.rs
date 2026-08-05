// axum-backend/src/repository/base.rs
//! 通用 Repository 基类：封装 SeaORM 原生 CRUD 操作
//!
//! 设计原则：
//! - 仅使用 SeaORM 原生 API，不引入任何 Web 层类型
//! - 泛型约束 `E: EntityTrait`，支持所有 SeaORM 实体
//! - 复杂约束的方法（insert/update）通过 where 子句按需约束
//! - `_conn` 系列方法接受 `impl ConnectionTrait`，支持事务上下文
//!   使 Service 层在事务闭包内仍可通过 Repository 访问数据库

use sea_orm::*;
use sea_orm::PaginatorTrait;
use std::marker::PhantomData;

/// 通用 Repository 基类，封装常见的数据库 CRUD 操作
#[derive(Clone)]
pub struct BaseRepository<E: EntityTrait> {
    db: DatabaseConnection,
    _phantom: PhantomData<E>,
}

impl<E: EntityTrait + Send + Sync> BaseRepository<E>
where
    E::Model: Send + Sync,
{
    /// 创建 Repository 实例
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            _phantom: PhantomData,
        }
    }

    /// 获取数据库连接引用
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// 查询全部记录
    pub async fn find_all(&self) -> Result<Vec<E::Model>, DbErr> {
        E::find().all(&self.db).await
    }

    /// 按主键查询单条记录
    /// 单主键传 i64，复合主键传 (i64, i64)
    pub async fn find_by_id<V>(&self, id: V) -> Result<Option<E::Model>, DbErr>
    where
        V: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
    {
        E::find_by_id(id).one(&self.db).await
    }

    /// 统计总记录数
    pub async fn count(&self) -> Result<u64, DbErr> {
        E::find().paginate(&self.db, 1).num_items().await
    }

    /// 执行自定义查询并返回多条记录
    pub async fn find_many(&self, select: Select<E>) -> Result<Vec<E::Model>, DbErr> {
        select.all(&self.db).await
    }

    /// 执行自定义查询并返回单条记录
    pub async fn find_one(&self, select: Select<E>) -> Result<Option<E::Model>, DbErr> {
        select.one(&self.db).await
    }

    /// 插入一条记录（返回完整 Model）
    ///
    /// DB-22：MySQL 不支持 RETURNING 子句，按 backend 分支处理：
    /// - PostgreSQL / SQLite：使用 `exec_with_returning`（原生 RETURNING）
    /// - MySQL：先 `exec` 再 `find_by_id` 回查
    pub async fn insert(&self, model: E::ActiveModel) -> Result<E::Model, DbErr>
    where
        E::Model: IntoActiveModel<E::ActiveModel>,
    {
        let backend = self.db.get_database_backend();
        match backend {
            DatabaseBackend::MySql => {
                let res = E::insert(model).exec(&self.db).await?;
                E::find_by_id(res.last_insert_id)
                    .one(&self.db)
                    .await?
                    .ok_or_else(|| {
                        DbErr::RecordNotFound("Failed to find inserted item".to_owned())
                    })
            }
            _ => E::insert(model).exec_with_returning(&self.db).await,
        }
    }

    /// 更新一条记录（返回更新后的 Model）
    pub async fn update(&self, model: E::ActiveModel) -> Result<E::Model, DbErr>
    where
        E::ActiveModel: ActiveModelTrait<Entity = E> + Send,
        E::Model: IntoActiveModel<E::ActiveModel>,
    {
        model.update(&self.db).await
    }

    /// 按主键物理删除
    pub async fn delete_by_id<V>(&self, id: V) -> Result<DeleteResult, DbErr>
    where
        V: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
    {
        E::delete_by_id(id).exec(&self.db).await
    }

    // ==================== 事务上下文方法（_conn 系列） ====================
    //
    // 这些方法接受 `impl ConnectionTrait` 参数，既可传入 `&DatabaseConnection`
    // 也可传入 `&Transaction`，使 Service 层在事务闭包内仍通过 Repository 访问数据库。
    // 方法为实例方法（`&self`）以复用具体 Repository 的调用路径，但内部不使用 `self.db`。

    /// 按主键查询单条记录（使用指定连接）
    pub async fn find_by_id_conn<C, V>(
        &self,
        conn: &C,
        id: V,
    ) -> Result<Option<E::Model>, DbErr>
    where
        C: ConnectionTrait,
        V: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
    {
        E::find_by_id(id).one(conn).await
    }

    /// 执行自定义查询返回单条记录（使用指定连接）
    pub async fn find_one_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        select: Select<E>,
    ) -> Result<Option<E::Model>, DbErr> {
        select.one(conn).await
    }

    /// 执行自定义查询返回多条记录（使用指定连接）
    pub async fn find_many_conn<C: ConnectionTrait>(
        &self,
        conn: &C,
        select: Select<E>,
    ) -> Result<Vec<E::Model>, DbErr> {
        select.all(conn).await
    }

    /// 插入一条记录（使用指定连接，返回完整 Model）
    ///
    /// DB-22：MySQL 不支持 RETURNING 子句，按 backend 分支处理：
    /// - PostgreSQL / SQLite：使用 `exec_with_returning`（原生 RETURNING）
    /// - MySQL：先 `exec` 再 `find_by_id` 回查
    pub async fn insert_conn<C>(
        &self,
        conn: &C,
        model: E::ActiveModel,
    ) -> Result<E::Model, DbErr>
    where
        C: ConnectionTrait,
        E::Model: IntoActiveModel<E::ActiveModel>,
    {
        let backend = conn.get_database_backend();
        match backend {
            DatabaseBackend::MySql => {
                let res = E::insert(model).exec(conn).await?;
                E::find_by_id(res.last_insert_id)
                    .one(conn)
                    .await?
                    .ok_or_else(|| {
                        DbErr::RecordNotFound("Failed to find inserted item".to_owned())
                    })
            }
            _ => E::insert(model).exec_with_returning(conn).await,
        }
    }

    /// 批量插入记录（使用指定连接）
    ///
    /// 注意：MySQL 不支持 `exec_with_returning`，返回的是受影响行数而非 Model 列表。
    pub async fn insert_many_conn<C>(
        &self,
        conn: &C,
        models: Vec<E::ActiveModel>,
    ) -> Result<InsertResult<E::ActiveModel>, DbErr>
    where
        C: ConnectionTrait,
        E::Model: IntoActiveModel<E::ActiveModel>,
    {
        E::insert_many(models).exec(conn).await
    }

    /// 更新一条记录（使用指定连接，返回更新后的 Model）
    pub async fn update_conn<C>(
        &self,
        conn: &C,
        model: E::ActiveModel,
    ) -> Result<E::Model, DbErr>
    where
        C: ConnectionTrait,
        E::ActiveModel: ActiveModelTrait<Entity = E> + Send,
        E::Model: IntoActiveModel<E::ActiveModel>,
    {
        model.update(conn).await
    }
}
