// axum-backend/src/repository/sys_user.rs
//! sys_user 数据访问层
//!
//! 继承 BaseRepository 通用 CRUD，扩展用户特有查询：
//! - 按用户名查询（登录认证）
//! - 软删除过滤（del_flag = '0'）
//! - 软删除操作（del_flag = '2'）
//! - 按部门查询

use chrono::NaiveDateTime;
use sea_orm::sea_query::{Expr, SimpleExpr};
use sea_orm::*;

use crate::common::custom_scope::{self, CustomCondition, Op};
use crate::common::like_escape;
use crate::entity::sys_user::{ActiveModel, Column, Entity as SysUser, Model};
use crate::repository::base::BaseRepository;

/// 把自定义数据权限条件映射为 `sys_user` 行的参数化 `SimpleExpr`。
///
/// 列名白名单 + 参数化值重建（`Column::X.eq(v)`），绝不拼接裸 SQL。
/// 未知列 / 类型不匹配（如对整型列做 LIKE）一律返回 `None` 丢弃该条件。
fn map_user_custom_scope(c: &CustomCondition) -> Option<SimpleExpr> {
    use sea_orm::ColumnTrait;
    macro_rules! str_col {
        ($col:ident, $val:expr) => {{
            let v = $val.as_str()?;
            Some(match c.op {
                Op::Eq => Column::$col.eq(v),
                Op::Ne => Column::$col.ne(v),
                Op::Gt => Column::$col.gt(v),
                Op::Gte => Column::$col.gte(v),
                Op::Lt => Column::$col.lt(v),
                Op::Lte => Column::$col.lte(v),
                Op::Like => Column::$col.like(v),
            })
        }};
    }
    macro_rules! int_col {
        ($col:ident, $val:expr) => {{
            let v = $val.as_i64()?;
            Some(match c.op {
                Op::Like => return None, // LIKE 仅对文本列有意义
                Op::Eq => Column::$col.eq(v),
                Op::Ne => Column::$col.ne(v),
                Op::Gt => Column::$col.gt(v),
                Op::Gte => Column::$col.gte(v),
                Op::Lt => Column::$col.lt(v),
                Op::Lte => Column::$col.lte(v),
            })
        }};
    }
    match c.column.as_str() {
        "user_id" => int_col!(UserId, &c.value),
        "dept_id" => int_col!(DeptId, &c.value),
        "user_name" => str_col!(UserName, &c.value),
        "nick_name" => str_col!(NickName, &c.value),
        "phonenumber" => str_col!(Phonenumber, &c.value),
        "email" => str_col!(Email, &c.value),
        "status" => str_col!(Status, &c.value),
        "sex" => str_col!(Sex, &c.value),
        _ => None,
    }
}

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

    /// 批量查询 user_id → tenant_id（在线会话/审计兜底回填用；不含软删行）
    pub async fn find_tenant_ids_by_user_ids(
        &self,
        user_ids: &[i64],
    ) -> Result<Vec<(i64, i64)>, DbErr> {
        if user_ids.is_empty() {
            return Ok(Vec::new());
        }
        SysUser::find()
            .select_only()
            .column(Column::UserId)
            .column(Column::TenantId)
            .filter(Column::UserId.is_in(user_ids.to_vec()))
            .filter(Column::DelFlag.eq("0"))
            .into_tuple::<(i64, i64)>()
            .all(self.base.db())
            .await
    }

    /// 批量查询 user_name → tenant_id（在线用户 Redis 降级路径的租户过滤用）
    pub async fn find_tenant_ids_by_user_names(
        &self,
        user_names: &[String],
    ) -> Result<Vec<(String, i64)>, DbErr> {
        if user_names.is_empty() {
            return Ok(Vec::new());
        }
        SysUser::find()
            .select_only()
            .column(Column::UserName)
            .column(Column::TenantId)
            .filter(Column::UserName.is_in(user_names.to_vec()))
            .filter(Column::DelFlag.eq("0"))
            .into_tuple::<(String, i64)>()
            .all(self.base.db())
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

    /// 按用户 ID 查询未删除用户（del_flag = '0'），OAuth 绑定校验用
    pub async fn find_active_by_user_id(&self, user_id: i64) -> Result<Option<Model>, DbErr> {
        SysUser::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::DelFlag.eq("0"))
            .one(self.base.db())
            .await
    }

    /// 按邮箱查询用户（含软删除），OAuth 自动创建前邮箱冲突检查用
    ///
    /// 包含 del_flag='2' 用户：写入 sys_oauth_user 前需避免邮箱被软删除账号占用，
    /// 导致后续恢复/补录冲突。
    pub async fn find_by_email(&self, email: &str) -> Result<Option<Model>, DbErr> {
        SysUser::find()
            .filter(Column::Email.eq(email))
            .one(self.base.db())
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

    /// 多条件分页查询 + data_scope 数据权限过滤（P0-R81-004）
    ///
    /// 追加两类过滤（**含租户过滤**）：
    /// - scope_dept_ids: Some 时限定 user.dept_id 必须在此集合内
    ///   - None: 不追加 dept_id 过滤
    ///   - Some(空): 不可见任何部门 → 返回空结果
    ///   - Some(非空): 限定 dept_id IN 集合
    /// - scope_user_id: Some 时限定 user_id = 此值（用于 data_scope=5 仅本人）
    /// - custom_conds: 自定义数据权限（data_scope=2）的白名单字段条件（参数化，防注入）
    ///   与前面 dept/user 过滤是「与」关系。
    ///
    /// `last_id`：游标（keyset 深分页）参数。携带时按 `user_id < last_id` 过滤 +
    /// `user_id DESC` 排序，适用于深翻页（避免 OFFSET 线性扫描）；为 `None` 时沿用
    /// `offset/limit` 分页路径。
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
        custom_conds: Option<&[CustomCondition]>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        last_id: Option<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysUser::find().filter(Column::DelFlag.eq("0"));
        // 多租户 Phase 2：租户用户仅见本租户（tenant_scope(tid)=Some(t)）；平台 0 不过滤
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
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
        // 自定义数据权限（data_scope=2）的字段条件：白名单 + 参数化重建，防注入
        if let Some(conds) = custom_conds
            && let Some(cond) = custom_scope::build_filter(conds, map_user_custom_scope)
        {
            query = query.filter(cond);
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }

        // 过滤条件已齐备，统计总数（与分页模式无关，过滤后计数保持一致）
        let total = query.clone().count(self.base.db()).await?;

        // P1：keyset 深分页（PK < last_id）+ PK DESC；否则走原 OFFSET 深翻页路径。
        // 注意 keyset 模式排序方向与默认相反（倒序），二者各自返回一致、无重复的分页。
        let rows = if last_id.is_some() {
            crate::common::page::apply_keyset_filter(query, last_id, |id| Column::UserId.lt(id))
                .order_by_desc(Column::UserId)
                .limit(limit)
                .all(self.base.db())
                .await?
        } else {
            // P1：稳定排序，防翻页重复/漏行
            query
                .order_by_asc(Column::UserId)
                .offset(offset)
                .limit(limit)
                .all(self.base.db())
                .await?
        };
        Ok((rows, total))
    }

    /// 分页查询指定 user_id 集合内的用户（角色已授权用户列表，支持 user_name/phonenumber 模糊）
    ///
    /// P0-6：`scope_dept_ids` / `scope_user_id` 为操作人数据范围过滤（None=不过滤），
    /// 防止低权限管理员通过本端点枚举全部用户；同时补 order_by 稳定分页（P1）。
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅本租户用户；`None`（平台）→ 全量。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_in_ids(
        &self,
        offset: u64,
        limit: u64,
        user_ids: Vec<i64>,
        user_name: Option<&str>,
        phonenumber: Option<&str>,
        scope_dept_ids: Option<&[i64]>,
        scope_user_id: Option<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysUser::find()
            .filter(Column::DelFlag.eq("0"))
            .filter(Column::UserId.is_in(user_ids))
            .order_by_asc(Column::UserId);
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(name) = user_name {
            query = query.filter(Column::UserName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(phone) = phonenumber {
            query = query.filter(Column::Phonenumber.like(format!("%{}%", like_escape(phone))));
        }
        // 数据范围过滤（P0-6）
        if let Some(scope_uid) = scope_user_id {
            query = query.filter(Column::UserId.eq(scope_uid));
        }
        if let Some(ids) = scope_dept_ids {
            if ids.is_empty() {
                query = query.filter(Column::UserId.eq(-1_i64)); // 永假：无可见部门
            } else {
                query = query.filter(Column::DeptId.is_in(ids.iter().copied()));
            }
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
    ///
    /// P0-6：`scope_dept_ids` / `scope_user_id` 为操作人数据范围过滤（None=不过滤）；
    /// 补 order_by 稳定分页（P1）。
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅本租户用户；`None`（平台）→ 全量。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_not_in_ids(
        &self,
        offset: u64,
        limit: u64,
        exclude_ids: Vec<i64>,
        user_name: Option<&str>,
        phonenumber: Option<&str>,
        scope_dept_ids: Option<&[i64]>,
        scope_user_id: Option<i64>,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysUser::find()
            .filter(Column::DelFlag.eq("0"))
            .order_by_asc(Column::UserId);
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if !exclude_ids.is_empty() {
            query = query.filter(Column::UserId.is_not_in(exclude_ids));
        }
        if let Some(name) = user_name {
            query = query.filter(Column::UserName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(phone) = phonenumber {
            query = query.filter(Column::Phonenumber.like(format!("%{}%", like_escape(phone))));
        }
        // 数据范围过滤（P0-6）
        if let Some(scope_uid) = scope_user_id {
            query = query.filter(Column::UserId.eq(scope_uid));
        }
        if let Some(ids) = scope_dept_ids {
            if ids.is_empty() {
                query = query.filter(Column::UserId.eq(-1_i64)); // 永假：无可见部门
            } else {
                query = query.filter(Column::DeptId.is_in(ids.iter().copied()));
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Set;

    /// 构造一条用户（id/dept/状态，其余列取默认）。
    fn user_row(id: i64, dept_id: i64, status: &str) -> ActiveModel {
        ActiveModel {
            user_id: Set(id),
            dept_id: Set(Some(dept_id)),
            user_name: Set(format!("user{id}")),
            nick_name: Set(format!("用户{id}")),
            status: Set(Some(status.to_string())),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        }
    }

    /// 插入 7 个未删除用户：dept 分段（含可过滤目标），i=6 状态为 1（其余成功）。
    /// user_id 从 101 起（迁移已预置 user_id=1 的 admin，避免主键冲突）。
    async fn insert_7(db: &DatabaseConnection) -> SysUserRepository {
        let repo = SysUserRepository::new(db.clone());
        let depts = [100, 100, 200, 200, 100, 100, 100];
        for i in 1..=7 {
            let status = if i == 6 { "1" } else { "0" };
            repo.base()
                .insert(user_row(100 + i, depts[(i - 1) as usize], status))
                .await
                .unwrap();
        }
        repo
    }

    #[tokio::test]
    async fn keyset_returns_strictly_decreasing_pages_no_duplicates() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = insert_7(&db).await;
        let size = 3u64;

        // 全程 keyset 连续翻页：首页用极大游标触发 keyset 分支，避免混入 OFFSET 升序页。
        let mut cursor = Some(i64::MAX);
        let mut collected: Vec<i64> = Vec::new();
        let mut pages = 0u32;
        loop {
            let (page, _) = repo
                .find_page_with_data_scope(
                    0, size, None, None, None, None, None, None, None, None, None, cursor, None,
                )
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            assert!(
                page.windows(2).all(|w| w[0].user_id > w[1].user_id),
                "keyset 页内应按 user_id 严格递减"
            );
            pages += 1;
            cursor = Some(page.last().unwrap().user_id);
            collected.extend(page.iter().map(|m| m.user_id));
        }
        assert!(pages >= 3, "应产生多页 keyset 结果");

        // 跨页无重复：收集到的 id 数 == 去重后数；耗尽后最后一页为空（上方循环已保证）。
        let uniq: std::collections::HashSet<i64> = collected.iter().copied().collect();
        assert_eq!(collected.len(), uniq.len(), "keyset 分页不应出现重复");
    }

    #[tokio::test]
    async fn keyset_works_alongside_data_scope_and_custom_conds() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = insert_7(&db).await;

        // 自定义数据权限（data_scope=2）：custom_sql "status = '0' AND dept_id = 100"
        let conds = custom_scope::parse_custom_sql(
            "status = '0' AND dept_id = 100",
            custom_scope::USER_CUSTOM_COLUMNS,
        )
        .unwrap();

        // 计算过滤后应命中的集合（分页方式无关），作为预期
        let (expected_rows, expected_total) = repo
            .find_page_with_data_scope(
                0,
                1000,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(&conds),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(expected_total >= 4, "自定义数据权限过滤应命中至少 4 条");
        assert!(
            expected_rows
                .iter()
                .all(|u| u.status.as_deref() == Some("0") && u.dept_id == Some(100))
        );

        // keyset 连续翻页应完整覆盖过滤后的行，且全部满足条件、无重复
        let mut cursor = Some(i64::MAX);
        let mut collected: Vec<i64> = Vec::new();
        loop {
            let (page, _) = repo
                .find_page_with_data_scope(
                    0,
                    2,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(&conds),
                    None,
                    None,
                    cursor,
                    None,
                )
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            assert!(
                page.iter()
                    .all(|u| u.status.as_deref() == Some("0") && u.dept_id == Some(100))
            );
            cursor = Some(page.last().unwrap().user_id);
            collected.extend(page.iter().map(|m| m.user_id));
        }
        let uniq: std::collections::HashSet<i64> = collected.iter().copied().collect();
        assert_eq!(
            collected.len(),
            uniq.len(),
            "过滤 + keyset 组合不应出现重复"
        );
        let expected_ids: std::collections::HashSet<i64> =
            expected_rows.iter().map(|u| u.user_id).collect();
        assert_eq!(uniq, expected_ids, "keyset 应命中全部过滤行");
    }

    #[tokio::test]
    async fn keyset_covers_same_rows_as_offset_for_small_datasets() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .unwrap();
        let repo = insert_7(&db).await;
        let size = 3u64;

        // OFFSET 全量（大 limit，无过滤）作为基准集合
        let (offset_all, _) = repo
            .find_page_with_data_scope(
                0, 1000, None, None, None, None, None, None, None, None, None, None, None,
            )
            .await
            .unwrap();
        let offset_ids: std::collections::HashSet<i64> =
            offset_all.iter().map(|u| u.user_id).collect();

        // keyset 从极大游标连续翻页到耗尽
        let mut got: Vec<i64> = Vec::new();
        let mut cursor = Some(i64::MAX);
        loop {
            let (page, _) = repo
                .find_page_with_data_scope(
                    0, size, None, None, None, None, None, None, None, None, None, cursor, None,
                )
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            got.extend(page.iter().map(|m| m.user_id));
            cursor = Some(page.last().unwrap().user_id);
        }
        let keyset_ids: std::collections::HashSet<i64> = got.into_iter().collect();
        assert_eq!(
            offset_ids, keyset_ids,
            "keyset 与 OFFSET 对小数据集应覆盖相同行集合"
        );
    }
}
