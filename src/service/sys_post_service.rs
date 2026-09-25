//! 岗位模块 Service 层
//!
//! 职责：
//! - 岗位 CRUD、post_code 唯一性校验
//! - 删除前预检 sys_user_post 关联（有关联则拒绝删除）
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 数据访问通过 Repository 层委托

use futures::future::FutureExt;
use garde::Validate;
use sea_orm::{DatabaseConnection, Set, TransactionTrait};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::common::error::ServiceError;
use crate::common::page::{PageDomain, default_page_num, default_page_size};
use crate::entity::sys_post::{ActiveModel as SysPostActiveModel, Model as SysPostModel};
use crate::repository::sys_post::SysPostRepository;
use crate::repository::sys_user_post::SysUserPostRepository;

// ==================== DTO ====================

/// 岗位分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PostQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub post_code: Option<String>,
    pub post_name: Option<String>,
    pub status: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&PostQueryDto> for PageDomain {
    fn from(dto: &PostQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 新增岗位 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PostAddDto {
    #[garde(length(min = 1, max = 64))]
    pub post_code: String,
    #[garde(length(min = 1, max = 50))]
    pub post_name: String,
    #[garde(range(min = 0))]
    pub post_sort: Option<i32>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 修改岗位 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PostEditDto {
    #[garde(skip)]
    pub post_id: i64,
    #[garde(length(min = 1, max = 64))]
    pub post_code: String,
    #[garde(length(min = 1, max = 50))]
    pub post_name: String,
    #[garde(range(min = 0))]
    pub post_sort: Option<i32>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

// ==================== Service 实现 ====================

/// 岗位模块 Service
///
/// 数据访问通过 Repository 层委托：
/// - post_repo: sys_post 表 CRUD
/// - user_post_repo: sys_user_post 关联表（删除预检用）
pub struct SysPostService {
    post_repo: SysPostRepository,
    user_post_repo: SysUserPostRepository,
}

impl SysPostService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            post_repo: SysPostRepository::new(db.clone()),
            user_post_repo: SysUserPostRepository::new(db),
        }
    }

    /// 获取数据库连接引用（用于事务）
    fn db(&self) -> &DatabaseConnection {
        self.post_repo.base().db()
    }

    /// 分页查询岗位
    ///
    /// 支持 post_code 模糊、post_name 模糊、status 精确筛选
    pub async fn get_post_page(
        &self,
        query: PostQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<(Vec<SysPostModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let (rows, total) = self
            .post_repo
            .find_page_filtered(
                offset,
                limit,
                query.post_code.as_deref(),
                query.post_name.as_deref(),
                query.status.as_deref(),
                tenant_scope,
            )
            .await?;
        Ok((rows, total))
    }

    /// 查询未删除岗位（前端下拉选择用）。
    ///
    /// 多租户：`tenant_scope = Some(tid)` → 仅本租户岗位；`None`（平台操作者）→ 全量。
    pub async fn get_post_options(
        &self,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<SysPostModel>, ServiceError> {
        let rows = self.post_repo.find_active_all(tenant_scope).await?;
        Ok(rows)
    }

    /// 根据 post_id 查询岗位详情
    pub async fn get_post_by_id(&self, post_id: i64) -> Result<SysPostModel, ServiceError> {
        let model = self
            .post_repo
            .find_active_by_id(post_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.post.not_found")))?;
        Ok(model)
    }

    /// 新增岗位
    ///
    /// 业务校验：post_code 唯一性（未删除范围内）
    pub async fn add_post(
        &self,
        dto: PostAddDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysPostModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // post_code 唯一性校验
        let existing = self.post_repo.find_by_post_code(&dto.post_code).await?;
        if existing.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.post.code_exists"
            )));
        }

        let now = crate::common::datetime::now_naive();
        let am = SysPostActiveModel {
            // 多租户 Phase 2：岗位归属操作者租户（平台管理员=0）
            tenant_id: Set(operator_tid),
            post_code: Set(dto.post_code),
            post_name: Set(dto.post_name),
            post_sort: Set(dto.post_sort.unwrap_or(0)),
            status: Set(dto.status.or(Some("0".to_string()))),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(dto.remark),
            del_flag: Set(Some("0".to_string())),
            ..Default::default()
        };

        let model = self.post_repo.insert(am).await?;
        Ok(model)
    }

    /// 修改岗位
    ///
    /// 业务校验：
    /// - 目标存在且未删除
    /// - post_code 若变更，校验新值唯一性（排除自身）
    pub async fn edit_post(
        &self,
        dto: PostEditDto,
        operator: &str,
        operator_tid: i64,
    ) -> Result<SysPostModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let existing = self.get_post_by_id(dto.post_id).await?;
        // 多租户越权防护：只能修改本租户岗位（平台操作者放行）
        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id) {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.common.forbidden"
            )));
        }

        // post_code 变更时校验唯一性（排除自身）
        let old_post_code = existing.post_code.clone();
        if dto.post_code != old_post_code {
            let conflict = self.post_repo.find_by_post_code(&dto.post_code).await?;
            if conflict.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.post.code_exists"
                )));
            }
        }

        let now = crate::common::datetime::now_naive();
        // 部分更新语义快照（2026-09-26 缺陷修复）：`existing` 随即被 `into()` 转移；
        // 未传排序/状态时保持现值，避免排序被归零、岗位被静默置 NULL 失效
        let existing_sort = existing.post_sort;
        let existing_status = existing.status.clone();
        let mut am: SysPostActiveModel = existing.into();
        am.post_code = Set(dto.post_code);
        am.post_name = Set(dto.post_name);
        am.post_sort = Set(dto.post_sort.unwrap_or(existing_sort));
        am.status = Set(dto.status.or(existing_status));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.remark = Set(dto.remark);

        let model = self.post_repo.update(am).await?;
        Ok(model)
    }

    /// 批量删除岗位（软删除，事务保证原子化 P0-76）
    ///
    /// 预检 sys_user_post 关联：有关联用户则拒绝删除
    ///
    /// REGRESS-003：软删除时重命名 post_code 为 `{original}_deleted_{post_id}`，
    /// 释放 uk_sys_post_code 唯一索引，避免无法重新创建同名岗位编码。
    ///
    /// C-05：预检查（关联校验 + post_code 预查询）移入事务内，使用同一 conn 查询，
    /// 消除"事务外预检 → 事务内删除"的 TOCTOU 竞态窗口。
    pub async fn delete_posts(
        &self,
        post_ids: Vec<i64>,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        // 事务保证：预检 + 批量软删除原子化（预检移入事务内，消除 TOCTOU 竞态 C-05）
        let post_repo = self.post_repo.clone();
        let user_post_repo = self.user_post_repo.clone();
        self.db()
            .transaction::<_, (), ServiceError>(|txn| {
                let post_ids_inner = post_ids.clone();
                async move {
                    for post_id in &post_ids_inner {
                        // 预检：岗位是否已分配给用户（事务内查询，消除 TOCTOU 竞态）
                        let relations = user_post_repo.find_by_post_id_conn(txn, *post_id).await?;
                        if !relations.is_empty() {
                            return Err(ServiceError::bad_request(&crate::tr!(
                                "error.post.assigned_to_user",
                                id = post_id
                            )));
                        }
                        // 校验岗位存在且未删除，并记录 post_code 用于重命名（事务内预查询）
                        let existing = post_repo
                            .find_active_by_id_conn(txn, *post_id)
                            .await?
                            .ok_or_else(|| {
                                ServiceError::not_found(&crate::tr!("error.post.not_found"))
                            })?;
                        if existing.del_flag.as_deref() == Some("2") {
                            return Err(ServiceError::not_found(&crate::tr!(
                                "error.post.not_found"
                            )));
                        }
                        // 多租户越权防护：只能删除本租户岗位（平台操作者放行）
                        if !crate::common::tenant::tenant_allowed(operator_tid, existing.tenant_id)
                        {
                            return Err(ServiceError::forbidden(&crate::tr!(
                                "error.common.forbidden"
                            )));
                        }
                        let renamed = format!("{}_deleted_{}", existing.post_code, post_id);
                        post_repo
                            .soft_delete_with_rename_conn(txn, *post_id, renamed)
                            .await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Transaction(se) => se,
                sea_orm::TransactionError::Connection(db_err) => {
                    tracing::error!("岗位删除事务连接错误: {}", db_err);
                    ServiceError::internal(&crate::tr!("error.common.tx_failed"))
                }
            })?;
        Ok(())
    }

    /// 导出岗位列表（受 EXPORT_MAX_ROWS 限制，避免无上限查询导致 OOM）
    pub async fn export_posts(
        &self,
        query: PostQueryDto,
        tenant_scope: Option<i64>,
    ) -> Result<Vec<SysPostModel>, ServiceError> {
        // 导出使用大分页，获取全部符合条件的记录（上限 EXPORT_MAX_ROWS）
        let (rows, _) = self
            .post_repo
            .find_page_filtered(
                0,
                crate::common::page::EXPORT_MAX_ROWS,
                query.post_code.as_deref(),
                query.post_name.as_deref(),
                query.status.as_deref(),
                tenant_scope,
            )
            .await?;
        Ok(rows)
    }
}
