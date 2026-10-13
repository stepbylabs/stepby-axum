// stepby-axum/src/repository/sys_config.rs
//! sys_config 数据访问层（参数配置表，物理删除）
//!
//! 继承 BaseRepository 通用 CRUD，扩展参数配置特有查询：
//! - 生效行查询（租户覆盖行优先，回落平台默认行；复合唯一域 `uk_sys_config_tenant_key`）
//! - 租户生效视图（列表/导出：本租户行 + 平台可见行，绝不返回 platform_only）
//! - 多条件分页查询（config_name/config_key 模糊 + config_type 精确 + 时间范围）
//! - 多条件全量查询（导出用，不分页，但受 EXPORT_MAX_ROWS 限制）

use chrono::NaiveDateTime;
use sea_orm::*;

use crate::common::like_escape;
use crate::common::page::EXPORT_MAX_ROWS;
use crate::common::sort::SortOrder;
use crate::entity::sys_config::{ActiveModel, Column, Entity as SysConfig, Model};
use crate::repository::base::BaseRepository;

/// 参数配置 Repository
#[derive(Clone)]
pub struct SysConfigRepository {
    base: BaseRepository<SysConfig>,
}

impl SysConfigRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn base(&self) -> &BaseRepository<SysConfig> {
        &self.base
    }

    /// 按 config_id 查询单条参数配置
    pub async fn find_by_id(&self, config_id: i64) -> Result<Option<Model>, DbErr> {
        SysConfig::find_by_id(config_id).one(self.base.db()).await
    }

    /// 按 (tenant_id, config_key) 查询单行（复合唯一域 `uk_sys_config_tenant_key`）。
    ///
    /// 用于租户覆盖层的精确查询：仅返回 `tenant_id = tenant_id` 的行。
    pub async fn find_by_tenant_key(
        &self,
        tenant_id: i64,
        config_key: &str,
    ) -> Result<Option<Model>, DbErr> {
        SysConfig::find()
            .filter(Column::TenantId.eq(tenant_id))
            .filter(Column::ConfigKey.eq(config_key))
            .one(self.base.db())
            .await
    }

    /// 按 config_key 查询平台行（`tenant_id = 0`）——平台默认层的唯一事实来源。
    pub async fn find_platform_by_key(&self, config_key: &str) -> Result<Option<Model>, DbErr> {
        self.find_by_tenant_key(0, config_key).await
    }

    /// **生效行查询**（读时合并，§27.8）：租户覆盖行（`tenant_id = tid`）优先，
    /// 无覆盖行则回落平台行（`tenant_id = 0`）。
    ///
    /// - `tenant_id = None / Some(0)`：只读平台默认层；
    /// - `tenant_id = Some(tid)`（tid≠0）：`tenant_id IN (0, tid)`，按 tenant_id 降序取首行
    ///   → 租户行优先。`tenant_private` 行天然只在 tid 匹配时可见（查询条件为等值 tid）。
    ///
    /// 这是 config 值的**唯一**生效读取入口，不存在"只按 key 查、无租户条件"的路径。
    pub async fn find_effective_by_key(
        &self,
        config_key: &str,
        tenant_id: Option<i64>,
    ) -> Result<Option<Model>, DbErr> {
        match tenant_id.filter(|t| *t != 0) {
            Some(tid) => {
                SysConfig::find()
                    .filter(Column::ConfigKey.eq(config_key))
                    .filter(Column::TenantId.is_in([0i64, tid]))
                    .order_by_desc(Column::TenantId)
                    .one(self.base.db())
                    .await
            }
            // None / Some(0)：平台默认层
            None => self.find_platform_by_key(config_key).await,
        }
    }

    /// **租户生效视图**（列表 / 导出用，§27.8）：本租户自己的行 + 平台行中
    /// `visible_to_tenant = '1'`（租户可见）的行；同一 key 以本租户行覆盖平台行展示。
    ///
    /// fail-closed：
    /// - **绝不返回** `visible_to_tenant != '1'` 的平台行（含全部 `platform_only` 行）；
    /// - 绝不返回其它租户的行（仅 `tenant_id = tid` 与平台 `tenant_id = 0`）。
    ///
    /// 实现说明：平台行需排除"已被本租户覆盖"的 key，跨方言的 `NOT EXISTS` 子查询写法
    /// 成本高且可读性差；sys_config 为小表（运维元数据），故在内存中按键去重合并，
    /// 由调用方分页（见 `find_effective_page`）。
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）。合并后的行集
    /// 无法再走 SQL `ORDER BY`，在内存中按列排序（列覆盖与 service 白名单一致）；
    /// `None` 时保持原 `config_id ASC` 稳定排序。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_effective_all(
        &self,
        tid: i64,
        config_name: Option<&str>,
        config_key: Option<&str>,
        config_type: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<Vec<Model>, DbErr> {
        // 1. 本租户自己的行（全量可见，含 tenant_private）
        let mut own =
            Self::build_filter_query(config_name, config_key, config_type, begin_time, end_time)
                .filter(Column::TenantId.eq(tid))
                .all(self.base.db())
                .await?;

        // 2. 平台可见行（visible_to_tenant = '1'，已排除 platform_only）
        let platform =
            Self::build_filter_query(config_name, config_key, config_type, begin_time, end_time)
                .filter(Column::TenantId.eq(0))
                .filter(Column::VisibleToTenant.eq("1"))
                .all(self.base.db())
                .await?;

        // 3. 同 key 以租户行覆盖平台行（租户行优先）
        let overridden: std::collections::HashSet<String> =
            own.iter().map(|m| m.config_key.clone()).collect();
        for p in platform {
            if !overridden.contains(&p.config_key) {
                own.push(p);
            }
        }
        match sort {
            Some(s) => Self::sort_models_by(&mut own, s),
            None => own.sort_by_key(|m| m.config_id),
        }
        Ok(own)
    }

    /// 内存排序：租户生效视图为「两查询各自拉取后内存合并」，动态排序在此按列应用。
    ///
    /// 列覆盖与 service 层 `SORTABLE_COLUMNS` 白名单一致（白名单外的列不会传进来，
    /// 通配分支仅防御性保持原序）；`Order::Desc` 时反转比较结果（`Equal` 反转仍为 `Equal`）。
    fn sort_models_by(rows: &mut [Model], sort: SortOrder<Column>) {
        use std::cmp::Ordering;
        let asc = matches!(sort.dir, Order::Asc);
        rows.sort_by(|a, b| {
            let ord = match sort.column {
                Column::ConfigId => a.config_id.cmp(&b.config_id),
                Column::ConfigName => a.config_name.cmp(&b.config_name),
                Column::ConfigKey => a.config_key.cmp(&b.config_key),
                Column::ConfigType => a.config_type.cmp(&b.config_type),
                Column::CreateTime => a.create_time.cmp(&b.create_time),
                Column::UpdateTime => a.update_time.cmp(&b.update_time),
                _ => Ordering::Equal,
            };
            if asc { ord } else { ord.reverse() }
        });
    }

    /// 租户生效视图分页（见 `find_effective_all`）。total 为合并去重后的总数。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_effective_page(
        &self,
        tid: i64,
        offset: u64,
        limit: u64,
        config_name: Option<&str>,
        config_key: Option<&str>,
        config_type: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let merged = self
            .find_effective_all(
                tid,
                config_name,
                config_key,
                config_type,
                begin_time,
                end_time,
                sort,
            )
            .await?;
        let total = merged.len() as u64;
        let rows = merged
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok((rows, total))
    }

    /// 按 config_id 批量查询（H-4：删除前查询 config_key 用于缓存失效，避免 N+1）
    pub async fn find_by_ids(&self, ids: Vec<i64>) -> Result<Vec<Model>, DbErr> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        SysConfig::find()
            .filter(Column::ConfigId.is_in(ids))
            .all(self.base.db())
            .await
    }

    /// 多条件分页查询（config_name 模糊，config_key 模糊，config_type 精确，时间范围）
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `config_id ASC`（原稳定排序语义不变）。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        config_name: Option<&str>,
        config_key: Option<&str>,
        config_type: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        // 稳定排序，防翻页重复/漏行；动态排序（白名单已解析）或默认 config_id ASC
        let query =
            Self::build_filter_query(config_name, config_key, config_type, begin_time, end_time);
        let query = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_asc(Column::ConfigId),
        };

        let total = query.clone().count(self.base.db()).await?;
        let rows = query
            .offset(offset)
            .limit(limit)
            .all(self.base.db())
            .await?;
        Ok((rows, total))
    }

    /// 多条件全量查询（导出用，不分页但受 EXPORT_MAX_ROWS 限制防 OOM）
    ///
    /// `sort` 与 `find_page_filtered` 同口径，保证导出与页面列表同序
    /// （`None` 时同为 `config_id ASC`）。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_all_filtered(
        &self,
        config_name: Option<&str>,
        config_key: Option<&str>,
        config_type: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<Vec<Model>, DbErr> {
        let query =
            Self::build_filter_query(config_name, config_key, config_type, begin_time, end_time);
        let query = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_asc(Column::ConfigId),
        };
        query.limit(EXPORT_MAX_ROWS).all(self.base.db()).await
    }

    /// 构建多条件查询（分页与全量查询共用）
    fn build_filter_query(
        config_name: Option<&str>,
        config_key: Option<&str>,
        config_type: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
    ) -> Select<SysConfig> {
        let mut query = SysConfig::find();
        if let Some(name) = config_name {
            query = query.filter(Column::ConfigName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(key) = config_key {
            query = query.filter(Column::ConfigKey.like(format!("%{}%", like_escape(key))));
        }
        if let Some(ct) = config_type {
            query = query.filter(Column::ConfigType.eq(ct));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }
        query
    }

    /// 批量删除参数配置（物理删除）
    pub async fn delete_by_ids(&self, config_ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysConfig::delete_many()
            .filter(Column::ConfigId.is_in(config_ids))
            .exec(self.base.db())
            .await
    }

    /// 插入参数配置
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 更新参数配置
    pub async fn update(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.update(model).await
    }
}
