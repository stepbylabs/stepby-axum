//! 参数配置模块 Service 层
//!
//! 职责：
//! - 参数配置 CRUD、config_key 唯一性校验
//! - 按 config_key 查询参数值（前端读取配置用）
//! - 批量物理删除（config 表无 del_flag）
//! - Excel 导出全量查询
//! - 刷新缓存（当前无缓存层，直接返回成功）
//!
//! 不依赖任何 Web 框架类型（axum / tower / tower-http）

use chrono::NaiveDateTime;
use sea_orm::{DatabaseConnection, Set};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::common::error::ServiceError;
use crate::common::page::{default_page_num, default_page_size, PageDomain};
use crate::entity::sys_config::{
    ActiveModel as SysConfigActiveModel, Model as SysConfigModel,
};
use crate::repository::sys_config::SysConfigRepository;

// ==================== DTO ====================

/// 参数配置分页查询 DTO
#[derive(Debug, Clone, Deserialize, IntoParams, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigQueryDto {
    #[serde(default = "default_page_num")]
    pub page_num: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub config_name: Option<String>,
    pub config_key: Option<String>,
    pub config_type: Option<String>,
    /// 开始时间（兼容前端 addDateRange 嵌套格式 params[beginTime]）
    #[serde(alias = "params[beginTime]", default)]
    pub begin_time: Option<String>,
    /// 结束时间（兼容前端 addDateRange 嵌套格式 params[endTime]）
    #[serde(alias = "params[endTime]", default)]
    pub end_time: Option<String>,
}

impl From<&ConfigQueryDto> for PageDomain {
    fn from(dto: &ConfigQueryDto) -> Self {
        PageDomain {
            page_num: dto.page_num,
            page_size: dto.page_size,
            order_by_column: None,
            is_asc: None,
        }
    }
}

/// 新增参数配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigAddDto {
    #[validate(length(min = 1, max = 100, message = "参数名称不能为空且不超过100字符"))]
    pub config_name: Option<String>,
    #[validate(length(min = 1, max = 100, message = "参数键名不能为空且不超过100字符"))]
    pub config_key: String,
    pub config_value: Option<String>,
    pub config_type: Option<String>,
    #[validate(length(max = 500, message = "备注长度不能超过500"))]
    pub remark: Option<String>,
}

/// 修改参数配置 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigEditDto {
    pub config_id: i64,
    #[validate(length(min = 1, max = 100, message = "参数名称不能为空且不超过100字符"))]
    pub config_name: Option<String>,
    #[validate(length(min = 1, max = 100, message = "参数键名不能为空且不超过100字符"))]
    pub config_key: String,
    pub config_value: Option<String>,
    pub config_type: Option<String>,
    #[validate(length(max = 500, message = "备注长度不能超过500"))]
    pub remark: Option<String>,
}

// ==================== 辅助函数 ====================

/// 解析时间字符串（%Y-%m-%d 格式），失败返回 ServiceError
fn parse_time(s: &str) -> Result<NaiveDateTime, ServiceError> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| ServiceError::bad_request(&format!("时间格式不正确: {}", s)))
}

// ==================== Service 实现 ====================

/// 参数配置模块 Service
pub struct SysConfigService {
    config_repo: SysConfigRepository,
}

impl SysConfigService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            config_repo: SysConfigRepository::new(db),
        }
    }

    /// 分页查询参数配置
    ///
    /// 支持 config_name 模糊、config_key 模糊、config_type 精确、时间范围筛选
    pub async fn get_config_page(
        &self,
        query: ConfigQueryDto,
    ) -> Result<(Vec<SysConfigModel>, u64), ServiceError> {
        let page = PageDomain::from(&query);
        let offset = page.offset();
        let limit = page.limit();

        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };

        let (rows, total) = self
            .config_repo
            .find_page_filtered(
                offset,
                limit,
                query.config_name.as_deref(),
                query.config_key.as_deref(),
                query.config_type.as_deref(),
                begin,
                end,
            )
            .await?;
        Ok((rows, total))
    }

    /// 根据 config_id 查询参数配置详情
    pub async fn get_config_by_id(
        &self,
        config_id: i64,
    ) -> Result<SysConfigModel, ServiceError> {
        let model = self
            .config_repo
            .find_by_id(config_id)
            .await?
            .ok_or_else(|| ServiceError::not_found("参数配置不存在"))?;
        Ok(model)
    }

    /// 按 config_key 查询参数值（前端读取配置用）
    ///
    /// 返回 config_value 字符串；若配置不存在返回 not_found
    pub async fn get_config_by_key(
        &self,
        config_key: &str,
    ) -> Result<String, ServiceError> {
        let model = self
            .config_repo
            .find_by_config_key(config_key)
            .await?
            .ok_or_else(|| ServiceError::not_found("参数配置不存在"))?;
        Ok(model.config_value.unwrap_or_default())
    }

    /// 新增参数配置
    ///
    /// 业务校验：config_key 唯一性
    pub async fn add_config(
        &self,
        dto: ConfigAddDto,
        operator: &str,
    ) -> Result<SysConfigModel, ServiceError> {
        dto.validate()?;

        // config_key 唯一性校验
        let existing = self.config_repo.find_by_config_key(&dto.config_key).await?;
        if existing.is_some() {
            return Err(ServiceError::bad_request("参数键名已存在"));
        }

        let now = chrono::Local::now().naive_local();
        let am = SysConfigActiveModel {
            config_name: Set(dto.config_name),
            config_key: Set(dto.config_key),
            config_value: Set(dto.config_value),
            config_type: Set(dto.config_type),
            create_by: Set(Some(operator.to_string())),
            create_time: Set(Some(now)),
            update_by: Set(Some(operator.to_string())),
            update_time: Set(Some(now)),
            remark: Set(dto.remark),
            ..Default::default()
        };

        let model = self.config_repo.insert(am).await?;
        Ok(model)
    }

    /// 修改参数配置
    ///
    /// 业务校验：config_key 唯一性（排除自身）
    pub async fn edit_config(
        &self,
        dto: ConfigEditDto,
        operator: &str,
    ) -> Result<SysConfigModel, ServiceError> {
        dto.validate()?;

        let existing = self.get_config_by_id(dto.config_id).await?;

        // config_key 变更时校验唯一性（排除自身）
        let old_key = existing.config_key.clone();
        if dto.config_key != old_key {
            let conflict = self.config_repo.find_by_config_key(&dto.config_key).await?;
            if conflict.is_some() {
                return Err(ServiceError::bad_request("参数键名已存在"));
            }
        }

        let now = chrono::Local::now().naive_local();
        let mut am: SysConfigActiveModel = existing.into();
        am.config_name = Set(dto.config_name);
        am.config_key = Set(dto.config_key);
        am.config_value = Set(dto.config_value);
        am.config_type = Set(dto.config_type);
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.remark = Set(dto.remark);

        let model = self.config_repo.update(am).await?;
        Ok(model)
    }

    /// 批量删除参数配置（物理删除，config 表无 del_flag）
    pub async fn delete_configs(&self, config_ids: Vec<i64>) -> Result<(), ServiceError> {
        self.config_repo.delete_by_ids(config_ids).await?;
        Ok(())
    }

    /// 刷新缓存
    ///
    /// 当前后端参数查询直接走 DB，无 Redis 缓存层，此接口直接返回成功。
    pub async fn refresh_cache(&self) -> Result<(), ServiceError> {
        Ok(())
    }

    /// 导出参数配置（全量查询不分页）
    ///
    /// 支持与分页查询相同的筛选条件，返回全部匹配记录
    pub async fn export_configs(
        &self,
        query: ConfigQueryDto,
    ) -> Result<Vec<SysConfigModel>, ServiceError> {
        let begin = match query.begin_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };
        let end = match query.end_time.as_deref() {
            Some(s) if !s.is_empty() => Some(parse_time(s)?),
            _ => None,
        };

        let rows = self
            .config_repo
            .find_all_filtered(
                query.config_name.as_deref(),
                query.config_key.as_deref(),
                query.config_type.as_deref(),
                begin,
                end,
            )
            .await?;
        Ok(rows)
    }
}
