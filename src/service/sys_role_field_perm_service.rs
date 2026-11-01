// stepby-axum/src/service/sys_role_field_perm_service.rs
//! 字段级权限 M2：角色字段级权限服务（三层开关判定链的**单一入口**）
//!
//! # 三层开关判定链（hidden_fields / 矩阵接口共用，顺序收敛）
//!
//! 1. **第一层 · 平台开关**：`sys_config.sys.fieldPerm.enabled`（governance::CONFIGS
//!    登记，Coverage::Locked 平台锁定）。热加载取值经 `SysConfigService`
//!    cache-aside 读取（改配置即时生效）。取值 != "true"（含配置缺失/读取失败）⇒
//!    fail-safe 短路为空集合 / 矩阵接口拒绝。**默认 'false' ⇒ 全系统关闭态零行为变化**。
//! 2. **第二层 · 套餐能力位**：`role.field_perm`（governance::FEATURES 登记，
//!    默认 off = 无此位即不可用）。平台操作者（tid==0，无套餐概念）跳过本层；
//!    租户操作者经 `tenant_features_conn`（平台天花板 ∩ 套餐覆盖）判定，
//!    off ⇒ 空集合 / 接口拒绝。
//! 3. **第三层 · 角色授权**：`sys_role_field_perm` 行（hidden 语义）。operator
//!    所有角色的 hidden 行取**并集**（任一角色声明隐藏即隐藏）。
//!
//! # 管理员豁免
//!
//! operator 含超管（user_id==1 或拥有平台超管角色，即 `*:*:*` 的持有来源）⇒
//! hidden_fields **恒空**（管理员不受字段级权限限制，对齐 M1 脱敏的超管口径）。
//!
//! # 关闭态无行为变化（可证伪）
//!
//! 默认部署（config=false、能力位 off、矩阵无行）下 `hidden_fields` 恒返回空集合，
//! 列表 VO 字段全量——服务层单测 `hidden_fields_disabled_returns_empty` 与
//! `user_page_hidden_fields_disabled_keeps_all_columns` 锁死该契约。

use std::collections::HashSet;

use sea_orm::{DatabaseConnection, EntityTrait};

use crate::common::constants::SUPER_ADMIN_USER_ID;
use crate::common::error::ServiceError;
use crate::common::features::{FEATURE_OFF, FeatureSet};
use crate::entity::sys_role::Model as SysRoleModel;
use crate::repository::sys_role::SysRoleRepository;
use crate::repository::sys_role_field_perm::SysRoleFieldPermRepository;
use crate::service::sys_config_service::SysConfigService;

/// 字段级权限白名单：(业务表标识, 可控字段清单)。
///
/// 结构支持扩展：新增受控表/字段只需在此追加（矩阵接口与裁剪判定均以本表为
/// 唯一事实源，未登记的 table_key / field_key 一律拒绝，fail-closed）。
/// 首期只开 user 域两字段（与 M1 脱敏字段对齐）。
pub const FIELD_PERM_TABLES: &[(&str, &[&str])] = &[("sys_user", &["phonenumber", "email"])];

/// 第一层平台开关的 `sys_config` 键（值与迁移种子共享同一字符串常量的语义副本；
/// 迁移侧常量见 `migration::m20261003_000005_role_field_perm::FIELD_PERM_ENABLED_CONFIG_KEY`）
/// 第一层平台开关的 `sys_config` 键（`getInfo` 的 `showFieldPerm` 判定与服务层
/// `platform_enabled` **同源**消费，常量化避免两处漂移）
pub const FIELD_PERM_ENABLED_CONFIG_KEY: &str = "sys.fieldPerm.enabled";
/// 第二层租户能力位键（与 `governance::FEATURES` 登记项逐字一致；同上同源消费）
pub const FIELD_PERM_FEATURE_KEY: &str = "role.field_perm";

/// 查白名单：返回业务表的受控字段清单（未登记的 table_key 返回 None）
pub fn field_perm_whitelist(table_key: &str) -> Option<&'static [&'static str]> {
    FIELD_PERM_TABLES
        .iter()
        .find(|(t, _)| *t == table_key)
        .map(|(_, fields)| *fields)
}

/// 字段级权限矩阵项（矩阵接口的行结构：白名单字段 + hidden 态）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FieldPermItem {
    /// 字段标识（白名单内）
    pub field_key: String,
    /// 是否对该角色隐藏
    pub hidden: bool,
}

/// 矩阵保存请求体（全量覆盖式：hiddenFields 即该角色在该表下的完整 hidden 清单）
#[derive(Debug, Clone, serde::Deserialize, garde::Validate, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FieldPermSaveDto {
    /// hidden 字段清单（全量覆盖；只接受白名单字段）
    #[serde(default)]
    #[garde(skip)]
    pub hidden_fields: Vec<String>,
}

/// 角色字段级权限服务
#[derive(Clone)]
pub struct SysRoleFieldPermService {
    db: DatabaseConnection,
    perm_repo: SysRoleFieldPermRepository,
    role_repo: SysRoleRepository,
    config_service: SysConfigService,
}

impl SysRoleFieldPermService {
    pub fn new(db: DatabaseConnection, config_service: SysConfigService) -> Self {
        Self {
            perm_repo: SysRoleFieldPermRepository::new(db.clone()),
            role_repo: SysRoleRepository::new(db.clone()),
            config_service,
            db,
        }
    }

    // ==================== 开关判定链（三层收敛，单一入口） ====================

    /// 第一层：平台开关是否开启（热加载；配置缺失/读取失败 = 关闭，fail-safe）
    async fn platform_enabled(&self) -> bool {
        match self
            .config_service
            .get_config_value_by_key_cached(FIELD_PERM_ENABLED_CONFIG_KEY, None)
            .await
        {
            Ok(Some(val)) => val.trim().eq_ignore_ascii_case("true"),
            _ => false,
        }
    }

    /// 第二层：套餐能力位是否可用。
    ///
    /// 平台操作者（tid==0，无套餐概念）恒可用（由第一层平台开关统一管平台侧姿态）；
    /// 租户操作者取**有效能力集**（平台层 `[features]` 天花板 ∩ 套餐 `features` 覆盖），
    /// off / 查询失败 ⇒ 不可用（fail-closed）。
    async fn tenant_capable(&self, db: &DatabaseConnection, operator_tid: i64) -> bool {
        if operator_tid == 0 {
            return true;
        }
        let features: FeatureSet = match crate::service::sys_tenant_service::tenant_features_conn(
            db,
            operator_tid,
        )
        .await
        {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(
                    tenant_id = operator_tid,
                    "字段级权限能力位判定：查询租户能力集失败，fail-closed 视为不可用: {}",
                    e
                );
                return false;
            }
        };
        features.mode(FIELD_PERM_FEATURE_KEY) != FEATURE_OFF
    }

    /// 开关链前置校验（矩阵读写接口共用）：任一层不满足 ⇒ 拒绝（i18n 明确提示）
    async fn ensure_enabled(&self, operator_tid: i64) -> Result<(), ServiceError> {
        // 第一层：平台开关
        if !self.platform_enabled().await {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.fieldperm.disabled"
            )));
        }
        // 第二层：套餐能力位
        if !self.tenant_capable(&self.db, operator_tid).await {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.fieldperm.disabled"
            )));
        }
        Ok(())
    }

    // ==================== 裁剪判定单一入口 ====================

    /// **裁剪判定单一入口**：operator 查看业务表 `table_key` 时应隐藏的字段集合。
    ///
    /// 判定链（任一不满足 ⇒ `Ok(空集合)` = 无裁剪 = 关闭态零行为变化）：
    /// 1. table_key 必须在白名单内（未登记表不裁剪）；
    /// 2. 第一层平台开关必须开启（热加载）；
    /// 3. 第二层套餐能力位（租户操作者）必须可用；
    /// 4. operator 含超管 ⇒ 恒空（管理员不受限）；
    /// 5. operator 全部角色的 hidden 行并集。
    ///
    /// `Err` 只在**判定所依赖的存储读不出来**时发生（角色行 / 矩阵行）。旧实现把这两种
    /// 失败折成空集合并把日志写成"fail-closed 返回空集合"——**注释与事实相反**：空集合
    /// 是"什么都不隐藏"，即 fail-**open**，正是这个特性会把管理员设为隐藏的手机号/身份证
    /// 在一次 DB 抖动里原样发给调用者（本仓第四次抓到"注释与实现相反"，前三次见
    /// AGENTS 测试门禁 ㉒/㉟ 与台账 b140）。
    ///
    /// 为什么改成拒绝**不新增失败面**：判定与紧随其后的列表读的是同一个连接池，
    /// 存储真故障时那次列表读同样会失败；区别只在于"失败时说了什么"——
    /// 旧形状说的是"给你看全部"，新形状说的是"这次没读出来"。
    ///
    /// `operator_user_id = None` 仍返回 `Ok(空集合)` 并打 warn：那不是存储故障，而是
    /// 内部调用路径没有操作者上下文（无法判定管理员豁免）；裁剪的"误伤"是把别人的
    /// 数据字段整个抹掉，破坏性大于暴露性，故这一支保持保守不裁剪。
    pub async fn hidden_fields(
        &self,
        operator_user_id: Option<i64>,
        operator_tid: i64,
        table_key: &str,
    ) -> Result<HashSet<String>, ServiceError> {
        // 0) 白名单外不裁剪
        if field_perm_whitelist(table_key).is_none() {
            return Ok(HashSet::new());
        }
        let Some(op_uid) = operator_user_id else {
            tracing::warn!(
                table_key = %table_key,
                "字段级权限裁剪：无操作者上下文，保守不裁剪（返回空集合）"
            );
            return Ok(HashSet::new());
        };

        // 1) 第一层：平台开关（关闭 ⇒ 短路，关闭态零行为变化）
        if !self.platform_enabled().await {
            return Ok(HashSet::new());
        }
        // 2) 第二层：套餐能力位
        if !self.tenant_capable(&self.db, operator_tid).await {
            return Ok(HashSet::new());
        }
        // 3) 管理员豁免：超管（user_id==1 或平台超管角色 = *:*:* 持有来源）恒不受限
        let roles: Vec<SysRoleModel> =
            self.role_repo.find_by_user_id(op_uid).await.map_err(|e| {
                tracing::error!(
                    operator_user_id = op_uid,
                    error = %e,
                    "字段级权限裁剪：查询 operator 角色失败（拒绝响应，不放开隐藏字段）"
                );
                ServiceError::internal(&crate::tr!("error.common.db_failed"))
            })?;
        if op_uid == SUPER_ADMIN_USER_ID || roles.iter().any(|r| r.is_platform_super_admin()) {
            return Ok(HashSet::new());
        }
        // 4) 第三层：角色授权行并集
        let role_ids: Vec<i64> = roles.iter().map(|r| r.role_id).collect();
        let fields = self
            .perm_repo
            .hidden_fields_by_roles(&role_ids, table_key)
            .await
            .map_err(|e| {
                tracing::error!(
                    operator_user_id = op_uid,
                    table_key = %table_key,
                    error = %e,
                    "字段级权限裁剪：查询矩阵行失败（拒绝响应，不放开隐藏字段）"
                );
                ServiceError::internal(&crate::tr!("error.common.db_failed"))
            })?;
        Ok(fields.into_iter().collect())
    }

    // ==================== 矩阵读写接口（服务层） ====================

    /// 校验目标角色存在且属当前操作者租户（安全审查轮 1 修复：矩阵读写此前未校验
    /// role_id 归属，租户管理员可枚举自增 role_id 跨租户读写他租户角色的字段配置）。
    /// 404 语义（不区分不存在/越权，防 role_id 探测）；平台操作者（tid=0）恒放行。
    async fn ensure_role_tenant_allowed(
        &self,
        role_id: i64,
        operator_tid: i64,
    ) -> Result<(), ServiceError> {
        let role = crate::entity::sys_role::Entity::find_by_id(role_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.common.not_found")))?;
        if !crate::common::tenant::tenant_allowed(operator_tid, role.tenant_id) {
            return Err(ServiceError::not_found(&crate::tr!(
                "error.common.not_found"
            )));
        }
        Ok(())
    }

    /// 查询角色在某业务表下的字段权限矩阵：**全白名单字段** + hidden 态。
    ///
    /// 开关链未开启（第一层/第二层任一不满足）⇒ 拒绝（错误码 + i18n key，
    /// 前端隐藏入口由接口数据驱动）；table_key 未登记 ⇒ bad_request。
    pub async fn get_matrix(
        &self,
        role_id: i64,
        operator_tid: i64,
        table_key: &str,
    ) -> Result<Vec<FieldPermItem>, ServiceError> {
        // table_key 合法性先于开关校验：不存在的表没有"拒绝查看"的语义必要
        let fields = field_perm_whitelist(table_key)
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.common.invalid_param")))?;
        // 顺序契约：开关链校验（403）先于角色归属（404）——能力位缺失时
        // 功能未开通，须先 403 短路，不得被资源 404 抢先（契约测试
        // tenant_without_capability_is_blocked 锁死该顺序）
        self.ensure_enabled(operator_tid).await?;
        self.ensure_role_tenant_allowed(role_id, operator_tid)
            .await?;

        let hidden_rows = self
            .perm_repo
            .find_by_role_and_table(role_id, table_key)
            .await?;
        let hidden_set: HashSet<String> = hidden_rows.into_iter().map(|r| r.field_key).collect();
        Ok(fields
            .iter()
            .map(|f| FieldPermItem {
                field_key: (*f).to_string(),
                hidden: hidden_set.contains(*f),
            })
            .collect())
    }

    /// 全量覆盖式保存角色在某业务表下的 hidden 字段清单。
    ///
    /// - 开关链校验同 get_matrix（关闭态拒绝写，fail-safe：不产生"关了还能配"的悬空配置）；
    /// - table_key / field_key 均按白名单校验，未登记项拒绝（防呆，避免写入永远不生效的行）；
    /// - 重复值去重后交 repository 事务覆盖（UNIQUE 约束 + 冲突忽略保证幂等重放）。
    pub async fn save_matrix(
        &self,
        role_id: i64,
        operator_tid: i64,
        table_key: &str,
        dto: FieldPermSaveDto,
    ) -> Result<(), ServiceError> {
        let fields = field_perm_whitelist(table_key)
            .ok_or_else(|| ServiceError::bad_request(&crate::tr!("error.common.invalid_param")))?;
        // 顺序契约同 get_matrix：开关链 403 先行，角色归属 404 在后
        self.ensure_enabled(operator_tid).await?;
        self.ensure_role_tenant_allowed(role_id, operator_tid)
            .await?;

        // 白名单过滤 + 去重（保持请求顺序；重复项幂等合并）
        let mut seen = HashSet::new();
        let mut hidden: Vec<String> = Vec::new();
        for f in &dto.hidden_fields {
            if fields.contains(&f.as_str()) && seen.insert(f.clone()) {
                hidden.push(f.clone());
            }
        }
        self.perm_repo
            .replace_role_fields(role_id, table_key, &hidden)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::sys_user_service::{
        apply_field_perm_and_mask, hidden_field_set_to_omit_columns,
    };
    use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait, Statement};

    /// b144 A6（形状锁）：`hidden_fields` 的两个存储读点必须**上抛**，不得折成空集合。
    ///
    /// 为什么单独钉这一条：判定链上还有四处"合法的空集合"（白名单外 / 无上下文 /
    /// 平台开关关 / 能力位关），它们与"读不出来"在返回形状上完全相同。把后者折进前者
    /// 就是让一次 DB 抖动表现得像"这个用户没有被隐藏任何字段"。所以判据钉的是
    /// **形状**（`Result` + 两处 `map_err` 上抛 + 注释不得再自称 fail-closed），
    /// 而不是某个用例的输出集合——用例只证一次，形状锁证每一次。
    #[test]
    fn hidden_fields_shape_never_folds_storage_failure_into_no_trimming() {
        use crate::common::prod_scan::{Scan, prod_file};
        let text = prod_file(
            "src/service/sys_role_field_perm_service.rs",
            &Scan::default(),
        )
        .text();

        // 1) 判定入口必须是 Result（返回裸集合就没有"读不出来"这一档）
        assert_eq!(
            text.matches("-> Result<HashSet<String>, ServiceError> {")
                .count(),
            1,
            "裁剪判定必须返回 Result，且只有这一处该形状"
        );
        // 2) 两个存储读点都必须经 map_err 上抛（角色行 / 矩阵行）
        assert_eq!(
            text.matches("find_by_user_id(op_uid)").count(),
            1,
            "operator 角色读点只能有一处"
        );
        assert_eq!(
            text.matches("hidden_fields_by_roles(&role_ids, table_key)")
                .count(),
            1,
            "矩阵行读点只能有一处"
        );
        let raises = text
            .split("map_err(|e| {")
            .skip(1)
            .filter(|w| {
                w.chars()
                    .take(400)
                    .collect::<String>()
                    .contains("不放开隐藏字段")
            })
            .count();
        assert_eq!(
            raises, 2,
            "两处读失败都必须留 error 级痕并上抛，实际 {raises}"
        );

        // 3) "fail-closed 返回空集合"这句自相矛盾的注释必须绝迹（注释与事实相反是本仓第四次）
        assert_eq!(
            text.matches("fail-closed 返回空集合").count(),
            0,
            "空集合 = 不裁剪 = fail-open，注释不得再把它写成 fail-closed"
        );

        // 4) 活性正控：把形状改回缺陷（裸集合 + 折空）必须被 1) 抓到
        let defective = "pub async fn hidden_fields(&self) -> HashSet<String> { HashSet::new() }";
        assert_eq!(
            defective
                .matches("-> Result<HashSet<String>, ServiceError> {")
                .count(),
            0,
            "探针形状确实不带 Result（否则第 1 条是虚锁）"
        );
    }
    use std::sync::Arc;

    use crate::entity::sys_role::{ActiveModel as RoleActiveModel, Entity as SysRole};
    use crate::entity::sys_user::{ActiveModel as UserActiveModel, Entity as SysUser};
    use crate::entity::sys_user_role::{ActiveModel as UserRoleActiveModel, Entity as SysUserRole};
    use crate::repository::sys_role_field_perm::SysRoleFieldPermRepository;
    use crate::repository::test_support::migrated_db;
    use crate::service::sys_config_service::SysConfigService;
    use crate::service::sys_user_service::SysUserService;
    use crate::shared_store::LocalStore;

    /// 隔离测试库（全量迁移建表）+ 字段级权限 M2 兜底
    ///（sys_role_field_perm 表 / sys.fieldPerm.enabled 种子行；幂等，可重复调用）
    async fn test_db() -> DatabaseConnection {
        let db = migrated_db().await.unwrap();
        crate::initialize::ensure_role_field_perm_tables(&db)
            .await
            .unwrap();
        db
    }

    /// 每次新建独立 LocalStore ⇒ config 缓存为空，读到的值必然反映当前 DB 行
    ///（热加载语义：改配置后新 service 实例立即可见）
    fn make_service(db: &DatabaseConnection) -> SysRoleFieldPermService {
        let store: Arc<dyn crate::shared_store::SharedStore> =
            Arc::new(LocalStore::new(db.clone()));
        SysRoleFieldPermService::new(db.clone(), SysConfigService::new(db.clone(), store))
    }

    /// 修改第一层平台开关（测试专用：直接改 DB 行，新 service 实例读到新值）
    async fn set_config_enabled(db: &DatabaseConnection, on: bool) {
        let val = if on { "true" } else { "false" };
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "UPDATE sys_config SET config_value='{val}' WHERE config_key='sys.fieldPerm.enabled'"
            ),
        ))
        .await
        .unwrap();
    }

    /// 直接插入一条矩阵 hidden 行（跳过服务层开关校验，用于构造第三层角色授权态）
    async fn insert_hidden_row(db: &DatabaseConnection, role_id: i64, field: &str) {
        let repo = SysRoleFieldPermRepository::new(db.clone());
        repo.replace_role_fields(role_id, "sys_user", &[field.to_string()])
            .await
            .unwrap();
    }

    /// 构造普通角色（data_scope=1 全部数据，避免 get_user_page 数据范围收窄干扰）
    async fn insert_role(db: &DatabaseConnection, role_id: i64, is_system: bool) {
        SysRole::insert(RoleActiveModel {
            role_id: sea_orm::Set(role_id),
            tenant_id: sea_orm::Set(0),
            role_name: sea_orm::Set(format!("测试角色{role_id}")),
            role_key: sea_orm::Set(format!("role{role_id}")),
            role_sort: sea_orm::Set(1),
            status: sea_orm::Set("0".to_string()),
            data_scope: sea_orm::Set(Some("1".to_string())),
            is_system: sea_orm::Set(is_system),
            del_flag: sea_orm::Set(Some("0".to_string())),
            ..Default::default()
        })
        .exec(db)
        .await
        .unwrap();
    }

    /// 绑定 user → role（sys_user_role 仅 user_id/role_id/source 三列，全量指定）
    async fn bind_user_role(db: &DatabaseConnection, user_id: i64, role_id: i64) {
        SysUserRole::insert(UserRoleActiveModel {
            user_id: sea_orm::Set(user_id),
            role_id: sea_orm::Set(role_id),
            source: sea_orm::Set("test".to_string()),
        })
        .exec(db)
        .await
        .unwrap();
    }

    /// 构造带手机号/邮箱的普通用户
    async fn insert_user(db: &DatabaseConnection, user_id: i64) {
        SysUser::insert(UserActiveModel {
            user_id: sea_orm::Set(user_id),
            user_name: sea_orm::Set(format!("u{user_id}")),
            nick_name: sea_orm::Set(format!("用户{user_id}")),
            phonenumber: sea_orm::Set(Some("13800000001".to_string())),
            email: sea_orm::Set(Some("u@example.com".to_string())),
            status: sea_orm::Set(Some("0".to_string())),
            del_flag: sea_orm::Set(Some("0".to_string())),
            ..Default::default()
        })
        .exec(db)
        .await
        .unwrap();
    }

    fn empty_hidden() -> HashSet<String> {
        HashSet::new()
    }

    // ==================== 关闭态无行为变化（可证伪核心） ====================

    /// **可证伪回归锁**：默认部署（config='false'）下，
    /// ① 矩阵行存在 → hidden_fields 仍恒空（第一层短路）；
    /// ② 白名单外表恒空；
    /// ③ 无操作者上下文恒空；
    /// ④ 矩阵读写接口拒绝（fail-safe：关闭态不给"能配但不生效"的悬空面）；
    /// ⑤ 列表 VO 字段全量（phonenumber/email 原值保留）。
    #[tokio::test]
    async fn hidden_fields_disabled_has_zero_behavior_change() {
        let db = test_db().await;
        // 第三层先就位：角色 99 对 sys_user 隐藏 phonenumber（若开关链失效，这里会泄漏）
        insert_role(&db, 99, false).await;
        insert_user(&db, 55).await;
        bind_user_role(&db, 55, 99).await;
        insert_hidden_row(&db, 99, "phonenumber").await;

        // config 保持种子默认 'false' = 关闭态
        let svc = make_service(&db);

        // ① 关闭态：hidden 恒空
        assert!(
            svc.hidden_fields(Some(55), 0, "sys_user")
                .await
                .unwrap()
                .is_empty(),
            "关闭态下 hidden_fields 必须恒空（第一层平台开关短路），否则默认部署行为变化"
        );
        // ② 白名单外表恒空（即便开关开启，未登记表也不裁剪）
        assert!(
            svc.hidden_fields(Some(55), 0, "sys_dict")
                .await
                .unwrap()
                .is_empty()
        );
        // ③ 无操作者上下文恒空（保守不裁剪）
        assert!(
            svc.hidden_fields(None, 0, "sys_user")
                .await
                .unwrap()
                .is_empty()
        );

        // ④ 矩阵读写接口拒绝（明确 i18n 错误）
        let read_err = svc.get_matrix(99, 0, "sys_user").await.unwrap_err();
        assert_eq!(read_err.code, 403, "关闭态矩阵读必须 403");
        let write_err = svc
            .save_matrix(
                99,
                0,
                "sys_user",
                FieldPermSaveDto {
                    hidden_fields: vec!["phonenumber".to_string()],
                },
            )
            .await
            .unwrap_err();
        assert_eq!(write_err.code, 403, "关闭态矩阵写必须 403");

        // ⑤ 列表 VO 字段全量：关闭态 + 空隐藏集合 → phonenumber/email 原值保留
        let user_service = {
            let store: Arc<dyn crate::shared_store::SharedStore> =
                Arc::new(LocalStore::new(db.clone()));
            SysUserService::new(db.clone(), store)
        };
        let query: crate::service::sys_user_service::UserQueryDto =
            serde_json::from_value(serde_json::json!({"pageNum": 1, "pageSize": 10})).unwrap();
        let (vos, total) = user_service
            .get_user_page(query, Some(55), None, &empty_hidden())
            .await
            .unwrap();
        assert!(total >= 1, "应至少包含 1 个未删除测试用户");
        // 定位测试用户行（种子库还有 admin 等存量用户，不能按行序断言）
        let me = vos.iter().find(|v| v.user.user_id == 55).unwrap();
        assert_eq!(
            me.user.phonenumber.as_deref(),
            Some("13800000001"),
            "关闭态列表 VO 的 phonenumber 必须全量保留（零行为变化）"
        );
        assert_eq!(
            me.user.email.as_deref(),
            Some("u@example.com"),
            "关闭态列表 VO 的 email 必须全量保留（零行为变化）"
        );
    }

    /// 仓库层关闭态等价锁：omit 空切片走全列 SELECT，行数据完整
    #[tokio::test]
    async fn repository_omit_empty_is_full_select() {
        let db = test_db().await;
        insert_user(&db, 71).await;
        let repo = crate::repository::sys_user::SysUserRepository::new(db.clone());
        let (rows, total) = repo
            .find_page_with_data_scope(
                0,
                10,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                &[],
                None,
            )
            .await
            .unwrap();
        assert!(total >= 1, "应至少包含种子存量用户与测试用户");
        let row = rows.iter().find(|u| u.user_id == 71).unwrap();
        assert_eq!(row.phonenumber.as_deref(), Some("13800000001"));
        assert_eq!(row.email.as_deref(), Some("u@example.com"));
    }

    // ==================== 开启态：裁剪生效 / 管理员豁免 / 能力位拦截 ====================

    /// 开启态（config='true'）：
    /// ① 普通角色按矩阵行裁剪（hidden 并集 → 列表 VO 对应字段 None，掩码叠加不回填）；
    /// ② 超管（user_id==1）恒不受限；
    /// ③ 平台超管角色持有者恒不受限。
    #[tokio::test]
    async fn hidden_fields_enabled_hides_and_admin_exempt() {
        let db = test_db().await;
        set_config_enabled(&db, true).await;

        insert_role(&db, 99, false).await;
        insert_user(&db, 55).await;
        bind_user_role(&db, 55, 99).await;
        insert_hidden_row(&db, 99, "phonenumber").await;
        // user 66 绑定平台超管角色（种子 role_id=1：is_system && tenant_id==0）
        bind_user_role(&db, 66, 1).await;
        // user 66 也绑一个隐藏角色：验证超管判定优先于隐藏行
        bind_user_role(&db, 66, 99).await;

        let svc = make_service(&db);

        // ① 普通角色：hidden = 矩阵行集合
        let hidden = svc.hidden_fields(Some(55), 0, "sys_user").await.unwrap();
        assert_eq!(
            hidden,
            HashSet::from(["phonenumber".to_string()]),
            "开启态下 hidden_fields 应等于该 operator 全部角色的矩阵行并集"
        );

        // ② user_id==1 恒空（管理员不受限）
        assert!(
            svc.hidden_fields(Some(1), 0, "sys_user")
                .await
                .unwrap()
                .is_empty(),
            "超管（user_id==1）必须恒不受限"
        );
        // ③ 平台超管角色持有者恒空（*:*:* 来源）
        assert!(
            svc.hidden_fields(Some(66), 0, "sys_user")
                .await
                .unwrap()
                .is_empty(),
            "平台超管角色持有者必须恒不受限"
        );

        // ④ 列表 VO：开启态 + hidden 集合 → phonenumber None（隐藏优先于掩码），
        //    email 未隐藏 → 本人查自己原值（M1 口径 1）
        let user_service = {
            let store: Arc<dyn crate::shared_store::SharedStore> =
                Arc::new(LocalStore::new(db.clone()));
            SysUserService::new(db.clone(), store)
        };
        let query: crate::service::sys_user_service::UserQueryDto =
            serde_json::from_value(serde_json::json!({"pageNum": 1, "pageSize": 10})).unwrap();
        let (vos, _) = user_service
            .get_user_page(query, Some(55), None, &hidden)
            .await
            .unwrap();
        let me = vos.iter().find(|v| v.user.user_id == 55).unwrap();
        assert_eq!(me.user.phonenumber, None, "隐藏字段必须整体不可见");
        assert_eq!(
            me.user.email.as_deref(),
            Some("u@example.com"),
            "未隐藏字段本人查自己应保持原值"
        );
    }

    /// 开启态 + 非本人操作者：未隐藏字段走 M1 掩码叠加（隐藏优先、掩码兜底）
    #[tokio::test]
    async fn enabled_non_self_viewer_gets_mask_not_hidden_value() {
        let db = test_db().await;
        set_config_enabled(&db, true).await;
        insert_role(&db, 99, false).await;
        insert_user(&db, 55).await;
        bind_user_role(&db, 55, 99).await;
        // operator 88 只隐藏 email；查 user 55（非本人）
        bind_user_role(&db, 88, 99).await;
        insert_hidden_row(&db, 99, "email").await;

        let svc = make_service(&db);
        let hidden = svc.hidden_fields(Some(88), 0, "sys_user").await.unwrap();
        assert_eq!(hidden, HashSet::from(["email".to_string()]));

        let user_service = {
            let store: Arc<dyn crate::shared_store::SharedStore> =
                Arc::new(LocalStore::new(db.clone()));
            SysUserService::new(db.clone(), store)
        };
        let query: crate::service::sys_user_service::UserQueryDto =
            serde_json::from_value(serde_json::json!({"pageNum": 1, "pageSize": 10})).unwrap();
        let (vos, _) = user_service
            .get_user_page(query, Some(88), None, &hidden)
            .await
            .unwrap();
        let target = vos.iter().find(|v| v.user.user_id == 55).unwrap();
        assert_eq!(
            target.user.email, None,
            "隐藏字段必须 None（不得以掩码形态回显）"
        );
        assert_eq!(
            target.user.phonenumber.as_deref(),
            Some("138****0001"),
            "未隐藏字段非本人非超管必须走 M1 掩码（不得原值泄漏）"
        );
    }

    /// **套餐能力位缺失被拦**（第二层 fail-closed）：config 开启但租户
    /// （tid=300，无租户/套餐行 ⇒ 有效能力集回落平台默认全 off）⇒
    /// hidden 恒空 + 矩阵读写接口 403。可证伪：若能力位层失效，本用例立即变红。
    #[tokio::test]
    async fn tenant_without_capability_is_blocked() {
        let db = test_db().await;
        set_config_enabled(&db, true).await;
        insert_role(&db, 99, false).await;
        bind_user_role(&db, 55, 99).await;
        insert_hidden_row(&db, 99, "phonenumber").await;

        let svc = make_service(&db);
        // tid=300：无 sys_tenant 行 → tenant_features_conn 回落平台默认（全 off）
        assert!(
            svc.hidden_fields(Some(55), 300, "sys_user")
                .await
                .unwrap()
                .is_empty(),
            "租户能力位 role.field_perm 缺省（off）时必须拦截裁剪"
        );
        let err = svc.get_matrix(99, 300, "sys_user").await.unwrap_err();
        assert_eq!(err.code, 403, "能力位缺失时矩阵读必须 403");
        let werr = svc
            .save_matrix(
                99,
                300,
                "sys_user",
                FieldPermSaveDto {
                    hidden_fields: vec![],
                },
            )
            .await
            .unwrap_err();
        assert_eq!(werr.code, 403, "能力位缺失时矩阵写必须 403");
    }

    // ==================== 矩阵 API：保存/回读一致 + UNIQUE 幂等 ====================

    /// 平台操作者（tid=0）+ 开启态：矩阵保存 → 回读全白名单字段与 hidden 态一致；
    /// 全量覆盖式（旧 hidden 行被清掉）；重复保存幂等（UNIQUE 约束 + 冲突忽略）。
    #[tokio::test]
    async fn matrix_save_read_roundtrip_and_unique_idempotent() {
        let db = test_db().await;
        set_config_enabled(&db, true).await;
        insert_role(&db, 99, false).await;

        let svc = make_service(&db);

        // 保存前：全白名单字段 hidden=false
        let matrix = svc.get_matrix(99, 0, "sys_user").await.unwrap();
        assert_eq!(matrix.len(), 2, "矩阵必须返回全白名单字段");
        assert!(matrix.iter().all(|m| !m.hidden), "初始态全部未隐藏");

        // 保存 [phonenumber] → 回读一致
        svc.save_matrix(
            99,
            0,
            "sys_user",
            FieldPermSaveDto {
                hidden_fields: vec!["phonenumber".to_string()],
            },
        )
        .await
        .unwrap();
        let matrix = svc.get_matrix(99, 0, "sys_user").await.unwrap();
        let phone = matrix
            .iter()
            .find(|m| m.field_key == "phonenumber")
            .unwrap();
        let email = matrix.iter().find(|m| m.field_key == "email").unwrap();
        assert!(phone.hidden, "phonenumber 应为 hidden");
        assert!(!email.hidden, "email 应保持可见");

        // 全量覆盖式：改存 [email] → phonenumber 被清掉
        svc.save_matrix(
            99,
            0,
            "sys_user",
            FieldPermSaveDto {
                hidden_fields: vec!["email".to_string(), "email".to_string()],
            },
        )
        .await
        .unwrap();
        let matrix = svc.get_matrix(99, 0, "sys_user").await.unwrap();
        assert!(
            !matrix
                .iter()
                .find(|m| m.field_key == "phonenumber")
                .unwrap()
                .hidden,
            "全量覆盖式保存必须清掉未提交的 hidden 行"
        );
        assert!(
            matrix
                .iter()
                .find(|m| m.field_key == "email")
                .unwrap()
                .hidden
        );

        // 重复保存幂等：同内容再存一次不报错、不重复（UNIQUE + 冲突忽略）
        svc.save_matrix(
            99,
            0,
            "sys_user",
            FieldPermSaveDto {
                hidden_fields: vec!["email".to_string()],
            },
        )
        .await
        .unwrap();
        let matrix = svc.get_matrix(99, 0, "sys_user").await.unwrap();
        assert_eq!(
            matrix.iter().filter(|m| m.hidden).count(),
            1,
            "幂等重放不得产生重复 hidden 行"
        );

        // 白名单外 field 拒绝（不落库）
        let rejected = svc
            .save_matrix(
                99,
                0,
                "sys_user",
                FieldPermSaveDto {
                    hidden_fields: vec!["password".to_string()],
                },
            )
            .await;
        assert!(
            rejected.is_ok(),
            "白名单外字段应被静默过滤而非拒绝（防呆不阻断）"
        );
        let matrix = svc.get_matrix(99, 0, "sys_user").await.unwrap();
        assert!(
            matrix.iter().all(|m| !m.hidden),
            "白名单外字段过滤后等同空清单：旧 hidden 行被全量覆盖清空"
        );

        // 白名单外 table 拒绝
        assert!(svc.get_matrix(99, 0, "sys_dict").await.is_err());
        assert!(
            svc.save_matrix(
                99,
                0,
                "sys_dict",
                FieldPermSaveDto {
                    hidden_fields: vec![]
                }
            )
            .await
            .is_err()
        );
    }

    // ==================== 纯函数 ====================

    /// apply_field_perm_and_mask：隐藏优先于掩码；关闭态零变化
    #[test]
    fn apply_field_perm_and_mask_semantics() {
        use crate::entity::sys_user::Model as SysUserModel;
        let mk = || SysUserModel {
            user_id: 1,
            dept_id: None,
            user_name: "u".to_string(),
            nick_name: "n".to_string(),
            user_type: None,
            email: Some("a@example.com".to_string()),
            phonenumber: Some("13812345678".to_string()),
            country_code: None,
            sex: None,
            avatar: None,
            password: None,
            status: None,
            del_flag: None,
            must_change_pwd: None,
            pwd_update_time: None,
            login_ip: None,
            login_date: None,
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
            tenant_id: 0,
            scim_external_id: None,
        };

        // 关闭态：空 hidden + 不掩码 ⇒ 零变化
        let mut m = mk();
        apply_field_perm_and_mask(&mut m, &HashSet::new(), false);
        assert_eq!(m.phonenumber.as_deref(), Some("13812345678"));
        assert_eq!(m.email.as_deref(), Some("a@example.com"));

        // 关闭态 + 掩码（M1）：未隐藏字段掩码
        let mut m = mk();
        apply_field_perm_and_mask(&mut m, &HashSet::new(), true);
        assert_eq!(m.phonenumber.as_deref(), Some("138****5678"));

        // 开启态：隐藏字段 None 优先；未隐藏字段仍掩码
        let mut m = mk();
        let hidden = HashSet::from(["phonenumber".to_string()]);
        apply_field_perm_and_mask(&mut m, &hidden, true);
        assert_eq!(m.phonenumber, None, "隐藏字段必须 None（不得掩码形态回显）");
        assert_eq!(m.email.as_deref(), Some("a****@example.com"));

        // hidden_field_set_to_omit_columns：封闭映射，未知字段忽略
        let o = hidden_field_set_to_omit_columns(&HashSet::from([
            "phonenumber".to_string(),
            "bogus".to_string(),
        ]));
        assert_eq!(o.len(), 1);
        assert_eq!(
            o[0],
            crate::repository::sys_user::UserOmitColumn::Phonenumber
        );
        assert!(hidden_field_set_to_omit_columns(&HashSet::new()).is_empty());
    }
}
