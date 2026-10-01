//! 菜单模块 Service 层
//!
//! 职责：
//! - 菜单 CRUD、树形结构递归组装、权限标识校验
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 多表操作使用 SeaORM 事务保证一致性
//! - 参数校验使用 garde crate（经 common::i18n::validate 统一入口）
//! - 数据访问通过 Repository 层委托

use futures::future::FutureExt;
use garde::Validate;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use utoipa::{IntoParams, ToSchema};

use crate::common::constants::menu_type as menu_kind;
use crate::common::error::ServiceError;
use crate::common::{TreeSelectVo, like_escape};
use crate::entity::sys_menu::{
    ActiveModel as SysMenuActiveModel, Column as MenuColumn, Entity as SysMenu,
    Model as SysMenuModel,
};
use crate::repository::sys_menu::SysMenuRepository;
use crate::repository::sys_role::SysRoleRepository;
use crate::repository::sys_role_menu::SysRoleMenuRepository;
use crate::shared_store::SharedStore;
use crate::utils::parse_id_list;
use crate::utils::tree::build_tree;

/// 权限缓存 key 前缀（格式：perm:user:{user_id}）
const PERM_CACHE_PREFIX: &str = "perm:user:";
/// 权限缓存 TTL（秒，5 分钟，较短以保证权限变更及时生效）
const PERM_CACHE_TTL: i64 = 300;
/// 空值缓存标记（防穿透：用户无角色时缓存此标记，避免反复打 DB）
const PERM_NULL_MARKER: &str = "__NULL__";
const PERM_NULL_TTL: i64 = 60;

// ==================== DTO 定义 ====================

/// 新增菜单 DTO
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MenuAddDto {
    #[garde(skip)]
    pub parent_id: Option<i64>,
    #[garde(length(min = 2, max = 50))]
    pub menu_name: String,
    #[garde(range(min = 0, max = 999))]
    pub order_num: Option<i32>,
    #[garde(length(max = 200))]
    pub path: Option<String>,
    #[garde(length(max = 255))]
    pub component: Option<String>,
    #[garde(length(max = 255))]
    pub query: Option<String>,
    #[garde(length(max = 50))]
    pub route_name: Option<String>,
    #[garde(skip)]
    pub is_frame: Option<String>,
    #[garde(skip)]
    pub is_cache: Option<String>,
    #[garde(length(min = 1, max = 1))]
    pub menu_type: String,
    #[garde(skip)]
    pub visible: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 100))]
    pub perms: Option<String>,
    #[garde(length(max = 100))]
    pub icon: Option<String>,
    /// i18n 翻译 key（可选）：前端按此 key 翻译菜单标题，留空则回退到 menu_name 原文
    #[garde(length(max = 100))]
    pub i18n_key: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 修改菜单 DTO（同 MenuAddDto，增加 menu_id）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MenuEditDto {
    #[garde(skip)]
    pub menu_id: i64,
    #[garde(range(min = 0))]
    pub parent_id: Option<i64>,
    #[garde(length(min = 2, max = 50))]
    pub menu_name: Option<String>,
    #[garde(range(min = 0, max = 999))]
    pub order_num: Option<i32>,
    #[garde(length(max = 200))]
    pub path: Option<String>,
    #[garde(length(max = 255))]
    pub component: Option<String>,
    #[garde(length(max = 255))]
    pub query: Option<String>,
    #[garde(length(max = 50))]
    pub route_name: Option<String>,
    #[garde(skip)]
    pub is_frame: Option<String>,
    #[garde(skip)]
    pub is_cache: Option<String>,
    #[garde(skip)]
    pub menu_type: Option<String>,
    #[garde(skip)]
    pub visible: Option<String>,
    #[garde(skip)]
    pub status: Option<String>,
    #[garde(length(max = 100))]
    pub perms: Option<String>,
    #[garde(length(max = 100))]
    pub icon: Option<String>,
    /// i18n 翻译 key（可选）
    #[garde(length(max = 100))]
    pub i18n_key: Option<String>,
    #[garde(length(max = 500))]
    pub remark: Option<String>,
}

/// 菜单列表查询 DTO
#[derive(Debug, Clone, Deserialize, Default, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct MenuQueryDto {
    pub menu_name: Option<String>,
    pub status: Option<String>,
}

/// 保存菜单排序 DTO（对齐前端 MenuSortParams）
///
/// menu_ids 和 order_nums 均为逗号分隔字符串，按位置一一对应。
/// 例：menuIds="1,2,3" orderNums="10,20,30" 表示 menuId=1→orderNum=10, menuId=2→orderNum=20...
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MenuSortDto {
    #[garde(length(min = 1))]
    pub menu_ids: String,
    #[garde(length(min = 1))]
    pub order_nums: String,
}

// ==================== Service 实现 ====================

/// 权限缓存值（序列化为 JSON 存储）
///
/// 缓存格式：`{"roles": ["admin"], "permissions": ["*:*:*"]}`
/// 同时缓存 role_keys 和 permissions，便于未来扩展（如角色级权限校验）。
#[derive(serde::Serialize, serde::Deserialize)]
struct PermCacheValue {
    roles: Vec<String>,
    permissions: Vec<String>,
}

/// 菜单模块 Service
///
/// 数据访问通过 Repository 层委托：
/// - menu_repo: sys_menu 表 CRUD + 按用户/角色查询菜单
/// - role_menu_repo: sys_role_menu 关联表 CRUD（删除校验 + 级联清理）
/// - role_repo: sys_role 表查询（超管判断）
/// - store: 共享态存储（SharedStore），用于权限缓存（cache-aside 模式）
/// - inflight: singleflight 锁表，防缓存击穿
/// - 事务通过 menu_repo.base().db() 获取连接
#[derive(Clone)]
pub struct SysMenuService {
    menu_repo: SysMenuRepository,
    role_menu_repo: SysRoleMenuRepository,
    role_repo: SysRoleRepository,
    /// 共享态存储（权限缓存）
    store: Arc<dyn SharedStore>,
    /// singleflight 防击穿：同 user_id 的并发查询只允许一个查 DB
    inflight: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl SysMenuService {
    pub fn new(db: DatabaseConnection, store: Arc<dyn SharedStore>) -> Self {
        Self {
            menu_repo: SysMenuRepository::new(db.clone()),
            role_menu_repo: SysRoleMenuRepository::new(db.clone()),
            role_repo: SysRoleRepository::new(db),
            store,
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 获取数据库连接引用（用于事务和复杂查询）
    fn db(&self) -> &DatabaseConnection {
        self.menu_repo.base().db()
    }

    // ==================== 缓存辅助方法 ====================

    /// 失效指定用户的权限缓存（best-effort，失败仅记日志不阻断业务）
    pub async fn invalidate_perm_cache(&self, user_id: i64) {
        let key = format!("{}{}", PERM_CACHE_PREFIX, user_id);
        if let Err(e) = self.store.del(std::slice::from_ref(&key)).await {
            tracing::warn!("失效权限缓存 {} 失败: {}", key, e);
        }
    }

    /// 失效所有用户权限缓存（菜单变更时，best-effort）
    ///
    /// 使用 SCAN 遍历所有 perm:user:* 键并批量删除，避免 KEYS 命令阻塞 Redis。
    pub async fn invalidate_all_perm_cache(&self) {
        let pattern = format!("{}*", PERM_CACHE_PREFIX);
        // 全量扫描（原 cursor 循环至游标归零的语义）；失败即中止（best-effort，与原 Err(_) => break 一致）
        let Ok(keys) = self.store.scan(&pattern, None).await else {
            return;
        };
        if keys.is_empty() {
            return;
        }
        // 批量删除（原 pipeline 语义——非事务允许部分成功；结果忽略，best-effort）
        let _ = self.store.del(&keys).await;
    }

    /// 菜单列表（扁平，可加 menu_name/status 过滤）
    ///
    /// 用途：菜单管理表格展示（前端自行组装树）
    pub async fn get_menu_list(
        &self,
        query: MenuQueryDto,
    ) -> Result<Vec<SysMenuModel>, ServiceError> {
        let mut select = SysMenu::find().filter(MenuColumn::DelFlag.eq("0"));
        if let Some(ref name) = query.menu_name {
            select = select.filter(MenuColumn::MenuName.like(format!("%{}%", like_escape(name))));
        }
        if let Some(ref status) = query.status {
            select = select.filter(MenuColumn::Status.eq(status));
        }
        // 按 order_num 升序、menu_id 升序排序，确保菜单管理页顺序与下拉树一致
        select = select
            .order_by_asc(MenuColumn::OrderNum)
            .order_by_asc(MenuColumn::MenuId);
        // 通过 Repository find_many 执行查询
        let list = self.menu_repo.base().find_many(select).await?;
        Ok(list)
    }

    /// 菜单下拉树（递归组装树形结构）
    pub async fn get_menu_tree(&self) -> Result<Vec<SysMenuModel>, ServiceError> {
        let list = self.menu_repo.find_active_all().await?;
        // 根节点 parent_id=0
        let tree = build_tree(&list, 0);
        Ok(tree)
    }

    /// 菜单下拉树（TreeSelect 格式，对齐前端 treeselect 接口）
    ///
    /// 返回 `{ id, label, disabled, children }` 结构，用于下拉选择场景。
    /// disabled = status != "0"（停用状态禁用选择）。
    pub async fn get_menu_tree_select(&self) -> Result<Vec<TreeSelectVo>, ServiceError> {
        let list = self.menu_repo.find_active_all().await?;
        let tree = build_menu_tree_select(&list, 0);
        Ok(tree)
    }

    /// 批量更新菜单排序（对齐前端 updateSort 接口）
    ///
    /// menu_ids 和 order_nums 按位置一一对应，逐条更新 order_num 字段。
    /// 使用事务保证全部成功或全部回滚。
    pub async fn update_menu_sort(
        &self,
        dto: MenuSortDto,
        operator: &str,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // 解析逗号分隔的 menu_ids 和 order_nums
        let menu_ids: Vec<i64> = parse_id_list::<i64>(&dto.menu_ids);
        let order_nums: Vec<i32> = parse_id_list::<i32>(&dto.order_nums);

        if menu_ids.is_empty() || order_nums.is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.menu.ids_empty"
            )));
        }
        if menu_ids.len() != order_nums.len() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.menu.ids_count_mismatch"
            )));
        }

        let now = crate::common::datetime::now_naive();
        let operator = operator.to_string();
        let menu_repo = self.menu_repo.clone();
        self.db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let menu_ids = menu_ids.clone();
                let order_nums = order_nums.clone();
                let operator = operator.clone();
                async move {
                    for (menu_id, order_num) in menu_ids.iter().zip(order_nums.iter()) {
                        // 直接 UPDATE order_num：未匹配到记录时 affected_rows=0，
                        // 等价于原 find_by_id 后 continue 的 silent skip 行为（前端可能传了已删除的 ID），
                        // 同时避免"先查完整实体再保存全行"的两轮 DB 往返。
                        menu_repo
                            .update_sort_conn(txn, *menu_id, *order_num, &operator, now)
                            .await?;
                    }
                    Ok(())
                }
                .boxed()
            })
            .await?;

        Ok(())
    }

    /// 查询菜单详情
    pub async fn get_menu_by_id(&self, menu_id: i64) -> Result<SysMenuModel, ServiceError> {
        let menu = self
            .menu_repo
            .base()
            .find_by_id(menu_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.menu.not_found")))?;
        if menu.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.menu.not_found")));
        }
        Ok(menu)
    }

    /// 新增菜单
    pub async fn add_menu(
        &self,
        dto: MenuAddDto,
        operator: &str,
    ) -> Result<SysMenuModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // parent_id 校验：若非 0，查询父菜单是否存在
        let parent_id = dto.parent_id.unwrap_or(0);
        if parent_id != 0 {
            let parent = self
                .menu_repo
                .base()
                .find_by_id(parent_id)
                .await?
                .ok_or_else(|| {
                    ServiceError::bad_request(&crate::tr!("error.menu.parent_not_found"))
                })?;
            if parent.del_flag.as_deref() == Some("2") {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.menu.parent_deleted"
                )));
            }
        }

        // perms 查重（仅 menu_type='C' 或 'F' 时，通过 Repository）
        let menu_type = dto.menu_type.as_str();
        if (menu_type == menu_kind::MENU || menu_type == menu_kind::BUTTON)
            && let Some(ref perms) = dto.perms
            && !perms.is_empty()
        {
            let select = SysMenu::find()
                .filter(MenuColumn::Perms.eq(perms))
                .filter(MenuColumn::DelFlag.eq("0"));
            let dup = self.menu_repo.base().find_one(select).await?;
            if dup.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.menu.perm_exists"
                )));
            }
        }

        // 按 menu_type 分支处理字段
        let (perms_val, component_val, path_val) = apply_menu_type_rules(
            menu_type,
            dto.perms.clone(),
            dto.component.clone(),
            dto.path.clone(),
        );

        let now = crate::common::datetime::now_naive();
        let mut am = SysMenuActiveModel {
            ..Default::default()
        };
        am.menu_name = Set(dto.menu_name.clone());
        am.parent_id = Set(Some(parent_id));
        am.order_num = Set(dto.order_num);
        am.path = Set(path_val);
        am.component = Set(component_val);
        am.query = Set(dto.query.clone());
        am.route_name = Set(dto.route_name.clone());
        am.is_frame = Set(dto.is_frame.clone());
        am.is_cache = Set(dto.is_cache.clone());
        am.menu_type = Set(Some(menu_type.to_string()));
        am.visible = Set(dto.visible.clone());
        am.status = Set(dto.status.clone().or_else(|| Some("0".to_string())));
        am.perms = Set(perms_val);
        am.icon = Set(dto.icon.clone());
        am.i18n_key = Set(dto.i18n_key.clone());
        am.create_by = Set(Some(operator.to_string()));
        am.create_time = Set(Some(now));
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));
        am.remark = Set(dto.remark.clone());
        am.del_flag = Set(Some("0".to_string()));

        let new_menu = self.menu_repo.insert(am).await?;
        // 菜单变更影响所有用户权限，全量失效权限缓存
        self.invalidate_all_perm_cache().await;
        Ok(new_menu)
    }

    /// 修改菜单（含防环校验）
    pub async fn edit_menu(
        &self,
        dto: MenuEditDto,
        operator: &str,
    ) -> Result<SysMenuModel, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // 查询菜单是否存在
        let existing = self
            .menu_repo
            .base()
            .find_by_id(dto.menu_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.menu.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.menu.not_found")));
        }

        // parent_id 校验
        let parent_id = dto.parent_id.unwrap_or(existing.parent_id.unwrap_or(0));
        if parent_id == dto.menu_id {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.menu.parent_self_forbidden"
            )));
        }
        if parent_id != 0 {
            // 校验新父菜单存在
            let parent = self
                .menu_repo
                .base()
                .find_by_id(parent_id)
                .await?
                .ok_or_else(|| {
                    ServiceError::bad_request(&crate::tr!("error.menu.parent_not_found"))
                })?;
            if parent.del_flag.as_deref() == Some("2") {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.menu.parent_deleted"
                )));
            }

            // 防环校验：新 parent_id 不能是当前菜单的后代节点
            if self.is_descendant(dto.menu_id, parent_id).await? {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.menu.parent_self_forbidden"
                )));
            }
        }

        // perms 查重：若 perms 变更，校验新 perms 是否已被其他菜单占用（通过 Repository）
        let new_perms = dto.perms.clone().or(existing.perms.clone());
        if let Some(ref perms) = new_perms
            && !perms.is_empty()
        {
            let select = SysMenu::find()
                .filter(MenuColumn::Perms.eq(perms))
                .filter(MenuColumn::DelFlag.eq("0"))
                .filter(MenuColumn::MenuId.ne(dto.menu_id));
            let dup = self.menu_repo.base().find_one(select).await?;
            if dup.is_some() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.menu.perm_exists"
                )));
            }
        }

        // 按 menu_type 分支处理
        let menu_type = dto
            .menu_type
            .clone()
            .or_else(|| existing.menu_type.clone())
            .unwrap_or_default();
        let (perms_val, component_val, path_val) = apply_menu_type_rules(
            &menu_type,
            new_perms,
            dto.component.clone().or(existing.component.clone()),
            dto.path.clone().or(existing.path.clone()),
        );

        let now = crate::common::datetime::now_naive();
        let mut am: SysMenuActiveModel = existing.into();
        am.parent_id = Set(Some(parent_id));
        if let Some(ref name) = dto.menu_name {
            am.menu_name = Set(name.clone());
        }
        if let Some(order) = dto.order_num {
            am.order_num = Set(Some(order));
        }
        am.path = Set(path_val);
        am.component = Set(component_val);
        if let Some(ref q) = dto.query {
            am.query = Set(Some(q.clone()));
        }
        if let Some(ref rn) = dto.route_name {
            am.route_name = Set(Some(rn.clone()));
        }
        if let Some(ref frame) = dto.is_frame {
            am.is_frame = Set(Some(frame.clone()));
        }
        if let Some(ref cache) = dto.is_cache {
            am.is_cache = Set(Some(cache.clone()));
        }
        am.menu_type = Set(Some(menu_type));
        if let Some(ref vis) = dto.visible {
            am.visible = Set(Some(vis.clone()));
        }
        if let Some(ref status) = dto.status {
            am.status = Set(Some(status.clone()));
        }
        am.perms = Set(perms_val);
        if let Some(ref icon) = dto.icon {
            am.icon = Set(Some(icon.clone()));
        }
        if let Some(ref i18n_key) = dto.i18n_key {
            am.i18n_key = Set(Some(i18n_key.clone()));
        }
        if let Some(ref remark) = dto.remark {
            am.remark = Set(Some(remark.clone()));
        }
        am.update_by = Set(Some(operator.to_string()));
        am.update_time = Set(Some(now));

        let updated = self.menu_repo.update(am).await?;
        // 菜单变更影响所有用户权限，全量失效权限缓存
        self.invalidate_all_perm_cache().await;
        Ok(updated)
    }

    /// 删除菜单（事务：子菜单校验 + 菜单分配校验 + 软删除 + 清理 sys_role_menu）
    pub async fn delete_menu(&self, menu_id: i64) -> Result<(), ServiceError> {
        let existing = self
            .menu_repo
            .base()
            .find_by_id(menu_id)
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.menu.not_found")))?;
        if existing.del_flag.as_deref() == Some("2") {
            return Err(ServiceError::not_found(&crate::tr!("error.menu.not_found")));
        }

        let menu_repo = self.menu_repo.clone();
        let role_menu_repo = self.role_menu_repo.clone();
        // R12 TOCTOU 修复：将子菜单和角色分配校验移入事务内（与 delete_role/delete_dept 一致）
        let txn_result = self
            .db()
            .transaction::<_, (), sea_orm::DbErr>(|txn| {
                let menu_repo = menu_repo.clone();
                let role_menu_repo = role_menu_repo.clone();
                async move {
                    // 1. 事务内重新检查子菜单
                    let child_select = SysMenu::find()
                        .filter(MenuColumn::ParentId.eq(menu_id))
                        .filter(MenuColumn::DelFlag.eq("0"));
                    let child_count = menu_repo
                        .base()
                        .find_many_conn(txn, child_select)
                        .await?
                        .len() as u64;
                    if child_count > 0 {
                        return Err(sea_orm::DbErr::Custom(crate::tr!(
                            "error.menu.has_children"
                        )));
                    }

                    // 2. 事务内重新检查角色分配
                    let role_count = role_menu_repo.count_by_menu_id_conn(txn, menu_id).await?;
                    if role_count > 0 {
                        return Err(sea_orm::DbErr::Custom(crate::tr!(
                            "error.menu.assigned_to_role"
                        )));
                    }

                    // 3. 软删除 sys_menu（通过 Repository 事务上下文）
                    let mut am: SysMenuActiveModel = existing.into();
                    am.del_flag = Set(Some("2".to_string()));
                    menu_repo.base().update_conn(txn, am).await?;

                    // 4. 物理删除 sys_role_menu 关联（冗余保护，正常应已被校验拦截）
                    role_menu_repo.delete_by_menu_id_conn(txn, menu_id).await?;
                    Ok(())
                }
                .boxed()
            })
            .await;

        match txn_result {
            Ok(()) => {}
            // TOCTOU 检查的业务错误：映射为 400 bad_request
            Err(sea_orm::TransactionError::Transaction(sea_orm::DbErr::Custom(msg))) => {
                return Err(ServiceError::bad_request(&msg));
            }
            Err(e) => return Err(ServiceError::from(e)),
        }
        // 菜单变更影响所有用户权限，全量失效权限缓存
        self.invalidate_all_perm_cache().await;

        Ok(())
    }

    /// 查询用户菜单树（超管短路 + 过滤按钮类型/隐藏/停用）
    ///
    /// 过滤规则（selectMenuTreeByUserId）：
    /// - menu_type != 'F'：按钮类型不进路由树
    /// - visible == '0'：隐藏菜单（visible='1'）不进入 getRouters 返回
    ///   * hidden 路由（如 profile / user-auth/role / dict-data / job-log / gen-edit）
    ///     已在前端 constantRoutes/dynamicRoutes 中静态定义，无需后端返回
    /// - status == '0'：停用菜单不返回
    ///
    /// 背景：menu_id=111（druid）通过 m20260720 迁移设为 visible='1' 隐藏，
    /// 但前端 views/monitor/druid/index.vue 已删除，若不过滤会导致 loadView 返回 undefined，
    /// router.addRoute 抛错，Vue Router 启动失败（VUE_ROUTER_R0011）。
    pub async fn get_menu_tree_by_user_id(
        &self,
        user_id: i64,
    ) -> Result<Vec<SysMenuModel>, ServiceError> {
        // 先查用户角色（通过 Repository）
        let roles = self.role_repo.find_by_user_id(user_id).await?;

        let mut menus: Vec<SysMenuModel> = if roles.is_empty() {
            vec![]
        } else {
            // 超管判定（台账 P0-2）：以系统标记 + 平台租户归属判定，不依赖可变 role_key
            let is_admin = roles.iter().any(|r| r.is_platform_super_admin());

            if is_admin {
                // 超管短路：返回所有未删除菜单
                self.menu_repo.find_active_all().await?
            } else {
                // 非超管：通过 Repository 查询用户菜单
                self.menu_repo.find_by_user_id(user_id).await?
            }
        };

        // 过滤按钮类型（F 不进路由树）+ 隐藏菜单（visible='1'）+ 停用菜单（status='1'）
        menus.retain(|m| {
            m.menu_type.as_deref() != Some(menu_kind::BUTTON)
                && m.visible.as_deref() == Some("0")
                && m.status.as_deref() == Some("0")
        });

        // 组装树
        let tree = build_tree(&menus, 0);
        Ok(tree)
    }

    /// 查询用户权限标识列表（超管返回 ["*:*:*"]）
    ///
    /// 采用 cache-aside 模式：先查 Redis（key=perm:user:{user_id}），命中则直接返回；
    /// 未命中则查 DB，结果序列化后写入 Redis（TTL 5 分钟）。
    /// 缓存读写失败不阻断业务（best-effort），降级为直接查 DB。
    ///
    /// 防护策略（与字典缓存一致）：
    /// - 穿透防护：用户无角色时缓存空值标记（TTL 60s），避免反复打 DB
    /// - 击穿防护：热点 key 失效瞬间通过 singleflight 串行化 DB 查询
    pub async fn get_permissions_by_user_id(
        &self,
        user_id: i64,
    ) -> Result<Vec<String>, ServiceError> {
        let (_, permissions) = self.get_roles_and_permissions_by_user_id(user_id).await?;
        Ok(permissions)
    }

    /// 合并查询用户角色 + 权限标识（缓存命中时 0 次 DB）
    ///
    /// 返回 (role_keys, permissions)：
    /// - role_keys: 用户角色 key 列表（如 ["admin", "common"]）
    /// - permissions: 权限标识列表（超管返回 ["*:*:*"]）
    ///
    /// 合并到单个缓存值避免 getInfo 中分别查询 role_keys 和 permissions 导致的冗余 DB 往返
    /// （原 getInfo 8 次 DB → 缓存命中时 3 次 DB + 1 次 Redis GET）
    pub async fn get_roles_and_permissions_by_user_id(
        &self,
        user_id: i64,
    ) -> Result<(Vec<String>, Vec<String>), ServiceError> {
        let key = format!("{}{}", PERM_CACHE_PREFIX, user_id);

        // 1. 尝试读取缓存
        let cached: Option<String> = self.store.get(&key).await.ok().flatten();

        if let Some(json_str) = cached {
            // 空值标记：用户无角色，返回空列表（防穿透）
            if json_str == PERM_NULL_MARKER {
                return Ok((vec![], vec![]));
            }
            match serde_json::from_str::<PermCacheValue>(&json_str) {
                Ok(val) => return Ok((val.roles, val.permissions)),
                Err(e) => {
                    // 缓存数据损坏，记日志并回退到 DB
                    tracing::warn!("权限缓存 {} 反序列化失败，回退查 DB: {}", key, e);
                }
            }
        }

        // 2. 缓存未命中或损坏，通过 singleflight 串行化 DB 查询（防击穿）
        let inflight_key = user_id.to_string();
        let inflight_lock = {
            let mut map = self.inflight.lock().await;
            map.entry(inflight_key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };

        // 持有 inflight 锁期间查 DB + 写缓存
        let result: Result<(Vec<String>, Vec<String>), ServiceError> = async {
            let _guard = inflight_lock.lock().await;

            // double-check：持有锁后再次查缓存，可能已被前一个持锁请求填充
            let cached: Option<String> = self.store.get(&key).await.ok().flatten();
            if let Some(json_str) = cached {
                if json_str == PERM_NULL_MARKER {
                    return Ok((vec![], vec![]));
                }
                if let Ok(val) = serde_json::from_str::<PermCacheValue>(&json_str) {
                    return Ok((val.roles, val.permissions));
                }
            }

            // 3. 查询 DB：先查用户角色（通过 Repository）
            let roles = self.role_repo.find_by_user_id(user_id).await?;

            if roles.is_empty() {
                // 写入空值标记（防穿透）
                if let Err(e) = self
                    .store
                    .set_ex(&key, PERM_NULL_MARKER, PERM_NULL_TTL as u64)
                    .await
                {
                    tracing::warn!("写入权限空值缓存 {} 失败: {}", key, e);
                }
                return Ok((vec![], vec![]));
            }

            let role_keys: Vec<String> = roles.iter().map(|r| r.role_key.clone()).collect();
            // 超管判定（台账 P0-2）：以系统标记 + 平台租户归属判定，不依赖可变 role_key
            let is_admin = roles.iter().any(|r| r.is_platform_super_admin());

            let permissions = if is_admin {
                // 超管返回通配权限
                vec!["*:*:*".to_string()]
            } else {
                // 非超管：通过 Repository 查询用户菜单，提取 perms
                let menus = self.menu_repo.find_by_user_id(user_id).await?;
                let mut perms: Vec<String> = menus
                    .into_iter()
                    .filter_map(|m| m.perms)
                    .filter(|p| !p.is_empty())
                    .collect();
                // 去重
                perms.sort();
                perms.dedup();
                perms
            };

            // 4. 写入缓存（best-effort，失败仅记日志）
            let cache_value = PermCacheValue {
                roles: role_keys.clone(),
                permissions: permissions.clone(),
            };
            let json = serde_json::to_string(&cache_value).unwrap_or_else(|e| {
                tracing::warn!("序列化权限缓存失败，跳过缓存写入: {}", e);
                PERM_NULL_MARKER.to_string()
            });
            if let Err(e) = self
                .store
                .set_ex(&key, &json, PERM_CACHE_TTL as u64)
                .await
            {
                tracing::warn!("写入权限缓存 {} 失败: {}", key, e);
            }

            Ok((role_keys, permissions))
        }
        .await;

        // 清理 inflight 条目，防止 HashMap 无限增长（与字典缓存一致）
        drop(inflight_lock);
        {
            let mut map = self.inflight.lock().await;
            if let Some(arc) = map.get(&inflight_key)
                && Arc::strong_count(arc) == 1
            {
                map.remove(&inflight_key);
            }
        }

        result
    }

    // ==================== 内部辅助方法 ====================

    /// 防环校验：判断 candidate_parent_id 是否是 menu_id 的后代节点
    ///
    /// N+1 优化：菜单表数据量小（通常 < 500 条），一次性加载全部菜单到内存，
    /// 构建 parent_id → menu_id 映射后在内存中遍历祖先链，
    /// 复杂度从 O(N) 次 DB 查询降为 O(1) DB + O(depth) 内存遍历。
    async fn is_descendant(
        &self,
        menu_id: i64,
        candidate_parent_id: i64,
    ) -> Result<bool, ServiceError> {
        if candidate_parent_id == 0 {
            return Ok(false);
        }
        if candidate_parent_id == menu_id {
            return Ok(true);
        }
        // 一次性加载全部菜单（数据量小），构建 id → parent_id 映射
        let all_menus = self.menu_repo.find_active_all().await?;
        let parent_map: std::collections::HashMap<i64, i64> = all_menus
            .iter()
            .map(|m| {
                let id = m.menu_id;
                let parent = m.parent_id.unwrap_or(0);
                (id, parent)
            })
            .collect();

        // 在内存中遍历祖先链
        let mut current = candidate_parent_id;
        for _ in 0..100 {
            if current == 0 {
                return Ok(false);
            }
            if current == menu_id {
                return Ok(true);
            }
            match parent_map.get(&current) {
                Some(&next) => {
                    if next == current {
                        // 异常数据自环，退出避免死循环
                        return Ok(false);
                    }
                    current = next;
                }
                None => {
                    // current 不在菜单表中（数据不一致），退出
                    return Ok(false);
                }
            }
        }
        // 超过 100 层仍未回到根，视为异常
        Err(ServiceError::bad_request(&crate::tr!(
            "error.menu.level_too_deep"
        )))
    }
}

/// 按 menu_type 分支处理 perms / component / path 字段
///
/// - M（目录）：perms 置空，component 置空
/// - C（菜单）：保留 path/component/perms
/// - F（按钮）：path 置空，component 置空，保留 perms
fn apply_menu_type_rules(
    menu_type: &str,
    perms: Option<String>,
    component: Option<String>,
    path: Option<String>,
) -> (Option<String>, Option<String>, Option<String>) {
    match menu_type {
        "M" => (None, None, path),
        "F" => (perms, None, None),
        _ => (perms, component, path),
    }
}

/// 将扁平菜单列表组装为 TreeSelect 树结构
///
/// - 根节点 parent_id = 0 或 null
/// - disabled = status != "0"（停用状态禁用选择）
fn build_menu_tree_select(list: &[SysMenuModel], root_parent_id: i64) -> Vec<TreeSelectVo> {
    let mut roots: Vec<TreeSelectVo> = list
        .iter()
        .filter(|m| m.parent_id.unwrap_or(0) == root_parent_id)
        .map(menu_model_to_tree_select)
        .collect();
    for root in &mut roots {
        build_menu_tree_children(root, list, 0);
    }
    roots
}

/// 菜单树最大深度（P1：防脏数据 parent_id 成环导致无限递归栈溢出）
const MAX_MENU_TREE_DEPTH: usize = 30;

fn build_menu_tree_children(node: &mut TreeSelectVo, list: &[SysMenuModel], depth: usize) {
    if depth >= MAX_MENU_TREE_DEPTH {
        tracing::warn!(
            "菜单树构建达到最大深度 {}（可能存在 parent_id 循环引用），停止递归",
            MAX_MENU_TREE_DEPTH
        );
        return;
    }
    let node_id = node.id;
    let children: Vec<TreeSelectVo> = list
        .iter()
        .filter(|m| m.parent_id.unwrap_or(0) == node_id)
        .map(menu_model_to_tree_select)
        .collect();
    if children.is_empty() {
        return;
    }
    node.children = children;
    for kid in &mut node.children {
        build_menu_tree_children(kid, list, depth + 1);
    }
}

/// 将 SysMenuModel 转换为 TreeSelectVo 节点
fn menu_model_to_tree_select(m: &SysMenuModel) -> TreeSelectVo {
    TreeSelectVo {
        id: m.menu_id,
        label: m.menu_name.clone(),
        disabled: m.status.as_deref() != Some("0"),
        children: vec![],
    }
}
