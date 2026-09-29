# Service 层业务方案设计文档（service-spec.md）

> **阶段：** 第三阶段「用户/角色/菜单 Service 层业务实现」
> **项目：** axum-backend（纯 Axum 0.8 + SeaORM 1.1 生产级后端服务）
> **规则基线：** `backend-axum/.trae/rules/project-rules.md`（全程永久生效）
> **开发优先原则：** 接口契约对齐 frontend-vue 前端调用规范 ＞ 架构规范遵循 Axum 官方最佳实践 ＞ 同栈细节遵循 Axum + SeaORM 原生惯例

---

## 1. 概述与目标

### 1.1 本阶段目标

基于第二阶段已完成的数据库表结构、Entity 实体层、Repository 数据访问层，设计并实现用户、角色、菜单三大核心模块的 Service 业务逻辑层，完成以下交付：

1. **Service 层完全独立**：不依赖 axum / tower / tower-http 任何 Web 框架类型
2. **事务控制**：核心多表操作使用 SeaORM `TransactionTrait` 真事务（修正旧实现事务形同虚设的缺陷）
3. **参数校验**：使用 `garde` crate 对 DTO 进行结构化校验
4. **业务规则**：补齐查重、级联清理、超管保护等业务规则
5. **密码安全**：复用已有 `utils::password` 模块（Argon2id 为主算法，"stepby_admin" 仅作 LEGACY_SALT 用于旧 MD5 验证 fallback，不兼容旧数据）
6. **树形组装**：复用已有 `utils::tree::build_tree` 工具函数，规避 O(n²) 递归 clone 问题

### 1.2 模块清单

| 模块 | Service 文件 | 核心职责 |
|------|-------------|---------|
| 用户 | `src/service/sys_user_service.rs` | 用户 CRUD、密码加密校验、用户角色分配、状态启停 |
| 角色 | `src/service/sys_role_service.rs` | 角色 CRUD、角色菜单绑定、数据权限配置、级联删除校验 |
| 菜单 | `src/service/sys_menu_service.rs` | 菜单 CRUD、树形结构递归组装、权限标识校验 |

### 1.3 非目标（本阶段不实现）

- Handler 层 HTTP 路由与请求解析（留待第四阶段）
- 部门/岗位模块（留待后续阶段）
- 数据权限 SQL 过滤的运行时落地（data_scope 字段仅存储配置，过滤逻辑留待后续）
- JWT 鉴权中间件对接（留待第四阶段）
- 操作日志自动记录（留待后续阶段）

---

## 2. 设计原则与决策

### 2.1 分层依赖方向

```
Handler（HTTP 层，本阶段不实现）
   ↓ 调用
Service（业务逻辑层，本阶段实现）
   ↓ 调用
Repository（数据访问层，已完成）
   ↓ 调用
Entity（实体层，已完成）
```

### 2.2 事务控制策略

**采用 SeaORM 原生 `TransactionTrait`**，修正旧实现的三大事务缺陷：

| 旧实现缺陷 | 本项目修正方案 |
|---------------------|--------------|
| 事务内操作用 `GLOBAL_DB.clone()` 而非 `tx` | 所有事务内操作绑定到 `txn` 连接 |
| `commit()` 后紧接着 `rollback()` | 使用 `db.transaction(|txn| async { ... }.into_future()).await` 自动提交/回滚 |
| `unwrap()` 掩盖错误 | 全程 `?` 传播错误，由 `AppError` 统一转换 |

**事务使用模式：**

```rust
use sea_orm::{DatabaseConnection, TransactionTrait};
use futures::future::FutureExt;

pub async fn add_user(&self, dto: UserAddDto, operator: &str) -> Result<SysUserModel, AppError> {
    let result = self.db.transaction::<_, SysUserModel, DbErr>(|txn| {
        async move {
            // 1. 用户名查重（使用 txn 连接）
            // 2. 插入 sys_user（使用 txn 连接）
            // 3. 批量插入 sys_user_role（使用 txn 连接）
            Ok(new_user)
        }.boxed()  // SeaORM 1.1 需要 BoxFuture
    }).await?;
    Ok(result)
}
```

> **说明：**
> - SeaORM 1.1 的 `transaction` 闭包需要返回 `BoxFuture<...>`，使用 `.boxed()` 包装
> - 需在 Cargo.toml 添加 `futures = "0.3"` 依赖（提供 `FutureExt::boxed`）
> - 事务闭包内所有 DB 操作必须使用 `txn` 连接，不能使用 `self.db`
> - 闭包内返回 `Err` 时 SeaORM 自动回滚事务

### 2.3 参数校验策略

**采用 `garde` crate（已在 Cargo.toml 声明）**，在 DTO 结构体上使用 `#[garde]` 注解：

```rust
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UserAddDto {
    #[garde(length(min = 2, max = 30, message = "用户名长度必须在2-30之间"))]
    pub user_name: String,
    #[garde(length(min = 2, max = 30, message = "昵称长度必须在2-30之间"))]
    pub nick_name: String,
    #[garde(email(message = "邮箱格式不正确")))]
    pub email: Option<String>,
    #[garde(regex(path = "PHONE_REGEX", message = "手机号格式不正确"))]
    pub phonenumber: Option<String>,
    // ...
}
```

Service 方法入口处统一调用 `dto.validate()?` 进行校验，校验失败返回 `AppError::bad_request`。

### 2.4 密码安全策略

复用已有 `utils::password` 模块：

| 场景 | 加密方式 | 校验方式 |
|------|---------|---------|
| 新增用户 | `encrypt_password(明文)` 后入库 | — |
| 管理员重置密码 | `encrypt_password(新明文)` 后入库 | — |
| 个人中心改密 | `encrypt_password(新明文)` 后入库 | `verify_password(旧明文, 旧密文)` 比对 |
| 登录校验 | — | `verify_password(输入明文, 库中密文)` 比对 |

> **盐值说明：** 本项目密码算法为 Argon2id（每用户独立随机盐），"stepby_admin" 仅作 LEGACY_SALT 用于旧 MD5 哈希的验证 fallback（升级前已存在的用户密码）。初始数据密码均为 `admin123`。数据库密码与旧数据**不兼容**，新部署需使用 Argon2id 生成的密码。

### 2.5 软删除策略

| 表 | 删除方式 | 说明 |
|----|---------|------|
| sys_user | 软删除 `del_flag='2'` | 保留用户数据可追溯 |
| sys_role | 软删除 `del_flag='2'` | 保留角色数据可追溯 |
| sys_menu | 软删除 `del_flag='2'` | 保留菜单数据可追溯 |
| sys_user_role | 物理删除 | 关联表无需保留 |
| sys_role_menu | 物理删除 | 关联表无需保留 |

### 2.6 超管保护策略

**硬编码保护规则**（对齐本项目前端约定）：

| 保护对象 | 判定条件 | 保护规则 |
|---------|---------|---------|
| 超管用户 | `user_id == 1` 或 `role_key == "admin"` | 禁止删除、禁止停用 |
| 超管角色 | `role_id == 1` 或 `role_key == "admin"` | 禁止删除、禁止修改 role_key |
| 超管菜单 | `menu_id == 1`（系统管理目录） | 不做特殊保护，但删除时需级联校验 |

### 2.7 树形组装策略

复用 `utils::tree::build_tree<T: TreeNode>`，为菜单实现 `TreeNode` trait：

```rust
impl TreeNode for SysMenuModel {
    fn id(&self) -> i64 { self.menu_id }
    fn parent_id(&self) -> i64 { self.parent_id.unwrap_or(0) }
    fn children_mut(&mut self) -> &mut Option<Vec<Self>> { &mut self.children }
}
```

> **注意：** 需在 `SysMenuModel` 上新增 `children: Option<Vec<SysMenuModel>>` 字段（`#[sea_orm(ignore)]` 标注，不入库）。此修改在实现阶段执行。

### 2.8 Service 结构体设计

每个 Service 结构体持有 `DatabaseConnection`，在构造时实例化所需的各 Repository：

```rust
pub struct SysUserService {
    db: DatabaseConnection,
    user_repo: SysUserRepository,
    role_repo: SysRoleRepository,
    user_role_repo: SysUserRoleRepository,
}

impl SysUserService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            user_repo: SysUserRepository::new(db.clone()),
            role_repo: SysRoleRepository::new(db.clone()),
            user_role_repo: SysUserRoleRepository::new(db.clone()),
            db,
        }
    }
}
```

> **设计决策：**
> - 持有 `db` 用于事务控制（`db.transaction()`）
> - 持有各 Repository 用于非事务场景的查询
> - 事务场景下，Repository 方法需支持传入 `txn` 连接（通过 `db()` 获取连接后无法切换为 txn，需在事务闭包内直接调用 Entity API）
> - **事务内查询方案：** 事务闭包内不使用 Repository，直接调用 `Entity::find().filter(...).one(&txn).await` 等 SeaORM 原生 API

### 2.9 operator 参数来源

Service 方法中的 `operator: &str` 参数表示操作人用户名，来源链路：

```
HTTP 请求 → JWT 中间件解析 token → 提取 claims.user_name → 注入 Handler
Handler 调用 Service 时传入 operator 参数
```

本阶段 Service 层仅接收 `operator: &str`，不关心来源。Handler 层（第四阶段）负责从 JWT claims 中提取并传入。

### 2.10 新增依赖

本阶段需在 `Cargo.toml` 添加以下依赖：

```toml
# 异步 Future 工具（事务闭包 boxed()）
futures = "0.3"

# 正则表达式（garde regex 校验手机号）
regex = "1"

# once_cell（定义全局正则常量）
once_cell = "1"
```

> **说明：** `garde` 的 `regex` 校验需要 `regex` crate，且需用 `once_cell` 定义编译期正则常量。

---

## 3. 用户模块业务设计

### 3.1 DTO 定义

#### 3.1.1 UserAddDto（新增用户）

| 字段 | 类型 | 校验规则 | 说明 |
|------|------|---------|------|
| dept_id | Option\<i64\> | — | 部门 ID（本阶段可选，部门模块未实现） |
| user_name | String | length(2,30) | 用户账号 |
| nick_name | String | length(2,30) | 用户昵称 |
| email | Option\<String\> | email 格式 | 邮箱 |
| phonenumber | Option\<String\> | 手机号正则 | 手机号 |
| sex | Option\<String\> | 枚举 "0"/"1"/"2" | 性别 |
| password | String | length(5,20) | 明文密码（Service 内加密） |
| status | Option\<String\> | 枚举 "0"/"1" | 状态 |
| role_ids | Option\<Vec\<i64\>\> | — | 角色 ID 列表 |
| remark | Option\<String\> | length(0,500) | 备注 |

#### 3.1.2 UserEditDto（修改用户）

| 字段 | 类型 | 校验规则 | 说明 |
|------|------|---------|------|
| user_id | i64 | required | 用户 ID |
| dept_id | Option\<i64\> | — | 部门 ID |
| nick_name | Option\<String\> | length(2,30) | 昵称 |
| email | Option\<String\> | email | 邮箱 |
| phonenumber | Option\<String\> | 手机号 | 手机号 |
| sex | Option\<String\> | 枚举 | 性别 |
| status | Option\<String\> | 枚举 | 状态 |
| role_ids | Option\<Vec\<i64\>\> | — | 角色 ID 列表（None 不修改，Some(vec![]) 清空） |
| remark | Option\<String\> | length(0,500) | 备注 |

> **注意：** 修改用户不允许通过此接口改密码、user_name。

#### 3.1.3 UserPwdResetDto（管理员重置密码）

| 字段 | 类型 | 校验规则 | 说明 |
|------|------|---------|------|
| user_id | i64 | required | 用户 ID |
| password | String | length(5,20) | 新明文密码 |

#### 3.1.4 UserPwdUpdateDto（个人中心改密）

| 字段 | 类型 | 校验规则 | 说明 |
|------|------|---------|------|
| old_password | String | length(5,20) | 旧明文密码 |
| new_password | String | length(5,20) | 新明文密码 |

#### 3.1.5 UserQueryDto（分页查询）

| 字段 | 类型 | 说明 |
|------|------|------|
| page_num | u64 | 页码（默认 1） |
| page_size | u64 | 每页条数（默认 10） |
| user_name | Option\<String\> | 用户名模糊 |
| phonenumber | Option\<String\> | 手机号模糊 |
| status | Option\<String\> | 状态精确 |

### 3.2 业务方法清单

#### 3.2.1 get_user_page（分页查询用户）

**流程：**
1. 解析 `PageDomain` 计算 offset/limit
2. 调用 Repository `find_active_page` 查询未删除用户
3. 对每条用户记录，查询其角色列表（`SysRoleRepository::find_by_user_id`）
4. 返回 `TableDataInfo<UserVo>`

**业务规则：**
- 仅查询 `del_flag='0'` 的用户
- 分页参数默认值：page_num=1, page_size=10

**性能优化：** 本阶段接受 N+1 查询（用户量通常 <1000），后续可优化为批量查询角色关联。

#### 3.2.2 get_user_by_id（查询用户详情）

**流程：**
1. 按 `user_id` 查询用户主体
2. 查询用户角色列表 → 提取 `role_ids`
3. 返回 `UserVo`（含 role_ids）

**业务规则：**
- 用户不存在返回 `AppError::not_found`
- 仅查询未删除用户

#### 3.2.3 add_user（新增用户）

**流程（事务）：**
1. `dto.validate()` 参数校验
2. **用户名查重**：`SysUserRepository::find_by_user_name`，若存在返回 `AppError::bad_request("用户名不能重复")`
3. 密码加密：`encrypt_password(&dto.password)`
4. 构造 `SysUserActiveModel`，设置 del_flag='0'
5. **开启事务**：
   - 插入 sys_user → 获取 new_user_id
   - 若 `role_ids` 非空：批量插入 sys_user_role
6. 返回新用户 Model

**业务规则：**
- 用户名唯一（含已软删除的，避免恢复后冲突）
- 密码在 Service 层加密，DTO 接收明文
- 默认 status='0'（正常），del_flag='0'

#### 3.2.4 edit_user（修改用户）

**流程（事务）：**
1. `dto.validate()` 参数校验
2. 查询用户是否存在（不存在返回 not_found）
3. **超管保护**：若 user_id==1 且 status=='1'，拒绝停用
4. 构造 `SysUserActiveModel`，**不修改** user_name/password/avatar/del_flag
5. **开启事务**：
   - 更新 sys_user
   - 若 `role_ids` 为 `Some`（非 None）：
     - 先删除该用户所有 sys_user_role 关联
     - 若 `role_ids` 非空数组，再批量插入新关联
6. 返回更新后用户 Model

**业务规则：**
- 不允许通过此接口修改密码（用 reset_user_pwd）
- 不允许修改 user_name（业务唯一标识）
- `role_ids=None` 表示不修改角色绑定，`role_ids=Some(vec![])` 表示清空角色绑定

#### 3.2.5 delete_user（删除用户）

**流程（事务）：**
1. **超管保护**：若 user_id==1，返回 `AppError::bad_request("不允许删除超级管理员")`
2. 查询用户是否存在
3. **开启事务**：
   - 软删除 sys_user（`del_flag='2'`）
   - 物理删除 sys_user_role 关联（`delete_by_user_id`）
4. 返回 `()`

**业务规则：**
- 软删除用户，保留数据
- 级联清理 sys_user_role（修正旧实现未清理的缺陷）

#### 3.2.6 reset_user_pwd（管理员重置密码）

**流程：**
1. 查询用户是否存在
2. 密码加密：`encrypt_password(&dto.password)`
3. 构造 `SysUserActiveModel`，仅设置 password 字段
4. 调用 Repository `update`
5. 返回 `()`

**业务规则：**
- 无需校验旧密码
- 无超管保护（管理员可重置任何用户密码）

#### 3.2.7 update_user_password（个人中心改密）

**流程：**
1. `dto.validate()` 参数校验
2. 查询用户当前密码
3. `verify_password(&dto.old_password, &old_hashed)` 校验旧密码
4. 校验失败返回 `AppError::bad_request("旧密码不正确")`
5. 密码加密：`encrypt_password(&dto.new_password)`
6. 更新 sys_user password 字段
7. 返回 `()`

**业务规则：**
- 需校验旧密码
- 新旧密码不能相同（业务规则校验）

#### 3.2.8 update_user_status（启停用户）

**流程：**
1. **超管保护**：若 user_id==1 且 status=='1'，返回 `AppError::bad_request("不允许停用超级管理员")`
2. 查询用户是否存在
3. 构造 `SysUserActiveModel`，仅设置 status 字段
4. 调用 Repository `update`
5. 返回 `()`

#### 3.2.9 assign_user_roles（分配用户角色）

**流程（事务）：**
1. 查询用户是否存在
2. **开启事务**：
   - 先删除该用户所有 sys_user_role 关联
   - 若 role_ids 非空，批量插入新关联
3. 返回 `()`

**业务规则：**
- 全量覆盖模式：先清空再插入
- `role_ids=vec![]` 表示解除所有角色

#### 3.2.10 get_user_by_username（登录认证用）

**流程：**
1. 按 `user_name` 查询用户（不过滤 del_flag）
2. 返回 `Option<SysUserModel>`

**业务规则：**
- **不过滤 del_flag**：登录时需区分"账号不存在"和"账号已删除"两种场景，由 Handler 层根据返回的 `del_flag` 字段判断并返回不同错误信息
- Handler 层判断逻辑：
  - `None` → "用户不存在"
  - `Some(user)` 且 `del_flag == "2"` → "账号已删除，请联系管理员"
  - `Some(user)` 且 `status == "1"` → "账号已停用，请联系管理员"
  - `Some(user)` 且 `del_flag == "0"` 且 `status == "0"` → 正常进入密码校验

---

## 4. 角色模块业务设计

### 4.1 DTO 定义

#### 4.1.1 RoleAddDto（新增角色）

| 字段 | 类型 | 校验规则 | 说明 |
|------|------|---------|------|
| role_name | String | length(2,30) | 角色名称 |
| role_key | String | length(2,100) | 角色权限字符串 |
| role_sort | i32 | range(0,999) | 显示顺序 |
| data_scope | Option\<String\> | 枚举 "1"-"5" | 数据范围 |
| menu_check_strictly | Option\<bool\> | — | 菜单树关联显示 |
| dept_check_strictly | Option\<bool\> | — | 部门树关联显示 |
| status | String | 枚举 "0"/"1" | 状态 |
| menu_ids | Option\<Vec\<i64\>\> | — | 菜单 ID 列表 |
| remark | Option\<String\> | length(0,500) | 备注 |

#### 4.1.2 RoleEditDto（修改角色）

| 字段 | 类型 | 校验规则 | 说明 |
|------|------|---------|------|
| role_id | i64 | required | 角色 ID |
| role_name | Option\<String\> | length(2,30) | 角色名称 |
| role_key | Option\<String\> | length(2,100) | 角色权限字符串 |
| role_sort | Option\<i32\> | range(0,999) | 显示顺序 |
| data_scope | Option\<String\> | 枚举 "1"-"5" | 数据范围 |
| menu_check_strictly | Option\<bool\> | — | 菜单树关联显示 |
| dept_check_strictly | Option\<bool\> | — | 部门树关联显示 |
| status | Option\<String\> | 枚举 "0"/"1" | 状态 |
| menu_ids | Option\<Vec\<i64\>\> | — | 菜单 ID 列表 |
| remark | Option\<String\> | length(0,500) | 备注 |

#### 4.1.3 RoleQueryDto（分页查询）

| 字段 | 类型 | 说明 |
|------|------|------|
| page_num | u64 | 页码 |
| page_size | u64 | 每页条数 |
| role_name | Option\<String\> | 角色名模糊 |
| role_key | Option\<String\> | 权限字符串精确 |
| status | Option\<String\> | 状态精确 |

### 4.2 业务方法清单

#### 4.2.1 get_role_page（分页查询角色）

**流程：**
1. 解析分页参数
2. 调用 Repository `find_active_page`
3. 返回 `TableDataInfo<SysRoleModel>`

#### 4.2.2 get_role_by_id（查询角色详情）

**流程：**
1. 按 role_id 查询角色
2. 查询角色已绑定菜单 ID 列表（`SysRoleMenuRepository::find_by_role_id` → 提取 menu_ids）
3. 返回 `RoleVo`（含 menu_ids）

#### 4.2.3 get_all_roles（查询所有角色）

**流程：**
1. 调用 Repository `find_active_all`
2. 返回 `Vec<SysRoleModel>`

**用途：** 用户编辑页角色下拉选择

#### 4.2.4 add_role（新增角色）

**流程（事务）：**
1. `dto.validate()` 参数校验
2. **role_key 查重**：`SysRoleRepository::find_by_role_key`，若存在返回 bad_request
3. 构造 `SysRoleActiveModel`，data_scope 默认 "1"（全部数据权限），del_flag='0'
4. **开启事务**：
   - 插入 sys_role → 获取 new_role_id
   - 若 menu_ids 非空：批量插入 sys_role_menu
5. 返回新角色 Model

**业务规则：**
- role_key 唯一（权限标识不能重复）
- 新增角色 data_scope 默认 "1"（修正旧实现硬编码 "2"）

#### 4.2.5 edit_role（修改角色）

**流程（事务）：**
1. `dto.validate()` 参数校验
2. 查询角色是否存在
3. **超管保护**：若 role_id==1，不允许修改 role_key
4. **role_key 查重**：若 dto.role_key 变更，校验新 role_key 是否已被其他角色占用
5. **开启事务**：
   - 更新 sys_role
   - 若 menu_ids 为 `Some`：
     - 先删除该角色所有 sys_role_menu 关联
     - 若 menu_ids 非空，批量插入新关联
6. 返回更新后角色 Model

**业务规则：**
- 不允许修改超管角色的 role_key（保持 "admin"）
- `menu_ids=None` 不修改菜单绑定，`menu_ids=Some(vec![])` 清空菜单绑定

#### 4.2.6 delete_role（删除角色）

**流程（事务）：**
1. **超管保护**：若 role_id==1，返回 `AppError::bad_request("不允许删除超级管理员角色")`
2. 查询角色是否存在
3. **级联删除校验**：查询 sys_user_role 中是否有关联用户
   - 若有，返回 `AppError::bad_request("该角色已分配给用户，不允许删除")`
4. **开启事务**：
   - 软删除 sys_role（`del_flag='2'`）
   - 物理删除 sys_role_menu 关联（`delete_by_role_id`）
   - 物理删除 sys_user_role 关联（`delete_by_role_id`，冗余保护）
5. 返回 `()`

**业务规则：**
- 禁止删除超管角色
- 禁止删除已分配用户的角色（修正旧实现无校验的缺陷）
- 级联清理 sys_role_menu 和 sys_user_role（修正旧实现仅清理 role_menu 的缺陷）

#### 4.2.7 update_role_status（启停角色）

**流程：**
1. **超管保护**：若 role_id==1 且 status=='1'，拒绝停用
2. 查询角色是否存在
3. 构造 `SysRoleActiveModel`，仅设置 status
4. 调用 Repository `update`
5. 返回 `()`

#### 4.2.8 assign_role_menus（分配角色菜单）

**流程（事务）：**
1. 查询角色是否存在
2. **开启事务**：
   - 先删除该角色所有 sys_role_menu 关联
   - 若 menu_ids 非空，批量插入新关联
3. 返回 `()`

**业务规则：**
- 全量覆盖模式
- 超管角色的菜单绑定也可修改（超管通过 role_key 短路，不依赖菜单绑定）

#### 4.2.9 get_roles_by_user_id（查询用户角色）

**流程：**
1. 调用 `SysRoleRepository::find_by_user_id`
2. 返回 `Vec<SysRoleModel>`

**用途：** 登录后获取用户角色列表，注入 JWT

#### 4.2.10 get_role_keys_by_user_id（查询用户角色 key 列表）

**流程：**
1. 调用 `get_roles_by_user_id`
2. 提取 `role_key` 列表
3. 返回 `Vec<String>`

**用途：** 权限校验

### 4.3 数据权限配置说明

角色实体的 `data_scope` 字段定义数据权限范围，取值如下：

| data_scope | 含义 | 本阶段实现状态 |
|-----------|------|--------------|
| "1" | 全部数据权限 | 本阶段不实现过滤逻辑 |
| "2" | 自定义数据权限 | 本阶段不实现（需 sys_role_dept 表，本阶段无此表） |
| "3" | 本部门数据权限 | 本阶段不实现（需部门模块） |
| "4" | 本部门及以下数据权限 | 本阶段不实现（需部门模块） |
| "5" | 仅本人数据权限 | 本阶段不实现 |

> **本阶段范围：** `data_scope` 字段仅作为配置存储，新增角色默认 "1"，修改角色时可通过 DTO 更新。运行时数据过滤逻辑留待后续阶段实现（需部门模块支持）。

---

## 5. 菜单模块业务设计

### 5.1 DTO 定义

#### 5.1.1 MenuAddDto（新增菜单）

| 字段 | 类型 | 校验规则 | 说明 |
|------|------|---------|------|
| parent_id | Option\<i64\> | — | 父菜单 ID（默认 0） |
| menu_name | String | length(2,50) | 菜单名称 |
| order_num | Option\<i32\> | range(0,999) | 显示顺序 |
| path | Option\<String\> | length(0,200) | 路由地址 |
| component | Option\<String\> | length(0,255) | 组件路径 |
| query | Option\<String\> | length(0,255) | 路由参数 |
| route_name | Option\<String\> | length(0,50) | 路由名称 |
| is_frame | Option\<String\> | 枚举 "0"/"1" | 是否外链 |
| is_cache | Option\<String\> | 枚举 "0"/"1" | 是否缓存 |
| menu_type | String | 枚举 "M"/"C"/"F" | 菜单类型 |
| visible | Option\<String\> | 枚举 "0"/"1" | 显示状态 |
| status | Option\<String\> | 枚举 "0"/"1" | 状态 |
| perms | Option\<String\> | length(0,100) | 权限标识 |
| icon | Option\<String\> | length(0,100) | 图标 |
| remark | Option\<String\> | length(0,500) | 备注 |

#### 5.1.2 MenuEditDto（修改菜单）

同 MenuAddDto，增加必填 `menu_id: i64`。

#### 5.1.3 MenuQueryDto（列表查询）

| 字段 | 类型 | 说明 |
|------|------|------|
| menu_name | Option\<String\> | 菜单名模糊 |
| status | Option\<String\> | 状态精确 |

### 5.2 业务方法清单

#### 5.2.1 get_menu_list（菜单列表，扁平）

**流程：**
1. 调用 `SysMenuRepository::find_active_all`（可加 menu_name/status 过滤）
2. 返回 `Vec<SysMenuModel>`

**用途：** 菜单管理表格展示（前端自行组装树）

#### 5.2.2 get_menu_tree（菜单下拉树）

**流程：**
1. 调用 `SysMenuRepository::find_active_all`
2. 调用 `utils::tree::build_tree(&list, 0)` 组装树
3. 返回 `Vec<SysMenuModel>`（带 children）

**业务规则：**
- 根节点 parent_id=0
- 所有菜单类型（M/C/F）均进入树（前端按需过滤）

#### 5.2.3 get_menu_by_id（查询菜单详情）

**流程：**
1. 按 menu_id 查询菜单
2. 不存在返回 not_found
3. 返回 `SysMenuModel`

#### 5.2.4 add_menu（新增菜单）

**流程：**
1. `dto.validate()` 参数校验
2. **parent_id 校验**：若 parent_id != 0，查询父菜单是否存在
3. **perms 查重**（仅 menu_type='C' 或 'F' 时）：若 perms 非空，查询是否已存在相同 perms
4. **按 menu_type 分支处理**：
   - **M（目录）**：perms 置空，component 置空
   - **C（菜单）**：保留 path/component/query/perms
   - **F（按钮）**：path 置空，component 置空，保留 perms
5. 构造 `SysMenuActiveModel`，del_flag='0'
6. 调用 Repository `insert`
7. 返回新菜单 Model

**业务规则：**
- 权限标识 perms 唯一（修正旧实现无校验的缺陷）
- 父菜单必须存在（parent_id=0 除外）
- menu_type 决定字段填充规则

#### 5.2.5 edit_menu（修改菜单）

**流程：**
1. `dto.validate()` 参数校验
2. 查询菜单是否存在
3. **perms 查重**：若 perms 变更，校验新 perms 是否已被其他菜单占用
4. **parent_id 校验**：
   - 若 parent_id == menu_id，返回 bad_request("上级菜单不能选择自己")
   - 若 parent_id != 0，校验新父菜单存在
   - **防环校验**：递归检查新 parent_id 是否是当前菜单的后代节点（若是则拒绝，否则会形成环）
5. 按 menu_type 分支处理（同 add_menu）
6. 构造 `SysMenuActiveModel`
7. 调用 Repository `update`
8. 返回更新后菜单 Model

**防环校验算法：**
```
fn is_descendant(menu_id: i64, candidate_parent_id: i64) -> bool:
    // 查询 candidate_parent_id 的所有祖先 ID
    // 若 menu_id 在祖先链中，说明 candidate_parent_id 是 menu_id 的后代，形成环
    let mut current = candidate_parent_id
    while current != 0:
        if current == menu_id:
            return true  // 形成环
        current = 查询 current 的 parent_id
    return false
```

**业务规则：**
- 权限标识唯一
- 防止菜单层级成环（parent_id 不能是自己或自己的后代）

#### 5.2.6 delete_menu（删除菜单）

**流程（事务）：**
1. 查询菜单是否存在
2. **子菜单校验**：查询是否有子菜单（parent_id==menu_id 且 del_flag='0'）
   - 若有，返回 `AppError::bad_request("存在子菜单，不允许删除")`
3. **菜单分配校验**：查询 sys_role_menu 中是否有关联角色
   - 若有，返回 `AppError::bad_request("菜单已分配给角色，不允许删除")`
4. **开启事务**：
   - 软删除 sys_menu（`del_flag='2'`）
   - 物理删除 sys_role_menu 关联（`delete_by_menu_id`）
5. 返回 `()`

**业务规则：**
- 禁止删除有子菜单的菜单（修正旧实现无校验的缺陷）
- 禁止删除已分配角色的菜单（修正旧实现无校验的缺陷）
- 软删除菜单，级联清理 sys_role_menu

#### 5.2.7 get_menu_tree_by_user_id（查询用户菜单树）

**流程：**
1. **超管短路**：若用户角色含 "admin"，查询所有未删除菜单
2. 非超管：调用 `SysMenuRepository::find_by_user_id`
3. 过滤 menu_type != 'F'（按钮不进路由树）
4. 调用 `utils::tree::build_tree(&list, 0)` 组装树
5. 返回 `Vec<SysMenuModel>`（带 children）

**业务规则：**
- 超管返回所有菜单
- 按钮类型（F）不进路由树

#### 5.2.8 get_permissions_by_user_id（查询用户权限标识列表）

**流程：**
1. **超管短路**：若用户角色含 "admin"，返回 `vec!["*:*:*".to_string()]`
2. 非超管：调用 `SysMenuRepository::find_by_user_id`
3. 提取所有非空的 `perms` 字段
4. 返回 `Vec<String>`

**业务规则：**
- 超管返回 `["*:*:*"]` 通配权限
- 去重（多个菜单可能有相同 perms）

---

## 6. 跨模块依赖关系

### 6.1 用户模块依赖

```
SysUserService
  ├─ SysUserRepository
  ├─ SysRoleRepository（查询用户角色）
  ├─ SysUserRoleRepository（用户角色关联）
  ├─ utils::password（密码加密校验）
  └─ common::page（分页）
```

### 6.2 角色模块依赖

```
SysRoleService
  ├─ SysRoleRepository
  ├─ SysMenuRepository（查询角色菜单）
  ├─ SysRoleMenuRepository（角色菜单关联）
  ├─ SysUserRoleRepository（级联删除校验）
  └─ common::page（分页）
```

### 6.3 菜单模块依赖

```
SysMenuService
  ├─ SysMenuRepository
  ├─ SysRoleMenuRepository（删除校验）
  ├─ SysRoleRepository（超管判定）
  ├─ SysUserRoleRepository（超管判定）
  ├─ utils::tree（树形组装）
  └─ common::page（分页）
```

---

## 7. 错误处理约定

### 7.1 Service 层返回类型

所有 Service 方法统一返回 `Result<T, AppError>`：

```rust
pub async fn add_user(&self, dto: UserAddDto, operator: &str) -> Result<SysUserModel, AppError>
```

### 7.2 错误分类

| 错误类型 | AppError 构造 | 使用场景 |
|---------|--------------|---------|
| 参数校验失败 | `AppError::bad_request(msg)` | garde 校验失败、业务规则校验失败 |
| 资源不存在 | `AppError::not_found(msg)` | 查询的记录不存在 |
| 未认证 | `AppError::unauthorized(msg)` | 登录校验失败 |
| 数据库错误 | `From<DbErr>` 自动转换 | SeaORM 操作失败 |
| 内部错误 | `AppError::internal(msg)` | 其他未知错误 |

### 7.3 事务错误传播

事务闭包内返回 `DbErr` 时，SeaORM 自动回滚事务。Service 层将 `DbErr` 转为 `AppError` 返回。

---

## 8. 文件组织结构

```
src/service/
├── mod.rs                      # 模块声明与 re-export
├── sys_user_service.rs         # 用户 Service
├── sys_role_service.rs         # 角色 Service
└── sys_menu_service.rs         # 菜单 Service

src/service/dto/                # DTO 定义（可选独立目录）
├── mod.rs
├── sys_user_dto.rs
├── sys_role_dto.rs
└── sys_menu_dto.rs
```

> **决策：** DTO 与 Service 放在同一文件内（`sys_user_service.rs` 包含 `SysUserService` + `UserAddDto` 等），避免文件碎片化。若 DTO 过多可后续拆分。

---

## 9. 关键实现差异对照

| 维度 | 旧实现 | 本项目 |
|------|----------------|--------|
| ORM | rbatis + html_sql | SeaORM 原生 |
| 事务 | `GLOBAL_DB.acquire_begin()`（形同虚设） | `TransactionTrait::transaction()`（真事务） |
| 密码 | MD5 + "salvo_admin" | MD5 + "stepby_admin"（不兼容旧数据） |
| 参数校验 | 零散 if 判断 | garde crate 结构化校验 |
| 用户名查重 | 有 | 有 |
| role_key 查重 | 无 | 有 |
| perms 查重 | 无 | 有 |
| 删除用户级联 | 未清理 user_role | 清理 |
| 删除角色级联 | 仅清理 role_menu | 清理 role_menu + user_role |
| 删除菜单级联 | 未清理 role_menu | 清理 |
| 子菜单校验 | 无 | 有 |
| 菜单分配校验 | 无 | 有 |
| 超管保护 | 仅 user_id==1 设 admin=true | 禁删/禁停超管用户和角色 |
| 树形组装 | 递归 clone O(n²) | `build_tree` 单次遍历 |
| N+1 查询 | 用户列表逐条查部门 | 用户列表逐条查角色（本阶段接受） |
