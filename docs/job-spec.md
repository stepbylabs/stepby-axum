# 定时任务模块（sys_job）架构设计

## 一、需求概述

基于全局规则（纯 Axum + SeaORM），使用 `tokio-cron-scheduler` 独立实现定时任务调度内核，接口 100% 对齐本项目前端 `/monitor/job` 和 `/monitor/jobLog` 契约。

### 核心能力

| 能力 | 说明 |
|------|------|
| 任务 CRUD | 新增/修改/删除/查询/详情，对齐前端 `SysJob` 字段 |
| 任务启停同步 | status 切换时同步启停调度器中的任务 |
| 手动单次执行 | `PUT /monitor/job/run`，立即触发一次，不影响原调度 |
| 执行日志落盘 | 每次执行（定时/手动）写入 `sys_job_log`，含状态/耗时/异常 |
| 启动自动加载 | 服务启动时从数据库加载所有 `status='0'` 的任务注册到调度器 |
| 异常隔离 | 任务执行失败捕获异常写日志，不影响调度器和其他任务 |
| 下次执行时间 | 查询任务详情/列表时根据 cron 表达式计算 `nextValidTime` 返回前端 |
| 任务导出 | `POST /monitor/job/export` 导出任务列表为 Excel |

---

## 二、表结构对齐

### 2.1 sys_job（已有，无需修改）

| 字段 | 类型 | 说明 |
|------|------|------|
| job_id | i64 PK AUTO_INCREMENT | 任务 ID（起始 100） |
| job_name | varchar(64) NOT NULL | 任务名称 |
| job_group | varchar(64) default 'DEFAULT' | 任务组名 |
| invoke_target | varchar(500) NOT NULL | 调用目标字符串 |
| cron_expression | varchar(255) default '' | cron 表达式 |
| misfire_policy | varchar(20) default '3' | 错误策略：1立即 2执行一次 3放弃 |
| concurrent | char(1) default '1' | 并发：0允许 1禁止 |
| status | char(1) default '0' | **0=正常(运行) 1=暂停** |
| create_by/create_time/update_by/update_time/remark | 标准字段 | |
| del_flag | char(1) default '0' | 软删除：0正常 2删除 |
| **唯一索引** | uk_sys_job_name_group(job_name, job_group) | |

### 2.2 sys_job_log（已有，无需修改）

| 字段 | 类型 | 说明 |
|------|------|------|
| job_log_id | i64 PK AUTO_INCREMENT | 日志 ID |
| job_name | varchar(64) NOT NULL | 任务名称 |
| job_group | varchar(64) NOT NULL | 任务组名 |
| invoke_target | varchar(500) NOT NULL | 调用目标 |
| job_message | varchar(500) NULL | 执行信息（含耗时，格式：`执行成功 (耗时 123ms)`） |
| status | char(1) default '0' | **0=成功 1=失败** |
| exception_info | varchar(2000) default '' | 异常信息 |
| create_time | datetime NULL | 执行时间 |
| **索引** | idx_sys_job_log_status, idx_sys_job_log_create_time | |

> **job_message 耗时格式**：前端 detail.vue 通过 `startTime`/`endTime` 计算 `costTime`，但后端表无这两个字段。后端在 `job_message` 中包含耗时信息（格式：`执行成功 (耗时 123ms)`），前端日志详情中该字段直接展示在"日志信息"栏。

### 2.3 状态语义对照（关键）

| 表 | 字段值 | 语义 | 注意 |
|----|--------|------|------|
| sys_job | status='0' | 正常（调度运行中） | 与前端 el-switch active-value="0" 一致 |
| sys_job | status='1' | 暂停（调度停止） | 与前端 inactive-value="1" 一致 |
| sys_job_log | status='0' | 执行成功 | |
| sys_job_log | status='1' | 执行失败 | |

> **注意**：旧实现的 status 语义（0=暂停 1=运行）与前端**相反**，stepby-axum 遵循前端语义，不照搬旧实现。

---

## 三、接口契约（对齐本项目前端）

### 3.1 任务管理接口 `/monitor/job`

| # | HTTP | 路径 | 入参 | 出参 | 前端函数 |
|---|------|------|------|------|----------|
| 1 | GET | `/monitor/job/list` | Query: JobQueryDto | TableDataInfo\<JobVo\> | listJob |
| 2 | GET | `/monitor/job/{jobId}` | Path: i64 | AjaxResult\<JobVo\> | getJob |
| 3 | POST | `/monitor/job` | Body: JobAddDto | AjaxResult | addJob |
| 4 | PUT | `/monitor/job` | Body: JobEditDto | AjaxResult | updateJob |
| 5 | DELETE | `/monitor/job/{jobIds}` | Path: String(逗号分隔) | AjaxResult | delJob |
| 6 | PUT | `/monitor/job/changeStatus` | Body: JobStatusDto | AjaxResult | changeJobStatus |
| 7 | PUT | `/monitor/job/run` | Body: JobRunDto | AjaxResult | runJob |
| 8 | POST | `/monitor/job/export` | Body: JobQueryDto | 文件流(xlsx) | handleExport |

### 3.2 任务日志接口 `/monitor/jobLog`

| # | HTTP | 路径 | 入参 | 出参 | 前端函数 |
|---|------|------|------|------|----------|
| 9 | GET | `/monitor/jobLog/list` | Query: JobLogQueryDto | TableDataInfo\<SysJobLog\> | listJobLog |
| 10 | DELETE | `/monitor/jobLog/{jobLogIds}` | Path: String(逗号分隔) | AjaxResult | delJobLog |
| 11 | DELETE | `/monitor/jobLog/clean` | 无 | AjaxResult | cleanJobLog |
| 12 | POST | `/monitor/jobLog/export` | Body: JobLogQueryDto | 文件流(xlsx) | handleExport(log.vue:236) |

> **注意**：前端 `log.vue` 第 236 行通过 `proxy.download("monitor/jobLog/export", ...)` 调用导出接口，虽未在 `api/monitor/jobLog.ts` 中定义独立函数，但后端必须实现该接口。

### 3.3 响应 VO（nextValidTime 计算返回）

前端 `SysJob` 类型含 `nextValidTime?: Date` 字段，detail.vue 第 119 行展示"下次执行时间"。后端需在查询任务详情/列表时计算并返回。

```rust
/// 任务响应 VO（在 SysJobModel 基础上增加 nextValidTime 计算字段）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobVo {
    #[serde(flatten)]
    pub job: SysJobModel,
    /// 下次执行时间（根据 cron_expression 计算，cron 非法时为 None）
    pub next_valid_time: Option<String>,
}

impl JobVo {
    /// 从 Model 构造，自动计算 nextValidTime
    pub fn from_model(job: SysJobModel) -> Self {
        let next_valid_time = job.cron_expression
            .as_ref()
            .and_then(|cron| calc_next_valid_time(cron));
        Self { job, next_valid_time }
    }
}

/// 解析 cron 表达式，返回下次执行时间的 ISO 8601 字符串
fn calc_next_valid_time(cron_str: &str) -> Option<String> {
    use croner::Schedule;
    use std::str::FromStr;
    match Schedule::from_str(cron_str) {
        Ok(schedule) => {
            schedule.upcoming(chrono::Utc).next()
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        }
        Err(_) => None,
    }
}
```

### 3.4 DTO 定义

```rust
// ===== 任务查询 DTO =====
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobQueryDto {
    #[serde(flatten)]
    pub page: PageDomain,
    pub job_name: Option<String>,
    pub job_group: Option<String>,
    pub status: Option<String>,
}

// ===== 新增任务 DTO =====
#[derive(Debug, Deserialize, Garde)]
#[serde(rename_all = "camelCase")]
pub struct JobAddDto {
    #[garde(length(min = 1, max = 64, message = "任务名称不能为空且不超过64字符"))]
    pub job_name: String,
    #[garde(length(max = 64, message = "任务组名不超过64字符"))]
    pub job_group: String,
    #[garde(length(min = 1, max = 500, message = "调用目标不能为空且不超过500字符"))]
    pub invoke_target: String,
    #[garde(length(min = 1, max = 255, message = "cron表达式不能为空且不超过255字符"))]
    pub cron_expression: String,
    pub misfire_policy: Option<String>,  // 默认 "3"
    pub concurrent: Option<String>,      // 默认 "1"
    pub status: Option<String>,          // 默认 "0"
    #[garde(length(max = 500, message = "备注不超过500字符"))]
    pub remark: Option<String>,
}

// ===== 修改任务 DTO =====
#[derive(Debug, Deserialize, Garde)]
#[serde(rename_all = "camelCase")]
pub struct JobEditDto {
    pub job_id: i64,
    #[garde(length(min = 1, max = 64, message = "任务名称不能为空且不超过64字符"))]
    pub job_name: String,
    #[garde(length(max = 64, message = "任务组名不超过64字符"))]
    pub job_group: String,
    #[garde(length(min = 1, max = 500, message = "调用目标不能为空且不超过500字符"))]
    pub invoke_target: String,
    #[garde(length(min = 1, max = 255, message = "cron表达式不能为空且不超过255字符"))]
    pub cron_expression: String,
    pub misfire_policy: Option<String>,
    pub concurrent: Option<String>,
    pub status: Option<String>,
    #[garde(length(max = 500, message = "备注不超过500字符"))]
    pub remark: Option<String>,
}

// ===== 状态切换 DTO =====
#[derive(Debug, Deserialize, Garde)]
#[serde(rename_all = "camelCase")]
pub struct JobStatusDto {
    pub job_id: i64,
    #[garde(length(min = 1, max = 1, message = "状态值不合法"))]
    pub status: String,  // "0"=正常运行 "1"=暂停
}

// ===== 立即执行 DTO =====
#[derive(Debug, Deserialize, Garde)]
#[serde(rename_all = "camelCase")]
pub struct JobRunDto {
    pub job_id: i64,
    #[garde(length(max = 64, message = "任务组名不超过64字符"))]
    pub job_group: String,
}

// ===== 日志查询 DTO =====
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobLogQueryDto {
    #[serde(flatten)]
    pub page: PageDomain,
    pub job_name: Option<String>,
    pub job_group: Option<String>,
    pub status: Option<String>,
    pub params: Option<TimeRange>,  // beginTime/endTime
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeRange {
    pub begin_time: Option<String>,
    pub end_time: Option<String>,
}
```

### 3.5 权限标识映射（对齐前端 v-hasPermi）

| 接口 | 权限标识 |
|------|----------|
| GET /monitor/job/list | monitor:job:list |
| GET /monitor/job/{jobId} | monitor:job:query |
| POST /monitor/job | monitor:job:add |
| PUT /monitor/job | monitor:job:edit |
| PUT /monitor/job/changeStatus | monitor:job:changeStatus |
| PUT /monitor/job/run | monitor:job:changeStatus |
| DELETE /monitor/job/{jobIds} | monitor:job:remove |
| POST /monitor/job/export | monitor:job:export |
| GET /monitor/jobLog/list | monitor:job:list |
| DELETE /monitor/jobLog/{jobLogIds} | monitor:job:remove |
| DELETE /monitor/jobLog/clean | monitor:job:remove |
| POST /monitor/jobLog/export | monitor:job:export |

---

## 四、架构设计

### 4.1 分层架构

```
┌─────────────────────────────────────────────────────┐
│                    Handler 层                        │
│  sys_job_handler.rs / sys_job_log_handler.rs        │
│  职责：参数解析 → Service 调用 → 响应封装             │
├─────────────────────────────────────────────────────┤
│                    Service 层                        │
│  sys_job_service.rs                                 │
│  职责：CRUD 业务逻辑 + 调度器委托（启停/执行）        │
│  持有：SysJobRepository + SysJobLogRepository        │
│       + Arc<JobScheduler>                            │
├─────────────────────────────────────────────────────┤
│                   调度内核层                          │
│  scheduler/mod.rs       — JobScheduler 封装          │
│  scheduler/registry.rs  — 任务函数注册表              │
│  职责：tokio-cron-scheduler 生命周期管理              │
│       + 任务函数路由 + 日志写入                       │
│  约束：不依赖 axum/web 类型，仅依赖 sea-orm + tokio   │
├─────────────────────────────────────────────────────┤
│                   Repository 层                      │
│  sys_job.rs / sys_job_log.rs（已有）                 │
│  职责：SeaORM 查询封装                               │
├─────────────────────────────────────────────────────┤
│                   Entity 层                          │
│  sys_job.rs / sys_job_log.rs（已有）                 │
└─────────────────────────────────────────────────────┘
```

### 4.2 调度内核错误类型（SchedulerError）

```rust
// src/scheduler/mod.rs

/// 调度内核错误类型（不依赖 Web 框架）
#[derive(Debug)]
pub enum SchedulerError {
    /// cron 表达式解析失败
    InvalidCron(String),
    /// 调度器内部错误（add/remove/start 失败）
    SchedulerInternal(String),
}

impl std::fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchedulerError::InvalidCron(msg) => write!(f, "cron 表达式非法: {}", msg),
            SchedulerError::SchedulerInternal(msg) => write!(f, "调度器内部错误: {}", msg),
        }
    }
}

impl std::error::Error for SchedulerError {}

/// SchedulerError → ServiceError 转换（Service 层 ? 自动使用）
impl From<SchedulerError> for crate::common::error::ServiceError {
    fn from(err: SchedulerError) -> Self {
        match err {
            SchedulerError::InvalidCron(msg) => {
                crate::common::error::ServiceError::bad_request(&format!("cron 表达式非法: {}", msg))
            }
            SchedulerError::SchedulerInternal(msg) => {
                tracing::error!("调度器内部错误: {}", msg);
                crate::common::error::ServiceError::internal("调度器操作失败，请联系管理员")
            }
        }
    }
}
```

### 4.3 调度内核设计（JobScheduler）

```rust
// src/scheduler/mod.rs

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio_cron_scheduler::{JobScheduler as TokioScheduler, Job};
use sea_orm::DatabaseConnection;
use redis::aio::ConnectionManager;
use crate::entity::sys_job::Model as SysJobModel;
use crate::repository::{SysJobRepository, SysJobLogRepository};

/// 调度内核封装（不依赖 Web 框架）
pub struct JobScheduler {
    scheduler: Arc<TokioScheduler>,
    db: DatabaseConnection,
    /// Redis 连接管理器，用于分布式锁（多实例部署时防止任务重复执行）
    redis: ConnectionManager,
    /// 运行中任务的 UUID 映射（job_id -> scheduler 内部 job guid）
    /// 用于启停/更新时精确移除
    running_jobs: RwLock<HashMap<i64, uuid::Uuid>>,
    /// 正在执行中的任务标记（job_id -> true）
    /// 用于 concurrent='1' 时禁止并发执行
    /// 使用 std::sync::Mutex 以支持 ExecutingFlagGuard 的同步 Drop
    /// （锁持有时间极短，不跨 await，符合异步上下文使用约束）
    executing_jobs: Arc<std::sync::Mutex<HashMap<i64, bool>>>,
}

impl JobScheduler {
    /// 创建并启动调度器
    pub async fn new(
        db: DatabaseConnection,
        redis: ConnectionManager,
        ip_location_service: crate::service::IpLocationService,
    ) -> Result<Self, SchedulerError>;

    /// 从数据库加载所有 status='0' 的任务并注册
    pub async fn load_from_db(&self) -> Result<(), SchedulerError>;

    /// 添加任务到调度器
    pub async fn add_job(&self, job: &SysJobModel) -> Result<uuid::Uuid, SchedulerError>;

    /// 从调度器移除任务（幂等：不存在时静默成功）
    pub async fn remove_job(&self, job_id: i64) -> Result<(), SchedulerError>;

    /// 更新任务（先移除再添加）
    pub async fn update_job(&self, job: &SysJobModel) -> Result<(), SchedulerError>;

    /// 手动执行一次（不注册调度，直接 spawn）
    pub async fn run_once(&self, job: &SysJobModel) -> Result<(), SchedulerError>;
}
```

### 4.4 任务函数注册表与 invoke_target 解析策略

```rust
// src/scheduler/registry.rs

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use std::sync::Arc;
use futures::future::BoxFuture;

/// 任务执行函数签名（返回执行信息或错误信息）
pub type TaskFn = Arc<
    dyn Fn() -> BoxFuture<'static, Result<String, String>> + Send + Sync,
>;

/// 全局任务注册表
static TASK_REGISTRY: LazyLock<RwLock<HashMap<String, TaskFn>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// 注册任务函数
pub fn register_task(invoke_target: &str, func: TaskFn);

/// 查询任务函数
pub fn get_task(invoke_target: &str) -> Option<TaskFn>;

/// 列出所有已注册的 invoke_target
pub fn list_registered_tasks() -> Vec<String>;
```

**invoke_target 解析策略**：

由于 Rust 后端无 Java Bean 反射调用，采用**完整字符串匹配**策略：

| invoke_target 字符串 | 注册表 key | 说明 |
|----------------------|-----------|------|
| `demoTask.demoNoParams` | `demoTask.demoNoParams` | 完整字符串作为 key |
| `demoTask.demoParams('demo')` | `demoTask.demoParams('demo')` | 完整字符串（含参数）作为 key |
| `demoTask.demoMultipleParams('demo', true, 2000L, 316.5F, 100)` | 同左 | 完整字符串作为 key |

- 内置任务在 `scheduler/mod.rs` 的 `register_builtin_tasks()` 中注册
- 后续扩展：调用 `register_task("customTask.doSomething", func)` 即可
- 未注册的 invoke_target：调度器执行时写失败日志（status='1', exception_info="未找到调用目标: xxx"）

### 4.5 任务执行流程

```
定时触发 / 手动执行
        │
        ▼
┌───────────────────────┐
│ 并发检查               │
│ concurrent='1' 且      │──Yes──→ 跳过本次，tracing::debug! 记录
│ executing_jobs 含此 id │        （不写日志，不影响后续调度）
└───────┬───────────────┘
        │ No
        ▼
┌───────────────────────┐
│ 标记 executing_jobs   │
│ 从 registry 查表      │
│ invoke_target -> fn   │
└───────┬───────────────┘
        │
   ┌────┴────┐
   │ 找到？  │
   └────┬────┘
    Yes │ No
        │    → job_message="未找到调用目标: xxx", status="1"(失败)
        │      exception_info="invoke_target not registered"
        │      → 写日志 → 清除标记 → 结束
        ▼
┌───────────────────────┐
│ 执行任务函数          │
│ tokio::time::timeout  │
│ 60s 超时              │
└───────┬───────────────┘
        │
   ┌────┴────┐
   │ 成功？  │
   └────┬────┘
    Yes │ No
        │    → job_message=错误信息, status="1"(失败)
        │      exception_info=错误堆栈
        ▼      → 写日志 → 清除标记 → 结束
┌───────────────────────┐
│ job_message=返回值     │
│ status="0"(成功)      │
│ 写日志 → 清除标记 → 结束│
└───────────────────────┘
```

### 4.6 misfire_policy 实现方案

| misfire_policy | 语义 | 实现方式 |
|----------------|------|----------|
| '1' | 立即执行 | 调度器启动时若发现任务错过了执行时间，立即补执行一次 |
| '2' | 执行一次 | 调度器启动时若发现任务错过了执行时间，补执行一次后恢复正常调度 |
| '3' | 放弃执行（默认） | 调度器启动时跳过错过的执行，等待下次正常触发 |

**实现说明**：
- tokio-cron-scheduler 内部基于 cron 表达式触发，不跟踪 misfire 历史
- stepby-axum 在 `load_from_db()` 阶段对 `misfire_policy='1'` 或 `'2'` 的任务，启动后立即 spawn 一次 `execute_task`
- `misfire_policy='3'` 的任务仅按 cron 正常调度，不补执行
- 这是简化实现，不追踪精确的 misfire 次数（Quartz 行为过于复杂，Rust 后端按业务够用原则简化）

### 4.7 AppState 集成

```rust
// src/state.rs 新增字段
pub struct AppState {
    // ...已有字段...
    pub job_service: SysJobService,
    pub job_scheduler: Arc<JobScheduler>,
}

// AppState::new 新增参数 job_scheduler
// 调用方（AppInitializer）提前创建 scheduler 后传入
pub fn new(
    db: DatabaseConnection,
    redis: ConnectionManager,
    config: Arc<Settings>,
    job_scheduler: Arc<JobScheduler>,  // 新增参数
) -> Self {
    Self {
        job_service: SysJobService::new(db.clone(), job_scheduler.clone()),
        job_scheduler,
        // ...已有字段...
        db, redis, config,
        user_service: SysUserService::new(db.clone()),
        role_service: SysRoleService::new(db.clone()),
        menu_service: SysMenuService::new(db.clone()),
        auth_service: AuthService::new(db.clone()),
    }
}
```

> **设计决策**：`AppState::new` 保持同步函数（不改 async），调度器在 `AppInitializer::run` 中提前异步创建后以参数传入，避免污染 AppState 的同步签名。

### 4.8 启动初始化流程

```
AppInitializer::run()
    │
    ├── 1. 加载配置 → 日志 → DB → Redis
    │
    ├── 2. 创建 JobScheduler::new(db)  ← 新增
    │   └── 内部启动 tokio-cron-scheduler
    │
    ├── 3. job_scheduler.load_from_db()  ← 新增
    │   └── 查询 sys_job WHERE status='0' AND del_flag='0'
    │   └── 逐个 add_job() 注册到调度器
    │   └── misfire_policy='1'/'2' 的任务补执行一次
    │
    ├── 4. 构建 AppState::new(db, redis, settings, job_scheduler)
    │   └── AppState 内部创建 SysJobService（持有 scheduler 引用）
    │
    └── 5. 返回 AppState
```

---

## 五、状态流转

### 5.1 任务状态流转图

```
                    ┌─────────────┐
                    │  数据库新增  │
                    │ status='0'  │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
          ┌─────────┤  调度运行中  ├─────────┐
          │         └─────────────┘         │
          │ changeStatus(status='1')        │ changeStatus(status='0')
          │                                 │
    ┌─────▼──────┐                   ┌──────▼──────┐
    │  调度暂停   │←──────────────────┤  重新启动    │
    │ status='1' │   changeStatus    │ status='0'  │
    └─────┬──────┘    (status='1')   └─────────────┘
          │
          │ DELETE
          │
    ┌─────▼──────┐
    │  软删除     │
    │ del_flag='2'│
    └────────────┘
```

### 5.2 CRUD 操作与调度器同步矩阵

| 操作 | 数据库变更 | 调度器动作 | 条件 |
|------|-----------|-----------|------|
| 新增（status='0'） | INSERT sys_job | add_job() | cron 合法 |
| 新增（status='1'） | INSERT sys_job | 无 | — |
| 修改（cron/target 变更，status='0'） | UPDATE sys_job | update_job()（remove+add） | cron 合法 |
| 修改（cron/target 变更，status='1'） | UPDATE sys_job | 无 | — |
| 修改（status 0→1） | UPDATE sys_job.status | remove_job() | — |
| 修改（status 1→0） | UPDATE sys_job.status | add_job() | cron 合法 |
| 删除 | UPDATE del_flag='2' | remove_job() | 原状态='0' |
| changeStatus(0→1) | UPDATE sys_job.status | remove_job() | — |
| changeStatus(1→0) | UPDATE sys_job.status | add_job() | cron 合法 |
| run（手动执行） | 无 DB 变更 | run_once()（spawn 独立任务） | — |

### 5.3 并发控制

| concurrent 值 | 语义 | 实现方式 | 跳过时行为 |
|---------------|------|----------|-----------|
| '0' | 允许并发 | 调度器正常触发，不阻止重叠执行 | — |
| '1' | 禁止并发 | 调度器触发前检查 `executing_jobs` 标记，若正在执行则跳过本次 | tracing::debug! 记录，不写日志，不影响后续调度 |

---

## 六、异常处理方案

### 6.1 异常分级

| 级别 | 场景 | 处理方式 | 用户可见 |
|------|------|----------|----------|
| L1 | 任务函数执行失败 | 捕获异常 → 写日志(status='1') → 继续调度 | 日志可查 |
| L2 | cron 表达式非法 | 拒绝新增/修改 → 返回 400 | 是 |
| L3 | invoke_target 未注册 | 写日志(status='1', exception="未找到调用目标") | 日志可查 |
| L4 | 调度器启动失败 | 返回 Err → AppInitializer 传播 → 服务不启动 | 是 |
| L5 | 任务执行超时(>60s) | tokio::time::timeout 杀死 → 写日志(status='1') | 日志可查 |
| L6 | 日志写入失败 | tracing::error! 记录 → 不影响任务执行 | 否 |
| L7 | 并发跳过 | tracing::debug! 记录 → 不写日志 → 等待下次触发 | 否 |
| L8 | remove_job 时任务不存在 | tracing::warn! 记录 → 静默成功（幂等） | 否 |

### 6.2 任务执行异常捕获（核心代码结构）

```rust
/// 执行任务并写日志
///
/// 并发控制：concurrent='1' 时检查 executing_jobs 跳过
/// 超时控制：60 秒
/// 异常隔离：所有错误捕获写日志，不 panic
async fn execute_task(&self, job: &SysJobModel) {
    let concurrent = job.concurrent.as_deref().unwrap_or("1");

    // 并发检查
    if concurrent == "1" {
        let executing = self.executing_jobs.read().await;
        if executing.get(&job.job_id).copied().unwrap_or(false) {
            tracing::debug!(
                "任务 {} 禁止并发，跳过本次执行",
                job.job_name
            );
            return;
        }
    }

    // 标记执行中
    {
        let mut executing = self.executing_jobs.write().await;
        executing.insert(job.job_id, true);
    }

    let start = std::time::Instant::now();
    let (status, message, exception_info) = match execute_inner(&job.invoke_target).await {
        Ok(msg) => ("0", msg, String::new()),
        Err(e) => ("1", format!("任务执行失败: {}", e), e),
    };
    let elapsed = start.elapsed().as_millis();

    // 清除执行标记
    {
        let mut executing = self.executing_jobs.write().await;
        executing.remove(&job.job_id);
    }

    // 写日志（失败不影响主流程）
    let log_am = sys_job_log::ActiveModel {
        job_name: Set(job.job_name.clone()),
        job_group: Set(job.job_group.clone()),
        invoke_target: Set(job.invoke_target.clone()),
        job_message: Set(Some(format!("{} (耗时 {}ms)", message, elapsed))),
        status: Set(Some(status.to_string())),
        exception_info: if exception_info.is_empty() {
            Set(None)
        } else {
            Set(Some(exception_info))
        },
        create_time: Set(Some(chrono::Local::now().naive_local())),
        ..Default::default()
    };
    if let Err(e) = self.job_log_repo.insert(log_am).await {
        tracing::error!("写入任务日志失败 job_id={}: {}", job.job_id, e);
    }
}

async fn execute_inner(invoke_target: &str) -> Result<String, String> {
    let func = registry::get_task(invoke_target)
        .ok_or_else(|| format!("未找到调用目标: {}", invoke_target))?;

    // 60 秒超时
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        func(),
    )
    .await
    .map_err(|_| "任务执行超时（>60s）".to_string())?
}
```

### 6.3 调度器操作异常处理

| 操作 | 失败处理 | 原因 |
|------|----------|------|
| `add_job` 失败 | 返回 `SchedulerError::SchedulerInternal` → ServiceError → Handler 500 | 任务未成功注册，用户需重试 |
| `remove_job` 失败（任务不存在） | tracing::warn! → 静默成功（幂等） | 任务可能已从调度器自然过期 |
| `remove_job` 失败（其他错误） | tracing::warn! 记录但不阻断 DB 操作 | DB 已变更，调度器下次重启自然清理 |
| `load_from_db` 单个任务失败 | tracing::warn! 记录，继续加载下一个 | 单个任务失败不影响其他任务 |
| `run_once` 失败 | 返回 `SchedulerError` → ServiceError → Handler 500 | 用户需知道执行是否提交成功 |

---

## 七、文件清单

### 7.1 新建文件

| 文件路径 | 职责 |
|----------|------|
| `src/scheduler/mod.rs` | 调度内核模块入口 + JobScheduler 封装 + SchedulerError + 内置任务注册 |
| `src/scheduler/registry.rs` | 任务函数注册表 |
| `src/service/sys_job_service.rs` | 任务 Service 层（CRUD + 调度器委托 + JobVo + nextValidTime 计算） |
| `src/handler/sys_job_handler.rs` | 任务 Handler 层（含 export） |
| `src/handler/sys_job_log_handler.rs` | 日志 Handler 层（含 export） |
| `src/router/sys_job_router.rs` | 任务 + 日志路由注册 |

### 7.2 修改文件

| 文件路径 | 修改内容 |
|----------|----------|
| `Cargo.toml` | 新增 `tokio-cron-scheduler = "0.15"` + `croner = "3"` 依赖 |
| `src/lib.rs` | 新增 `pub mod scheduler;` |
| `src/service/mod.rs` | 新增 `pub mod sys_job_service;` + re-export `SysJobService` |
| `src/handler/mod.rs` | 新增 `pub mod sys_job_handler;` + `pub mod sys_job_log_handler;` |
| `src/router/mod.rs` | 新增 `pub mod sys_job_router;` + merge job_routes 到 protected |
| `src/state.rs` | 新增 `job_service` + `job_scheduler` 字段，`new()` 新增 `job_scheduler` 参数 |
| `src/initialize/mod.rs` | 新增调度器创建 + load_from_db 调用，AppState::new 传入 scheduler |
| `src/repository/sys_job.rs` | 新增 `find_by_status` / `find_active_by_id` / `find_page_filtered` 方法 |
| `src/repository/sys_job_log.rs` | 新增 `find_page_filtered` / `delete_by_ids` 方法 |
| `src/middleware/permission.rs` | 权限映射表新增 `/monitor/job/*` 和 `/monitor/jobLog/*` 条目 |
| `src/common/error.rs` | 新增 `From<SchedulerError> for ServiceError` 实现 |

### 7.3 不修改文件

| 文件 | 原因 |
|------|------|
| `src/entity/sys_job.rs` | 字段已对齐前端，无需修改 |
| `src/entity/sys_job_log.rs` | 字段已对齐前端，无需修改 |
| `migration/src/m20250711_000001_init.rs` | 表结构和索引已就绪，无需修改 |

---

## 八、内置任务函数

服务启动时自动注册以下内置任务（对齐内置初始数据）：

| invoke_target | 功能 | 默认 cron | 说明 |
|---------------|------|-----------|------|
| `demoTask.demoNoParams` | 示例任务（无参数） | 0/10 * * * * ? | 每 10 秒执行，输出 "demoNoParams 执行成功" |
| `demoTask.demoParams('demo')` | 示例任务（带参数） | 0/15 * * * * ? | 每 15 秒执行，输出 "demoParams 执行成功，参数: stepby" |
| `demoTask.demoMultipleParams('demo', true, 2000L, 316.5F, 100)` | 示例任务（多参数） | 0/20 * * * * ? | 每 20 秒执行，输出 "demoMultipleParams 执行成功" |

注册位置：`src/scheduler/mod.rs` 的 `register_builtin_tasks()` 函数，在 `JobScheduler::new()` 中调用。

> 说明：Rust 后端无 Java Bean 反射调用，invoke_target 完整字符串作为注册表 key。内置任务仅做日志输出。后续扩展通过 `register_task("customTask.doSomething", func)` 注册新函数即可。

---

## 九、测试计划

### 9.1 单元测试

| 测试文件 | 测试内容 |
|----------|----------|
| `src/scheduler/registry.rs` | `test_register_and_get_task` — 注册后能查到 |
| `src/scheduler/registry.rs` | `test_get_unregistered_task` — 未注册返回 None |
| `src/scheduler/registry.rs` | `test_list_registered_tasks` — 列出所有 key |
| `src/service/sys_job_service.rs` | `test_calc_next_valid_time_valid` — 合法 cron 返回时间 |
| `src/service/sys_job_service.rs` | `test_calc_next_valid_time_invalid` — 非法 cron 返回 None |
| `src/service/sys_job_service.rs` | `test_job_vo_from_model` — VO 构造含 nextValidTime |

### 9.2 集成验证（手工/联调）

| 场景 | 验证步骤 |
|------|----------|
| 新增运行任务 | POST /monitor/job (status='0') → 查看调度器日志确认注册 |
| 新增暂停任务 | POST /monitor/job (status='1') → 确认调度器无注册 |
| 修改 cron | PUT /monitor/job → 确认调度器更新触发频率 |
| 状态切换 | PUT /changeStatus (0→1) → 确认停止；1→0 → 确认启动 |
| 手动执行 | PUT /run → 确认日志写入 sys_job_log |
| 删除任务 | DELETE → 确认调度器移除 + DB 软删除 |
| 启动加载 | 重启服务 → 确认 status='0' 的任务自动注册 |
| 执行失败 | invoke_target 设为未注册值 → 确认日志 status='1' |
| 并发禁止 | concurrent='1' + 长耗时任务 → 确认跳过重叠执行 |

---

## 十、技术选型说明

### 10.1 tokio-cron-scheduler vs delay_timer

| 维度 | tokio-cron-scheduler | delay_timer |
|------|---------------------|-------------|
| 生态 | tokio 原生，与 axum 同生态 | 独立实现 |
| 活跃度 | GitHub 1.2k+ star | 较小社区 |
| API | JobScheduler + Job，简洁 | TaskBuilder 较复杂 |
| 全局状态 | 支持 Arc 共享 | 依赖全局 Lazy |
| cron 解析 | 内置 | 内置 |

**决策**：选用 `tokio-cron-scheduler`，符合全局规则"调度内核独立实现"的要求，且与 stepby-axum 现有 tokio 生态无缝集成。

### 10.2 调度器实例管理

- 不使用全局 `Lazy<TokioScheduler>`（违反 AppState 注入原则）
- 通过 `Arc<JobScheduler>` 注入 AppState，Handler 通过 `State<Arc<AppState>>` 访问
- Service 持有 `Arc<JobScheduler>` 引用，用于 CRUD 时同步调度器

### 10.3 cron crate 选型

- `tokio-cron-scheduler` 内部依赖 `croner` crate 做 cron 表达式解析
- 额外在 `Cargo.toml` 显式声明 `croner = "3"` 用于：
  - `calc_next_valid_time()` 计算 nextValidTime 返回前端
  - Service 层新增/修改任务时校验 cron 合法性（在写入 DB 前拦截）
