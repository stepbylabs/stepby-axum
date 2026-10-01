# 定时任务模块实现任务分解

> 基于 `job-spec.md` 架构设计，按依赖顺序分解为 9 个任务。

## 前置约束

- 全局规则：纯 Axum + SeaORM，禁止 salvo / rbatis / delay_timer
- 调度器：`tokio-cron-scheduler = "0.14"` + `cron = "0.15"`（新增依赖）
- 状态注入：`Arc<JobScheduler>` 通过 AppState 注入，不用全局 Lazy
- 路径前缀：`/monitor/job` + `/monitor/jobLog`（对齐前端）

---

## Task 1：添加依赖 + 模块声明

**文件：**
- 修改：`Cargo.toml`
- 修改：`src/lib.rs`
- 修改：`src/service/mod.rs`
- 修改：`src/handler/mod.rs`
- 修改：`src/router/mod.rs`

**步骤：**

- [ ] 1.1 `Cargo.toml` `[dependencies]` 新增：
```toml
tokio-cron-scheduler = "0.14"
cron = "0.15"
```

- [ ] 1.2 `src/lib.rs` 新增模块声明：
```rust
// ========== 定时任务调度内核 ==========
pub mod scheduler;
```

- [ ] 1.3 `src/service/mod.rs` 新增：
```rust
pub mod sys_job_service;
pub use sys_job_service::SysJobService;
```

- [ ] 1.4 `src/handler/mod.rs` 新增：
```rust
pub mod sys_job_handler;
pub mod sys_job_log_handler;
```

- [ ] 1.5 `src/router/mod.rs` 新增：
```rust
pub mod sys_job_router;
```

- [ ] 1.6 运行 `cargo check` 确认依赖下载成功（模块文件暂不存在会有 warning，忽略）

---

## Task 2：调度内核 - 注册表

**文件：**
- 创建：`src/scheduler/registry.rs`

**步骤：**

- [ ] 2.1 创建 `src/scheduler/registry.rs`，实现：
  - `TaskFn` 类型别名（`Arc<dyn Fn() -> BoxFuture<'static, Result<String, String>> + Send + Sync>`）
  - `TASK_REGISTRY: LazyLock<RwLock<HashMap<String, TaskFn>>>` 全局注册表
  - `register_task(invoke_target, func)` 注册函数
  - `get_task(invoke_target) -> Option<TaskFn>` 查询函数
  - `list_registered_tasks() -> Vec<String>` 列出所有 key
  - 3 个单元测试：`test_register_and_get_task` / `test_get_unregistered_task` / `test_list_registered_tasks`

- [ ] 2.2 运行 `cargo check` 确认编译

---

## Task 3：调度内核 - JobScheduler + SchedulerError

**文件：**
- 创建：`src/scheduler/mod.rs`

**步骤：**

- [ ] 3.1 定义 `SchedulerError` 枚举：
  - `InvalidCron(String)` — cron 解析失败
  - `SchedulerInternal(String)` — 调度器内部错误
  - `JobNotFound(i64)` — 任务在调度器中不存在
  - 实现 `Display` + `std::error::Error`

- [ ] 3.2 实现 `JobScheduler` 结构体：
  - 字段：`scheduler: Arc<TokioScheduler>` + `db: DatabaseConnection` + `job_log_repo: SysJobLogRepository` + `running_jobs: RwLock<HashMap<i64, uuid::Uuid>>` + `executing_jobs: RwLock<HashMap<i64, bool>>`
  - `new(db)` — 创建 TokioScheduler 并 start() + 调用 `register_builtin_tasks()`
  - `load_from_db()` — 查询 status='0' AND del_flag='0' 任务，逐个 add_job，misfire_policy='1'/'2' 的补执行一次
  - `add_job(job)` — 解析 cron → 创建 Job（闭包内调用 `execute_task`）→ 注册到调度器 → 记录 uuid 到 running_jobs
  - `remove_job(job_id)` — 从 running_jobs 取 uuid → 从调度器 remove → 从 running_jobs 移除（幂等：不存在静默成功）
  - `update_job(job)` — remove_job + add_job
  - `run_once(job)` — 直接 spawn execute_task（不注册调度）
  - `execute_task(job)` — 核心执行逻辑：并发检查 → 标记 → 查表 → 超时执行 → 写日志 → 清除标记

- [ ] 3.3 实现 `register_builtin_tasks()` 注册内置任务：
  - `demoTask.demoNoParams` → 返回 Ok("demoNoParams 执行成功")
  - `demoTask.demoParams('demo')` → 返回 Ok("demoParams 执行成功，参数: stepby")
  - `demoTask.demoMultipleParams('demo', true, 2000L, 316.5F, 100)` → 返回 Ok("demoMultipleParams 执行成功")

- [ ] 3.4 在 `src/common/error.rs` 新增 `From<SchedulerError> for ServiceError` 实现

- [ ] 3.5 运行 `cargo check` 确认编译

---

## Task 4：Repository 层扩展

**文件：**
- 修改：`src/repository/sys_job.rs`
- 修改：`src/repository/sys_job_log.rs`

**步骤：**

- [ ] 4.1 `src/repository/sys_job.rs` 新增方法：
  - `find_by_status(status: &str)` — 查询指定状态的未删除任务
  - `find_active_by_id(job_id: i64)` — 按 ID 查询未删除任务（del_flag='0'）
  - `find_page_filtered(offset, limit, job_name, job_group, status)` — 多条件分页查询（job_name 模糊匹配，job_group/status 精确匹配，按 job_id 升序）

- [ ] 4.2 `src/repository/sys_job_log.rs` 新增方法：
  - `find_page_filtered(offset, limit, job_name, job_group, status, begin_time, end_time)` — 多条件分页（job_name 模糊，job_group/status 精确，时间范围，按 create_time 倒序）
  - `delete_by_ids(ids: Vec<i64>)` — 批量物理删除

- [ ] 4.3 运行 `cargo check` 确认编译

---

## Task 5：Service 层 - SysJobService

**文件：**
- 创建：`src/service/sys_job_service.rs`

**步骤：**

- [ ] 5.1 定义全部 DTO（JobQueryDto / JobAddDto / JobEditDto / JobStatusDto / JobRunDto / JobLogQueryDto / TimeRange）+ `JobVo`（含 nextValidTime 计算字段，`#[serde(flatten)]` 嵌入 SysJobModel）

- [ ] 5.2 实现 `calc_next_valid_time(cron_str) -> Option<String>` 函数：
  - 使用 `cron::Schedule::from_str` 解析
  - 成功时返回下次执行时间（格式 `%Y-%m-%d %H:%M:%S`）
  - 失败时返回 None
  - 实现 `JobVo::from_model(job)` 自动计算 nextValidTime

- [ ] 5.3 实现 `SysJobService`：
  - 持有 `job_repo: SysJobRepository` + `job_log_repo: SysJobLogRepository` + `scheduler: Arc<JobScheduler>`
  - `new(db, scheduler)` 构造函数
  - `get_job_page(query)` — 委托 job_repo.find_page_filtered → 转为 `Vec<JobVo>`
  - `get_job_by_id(job_id)` — 委托 job_repo.find_active_by_id → 转为 `JobVo`
  - `add_job(dto, operator)` — dto.validate() → cron 合法性校验（calc_next_valid_time 返回 None 则报错）→ job_name+job_group 查重 → INSERT → 若 status='0' 调用 scheduler.add_job
  - `edit_job(dto, operator)` — dto.validate() → 查询存在 → cron 合法性校验 → UPDATE → 若 status='0' 调用 scheduler.update_job（若 status='1' 且原 status='0' 调用 scheduler.remove_job）
  - `delete_jobs(job_ids)` — 遍历：查询任务存在 → 若 status='0' 先 scheduler.remove_job → job_repo.soft_delete
  - `change_status(dto)` — dto.validate() → 查询任务 → UPDATE status → 0→1: remove_job / 1→0: add_job
  - `run_job_once(dto)` — dto.validate() → 查询任务 → 验证 job_group 一致 → scheduler.run_once
  - `get_job_log_page(query)` — 委托 job_log_repo.find_page_filtered
  - `delete_job_logs(ids)` — 委托 job_log_repo.delete_by_ids
  - `clean_job_logs()` — 委托 job_log_repo.clean_all
  - `export_jobs(query)` — 查询全量数据（不分页）→ 返回 Vec<JobVo> 供 Handler 导出
  - `export_job_logs(query)` — 查询全量日志数据（不分页）→ 返回 Vec<SysJobLogModel> 供 Handler 导出

- [ ] 5.4 单元测试：
  - `test_calc_next_valid_time_valid` — 合法 cron（如 `0 * * * * *`）返回 Some
  - `test_calc_next_valid_time_invalid` — 非法 cron 返回 None
  - `test_job_vo_from_model` — VO 构造含 nextValidTime

- [ ] 5.5 运行 `cargo check` 确认编译

---

## Task 6：Handler 层

**文件：**
- 创建：`src/handler/sys_job_handler.rs`
- 创建：`src/handler/sys_job_log_handler.rs`

**步骤：**

- [ ] 6.1 创建 `src/handler/sys_job_handler.rs`：
  - `list` — GET /monitor/job/list，Query<JobQueryDto> → TableDataInfo<JobVo>
  - `get_info_by_id` — GET /monitor/job/{jobId}，Path<i64> → AjaxResult<JobVo>
  - `add` — POST /monitor/job，Json<JobAddDto> → AjaxResult（dto.validate()）
  - `edit` — PUT /monitor/job，Json<JobEditDto> → AjaxResult（dto.validate()）
  - `remove` — DELETE /monitor/job/{jobIds}，Path<String> 解析逗号分隔 → AjaxResult
  - `change_status` — PUT /monitor/job/changeStatus，Json<JobStatusDto> → AjaxResult（dto.validate()）
  - `run` — PUT /monitor/job/run，Json<JobRunDto> → AjaxResult（dto.validate()）
  - `export` — POST /monitor/job/export，Json<JobQueryDto> → 导出 Excel 文件流（使用 serde_json 转 CSV 或返回 JSON 让前端处理）
  - 所有 Handler 使用 `State<Arc<AppState>>` + `Operator` 提取器

- [ ] 6.2 创建 `src/handler/sys_job_log_handler.rs`：
  - `list` — GET /monitor/jobLog/list，Query<JobLogQueryDto> → TableDataInfo<SysJobLogModel>
  - `remove` — DELETE /monitor/jobLog/{jobLogIds}，Path<String> 解析逗号分隔 → AjaxResult
  - `clean` — DELETE /monitor/jobLog/clean → AjaxResult
  - `export` — POST /monitor/jobLog/export，Json<JobLogQueryDto> → 导出 Excel 文件流（对齐前端 log.vue:236 `proxy.download("monitor/jobLog/export", ...)`）

- [ ] 6.3 运行 `cargo check` 确认编译

---

## Task 7：Router 层 + 权限映射

**文件：**
- 创建：`src/router/sys_job_router.rs`
- 修改：`src/router/mod.rs`（merge job_routes 到 protected）
- 修改：`src/middleware/permission.rs`（权限映射表新增 /monitor/* 条目）

**步骤：**

- [ ] 7.1 创建 `src/router/sys_job_router.rs`：
```rust
pub fn job_routes() -> Router<Arc<AppState>> {
    Router::new()
        // 任务管理
        .route("/monitor/job/list", get(sys_job_handler::list))
        .route("/monitor/job/{jobId}", get(sys_job_handler::get_info_by_id))
        .route("/monitor/job", post(sys_job_handler::add))
        .route("/monitor/job", put(sys_job_handler::edit))
        .route("/monitor/job/{jobIds}", delete(sys_job_handler::remove))
        .route("/monitor/job/changeStatus", put(sys_job_handler::change_status))
        .route("/monitor/job/run", put(sys_job_handler::run))
        .route("/monitor/job/export", post(sys_job_handler::export))
        // 任务日志
        .route("/monitor/jobLog/list", get(sys_job_log_handler::list))
        .route("/monitor/jobLog/{jobLogIds}", delete(sys_job_log_handler::remove))
        .route("/monitor/jobLog/clean", delete(sys_job_log_handler::clean))
        .route("/monitor/jobLog/export", post(sys_job_log_handler::export))
}
```

- [ ] 7.2 `src/router/mod.rs` 的 `build_app` 中 protected 分组新增：
```rust
.merge(sys_job_router::job_routes())
```

- [ ] 7.3 `src/middleware/permission.rs` 的 `get_required_perm` 函数新增：
```rust
// ===== 定时任务管理 =====
("GET", "/monitor/job/list") => Some("monitor:job:list"),
("GET", "/monitor/job/{jobId}") => Some("monitor:job:query"),
("POST", "/monitor/job") => Some("monitor:job:add"),
("PUT", "/monitor/job") => Some("monitor:job:edit"),
("PUT", "/monitor/job/changeStatus") => Some("monitor:job:changeStatus"),
("PUT", "/monitor/job/run") => Some("monitor:job:changeStatus"),
("DELETE", "/monitor/job/{jobIds}") => Some("monitor:job:remove"),
("POST", "/monitor/job/export") => Some("monitor:job:export"),
("GET", "/monitor/jobLog/list") => Some("monitor:job:list"),
("DELETE", "/monitor/jobLog/{jobLogIds}") => Some("monitor:job:remove"),
("DELETE", "/monitor/jobLog/clean") => Some("monitor:job:remove"),
("POST", "/monitor/jobLog/export") => Some("monitor:job:export"),
```

- [ ] 7.4 运行 `cargo check` 确认编译

---

## Task 8：State 集成 + 启动初始化

**文件：**
- 修改：`src/state.rs`
- 修改：`src/initialize/mod.rs`

**步骤：**

- [ ] 8.1 `src/state.rs` 的 `AppState` 新增字段：
```rust
pub struct AppState {
    // ...已有...
    pub job_service: SysJobService,
    pub job_scheduler: Arc<JobScheduler>,
}
```

- [ ] 8.2 `src/state.rs` 的 `AppState::new` 新增 `job_scheduler: Arc<JobScheduler>` 参数（保持同步函数）：
```rust
pub fn new(
    db: DatabaseConnection,
    redis: ConnectionManager,
    config: Arc<Settings>,
    job_scheduler: Arc<JobScheduler>,
) -> Self {
    Self {
        job_service: SysJobService::new(db.clone(), job_scheduler.clone()),
        job_scheduler,
        user_service: SysUserService::new(db.clone()),
        role_service: SysRoleService::new(db.clone()),
        menu_service: SysMenuService::new(db.clone()),
        auth_service: AuthService::new(db.clone()),
        db, redis, config,
    }
}
```

- [ ] 8.3 `src/initialize/mod.rs` 的 `run` 方法新增调度器创建和加载：
```rust
// 5. 创建调度器并加载任务
let job_scheduler = Arc::new(JobScheduler::new(db.clone()).await?);
job_scheduler.load_from_db().await?;

// 6. 构建 AppState（传入 scheduler）
let state = Arc::new(AppState::new(db, redis, settings, job_scheduler));
```

- [ ] 8.4 运行 `cargo check` 确认编译

---

## Task 9：编译验证 + 自查

**步骤：**

- [ ] 9.1 运行 `cargo check`，修复所有错误
- [ ] 9.2 运行 `cargo build`，确认零错误
- [ ] 9.3 运行 `cargo test`，确认全部通过（含新增的 6 个单元测试）
- [ ] 9.4 全局搜索 `salvo|rbatis|delay_timer|once_cell` 确认无残留
- [ ] 9.5 全局搜索 `unwrap()|expect(` 确认业务代码无使用（测试除外）
- [ ] 9.6 确认调度内核 `src/scheduler/` 无 `axum|tower` 引用
- [ ] 9.7 确认 Service 层 `src/service/sys_job_service.rs` 无 `axum|tower` 引用
- [ ] 9.8 按 `job-checklist.md` 逐项验收
