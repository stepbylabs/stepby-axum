# 定时任务模块验收清单

## 阻断性验收（必须全部通过）

- [ ] `cargo check` 零错误
- [ ] `cargo build` 零错误
- [ ] `cargo test` 全部通过
- [ ] 无 salvo / rbatis / delay_timer 依赖残留（grep 全局确认）
- [ ] 调度内核层（`src/scheduler/`）无 `axum` / `tower` / `tower-http` 类型引用
- [ ] Service 层（`src/service/sys_job_service.rs`）无 `axum` / `tower` 类型引用
- [ ] `tokio-cron-scheduler` 为唯一调度器依赖
- [ ] 无 `once_cell` crate 依赖（用 `std::sync::LazyLock`）
- [ ] 业务代码无 `unwrap()` / `expect()` 调用（测试代码除外）

## 表结构验收

- [ ] `sys_job` 表字段与本项目前端 `SysJob` 接口 100% 对齐
- [ ] `sys_job_log` 表字段与本项目前端 `SysJobLog` 接口 100% 对齐
- [ ] `sys_job.status`：0=正常(运行) 1=暂停（与前端 el-switch 一致）
- [ ] `sys_job_log.status`：0=成功 1=失败
- [ ] `sys_job` 唯一索引 `uk_sys_job_name_group(job_name, job_group)` 存在
- [ ] `sys_job_log` 索引 `idx_sys_job_log_status` / `idx_sys_job_log_create_time` 存在
- [ ] `sys_job` AUTO_INCREMENT = 100
- [ ] `sys_job` 软删除字段 `del_flag` 默认 '0'，删除时置 '2'
- [ ] `sys_job_log` 物理删除（无 del_flag 字段）

## 接口验收（12 个接口对齐前端）

### 任务管理 `/monitor/job`（8 个接口）

- [ ] `GET /monitor/job/list` — 返回 `TableDataInfo<JobVo>`，含 `code/msg/total/rows`
- [ ] `GET /monitor/job/list` — 支持 `jobName` / `jobGroup` / `status` 查询过滤
- [ ] `GET /monitor/job/list` — 分页参数 `pageNum` / `pageSize` 正确，pageSize ≤ 100
- [ ] `GET /monitor/job/list` — 返回的 JobVo 含 `nextValidTime` 字段（根据 cron 计算）
- [ ] `GET /monitor/job/{jobId}` — 返回 `AjaxResult<JobVo>`
- [ ] `GET /monitor/job/{jobId}` — 不存在时返回 404
- [ ] `GET /monitor/job/{jobId}` — 返回的 JobVo 含 `nextValidTime` 字段
- [ ] `POST /monitor/job` — 新增后返回 `AjaxResult` success
- [ ] `POST /monitor/job` — `status='0'` 的任务自动注册到调度器
- [ ] `POST /monitor/job` — cron 表达式非法时返回 400
- [ ] `POST /monitor/job` — job_name + job_group 重复时返回 400
- [ ] `PUT /monitor/job` — 修改 cron 后调度器同步更新（remove + add）
- [ ] `PUT /monitor/job` — `status='1'` 的任务修改不触发调度器动作
- [ ] `DELETE /monitor/job/{jobIds}` — 支持逗号分隔批量删除
- [ ] `DELETE /monitor/job/{jobIds}` — 同步移除调度器中运行的任务
- [ ] `DELETE /monitor/job/{jobIds}` — 软删除（del_flag='2'），不物理删除
- [ ] `PUT /monitor/job/changeStatus` — body `{jobId, status}`
- [ ] `PUT /monitor/job/changeStatus` — 0→1 停止调度（remove_job）
- [ ] `PUT /monitor/job/changeStatus` — 1→0 启动调度（add_job）
- [ ] `PUT /monitor/job/run` — body `{jobId, jobGroup}`
- [ ] `PUT /monitor/job/run` — 立即执行一次，不影响原调度
- [ ] `PUT /monitor/job/run` — 执行后写入 `sys_job_log`
- [ ] `POST /monitor/job/export` — 导出任务列表为 Excel 文件流（对齐前端 index.vue handleExport）

### 任务日志 `/monitor/jobLog`（4 个接口）

- [ ] `GET /monitor/jobLog/list` — 返回 `TableDataInfo<SysJobLog>`
- [ ] `GET /monitor/jobLog/list` — 支持 `jobName` / `jobGroup` / `status` 过滤
- [ ] `GET /monitor/jobLog/list` — 支持 `params.beginTime` / `params.endTime` 时间范围
- [ ] `GET /monitor/jobLog/list` — 按 `create_time` 倒序
- [ ] `DELETE /monitor/jobLog/{jobLogIds}` — 支持逗号分隔批量删除
- [ ] `DELETE /monitor/jobLog/{jobLogIds}` — 物理删除
- [ ] `DELETE /monitor/jobLog/clean` — 清空全部日志
- [ ] `DELETE /monitor/jobLog/clean` — 物理删除（truncate 或 delete_all）
- [ ] `POST /monitor/jobLog/export` — 导出日志列表为 Excel 文件流（对齐前端 log.vue:236 handleExport）

## 调度内核验收

### 基本功能

- [ ] `JobScheduler::new()` 创建并启动 tokio-cron-scheduler 实例
- [ ] `JobScheduler::new()` 内部调用 `register_builtin_tasks()` 注册内置任务
- [ ] `load_from_db()` 从数据库加载 `status='0' AND del_flag='0'` 的任务
- [ ] `load_from_db()` 单个任务加载失败不阻断其他任务
- [ ] `add_job()` 将任务注册到调度器，返回 job guid
- [ ] `add_job()` cron 非法时返回错误，不注册
- [ ] `remove_job()` 从调度器精确移除指定 job_id 的任务
- [ ] `remove_job()` 调度器中不存在该任务时静默成功（幂等）
- [ ] `update_job()` 先 remove 再 add
- [ ] `run_once()` 直接 spawn 执行，不注册到调度器

### 任务执行

- [ ] 任务按 cron 表达式定时触发
- [ ] 任务执行成功写入日志 `status='0'`
- [ ] 任务执行失败写入日志 `status='1'` + `exception_info`
- [ ] 任务执行失败不影响调度器和其他任务
- [ ] 任务执行超时(>60s)被 tokio::time::timeout 杀死并写失败日志
- [ ] `concurrent='1'` 的任务禁止并发执行（重叠时跳过本次）
- [ ] `concurrent='0'` 的任务允许并发执行
- [ ] invoke_target 未注册时写失败日志（status='1', exception_info="未找到调用目标"）
- [ ] 日志写入失败仅 tracing::error! 记录，不影响任务执行

### SchedulerError 错误类型

- [ ] `SchedulerError` 枚举定义：`InvalidCron(String)` / `SchedulerInternal(String)` / `JobNotFound(i64)`
- [ ] `SchedulerError` 实现 `Display` + `std::error::Error`
- [ ] `From<SchedulerError> for ServiceError` 实现存在（Service 层 `?` 自动转换）
- [ ] `InvalidCron` → ServiceError::bad_request（400）
- [ ] `SchedulerInternal` → ServiceError::internal（500）+ tracing::error!
- [ ] `JobNotFound` → 静默成功（幂等移除）+ tracing::warn!

### misfire_policy 实现

- [ ] `misfire_policy='1'`（立即执行）— `load_from_db()` 阶段补执行一次
- [ ] `misfire_policy='2'`（执行一次）— `load_from_db()` 阶段补执行一次
- [ ] `misfire_policy='3'`（放弃执行，默认）— 不补执行，按 cron 正常调度

### invoke_target 解析策略

- [ ] invoke_target 完整字符串作为注册表 key（无 Java Bean 反射）
- [ ] `demoTask.demoNoParams` → 注册表 key 为 `demoTask.demoNoParams`
- [ ] `demoTask.demoParams('demo')` → 注册表 key 为 `demoTask.demoParams('demo')`（含参数）
- [ ] `demoTask.demoMultipleParams('demo', true, 2000L, 316.5F, 100)` → 完整字符串作为 key
- [ ] 未注册的 invoke_target → 写失败日志（status='1', exception_info="未找到调用目标: xxx"）

### 并发控制

- [ ] `executing_jobs: RwLock<HashMap<i64, bool>>` 字段存在
- [ ] `concurrent='1'` 且 `executing_jobs` 含此 id 时跳过本次执行
- [ ] 并发跳过时 tracing::debug! 记录，不写日志，不影响后续调度
- [ ] `concurrent='0'` 时不检查 executing_jobs，允许重叠执行

## 启动初始化验收

- [ ] `AppInitializer::run()` 中创建 `JobScheduler`（`JobScheduler::new(db).await?`）
- [ ] `AppInitializer::run()` 中调用 `job_scheduler.load_from_db()`
- [ ] `AppState` 含 `job_service: SysJobService` 字段
- [ ] `AppState` 含 `job_scheduler: Arc<JobScheduler>` 字段
- [ ] `AppState::new()` 保持**同步函数**签名（不改 async）
- [ ] `AppState::new()` 新增 `job_scheduler: Arc<JobScheduler>` 参数
- [ ] 调度器在 `AppInitializer::run` 中提前异步创建后以参数传入 `AppState::new`
- [ ] 内置任务函数（demoNoParams / demoParams / demoMultipleParams）启动时注册到 registry

## 安全验收

- [ ] 所有 `/monitor/job/*` 路由挂载 `auth_middleware`（需登录）
- [ ] 所有 `/monitor/jobLog/*` 路由挂载 `auth_middleware`（需登录）
- [ ] 权限中间件按 `monitor:job:*` 权限标识拦截（映射表含 12 条映射）
- [ ] `JobAddDto` 校验：job_name 非空且 ≤64 字符
- [ ] `JobAddDto` 校验：invoke_target 非空且 ≤500 字符
- [ ] `JobAddDto` 校验：cron_expression ≤255 字符
- [ ] `JobStatusDto` 校验：status 长度=1
- [ ] `JobRunDto` 校验：job_group ≤64 字符
- [ ] cron 表达式新增/修改时校验合法性（解析失败返回 400）
- [ ] 错误信息脱敏：DbErr 不暴露给前端（经 ServiceError 转通用文案）
- [ ] 调度器操作错误经 ServiceError → AppError 返回通用文案

## 架构合规验收

- [ ] Handler 层仅参数解析 + Service 调用 + 响应封装
- [ ] Handler 层无业务逻辑
- [ ] Service 层不依赖 `axum` / `tower` / `tower-http`
- [ ] Service 层持有 `SysJobRepository` + `SysJobLogRepository` + `Arc<JobScheduler>`
- [ ] 调度内核层不依赖 `axum` / `tower` / `tower-http`
- [ ] 调度内核仅依赖 `sea-orm` + `tokio` + `tokio-cron-scheduler` + `tracing`
- [ ] Repository 层仅与 SeaORM 交互
- [ ] 依赖方向：Handler → Service → Repository/Scheduler，无反向依赖
- [ ] 无 `once_cell` 使用（用 `std::sync::LazyLock`）
- [ ] 无 `unwrap()` / `expect()` 在业务代码中（测试代码除外）
- [ ] 所有 DTO 使用 `#[serde(rename_all = "camelCase")]` 对齐前端
- [ ] `src/lib.rs` 新增 `pub mod scheduler;`
- [ ] `src/service/mod.rs` 新增 `pub mod sys_job_service;` + re-export
- [ ] `src/handler/mod.rs` 新增 `pub mod sys_job_handler;` + `pub mod sys_job_log_handler;`
- [ ] `src/router/mod.rs` 新增 `pub mod sys_job_router;` + merge 到 protected

## 状态语义验证（关键，不照搬旧实现）

- [ ] `sys_job.status='0'` → 调度运行中（与前端 active-value="0" 一致）
- [ ] `sys_job.status='1'` → 调度暂停（与前端 inactive-value="1" 一致）
- [ ] 新增任务默认 `status='0'`（运行）
- [ ] changeStatus 0→1 时 remove_job
- [ ] changeStatus 1→0 时 add_job
- [ ] `sys_job_log.status='0'` → 执行成功
- [ ] `sys_job_log.status='1'` → 执行失败

## 路径前缀验证

- [ ] 任务接口路径前缀为 `/monitor/job`（不是 `/system/job`）
- [ ] 日志接口路径前缀为 `/monitor/jobLog`（不是 `/system/job_log`）
- [ ] 路径风格为 RESTful（`/{jobId}` path 参数，不是 `?jobId=` query）
- [ ] DELETE 支持逗号分隔多 ID（`/monitor/job/1,2,3`）

## nextValidTime 计算验收

- [ ] `JobVo` 结构体定义含 `next_valid_time: Option<String>` 字段
- [ ] `JobVo` 使用 `#[serde(flatten)]` 嵌入 `SysJobModel`
- [ ] `JobVo` 使用 `#[serde(rename_all = "camelCase")]` 对齐前端 `nextValidTime`
- [ ] `calc_next_valid_time()` 使用 `cron::Schedule::from_str` 解析 cron
- [ ] `calc_next_valid_time()` 合法 cron 返回 `Some("YYYY-MM-DD HH:MM:SS")`
- [ ] `calc_next_valid_time()` 非法 cron 返回 `None`
- [ ] `JobVo::from_model()` 自动调用 `calc_next_valid_time` 计算字段
- [ ] 任务列表/详情接口返回的 VO 含 `nextValidTime`（前端 detail.vue:119 展示）

## job_message 格式验收

- [ ] 任务执行成功时 `job_message` 格式为 `执行成功 (耗时 123ms)`（含耗时信息）
- [ ] 任务执行失败时 `job_message` 格式为 `任务执行失败: {错误信息} (耗时 123ms)`
- [ ] invoke_target 未注册时 `job_message` 为 `未找到调用目标: xxx (耗时 0ms)`
- [ ] 前端 detail.vue 通过 `jobMessage` 字段展示日志信息（后端无 startTime/endTime/costTime 字段，通过 job_message 补偿）

## 权限映射验收（12 条映射）

- [ ] `("GET", "/monitor/job/list")` → `monitor:job:list`
- [ ] `("GET", "/monitor/job/{jobId}")` → `monitor:job:query`
- [ ] `("POST", "/monitor/job")` → `monitor:job:add`
- [ ] `("PUT", "/monitor/job")` → `monitor:job:edit`
- [ ] `("PUT", "/monitor/job/changeStatus")` → `monitor:job:changeStatus`
- [ ] `("PUT", "/monitor/job/run")` → `monitor:job:changeStatus`
- [ ] `("DELETE", "/monitor/job/{jobIds}")` → `monitor:job:remove`
- [ ] `("POST", "/monitor/job/export")` → `monitor:job:export`
- [ ] `("GET", "/monitor/jobLog/list")` → `monitor:job:list`
- [ ] `("DELETE", "/monitor/jobLog/{jobLogIds}")` → `monitor:job:remove`
- [ ] `("DELETE", "/monitor/jobLog/clean")` → `monitor:job:remove`
- [ ] `("POST", "/monitor/jobLog/export")` → `monitor:job:export`

## 测试验收

### 单元测试（6 个）

- [ ] `src/scheduler/registry.rs` — `test_register_and_get_task`（注册后能查到）
- [ ] `src/scheduler/registry.rs` — `test_get_unregistered_task`（未注册返回 None）
- [ ] `src/scheduler/registry.rs` — `test_list_registered_tasks`（列出所有 key）
- [ ] `src/service/sys_job_service.rs` — `test_calc_next_valid_time_valid`（合法 cron 返回 Some）
- [ ] `src/service/sys_job_service.rs` — `test_calc_next_valid_time_invalid`（非法 cron 返回 None）
- [ ] `src/service/sys_job_service.rs` — `test_job_vo_from_model`（VO 构造含 nextValidTime）

### 集成验证场景（9 个）

- [ ] 新增运行任务 — POST /monitor/job (status='0') → 查看调度器日志确认注册
- [ ] 新增暂停任务 — POST /monitor/job (status='1') → 确认调度器无注册
- [ ] 修改 cron — PUT /monitor/job → 确认调度器更新触发频率
- [ ] 状态切换 — PUT /changeStatus (0→1) → 确认停止；1→0 → 确认启动
- [ ] 手动执行 — PUT /run → 确认日志写入 sys_job_log
- [ ] 删除任务 — DELETE → 确认调度器移除 + DB 软删除
- [ ] 启动加载 — 重启服务 → 确认 status='0' 的任务自动注册
- [ ] 执行失败 — invoke_target 设为未注册值 → 确认日志 status='1'
- [ ] 并发禁止 — concurrent='1' + 长耗时任务 → 确认跳过重叠执行

## 文件清单验收

### 新建文件（6 个）

- [ ] `src/scheduler/mod.rs` — 调度内核模块入口 + JobScheduler + SchedulerError + 内置任务注册
- [ ] `src/scheduler/registry.rs` — 任务函数注册表
- [ ] `src/service/sys_job_service.rs` — 任务 Service 层（CRUD + 调度器委托 + JobVo + nextValidTime）
- [ ] `src/handler/sys_job_handler.rs` — 任务 Handler 层（含 export）
- [ ] `src/handler/sys_job_log_handler.rs` — 日志 Handler 层（含 export）
- [ ] `src/router/sys_job_router.rs` — 任务 + 日志路由注册

### 修改文件（8 个）

- [ ] `Cargo.toml` — 新增 `tokio-cron-scheduler = "0.14"` + `cron = "0.15"`
- [ ] `src/lib.rs` — 新增 `pub mod scheduler;`
- [ ] `src/service/mod.rs` — 新增 `pub mod sys_job_service;` + re-export
- [ ] `src/handler/mod.rs` — 新增 `pub mod sys_job_handler;` + `pub mod sys_job_log_handler;`
- [ ] `src/router/mod.rs` — 新增 `pub mod sys_job_router;` + merge 到 protected
- [ ] `src/state.rs` — 新增 `job_service` + `job_scheduler` 字段，`new()` 新增参数（保持同步）
- [ ] `src/initialize/mod.rs` — 新增调度器创建 + load_from_db 调用
- [ ] `src/repository/sys_job.rs` — 新增 `find_by_status` / `find_active_by_id` / `find_page_filtered`
- [ ] `src/repository/sys_job_log.rs` — 新增 `find_page_filtered` / `delete_by_ids`
- [ ] `src/middleware/permission.rs` — 权限映射表新增 12 条 `/monitor/*` 条目
- [ ] `src/common/error.rs` — 新增 `From<SchedulerError> for ServiceError` 实现

### 不修改文件（3 个）

- [ ] `src/entity/sys_job.rs` — 字段已对齐前端，无需修改
- [ ] `src/entity/sys_job_log.rs` — 字段已对齐前端，无需修改
- [ ] `migration/src/m20250711_000001_init.rs` — 表结构和索引已就绪，无需修改
