// stepby-axum/src/service/op_recording_replay.rs
//! 操作回放执行器（录制链路的执行半边）。
//!
//! ## 回放怎么"再执行一次"
//!
//! 三条候选路径，选第三条：
//!
//! | 方案 | 做法 | 为什么不选 |
//! |---|---|---|
//! | ① 进程内 `Router::oneshot` | 把构造好的请求直接投给路由 | 绕过网络、中间件顺序、限流与审计——回放**通过**了不代表线上通过，恰好毁掉回放最重要的价值（端到端验证） |
//! | ② 服务层直调 | 按路径映射到 service 方法 | 路径→方法映射表本身就要维护，且 DAO/校验/权限全跳过；录下来的"用户操作"被解释成"另一段代码" |
//! | ③ 回环 HTTP（本实现） | 以配置里的监听端口为基址重发请求 | 走的是**和生产完全同一条链路**（中间件、权限、限流、审计全在），因此"回放绿"是有意义的证据 |
//!
//! 方案 ③ 的两个前提都写死在代码里：
//! - **目标地址不由录制内容决定**：基址取 `config.server.port`，步骤只允许提供 `path`。
//!   历史脏数据里若出现绝对 URL，回放侧再拒一次（写入侧也拒，见 `validate_step_path`）。
//! - **身份用执行者自己的令牌**：录制里不存 `Authorization`（采集侧已排除），回放时把
//!   触发者的令牌逐跳注入 ⇒ 回放能做什么，取决于**触发者**的权限，不会因为"别人录的"
//!   而获得额外能力（无提权面）。
//!
//! ## 为什么要后台跑
//!
//! 一趟 30 步 × 每步最多 15s 最坏 7 分钟，超过任何合理的请求超时。因此回放**先建任务行
//! 再异步执行**，进度经既有 `sys_task` + WS `taskProgress` 推给前端浮层；调用方立刻拿到
//! `runId` / `taskId`，随后按需轮询 `/tool/recording/run/{runId}` 看逐步骤结论。
//!
//! ## 结论为什么有四档
//!
//! `success` / `failed` / `partial` / `running`。`partial` 是必要的：`stopOnError=false`
//! 时"跑完 5 步错 2 步"与"第 3 步就停了"是两种不同的结论，压成一个 `failed` 会让使用者
//! 以为后半段没执行（那正是他下一步要判断的事）。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::NaiveDateTime;
use sea_orm::Set;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::common::error::ServiceError;
use crate::common::i18n::pick;
use crate::entity::sys_op_recording_run::{ActiveModel as RunActiveModel, Model as RunModel};
use crate::entity::sys_op_recording_step::Model as StepModel;
use crate::observability::metrics::OutboundGuard;
use crate::repository::op_recording::OpRecordingRepository;
use crate::service::op_recording::{
    OpRecordingService, extract_json_path, parse_extract_rules, redact_json_like, substitute_vars,
    validate_step_path,
};
use crate::service::sys_task_service::TaskCreateDto;
use crate::state::AppState;

/// 单步出站超时上限（秒）
pub const MAX_STEP_TIMEOUT_SECS: u64 = 30;
/// 单步出站超时默认值（秒）
pub const DEFAULT_STEP_TIMEOUT_SECS: u64 = 15;
/// 一次回放的整体预算（秒）：超过即判超时并落 `failed`，不无限占用后台槽位。
///
/// 取 600 的判据：200 步 × 3s 平均 ≈ 10 分钟，正好是"一整段人工流程"的量级上限；
/// 再长就应该拆成多个录制，而不是让一个后台任务跑一小时。
pub const REPLAY_BUDGET_SECS: u64 = 600;
/// 响应体留存上限（字节）：只留开头用于归因，不把大响应搬进库。
pub const RESPONSE_EXCERPT_BYTES: usize = 2048;
/// 逐步骤结局：单步在回放里的最终定性。
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StepOutcome {
    /// 步骤序号（与录制一致）
    pub seq: i32,
    pub method: String,
    pub path: String,
    /// 实际状态码（未发出请求时为 None）
    pub status: Option<i32>,
    /// 是否通过（含"按策略跳过"以外的成功）
    pub ok: bool,
    /// 是否被跳过（前序失败后的批量跳过）
    pub skipped: bool,
    /// 耗时毫秒
    pub duration_ms: u64,
    /// 失败原因（缺变量 / 状态码不符 / 网络错误）
    pub error: Option<String>,
    /// 响应体开头（已脱敏、已截断）
    pub response_excerpt: Option<String>,
}

/// 回放选项
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReplayOptions {
    /// 遇错即停（默认 true）。false = 跑完全部步骤并汇总成 partial
    #[serde(default = "default_stop_on_error")]
    pub stop_on_error: bool,
    /// 变量表（`{{name}}` 的取值来源；抽取规则抽到的值会覆盖同名的）
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// 单步超时（秒），夹取 1..=30
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// 只回放前 N 步（分片调试用；None = 全部）
    #[serde(default)]
    pub max_steps: Option<i32>,
    /// 预检模式：只解析 + 校验 + 渲染请求，不发任何网络请求
    #[serde(default)]
    pub dry_run: bool,
}

fn default_stop_on_error() -> bool {
    true
}

impl Default for ReplayOptions {
    fn default() -> Self {
        Self {
            stop_on_error: true,
            vars: BTreeMap::new(),
            timeout_secs: None,
            max_steps: None,
            dry_run: false,
        }
    }
}

impl ReplayOptions {
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(
            self.timeout_secs
                .unwrap_or(DEFAULT_STEP_TIMEOUT_SECS)
                .clamp(1, MAX_STEP_TIMEOUT_SECS),
        )
    }
}

/// 启动回放的返回
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReplayStartVo {
    pub run_id: i64,
    pub task_id: i64,
    pub total: i32,
    /// 预检模式下返回的渲染结果（真跑时为 None）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Vec<StepPreview>>,
}

/// 预检渲染的一步
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StepPreview {
    pub seq: i32,
    pub method: String,
    pub url: String,
    pub content_type: Option<String>,
    pub body: Option<String>,
    pub expect_status: Option<i32>,
    /// 该步的问题（缺变量等）；有值即代表真跑时这步必失败
    pub problem: Option<String>,
}

/// 回放详情（运行结论 + 逐步骤）
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RunDetailVo {
    #[serde(flatten)]
    pub run: RunModel,
    pub steps: Vec<StepOutcome>,
}

/// 回放执行器
pub struct OpRecordingReplayService {
    repo: OpRecordingRepository,
    recorder: OpRecordingService,
}

impl OpRecordingReplayService {
    pub fn new(db: sea_orm::DatabaseConnection) -> Self {
        Self {
            repo: OpRecordingRepository::new(db.clone()),
            recorder: OpRecordingService::new(db),
        }
    }

    /// 启动一次回放。
    ///
    /// 返回值里的 `run_id` / `task_id` 在**执行开始前**就已入库，调用方不会拿到
    /// "任务不存在但工作已经开始"的悬空句柄。
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        &self,
        state: Arc<AppState>,
        recording_id: i64,
        tenant_id: i64,
        tenant_scope: Option<i64>,
        operator: &str,
        operator_id: Option<i64>,
        token: &str,
        base_url: &str,
        options: ReplayOptions,
    ) -> Result<ReplayStartVo, ServiceError> {
        let detail = self.recorder.detail(recording_id, tenant_scope).await?;
        if detail.steps.is_empty() {
            return Err(ServiceError::bad_request(pick(
                "该录制还没有任何步骤，无法回放",
                "This recording has no steps to replay",
            )));
        }
        let mut steps = detail.steps;
        if let Some(limit) = options.max_steps {
            if limit <= 0 {
                return Err(ServiceError::bad_request(pick(
                    "maxSteps 必须大于 0",
                    "maxSteps must be positive",
                )));
            }
            steps.truncate(limit as usize);
        }

        // 预检：渲染全部请求但不发。校验与真跑共用同一段代码（不是另一套"估算"）。
        if options.dry_run {
            let preview = self.preview_steps(&steps, base_url, &options)?;
            return Ok(ReplayStartVo {
                run_id: 0,
                task_id: 0,
                total: steps.len() as i32,
                preview: Some(preview),
            });
        }

        let total = steps.len() as i32;
        let now = crate::common::datetime::now_naive();

        // ① 任务进度行（前端浮层据此显示）
        let task = self
            .recorder
            .task_service()
            .create_task(
                TaskCreateDto {
                    task_type: "replay".to_string(),
                    task_name: truncate(&format!("回放：{}", detail.recording.name), 200),
                    total: total as i64,
                    operator_id,
                },
                operator,
                tenant_id,
                &state,
            )
            .await?;

        // ② 运行记录（先把 running 落库，再 spawn，避免"跑完了却没有上行"）
        let run = self
            .repo
            .insert_run(RunActiveModel {
                tenant_id: Set(tenant_id),
                recording_id: Set(recording_id),
                task_id: Set(Some(task.task_id)),
                status: Set("running".to_string()),
                total: Set(total),
                succeeded: Set(0),
                failed: Set(0),
                skipped: Set(0),
                detail_json: Set(Some("[]".to_string())),
                operator: Set(Some(operator.to_string())),
                started_at: Set(Some(now)),
                finished_at: Set(None),
                ..Default::default()
            })
            .await?;

        // ③ 异步执行
        let repo = self.repo.clone();
        let token = token.to_string();
        let base = base_url.trim_end_matches('/').to_string();
        let opts = options.clone();
        let state_bg = state.clone();
        let run_id = run.run_id;
        let task_id = task.task_id;
        crate::common::background::spawn_tracked(
            "op_recording_replay",
            Duration::from_secs(REPLAY_BUDGET_SECS),
            Some(crate::observability::metrics::MetricsRegistry::global()),
            async move {
                let outcome = execute_steps(
                    repo.clone(),
                    state_bg.clone(),
                    run_id,
                    task_id,
                    steps,
                    base,
                    token,
                    opts,
                )
                .await;
                if let Err(e) = outcome {
                    // 兜底：任何未预期错误都要落终态，否则任务行会永久停在 running
                    tracing::warn!(run_id, error = %e, "回放执行异常中止");
                    let _ = settle_run(&repo, run_id, "failed", 0, total, 0, None, vec![]).await;
                    let _ = state_bg
                        .task_service
                        .fail_task(task_id, format!("回放异常中止：{e}"), &state_bg)
                        .await;
                }
            },
        );

        Ok(ReplayStartVo {
            run_id: run.run_id,
            task_id: task.task_id,
            total,
            preview: None,
        })
    }

    /// 预检：渲染每一步的最终请求（含变量替换）并给出问题清单。
    pub fn preview_steps(
        &self,
        steps: &[StepModel],
        base_url: &str,
        options: &ReplayOptions,
    ) -> Result<Vec<StepPreview>, ServiceError> {
        preview_steps(steps, base_url, options)
    }

    pub async fn run_detail(
        &self,
        run_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<RunDetailVo, ServiceError> {
        let run = self
            .repo
            .find_run(run_id)
            .await?
            .filter(|r| tenant_scope.is_none_or(|t| r.tenant_id == t))
            .ok_or_else(|| ServiceError::not_found(pick("回放记录不存在", "Run not found")))?;
        let steps: Vec<StepOutcome> = run
            .detail_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        Ok(RunDetailVo { run, steps })
    }

    pub async fn runs_of(
        &self,
        recording_id: i64,
        tenant_scope: Option<i64>,
        limit: u64,
    ) -> Result<Vec<RunModel>, ServiceError> {
        Ok(self
            .repo
            .runs_of(recording_id, tenant_scope, limit.clamp(1, 100))
            .await?)
    }
}

/// 预检：渲染每一步的最终请求（含变量替换）并给出问题清单。
///
/// 与真跑共用 `render_url` / `substitute_vars`，因此"预检没问题但真跑失败"只可能
/// 来自网络或对端行为，不可能来自两套渲染逻辑的漂移。
///
/// 这两个辅助函数是模块私有：这里刻意用代码 Span 而不是文档链接——公有文档链到私有项
/// 会让 `cargo doc -D warnings` 直接失败（b145 同族，见台账 N-147-D）。
pub fn preview_steps(
    steps: &[StepModel],
    base_url: &str,
    options: &ReplayOptions,
) -> Result<Vec<StepPreview>, ServiceError> {
    let base = base_url.trim_end_matches('/');
    // 预检**不推进**变量：抽取规则只在真跑时生效（第 N+1 步引用的 {{var}} 在预检里必然
    // 还没有值，报成"缺变量"才是真话；把抽取规则的点路径当值填进去会把必失败报成正常）
    let vars = options.vars.clone();
    let mut out = Vec::with_capacity(steps.len());
    for st in steps {
        let mut problem: Option<String> = None;
        if let Err(e) = validate_step_path(&st.path) {
            problem = Some(e.to_string());
        }
        let url = match render_url(base, st, &vars) {
            Ok(u) => u,
            Err(e) => {
                problem.get_or_insert(e);
                format!("{base}{}", st.path)
            }
        };
        let body = match st.body.as_deref() {
            Some(b) => match substitute_vars(b, &vars) {
                Ok(rendered) => Some(rendered),
                Err(e) => {
                    problem.get_or_insert(e);
                    Some(b.to_string())
                }
            },
            None => None,
        };
        // **预检不推进变量**：抽取规则的值来自真实响应，预检没有响应。
        // 早先这里把"点路径"当成变量值塞进 vars，于是第二步的 `{{deptId}}` 被替换成
        // 字面量 `data.deptId` 且 problem 为空——预检把"必失败"报成了"正常"。
        out.push(StepPreview {
            seq: st.seq,
            method: st.method.clone(),
            url,
            content_type: st.content_type.clone(),
            body,
            expect_status: st.expect_status,
            problem,
        });
    }
    Ok(out)
}

/// 逐步骤执行（在后台任务里跑）。
#[allow(clippy::too_many_arguments)]
async fn execute_steps(
    repo: OpRecordingRepository,
    state: Arc<AppState>,
    run_id: i64,
    task_id: i64,
    steps: Vec<StepModel>,
    base: String,
    token: String,
    options: ReplayOptions,
) -> Result<(), String> {
    let client = crate::common::outbound_client::build(
        "recording_replay",
        Duration::from_secs(5),
        options.timeout() + Duration::from_secs(2),
    )
    .map_err(|e| format!("回放出站客户端构造失败：{e}"))?;

    let total = steps.len() as i32;
    let mut vars = options.vars.clone();
    let mut outcomes: Vec<StepOutcome> = Vec::with_capacity(steps.len());
    let mut failed = 0i32;
    let mut succeeded = 0i32;
    let mut skipped = 0i32;
    let mut aborted = false;

    for (idx, st) in steps.iter().enumerate() {
        if aborted {
            skipped += 1;
            outcomes.push(StepOutcome {
                seq: st.seq,
                method: st.method.clone(),
                path: st.path.clone(),
                status: None,
                ok: false,
                skipped: true,
                duration_ms: 0,
                error: Some(
                    pick(
                        "前序步骤失败，已按 stopOnError 跳过",
                        "Skipped because an earlier step failed (stopOnError)",
                    )
                    .to_string(),
                ),
                response_excerpt: None,
            });
            continue;
        }

        let started = Instant::now();
        // 每一步都出网一次 ⇒ 一个 guard 记一条 `stepby_outbound_requests_total{component="recording_replay"}`
        // 与一次耗时。不放 `run_one` 里是因为"一次回放 N 次出站"才是观测单位：
        // 放在这里既能逐步骤看 latency，也不会把"构造失败"误记成一次成功出站。
        let mut outbound = OutboundGuard::start("recording_replay");
        let outcome = match run_one(&client, &base, &token, st, &mut vars, options.timeout()).await
        {
            Ok((status, excerpt)) => {
                outbound.succeeded();
                let expect_ok = match st.expect_status {
                    Some(exp) => status == exp,
                    None => (200..400).contains(&status),
                };
                StepOutcome {
                    seq: st.seq,
                    method: st.method.clone(),
                    path: st.path.clone(),
                    status: Some(status),
                    ok: expect_ok,
                    skipped: false,
                    duration_ms: started.elapsed().as_millis() as u64,
                    error: if expect_ok {
                        None
                    } else {
                        Some(match st.expect_status {
                            Some(exp) => format!(
                                "{}（期望 {exp}，实际 {status}）",
                                pick("状态码不符", "Unexpected status code")
                            ),
                            None => format!(
                                "{}（实际 {status}）",
                                pick("期望 2xx/3xx", "Expected 2xx/3xx")
                            ),
                        })
                    },
                    response_excerpt: excerpt,
                }
            }
            Err(e) => StepOutcome {
                seq: st.seq,
                method: st.method.clone(),
                path: st.path.clone(),
                status: None,
                ok: false,
                skipped: false,
                duration_ms: started.elapsed().as_millis() as u64,
                error: Some(e),
                response_excerpt: None,
            },
        };

        if outcome.ok {
            succeeded += 1;
        } else {
            failed += 1;
            if options.stop_on_error {
                aborted = true;
            }
        }
        outcomes.push(outcome);

        // 进度：按"已处理步数"推进（跳过与失败都算已处理——它们是事实，不是待办）
        let _ = state
            .task_service
            .update_progress(task_id, (idx as i32 + 1) as i64, Some(total as i64), &state)
            .await;

        // 中途把结论写进 detail_json：任务被超时中断时，已跑完的步骤仍可归因
        let _ = repo
            .update_run(RunActiveModel {
                run_id: Set(run_id),
                succeeded: Set(succeeded),
                failed: Set(failed),
                skipped: Set(skipped),
                detail_json: Set(Some(
                    serde_json::to_string(&outcomes).unwrap_or_else(|_| "[]".to_string()),
                )),
                ..Default::default()
            })
            .await;
    }

    let final_status = if failed == 0 {
        "success"
    } else if succeeded == 0 {
        "failed"
    } else {
        "partial"
    };
    let now = crate::common::datetime::now_naive();
    settle_run(
        &repo,
        run_id,
        final_status,
        succeeded,
        failed,
        skipped,
        Some(now),
        outcomes.clone(),
    )
    .await?;

    if final_status == "success" {
        let _ = state
            .task_service
            .complete_task(
                task_id,
                Some(format!(
                    "{} {succeeded}/{total}",
                    pick("回放完成", "Replay finished")
                )),
                &state,
            )
            .await;
    } else {
        let msg = format!(
            "{}：{} {succeeded} / {} {failed} / {} {skipped}",
            pick("回放未全部通过", "Replay did not fully pass"),
            pick("成功", "ok"),
            pick("失败", "failed"),
            pick("跳过", "skipped")
        );
        let _ = state.task_service.fail_task(task_id, msg, &state).await;
    }
    Ok(())
}

/// 落运行终态（幂等：重复调用只改终态字段）。
#[allow(clippy::too_many_arguments)]
async fn settle_run(
    repo: &OpRecordingRepository,
    run_id: i64,
    status: &str,
    succeeded: i32,
    failed: i32,
    skipped: i32,
    finished_at: Option<NaiveDateTime>,
    outcomes: Vec<StepOutcome>,
) -> Result<(), String> {
    repo.update_run(RunActiveModel {
        run_id: Set(run_id),
        status: Set(status.to_string()),
        succeeded: Set(succeeded),
        failed: Set(failed),
        skipped: Set(skipped),
        finished_at: Set(finished_at),
        detail_json: Set(Some(
            serde_json::to_string(&outcomes).unwrap_or_else(|_| "[]".to_string()),
        )),
        ..Default::default()
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// 执行单步：渲染 → 发送 → 抽取 → 返回 (状态码, 响应摘要)。
async fn run_one(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    st: &StepModel,
    vars: &mut BTreeMap<String, String>,
    timeout: Duration,
) -> Result<(i32, Option<String>), String> {
    // 出网前**再校验一次**路径形状：历史数据/直接改库都可能绕过写入侧
    validate_step_path(&st.path).map_err(|e| e.to_string())?;
    let url = render_url(base, st, vars)?;
    let method = reqwest::Method::from_bytes(st.method.as_bytes())
        .map_err(|_| format!("不支持的 HTTP 方法：{}", st.method))?;

    let mut req = client.request(method, &url).timeout(timeout);
    // 身份：执行者自己的令牌（录制里从不存 Authorization）
    req = req.bearer_auth(token);
    if let Some(ct) = st.content_type.as_deref().filter(|c| !c.is_empty()) {
        req = req.header(reqwest::header::CONTENT_TYPE, ct);
    }
    // 录制时存下的可回放头（坏 JSON 直接当没有：它只是元数据，不该让回放失败）
    let stored_headers = st
        .headers_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<BTreeMap<String, String>>(raw).ok());
    if let Some(map) = stored_headers {
        for (k, v) in map {
            // 双保险：白名单外的头一律不注入（防历史数据里混进凭据/逐跳头）
            if crate::service::op_recording::REPLAYABLE_HEADERS
                .contains(&k.to_ascii_lowercase().as_str())
            {
                req = req.header(k, v);
            }
        }
    }
    if let Some(body) = st.body.as_deref().filter(|b| !b.is_empty()) {
        let rendered = substitute_vars(body, vars)?;
        req = req.body(rendered);
    }

    let started = Instant::now();
    let resp = req.send().await;
    let elapsed = started.elapsed().as_secs_f64();
    let resp = match resp {
        Ok(r) => {
            crate::observability::metrics::MetricsRegistry::global().record_outbound(
                "recording_replay",
                "ok",
                elapsed,
            );
            r
        }
        Err(e) => {
            let outcome = if e.is_timeout() { "timeout" } else { "error" };
            crate::observability::metrics::MetricsRegistry::global().record_outbound(
                "recording_replay",
                outcome,
                elapsed,
            );
            return Err(format!("{}：{e}", pick("请求发送失败", "Request failed")));
        }
    };

    let status = resp.status().as_u16() as i32;
    // 流式读取开头若干字节：大响应不整体进内存，也不落库
    let mut buf: Vec<u8> = Vec::new();
    let mut body = resp;
    loop {
        if buf.len() >= RESPONSE_EXCERPT_BYTES {
            break;
        }
        match body.chunk().await {
            Ok(Some(chunk)) => {
                let room = RESPONSE_EXCERPT_BYTES - buf.len();
                let take = chunk.len().min(room);
                buf.extend_from_slice(&chunk[..take]);
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    let excerpt = if buf.is_empty() {
        None
    } else {
        let text = String::from_utf8_lossy(&buf).to_string();
        Some(truncate(&redact_json_like(&text), RESPONSE_EXCERPT_BYTES))
    };

    // 抽取：只有 2xx 才抽（失败响应里的字段没有语义）
    let extract_rule = st
        .extract_json
        .as_deref()
        .filter(|_| (200..300).contains(&status));
    if let Some(raw) = extract_rule {
        let text = String::from_utf8_lossy(&buf).to_string();
        for (name, path) in parse_extract_rules(raw) {
            if let Some(value) = extract_json_path(&text, &path) {
                vars.insert(name, value);
            }
        }
    }

    Ok((status, excerpt))
}

/// 渲染最终 URL（path / query / 变量替换）。
fn render_url(
    base: &str,
    st: &StepModel,
    vars: &BTreeMap<String, String>,
) -> Result<String, String> {
    let path = substitute_vars(&st.path, vars)?;
    let mut url = format!("{}{}", base.trim_end_matches('/'), path);
    if let Some(q) = st.query_string.as_deref().filter(|q| !q.is_empty()) {
        let rendered = substitute_vars(q, vars)?;
        url.push('?');
        url.push_str(&rendered);
    }
    Ok(url)
}

fn truncate(text: &str, max: usize) -> String {
    crate::service::op_recording::truncate_bytes(text, max).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::sys_op_recording::Model as RecordingModel;
    use crate::entity::sys_op_recording_step::Model as StepModel;
    use crate::service::op_recording::{
        CaptureDecision, MAX_CAPTURED_BODY_BYTES, ScriptFormat, build_script, decide_capture,
        extract_json_path, filter_headers, is_sensitive_field, normalize_extract_rules,
        redact_json_like, redact_query, substitute_vars, truncate_bytes, validate_step_path,
    };

    fn recording() -> RecordingModel {
        RecordingModel {
            tenant_id: 0,
            recording_id: 7,
            name: "部门与用户".to_string(),
            description: Some("建部门→建用户".to_string()),
            source: "ui".to_string(),
            status: "ready".to_string(),
            step_count: 2,
            last_run_status: None,
            last_run_time: None,
            owner_id: Some(1),
            owner_name: Some("admin".to_string()),
            create_time: None,
            update_time: None,
        }
    }

    fn step(seq: i32, method: &str, path: &str, body: Option<&str>) -> StepModel {
        StepModel {
            tenant_id: 0,
            step_id: seq as i64,
            recording_id: 7,
            seq,
            method: method.to_string(),
            path: path.to_string(),
            query_string: None,
            content_type: body.map(|_| "application/json".to_string()),
            body: body.map(|b| b.to_string()),
            headers_json: None,
            extract_json: None,
            expect_status: None,
            note: None,
            create_time: None,
        }
    }

    // ---------- 路径形状 ----------

    #[test]
    fn step_path_rejects_every_ssrf_shape() {
        for bad in [
            "",
            "system/user",
            "http://evil.example/x",
            "https://evil.example/x",
            "//evil.example/x",
            "/a/../b",
            "/a\\b",
        ] {
            assert!(
                validate_step_path(bad).is_err(),
                "非法路径必须被拒（回放目标不得由录制内容决定）：{bad}"
            );
        }
        for good in ["/system/user", "/a/b/c", "/system/user/1"] {
            assert!(validate_step_path(good).is_ok(), "站内路径应通过：{good}");
        }
    }

    // ---------- 采集判定 ----------

    #[test]
    fn capture_only_mutating_and_excludes_known_prefixes() {
        assert_eq!(
            decide_capture("GET", "/system/user", 0),
            CaptureDecision::NotMutating
        );
        assert_eq!(
            decide_capture("HEAD", "/system/user", 0),
            CaptureDecision::NotMutating
        );
        assert_eq!(
            decide_capture("POST", "/system/user", 0),
            CaptureDecision::Capture
        );
        assert_eq!(
            decide_capture("POST", "/auth/login", 0),
            CaptureDecision::Excluded("/auth/")
        );
        assert_eq!(
            decide_capture("DELETE", "/tool/recording/1", 0),
            CaptureDecision::Excluded("/tool/recording")
        );
        assert_eq!(
            decide_capture("POST", "http://x/y", 0),
            CaptureDecision::BadPath
        );
        assert_eq!(
            decide_capture("POST", "/system/user", 200),
            CaptureDecision::Full,
            "达到步数上限必须显式判定为 Full，而不是静默丢弃"
        );
    }

    #[test]
    fn capture_outcome_labels_are_distinct() {
        // 标签必须可区分：全折成 "skipped" 会让"为什么没录进去"无法归因
        let labels = [
            CaptureDecision::Capture.outcome(),
            CaptureDecision::NotMutating.outcome(),
            CaptureDecision::Excluded("/auth/").outcome(),
            CaptureDecision::BadPath.outcome(),
            CaptureDecision::Full.outcome(),
        ];
        let uniq: std::collections::BTreeSet<_> = labels.iter().collect();
        assert_eq!(uniq.len(), labels.len(), "五种采集结局必须有五个不同标签");
    }

    // ---------- 脱敏 ----------

    #[test]
    fn sensitive_fields_are_folded_in_both_json_and_form_shapes() {
        let json = r#"{"userName":"u1","password":"p@ss","nested":{"apiKey":"k"},"list":[{"secret":"s"}]}"#;
        let out = redact_json_like(json);
        assert!(!out.contains("p@ss"), "JSON 里的密码必须被折叠：{out}");
        assert!(!out.contains("\"k\""), "apiKey 必须被折叠：{out}");
        assert!(
            !out.contains("\"s\""),
            "嵌套数组里的 secret 也必须折叠：{out}"
        );
        assert!(out.contains("u1"), "非敏感字段不得误伤：{out}");

        let form = "userName=u1&password=p%40ss&token=abc";
        let out = redact_json_like(form);
        assert!(!out.contains("p%40ss"), "表单形态的密码必须被折叠：{out}");
        assert!(!out.contains("abc"), "表单形态的 token 必须被折叠：{out}");
        assert!(out.contains("u1"), "表单里的非敏感字段不得误伤：{out}");
    }

    #[test]
    fn field_name_matching_ignores_case_and_separators() {
        for name in [
            "Password",
            "old_password",
            "new-password",
            "clientSecret",
            "X-API-KEY",
        ] {
            assert!(is_sensitive_field(name), "{name} 必须被判为敏感");
        }
        for name in ["userName", "deptId", "status"] {
            assert!(!is_sensitive_field(name), "{name} 不得被判为敏感");
        }
    }

    #[test]
    fn query_redaction_keeps_order_and_drops_values_only() {
        let out = redact_query("pageNum=1&password=x&pageSize=10&accessToken=t");
        assert_eq!(out, "pageNum=1&password=***&pageSize=10&accessToken=***");
    }

    // ---------- 截断 ----------

    #[test]
    fn truncation_is_utf8_safe_and_marked() {
        let long = "密".repeat(MAX_CAPTURED_BODY_BYTES); // 每字 3 字节，必然越界
        let (cut, truncated) = truncate_bytes(&long, 10);
        assert!(truncated);
        assert_eq!(
            cut,
            "密".repeat(3),
            "按字符边界截断：10 字节只能容纳 3 个汉字"
        );
        // 截断后必须是合法 UTF-8（`String::from_utf8` 不会因为半字符失败）
        assert!(std::str::from_utf8(cut.as_bytes()).is_ok());
    }

    // ---------- 变量 ----------

    #[test]
    fn variable_substitution_reports_the_missing_name() {
        let mut vars = BTreeMap::new();
        vars.insert("deptId".to_string(), "12".to_string());
        assert_eq!(
            substitute_vars("/system/dept/{{deptId}}", &vars).unwrap(),
            "/system/dept/12"
        );
        let err = substitute_vars("/system/dept/{{userId}}", &vars).unwrap_err();
        assert!(err.contains("userId"), "错误必须点名缺失的变量：{err}");
        // 未闭合的 `{{` 原样保留（不制造新的失败模式）
        assert_eq!(substitute_vars("a{{b", &vars).unwrap(), "a{{b");
    }

    #[test]
    fn json_path_extraction_handles_objects_and_arrays() {
        let body = r#"{"data":{"rows":[{"id":42}],"total":1},"msg":"ok"}"#;
        assert_eq!(
            extract_json_path(body, "data.rows.0.id").as_deref(),
            Some("42")
        );
        assert_eq!(extract_json_path(body, "msg").as_deref(), Some("ok"));
        assert_eq!(extract_json_path(body, "data.missing"), None);
        assert_eq!(extract_json_path("not json", "a"), None);
    }

    #[test]
    fn extract_rules_are_normalized_and_sorted() {
        let out = normalize_extract_rules(r#"{"b":"data.b","a":"data.a"}"#).unwrap();
        assert_eq!(
            out, r#"{"a":"data.a","b":"data.b"}"#,
            "必须按键排序，保证可 diff"
        );
        for bad in [r#"{"a":"$..id"}"#, r#"{"a b":"x"}"#, r#"{"a":1}"#, r#"[]"#] {
            assert!(
                normalize_extract_rules(bad).is_err(),
                "非法抽取规则必须在写入侧被拒：{bad}"
            );
        }
    }

    // ---------- 头白名单 ----------

    #[test]
    fn header_filter_never_carries_credentials() {
        let headers = vec![
            ("Authorization".to_string(), "Bearer x".to_string()),
            ("Cookie".to_string(), "sid=1".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Request-Id".to_string(), "r1".to_string()),
            ("content-type".to_string(), "text/plain".to_string()),
        ];
        let kept = filter_headers(headers.into_iter());
        assert!(!kept.contains_key("authorization"), "凭据头不得入库");
        assert!(!kept.contains_key("cookie"), "Cookie 不得入库");
        assert_eq!(
            kept.get("content-type").map(String::as_str),
            Some("application/json"),
            "同名头只留第一条"
        );
        assert_eq!(kept.get("x-request-id").map(String::as_str), Some("r1"));
    }

    // ---------- 脚本导出 ----------

    #[test]
    fn curl_script_is_shell_safe_and_ordered() {
        let steps = vec![
            step(1, "POST", "/system/dept", Some(r#"{"deptName":"it's"}"#)),
            step(2, "DELETE", "/system/dept/9", None),
        ];
        let script = build_script(
            ScriptFormat::Curl,
            &recording(),
            &steps,
            "http://127.0.0.1:8080/",
        );
        assert!(script.starts_with("#!/usr/bin/env bash"));
        assert!(script.contains("set -euo pipefail"), "脚本必须遇错即停");
        assert!(
            script.contains(r#"'{"deptName":"it'\''s"}'"#),
            "单引号必须按 POSIX 转义，否则脚本语法错误：{script}"
        );
        let pos1 = script.find("第 1 步").unwrap();
        let pos2 = script.find("第 2 步").unwrap();
        assert!(pos1 < pos2, "步骤顺序必须与录制一致");
        assert!(
            !script.contains("Bearer ey"),
            "脚本不得内联任何真实令牌（只引用环境变量）"
        );
    }

    #[test]
    fn http_script_uses_variables_and_base() {
        let steps = vec![step(1, "POST", "/system/dept", Some("{}"))];
        let script = build_script(ScriptFormat::Http, &recording(), &steps, "http://h:1");
        // 定义侧 @base / @token，引用侧 {{base}} / {{token}}——这是 .http 文件的真实语法，
        // 写成 {base} 或 {base 客户端不会替换，脚本会打到字面地址上。
        assert!(script.contains("@base = http://h:1"));
        assert!(script.contains("@token = "), "必须留出令牌占位行");
        assert!(
            script.contains("POST {{base}}/system/dept"),
            "URL 必须用 {{{{base}}}} 前缀：{script}"
        );
        assert!(script.contains("Authorization: Bearer {{token}}"));
        assert!(
            !script.contains("@token = ey"),
            "令牌占位不得被真实令牌替换"
        );
    }

    #[test]
    fn json_script_round_trips_through_serde() {
        let steps = vec![step(1, "POST", "/system/dept", Some("{}"))];
        let script = build_script(ScriptFormat::Json, &recording(), &steps, "http://h:1");
        let parsed: serde_json::Value = serde_json::from_str(&script).expect("必须是合法 JSON");
        assert_eq!(parsed["steps"].as_array().map(|a| a.len()), Some(1));
        assert_eq!(parsed["baseUrl"], "http://h:1");
        assert_eq!(parsed["steps"][0]["path"], "/system/dept");
    }

    // ---------- 选项夹取 ----------

    #[test]
    fn step_timeout_is_clamped() {
        let mut o = ReplayOptions::default();
        assert_eq!(o.timeout(), Duration::from_secs(DEFAULT_STEP_TIMEOUT_SECS));
        o.timeout_secs = Some(0);
        assert_eq!(o.timeout().as_secs(), 1, "0 秒必须夹到 1，而不是立即超时");
        o.timeout_secs = Some(9999);
        assert_eq!(o.timeout().as_secs(), MAX_STEP_TIMEOUT_SECS);
        assert!(
            o.stop_on_error,
            "默认必须遇错即停（避免把后面的写操作也发出去）"
        );
    }

    // ---------- 预检 ----------

    #[test]
    fn preview_renders_and_flags_missing_vars_without_network() {
        let mut missing = step(2, "DELETE", "/system/dept/{{deptId}}", None);
        missing.expect_status = Some(200);
        let steps = vec![
            {
                let mut s = step(
                    1,
                    "POST",
                    "/system/dept",
                    Some(r#"{"deptName":"{{deptName}}"}"#),
                );
                s.extract_json = Some(r#"{"deptId":"data.deptId"}"#.to_string());
                s
            },
            missing,
        ];
        let options = ReplayOptions {
            vars: BTreeMap::from([("deptName".to_string(), "研发部".to_string())]),
            ..Default::default()
        };
        let preview = preview_steps(&steps, "http://127.0.0.1:8080", &options).unwrap();
        assert_eq!(preview.len(), 2);
        assert_eq!(preview[0].url, "http://127.0.0.1:8080/system/dept");
        assert!(preview[0].body.as_deref().unwrap().contains("研发部"));
        assert!(preview[0].problem.is_none());
        // 第 2 步的 deptId 还没被抽到（预检不执行第 1 步），必须点名缺哪个变量
        assert!(
            preview[1]
                .problem
                .as_deref()
                .unwrap_or_default()
                .contains("deptId"),
            "预检必须指出缺失变量，实际：{:?}",
            preview[1].problem
        );
    }
}
