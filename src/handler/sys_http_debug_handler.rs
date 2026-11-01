//! 在线 HTTP 调试器 Handler（/tool/http-debug/execute）
//!
//! 受保护接口（需 auth_middleware + permission_middleware，权限 tool:httpDebug:list）。
//! 由服务端转发用户指定的目标接口并返回状态码/响应头/响应体/耗时等调试信息。
//! SSRF 防护位于 Service 层（见 sys_http_debug_service / common::ssrf）。

use std::sync::Arc;

use axum::Json;
use axum::extract::State;

use crate::common::{AjaxResult, AppError};
use crate::middleware::Operator;
use crate::service::sys_http_debug_service::{HttpDebugDto, HttpDebugVo};
use crate::state::AppState;

/// POST /tool/http-debug/execute — 执行一次调试请求
///
/// 返回 200 + AjaxResult；传输层错误（连接失败/超时等）不视为 HTTP 错误，
/// 而是通过 `error` 字段返回（status=0），便于前端在不产生 HTTP 4xx/5xx 的前提下
/// 统一展示调试结果。SSRF 违规/参数非法则以 400 直接拒绝。
#[utoipa::path(
    post,
    path = "/tool/http-debug/execute",
    request_body = HttpDebugDto,
    responses(
        (status = 200, description = "调试结果（状态码/响应头/响应体/耗时）", body = AjaxResult<HttpDebugVo>),
        (status = 400, description = "参数非法或目标地址未通过 SSRF 校验"),
        (status = 403, description = "无权限（tool:httpDebug:list）或非平台操作者"),
    ),
    tag = "tool-http-debug"
)]
pub async fn execute(
    State(state): State<Arc<AppState>>,
    operator: Operator,
    Json(dto): Json<HttpDebugDto>,
) -> Result<AjaxResult<HttpDebugVo>, AppError> {
    // b145：入参校验必须排在**占闸之前**。`tool:http-debug` 只有 2 个许可，而一个 URL 写错的
    // 请求根本不会出网——原先它也要先抢许可，闸满时拿到的是 429「该操作正在进行中」，
    // 正确答案是 400「URL 格式非法」（把背压冒充参数错误，运维据此去查"调试器为什么这么忙"）。
    // 校验只有 `precheck` 一份实现，`execute` 内部会再跑一次（纯计算，代价可忽略）。
    crate::service::sys_http_debug_service::precheck(&dto)?;
    let _gate = crate::common::resource_gate::try_enter(
        crate::common::resource_gate::HeavyEntry::HttpDebugExecute,
    )?;
    tracing::info!(
        user = operator.username(),
        method = %dto.method,
        url = %dto.url,
        "在线 HTTP 调试器转发请求"
    );
    let vo = state.http_debug_service.execute(dto).await?;
    Ok(AjaxResult::success(vo))
}

#[cfg(test)]
mod tests {
    /// b145：**入参校验必须排在占闸之前**。
    ///
    /// 立的案是实测的：`tool:http-debug` 只有 2 个许可，而一个 URL 写错的请求根本不会出网，
    /// 原先也要先抢许可——闸满时它收到 429「该操作正在进行中（tool:http-debug）」，
    /// 正确答案是 400「URL 格式非法」。同一轮集成测试里三个调试用例并发，非法输入那条
    /// 就成了随机红（㉒：绿红由并行度决定）。
    /// 这一条锁的是**顺序**，不是"有没有调用"：把 `precheck` 挪到闸后，形状完全合法但缺陷回来了。
    #[test]
    fn input_precheck_runs_before_the_gate() {
        let cfg = crate::common::prod_scan::Scan::default();
        let text =
            crate::common::prod_scan::prod_file("src/handler/sys_http_debug_handler.rs", &cfg)
                .text();
        let pre = text
            .find("precheck(&dto)")
            .expect("生产视图里找不到入参校验调用点 ⇒ 校验被摘掉或改名，这条锁在看空处");
        let gate = text
            .find("resource_gate::try_enter(")
            .expect("生产视图里找不到占闸点 ⇒ 闸被摘掉，出站重活失去背压");
        assert!(
            pre < gate,
            "入参校验（偏移 {pre}）必须排在占闸（偏移 {gate}）之前，否则非法输入会被背压冒充"
        );
        // 对照：真实工作（execute）必须仍在闸之后——把闸整个摘掉同样能让上面那句成立
        let work = text
            .find("http_debug_service.execute(")
            .expect("生产视图里找不到出站调用点");
        assert!(gate < work, "占闸必须排在真实工作之前（b89 的接线纪律）");
    }
}
