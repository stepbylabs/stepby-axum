//! 重资源入口的全局并发闸门（b89 项 E2，AGENTS 工程硬基线 A-2）——端到端那一腿。
//!
//! 闸的形状、拒绝文案、槽位划分、handler 接线与顺序都由 `common::resource_gate`
//! 里的单元测试锁；本文件只补**真实请求链路**上的一件事：
//! 闸满时 handler 真的把 429 + `Retry-After` 送回客户端（而不是 500、不是排队等到超时）。
//!
//! ⚠️ 只用 `ComplianceReport` 这一个入口：其余四个在全仓集成测试里是**真实业务链路**
//! （`sys_backup.rs` 真跑 `POST /system/backup`），测试占住全局许可会让那条链路偶发 429
//! ——"门禁绿红由并行时序决定"是 AGENTS 前言 ㉒ 明令禁止的形态。

use super::TestContext;
use crate::common::resource_gate::{HeavyEntry, available_permits, try_enter};
use axum::http::{Method, StatusCode};

/// 占满合规报表闸 ⇒ 请求 429 + Retry-After；释放后同一请求必须恢复 200
/// （前后配对，否则"永远 429"的实现也能满足上半句——b83 那条"两种相反状态同时满足判据"的形状）
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compliance_report_rejects_when_gate_is_full_then_recovers() {
    let ctx = TestContext::new().await;
    let entry = HeavyEntry::ComplianceReport;

    // 先证"空闸可进、进得去也能出 200"（对照组：闸门不能把正常请求也挡掉）
    let first = try_enter(entry).expect("空闸必须取得许可");
    drop(first);
    let (status, _headers, body) = ctx
        .send_with_headers(ctx.request(
            Method::GET,
            "/monitor/operlog/compliance-report?days=1",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "空闸时合规报表必须照常可用（否则闸门是把功能关掉了，不是背压）: {body}"
    );

    // 占满两路 ⇒ 第三路（真实请求）必须当场被拒
    let held = (
        try_enter(entry).expect("第一路必须进得去"),
        try_enter(entry).expect("第二路必须进得去"),
    );
    assert_eq!(
        available_permits(entry),
        0,
        "占满后可用量必须为 0（否则 try_enter 没在动同一把闸）"
    );
    let (status, headers, body) = ctx
        .send_with_headers(ctx.request(
            Method::GET,
            "/monitor/operlog/compliance-report?days=1",
            None,
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "闸满必须 429，实际 {status}（body: {body}）"
    );
    assert_eq!(body["code"], 429, "业务码必须与 HTTP 状态同向: {body}");
    let retry = headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        !retry.is_empty(),
        "429 必须带非空 Retry-After（客户端只能靠猜的退避不算背压），实际头: {headers:?}"
    );
    assert!(
        body["msg"]
            .as_str()
            .unwrap_or_default()
            .contains("operlog:compliance-report"),
        "拒绝文案必须点名是哪个入口忙，实际: {body}"
    );

    drop(held);
    assert_eq!(
        available_permits(entry),
        2,
        "许可必须随请求结束归还（不得泄漏）"
    );
    let (status, _headers, body) = ctx
        .send_with_headers(ctx.request(
            Method::GET,
            "/monitor/operlog/compliance-report?days=1",
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "释放后同一请求必须恢复可用: {body}");

    // 拒绝必须**在 /metrics 里看得见**（AGENTS B-4：组件自带指标）。
    // 只有客户端收到 429 而服务端无痕 = 背压被藏起来，运维侧的表现是
    // "备份有时候点不动"这种归不了因的一句话（本文件上半段那条 WARN 是日志面，
    // 日志会被窗口/采样淹掉，指标才是给监控用的通道）。
    let (status, text) = ctx
        .send_text(ctx.request(Method::GET, "/metrics", None))
        .await;
    assert_eq!(status, StatusCode::OK, "/metrics 必须可用");
    let line = text
        .lines()
        .find(|l| {
            l.starts_with(
                "stepby_resource_gate_decisions_total{entry=\"operlog:compliance-report\",outcome=\"rejected\"} ",
            )
        })
        .unwrap_or_else(|| panic!("指标里没有合规报表这一档的拒绝计数 ⇒ 渲染未接入 /metrics:\n{text}"));
    let count: u64 = line
        .rsplit(' ')
        .next()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("指标行尾不是数字: {line}"));
    assert!(
        count >= 1,
        "刚才那一次 429 必须被记进指标（读到 0 = 计数点与拒绝点不是同一条路径）"
    );
    assert!(
        text.contains(
            "stepby_resource_gate_available_permits{entry=\"operlog:compliance-report\"} 2"
        ),
        "释放后可用量必须回到 2（指标口径与闸口径同源）:\n{text}"
    );
}
