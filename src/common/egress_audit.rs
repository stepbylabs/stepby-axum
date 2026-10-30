//! 数据外带出口（整库快照 / 全租户合规归档 / 全量变更留痕）的审计留痕**单一实现**。
//!
//! 为什么需要这一层（b137 实测起点）：`middleware::oper_log` 只记录 POST/PUT/DELETE
//! （`is_write_method`），而本仓最敏感的三条出口恰恰是**GET**——
//! `GET /system/backup/download/{backupId}`（整库/整租户快照）、
//! `GET /monitor/operlog/archive/{anchorId}`（全租户合规归档）、
//! `GET /system/audit-change/export`（全量变更留痕 CSV）。GET 不进中间件 ⇒
//! 「谁、在什么时候、把多少数据带走了」在审计面上整段空白，而 AGENTS C.10 要求
//! 敏感操作必须有独立于全局限流的速率限制**和审计**。
//!
//! 口径（三条，写错任一条都会让审计失真）：
//! - **只在数据真的可取之后写**：处理器先完成权限/归属/存在性与体积校验，再调用本模块。
//!   失败路径（403/404/400）不落审计——权限层拒绝发生在处理器之前，探测失败留痕由
//!   后端 WARN 日志承担，把失败也写进 `sys_oper_log` 会把审计面刷成探测流水（b69 同族）。
//! - **不阻断响应**：走 `background::spawn_tracked`（超时 + panic 隔离 + 结局计数），
//!   审计写失败只留 WARN；下载的流已经在路上，不能因为审计写库失败改回 500。
//! - **只记非敏感事实**：目标标识、体积/行数、文件名与目标租户；查询串不进 `oper_url`
//!   （可能含用户搜索词），`dept_name` 留空（可经 `oper_name` 反查，不为一条外带审计
//!   再加一次部门查询）。
//!
//! 新增同类出口必须先在 [`EgressKind`] 登记：路由模板、限流档位与审计标题都以它为
//! 单一事实源——`initialize::rate_limit` 的 `get_egress_routes_are_rate_limited_or_exempt`
//! 由路由注册派生采集面（漏登记即红），本模块的 `every_egress_kind_is_wired_into_its_handler`
//! 反查每个变体的处理器函数体里确实调用了 [`record_egress`]。

use std::sync::Arc;

use crate::middleware::auth::Operator;
use crate::service::sys_oper_log_service::OperLogRecord;
use crate::state::AppState;

/// 数据外带出口清单（路由模板须与 `src/router/**` 注册逐字一致）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressKind {
    /// 备份/租户数据包下载（整库或整租户快照）。
    BackupDownload,
    /// 合规归档下载（清理锚点关联的 JSONL，全租户混合）。
    OperLogArchive,
    /// 变更留痕 CSV 导出（含操作人/表/主键/变更字段的全量外带）。
    AuditChangeExport,
    /// AI 历史管理导出（跨租户问答与 SQL 的批量外带）。
    AiHistoryExport,
}

impl EgressKind {
    /// 全部成员（接线反查与限流对账都以本表为采集面）。
    pub const ALL: [EgressKind; 4] = [
        EgressKind::BackupDownload,
        EgressKind::OperLogArchive,
        EgressKind::AuditChangeExport,
        EgressKind::AiHistoryExport,
    ];

    /// axum 路由模板（与限流档位、`MatchedPath` 同口径）。
    pub const fn route(self) -> &'static str {
        match self {
            EgressKind::BackupDownload => "/system/backup/download/{backupId}",
            EgressKind::OperLogArchive => "/monitor/operlog/archive/{anchorId}",
            EgressKind::AuditChangeExport => "/system/audit-change/export",
            EgressKind::AiHistoryExport => "/system/ai/history/admin/export",
        }
    }

    /// 处理器所在文件与函数名（接线反查用；新增变体必须同时补上）。
    pub const fn handler(self) -> (&'static str, &'static str) {
        match self {
            EgressKind::BackupDownload => ("src/handler/sys_backup_handler.rs", "download"),
            EgressKind::OperLogArchive => {
                ("src/handler/sys_oper_log_handler.rs", "archive_download")
            }
            EgressKind::AuditChangeExport => ("src/audit/handler.rs", "export"),
            EgressKind::AiHistoryExport => ("src/ai/handler.rs", "export_admin_history"),
        }
    }

    /// 审计业务类型：5=导出（下载与导出在审计面同属"把数据带出去"）。
    pub const fn business_type(self) -> i32 {
        5
    }

    /// 审计标题（复用中间件同一套模块归类，避免两处各写一份映射）。
    pub fn title(self) -> String {
        crate::middleware::oper_log::infer_module_title(self.route())
    }
}

/// 一次外带请求的审计事实（由处理器构造；只放非敏感字段）。
pub struct EgressEvent {
    pub kind: EgressKind,
    /// 实际请求路径（含标识，**不含查询串**：搜索词不进审计面）。
    pub oper_url: String,
    /// 审计参数（目标标识等）。
    pub oper_param: serde_json::Value,
    /// 外带内容摘要（文件名 / 字节数 / 行数）。
    pub detail: serde_json::Value,
    /// 平台代管他租户资源时的目标租户；同租户或无目标租户时为 `None`。
    pub target_tenant_id: Option<i64>,
}

/// 审计主体（从 `Operator` + 请求侧事实派生；拆出来是为了让记录装配可单测）。
pub(crate) struct EgressActor<'a> {
    pub username: &'a str,
    pub tenant_id: i64,
    pub client_ip: &'a str,
    pub location: &'a str,
}

/// 纯函数：把主体与外带事实装配成一条 `oper_log` 记录（测试直接断言字段）。
///
/// b138：`oper_param` 与 `json_result` 必须过**中间件同款**脱敏与截断。
/// 此前这两列直接 `Value::to_string()` 落库，于是同一张 `sys_oper_log` 有两条严格度不同的
/// 写入路径：中间件那条会掩掉 password/token/phone/idCard/nickname/avatar，外带审计这条不会。
/// 两处各写一份必然漂（AGENTS ㉘），故直接复用 `middleware::oper_log` 的实现：
/// 先脱敏（解析成功则结构保持、逐字段掩码），再按 `MAX_LOG_FIELD_LEN` 截断（顺序与中间件一致）。
pub(crate) fn compose_record(actor: EgressActor<'_>, event: EgressEvent) -> OperLogRecord {
    let oper_param = crate::middleware::oper_log::sanitize_param(event.oper_param.to_string());
    let json_result = {
        let sanitized =
            crate::middleware::oper_log::sanitize_response_body(&event.detail.to_string());
        crate::middleware::oper_log::safe_truncate(
            &sanitized,
            crate::middleware::oper_log::MAX_LOG_FIELD_LEN,
        )
    };
    OperLogRecord {
        title: event.kind.title(),
        business_type: event.kind.business_type(),
        method: event.kind.route().to_string(),
        request_method: "GET".to_string(),
        operator_type: 1,
        oper_name: actor.username.to_string(),
        tenant_id: actor.tenant_id,
        target_tenant_id: event.target_tenant_id,
        // 部门名可经 oper_name 反查；外带审计不为此再加一次 DB 往返。
        dept_name: String::new(),
        oper_url: event.oper_url,
        oper_ip: actor.client_ip.to_string(),
        oper_location: actor.location.to_string(),
        oper_param,
        oper_before: String::new(),
        oper_diff: String::new(),
        json_result,
        // "0"=成功：本记录只在数据已真正可取之后写入（失败不落审计，见模块文档）。
        status: "0".to_string(),
        error_msg: String::new(),
        cost_time: 0,
    }
}

/// 记录一次数据外带（成功后调用；fire-and-forget，不阻断响应）。
pub fn record_egress(
    state: &Arc<AppState>,
    operator: &Operator,
    client_ip: &str,
    event: EgressEvent,
) {
    let record = compose_record(
        EgressActor {
            username: operator.username(),
            tenant_id: operator.tenant_id(),
            client_ip,
            location: &state.ip_locator.locate(client_ip),
        },
        event,
    );
    let service = state.oper_log_service.clone();
    crate::common::background::spawn_tracked(
        "egress_audit",
        crate::common::background::LIGHT_DB_BUDGET,
        Some(state.observability.metrics.clone()),
        async move { service.record_oper_log(record).await },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::prod_scan::{Scan, prod_file};
    use crate::middleware::oper_log::MAX_LOG_FIELD_LEN;

    fn event(kind: EgressKind) -> EgressEvent {
        EgressEvent {
            kind,
            oper_url: format!(
                "{}/42",
                kind.route().trim_end_matches("}").trim_end_matches('{')
            ),
            oper_param: serde_json::json!({ "id": 42 }),
            detail: serde_json::json!({ "size": 1024 }),
            target_tenant_id: Some(7),
        }
    }

    #[test]
    fn compose_record_carries_who_what_and_volume() {
        let record = compose_record(actor(), event(EgressKind::BackupDownload));
        assert_eq!(record.request_method, "GET", "外带审计必须标明是 GET");
        assert_eq!(record.method, EgressKind::BackupDownload.route());
        assert_eq!(record.title, "module.backup");
        assert_eq!(record.business_type, 5, "导出语义（5）");
        assert_eq!(record.status, "0", "只有成功发起才落审计");
        assert_eq!(record.oper_name, "admin");
        assert_eq!(record.target_tenant_id, Some(7));
        assert!(record.oper_param.contains("\"id\":42"));
        assert!(record.json_result.contains("\"size\":1024"));
        assert!(record.oper_url.starts_with("/system/backup/download/"));
        assert!(!record.oper_url.contains('?'), "查询串不进 oper_url");
    }

    fn actor() -> EgressActor<'static> {
        EgressActor {
            username: "admin",
            tenant_id: 0,
            client_ip: "10.1.2.3",
            location: "内网IP",
        }
    }

    /// b138：外带审计与中间件必须共用**同一份**脱敏（AGENTS ㉘：同一句纪律写两遍就有
    /// 两个严格度）。改造前 `oper_param` / `json_result` 直接 `Value::to_string()` 落库，
    /// 于是同一张 `sys_oper_log` 上有两条严格度不同的写入路径——中间件那条会掩掉
    /// password/token/phone/email，外带这条不会。
    #[test]
    fn compose_record_masks_sensitive_fields_like_the_middleware() {
        let mut ev = event(EgressKind::BackupDownload);
        ev.oper_param = serde_json::json!({
            "backupId": 42,
            "password": "p@ssw0rd",
            "accessToken": "eyJhbGciOiJIUzI1",
            "phone": "13800138000",
            "nested": { "email": "ops@example.com" }
        });
        ev.detail = serde_json::json!({
            "fileName": "backup-2026.sql",
            "size": 1024,
            "secret": "s3cr3t-value"
        });

        let record = compose_record(actor(), ev);

        // 对照组：非敏感事实必须原样保留——否则"一律 REDACTED"也能骗过脱敏断言
        assert!(
            record.oper_param.contains("\"backupId\":42"),
            "非敏感字段被误伤: {}",
            record.oper_param
        );
        assert!(
            record.json_result.contains("backup-2026.sql")
                && record.json_result.contains("\"size\":1024"),
            "外带摘要本身丢失: {}",
            record.json_result
        );
        // 敏感值一个都不许留明文（嵌套对象同样要走到）
        for leak in [
            "p@ssw0rd",
            "eyJhbGciOiJIUzI1",
            "13800138000",
            "ops@example.com",
            "s3cr3t-value",
        ] {
            assert!(
                !record.oper_param.contains(leak),
                "oper_param 泄漏 {leak}: {}",
                record.oper_param
            );
            assert!(
                !record.json_result.contains(leak),
                "json_result 泄漏 {leak}: {}",
                record.json_result
            );
        }
    }

    /// 接线反查：`compose_record` 必须真的调用中间件那三个助手，而不是"看起来像脱敏"
    /// （自己再写一份实现必然漂，下一次加敏感键时只改一处）。
    #[test]
    fn compose_record_reuses_the_middleware_helpers() {
        let text = prod_file("src/common/egress_audit.rs", &Scan::default()).text();
        let body = fn_body(&text, "compose_record").expect("采集面失效");
        for needle in [
            "middleware::oper_log::sanitize_param",
            "middleware::oper_log::sanitize_response_body",
            "middleware::oper_log::safe_truncate",
            "middleware::oper_log::MAX_LOG_FIELD_LEN",
        ] {
            assert!(body.contains(needle), "compose_record 未复用 {needle}");
        }
    }

    /// 超长摘要是常态（整库备份的文件名列表可达数百 KB），截断必须发生且不得 panic 在
    /// UTF-8 字符中间——`String::truncate` 在非字符边界上会直接 panic（C-1 同族）。
    #[test]
    fn compose_record_truncates_long_detail_without_splitting_utf8() {
        let mut ev = event(EgressKind::AuditChangeExport);
        // 每个"中"占 3 字节：MAX_LOG_FIELD_LEN 之后必然落在多字节字符中间
        ev.detail = serde_json::json!({ "rows": "中".repeat(MAX_LOG_FIELD_LEN) });

        let record = compose_record(actor(), ev);

        assert!(
            record.json_result.ends_with("...(truncated)"),
            "超长 json_result 必须带截断标记（实测 {} 字节）",
            record.json_result.len()
        );
        assert!(
            record.json_result.len() <= MAX_LOG_FIELD_LEN + "...(truncated)".len(),
            "截断后仍超上限: {} 字节",
            record.json_result.len()
        );
    }

    /// 对照组：没超上限时**不得**加截断标记（否则"永远截断"也能过上面那条）。
    #[test]
    fn compose_record_keeps_short_detail_verbatim() {
        let record = compose_record(actor(), event(EgressKind::AiHistoryExport));
        assert!(!record.json_result.contains("...(truncated)"));
        assert!(record.json_result.contains("\"size\":1024"));
    }

    #[test]
    fn every_kind_has_distinct_route_and_handler() {
        let mut routes = std::collections::HashSet::new();
        let mut handlers = std::collections::HashSet::new();
        for kind in EgressKind::ALL {
            assert!(routes.insert(kind.route()), "{kind:?} 路由重复");
            assert!(handlers.insert(kind.handler()), "{kind:?} 处理器重复");
            assert!(kind.route().starts_with('/'), "{kind:?} 路由必须是绝对路径");
        }
        assert_eq!(routes.len(), EgressKind::ALL.len());
        // 采集面自证：四条路由覆盖四类外带形态
        assert!(routes.contains("/system/backup/download/{backupId}"));
        assert!(routes.contains("/monitor/operlog/archive/{anchorId}"));
        assert!(routes.contains("/system/audit-change/export"));
        assert!(routes.contains("/system/ai/history/admin/export"));
    }

    /// 每条外带路由都必须有独立限流档（与 `initialize::rate_limit` 的反向锁互补：
    /// 那条锁保证"新增 GET 外带路由不登记就红"，这条保证"登记了的路由真的进了档位表"）。
    #[test]
    fn every_egress_kind_has_a_sensitive_rate_limit_tier() {
        for kind in EgressKind::ALL {
            assert!(
                crate::initialize::SENSITIVE_LIMIT_TIERS
                    .iter()
                    .any(|(route, ..)| *route == kind.route()),
                "{kind:?} 的路由 {} 没有独立限流档（只剩全局默认兜底）",
                kind.route()
            );
        }
    }

    #[test]
    fn every_egress_kind_is_wired_into_its_handler() {
        for kind in EgressKind::ALL {
            let (file, func) = kind.handler();
            let text = prod_file(file, &Scan::default()).text();
            let body = fn_body(&text, func)
                .unwrap_or_else(|| panic!("{file} 里找不到处理器 {func}（采集面失效）"));
            assert!(
                body.contains("record_egress("),
                "{file}::{func} 未调用 record_egress ⇒ {kind:?} 的外带没有审计留痕"
            );
        }
    }

    /// 提取 `[async] fn <name>(` 的函数体（花括号配对），供接线反查。
    ///
    /// 必须同时认同步与异步：`compose_record` 是同步函数，只认 `async fn` 会让接线反查在
    /// 真实树上恒返回 `None`（b138 实测：本测试首跑即红在"采集面失效"，而不是红在真正的
    /// 断线上——判据自己的输入形状错了）。
    fn fn_body(text: &str, name: &str) -> Option<String> {
        let heads = [format!("async fn {name}("), format!("fn {name}(")];
        let start = heads
            .iter()
            .filter_map(|head| text.find(head.as_str()))
            .min()?;
        let open = start + text[start..].find('{')?;
        let mut depth = 0usize;
        for (i, ch) in text[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(text[open..=open + i].to_string());
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// 反脆弱：提取器与 needle 必须真能区分"接线的"与"没接线的"两种形状。
    #[test]
    fn wiring_lock_is_falsifiable() {
        let wired = "pub async fn f() -> u8 {\n    record_egress(&s, &o, ip, e);\n    1\n}\n";
        let unwired = "pub async fn f() -> u8 {\n    1\n}\n";
        assert!(fn_body(wired, "f").unwrap().contains("record_egress("));
        assert!(!fn_body(unwired, "f").unwrap().contains("record_egress("));
        assert!(
            fn_body("fn other() {}", "f").is_none(),
            "找不到函数必须返回 None"
        );
        // 同名函数在后面：必须取到第一个匹配的函数体（且 needle 只出现在别处时不算接线）
        let decoy =
            "pub async fn f() -> u8 { 1 }\npub async fn g() { record_egress(&s, &o, ip, e); }\n";
        assert!(!fn_body(decoy, "f").unwrap().contains("record_egress("));
        // 同步函数同样要能提取（`compose_record` 就是同步的；只认 `async fn` 会让
        // `compose_record_reuses_the_middleware_helpers` 恒红在"采集面失效"上）
        let sync = "pub(crate) fn f(x: u8) -> u8 {\n    x + 1\n}\n";
        assert_eq!(fn_body(sync, "f").unwrap().trim(), "{\n    x + 1\n}");
        assert!(
            fn_body("fn f() -> u8;\n", "f").is_none(),
            "文本里没有函数体（没有花括号）时必须返回 None"
        );
    }
}
