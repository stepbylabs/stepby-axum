// stepby-axum/src/middleware/export_gate.rs
//! 导出路由的前置背压（b91 N-90-1）。
//!
//! 立项事实：`common::resource_gate` 的 `export:excel` 许可原本只在
//! `common::excel::export_to_excel_with_fields` 的**构造点**获取——那时 handler 已经
//! 把最多 `EXPORT_MAX_ROWS` 行读进内存了。闸门保护了 xlsx 构建，却让"闸满时的一次
//! 全量 DB 读"照常发生；一串并发导出会先把连接池与内存打满，再在构造点被 429。
//!
//! 本中间件只做**前置拒绝**：趁闸已经为空时在入口返回 429，重活（DB 读）根本不开始。
//! 它刻意**不持有许可**——真正的许可仍由构造点 `try_enter` 获取并覆盖 xlsx 构建段。
//! 这样不改变既有闸的并发语义（`export:excel` 仍是 8 路），也不会把请求占用时间
//! 拉长到整条链路（那会让并行集成测试里的导出用例互相 429，绿红由线程调度决定，
//! 正是 AGENTS 前言 ㉒ 禁止的形态）。竞态窗口内通过的请求会在构造点被同一把闸拒绝，
//! 两种结局都是 fail-closed，没有"放行到无上限"的分支。
//!
//! 路径判据取"以 `/export` 结尾"而不是 16 条硬编码：新增导出端点沿用既有命名即自动
//! 进闸；不沿用命名的会被 `export_path_predicate_covers_registered_routes` 从路由源码
//! 里逐条抓出来（判据的采集面由事实派生，不是名字清单）。

use crate::common::error::AppError;
use crate::common::resource_gate::{HeavyEntry, precheck};
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// 导出族路径判据（`/export` 后缀；见模块文档的"为什么不是硬编码清单"）。
pub fn is_export_path(path: &str) -> bool {
    path.ends_with("/export")
}

/// 导出路由前置闸：闸已满 ⇒ 429 + `Retry-After`，否则原样进入下游。
pub async fn export_gate_middleware(req: Request, next: Next) -> Result<Response, AppError> {
    if is_export_path(req.uri().path()) {
        precheck(HeavyEntry::ExcelExport)?;
    }
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// 路由表是**唯一采集面**：从 `src/router/*.rs` 里把每个 `/export` 字面量抓出来，
    /// 逐条过判据；少于 16 条即拒绝判据（扫不全 ≠ 没缺口）。
    #[test]
    fn export_path_predicate_covers_registered_routes() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/router");
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("router 目录必须可读（采集面坏了）")
        {
            let path = entry.expect("读目录项失败").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("router 文件必须可读");
            for part in text.split('"') {
                if part.starts_with('/') && part.ends_with("/export") {
                    paths.push(part.to_string());
                }
            }
        }
        paths.sort();
        paths.dedup();
        assert!(
            paths.len() >= 16,
            "导出路由采集面只有 {} 条（<16 ⇒ 扫描器走偏，不得据此判通过）: {paths:?}",
            paths.len()
        );
        for p in &paths {
            assert!(is_export_path(p), "导出路由不在前置闸采集面: {p}");
        }

        // 反证：相似但非导出路径不得被误伤（后缀判据只认 `/export` 整段）
        for p in [
            "/system/user",
            "/system/user/exportAll",
            "/system/exporters",
            "/uploads/1/file.png",
        ] {
            assert!(!is_export_path(p), "不得把非导出路径纳入前置闸: {p}");
        }
    }

    /// 接线反查：中间件必须真的挂在受保护路由上，且 `precheck` 排在 `next.run` 之前。
    /// 只测"函数存在"等于没测——挂没挂、先后顺序才是这条判据要回答的问题。
    #[test]
    fn export_gate_is_mounted_and_runs_before_the_handler() {
        fn has_code_line(src: &str, needle: &str) -> bool {
            src.lines().any(|line| {
                let t = line.trim_start();
                !t.starts_with("//") && t.contains(needle)
            })
        }
        fn precheck_is_after_handler(text: &str) -> bool {
            match (text.find("precheck("), text.find("next.run(req)")) {
                (Some(gate), Some(work)) => gate > work,
                _ => false,
            }
        }

        let router_src = include_str!("../router/mod.rs");
        assert!(
            has_code_line(router_src, ".route_layer(from_fn(export_gate_middleware))"),
            "router/mod.rs 没有把 export_gate_middleware 挂上受保护路由 ⇒ 前置闸是死代码"
        );
        // 正控：同一句写在注释里不得被当成接线；真实代码行必须放行
        assert!(!has_code_line(
            "// .route_layer(from_fn(export_gate_middleware))",
            ".route_layer(from_fn(export_gate_middleware))"
        ));
        assert!(has_code_line(
            "        .route_layer(from_fn(export_gate_middleware))",
            ".route_layer(from_fn(export_gate_middleware))"
        ));

        let text = crate::common::prod_scan::prod_file(
            "src/middleware/export_gate.rs",
            &crate::common::prod_scan::Scan::default(),
        )
        .text();
        let gate = text
            .find("precheck(")
            .expect("生产码里没有 precheck 调用点（前置闸被删了）");
        let work = text
            .find("next.run(req)")
            .expect("生产码里没有 next.run（本锁的对照失效）");
        assert!(
            gate < work,
            "前置拒绝必须排在 next.run 之前，否则请求已经进 handler 才被拒"
        );
        assert!(
            !precheck_is_after_handler("precheck(x); next.run(req);"),
            "合规顺序不得被误报"
        );
        assert!(
            precheck_is_after_handler("next.run(req); precheck(x);"),
            "顺序反例必须能被同一条判据抓到"
        );
    }
}
