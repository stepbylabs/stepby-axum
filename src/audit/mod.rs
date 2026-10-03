// stepby-axum/src/audit/mod.rs
//! 审计合规域（audit compliance）
//!
//! 数据变更留痕 + 操作日志防篡改链校验的独立域模块：
//! - `handler`：变更留痕查询 / 详情 / CSV 导出接口
//! - `router`：域路由器（merge 挂载点见 `src/router/mod.rs` 集成片段）

pub mod handler;
pub mod router;
