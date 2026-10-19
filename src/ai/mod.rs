//! AI 助手（NL2SQL Copilot）模块
//!
//! 方案锚点：`docs/optimization/topic-ai-nl2sql-final-2026-09-23.md`（对 v1→v4 四版方案的最终核查定稿）。
//! v4.1 增量（多租户三层开关 / SSO-PAT 限制 / UX 约束）的落地裁决记录见
//! `docs/optimization/all-topics-open-items-2026-09-26.md`。
//!
//! 安全模型（缺一不可）：
//! 1. **三层开关**：`[ai].enabled`（平台）→ 能力位 `ai.copilot`（租户）→ `ai:chat`（角色）；
//! 2. **PAT 拒绝**（v4.1-B2）：非交互式 token 不获得 AI 会话；
//! 3. **SQL 守卫**（[`sql_guard`]）：仅 SELECT / 单语句 / 表白名单 / 租户过滤强制 / LIMIT；
//! 4. **租户隔离**（v4.1-A3）：非平台调用者的 SQL 必须含 `tenant_id` 过滤（提示词强制 + 守卫兜底）；
//! 5. **行数上限**：守卫注入 `LIMIT`（`[ai].max_rows`）；
//! 6. **资源上限**（b72，AGENTS A.2）：推理并发闸 [`gate`]，闸满立即 429（不排队、不降级）。

pub mod config_service;
pub mod gate;
pub mod handler;
pub mod provider;
pub mod service;
pub mod sql_guard;

/// 能力位键（与 `governance::FEATURES` 登记项逐字一致）
pub const FEATURE_AI_COPILOT: &str = "ai.copilot";

/// AI 助手菜单（menu_id=4100）的权限标识。
///
/// `ai:chat` 是普通业务权限（非平台专属下放项，`unlocked = &[]`），经菜单 4100 的
/// role_menu 授权即可；进程级 `[ai].enabled` 与租户能力位 `ai.copilot` 关闭时，
/// 服务层 403 + getRouters 剪除菜单（`prune_capability_gated_menus`）双管齐下，
/// 消除"菜单可见但请求 403"的假入口。常量化避免字符串散落（getRouters 剪除判定
/// 与 permission_middleware 路由映射须同字面值）。
pub const AI_CHAT_PERM: &str = "ai:chat";
