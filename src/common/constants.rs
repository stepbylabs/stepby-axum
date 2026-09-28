// axum-backend/src/common/constants.rs

//! 项目级常量定义
//!
//! 集中管理超管 ID 等常量，避免硬编码导致维护期回归。

/// 超级管理员用户 ID
pub const SUPER_ADMIN_USER_ID: i64 = 1;

/// 超级管理员角色 ID
pub const SUPER_ADMIN_ROLE_ID: i64 = 1;

/// 批量操作（删除/导出/分配等）单次允许的最大 ID 数量
///
/// R8-API-005：覆盖角色/岗位/通知/字典/用户等所有批量端点，
/// 防止恶意提交 `ids=1,2,3,...,100000` 导致：
/// - 服务 OOM（解析超大 Vec）
/// - 长事务拖垮 DB（批量 DELETE 持有锁过久）
/// - 接口间行为不一致（部分接口无上限校验）
///
/// 100 个 ID 覆盖正常批量操作场景，超出应分批调用。
pub const MAX_BATCH_DELETE_SIZE: usize = 100;

/// 每小时秒数（用于 JWT TTL、时间格式化等场景，避免硬编码 3600）
pub const SECS_PER_HOUR: i64 = 3600;

/// 每天秒数（用于时长格式化、日志保留期等场景，避免硬编码 86400）
pub const SECS_PER_DAY: i64 = 86400;

/// 每分钟秒数（用于时长格式化场景，避免硬编码 60）
pub const SECS_PER_MIN: i64 = 60;

/// 日志保留天数（定时清理任务用）
pub const LOG_RETENTION_DAYS: i64 = 90;

/// 登录异常检测窗口（分钟）：扫描最近 N 分钟的登录失败记录
pub const LOGIN_ANOMALY_WINDOW_MINS: i64 = 5;

/// 撞库攻击判定阈值：N 分钟内同一 IP 登录失败次数 >= 此值视为撞库
pub const CREDENTIAL_STUFFING_THRESHOLD: i64 = 5;

/// 撞库告警去重窗口（分钟）：同一 IP 在此时间内不重复告警
pub const CREDENTIAL_STUFFING_DEDUP_MINS: i64 = 30;

/// mmdb 热加载分布式锁 TTL（秒）
pub const MMDB_LOCK_TTL_SECS: u64 = 30 * 60;

/// 下拉列表/批量查询的最大返回行数
pub const DROPDOWN_MAX_ROWS: u64 = 500;

/// mmdb 文件最小合法大小（字节，1MB），小于此值视为损坏
pub const MMDB_MIN_FILE_SIZE: usize = 1024 * 1024;

/// 密码长度阈值（字符数）
pub const PASSWORD_LEN_MIN: usize = 8;
pub const PASSWORD_LEN_STRONG: usize = 12;

/// 验证码图片尺寸（像素）
pub const CAPTCHA_IMG_WIDTH: u32 = 220;
pub const CAPTCHA_IMG_HEIGHT: u32 = 120;

/// 验证码噪点数量
pub const CAPTCHA_NOISE_DOTS: usize = 100;

/// 静态资源长期不可变缓存（秒，1 年）
pub const CACHE_IMMUTABLE_SECS: &str = "public, max-age=31536000, immutable";

/// Swagger UI 静态资源缓存（秒，5 分钟）
pub const CACHE_SWAGGER_SECS: &str = "public, max-age=300";

/// 头像上传最大大小（字节，5MB）
pub const AVATAR_MAX_SIZE: usize = 5 * 1024 * 1024;

/// 通用文件上传最大大小（字节，10MB）
pub const UPLOAD_MAX_SIZE: usize = 10 * 1024 * 1024;

/// 邮件 SMTP 发送超时（P1：防止 SMTP 无响应时无限挂起拖住请求）
pub const MAIL_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `sys_job.cron_expression` 列宽 / DTO 校验上限（字符数）。
///
/// 为什么必须是 64 而不是建表语句里的 255：`migration/src/m20260719_000001_adjust_field_length.rs`
/// 对**所有安装形态**把该列收窄到 64（存量库 `ALTER`；新库先建 255 再收窄 ⇒ 终态一致）。
/// DTO 若仍按 255 校验，则 65~255 字符的表达式会**通过校验后**在落库时报错（500），
/// 用户看到的是"系统错误"而不是"参数过长"。此处对齐为 64，把失败提前成可诊断的 400。
///
/// ⚠️ 该值与 migration 的 64 属**跨 crate 约定**（migration 不依赖 axum-backend，
/// 无法直接引用本常量）——改宽度必须同时改迁移文件。
/// 64 字符对 Quartz 风格表达式（含 `MON-FRI` 与年份字段）绰绰有余。
pub const CRON_EXPRESSION_MAX_LEN: usize = 64;

// ==================== 菜单类型（sys_menu.menu_type 取值域） ====================

/// `sys_menu.menu_type` 的取值域 —— **单一事实源**。
///
/// R6-RUST-10：这三个字面量此前在 `auth_service` / `sys_menu_service` /
/// `sys_tenant_nav_service` 三处各写一遍（其中一处还自建了局部数组 `NAV_MENU_TYPES`），
/// 拼错一个字母不会报错、只会**静默走错分支**（例如把 `"C"` 写成 `"c"` ⇒ 菜单被当成按钮过滤掉）。
/// 收敛到此处后，各调用点只引用常量。
///
/// 为什么不抽 enum：`menu_type` 允许**未登记取值**（历史数据 / 第三方导入 / 手改库），
/// 现有实现把它们一律当作"既不是目录也不是菜单"（既不加 Layout/ParentView，也满足 `!= "C"`）。
/// 改成 enum 必须额外引入 `Unknown` 变体才能保持同一语义，换来仅是穷尽性检查，不值当；
/// 而常量化已消除"拼写不一致"这一真实风险。
///
/// 取值为**数据库持久化契约**（有单测锁死），不得改动；改动等于静默改变所有存量数据的语义。
pub mod menu_type {
    /// 目录（Directory）：仅承载子路由，不渲染页面组件（`component` 走 Layout / ParentView）
    pub const DIR: &str = "M";
    /// 菜单（Menu）：渲染 `component` 的页面
    pub const MENU: &str = "C";
    /// 按钮（Button）：仅作为权限点（`perms`），**不进路由树**
    pub const BUTTON: &str = "F";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 取值是**数据库持久化契约**：被改掉会静默改变全部存量菜单的语义
    #[test]
    fn test_menu_type_values_are_persisted_contract() {
        assert_eq!(menu_type::DIR, "M");
        assert_eq!(menu_type::MENU, "C");
        assert_eq!(menu_type::BUTTON, "F");
        // 三者互不相同：否则"目录 / 菜单 / 按钮"的分支会互相吞掉
        assert_ne!(menu_type::DIR, menu_type::MENU);
        assert_ne!(menu_type::MENU, menu_type::BUTTON);
        assert_ne!(menu_type::DIR, menu_type::BUTTON);
    }
}
