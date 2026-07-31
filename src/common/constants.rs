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
