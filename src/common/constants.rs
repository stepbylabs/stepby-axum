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
