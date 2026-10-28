// stepby-axum/src/shared_store/mod.rs
//! 共享态存储抽象（SharedStore）——`[cache].mode = local | redis` 双档架构
//!
//! 方案：`docs/optimization/ZERO-DEPENDENCY-DEPLOYMENT-PLAN-2026-10-01.md` v5.1。
//!
//! # 四级安全语义（键的丢失后果决定实现与验收分级）
//!
//! | 级别 | 键族 | 丢失后果 | local 档承载 |
//! |---|---|---|---|
//! | S1 安全态 | `blacklist:{hash}`、`pwd_ver:{uid}`、`tenant:state/exp:{tid}`、历史 `sso:at` 阻断 | **复活/越权**（已吊销/改密/停用/删除/停用租户的令牌复活） | DB 权威层（`sys_token_revocation` + `sys_user.password_version` + `sys_tenant` 求值） |
//! | S2 一次性/短期态 | `captcha:*`、`online:*`、`user_sessions:*`、`sso:code/rt/at:*`、幂等槽、`ws_conn:*`、`login_fail:*` | 失效/重置（无越权后果） | `sys_shared_kv`（TTL=expire_at 列） |
//! | S3 性能缓存 | 权限/配置/字典/菜单/角色/host 等 cache-aside | 仅变慢 | **直通 no-op**（不缓存不算失败） |
//! | S4 观测运维 | health PING / metrics INFO / 缓存监控 scan | 无 | 按档位适配 |
//!
//! # 档位与切换
//!
//! - `auto`（默认）：`[redis].url` 有效 → redis 档；缺省/占位符 → local 档
//! - `local`：纯 SQL 承载（与业务同库），S1/S2 天然持久且多实例可共享
//! - `redis`：现状命令；**S1 写路径双写 DB 权威层** + 启动期幂等回填 → 档位切换无缝
//!
//! # 接口纪律
//!
//! - 按语义建模（`auth_gate_check` / `revoke_session`），不按 Redis 命令建模——
//!   把 Set 索引、SCAN 兜底、Lua CAS 等**实现细节封进实现**，调用点不感知档位；
//! - `consume`（GETDEL）与 `set_nx_ex`（SETNX）是两种不可合并的原子语义；
//! - 新增任何共享态用途必须先归入本 trait 方法集，**禁止直接 `redis.clone()` 裸调用**。

pub mod gc;
pub mod local_store;
pub mod redis_store;

use sea_orm::ConnectionTrait;

/// 清理 `sys_token_revocation` 中已过期的吊销行（调度任务 `tokenRevocationCleanup` 用）
///
/// 全链路核查补录（2026-10-04）：该表是登出/强退/SSO 旧版吊销的 **S1 安全态 DB 权威层**，
/// 读路径虽有 `expire_at` 过滤 + 索引兜底保证正确性，但过期行此前无任何删除路径，
/// 会随登出/强退次数无限累积。两档 SharedStore 共用本权威层（redis 档 SETEX 自过期 +
/// DB 双写），清理仅针对 DB 行；redis 键由 TTL 自行过期，无需干预。
///
/// 三方言 `DELETE ... WHERE expire_at <= <epoch>` 语法一致；时间戳为服务端 i64 整数
/// （无注入面），故直接拼接而非参数绑定。
/// 锁定类响应的 `Retry-After` 剩余秒数（失败计数键族共用：TOTP verify / TOTP enable / 登录链）。
///
/// 三条口径都是设计而非巧合：
/// 1. **读提示失败绝不改变结论**。是否锁定由调用方的 `get` 判定，本函数只补一个头，
///    因此 `Err`/`None` 一律回落到窗口上限（保守侧），绝不放行、也绝不发 0。
/// 2. 下限 1 秒：`ttl` 可能返回 0（即将过期），0 会被客户端读成"立即可重试"。
/// 3. 上限 `window_secs`：跨实例时钟偏移让 `expire_at` 落在未来时，宁可多提示也不给出
///    一个比窗口还长的承诺（那会把 5 分钟的窗口说成 500 分钟）。
pub async fn lockout_retry_after_secs(store: &dyn SharedStore, key: &str, window_secs: u64) -> u64 {
    match store.ttl(key).await {
        Ok(Some(secs)) => (secs.max(0) as u64).clamp(1, window_secs.max(1)),
        _ => window_secs.max(1),
    }
}

pub async fn cleanup_expired_token_revocations(
    db: &sea_orm::DatabaseConnection,
) -> Result<u64, sea_orm::DbErr> {
    let now_epoch = chrono::Utc::now().timestamp();
    let res = db
        .execute_raw(sea_orm::Statement::from_string(
            db.get_database_backend(),
            format!("DELETE FROM sys_token_revocation WHERE expire_at <= {now_epoch}"),
        ))
        .await?;
    Ok(res.rows_affected())
}

use async_trait::async_trait;

pub use local_store::LocalStore;
pub use redis_store::RedisStore;

/// 共享态存储错误（实现层统一错误；调用方按既有口径 map 到 `ServiceError`/`AppError`）
///
/// i18n 豁免：Display 串仅进日志（如 `monitor_cache_handler::map_scan_error` 写
/// `tracing::error!` 后返回翻译键 `error.common.cache_failed`；`sys_tenant_service`
/// 的运行时键写入仅 `tracing::warn!`）——本枚举不直达 HTTP 响应体；
/// 且 thiserror `#[error]` 于 Display 上下文运行，无 locale 作用域，不适配 t!。
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// 后端操作失败（Redis 命令错误 / SQL 错误）
    #[error("共享态后端操作失败: {0}")]
    Backend(String),
    /// 序列化/反序列化失败（绑定 JSON 损坏等）
    #[error("共享态数据损坏: {0}")]
    Corrupted(String),
}

impl StoreError {
    pub fn backend<E: std::fmt::Display>(e: &E) -> Self {
        Self::Backend(e.to_string())
    }
}

/// auth 中间件闸门检查快照（每请求一次，语义对齐原 Redis pipe 5 键）
///
/// 判定代码（`middleware/auth.rs`）保持不变，仅取数方式切换：
/// - `blacklisted`：`blacklist:{token_hash}` 命中（登出/踢线/租户停用拉黑）
/// - `sso_at_bound`：`sso:at:{token_hash}` 命中（历史 JWT 型 SSO AT 阻断，v4-F1 第二道）
/// - `pwd_ver`：`pwd_ver:{uid}` 当前值（None = 未设置；判定 `存储值 > claim.pwd_ver` 则拒绝）
/// - `tenant_state` / `tenant_expire`：租户运行时键原值（None = 键缺失 = Active；
///   tid=0 平台租户不查询，两字段恒 None）；local 档由 DB 求值给出等价值
#[derive(Debug, Clone)]
pub struct AuthGate {
    pub blacklisted: bool,
    pub sso_at_bound: bool,
    pub pwd_ver: Option<u64>,
    pub tenant_state: Option<String>,
    pub tenant_expire: Option<i64>,
}

/// 锁句柄（数据 only；释放/续期经 [`SharedStore`] 方法，供 RAII 守卫在 Drop 中
/// spawn 异步执行——与 `scheduler/mod.rs` 既有守卫范式一致）
#[derive(Debug, Clone)]
pub struct LockHandle {
    /// 锁键（如 `lock:scheduler:{job_id}`）
    pub key: String,
    /// 本实例的 fencing token（UUID v4；CAS 释放/续期必须匹配）
    pub token: String,
}

/// 共享态存储 trait（双实现：[`RedisStore`] / [`LocalStore`]）
#[async_trait]
pub trait SharedStore: Send + Sync {
    /// 档位标识："redis" | "local"
    fn kind(&self) -> &'static str;

    // ══ S1 认证闸门（auth 中间件每请求一次）══

    /// 闸门快照（原 pipe 5 键的语义收敛）。
    /// redis 档：单次 Pipeline（现状等价）；local 档：2-3 条 PK 点查（微秒级）。
    async fn auth_gate_check(
        &self,
        token_hash: &str,
        uid: &str,
        tid: i64,
    ) -> Result<AuthGate, StoreError>;

    /// 登记吊销（blacklist / 历史 SSO AT 阻断）。
    /// redis 档 = SETEX Redis（现状）+ DB 权威层幂等落库（双写）；local 档 = INSERT OR IGNORE DB。
    /// `exp_at`：UTC 秒。
    async fn revocation_add(
        &self,
        token_hash: &str,
        exp_at: i64,
        source: &str,
    ) -> Result<(), StoreError>;

    /// 密码版本号递增（改密/重置/停用/删除）。
    /// redis 档 = INCR Redis + DB 列 max 同步（双写）；local 档 = 事务内 SELECT+UPDATE DB 列。
    /// 返回递增后的新版本号。
    async fn pwd_ver_incr(&self, uid: &str) -> Result<u64, StoreError>;

    /// 读取当前密码版本号——**必须与 [`SharedStore::auth_gate_check`] 读同一事实源**。
    ///
    /// 登录签发 JWT 时写入 claim 的 `pwd_ver` 就是闸门下一请求要比对的版本号；两处若各读
    /// 一个源（b104 前的现实：登录读 DB 列、redis 档闸门读 Redis 键），双写任一侧失败都会
    /// 让新签发的令牌**当场被自己的闸门拒绝**——且 DB 列落后是永久的（`+1` 同步不会追平），
    /// 该账号此后每次登录都 401，只能人工修库。
    ///
    /// 返回口径与闸门一致：`None` = 未设置（按 0 处理）/ 行不存在；损坏值同闸门按 `None`。
    async fn pwd_ver_read(&self, uid: &str) -> Result<Option<u64>, StoreError>;

    /// **凭据撤权的唯一出口**（改密 / 重置 / 停用 / 删除 / 匿名化）：先递增密码版本号，
    /// 再全量吊销该用户的 SSO 访问令牌。
    ///
    /// 两条腿缺一不可、且**任一步失败都必须上抛**：
    /// - `pwd_ver` 不约束不透明 SSO AT（userinfo 只认绑定），只递增版本号等于把 AT 留着；
    /// - 只吊销 SSO AT 而不递增版本号，平台 JWT 会继续通过闸门——而 auth 中间件**不查**
    ///   `sys_user.status`，"已停用"的账号因此仍可全功能访问。
    ///
    /// 调用方**不得**把失败降级成 WARN 后照常返回成功（b104 前四处如此）：那等于对管理员
    /// 宣布"已停用/已改密"而旧会话仍然可用。失败后的重试必须由调用方保证可重放
    /// （停用/重置可重复提交；删除/匿名化须把撤权排在破坏性写入**之前**）。
    async fn revoke_credentials(&self, uid: &str) -> Result<(), StoreError> {
        self.pwd_ver_incr(uid).await?;
        self.revoke_all_for_user(uid).await?;
        Ok(())
    }

    // ══ S2 一次性/短期态 ══

    /// 读取（S2 会话绑定 / S3 cache-aside 通用 GET）
    async fn get(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// 写入并带 TTL（S3 cache-aside 通用 SETEX；S2 短期态写入）
    async fn set_ex(&self, key: &str, val: &str, ttl_secs: u64) -> Result<(), StoreError>;

    /// 原子抢占（SET NX EX；幂等槽位/互提醒窗）。返回 true = 抢占成功（首次）。
    async fn set_nx_ex(&self, key: &str, val: &str, ttl_secs: u64) -> Result<bool, StoreError>;

    /// 原子取删（GETDEL；验证码/SSO 授权码/RT 轮换的防重放消耗）。
    /// redis 档 = GETDEL（需 ≥6.2）；local 档 = 事务内 SELECT+DELETE。
    async fn consume(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// 删除（单/多键统一；返回实际删除条数）
    async fn del(&self, keys: &[String]) -> Result<u64, StoreError>;

    /// 批量读（单次往返/单次锁；覆盖 sso token_refresh 的双键 GET 等）
    async fn get_many(&self, keys: &[String]) -> Result<Vec<Option<String>>, StoreError>;

    /// 原子自增（首次自增时设置 TTL；登录失败锁定/IP 限流计数——原 INCR+EXPIRE Lua 语义）
    async fn incr_with_ttl(&self, key: &str, ttl_secs: u64) -> Result<i64, StoreError>;

    /// 剩余存活秒数（`Retry-After` 的事实源；原 INCR+EXPIRE 语义里"TTL 从首次自增起算"）。
    ///
    /// 返回口径（调用方**必须**按"取不到就回落到配置窗口上限"处理，不得因读不到而放行）：
    /// - `Ok(Some(n))`：键存在且带过期，剩余 `n` 秒（`n` 可能为 0，表示即将过期）；
    /// - `Ok(None)`：键不存在，或键存在但**永不过期**（`expire_at = NULL` / Redis TTL = -1）；
    /// - `Err`：后端读失败。锁定判定本身已由 `get` 完成，这里只补一个提示值，
    ///   因此读失败**不改变**拒绝结论，只是把提示退回窗口上限（保守侧）。
    ///
    /// redis 档 = `TTL` 命令（-1 永不过期 / -2 不存在，两档都归一到 `None`）；
    /// local 档 = 读 `sys_shared_kv.expire_at` 与服务端时钟作差（与 `is_expired` 同一口径）。
    async fn ttl(&self, key: &str) -> Result<Option<i64>, StoreError>;

    /// 原子自减（**连接计数专用**：`ws_conn:{uid}` 连接关闭侧递减，其它键族禁用——
    /// 本方法不携带 TTL 语义，且减到 ≤0 即删键）。
    /// - redis 档 = DECR + 条件 DEL（原 `ws_handler.rs` Lua 语义）；
    /// - local 档 = 事务内 SELECT + UPDATE-1，减到 ≤0 删除行；
    /// - 键不存在（或已过期）返回 -1（对齐 Redis DECR 空键语义，调用方照原逻辑忽略返回值）。
    async fn decr(&self, key: &str) -> Result<i64, StoreError>;

    /// 分布式锁获取（SETNX + UUID fencing token）。
    /// - redis 档：`SET NX EX`（release/renew 走 Lua CAS，现状等价）
    /// - local 档：`sys_shared_lock` 单语句 CAS
    /// 返回 None = 已被持有（本次跳过）；TTL 到期后其他持有者可抢占。
    async fn lock_acquire(
        &self,
        key: &str,
        ttl_secs: u64,
    ) -> Result<Option<LockHandle>, StoreError>;

    /// 释放锁（CAS：仅当 token 匹配才删除，防误删他实例的锁）
    async fn lock_release(&self, handle: &LockHandle) -> Result<(), StoreError>;

    /// 续期锁（CAS：仅当 token 匹配才延长 TTL；返回 false = 锁已被他人持有/过期）
    async fn lock_renew(&self, handle: &LockHandle, ttl_secs: u64) -> Result<bool, StoreError>;

    // ══ 吊销语义（原三键 Lua / Set 索引 + SCAN 兜底的语义收敛）══

    /// 强退/踢线单会话：blacklist 登记 + online 删除 + sso:at 删除（同生共死）。
    /// redis 档 = 原 Lua 三键（现状等价）；local 档 = 单事务（S1/S2 同库真原子）。
    async fn revoke_session(&self, token_hash: &str, blacklist_ttl: u64) -> Result<(), StoreError>;

    /// 全量吊销某用户的 SSO 令牌（登出/改密/GDPR 匿名化）：
    /// 覆盖 `sso:user_at:{uid}` / `sso:user_rt:{uid}` 集合（EXISTS 悬空自愈语义封进实现）。
    /// 返回吊销的令牌数。
    async fn revoke_all_for_user(&self, uid: &str) -> Result<u64, StoreError>;

    // ══ 集合索引（SSO「用户 → 已签发令牌」吊销索引 / 登录会话索引）══
    // 原实现为裸 Redis SADD/SREM/SMEMBERS + EXPIRE 两段式；迁移后调用点（sso_service）
    // 经本组方法写入/读取，禁止档位感知。

    /// 集合添加成员并刷新 TTL（原 `SADD + EXPIRE ttl` 两段式语义，两段合并）。
    /// - redis 档：SADD + EXPIRE 单次 pipe（与原两段式逐字节等价）；
    /// - local 档：`sys_shared_kv` JSON 数组 get→append→set_ex（非原子，
    ///   并发窗口说明见 [`LocalStore::set_add`] 实现注释；SCAN 全量吊销路径兜底）。
    async fn set_add(&self, key: &str, member: &str, ttl_secs: u64) -> Result<(), StoreError>;

    /// 集合移除成员（原 SREM 语义；集合变空时等价 Redis「空集合键自动消失」）。
    /// - redis 档：SREM；local 档：JSON 数组 remove→回写/删键。
    async fn set_rem(&self, key: &str, member: &str) -> Result<(), StoreError>;

    /// 集合全量成员（原 SMEMBERS 语义；键不存在返回空集）。
    /// - redis 档：SMEMBERS；local 档：JSON 数组解析。
    async fn set_members(&self, key: &str) -> Result<Vec<String>, StoreError>;

    // ══ S4 运维 ══

    /// 模式匹配键扫描。
    /// - `max = Some(n)`：**截断版**（只读展示/列表，达到上限即停——`utils::redis::scan_keys` 语义）
    /// - `max = None`：**全量版**（安全吊销必须扫到尾——`scan_keys_all` 语义；禁止用于展示）
    async fn scan(&self, pattern: &str, max: Option<usize>) -> Result<Vec<String>, StoreError>;

    /// 存活探测（health 用；local 档 = 探测 DB 可用性）
    async fn ping(&self) -> Result<(), StoreError>;

    /// 运行摘要（`/metrics` 用）：redis 档 = INFO 精简文本；local 档 = 条目/锁/吊销行计数
    async fn info_summary(&self) -> Result<String, StoreError>;
}

/// 模式匹配（local 档 SCAN 用）：仅支持项目实际使用的 `前缀*` / `*后缀` / `前缀*后缀` 形态
/// （Redis 键规范如 `sso:rt:*`、`online:*`、`user_sessions:1:*`）；含多个 `*` 时按段通配。
pub fn glob_match(pattern: &str, key: &str) -> bool {
    let p: Vec<&str> = pattern.split('*').collect();
    if p.len() == 1 {
        return pattern == key;
    }
    // 首段必须前缀匹配，尾段必须后缀匹配，中段按顺序贪心查找
    if !key.starts_with(p[0]) {
        return false;
    }
    let mut rest = &key[p[0].len()..];
    let last = p[p.len() - 1];
    if !rest.ends_with(last) {
        return false;
    }
    rest = &rest[..rest.len() - last.len()];
    for seg in &p[1..p.len() - 1] {
        if seg.is_empty() {
            continue;
        }
        match rest.find(seg) {
            Some(idx) => rest = &rest[idx + seg.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_covers_project_patterns() {
        // 项目实际使用的键模式形态
        assert!(glob_match("sso:rt:*", "sso:rt:abc123"));
        assert!(glob_match("online:*", "online:deadbeef"));
        assert!(glob_match(
            "user_sessions:1:*",
            "user_sessions:1:10.0.0.1:chrome"
        ));
        assert!(glob_match("ws_conn:*", "ws_conn:42"));
        assert!(glob_match("blacklist:*", "blacklist:ff00"));
        assert!(glob_match("*", "anything:here"));
        assert!(!glob_match("sso:rt:*", "sso:at:abc123"));
        assert!(!glob_match("online:*", "blacklist:deadbeef"));
        // 精确匹配（无通配符）
        assert!(glob_match("captcha:x:y", "captcha:x:y"));
        assert!(!glob_match("captcha:x:y", "captcha:x:z"));
    }
}
