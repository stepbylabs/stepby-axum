// stepby-axum/src/shared_store/redis_store.rs
//! SharedStore 的 redis 档实现——语义与项目现有 Redis 调用**逐字节等价**
//!
//! 照搬来源清单（改动前必须核对原文，勿凭记忆改脚本）：
//! - [`RedisStore::auth_gate_check`]：`middleware/auth.rs:99-141` 单次 pipe
//!   （GET blacklist / pwd_ver / sso:at [+ tenant:state / tenant:exp]，tid!=0 才追加）；
//!   值语义：blacklist/sso:at 命中即 true；pwd_ver 解析 u64（失败按 None）；
//!   tenant 键缺失为 None。3s 命令级超时由 `utils::redis::cmd_timeout` 统一保证
//!   （`db::redis::REDIS_CMD_TIMEOUT_SECS`，与 auth.rs 的显式 tokio timeout 等价）。
//! - [`RedisStore::revoke_session`]：`handler/monitor_online_handler.rs:44-49`
//!   FORCE_LOGOUT_SCRIPT **原样复制**（Lua 三键：SETEX blacklist + DEL online + DEL sso:at）。
//! - [`RedisStore::incr_with_ttl`]：`service/auth_service.rs:64-70` RATE_LIMIT_SCRIPT
//!   **原样复制**（INCR + 首次 EXPIRE 原子化，防止计数永驻）。
//! - [`RedisStore::set_nx_ex`]：`middleware/idempotency.rs:147-156`（SET key val NX EX）。
//! - [`RedisStore::consume`]：GETDEL（`service/auth_service.rs:839` 验证码、
//!   `service/sso_service.rs:1463` RT 轮换同款，需 Redis ≥ 6.2）。
//! - 锁：`scheduler/cluster.rs:120-129`（SET NX EX + UUID fencing token）与
//!   `scheduler/mod.rs:1109-1157`（release = GET+DEL CAS / renew = GET+EXPIRE CAS，
//!   两段 Lua **原样复制**）。
//! - [`RedisStore::scan`]：直接复用 `utils/redis.rs` 的 `scan_keys`（截断版，
//!   达上限即停）/ `scan_keys_all`（全量版，扫到游标归零）。
//! - [`RedisStore::revoke_all_for_user`]：`service/sso_service.rs:2510-2572`
//!   `revoke_user_sso_tokens` 语义（SMEMBERS 两个集合 + EXISTS 悬空自愈 +
//!   逐键删除绑定与 online + DEL 整个索引键），返回真实吊销数。
//! - [`RedisStore::set_add`] / [`SharedStore::set_rem`] / [`SharedStore::set_members`]：SADD+EXPIRE /
//!   SREM / SMEMBERS（原 sso_service 签发点与吊销点的裸命令收敛进 trait）。
//!
//! # S1 双写（本档关键新语义，v5.1 方案）
//!
//! - `revocation_add` / `revoke_session` 在 SETEX blacklist 之外**幂等落库**
//!   `sys_token_revocation`（已有行取 expire_at 更大值）；`pwd_ver_incr` 在 INCR 之外
//!   把 `sys_user.password_version` **单调收敛到本次实时值**（b104：原 `+1` 会让一次失败的
//!   双写变成永久落差）；
//! - DB 写失败**仅 tracing::warn 不返回错误**——Redis 已保证当期安全，落库只为档位切换；
//! - 启动期调用 [`RedisStore::bootstrap_from_db`] 从 DB 权威层幂等回填 Redis
//!   （吊销行 → blacklist 键；password_version 列 → pwd_ver 键），实现双档无缝切换。

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use sea_orm::{ActiveModelTrait, ConnectionTrait, DatabaseConnection, EntityTrait, Set, Statement};

use crate::entity::sys_token_revocation;
use crate::shared_store::{AuthGate, LockHandle, SharedStore, StoreError};

/// 强退/踢线三键 Lua（原样复制自 `handler/monitor_online_handler.rs:44-49` FORCE_LOGOUT_SCRIPT）
///
/// `KEYS[1]` = blacklist:{token_hash}, `KEYS[2]` = online:{token_hash},
/// `KEYS[3]` = sso:at:{token_hash}（平台会话无该 key，DEL no-op 无害）；`ARGV[1]` = 黑名单 TTL
const FORCE_LOGOUT_SCRIPT: &str = r#"
redis.call("SETEX", KEYS[1], ARGV[1], "1")
redis.call("DEL", KEYS[2])
redis.call("DEL", KEYS[3])
return 1
"#;

/// 限流原子化脚本（原样复制自 `service/auth_service.rs:64-70` RATE_LIMIT_SCRIPT）：
/// INCR + 首次 EXPIRE 原子执行，防止计数永不过期
const RATE_LIMIT_SCRIPT: &str = r#"
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"#;

/// 连接计数自减 Lua（原样复制自 `handler/ws_handler.rs:156-162` decr_ws_conn_count）：
/// DECR → 判断 ≤0 → DEL 单次原子执行，避免并发关闭时的误删/漏删竞态
const CONN_DECR_SCRIPT: &str = r#"
local v = redis.call('DECR', KEYS[1])
if v <= 0 then
    redis.call('DEL', KEYS[1])
end
return v
"#;

/// 锁释放 Lua CAS（原样复制自 `scheduler/mod.rs:1109-1117` release_lock）：
/// 仅当锁 value 匹配本实例 fencing token 时才删除，防误删他实例的锁
const RELEASE_LOCK_SCRIPT: &str = r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
"#;

/// 锁续期 Lua CAS（原样复制自 `scheduler/mod.rs:1141-1148` renew_lock）：
/// 仅当锁 value 匹配时才延长 TTL，防止误续他实例的锁
const RENEW_LOCK_SCRIPT: &str = r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("EXPIRE", KEYS[1], ARGV[2])
else
    return 0
end
"#;

/// SSO 键前缀（与 `service/sso_service.rs:42-52` 常量同源，勿单独改动）
const AT_KEY_PREFIX: &str = "sso:at:";
const RT_KEY_PREFIX: &str = "sso:rt:";
const USER_AT_KEY_PREFIX: &str = "sso:user_at:";
const USER_RT_KEY_PREFIX: &str = "sso:user_rt:";

/// 当前 UTC 秒
fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// redis 档共享态存储（Redis 当期安全 + DB 权威层双写 + 启动回填）
pub struct RedisStore {
    /// Redis 连接管理器（内部自动重连；方法内 clone 后使用）
    conn: ConnectionManager,
    /// DB 权威层连接（S1 双写 / 启动回填）
    db: DatabaseConnection,
}

impl RedisStore {
    /// 构造（local/redis 两档由 initialize 的存储工厂接线）
    pub fn new(conn: ConnectionManager, db: DatabaseConnection) -> Self {
        Self { conn, db }
    }

    /// DB 权威层幂等落库（S1 双写核心）：`sys_token_revocation` 已有行取 expire_at 更大值
    ///
    /// - 失败仅 WARN 不上抛：Redis SETEX 已保证当期安全，落库只为档位切换后的回填源；
    /// - source 同步更新为本次来源（同一 hash 先后被 logout 与 sso_legacy_at 命中时，
    ///   两个判定标志均导致拒绝，归类取最后来源不损失安全性，见 mod.rs AuthGate 注释）。
    async fn upsert_revocation_db(&self, token_hash: &str, exp_at: i64, source: &str) {
        let res: Result<(), sea_orm::DbErr> = async {
            match sys_token_revocation::Entity::find_by_id(token_hash)
                .one(&self.db)
                .await?
            {
                Some(m) if exp_at > m.expire_at => {
                    // 已有行且新 expire_at 更大：UPDATE（max 语义）
                    let mut am: sys_token_revocation::ActiveModel = m.into();
                    am.expire_at = Set(exp_at);
                    am.source = Set(source.to_string());
                    am.update(&self.db).await?;
                }
                Some(_) => {} // 已有行 expire_at 不小于新值：幂等跳过
                None => {
                    let am = sys_token_revocation::ActiveModel {
                        token_hash: Set(token_hash.to_string()),
                        expire_at: Set(exp_at),
                        source: Set(source.to_string()),
                    };
                    sys_token_revocation::Entity::insert(am)
                        .exec(&self.db)
                        .await?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = res {
            tracing::warn!(
                token_hash,
                source,
                error = %e,
                "吊销记录 DB 权威层落库失败（Redis 已保证当期安全，仅告警不影响主流程）"
            );
        }
    }
}

#[async_trait]
impl SharedStore for RedisStore {
    fn kind(&self) -> &'static str {
        "redis"
    }

    /// 闸门快照：单次 Pipeline（现状等价，照搬 `middleware/auth.rs:99-177`）
    async fn auth_gate_check(
        &self,
        token_hash: &str,
        uid: &str,
        tid: i64,
    ) -> Result<AuthGate, StoreError> {
        let mut redis = self.conn.clone();
        let mut pipe = redis::pipe();
        // 前 3 键恒查：blacklist / pwd_ver / sso:at（token_hash 已由调用方算好，方法内不再 hash）
        pipe.cmd("GET")
            .arg(format!("blacklist:{token_hash}"))
            .cmd("GET")
            .arg(format!("pwd_ver:{uid}"))
            .cmd("GET")
            .arg(format!("{AT_KEY_PREFIX}{token_hash}"));
        // 租户键仅租户用户追加（tid=0 平台租户零开销）
        if tid != 0 {
            pipe.cmd("GET")
                .arg(crate::common::tenant::tenant_state_key(tid))
                .cmd("GET")
                .arg(crate::common::tenant::tenant_expire_key(tid));
        }
        // 命令级超时（3s，fail-closed 由调用方按 StoreError 判定）——与 auth.rs:114-126 等价
        let vals: Vec<Option<String>> =
            crate::utils::redis::cmd_timeout(pipe.query_async(&mut redis))
                .await
                .map_err(|e| {
                    tracing::error!(user_id = %uid, error = %e, "Redis 闸门查询失败（auth pipe）");
                    StoreError::backend(&e)
                })?;
        // 值语义照搬 auth.rs:136-177
        Ok(AuthGate {
            // blacklist 命中即拉黑（登出/踢线/租户停用）
            blacklisted: vals.first().cloned().flatten().is_some(),
            // 历史 JWT 型 SSO AT 绑定命中即过渡阻断（v4-F1 第二道）
            sso_at_bound: vals.get(2).cloned().flatten().is_some(),
            // pwd_ver 解析 u64，解析失败按 None（未设置）
            pwd_ver: vals
                .get(1)
                .cloned()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok()),
            // 租户键缺失为 None；tid=0 恒 None
            tenant_state: (tid != 0).then(|| vals.get(3).cloned().flatten()).flatten(),
            // 不可解析按 None（调用端视为 0 = 永不过期，与 auth.rs:172-177 unwrap_or(0) 等价）
            tenant_expire: (tid != 0)
                .then(|| {
                    vals.get(4)
                        .cloned()
                        .flatten()
                        .and_then(|s| s.parse::<i64>().ok())
                })
                .flatten(),
        })
    }

    /// 登记吊销：SETEX `blacklist:{hash}`（现状）+ DB 权威层幂等落库（S1 双写）
    async fn revocation_add(
        &self,
        token_hash: &str,
        exp_at: i64,
        source: &str,
    ) -> Result<(), StoreError> {
        let mut redis = self.conn.clone();
        let ttl = (exp_at - now_secs()).max(1);
        let _: () = crate::utils::redis::cmd_timeout(
            redis::cmd("SETEX")
                .arg(format!("blacklist:{token_hash}"))
                .arg(ttl)
                .arg("1")
                .query_async(&mut redis),
        )
        .await
        .map_err(|e| StoreError::backend(&e))?;
        // S1 双写：DB 权威层（失败仅 WARN）
        self.upsert_revocation_db(token_hash, exp_at, source).await;
        Ok(())
    }

    /// 密码版本号递增：INCR Redis（现状）+ DB `password_version` 列**收敛到实时值**（S1 双写）
    ///
    /// b104 订正：DB 侧原先写 `password_version + 1`，于是任何一次 DB 双写失败都会让 DB 列
    /// **永久落后** Redis（后续每次 +1 只维持差距，永不相遇）。登录签发曾经直读 DB 列，
    /// 落后即意味着新签发的令牌当场被闸门判为"改密前的旧令牌"——该账号每次登录都 401。
    /// 现改为按本次 INCR 的实时值做**单调收敛**（只抬高不降低，方向与启动回填一致），
    /// 下一次成功双写就把历史欠账一并补齐。
    async fn pwd_ver_incr(&self, uid: &str) -> Result<u64, StoreError> {
        let mut redis = self.conn.clone();
        let new: i64 = crate::utils::redis::cmd_timeout(
            redis::cmd("INCR")
                .arg(format!("pwd_ver:{uid}"))
                .query_async(&mut redis),
        )
        .await
        .map_err(|e| StoreError::backend(&e))?;
        // S1 双写：DB 列同步（失败仅 WARN；uid 必为数值 user_id，parse 失败属异常仅告警跳过）
        match uid.parse::<i64>() {
            Ok(uid_i64) => {
                let new = std::cmp::max(new, 0);
                let stmt = crate::common::sql_dialect::stmt(
                    self.db.get_database_backend(),
                    "UPDATE sys_user SET password_version = ? WHERE user_id = ? AND password_version < ?",
                    [new.into(), uid_i64.into(), new.into()],
                );
                if let Err(e) = self.db.execute_raw(stmt).await {
                    tracing::warn!(
                        uid,
                        error = %e,
                        "pwd_ver DB 列同步失败（Redis 已保证当期安全，仅告警；下次递增会收敛补齐）"
                    );
                }
            }
            Err(_) => {
                tracing::warn!(uid, "pwd_ver DB 列同步跳过：uid 非数值");
            }
        }
        Ok(std::cmp::max(new, 0) as u64)
    }

    /// 当前密码版本号（与 `auth_gate_check` 同一个键与同一条解析规则，登录签发也走这里）
    async fn pwd_ver_read(&self, uid: &str) -> Result<Option<u64>, StoreError> {
        let mut redis = self.conn.clone();
        let v: Option<String> = crate::utils::redis::cmd_timeout(
            redis::cmd("GET")
                .arg(format!("pwd_ver:{uid}"))
                .query_async(&mut redis),
        )
        .await
        .map_err(|e| StoreError::backend(&e))?;
        Ok(v.and_then(|s| s.parse::<u64>().ok()))
    }

    async fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let mut redis = self.conn.clone();
        let v: Option<String> =
            crate::utils::redis::cmd_timeout(redis::cmd("GET").arg(key).query_async(&mut redis))
                .await
                .map_err(|e| StoreError::backend(&e))?;
        Ok(v)
    }

    /// SETEX（现状等价：`sys_tenant_service.rs:1918-1925` 同款参数序 key/ttl/value）
    async fn set_ex(&self, key: &str, val: &str, ttl_secs: u64) -> Result<(), StoreError> {
        let mut redis = self.conn.clone();
        let _: () = crate::utils::redis::cmd_timeout(
            redis::cmd("SETEX")
                .arg(key)
                .arg(ttl_secs)
                .arg(val)
                .query_async(&mut redis),
        )
        .await
        .map_err(|e| StoreError::backend(&e))?;
        Ok(())
    }

    /// SET NX EX（`middleware/idempotency.rs:147-156` 同款）：Some = 抢占成功
    async fn set_nx_ex(&self, key: &str, val: &str, ttl_secs: u64) -> Result<bool, StoreError> {
        let mut redis = self.conn.clone();
        let res: Option<String> = crate::utils::redis::cmd_timeout(
            redis::cmd("SET")
                .arg(key)
                .arg(val)
                .arg("NX")
                .arg("EX")
                .arg(ttl_secs)
                .query_async(&mut redis),
        )
        .await
        .map_err(|e| StoreError::backend(&e))?;
        Ok(res.is_some())
    }

    /// GETDEL 原子取删（`service/auth_service.rs:839` / `service/sso_service.rs:1463` 同款）
    async fn consume(&self, key: &str) -> Result<Option<String>, StoreError> {
        let mut redis = self.conn.clone();
        let v: Option<String> =
            crate::utils::redis::cmd_timeout(redis::cmd("GETDEL").arg(key).query_async(&mut redis))
                .await
                .map_err(|e| StoreError::backend(&e))?;
        Ok(v)
    }

    /// DEL 多键，返回实际删除条数
    async fn del(&self, keys: &[String]) -> Result<u64, StoreError> {
        if keys.is_empty() {
            return Ok(0);
        }
        let mut redis = self.conn.clone();
        let mut cmd = redis::cmd("DEL");
        for k in keys {
            cmd.arg(k);
        }
        let n: i64 = crate::utils::redis::cmd_timeout(cmd.query_async(&mut redis))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        Ok(std::cmp::max(n, 0) as u64)
    }

    /// 批量读：单次 Pipeline 多 GET（现状等价，如 sso token_refresh 双键 GET）
    async fn get_many(&self, keys: &[String]) -> Result<Vec<Option<String>>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut redis = self.conn.clone();
        let mut pipe = redis::pipe();
        for k in keys {
            pipe.cmd("GET").arg(k);
        }
        let vals: Vec<Option<String>> =
            crate::utils::redis::cmd_timeout(pipe.query_async(&mut redis))
                .await
                .map_err(|e| StoreError::backend(&e))?;
        Ok(vals)
    }

    /// 原子自增 + 首次 TTL（RATE_LIMIT_SCRIPT 原样搬运，`auth_service.rs:60-67`）
    async fn incr_with_ttl(&self, key: &str, ttl_secs: u64) -> Result<i64, StoreError> {
        let mut redis = self.conn.clone();
        let n: i64 = redis::Script::new(RATE_LIMIT_SCRIPT)
            .key(key)
            .arg(ttl_secs)
            .invoke_async(&mut redis)
            .await
            .map_err(|e| StoreError::backend(&e))?;
        Ok(n)
    }

    /// 剩余存活秒数：`TTL` 命令。`-1`（永不过期）与 `-2`（键不存在）都归一成 `None`，
    /// 与 local 档口径一致（调用方只见"有秒数"或"不知道"两种结局）。
    async fn ttl(&self, key: &str) -> Result<Option<i64>, StoreError> {
        let mut redis = self.conn.clone();
        let raw: i64 =
            crate::utils::redis::cmd_timeout(redis::cmd("TTL").arg(key).query_async(&mut redis))
                .await
                .map_err(|e| StoreError::backend(&e))?;
        Ok(if raw < 0 { None } else { Some(raw) })
    }

    /// 原子自减（连接计数专用）：CONN_DECR_SCRIPT 原样搬运；键不存在返回 -1（Redis DECR 语义）
    async fn decr(&self, key: &str) -> Result<i64, StoreError> {
        let mut redis = self.conn.clone();
        let n: i64 = redis::Script::new(CONN_DECR_SCRIPT)
            .key(key)
            .invoke_async(&mut redis)
            .await
            .map_err(|e| StoreError::backend(&e))?;
        Ok(n)
    }

    /// 分布式锁获取：SET NX EX + UUID fencing token（`scheduler/cluster.rs:120-129` 同款）
    async fn lock_acquire(
        &self,
        key: &str,
        ttl_secs: u64,
    ) -> Result<Option<LockHandle>, StoreError> {
        let mut redis = self.conn.clone();
        let token = uuid::Uuid::new_v4().to_string();
        let acquired: Option<String> = crate::utils::redis::cmd_timeout(
            redis::cmd("SET")
                .arg(key)
                .arg(&token)
                .arg("NX")
                .arg("EX")
                .arg(ttl_secs)
                .query_async(&mut redis),
        )
        .await
        .map_err(|e| StoreError::backend(&e))?;
        Ok(acquired.map(|_| LockHandle {
            key: key.to_string(),
            token,
        }))
    }

    /// 释放锁：Lua GET+DEL CAS（`scheduler/mod.rs:1109-1124` release_lock 同款）
    async fn lock_release(&self, handle: &LockHandle) -> Result<(), StoreError> {
        let mut redis = self.conn.clone();
        // 类型经 let 绑定推断（Script::invoke_async 为双泛型，不用 turbofish）
        let _: redis::Value = redis::Script::new(RELEASE_LOCK_SCRIPT)
            .key(&handle.key)
            .arg(&handle.token)
            .invoke_async(&mut redis)
            .await
            .map_err(|e| StoreError::backend(&e))?;
        Ok(())
    }

    /// 续期锁：Lua GET+EXPIRE CAS（`scheduler/mod.rs:1135-1157` renew_lock 同款）；
    /// 返回 false = 锁已被他人持有/过期（应中止当前任务）
    async fn lock_renew(&self, handle: &LockHandle, ttl_secs: u64) -> Result<bool, StoreError> {
        let mut redis = self.conn.clone();
        let result: i64 = redis::Script::new(RENEW_LOCK_SCRIPT)
            .key(&handle.key)
            .arg(&handle.token)
            .arg(ttl_secs)
            .invoke_async(&mut redis)
            .await
            .map_err(|e| StoreError::backend(&e))?;
        Ok(result == 1)
    }

    /// 强退/踢线单会话：Lua 三键原样搬运（`monitor_online_handler.rs:475-505` 同款调用形态）
    async fn revoke_session(&self, token_hash: &str, blacklist_ttl: u64) -> Result<(), StoreError> {
        let mut redis = self.conn.clone();
        let _: i64 = redis::Script::new(FORCE_LOGOUT_SCRIPT)
            .key(format!("blacklist:{token_hash}"))
            .key(format!("online:{token_hash}"))
            .key(format!("{AT_KEY_PREFIX}{token_hash}"))
            .arg(blacklist_ttl)
            .invoke_async(&mut redis)
            .await
            .map_err(|e| StoreError::backend(&e))?;
        // S1 双写：blacklist 变更同步落 DB 权威层（与 revocation_add 同源，档位切换无缝）
        self.upsert_revocation_db(
            token_hash,
            now_secs() + blacklist_ttl as i64,
            "logout", // trait 无 source 参数：monitor 强退/租户踢线统一按 logout 归类（均阻断）
        )
        .await;
        Ok(())
    }

    /// 全量吊销某用户 SSO 令牌（`sso_service.rs:2510-2572` revoke_user_sso_tokens 语义照搬）：
    /// - AT 侧：SMEMBERS `sso:user_at:{uid}` → 逐 hash EXISTS 悬空自愈 → DEL `sso:at:{hash}` +
    ///   `online:{hash}` → DEL 索引键；
    /// - RT 侧：SMEMBERS `sso:user_rt:{uid}` → 逐 hash EXISTS → DEL `sso:rt:{hash}` → DEL 索引键；
    /// - 返回真实吊销数（悬空成员不计——原实现仅日志计数，本 trait 有消费方故取真实值）。
    async fn revoke_all_for_user(&self, uid: &str) -> Result<u64, StoreError> {
        let mut redis = self.conn.clone();
        let mut count: u64 = 0;
        let mut failed: u64 = 0;

        // AT 侧（对齐 sso_service.rs:2511-2544）
        let user_at_key = format!("{USER_AT_KEY_PREFIX}{uid}");
        let at_hashes: Vec<String> = match self.set_members(&user_at_key).await {
            Ok(v) => v,
            Err(e) => {
                // 原实现：读索引失败仅记日志、按空集继续（best-effort，不阻断登出）
                tracing::warn!(user_id = %uid, error = %e, "读取用户 SSO AT 索引失败");
                Vec::new()
            }
        };
        for h in &at_hashes {
            let at_key = format!("{AT_KEY_PREFIX}{h}");
            let exists: i64 = match crate::utils::redis::cmd_timeout(
                redis::cmd("EXISTS").arg(&at_key).query_async(&mut redis),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    failed += 1;
                    tracing::error!(user_id = %uid, error = %e, "查询用户 SSO access_token 是否存在失败（跳过吊销）");
                    continue;
                }
            };
            if exists == 1 {
                // 绑定存在才算真吊销；悬空成员（绑定已自然过期）跳过自愈、不计数。
                // b102：DEL 失败不得计入 count——原实现"失败也 +1"，日志与实际状态相反。
                match crate::utils::redis::cmd_timeout(
                    redis::cmd("DEL")
                        .arg(&at_key)
                        .arg(format!("online:{h}"))
                        .query_async::<i64>(&mut redis),
                )
                .await
                {
                    Ok(_) => count += 1,
                    Err(e) => {
                        failed += 1;
                        tracing::error!(user_id = %uid, error = %e, "删除用户 SSO access_token 失败");
                    }
                }
            }
        }
        if !at_hashes.is_empty() {
            // 索引键整体删除（原实现 DEL user_at_key，非逐成员 SREM）
            if let Err(e) = crate::utils::redis::cmd_timeout(
                redis::cmd("DEL")
                    .arg(&user_at_key)
                    .query_async::<i64>(&mut redis),
            )
            .await
            {
                tracing::warn!(user_id = %uid, error = %e, "删除用户 SSO AT 索引失败（下次全量吊销会重试）");
            }
            tracing::info!(user_id = %uid, "已全量吊销用户 SSO access_token count={} failed={}", count, failed);
        }

        // RT 侧（对齐 sso_service.rs:2547-2571；RT 轮换链必须与 AT 同生命周期终止）
        let user_rt_key = format!("{USER_RT_KEY_PREFIX}{uid}");
        let rt_hashes: Vec<String> = match self.set_members(&user_rt_key).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(user_id = %uid, error = %e, "读取用户 SSO RT 索引失败");
                Vec::new()
            }
        };
        for h in &rt_hashes {
            let rt_key = format!("{RT_KEY_PREFIX}{h}");
            let exists: i64 = match crate::utils::redis::cmd_timeout(
                redis::cmd("EXISTS").arg(&rt_key).query_async(&mut redis),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    failed += 1;
                    tracing::error!(user_id = %uid, error = %e, "查询用户 SSO refresh_token 是否存在失败（跳过吊销）");
                    continue;
                }
            };
            if exists == 1 {
                match crate::utils::redis::cmd_timeout(
                    redis::cmd("DEL")
                        .arg(&rt_key)
                        .query_async::<i64>(&mut redis),
                )
                .await
                {
                    Ok(_) => count += 1,
                    Err(e) => {
                        failed += 1;
                        tracing::error!(user_id = %uid, error = %e, "删除用户 SSO refresh_token 失败");
                    }
                }
            }
        }
        if !rt_hashes.is_empty() {
            if let Err(e) = crate::utils::redis::cmd_timeout(
                redis::cmd("DEL")
                    .arg(&user_rt_key)
                    .query_async::<i64>(&mut redis),
            )
            .await
            {
                tracing::warn!(user_id = %uid, error = %e, "删除用户 SSO RT 索引失败（下次全量吊销会重试）");
            }
            // b102：打印**实际吊销数**而非索引成员数（原实现失败也报满数）
            tracing::info!(user_id = %uid, "已全量吊销用户 SSO refresh_token count={} failed={}", count, failed);
        }
        Ok(count)
    }

    /// 集合添加成员 + 刷新 TTL：SADD + EXPIRE 单次 pipe
    /// （原 sso_service 签发点为两段式独立命令，语义等价且少一次往返）
    async fn set_add(&self, key: &str, member: &str, ttl_secs: u64) -> Result<(), StoreError> {
        let mut redis = self.conn.clone();
        let _: () = crate::utils::redis::cmd_timeout(
            redis::pipe()
                .cmd("SADD")
                .arg(key)
                .arg(member)
                .cmd("EXPIRE")
                .arg(key)
                .arg(ttl_secs)
                .query_async(&mut redis),
        )
        .await
        .map_err(|e| StoreError::backend(&e))?;
        Ok(())
    }

    /// 集合移除成员：SREM（Redis 空集合键自动消失，语义天然等价）
    async fn set_rem(&self, key: &str, member: &str) -> Result<(), StoreError> {
        let mut redis = self.conn.clone();
        let _: () = crate::utils::redis::cmd_timeout(
            redis::cmd("SREM")
                .arg(key)
                .arg(member)
                .query_async(&mut redis),
        )
        .await
        .map_err(|e| StoreError::backend(&e))?;
        Ok(())
    }

    /// 集合全量成员：SMEMBERS
    async fn set_members(&self, key: &str) -> Result<Vec<String>, StoreError> {
        let mut redis = self.conn.clone();
        let members: Vec<String> = crate::utils::redis::cmd_timeout(
            redis::cmd("SMEMBERS").arg(key).query_async(&mut redis),
        )
        .await
        .map_err(|e| StoreError::backend(&e))?;
        Ok(members)
    }

    /// 模式匹配键扫描：直接复用 utils 层 SCAN 实现（截断/全量双版语义一一对应）
    async fn scan(&self, pattern: &str, max: Option<usize>) -> Result<Vec<String>, StoreError> {
        let mut redis = self.conn.clone();
        match max {
            // 截断版：达上限即停（只读展示/列表语义）
            Some(n) => crate::utils::redis::scan_keys(&mut redis, pattern, n)
                .await
                .map_err(|e| StoreError::backend(&e)),
            // 全量版：扫到游标归零（安全吊销必须扫到尾，禁止用于展示）
            None => crate::utils::redis::scan_keys_all(&mut redis, pattern)
                .await
                .map_err(|e| StoreError::backend(&e)),
        }
    }

    /// 存活探测：PING
    async fn ping(&self) -> Result<(), StoreError> {
        let mut redis = self.conn.clone();
        let _: String =
            crate::utils::redis::cmd_timeout(redis::cmd("PING").query_async(&mut redis))
                .await
                .map_err(|e| StoreError::backend(&e))?;
        Ok(())
    }

    /// 运行摘要：INFO 原文（`/metrics` 消费端自行解析）
    async fn info_summary(&self) -> Result<String, StoreError> {
        let mut redis = self.conn.clone();
        let info: String =
            crate::utils::redis::cmd_timeout(redis::cmd("INFO").query_async(&mut redis))
                .await
                .map_err(|e| StoreError::backend(&e))?;
        Ok(info)
    }
}

impl RedisStore {
    /// 启动期回填（best-effort：任何失败 WARN 继续，不阻断启动）
    ///
    /// ① `sys_token_revocation` 未过期行 → SETEX `blacklist:{hash}`（先 EXISTS 再 SET，
    ///    幂等且不覆盖 Redis 上可能更新的 TTL；值 "1" 与 revocation_add/Lua 一致）；
    /// ② `sys_user.password_version > 0` 行 → Redis `pwd_ver:{uid}` 值小于 DB 列时
    ///    SET 为 DB 列值（**无 TTL**，与现状 pwd_ver 键由裸 INCR 写入、从不 EXPIRE 一致，
    ///    见 `sys_user_handler.rs:558-573` / `auth_service.rs:1113-1127`）。
    pub async fn bootstrap_from_db(&self, db: &DatabaseConnection) {
        let now = now_secs();
        let backend = db.get_database_backend();

        // ① 吊销权威层 → blacklist 键
        let mut rev_count: usize = 0;
        match db
            .query_all_raw(crate::common::sql_dialect::stmt(
                backend,
                "SELECT token_hash, expire_at FROM sys_token_revocation WHERE expire_at > ?",
                [now.into()],
            ))
            .await
        {
            Ok(rows) => {
                for row in rows {
                    let (hash, exp) = match (
                        row.try_get::<String>("", "token_hash"),
                        row.try_get::<i64>("", "expire_at"),
                    ) {
                        (Ok(h), Ok(e)) => (h, e),
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::warn!(error = %e, "吊销回填：行解析失败，跳过");
                            continue;
                        }
                    };
                    let mut redis = self.conn.clone();
                    let key = format!("blacklist:{hash}");
                    // EXISTS 失败按已存在跳过（保守：避免对不可达 Redis 重复 SETEX 刷新 TTL）
                    let exists: i64 = crate::utils::redis::cmd_timeout(
                        redis::cmd("EXISTS").arg(&key).query_async(&mut redis),
                    )
                    .await
                    .unwrap_or(1);
                    if exists == 0 {
                        let ttl = (exp - now).max(1);
                        let _: Result<(), _> = crate::utils::redis::cmd_timeout(
                            redis::cmd("SET")
                                .arg(&key)
                                .arg("1")
                                .arg("EX")
                                .arg(ttl)
                                .query_async(&mut redis),
                        )
                        .await;
                        rev_count += 1;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "吊销回填：sys_token_revocation 读取失败（跳过该步）");
            }
        }

        // ② 密码版本列 → pwd_ver 键
        let mut ver_count: usize = 0;
        match db
            .query_all_raw(Statement::from_sql_and_values(
                backend,
                "SELECT user_id, password_version FROM sys_user WHERE password_version > 0",
                [],
            ))
            .await
        {
            Ok(rows) => {
                for row in rows {
                    let (uid, db_ver) = match (
                        row.try_get::<i64>("", "user_id"),
                        row.try_get::<i64>("", "password_version"),
                    ) {
                        (Ok(u), Ok(v)) if v > 0 => (u, v),
                        (Ok(_), Ok(_)) => continue,
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::warn!(error = %e, "pwd_ver 回填：行解析失败，跳过");
                            continue;
                        }
                    };
                    let mut redis = self.conn.clone();
                    let key = format!("pwd_ver:{uid}");
                    let redis_val: Option<String> = crate::utils::redis::cmd_timeout(
                        redis::cmd("GET").arg(&key).query_async(&mut redis),
                    )
                    .await
                    .unwrap_or(None);
                    let cur = redis_val.and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                    // 仅 Redis 值落后于 DB 列时回填（幂等；无 TTL，与现状一致）
                    if cur < std::cmp::max(db_ver, 0) as u64 {
                        let _: Result<(), _> = crate::utils::redis::cmd_timeout(
                            redis::cmd("SET")
                                .arg(&key)
                                .arg(db_ver.to_string())
                                .query_async(&mut redis),
                        )
                        .await;
                        ver_count += 1;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "pwd_ver 回填：sys_user 读取失败（跳过该步）");
            }
        }
        tracing::info!(
            revocations = rev_count,
            pwd_versions = ver_count,
            "Redis 启动回填完成（DB 权威层 → 共享态）"
        );
    }
}
