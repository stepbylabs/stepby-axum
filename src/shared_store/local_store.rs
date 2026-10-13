// stepby-axum/src/shared_store/local_store.rs
//! SharedStore 的 local 档实现——**纯 SQL 承载，不引入任何 Redis 调用**
//!
//! # 承载表
//! - S2 一次性/短期态：`sys_shared_kv`（TTL = `expire_at` 列，NULL = 永不过期）
//! - 调度锁：`sys_shared_lock`（PK CAS，见实体头注释）
//! - S1 安全态权威层：`sys_token_revocation`（吊销）+ `sys_user.password_version`（密码版本）
//!   + `sys_tenant`（status / expire_time 求值投影）
//!
//! # 跨方言约束（sqlite / mysql / pg 三后端共用，SQL 仅用通用子集）
//! - **禁用** `INSERT ... ON DUPLICATE KEY UPDATE` / `ON CONFLICT`（MySQL/PG 方言不通用）
//!   → UPSERT 一律「先 SELECT 后 UPDATE/INSERT」，INSERT 撞 PK 视为竞态回退更新；
//! - **禁用** `UPDATE/DELETE ... RETURNING`（MySQL 无）→ 受影响行数以 `rows_affected` 判定；
//! - **禁用** `SELECT ... FOR UPDATE`（SQLite 无）→ 并发正确性由「DELETE 的
//!   `rows_affected` 判定赢家」达成（READ COMMITTED 下后到者的 DELETE WHERE 条件
//!   二次求值为 0 行；SQLite 串行写天然安全）。
//!
//! # S3 cache-aside 的裁定（重要）
//! mod.rs 把 S3 标为「直通 no-op（不缓存不算失败）」——那是**允许**不缓存，不是**禁止**
//! 缓存。而 S2 的 online/captcha 等与 S3 的 cache-aside 迁移后调用的是**同一组**
//! `get/set_ex`，本实现无法（也不应）感知调用点属于哪一级。故本实现**统一真实 KV**
//! （DB 点查，微秒级，带 TTL）：S2 必须真实，S3 顺带真实缓存无碍。不做 no-op 特判。
//!
//! # 键族语义对照
//! - `sso:user_at:{uid}` / `sso:user_rt:{uid}` / `sso:sess:{uid}`：local 档无 Set 类型
//!   → 以 **JSON 数组字符串** 存于 `sys_shared_kv`（读改写封装在本文件
//!   [`LocalStore::set_add`] / [`set_rem`] / [`set_members`]，与 Redis 档 SMEMBERS 语义对齐）；
//! - `blacklist:{hash}` / `sso:at:{hash}` 的阻断语义统一由 `sys_token_revocation` 承载
//!   （source 归类，见 [`LocalStore::auth_gate_check`]）；
//! - `tenant:state:{tid}` / `tenant:exp:{tid}` 由 `sys_tenant` 现场投影求值
//!   （对齐 `sys_tenant_service.rs:1897-1914` sync_runtime_keys）。

use async_trait::async_trait;
use chrono::NaiveDateTime;
use sea_orm::{
    ActiveModelTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait, Set, Statement,
    TransactionTrait, Value,
};

use crate::common::tenant::{
    TENANT_EXPIRE_GRACE_DAYS, TENANT_STATE_ACTIVE, TENANT_STATE_DISABLED, TENANT_STATE_GRACE,
};
use crate::entity::sys_shared_kv::{ActiveModel as KvActive, Entity as KvEntity};
use crate::entity::sys_token_revocation::{ActiveModel as RevActive, Entity as RevEntity};
use crate::shared_store::{AuthGate, LockHandle, SharedStore, StoreError, glob_match};

/// 当前 UTC 秒
fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// 过期判定：`Some(t)` 且 `t <=` 当前 UTC 秒 = 过期；`None` = 永不过期
pub fn is_expired(expire_at: Option<i64>) -> bool {
    match expire_at {
        Some(t) => t <= now_secs(),
        None => false,
    }
}

/// 是否为唯一键/PK 冲突（跨方言判定：PG「duplicate key ... unique constraint」、
/// MySQL「Duplicate entry ... 1062」、SQLite「UNIQUE constraint failed」）
fn is_unique_conflict(e: &DbErr) -> bool {
    let s = e.to_string().to_ascii_lowercase();
    s.contains("unique") || s.contains("duplicate") || s.contains("1062")
}

/// local 档共享态存储（与业务同库，S1/S2 天然持久且多实例可共享）
#[allow(dead_code)]
pub struct LocalStore {
    db: DatabaseConnection,
}

impl LocalStore {
    /// 构造（未接线期 #[allow(dead_code)] 预防告警；接线后可移除）
    #[allow(dead_code)]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// 以本库方言构造参数化语句（占位符统一写 `?`，sea-orm 负责 PG 端 `$n` 转译）
    fn stmt(&self, sql: &str, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.db.get_database_backend(), sql, values)
    }

    /// UPSERT `sys_shared_kv`：先 SELECT 后 UPDATE/INSERT（跨方言通用写法）；
    /// INSERT 撞 PK（并发首插竞态）回退为更新，语义对齐 Redis SETEX 的无条件覆盖。
    /// `expire_at = None` 表示永不过期（对应无 TTL 键，如 pwd_ver 一类键族）。
    async fn upsert_kv(
        &self,
        key: &str,
        val: &str,
        expire_at: Option<i64>,
    ) -> Result<(), StoreError> {
        if let Some(m) = KvEntity::find_by_id(key)
            .one(&self.db)
            .await
            .map_err(|e| StoreError::backend(&e))?
        {
            let mut am: KvActive = m.into();
            am.kv_value = Set(val.to_string());
            am.expire_at = Set(expire_at);
            am.update(&self.db)
                .await
                .map_err(|e| StoreError::backend(&e))?;
            return Ok(());
        }
        let am = KvActive {
            kv_key: Set(key.to_string()),
            kv_value: Set(val.to_string()),
            expire_at: Set(expire_at),
        };
        match KvEntity::insert(am).exec(&self.db).await {
            Ok(_) => Ok(()),
            Err(e) if is_unique_conflict(&e) => {
                // 竞态兜底：另一协程/实例先插入 → 重新走更新路径
                match KvEntity::find_by_id(key).one(&self.db).await {
                    Ok(Some(m)) => {
                        let mut am: KvActive = m.into();
                        am.kv_value = Set(val.to_string());
                        am.expire_at = Set(expire_at);
                        am.update(&self.db)
                            .await
                            .map_err(|e| StoreError::backend(&e))?;
                        Ok(())
                    }
                    Ok(None) => Err(StoreError::Backend(format!(
                        "sys_shared_kv 行在插入竞态后消失: {key}"
                    ))),
                    Err(e) => Err(StoreError::backend(&e)),
                }
            }
            Err(e) => Err(StoreError::backend(&e)),
        }
    }
}

#[async_trait]
impl SharedStore for LocalStore {
    fn kind(&self) -> &'static str {
        "local"
    }

    /// 闸门快照：2-3 条 PK 点查（对齐 redis 档 pipe 5 键的语义，取数方式换 DB）
    async fn auth_gate_check(
        &self,
        token_hash: &str,
        uid: &str,
        tid: i64,
    ) -> Result<AuthGate, StoreError> {
        let now = now_secs();

        // ① S1 吊销权威层点查。blacklist:{hash} 与 sso:at:{hash} 两族键的 hash 段
        //    同为 token_hash → 在表中是同一 PK 行，source 决定归类：
        //    logout/kick → blacklisted；sso_legacy_at → sso_at_bound。
        //    同一行只承载一个 source 不损失安全性：任一归类为真都会被 auth 判定拒绝
        //    （logout 覆盖 sso_legacy_at 后仍被 blacklisted 拦截，反之被 sso_at_bound 拦截）。
        let revoked: Option<String> = match self
            .db
            .query_one_raw(self.stmt(
                "SELECT source FROM sys_token_revocation WHERE token_hash = ? AND expire_at > ?",
                vec![token_hash.to_owned().into(), now.into()],
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?
        {
            Some(r) => Some(
                r.try_get::<String>("", "source")
                    .map_err(|e| StoreError::backend(&e))?,
            ),
            None => None,
        };
        let blacklisted = matches!(revoked.as_deref(), Some(s) if s != "sso_legacy_at");
        let sso_at_bound = revoked.as_deref() == Some("sso_legacy_at");

        // ② 密码版本（sys_user.password_version：启动兜底列保证存在；行不存在 = None = 未设置）
        let pwd_ver: Option<u64> = match uid.parse::<i64>() {
            Ok(id) => {
                let row = self
                    .db
                    .query_one_raw(self.stmt(
                        "SELECT password_version FROM sys_user WHERE user_id = ?",
                        vec![id.into()],
                    ))
                    .await
                    .map_err(|e| StoreError::backend(&e))?;
                match row {
                    Some(r) => r
                        .try_get::<Option<i64>>("", "password_version")
                        .map_err(|e| StoreError::backend(&e))?
                        .map(|v| std::cmp::max(v, 0) as u64),
                    None => None,
                }
            }
            Err(_) => {
                tracing::warn!(uid, "auth_gate_check：uid 非数值，pwd_ver 按 None 处理");
                None
            }
        };

        // ③ 租户运行时（tid=0 平台租户不查询，两字段恒 None——对齐 middleware/auth.rs:95）
        //    投影逻辑对齐 sys_tenant_service.rs:1897-1914 sync_runtime_keys：
        //    DB status '1'（停用）→ 键值 '2'；expire_time 按宽限 7 天三态投影为 '0'/'1'/'2'；
        //    tenant:exp 键值 = 到期 UTC 秒（NULL → 0 = 永不过期）。
        let (tenant_state, tenant_expire) = if tid == 0 {
            (None, None)
        } else {
            match self
                .db
                .query_one_raw(self.stmt(
                    "SELECT status, expire_time FROM sys_tenant WHERE tenant_id = ?",
                    vec![tid.into()],
                ))
                .await
                .map_err(|e| StoreError::backend(&e))?
            {
                // 行缺失 = Redis 键缺失语义（eval 端视为 Active；事实源仍是登录闸门查库）
                None => (None, None),
                Some(r) => {
                    let status: Option<String> = r
                        .try_get::<Option<String>>("", "status")
                        .map_err(|e| StoreError::backend(&e))?;
                    let expire_time: Option<NaiveDateTime> = r
                        .try_get::<Option<NaiveDateTime>>("", "expire_time")
                        .map_err(|e| StoreError::backend(&e))?;
                    let exp_ts = expire_time.map(|dt| dt.and_utc().timestamp());
                    let state = if status.as_deref() == Some("1") {
                        TENANT_STATE_DISABLED
                    } else {
                        match exp_ts {
                            Some(exp) if now >= exp + TENANT_EXPIRE_GRACE_DAYS * 24 * 3600 => {
                                TENANT_STATE_DISABLED
                            }
                            Some(exp) if now >= exp => TENANT_STATE_GRACE,
                            _ => TENANT_STATE_ACTIVE,
                        }
                    };
                    (Some(state.to_string()), Some(exp_ts.unwrap_or(0)))
                }
            }
        };

        Ok(AuthGate {
            blacklisted,
            sso_at_bound,
            pwd_ver,
            tenant_state,
            tenant_expire,
        })
    }

    /// 吊销登记：INSERT，已有行取 expire_at 更大值（max 语义），source 同步为最后来源
    async fn revocation_add(
        &self,
        token_hash: &str,
        exp_at: i64,
        source: &str,
    ) -> Result<(), StoreError> {
        match RevEntity::find_by_id(token_hash)
            .one(&self.db)
            .await
            .map_err(|e| StoreError::backend(&e))?
        {
            Some(m) if exp_at > m.expire_at => {
                let mut am: RevActive = m.into();
                am.expire_at = Set(exp_at);
                am.source = Set(source.to_string());
                am.update(&self.db)
                    .await
                    .map_err(|e| StoreError::backend(&e))?;
            }
            Some(_) => {} // 已有行 expire_at 不小于新值：幂等跳过
            None => {
                let am = RevActive {
                    token_hash: Set(token_hash.to_string()),
                    expire_at: Set(exp_at),
                    source: Set(source.to_string()),
                };
                match RevEntity::insert(am).exec(&self.db).await {
                    Ok(_) => {}
                    Err(e) if is_unique_conflict(&e) => {
                        // 并发首插竞态：重读后按 max 更新
                        if let Some(m) = RevEntity::find_by_id(token_hash)
                            .one(&self.db)
                            .await
                            .map_err(|e| StoreError::backend(&e))?
                            && exp_at > m.expire_at
                        {
                            let mut am: RevActive = m.into();
                            am.expire_at = Set(exp_at);
                            am.source = Set(source.to_string());
                            am.update(&self.db)
                                .await
                                .map_err(|e| StoreError::backend(&e))?;
                        }
                    }
                    Err(e) => return Err(StoreError::backend(&e)),
                }
            }
        }
        Ok(())
    }

    /// 密码版本递增：事务内 SELECT 当前值 → +1 → UPDATE（DB 列即事实源，无 Redis）
    async fn pwd_ver_incr(&self, uid: &str) -> Result<u64, StoreError> {
        let uid_i64 = uid.parse::<i64>().map_err(|_| {
            tracing::warn!(uid, "pwd_ver_incr：uid 非数值");
            StoreError::Backend(format!("pwd_ver_incr：非法 uid {uid}"))
        })?;
        let txn = self.db.begin().await.map_err(|e| StoreError::backend(&e))?;
        let row = txn
            .query_one_raw(self.stmt(
                "SELECT password_version FROM sys_user WHERE user_id = ?",
                vec![uid_i64.into()],
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        let new: u64 = match row {
            None => {
                txn.commit().await.map_err(|e| StoreError::backend(&e))?;
                // 保守：行不存在（用户并发删除后不再有 INCR 调用方）按 new=1 返回
                tracing::warn!(uid, "pwd_ver_incr：sys_user 行不存在，按 new=1 返回");
                1
            }
            Some(r) => {
                let cur: Option<i64> = r
                    .try_get::<Option<i64>>("", "password_version")
                    .map_err(|e| StoreError::backend(&e))?;
                let new = cur.unwrap_or(0).max(0) + 1;
                let res = txn
                    .execute_raw(self.stmt(
                        "UPDATE sys_user SET password_version = ? WHERE user_id = ?",
                        vec![new.into(), uid_i64.into()],
                    ))
                    .await
                    .map_err(|e| StoreError::backend(&e))?;
                txn.commit().await.map_err(|e| StoreError::backend(&e))?;
                if res.rows_affected() == 0 {
                    tracing::warn!(
                        uid,
                        "pwd_ver_incr：UPDATE 影响 0 行（行并发删除？），按 new=1 返回"
                    );
                    1
                } else {
                    new as u64
                }
            }
        };
        Ok(new)
    }

    /// 读取（S2 会话绑定 / S3 cache-aside 通用 GET）：过期视为 None 并惰性删除
    async fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        match KvEntity::find_by_id(key)
            .one(&self.db)
            .await
            .map_err(|e| StoreError::backend(&e))?
        {
            Some(m) if is_expired(m.expire_at) => {
                // 惰性清理：读时发现已过期即删除（等价 Redis 键自然过期后消失）
                let _ = self
                    .db
                    .execute_raw(self.stmt(
                        "DELETE FROM sys_shared_kv WHERE kv_key = ?",
                        vec![key.to_owned().into()],
                    ))
                    .await;
                Ok(None)
            }
            Some(m) => Ok(Some(m.kv_value)),
            None => Ok(None),
        }
    }

    /// 写入并带 TTL（对齐 Redis SETEX：值与 TTL 均无条件覆盖）
    async fn set_ex(&self, key: &str, val: &str, ttl_secs: u64) -> Result<(), StoreError> {
        let exp = now_secs() + ttl_secs as i64;
        self.upsert_kv(key, val, Some(exp)).await
    }

    /// 原子抢占：事务内「惰性抢占过期行 → INSERT」，PK 冲突 = 已被未过期行占用
    async fn set_nx_ex(&self, key: &str, val: &str, ttl_secs: u64) -> Result<bool, StoreError> {
        let now = now_secs();
        let exp = now + ttl_secs as i64;
        let txn = self.db.begin().await.map_err(|e| StoreError::backend(&e))?;
        // ① 惰性抢占：仅删除同键**已过期**行（expire_at IS NOT NULL 排除永不过期行）
        txn.execute_raw(self.stmt(
            "DELETE FROM sys_shared_kv WHERE kv_key = ? AND expire_at IS NOT NULL AND expire_at <= ?",
            vec![key.to_owned().into(), now.into()],
        ))
        .await
        .map_err(|e| StoreError::backend(&e))?;
        // ② INSERT：PK 冲突 = 未过期行仍在 → 抢占失败（false）；真 DB 错误才 Err
        match txn
            .execute_raw(self.stmt(
                "INSERT INTO sys_shared_kv (kv_key, kv_value, expire_at) VALUES (?, ?, ?)",
                vec![key.to_owned().into(), val.to_owned().into(), exp.into()],
            ))
            .await
        {
            Ok(_) => {
                txn.commit().await.map_err(|e| StoreError::backend(&e))?;
                Ok(true)
            }
            Err(e) if is_unique_conflict(&e) => {
                let _ = txn.rollback().await;
                Ok(false)
            }
            Err(e) => Err(StoreError::backend(&e)),
        }
    }

    /// 原子取删：事务内 SELECT 备值 → DELETE，以 `rows_affected == 1` 判定赢家
    /// （并发 consume 只有一个删除成功；READ COMMITTED 下后到者的 DELETE WHERE
    /// 条件二次求值为 0 行；SQLite 串行写天然安全）
    async fn consume(&self, key: &str) -> Result<Option<String>, StoreError> {
        let txn = self.db.begin().await.map_err(|e| StoreError::backend(&e))?;
        let row = txn
            .query_one_raw(self.stmt(
                "SELECT kv_value, expire_at FROM sys_shared_kv WHERE kv_key = ?",
                vec![key.to_owned().into()],
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        let (value, valid) = match row {
            None => {
                txn.commit().await.map_err(|e| StoreError::backend(&e))?;
                return Ok(None);
            }
            Some(r) => {
                let v: String = r
                    .try_get::<String>("", "kv_value")
                    .map_err(|e| StoreError::backend(&e))?;
                let exp: Option<i64> = r
                    .try_get::<Option<i64>>("", "expire_at")
                    .map_err(|e| StoreError::backend(&e))?;
                // 过期行：值不返回，但仍走 DELETE 顺带清理
                (v, !is_expired(exp))
            }
        };
        let res = txn
            .execute_raw(self.stmt(
                "DELETE FROM sys_shared_kv WHERE kv_key = ?",
                vec![key.to_owned().into()],
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        txn.commit().await.map_err(|e| StoreError::backend(&e))?;
        Ok((valid && res.rows_affected() == 1).then_some(value))
    }

    /// 删除多键，返回实际删除条数
    async fn del(&self, keys: &[String]) -> Result<u64, StoreError> {
        if keys.is_empty() {
            return Ok(0);
        }
        let placeholders = vec!["?"; keys.len()].join(", ");
        let values: Vec<Value> = keys.iter().map(|k| k.clone().into()).collect();
        let res = self
            .db
            .execute_raw(self.stmt(
                &format!("DELETE FROM sys_shared_kv WHERE kv_key IN ({placeholders})"),
                values,
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        Ok(res.rows_affected())
    }

    /// 批量读：逐键点查（量小：SSO 双键等 ≤ 4 键；过期视为 None，不做惰性删除避免读放大写）
    async fn get_many(&self, keys: &[String]) -> Result<Vec<Option<String>>, StoreError> {
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let row = KvEntity::find_by_id(k)
                .one(&self.db)
                .await
                .map_err(|e| StoreError::backend(&e))?;
            out.push(row.filter(|m| !is_expired(m.expire_at)).map(|m| m.kv_value));
        }
        Ok(out)
    }

    /// 原子自增 + 首次 TTL（RATE_LIMIT_SCRIPT 语义：INCR 结果 1 时 EXPIRE；已有键不重置 TTL）
    async fn incr_with_ttl(&self, key: &str, ttl_secs: u64) -> Result<i64, StoreError> {
        // 并发首插竞态（两事务同时看到无键 → 双 INSERT 撞 PK）重试：重读后走 UPDATE 路径
        const MAX_RETRY: usize = 3;
        for _ in 0..MAX_RETRY {
            match self.try_incr_once(key, ttl_secs).await {
                Ok(n) => return Ok(n),
                Err(IncrErr::UniqueConflict) => continue,
                Err(IncrErr::Failed(e)) => return Err(e),
            }
        }
        Err(StoreError::Backend(format!(
            "incr_with_ttl 并发冲突重试耗尽: {key}"
        )))
    }

    /// 原子自减（**连接计数专用**：ws_conn:{uid} 关闭侧递减，其它键族禁用——
    /// 本方法不携带 TTL 语义，减到 ≤0 即删行，对齐原 Lua `DECR + 条件 DEL`）。
    /// - 事务内 SELECT 当前值 → -1 → UPDATE；新值 ≤0 时 DELETE（等价 Redis 条件 DEL）；
    /// - 键不存在（或已过期）返回 -1 且不落行（对齐 Redis DECR 空键返回 -1、随后被 DEL 消失的语义）；
    /// - 串行化说明：同 set_nx_ex/consume 范式，SQLite 串行写天然安全；
    ///   MySQL/PG 下同键并发 DECR 由单条 UPDATE/DELETE 的行锁保证原子。
    async fn decr(&self, key: &str) -> Result<i64, StoreError> {
        let txn = self.db.begin().await.map_err(|e| StoreError::backend(&e))?;
        let row = txn
            .query_one_raw(self.stmt(
                "SELECT kv_value, expire_at FROM sys_shared_kv WHERE kv_key = ?",
                vec![key.to_owned().into()],
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        let cur: i64 = match row {
            None => {
                txn.commit().await.map_err(|e| StoreError::backend(&e))?;
                return Ok(-1);
            }
            Some(r) => {
                let exp: Option<i64> = r
                    .try_get::<Option<i64>>("", "expire_at")
                    .map_err(|e| StoreError::backend(&e))?;
                if is_expired(exp) {
                    // 过期行 = 键已消失（Redis 键自然过期语义）：按空键 -1 返回并顺带删行
                    txn.execute_raw(self.stmt(
                        "DELETE FROM sys_shared_kv WHERE kv_key = ?",
                        vec![key.to_owned().into()],
                    ))
                    .await
                    .map_err(|e| StoreError::backend(&e))?;
                    txn.commit().await.map_err(|e| StoreError::backend(&e))?;
                    return Ok(-1);
                }
                let val: String = r
                    .try_get::<String>("", "kv_value")
                    .map_err(|e| StoreError::backend(&e))?;
                val.parse::<i64>().map_err(|_| {
                    StoreError::Corrupted(format!("decr：键 {key} 的值非整数: {val}"))
                })?
            }
        };
        let new = cur - 1;
        if new <= 0 {
            txn.execute_raw(self.stmt(
                "DELETE FROM sys_shared_kv WHERE kv_key = ?",
                vec![key.to_owned().into()],
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        } else {
            txn.execute_raw(self.stmt(
                "UPDATE sys_shared_kv SET kv_value = ? WHERE kv_key = ?",
                vec![new.to_string().into(), key.to_owned().into()],
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        }
        txn.commit().await.map_err(|e| StoreError::backend(&e))?;
        Ok(new)
    }

    /// 分布式锁获取：事务内「抢占过期锁 → INSERT」，PK 冲突 = 仍被有效持有（返回 None）
    async fn lock_acquire(
        &self,
        key: &str,
        ttl_secs: u64,
    ) -> Result<Option<LockHandle>, StoreError> {
        let now = now_secs();
        let token = uuid::Uuid::new_v4().to_string();
        let exp = now + ttl_secs as i64;
        let txn = self.db.begin().await.map_err(|e| StoreError::backend(&e))?;
        // ① 抢占过期锁（对齐 Redis 键 TTL 到期后可被抢占的语义）
        //
        // ⚠️ §5.35 双轨契约（E-03 定性）：本段对 `sys_shared_lock` 使用**裸 SQL**
        // 而非 sea-orm 实体——**设计选择，勿"顺手统一"**：
        // 1. `shared_store` 是独立基础设施抽象（AGENTS.md A.1），禁止依赖
        //    `entity` 层，否则引入 entity ↔ shared_store 双向耦合；
        // 2. 本段为 CAS 抢占语义（DELETE 过期行 → INSERT NX → CAS 释放/续期），
        //    需要事务内精确控制语句顺序，ORM 封装反而增加间接层；
        // 3. **表结构演进须双维护**：`sys_shared_lock` 列变更时必须同步
        //    `src/entity/sys_shared_lock.rs`（ORM 侧消费：count/巡检）与本段
        //    裸 SQL（CAS 语义消费），两处均在集成测试覆盖下。
        txn.execute_raw(self.stmt(
            "DELETE FROM sys_shared_lock WHERE lock_key = ? AND expire_at <= ?",
            vec![key.to_owned().into(), now.into()],
        ))
        .await
        .map_err(|e| StoreError::backend(&e))?;
        // ② INSERT：PK 冲突 = 被持有（None）；并发两事务同时抢占过期锁时，
        //    后者 INSERT 撞 PK → 同样归为 None（前者赢得锁）
        match txn
            .execute_raw(self.stmt(
                "INSERT INTO sys_shared_lock (lock_key, lock_token, expire_at) VALUES (?, ?, ?)",
                vec![key.to_owned().into(), token.clone().into(), exp.into()],
            ))
            .await
        {
            Ok(_) => {
                txn.commit().await.map_err(|e| StoreError::backend(&e))?;
                Ok(Some(LockHandle {
                    key: key.to_string(),
                    token,
                }))
            }
            Err(e) if is_unique_conflict(&e) => {
                let _ = txn.rollback().await;
                Ok(None)
            }
            Err(e) => Err(StoreError::backend(&e)),
        }
    }

    /// 释放锁：CAS 删除（仅 token 匹配才删，防误删他实例的锁；幂等，0 行亦视为已释放）
    async fn lock_release(&self, handle: &LockHandle) -> Result<(), StoreError> {
        self.db
            .execute_raw(self.stmt(
                "DELETE FROM sys_shared_lock WHERE lock_key = ? AND lock_token = ?",
                vec![handle.key.clone().into(), handle.token.clone().into()],
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        Ok(())
    }

    /// 续期锁：CAS 更新（仅 token 匹配才延长；false = 锁已被他人持有/过期，应中止当前任务）
    async fn lock_renew(&self, handle: &LockHandle, ttl_secs: u64) -> Result<bool, StoreError> {
        let exp = now_secs() + ttl_secs as i64;
        let res = self
            .db
            .execute_raw(self.stmt(
                "UPDATE sys_shared_lock SET expire_at = ? WHERE lock_key = ? AND lock_token = ?",
                vec![
                    exp.into(),
                    handle.key.clone().into(),
                    handle.token.clone().into(),
                ],
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        Ok(res.rows_affected() == 1)
    }

    /// 强退/踢线单会话：**单事务**完成吊销登记 + online/sso:at 删除
    /// （S1/S2 同库真原子；对齐 monitor_online_handler.rs:475-505 /
    /// sys_tenant_service.rs:2447-2452 的 Lua 三键语义）
    async fn revoke_session(&self, token_hash: &str, blacklist_ttl: u64) -> Result<(), StoreError> {
        let now = now_secs();
        let exp = now + blacklist_ttl as i64;
        let online_key = format!("online:{token_hash}");
        let sso_at_key = format!("sso:at:{token_hash}");
        // 并发首插竞态（两事务同时看到无吊销行）重试：重读后走 UPDATE max 路径
        for _ in 0..3 {
            let txn = self.db.begin().await.map_err(|e| StoreError::backend(&e))?;
            // ① 吊销登记（S1 权威层）：已有行取 expire_at 更大值；trait 无 source 参数，
            //    monitor 强退/租户踢线统一按 'logout' 归类（均阻断，见 mod.rs trait 注释）
            let row = txn
                .query_one_raw(self.stmt(
                    "SELECT expire_at FROM sys_token_revocation WHERE token_hash = ?",
                    vec![token_hash.to_owned().into()],
                ))
                .await
                .map_err(|e| StoreError::backend(&e))?;
            match row {
                Some(r) => {
                    let old: i64 = r
                        .try_get::<i64>("", "expire_at")
                        .map_err(|e| StoreError::backend(&e))?;
                    if exp > old {
                        txn.execute_raw(self.stmt(
                            "UPDATE sys_token_revocation SET expire_at = ?, source = ? WHERE token_hash = ?",
                            vec![exp.into(), "logout".to_owned().into(), token_hash.to_owned().into()],
                        ))
                        .await
                        .map_err(|e| StoreError::backend(&e))?;
                    }
                }
                None => {
                    match txn
                        .execute_raw(self.stmt(
                            "INSERT INTO sys_token_revocation (token_hash, expire_at, source) VALUES (?, ?, ?)",
                            vec![
                                token_hash.to_owned().into(),
                                exp.into(),
                                "logout".to_owned().into(),
                            ],
                        ))
                        .await
                    {
                        Ok(_) => {}
                        Err(e) if is_unique_conflict(&e) => {
                            let _ = txn.rollback().await;
                            continue; // 并发首插：重试后 SELECT 可见，走 UPDATE 路径
                        }
                        Err(e) => return Err(StoreError::backend(&e)),
                    }
                }
            }
            // ② online + sso:at 同生共死（Lua KEYS[2]/KEYS[3] 的 DEL）
            txn.execute_raw(self.stmt(
                "DELETE FROM sys_shared_kv WHERE kv_key IN (?, ?)",
                vec![online_key.clone().into(), sso_at_key.clone().into()],
            ))
            .await
            .map_err(|e| StoreError::backend(&e))?;
            txn.commit().await.map_err(|e| StoreError::backend(&e))?;
            return Ok(());
        }
        Err(StoreError::Backend(format!(
            "revoke_session 并发冲突重试耗尽: {token_hash}"
        )))
    }

    /// 全量吊销某用户 SSO 令牌（sso_service.rs:2510-2572 revoke_user_sso_tokens 语义照搬，
    /// Set 集合以 sys_shared_kv 中的 JSON 数组字符串承载）：
    /// - AT 侧：读 `sso:user_at:{uid}` 数组 → 逐 hash 悬空自愈（绑定不存在跳过且不计数）
    ///   → 删 `sso:at:{hash}` + `online:{hash}` → DEL 整个索引键（原实现非逐成员 SREM）；
    /// - RT 侧：读 `sso:user_rt:{uid}` 数组 → 逐 hash 删 `sso:rt:{hash}` → DEL 索引键；
    /// - 返回真实吊销数。与原函数一致**不做 blacklist 拉黑**（不透明令牌删除即失效）。
    async fn revoke_all_for_user(&self, uid: &str) -> Result<u64, StoreError> {
        let mut count: u64 = 0;

        // AT 侧（对齐 sso_service.rs:2511-2544）；索引损坏/读取失败按原语义上抛（Corrupted/Backend）
        let at_set_key = format!("sso:user_at:{uid}");
        let at_hashes: Vec<String> = self.set_members(&at_set_key).await?;
        for h in &at_hashes {
            let at_key = format!("sso:at:{h}");
            if self.get(&at_key).await?.is_some() {
                // 绑定存在才算真吊销（EXISTS 悬空自愈：绑定已自然过期的成员删除 no-op、跳过）
                self.del(&[at_key, format!("online:{h}")]).await?;
                count += 1;
            }
        }
        if !at_hashes.is_empty() {
            self.del(std::slice::from_ref(&at_set_key)).await?;
            tracing::info!(user_id = %uid, "已全量吊销用户 SSO access_token count={}", at_hashes.len());
        }

        // RT 侧（对齐 sso_service.rs:2547-2571；RT 轮换链必须与 AT 同生命周期终止）
        let rt_set_key = format!("sso:user_rt:{uid}");
        let rt_hashes: Vec<String> = self.set_members(&rt_set_key).await?;
        for h in &rt_hashes {
            let rt_key = format!("sso:rt:{h}");
            if self.get(&rt_key).await?.is_some() {
                self.del(&[rt_key]).await?;
                count += 1;
            }
        }
        if !rt_hashes.is_empty() {
            self.del(std::slice::from_ref(&rt_set_key)).await?;
            tracing::info!(user_id = %uid, "已全量吊销用户 SSO refresh_token count={}", rt_hashes.len());
        }
        Ok(count)
    }

    /// 集合添加成员：JSON 数组 get→append→set_ex 读改写（对齐 Redis SADD+EXPIRE）。
    ///
    /// ⚠ 非原子：同键并发 set_add 存在「后写覆盖前写」的丢成员窗口（同用户毫秒级并发
    /// 双签发才会触发）。影响评估：集合仅作「用户 → 已签发令牌」吊销索引，丢成员的后果
    /// = 漏吊销一条；而全量吊销/踢线的 SCAN 兜底路径（`sso:at:*` / `sso:rt:*` 模式扫描，
    /// 各绑定是独立 kv 行、SCAN 必达）不受索引成员缺失影响 ⇒ 安全全量性有兜底，窗口可接受。
    async fn set_add(&self, key: &str, member: &str, ttl_secs: u64) -> Result<(), StoreError> {
        let mut members: Vec<String> = match self.get(key).await? {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| StoreError::Corrupted(format!("集合键损坏 {key}: {e}")))?,
            None => Vec::new(),
        };
        if !members.iter().any(|m| m == member) {
            members.push(member.to_string());
        }
        let json = serde_json::to_string(&members)
            .map_err(|e| StoreError::Corrupted(format!("集合序列化失败 {key}: {e}")))?;
        self.set_ex(key, &json, ttl_secs).await
    }

    /// 集合移除成员：JSON 数组 remove→回写；移除后为空则删整键
    /// （等价 Redis「空集合键自动消失」）。键不存在/已过期/成员不在 = 幂等成功。
    /// 注意回写保留原 `expire_at`（对齐 SREM 不触碰 TTL 的语义，不续期）。
    async fn set_rem(&self, key: &str, member: &str) -> Result<(), StoreError> {
        let Some(m) = KvEntity::find_by_id(key)
            .one(&self.db)
            .await
            .map_err(|e| StoreError::backend(&e))?
        else {
            return Ok(()); // 键不存在：成员必然不在，幂等
        };
        if is_expired(m.expire_at) {
            return Ok(()); // 已过期 = 等价键已消失（惰性清理留给 get 路径），幂等成功
        }
        let members: Vec<String> = serde_json::from_str(&m.kv_value)
            .map_err(|e| StoreError::Corrupted(format!("集合键损坏 {key}: {e}")))?;
        let original_len = members.len();
        let remaining: Vec<String> = members
            .into_iter()
            .filter(|x| x.as_str() != member)
            .collect();
        if remaining.is_empty() {
            let key_owned = key.to_string();
            self.del(std::slice::from_ref(&key_owned)).await?;
        } else if remaining.len() != original_len {
            let json = serde_json::to_string(&remaining)
                .map_err(|e| StoreError::Corrupted(format!("集合序列化失败 {key}: {e}")))?;
            self.upsert_kv(key, &json, m.expire_at).await?;
        }
        Ok(())
    }

    /// 集合全量成员：JSON 数组解析；键不存在/已过期 = 空集（等价 SMEMBERS 空键语义）
    async fn set_members(&self, key: &str) -> Result<Vec<String>, StoreError> {
        match self.get(key).await? {
            Some(json) => serde_json::from_str(&json)
                .map_err(|e| StoreError::Corrupted(format!("集合键损坏 {key}: {e}"))),
            None => Ok(Vec::new()),
        }
    }

    /// 模式匹配键扫描：LIKE 前缀收窄（可选）+ glob_match 精确过滤，排除已过期行
    async fn scan(&self, pattern: &str, max: Option<usize>) -> Result<Vec<String>, StoreError> {
        if max == Some(0) {
            return Ok(Vec::new());
        }

        // 无通配符：退化为精确点查
        if !pattern.contains('*') {
            let row = self
                .db
                .query_one_raw(self.stmt(
                    "SELECT kv_key, expire_at FROM sys_shared_kv WHERE kv_key = ?",
                    vec![pattern.to_owned().into()],
                ))
                .await
                .map_err(|e| StoreError::backend(&e))?;
            return Ok(match row {
                Some(r) => {
                    let exp: Option<i64> = r
                        .try_get::<Option<i64>>("", "expire_at")
                        .map_err(|e| StoreError::backend(&e))?;
                    if is_expired(exp) {
                        Vec::new()
                    } else {
                        vec![pattern.to_string()]
                    }
                }
                None => Vec::new(),
            });
        }

        // 前缀优化：项目键规范均为 `前缀*` 形态（pattern 无前导 *）→ LIKE 'prefix%' 收窄。
        // 前缀含 LIKE 通配符（%/_/\）时放弃优化走全表（键为服务端生成、实际不会出现）。
        let prefix = pattern.split('*').next().unwrap_or("");
        let like_safe = !prefix.is_empty()
            && !prefix.contains('%')
            && !prefix.contains('_')
            && !prefix.contains('\\');
        let (sql, values) = if like_safe {
            (
                "SELECT kv_key, expire_at FROM sys_shared_kv WHERE kv_key LIKE ?".to_string(),
                vec![format!("{prefix}%").into()],
            )
        } else {
            (
                "SELECT kv_key, expire_at FROM sys_shared_kv".to_string(),
                Vec::new(),
            )
        };
        let rows = self
            .db
            .query_all_raw(self.stmt(&sql, values))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        let mut keys: Vec<String> = Vec::new();
        for r in rows {
            let key: String = r
                .try_get::<String>("", "kv_key")
                .map_err(|e| StoreError::backend(&e))?;
            let exp: Option<i64> = r
                .try_get::<Option<i64>>("", "expire_at")
                .map_err(|e| StoreError::backend(&e))?;
            if is_expired(exp) {
                continue; // 排除已过期行（等价 Redis 键自然消失）
            }
            if glob_match(pattern, &key) {
                keys.push(key);
                if let Some(n) = max
                    && keys.len() >= n
                {
                    // 截断语义对齐 utils::redis::scan_keys：达硬上限即停 + warn（只读展示用）
                    tracing::warn!("scan 达到上限 {n}（pattern={pattern}），提前停止扫描（截断）");
                    keys.truncate(n);
                    break;
                }
            }
        }
        Ok(keys)
    }

    /// 存活探测：DB ping
    async fn ping(&self) -> Result<(), StoreError> {
        self.db.ping().await.map_err(|e| StoreError::backend(&e))
    }

    /// 运行摘要：三承载表行计数（redis 档为 INFO 文本，消费端按 kind 区分解析）
    async fn info_summary(&self) -> Result<String, StoreError> {
        let kv = self.count_table("sys_shared_kv").await?;
        let locks = self.count_table("sys_shared_lock").await?;
        let revocations = self.count_table("sys_token_revocation").await?;
        Ok(format!(
            "mode=local kv_entries={kv} shared_locks={locks} revocations={revocations}"
        ))
    }
}

impl LocalStore {
    /// 计数单表（表名仅由 info_summary 传入字面量，无注入面）
    async fn count_table(&self, table: &str) -> Result<i64, StoreError> {
        let sql = format!("SELECT COUNT(*) AS cnt FROM {table}");
        let row = self
            .db
            .query_one_raw(self.stmt(&sql, Vec::new()))
            .await
            .map_err(|e| StoreError::backend(&e))?;
        match row {
            Some(r) => r
                .try_get::<i64>("", "cnt")
                .map_err(|e| StoreError::backend(&e)),
            None => Err(StoreError::Backend(format!("COUNT 无行: {table}"))),
        }
    }

    /// incr_with_ttl 单次尝试（返回 UniqueConflict 供上层重试）
    async fn try_incr_once(&self, key: &str, ttl_secs: u64) -> Result<i64, IncrErr> {
        // 无捕获闭包为 Copy，可反复作为 map_err 的 FnOnce 消费
        let failed = |e: DbErr| IncrErr::Failed(StoreError::backend(&e));
        let now = now_secs();
        let txn = self.db.begin().await.map_err(failed)?;
        let row = txn
            .query_one_raw(self.stmt(
                "SELECT kv_value, expire_at FROM sys_shared_kv WHERE kv_key = ?",
                vec![key.to_owned().into()],
            ))
            .await
            .map_err(failed)?;
        if let Some(r) = row {
            let val: String = r.try_get::<String>("", "kv_value").map_err(failed)?;
            let exp: Option<i64> = r.try_get::<Option<i64>>("", "expire_at").map_err(failed)?;
            if !is_expired(exp) {
                // 未过期：cur + 1，保留原 expire_at（对齐 Redis INCR 不重置 TTL）
                let cur = val.parse::<i64>().map_err(|_| {
                    IncrErr::Failed(StoreError::Corrupted(format!(
                        "incr_with_ttl：键 {key} 的值非整数: {val}"
                    )))
                })?;
                let new = cur + 1;
                txn.execute_raw(self.stmt(
                    "UPDATE sys_shared_kv SET kv_value = ? WHERE kv_key = ?",
                    vec![new.to_string().into(), key.to_owned().into()],
                ))
                .await
                .map_err(failed)?;
                txn.commit().await.map_err(failed)?;
                return Ok(new);
            }
            // 已过期：等价键已消失 → 删除后按首次自增处理
            txn.execute_raw(self.stmt(
                "DELETE FROM sys_shared_kv WHERE kv_key = ?",
                vec![key.to_owned().into()],
            ))
            .await
            .map_err(failed)?;
        }
        // 首次自增：new = 1 且设置 TTL（RATE_LIMIT_SCRIPT 的 INCR==1 → EXPIRE 分支）
        let exp = now + ttl_secs as i64;
        match txn
            .execute_raw(self.stmt(
                "INSERT INTO sys_shared_kv (kv_key, kv_value, expire_at) VALUES (?, ?, ?)",
                vec![key.to_owned().into(), "1".to_owned().into(), exp.into()],
            ))
            .await
        {
            Ok(_) => {
                txn.commit().await.map_err(failed)?;
                Ok(1)
            }
            Err(e) if is_unique_conflict(&e) => {
                let _ = txn.rollback().await;
                Err(IncrErr::UniqueConflict)
            }
            Err(e) => Err(failed(e)),
        }
    }
}

/// incr_with_ttl 单次尝试的错误分类（并发首插竞态可重试）
enum IncrErr {
    UniqueConflict,
    Failed(StoreError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_expired() {
        let now = now_secs();
        assert!(!is_expired(None), "None = 永不过期");
        assert!(!is_expired(Some(now + 10)), "未来时间未过期");
        assert!(is_expired(Some(now - 10)), "过去时间已过期");
        assert!(is_expired(Some(now)), "当前时刻视为过期（TTL 边界）");
    }

    #[test]
    fn test_is_unique_conflict() {
        // 三方言典型唯一键冲突报文均可识别
        assert!(is_unique_conflict(&DbErr::Custom(
            "UNIQUE constraint failed: sys_shared_kv.kv_key".to_string()
        )));
        assert!(is_unique_conflict(&DbErr::Custom(
            "duplicate key value violates unique constraint".to_string()
        )));
        assert!(is_unique_conflict(&DbErr::Custom(
            "Duplicate entry 'x' for key 'PRIMARY'".to_string()
        )));
        assert!(
            !is_unique_conflict(&DbErr::Custom("connection refused".to_string())),
            "真 DB 错误不得误判为键冲突"
        );
    }
}
