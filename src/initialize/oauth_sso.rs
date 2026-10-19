// stepby-axum/src/initialize/oauth_sso.rs

use crate::config::Settings;
use crate::shared_store::SharedStore;
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};
use std::sync::Arc;

/// 幂等检查表是否存在（三方言）
pub(crate) async fn sso_table_exists(db: &DatabaseConnection, table: &str) -> anyhow::Result<bool> {
    let backend = db.get_database_backend();

    let sql = match backend {
        DatabaseBackend::Sqlite => {
            format!("SELECT 1 FROM sqlite_master WHERE type='table' AND name='{table}'")
        }
        DatabaseBackend::Postgres => format!(
            "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema=current_schema() LIMIT 1"
        ),
        DatabaseBackend::MySql => format!(
            "SELECT 1 FROM information_schema.tables WHERE table_name='{table}' AND table_schema=DATABASE() LIMIT 1"
        ),
        _ => unreachable!("unknown backend"),
    };
    Ok(!db
        .query_all_raw(Statement::from_string(backend, sql))
        .await?
        .is_empty())
}

/// 幂等检查列是否存在（三方言）
pub(crate) async fn sso_has_column(
    db: &DatabaseConnection,
    table: &str,
    column: &str,
) -> anyhow::Result<bool> {
    let backend = db.get_database_backend();
    let rows = match backend {
        DatabaseBackend::Sqlite => {
            db.query_all_raw(Statement::from_string(
                backend,
                format!("PRAGMA table_info({table})"),
            ))
            .await?
        }
        _ => {
            let schema = if backend == DatabaseBackend::Postgres {
                "table_schema=current_schema()"
            } else {
                "table_schema=DATABASE()"
            };
            db.query_all_raw(Statement::from_string(
                backend,
                format!("SELECT 1 FROM information_schema.columns WHERE table_name='{table}' AND column_name='{column}' AND {schema} LIMIT 1"),
            ))
            .await?
        }
    };
    if backend == DatabaseBackend::Sqlite {
        Ok(rows.iter().any(|row| {
            row.try_get::<String>("", "name")
                .map(|n| n.eq_ignore_ascii_case(column))
                .unwrap_or(false)
        }))
    } else {
        Ok(!rows.is_empty())
    }
}

/// v4 加固：幂等确保 SSO 表新列与存量数据回填（等价 m20260923_000001_sso_v4_hardening）
///
/// - sys_oauth_client：+ update_by / + del_flag（客户端软删，v2-K7/P1-5）
/// - sys_oauth_consent：auth_time → consented_at 更名（v4-R4 语义修正）、
///   + client_name_snapshot（v4-R6 名称快照）、+ del_flag（撤销=软删，v2-I7）
/// - 存量回填：consented_at ← create_time；client_name_snapshot ← 当前客户端名；
///   grant_types 去除未实现的 refresh_token（v4 §1.2）
/// - 存量明文 id_token_secret 以 `CONFIG_ENC_KEY` 加密（v3-P1'-4，读到一条加密一条）
///
/// 第九批（D10）：主密钥改为**由调用方传入**（`settings.config_enc_key`），
/// 不再在本函数内 `std::env::var("CONFIG_ENC_KEY")` 直读 —— 收敛为 Settings 单一入口，
/// 未来接 KMS/HSM 只需改配置层一处（原实现绕过配置层，是密钥读取点分散的最后一处）。
pub(crate) async fn ensure_sso_v4_columns(
    db: &DatabaseConnection,
    config_enc_key: &str,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_client").await?
        || !sso_table_exists(db, "sys_oauth_consent").await?
    {
        tracing::info!("SSO 表尚未创建，跳过 v4 列检查（由 migration 负责建表）");
        return Ok(());
    }

    // ---- sys_oauth_client ----
    if !sso_has_column(db, "sys_oauth_client", "update_by").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN update_by VARCHAR(64) DEFAULT ''",
        ))
        .await?;
    }
    if !sso_has_column(db, "sys_oauth_client", "del_flag").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN del_flag VARCHAR(1) NOT NULL DEFAULT '0'",
        ))
        .await?;
    }

    // ---- sys_oauth_consent：auth_time → consented_at ----
    let has_consented_at = sso_has_column(db, "sys_oauth_consent", "consented_at").await?;
    let has_auth_time = sso_has_column(db, "sys_oauth_consent", "auth_time").await?;
    if !has_consented_at && has_auth_time {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent RENAME COLUMN auth_time TO consented_at",
        ))
        .await?;
        tracing::info!("sys_oauth_consent.auth_time 已更名为 consented_at（v4-R4）");
    } else if !has_consented_at && !has_auth_time {
        // 极旧结构缺列：直接补（无可迁移数据）
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent ADD COLUMN consented_at DATETIME",
        ))
        .await?;
    }
    if !sso_has_column(db, "sys_oauth_consent", "client_name_snapshot").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent ADD COLUMN client_name_snapshot VARCHAR(128) NOT NULL DEFAULT ''",
        ))
        .await?;
    }
    if !sso_has_column(db, "sys_oauth_consent", "del_flag").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_consent ADD COLUMN del_flag VARCHAR(1) NOT NULL DEFAULT '0'",
        ))
        .await?;
    }

    // ---- 存量回填 ----
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_oauth_consent SET consented_at = create_time WHERE consented_at IS NULL",
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_oauth_consent SET client_name_snapshot = COALESCE(\
            (SELECT c.client_name FROM sys_oauth_client c WHERE c.client_id = sys_oauth_consent.client_id), '') \
         WHERE client_name_snapshot = ''",
    ))
    .await?;
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "UPDATE sys_oauth_client SET grant_types = '[\"authorization_code\"]' \
         WHERE grant_types LIKE '%refresh_token%'",
    ))
    .await?;

    // ---- 存量明文 id_token_secret 加密（fail-open：主密钥未配置时跳过，留待配置后回填）----
    //
    // ⚠️ 双重加密防线（第八批修复，P0）：
    // 原实现有**两个叠加缺陷**，导致每次启动把已加密值**再加密一次**（base64 膨胀 ×4/3），
    // 实测把 `id_token_secret` 单字段涨到 743 MB、全表 4.5 GB（启动缓慢如挂死），
    // 且 HS256 签名密钥被套娃加密 N 层（原密钥不可直接使用）：
    //   ① SQL 判据 `NOT LIKE 'enc:%'` **认不出 `enc2:`**（本函数的写入格式就是 `enc2:`，
    //      见 `crypto::ENCRYPTED_PREFIX_V2`）⇒ 每次启动都把这些行重新选出来；
    //   ② 加密调用用的是**无防重守卫**的 `encrypt_config_value`（`seal_sensitive_value`
    //      才有前缀守卫）⇒ 选出来就真加密一次。
    // 修复：① 判据由**共享常量**拼出（两个前缀都排除，杜绝再次漂移）；
    //       ② 写入改用带守卫的 `seal_sensitive_value`；③ 循环内再用
    //       `crypto::is_encrypted` 做一次 Rust 侧权威判定（纵深防御）。
    let backend = db.get_database_backend();
    let (p1, p2) = (
        crate::utils::crypto::ENCRYPTED_PREFIX,
        crate::utils::crypto::ENCRYPTED_PREFIX_V2,
    );
    let rows = db
        .query_all_raw(Statement::from_string(
            backend,
            format!(
                "SELECT sso_client_id, id_token_secret FROM sys_oauth_client \
                 WHERE id_token_secret != '' \
                   AND id_token_secret NOT LIKE '{p1}%' \
                   AND id_token_secret NOT LIKE '{p2}%'"
            ),
        ))
        .await?;
    if rows.is_empty() {
        return Ok(());
    }
    let enc_key = config_enc_key.to_string();
    if enc_key.is_empty() {
        tracing::warn!(
            "检测到 {} 条明文 id_token_secret，但 CONFIG_ENC_KEY 未配置，跳过加密（fail-open，与配置层策略一致）",
            rows.len()
        );
        return Ok(());
    }
    let mut encrypted = 0usize;
    let (ph_enc, ph_pk) = if backend == DatabaseBackend::Postgres {
        ("$1", "$2")
    } else {
        ("?", "?")
    };
    for row in rows {
        let Ok(pk) = row.try_get::<i64>("", "sso_client_id") else {
            continue;
        };
        let Ok(plain) = row.try_get::<String>("", "id_token_secret") else {
            continue;
        };
        // Rust 侧权威判定：已加密（enc:/enc2:）一律跳过，避免任何 SQL 判据漂移导致双重加密
        if crate::utils::crypto::is_encrypted(&plain) {
            continue;
        }
        match crate::utils::crypto::seal_sensitive_value(&plain, &enc_key) {
            Ok(enc) => {
                db.execute_raw(Statement::from_sql_and_values(
                    backend,
                    format!(
                        "UPDATE sys_oauth_client SET id_token_secret = {ph_enc} WHERE sso_client_id = {ph_pk}"
                    ),
                    [enc.into(), pk.into()],
                ))
                .await?;
                encrypted += 1;
            }
            Err(e) => tracing::error!("id_token_secret 回填加密失败 sso_client_id={pk}: {e}"),
        }
    }
    if encrypted > 0 {
        tracing::info!("已加密存量明文 id_token_secret {encrypted} 条（v3-P1'-4）");
    }
    Ok(())
}

/// v4 §1.3 / §10：SSO 启动自检（仅告警，不阻断启动）
///
/// 1. SSO 启用时 issuer 必须为 https（本机回环豁免，validate_secrets 已硬校验，此处兜底告警）；
/// 2. 存量 client_id 与平台 JWT 命名空间（audience/issuer）碰撞 → 告警（新客户端已被
///    add_client 保留字校验拦截，存量只提示管理员整改）。
pub(crate) async fn sso_startup_self_check(db: &DatabaseConnection, settings: &Settings) {
    if !settings.sso.enabled {
        return;
    }
    if !sso_table_exists(db, "sys_oauth_client")
        .await
        .unwrap_or(false)
    {
        return;
    }
    let issuer = settings.sso.issuer.trim();
    if issuer.is_empty() {
        tracing::warn!("SSO 启动自检：issuer 未配置（SSO_ISSUER），发现文档将回退请求 base_url");
    }
    let audience = settings.jwt.audience.trim();
    let jwt_issuer = settings.jwt.issuer.trim();
    let backend = db.get_database_backend();
    for reserved in [audience, jwt_issuer] {
        if reserved.is_empty() {
            continue;
        }
        let sql =
            format!("SELECT COUNT(*) AS c FROM sys_oauth_client WHERE client_id = '{reserved}'");
        if let Ok(Some(row)) = db.query_one_raw(Statement::from_string(backend, sql)).await {
            let count = row.try_get::<i64>("", "c").unwrap_or(0);
            if count > 0 {
                tracing::warn!(
                    "SSO 启动自检：存在与平台 JWT 命名空间撞名的 client_id='{reserved}'，请尽快整改（v4 §1.3）"
                );
            }
        }
    }
}

/// 台账 MT-4 / E-2（第十批）：域名链路「**静默失效**」启动自检。
///
/// ## 为什么需要它
/// `middleware/tenant_host.rs` 仅在**直连 peer ∈ `server.trusted_proxies`** 时采信
/// `X-Tenant-Code` / `Host`；若生产反代未把网关 IP 段写入该白名单，域名链路会
/// **静默退化**为 `HostTenant(None)`（无异常、无日志、页面照常）——排障成本极高。
///
/// ## 判据（只报"确定不一致"的组合）
/// `trusted_proxies` 为空 **且** `sys_tenant_domain` 存在启用中的绑定行
/// ⇒ 已配置租户域名却永不生效。此组合在开发/单机环境属**正常**
/// （未部署反代、无域名绑定），故仅在"确有域名绑定"时才告警，避免噪音。
///
/// ## 边界
/// - **仅告警不阻断**（与 3.7 SSO 自检同口径：存量部署允许先启动后整改）；
/// - 数据隔离**不因此失效**：JWT `tid` 经 `common::tenant::tenant_scope` 仍强制过滤，
///   降级仅失去"按 host 判定租户 / host×tid 一致性校验"，不产生跨租户数据泄漏；
/// - 表缺失 / 查询失败一律静默返回（本函数绝不影响启动）。
///
/// 返回值：**已告警时**返回可解析的域名绑定数（`Some(count)`），否则 `None`。
/// "可解析"口径与 `find_active_by_domain` 一致（`del_flag='0' + status='0' + verify_status='1'`）。
/// 之所以把"是否告警"作为返回值暴露，是为了让本自检**可被断言**（见
/// `tenant_host_chain_self_check_tests`）——只写日志的检查无法证伪。
pub(crate) async fn tenant_host_chain_self_check(
    db: &DatabaseConnection,
    trusted_proxies: &[String],
) -> Option<i64> {
    if !trusted_proxies.is_empty() {
        return None;
    }
    if !sso_table_exists(db, "sys_tenant_domain")
        .await
        .unwrap_or(false)
    {
        return None;
    }
    // 口径与真实的 host→tid 解析源严格一致（`SysTenantDomainRepository::find_active_by_domain`：
    // del_flag='0' + status='0' + verify_status='1'）——只有"**可解析**的绑定"配合空白名单
    // 才是**确定**的静默失效；未验证/已停用的绑定不参与解析，不应产生误报。
    let sql = "SELECT COUNT(*) AS c FROM sys_tenant_domain \
               WHERE del_flag = '0' AND status = '0' AND verify_status = '1'";
    if let Ok(Some(row)) = db
        .query_one_raw(Statement::from_string(db.get_database_backend(), sql))
        .await
    {
        let count = row.try_get::<i64>("", "c").unwrap_or(0);
        if count > 0 {
            tracing::warn!(
                active_domains = count,
                "域名链路自检：server.trusted_proxies 为空但已存在 {count} 条**可解析**的租户域名绑定\
                 （启用 + 已校验）⇒ host→租户 解析将**静默失效**（header 一律不采信）。请在生产反代\
                 环境中把网关 IP 段写入 server.trusted_proxies（台账 MT-4 / E-2；数据隔离不受影响，\
                 仅失去 host 维度）。"
            );
            return Some(count);
        }
    }
    None
}

/// v5-D2：为存量 RS256 客户端补生成 RSA-2048 私钥（幂等：仅处理 rsa_private_key 为
/// NULL 且 id_token_alg='RS256' 的行）。PKCS#8 PEM 按 CONFIG_ENC_KEY 信封加密落库
/// （key 未配置时明文，迁移期策略与 v5-E6 一致）；CONFIG_ENC_KEY 未配置时整体跳过。
pub(crate) async fn ensure_sso_rs256_keys(
    db: &DatabaseConnection,
    enc_key: &str,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_client").await? {
        return Ok(());
    }
    // v5-D2/D5：存量库启动不跑 Migrator::up——先幂等补列（id_token_alg/rsa_private_key/
    // subject_type），否则下方查询因缺列直接失败（真实运行验证发现的启动阻断）
    if !sso_has_column(db, "sys_oauth_client", "id_token_alg").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN id_token_alg VARCHAR(8) NOT NULL DEFAULT 'RS256'"
                .to_string(),
        ))
        .await?;
        tracing::info!("sys_oauth_client.id_token_alg 列已补建（v5-D2 存量库兜底）");
    }
    if !sso_has_column(db, "sys_oauth_client", "rsa_private_key").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN rsa_private_key TEXT".to_string(),
        ))
        .await?;
        tracing::info!("sys_oauth_client.rsa_private_key 列已补建（v5-D2 存量库兜底）");
    }
    if !sso_has_column(db, "sys_oauth_client", "subject_type").await? {
        db.execute_raw(Statement::from_string(
            db.get_database_backend(),
            "ALTER TABLE sys_oauth_client ADD COLUMN subject_type VARCHAR(8) NOT NULL DEFAULT 'public'"
                .to_string(),
        ))
        .await?;
        tracing::info!("sys_oauth_client.subject_type 列已补建（v5-D5 存量库兜底）");
    }
    if enc_key.is_empty() {
        tracing::warn!("CONFIG_ENC_KEY 未配置：跳过 RS256 密钥生成（v5-D2，下次启动重试）");
        return Ok(());
    }
    let backend = db.get_database_backend();
    let select_sql = "SELECT sso_client_id AS pk, client_id AS cid FROM sys_oauth_client \
                      WHERE rsa_private_key IS NULL AND id_token_alg = 'RS256'";
    let rows = db
        .query_all_raw(Statement::from_string(backend, select_sql))
        .await?;
    for row in rows {
        let pk = row.try_get::<i64>("", "pk").unwrap_or(0);
        let cid = row.try_get::<String>("", "cid").unwrap_or_default();
        // v5-D2 修正：keygen 在专用大栈线程执行（tokio 栈上 stack overflow 硬崩，
        // 与 sso_service::generate_rsa_private_pem 同款防护）
        let pem = match tokio::task::spawn_blocking(|| {
            crate::service::sso_service::generate_rsa_private_pem()
        })
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                tracing::error!("v5-D2 RSA 生成失败 client_id={cid}: {}", e);
                continue;
            }
            Err(e) => {
                tracing::error!("v5-D2 RSA keygen 任务失败 client_id={cid}: {}", e);
                continue;
            }
        };
        let sealed = match crate::utils::crypto::seal_sensitive_value(&pem, enc_key) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("v5-D2 RSA 私钥加密失败 client_id={cid}: {}", e);
                continue;
            }
        };
        let update_sql = format!(
            "UPDATE sys_oauth_client SET rsa_private_key = '{}' WHERE sso_client_id = {pk}",
            sealed.replace('\'', "''")
        );
        db.execute_raw(Statement::from_string(backend, update_sql))
            .await?;
        tracing::info!("v5-D2 已为存量客户端生成 RS256 密钥 client_id={cid}");
    }
    Ok(())
}

/// v5-E1：consent 组合唯一索引兜底（幂等）——清软删行、同 (user_id, client_id)
/// 去重（保留最早）、建唯一索引 uq_sso_consent_user_client。与迁移
/// m20260924_000002_sso_consent_unique 等价；索引已存在时容错跳过。
pub(crate) async fn ensure_sso_consent_unique(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_consent").await? {
        return Ok(());
    }
    let backend = db.get_database_backend();
    // 去重 DELETE：MySQL 不允许 DELETE 目标表同时出现在子查询 FROM（1093），
    // 派生表包裹（物化）后三方言等价，与迁移侧 SQL 一致
    let dedup_sql = "DELETE FROM sys_oauth_consent WHERE consent_id NOT IN (\
         SELECT keep_id FROM (\
         SELECT MIN(consent_id) AS keep_id FROM sys_oauth_consent GROUP BY user_id, client_id\
         ) keep_rows)";
    let stmts = [
        "DELETE FROM sys_oauth_consent WHERE del_flag = '2'",
        dedup_sql,
    ];
    for sql in stmts {
        db.execute_raw(Statement::from_string(backend, sql.to_string()))
            .await?;
    }
    // 唯一索引：MySQL 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属子句），
    // 剥离子句后执行并容错"索引已存在"（1061 Duplicate key name / 42P07 / already exists）
    let idx_sql = match backend {
        DatabaseBackend::MySql => {
            "CREATE UNIQUE INDEX uq_sso_consent_user_client \
             ON sys_oauth_consent (user_id, client_id)"
        }
        _ => {
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_sso_consent_user_client \
             ON sys_oauth_consent (user_id, client_id)"
        }
    };
    if let Err(e) = db
        .execute_raw(Statement::from_string(backend, idx_sql.to_string()))
        .await
    {
        let msg = e.to_string();
        if !(msg.contains("Duplicate key name")
            || msg.contains("42P07")
            || msg.contains("already exists"))
        {
            return Err(e.into());
        }
        tracing::debug!("uq_sso_consent_user_client 已存在，跳过");
    }
    Ok(())
}

/// v5-E6：运行期敏感凭据存量明文回填（幂等）。
///
/// 范围（四组明文落库的敏感列，与 id_token_secret 同标准信封加密）：
/// - `sys_oauth_provider.client_secret`（第三方 OAuth 客户端密钥）
/// - `sys_oauth_user.access_token` / `refresh_token`（第三方用户令牌）
/// - `sys_msg_channel.config_json`（渠道配置，含 SMTP 凭据）
/// - `sys_web_hook.secret`（回调 HMAC 签名密钥）
///
/// 规则：CONFIG_ENC_KEY 未配置 → 跳过（fail-open，下次启动重试）；
/// 值已带 `enc3:` 前缀 → 跳过（已是当前格式，幂等）；`enc2:`/`enc:` 存量 →
/// 解密后以 v3 信封 re-encrypt（G-14 密钥轮换格式迁移，解密失败保持原值下轮重试）；
/// 明文/空值 → `seal_sensitive_value` 加密 UPDATE（逐行，幂等：回填后即带前缀）。
pub(crate) async fn ensure_runtime_secrets_encrypted(db: &DatabaseConnection, enc_key: &str) {
    if enc_key.is_empty() {
        tracing::warn!("CONFIG_ENC_KEY 未配置：跳过运行期敏感凭据存量明文回填（v5-E6）");
        return;
    }
    // (表, 主键列, 敏感列)
    const TARGETS: &[(&str, &str, &str)] = &[
        ("sys_oauth_provider", "provider_id", "client_secret"),
        ("sys_oauth_user", "oauth_id", "access_token"),
        ("sys_oauth_user", "oauth_id", "refresh_token"),
        ("sys_msg_channel", "channel_id", "config_json"),
        ("sys_web_hook", "id", "secret"),
    ];
    let backend = db.get_database_backend();
    let mut sealed_total = 0usize;
    let mut reencrypted_total = 0usize;
    for (table, pk, col) in TARGETS {
        let select_sql = format!(
            "SELECT {pk} AS pk, {col} AS val FROM {table} WHERE {col} IS NOT NULL AND {col} != ''"
        );
        let rows = match db
            .query_all_raw(Statement::from_string(backend, select_sql))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // 表可能不存在（极旧存量库），warn 并继续下一目标
                tracing::warn!("v5-E6 回填读取 {table}.{col} 失败（跳过）: {}", e);
                continue;
            }
        };
        for row in rows {
            let pk_val = match row.try_get::<i64>("", "pk") {
                Ok(v) => v,
                Err(_) => continue,
            };
            let val = match row.try_get::<String>("", "val") {
                Ok(v) => v,
                Err(_) => continue,
            };
            // G-14：已是 v3（enc3:）→ 跳过（幂等）；v1/v2（enc:/enc2:）→ unseal 后
            // 以 v3 信封 re-encrypt（密钥轮换迁移期）；明文 → seal（enc3）
            if val.starts_with("enc3:") {
                continue;
            }
            let is_legacy = val.starts_with("enc2:") || val.starts_with("enc:");
            let sealed = if is_legacy {
                // 格式迁移：解出明文再重加密（解密失败=密钥不匹配/数据损坏，
                // 保持原值不动并告警，下轮启动重试——不"修"坏数据）
                match crate::utils::crypto::decrypt_config_value(&val, enc_key)
                    .and_then(|plain| crate::utils::crypto::encrypt_config_value(&plain, enc_key))
                {
                    Ok(s) => {
                        reencrypted_total += 1;
                        s
                    }
                    Err(e) => {
                        tracing::warn!(
                            "v5-E6 存量 v1/v2 密文迁移失败（保持原值，下轮重试） {table}.{col} pk={pk_val}: {}",
                            e
                        );
                        continue;
                    }
                }
            } else {
                match crate::utils::crypto::seal_sensitive_value(&val, enc_key) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("v5-E6 回填加密失败 {table}.{col} pk={pk_val}: {}", e);
                        continue;
                    }
                }
            };
            let update_sql = format!(
                "UPDATE {table} SET {col} = '{}' WHERE {pk} = {pk_val}",
                sealed.replace('\'', "''")
            );
            if let Err(e) = db
                .execute_raw(Statement::from_string(backend, update_sql))
                .await
            {
                tracing::error!("v5-E6 回填更新失败 {table}.{col} pk={pk_val}: {}", e);
                continue;
            }
            if !is_legacy {
                sealed_total += 1;
            }
        }
    }
    if sealed_total > 0 {
        tracing::info!("v5-E6 已加密回填运行期敏感凭据 {sealed_total} 条（v5-E6）");
    }
    if reencrypted_total > 0 {
        tracing::info!(
            "G-14 密钥轮换格式迁移：v1/v2 信封已 re-encrypt 为 v3（enc3:k1）共 {reencrypted_total} 条"
        );
    }
}

/// v5-S1：SSO/OIDC 公开端点限流分档（存量库兜底，幂等）。
///
/// 与迁移 m20260924_000001_sso_rate_limit_tiers 等价：rate_limit 中间件先按
/// route_pattern 精确匹配、未命中回退 '*'；此处为不跑 Migrator::up 的存量库
/// 以「查存在 → 缺则 INSERT」补齐五条分档（应用层判存，跨 SQLite/PG/MySQL 稳定）。
/// 已有同 pattern 行（运维自调）不覆盖。生效时机：下次启动或 Redis 配置缓存过期。
pub(crate) async fn ensure_sso_rate_limit_tiers(db: &DatabaseConnection) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_rate_limit").await? {
        return Ok(()); // 极旧存量库无限流表（理论不可达，防御性跳过）
    }
    const TIERS: &[(&str, u32, f64, &str)] = &[
        (
            "/sso/token",
            30,
            0.5,
            "SSO 令牌兑换（机器对机器，严档防暴力试 secret）",
        ),
        (
            "/sso/authorize",
            60,
            1.0,
            "SSO 授权端点（浏览器导航，中档）",
        ),
        ("/sso/logout", 30, 0.5, "SSO 登出（低频严档）"),
        (
            "/sso/userinfo",
            120,
            2.0,
            "SSO 用户信息（RP 高频会话校验，宽档）",
        ),
        (
            "/.well-known/openid-configuration",
            60,
            1.0,
            "OIDC 发现文档（RP 启动期拉取，中档）",
        ),
    ];
    let backend = db.get_database_backend();
    for (pattern, capacity, refill, description) in TIERS {
        let count_sql =
            format!("SELECT COUNT(*) AS c FROM sys_rate_limit WHERE route_pattern = '{pattern}'");
        let exists = match db
            .query_one_raw(Statement::from_string(backend, count_sql))
            .await?
        {
            Some(row) => row.try_get::<i64>("", "c").unwrap_or(0) > 0,
            None => false,
        };
        if exists {
            continue;
        }
        // 落库时间必须走 UTC 口径（`now_naive()`），不得用本机挂钟：
        // 批七十四 B1 实测本行原为 `chrono::Local::now()` ⇒ 同一库内 SSO 限流档的
        // create_time 比运行期写入的其余行快 8 小时，`db_state_audit` 的"未来时间"
        // 检查看不到它（该检查仅在 UTC+ 时区暴露问题，见台账 §3.2-3 负偏移盲区）。
        let now = crate::common::datetime::now_naive().format("%Y-%m-%d %H:%M:%S");
        let insert_sql = format!(
            "INSERT INTO sys_rate_limit (route_pattern, capacity, refill_per_second, enabled, description, create_by, create_time, update_by, update_time) \
             VALUES ('{pattern}', {capacity}, {refill}, TRUE, '{description}', 'admin', '{now}', 'admin', '{now}')"
        );
        db.execute_raw(Statement::from_string(backend, insert_sql))
            .await?;
        tracing::info!("已插入 SSO 限流分档 route_pattern={pattern}");
    }
    Ok(())
}

/// 读取一条 `SELECT COUNT(*) AS c ...` 的结果（跨方言返回 i64）。
pub(crate) async fn count_scalar(db: &DatabaseConnection, sql: String) -> anyhow::Result<i64> {
    let backend = db.get_database_backend();
    let row = db
        .query_one_raw(Statement::from_string(backend, sql))
        .await?;
    match row {
        Some(r) => Ok(r.try_get::<i64>("", "c").unwrap_or(0)),
        None => Ok(0),
    }
}

pub(crate) async fn revoke_legacy_sso_at_tokens(store: &Arc<dyn SharedStore>) {
    const LEGACY_MARKER: &str = "sso:v4_legacy_at_migrated";
    const LEGACY_AT_PREFIX: &str = "sso:at:";
    /// 历史 JWT 型 SSO AT 的最大剩余寿命 = 平台 JWT TTL 上限（expire_hours ≤ 24h）
    const LEGACY_TTL_FLOOR_SECS: u64 = 86_400;
    /// 幂等标记 TTL。原实现为无 TTL 的永久 SETNX；trait 的 NX 语义统一带 TTL，
    /// 取 10 年近似"永久"（标记丢失的最坏后果 = 重跑一次幂等转写，无害）。
    const MARKER_TTL_SECS: u64 = 10 * 365 * 24 * 3600;

    // 幂等标记（SETNX；已标记即跳过转写）。store 内部已管超时/事务，无需 cmd_timeout 包裹。
    match store.set_nx_ex(LEGACY_MARKER, "1", MARKER_TTL_SECS).await {
        Err(e) => {
            tracing::warn!("v4-F1 存量转写跳过（共享态存储不可达，下次启动重试）: {e}");
            return;
        }
        Ok(false) => return, // 已标记：转写已完成
        Ok(true) => {}
    }

    // 全量扫描 sso:at:*（安全吊销必须扫到尾，禁用截断版）
    let keys = match store.scan(&format!("{LEGACY_AT_PREFIX}*"), None).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "v4-F1 存量转写 SCAN 失败（已置标记，可用 DEL {LEGACY_MARKER} 重跑）: {e}"
            );
            return;
        }
    };

    let mut migrated = 0usize;
    let mut skipped = 0usize;
    for key in &keys {
        let Some(hash) = key.strip_prefix(LEGACY_AT_PREFIX) else {
            continue;
        };
        if hash.is_empty() {
            continue;
        }
        // v5 核查：A 形态活跃绑定（value 含 access_token_hash）不转写，防误杀
        let is_legacy = store
            .get(key)
            .await
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok())
            .map(|json| !json.get("access_token_hash").is_some());
        match is_legacy {
            Some(false) => {
                skipped += 1;
                continue;
            }
            None => {
                // 读取/解析失败（key 已过期或 value 异常）→ 按过期清理处理
            }
            _ => {}
        }
        // TTL 语义：原实现 effective_ttl = max(剩余TTL, 24h) ≥ 24h；trait 未暴露 TTL 读数，
        // 统一取下界 24h（对已失效/不存在键多吊销一段 hash 属 fail-safe，无越权风险）。
        let effective_ttl = LEGACY_TTL_FLOOR_SECS;
        let expire_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
            + effective_ttl as i64;
        // blacklist 登记（redis 档 = SETEX + DB 权威层双写；local 档 = INSERT 权威层）
        let set = store.revocation_add(hash, expire_at, "sso_legacy_at").await;
        match set {
            Ok(()) => {
                // 绑定转写成功后删除原 key：userinfo（只认绑定）与业务路由（认 blacklist）
                // 双路径同时立即 401
                if let Err(e) = store.del(std::slice::from_ref(key)).await {
                    tracing::warn!(key = %key, error = %e, "SSO 旧令牌键清理失败，可能延迟 401（已写入 blacklist，安全语义不受影响）")
                }
                migrated += 1;
            }
            Err(e) => {
                tracing::warn!("v4-F1 绑定 {} 转写失败（跳过，下次启动重试）: {e}", key);
            }
        }
    }
    if migrated > 0 {
        tracing::info!(
            "v4-F1 已转写吊销历史 JWT 型 SSO 访问令牌 {migrated} 条（blacklist，TTL≥24h）"
        );
    }
    if skipped > 0 {
        tracing::info!("v4-F1 跳过 A 形态活跃绑定 {skipped} 条（含 access_token_hash，不转写）");
    }
}

/// 台账 D9（存量库兜底，等价迁移 m20260926_000004）：`sys_oauth_client.key_id`
/// 密钥版本列（RS256 密钥轮换预备；历史密钥留 NULL = 未登记版本）。
pub(crate) async fn ensure_oauth_client_key_id_column(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_client").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_oauth_client", "key_id").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_oauth_client ADD COLUMN key_id VARCHAR(64) NULL".to_string(),
    ))
    .await?;
    tracing::info!("sys_oauth_client.key_id 列已补建（台账 D9 存量库兜底）");
    Ok(())
}

/// SSO D9（存量库兜底，等价迁移 `m20260927_000001`）：`sys_oauth_client.previous_client_secret_hash`
/// —— `client_secret` 零停机轮换的"双密钥读取期"列。
///
/// 为何必须有本兜底：embedded/存量库按架构约定**不跑 `Migrator::up`**，而实体已声明该列
/// ⇒ 缺此兜底则客户端列表/详情/令牌端点鉴权全链报 `no such column: previous_client_secret_hash`（500）。
/// 幂等：列已存在或表不存在时安全返回；存量行留 `NULL` = 无过渡期 = 行为与改造前逐字节一致。
pub(crate) async fn ensure_oauth_client_prev_secret_column(
    db: &DatabaseConnection,
) -> anyhow::Result<()> {
    if !sso_table_exists(db, "sys_oauth_client").await? {
        return Ok(());
    }
    if sso_has_column(db, "sys_oauth_client", "previous_client_secret_hash").await? {
        return Ok(());
    }
    db.execute_raw(Statement::from_string(
        db.get_database_backend(),
        "ALTER TABLE sys_oauth_client ADD COLUMN previous_client_secret_hash VARCHAR(64) NULL"
            .to_string(),
    ))
    .await?;
    tracing::info!("sys_oauth_client.previous_client_secret_hash 列已补建（SSO D9 存量库兜底）");
    Ok(())
}
