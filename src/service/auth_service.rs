//! 认证服务层（Auth Service）
//!
//! 职责：
//! - 登录认证（验证码校验 + 密码校验 + JWT 签发 + 登录日志）
//! - 登出（token 加入 Redis 黑名单，fail-closed）
//! - 验证码生成与 Redis 存储
//! - 获取用户信息（user + roles + permissions）
//! - 获取路由树（菜单转路由）
//! - 登录安全：失败次数限制 + IP 限流 + GETDEL 原子化验证码
//! - 密码升级：登录时检测旧 MD5 哈希，自动升级为 Argon2
//!
//! 约束：
//! - 不依赖任何 Web 框架类型（axum / tower / tower-http）
//! - 错误统一使用 ServiceError
//! - Service 层返回 Vo（不含 code/msg），Handler 层负责包装为 Result

use std::sync::Arc;
use std::time::Duration;

use garde::Validate;
use sea_orm::Set;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use utoipa::ToSchema;

use crate::common::constants::SECS_PER_HOUR;
use crate::common::error::ServiceError;
use crate::config::{JwtConfig, Settings};
use crate::db::redis::REDIS_CMD_TIMEOUT_SECS;
use crate::entity::sys_logininfor;
use crate::entity::sys_menu::Model as SysMenuModel;
use crate::entity::sys_user::Model as SysUserModel;
use crate::jwt::JwtUtils;
use crate::repository::sys_logininfor::SysLogininforRepository;
use crate::service::sys_config_service::SysConfigService;
use crate::service::sys_menu_service::SysMenuService;
use crate::service::sys_user_service::{SysUserService, UserAddDto};
use crate::utils::captcha::generate_captcha;
use crate::utils::ip_location::IpLocator;
use crate::utils::password::{
    PasswordVerifyResult, encrypt_password, validate_password_complexity,
    verify_password_with_upgrade_hint,
};

/// 登录失败次数上限（每用户，5 分钟窗口）
const MAX_LOGIN_FAIL_COUNT: i64 = 5;
/// 登录失败计数 TTL（秒，5 分钟）
const LOGIN_FAIL_TTL: i64 = 300;
/// 同 IP 登录尝试上限（1 分钟窗口）
///
/// L-4：从 10 提升至 20，避免企业 NAT/校园网出口 IP 共享场景下正常用户被误限流。
/// 单 IP 仍受令牌桶中间件 + Redis 失败计数双重约束，提升上限不会显著放宽暴力破解防护。
const MAX_LOGIN_IP_COUNT: i64 = 20;
/// IP 限流计数 TTL（秒，1 分钟）
const LOGIN_IP_TTL: i64 = 60;

/// Redis 限流原子化脚本（INCR + EXPIRE 原子执行，防止计数永不过期）
///
/// - 首次 INCR 时设置 TTL，确保计数窗口一定会过期
/// - 通过 Lua 脚本保证原子性，避免 INCR 与 EXPIRE 分离导致计数永驻
const RATE_LIMIT_SCRIPT: &str = r#"
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"#;

// ==================== DTO / Vo 定义 ====================

/// 校验验证码会话 UUID 格式（ERR-29 防注入）
///
/// 安全说明：uuid 用于拼接 Redis key `captcha:{uuid}:{ip}`，
/// 若不校验格式，攻击者可注入换行符或特殊字符构造恶意 key。
///
/// 规则：
/// - 空字符串允许通过（验证码开关关闭时前端回传空 uuid）
/// - 非空字符串必须为合法 UUID 格式（由 uuid::Uuid::parse_str 校验）
fn validate_captcha_uuid_format(uuid: &str, _ctx: &()) -> garde::Result {
    if !uuid.is_empty() && uuid::Uuid::parse_str(uuid).is_err() {
        return Err(garde::Error::new(crate::tr!(
            "error.auth.captcha_uuid_invalid"
        )));
    }
    Ok(())
}

/// 登录请求 DTO（对齐前端 login 函数参数）
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LoginDto {
    #[garde(length(min = 2, max = 30))]
    pub username: String,
    #[garde(length(min = 5, max = 20))]
    pub password: String,
    /// 验证码（captchaEnabled=false 时前端/API 调用方可省略；serde default 兼容）
    #[serde(default)]
    #[garde(skip)]
    pub code: String,
    /// 验证码会话 UUID（ERR-29：校验格式防 Redis key 注入；captcha 关闭时可省略）
    #[serde(default)]
    #[garde(custom(validate_captcha_uuid_format))]
    pub uuid: String,
    /// TOTP 多因子验证码（可选，仅已启用 TOTP 的用户登录时必填，P0-4 登录链路集成）
    #[serde(default)]
    #[garde(skip)]
    pub totp_code: Option<String>,
}

/// 注册请求 DTO（对齐前端 register 函数参数）
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDto {
    #[garde(length(min = 2, max = 30))]
    pub username: String,
    #[garde(length(min = 5, max = 20))]
    pub password: String,
    /// 验证码（captchaEnabled=false 时可省略；serde default 兼容）
    #[serde(default)]
    #[garde(skip)]
    pub code: String,
    /// 验证码会话 UUID（ERR-29：校验格式防 Redis key 注入；captcha 关闭时可省略）
    #[serde(default)]
    #[garde(custom(validate_captcha_uuid_format))]
    pub uuid: String,
}

/// 锁屏解锁请求 DTO（对齐前端 unlockScreen 函数参数）
#[derive(Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct UnlockScreenDto {
    #[garde(length(min = 5, max = 20))]
    pub password: String,
}

/// 登录响应 Vo（Service 层返回，Handler 包装为 LoginResult）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginVo {
    pub token: String,
}

/// 验证码响应 Vo（Service 层返回，Handler 包装为 CaptchaResult）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptchaVo {
    /// 验证码开关（从 sys_config.sys.account.captchaEnabled 读取）
    pub captcha_enabled: bool,
    /// 验证码图片 Base64（不含 data:image/png;base64, 前缀；开关关闭时为空）
    pub img: String,
    /// 验证码会话 UUID（登录时回传；开关关闭时为空）
    pub uuid: String,
    /// 注册开关（从 sys_config.sys.account.registerUser 读取）
    /// 前端据此控制"立即注册"链接显示，避免探测 /register 触发 403 控制台错误
    pub register_enabled: bool,
}

/// 用户信息响应 Vo（Service 层返回，Handler 包装为 GetInfoResult）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetInfoVo {
    /// 用户信息（password 字段已清空为 None）
    pub user: SysUserModel,
    /// 角色 key 列表（超管为 ["admin"]）
    pub roles: Vec<String>,
    /// 权限标识列表（超管为 ["*:*:*"]）
    pub permissions: Vec<String>,
    /// 密码加密类型（对齐前端 pwdChrtype）
    pub pwd_chrtype: Option<String>,
    /// 是否初始密码未修改（对齐前端 isDefaultModifyPwd）
    pub is_default_modify_pwd: bool,
    /// 密码是否已过期（对齐前端 isPasswordExpired）
    pub is_password_expired: bool,
}

/// 路由节点 Vo（对齐前端 RouterVo）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterVo {
    pub name: String,
    pub path: String,
    pub hidden: bool,
    pub redirect: Option<String>,
    pub component: String,
    pub always_show: Option<bool>,
    pub meta: MetaVo,
    pub query: Option<String>,
    pub children: Option<Vec<RouterVo>>,
}

/// 路由 meta 信息（对齐前端 MetaVo）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaVo {
    pub title: String,
    pub icon: String,
    pub no_cache: bool,
    pub link: Option<String>,
    /// i18n 翻译 key（可选）：前端优先用 t(i18nKey) 翻译，回退到 title 原文
    pub i18n_key: Option<String>,
}

/// 登录流程共享上下文（减少子方法参数数量）
///
/// 封装登录流程中多个子方法共享的字符串参数（username, login_ip, login_location, browser, os），
/// 避免 check_rate_limit / verify_captcha / verify_user_credentials / finalize_login / write_login_log
/// 等方法各自接收 5 个 &str 参数（clippy too_many_arguments）。
pub struct LoginContext<'a> {
    pub username: &'a str,
    pub login_ip: &'a str,
    pub login_location: &'a str,
    pub browser: &'a str,
    pub os: &'a str,
}

// ==================== Service 实现 ====================

/// 认证服务（不依赖任何 Web 类型）
///
/// 持有 4 个 Service/Repository：
/// - user_service: 用户查询（登录认证、getInfo、密码升级）
/// - menu_service: 菜单树/权限查询（getInfo、getRouters，含角色+权限合并缓存）
/// - logininfor_repo: 登录日志写入
/// - config_service: 参数配置查询（验证码开关等，H-4 走 Redis cache-aside 缓存）
pub struct AuthService {
    user_service: SysUserService,
    menu_service: SysMenuService,
    logininfor_repo: SysLogininforRepository,
    config_service: SysConfigService,
    /// 全局配置（P0-4：TOTP secret 加解密需要 config_enc_key）
    config: Arc<Settings>,
}

impl AuthService {
    /// 构造 AuthService（依赖注入：复用 state 层已实例化的 Service / Repository）
    ///
    /// 修复 P0-R81-014：原本在内部重复实例化 user_service / role_service / menu_service，
    /// 导致与 AppState 中的同名实例各自独立（15 个重复 Repository 实例）。
    /// 现由调用方传入已实例化的 Service，确保单实例共享。
    ///
    /// 优化：role_service 已移除，角色查询合并到 menu_service.get_roles_and_permissions_by_user_id
    pub fn new(
        user_service: SysUserService,
        menu_service: SysMenuService,
        logininfor_repo: SysLogininforRepository,
        config_service: SysConfigService,
        config: Arc<Settings>,
    ) -> Self {
        Self {
            user_service,
            menu_service,
            logininfor_repo,
            config_service,
            config,
        }
    }

    /// 读取验证码开关（sys_config.sys.account.captchaEnabled）
    ///
    /// H-4：通过 SysConfigService 的 Redis cache-aside 缓存读取，减少登录流程 DB 查询。
    ///
    /// 返回规则：
    /// - 配置不存在或读取失败：默认 true（安全失败，偏向开启验证码）
    /// - 配置值为 "false"（不区分大小写）：返回 false
    /// - 其他值：返回 true
    async fn is_captcha_enabled(&self) -> bool {
        match self
            .config_service
            .get_config_value_by_key_cached("sys.account.captchaEnabled")
            .await
        {
            Ok(Some(val)) => !val.eq_ignore_ascii_case("false"),
            _ => true,
        }
    }

    /// 读取注册开关（sys_config.sys.account.registerUser）
    ///
    /// H-4：通过 SysConfigService 的 Redis cache-aside 缓存读取，减少注册流程 DB 查询。
    ///
    /// 返回规则（P0-R12-001）：
    /// - 配置不存在或读取失败：默认 false（安全失败：配置缺失时禁止注册）
    /// - 配置值为 "true"（不区分大小写）：返回 true
    /// - 其他值：返回 false
    async fn is_register_enabled(&self) -> bool {
        match self
            .config_service
            .get_config_value_by_key_cached("sys.account.registerUser")
            .await
        {
            Ok(Some(val)) => val.eq_ignore_ascii_case("true"),
            _ => false,
        }
    }

    /// 生成验证码并存入 Redis（绑定客户端 IP）
    ///
    /// 流程：
    /// 1. 读取 sys_config.sys.account.captchaEnabled 开关
    /// 2. 若开关关闭：返回 captcha_enabled=false，不生成图片（前端隐藏验证码输入框）
    /// 3. 若开关开启：
    ///    a. 调用 utils::captcha::generate_captcha() 生成验证码
    ///    b. Redis 写入 captcha:{uuid}:{ip} → 小写验证码，TTL 300s
    ///    c. 返回 CaptchaVo { captcha_enabled: true, img, uuid }
    ///
    /// 安全说明：验证码 key 绑定客户端 IP，防止跨 IP 重放（验证时同样校验 IP）。
    pub async fn generate_captcha(
        &self,
        redis: &mut redis::aio::ConnectionManager,
        ip: &str,
    ) -> Result<CaptchaVo, ServiceError> {
        // 1. 读取验证码开关
        let captcha_enabled = self.is_captcha_enabled().await;
        // 同时读取注册开关，前端据此控制"立即注册"链接显示，
        // 避免前端探测 /register 触发 403 控制台错误（P0 优化）
        let register_enabled = self.is_register_enabled().await;
        if !captcha_enabled {
            return Ok(CaptchaVo {
                captcha_enabled: false,
                img: String::new(),
                uuid: String::new(),
                register_enabled,
            });
        }

        // 2. 生成验证码
        // 验证码图片生成是 CPU 密集型同步操作，用 spawn_blocking 包裹避免阻塞 Tokio runtime（P0-32）
        let captcha = tokio::task::spawn_blocking(generate_captcha)
            .await
            .map_err(|e| {
                tracing::error!("验证码生成 spawn_blocking 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.auth.captcha_gen_failed"))
            })?;

        // 3. 存入 Redis，TTL 300s（5 分钟）
        //    key 绑定 IP：captcha:{uuid}:{ip}，防止验证码跨 IP 重放
        let captcha_key = format!("captcha:{}:{}", captcha.uuid, ip);
        // R11：命令级超时（fail-closed：超时则验证码未存储，用户无法登录）
        tokio::time::timeout(
            Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("SETEX")
                .arg(&captcha_key)
                .arg(300i64)
                .arg(captcha.code.to_lowercase())
                .query_async::<()>(redis),
        )
        .await
        .map_err(|_| {
            tracing::error!("Redis SETEX 验证码超时（fail-closed）");
            ServiceError::new(503, crate::tr!("error.auth.auth_unavailable"))
        })??;

        Ok(CaptchaVo {
            captcha_enabled: true,
            img: captcha.img_base64,
            uuid: captcha.uuid,
            register_enabled,
        })
    }

    /// 登录认证全流程
    ///
    /// 流程：
    /// 1. 参数校验
    /// 2. IP 限流校验（同 IP 1 分钟内 ≤10 次）
    /// 3. 用户失败次数校验（同用户 5 分钟内 ≤5 次）
    /// 4. 验证码校验（GETDEL 原子化，防重放攻击）
    /// 5. 用户查询 + 状态校验（del_flag / status）+ 密码校验
    /// 6. 密码升级（MD5 → Argon2，best-effort）
    /// 7. JWT 签发 + 登录日志（成功）+ 在线映射 + 更新登录信息 + 清除失败计数
    ///
    /// 修复 P0-R81-013：原 login() 长达 211 行、圈复杂度 20+，拆分为 6 个职责单一的私有子方法，
    /// 主函数仅负责参数校验、UA 解析、IP 归属地查询与流程编排。
    ///
    /// 安全说明：密码错误时返回"用户不存在/密码错误"，避免枚举攻击。
    /// 登录业务错误统一返回 code=500（对齐前端调用约定）。
    pub async fn login(
        &self,
        dto: LoginDto,
        login_ip: &str,
        user_agent: &str,
        redis: &mut redis::aio::ConnectionManager,
        jwt_config: &JwtConfig,
        ip_locator: &IpLocator,
    ) -> Result<LoginVo, ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let browser = parse_browser(user_agent);
        let os = parse_os(user_agent);
        // 查询 IP 归属地（mmdb 文件不存在或查询失败时返回空字符串）
        let login_location = ip_locator.locate(login_ip);

        let ctx = LoginContext {
            username: &dto.username,
            login_ip,
            login_location: &login_location,
            browser: &browser,
            os: &os,
        };

        // L-2：调整执行顺序为 captcha → rate_limit → fail_count → verify。
        // 原顺序（rate_limit → fail_count → captcha → verify）存在两个问题：
        // 1. 验证码放在限流之后，攻击者可消耗 IP 限流额度后才被验证码拦截，浪费限流配额
        // 2. 验证码 GETDEL 是幂等消耗操作，应在更早阶段拦截明显错误的请求
        // 新顺序：先验证码（无 Redis 计数副作用），再限流（IP/用户计数），最后密码校验
        // 1. 验证码校验（GETDEL 原子化，防重放攻击）
        self.verify_captcha(redis, &ctx, &dto.uuid, &dto.code)
            .await?;

        // 2. IP 限流校验
        self.check_rate_limit(redis, &ctx).await?;

        // 3. 用户失败次数校验
        self.check_fail_count(redis, &ctx).await?;

        // 4. 用户查询 + 状态校验 + 密码校验（返回 verify_result 以避免重复 Argon2 verify）
        let (user, verify_result) = self
            .verify_user_credentials(&ctx, &dto.password, redis)
            .await?;

        // 5. 密码升级（MD5 → Argon2，best-effort）
        self.upgrade_password_if_needed(&user, &dto.password, verify_result)
            .await?;

        // 5.5 TOTP 多因子校验（P0-4 登录链路集成）
        // 用户启用 TOTP 后必须提供有效验证码；未提供/错误返回业务码 1003，
        // 前端据此进入 TOTP 输入步骤二次提交。
        self.verify_totp_if_enabled(redis, &ctx, &user, dto.totp_code.as_deref())
            .await?;

        // 6. JWT 签发 + 登录日志（成功）+ 在线映射 + 更新登录信息 + 清除失败计数
        self.finalize_login(&user, redis, jwt_config, &ctx).await
    }

    /// TOTP 多因子校验（P0-4 登录链路集成）
    ///
    /// 登录时若用户已启用 TOTP（Redis key `totp:enabled:{user_id}` 存在），
    /// 必须提供有效验证码，否则返回业务码 1003（不签发 token）：
    /// - 未提供验证码 → 1003 "需要 TOTP 验证码"（前端展示 TOTP 输入步骤）
    /// - 验证码错误 → 1003 "验证码错误"（前端停留在 TOTP 步骤）
    /// - 验证码正确 → 放行并清除该用户名下的 TOTP 登录失败计数
    ///
    /// 防暴力：TOTP 验证码错误计入 `totp:login_fail:{username}`（10 分钟内 ≥5 次锁定）。
    async fn verify_totp_if_enabled(
        &self,
        redis: &mut redis::aio::ConnectionManager,
        ctx: &LoginContext<'_>,
        user: &SysUserModel,
        totp_code: Option<&str>,
    ) -> Result<(), ServiceError> {
        let redis_key = format!("totp:enabled:{}", user.user_id);
        let encrypted: Option<String> = redis::cmd("GET")
            .arg(&redis_key)
            .query_async(redis)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, user_id = user.user_id, "TOTP 状态查询失败（fail-closed 503）");
                ServiceError::new(503, crate::tr!("error.auth.auth_unavailable"))
            })?;

        let Some(encrypted) = encrypted else {
            // 未启用 TOTP：直接放行
            return Ok(());
        };

        // 已启用 TOTP：先做失败限流检查（防暴力枚举验证码）
        const MAX_TOTP_FAIL: i64 = 5;
        const TOTP_FAIL_TTL: i64 = 600;
        let fail_key = format!("totp:login_fail:{}", ctx.username);
        let fail_count: Option<i64> = redis::cmd("GET")
            .arg(&fail_key)
            .query_async(redis)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "TOTP 失败计数查询失败（fail-closed 503）");
                ServiceError::new(503, crate::tr!("error.auth.auth_unavailable"))
            })?;
        if let Some(count) = fail_count
            && count >= MAX_TOTP_FAIL
        {
            self.write_login_log_best_effort(ctx, "1", &crate::tr!("log.auth.totp_locked"))
                .await;
            return Err(ServiceError::new(
                1003,
                crate::tr!("error.totp.login_locked"),
            ));
        }

        let code = totp_code.unwrap_or("");
        if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ServiceError::new(
                1003,
                crate::tr!("error.totp.login_required"),
            ));
        }

        // 解密已绑定的 TOTP secret 并校验验证码
        let master_key = &self.config.config_enc_key;
        if master_key.is_empty() {
            tracing::error!("CONFIG_ENC_KEY 未配置，无法解密 TOTP secret（fail-closed 拒绝登录）");
            return Err(ServiceError::new(
                503,
                crate::tr!("error.totp.enc_key_missing"),
            ));
        }
        let secret_str = crate::utils::crypto::decrypt_config_value(&encrypted, master_key)
            .map_err(|e| {
                tracing::error!(error = %e, user_id = user.user_id, "TOTP secret 解密失败");
                ServiceError::new(500, crate::tr!("error.totp.decrypt_failed"))
            })?;
        let secret_bytes = Secret::Encoded(secret_str)
            .to_bytes()
            .map_err(|_| ServiceError::new(500, crate::tr!("error.totp.secret_decode_failed")))?;
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("Yebot".to_string()),
            "yebot-user".to_string(),
        )
        .map_err(|_| ServiceError::new(500, crate::tr!("error.totp.totp_build_failed")))?;

        if !totp.check_current(code).unwrap_or(false) {
            // 验证码错误：计数 + 写登录日志（fail 提示，不区分具体原因）
            let _: i64 = redis::Script::new(RATE_LIMIT_SCRIPT)
                .key(&fail_key)
                .arg(TOTP_FAIL_TTL)
                .invoke_async(redis)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "TOTP 失败计数写入失败");
                    ServiceError::new(503, crate::tr!("error.auth.auth_unavailable"))
                })?;
            self.write_login_log_best_effort(ctx, "1", &crate::tr!("log.auth.totp_failed"))
                .await;
            return Err(ServiceError::new(
                1003,
                crate::tr!("error.totp.code_invalid"),
            ));
        }

        // 验证通过：清除失败计数
        let _: i64 = redis::cmd("DEL")
            .arg(&fail_key)
            .query_async(redis)
            .await
            .unwrap_or(0);
        Ok(())
    }

    /// IP 限流校验（同 IP 1 分钟内 ≤10 次）
    ///
    /// 使用 Lua 脚本原子化 INCR + EXPIRE，防止计数永不过期。
    /// 超限时写入登录日志（status=1，msg="IP 请求频率超限"）并返回错误。
    async fn check_rate_limit(
        &self,
        redis: &mut redis::aio::ConnectionManager,
        ctx: &LoginContext<'_>,
    ) -> Result<(), ServiceError> {
        let ip_key = format!("login_ip:{}", ctx.login_ip);
        let ip_count: i64 = redis::Script::new(RATE_LIMIT_SCRIPT)
            .key(&ip_key)
            .arg(LOGIN_IP_TTL)
            .invoke_async(redis)
            .await
            .map_err(|e| {
                tracing::error!("Redis IP 限流计数失败（fail-closed）: {}", e);
                ServiceError::new(503, crate::tr!("error.auth.auth_unavailable"))
            })?;
        if ip_count > MAX_LOGIN_IP_COUNT {
            self.write_login_log_best_effort(ctx, "1", &crate::tr!("log.auth.ip_rate_limited"))
                .await;
            return Err(ServiceError::new(
                429,
                crate::tr!("error.auth.rate_limited"),
            ));
        }
        Ok(())
    }

    /// 用户失败次数校验（同用户 5 分钟内 ≤5 次）
    ///
    /// 超限时写入登录日志（status=1，msg="密码错误次数过多"）并返回错误。
    async fn check_fail_count(
        &self,
        redis: &mut redis::aio::ConnectionManager,
        ctx: &LoginContext<'_>,
    ) -> Result<(), ServiceError> {
        let fail_key = format!("login_fail:{}", ctx.username);
        // R11：命令级超时（fail-closed 503）
        let fail_count: Option<i64> = tokio::time::timeout(
            Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
            redis::cmd("GET").arg(&fail_key).query_async(redis),
        )
        .await
        .map_err(|_| {
            tracing::error!("Redis 登录失败计数查询超时（fail-closed）");
            ServiceError::new(503, crate::tr!("error.auth.auth_unavailable"))
        })?
        .map_err(|e| {
            tracing::error!("Redis 登录失败计数查询失败（fail-closed）: {}", e);
            ServiceError::new(503, crate::tr!("error.auth.auth_unavailable"))
        })?;
        if let Some(count) = fail_count
            && count >= MAX_LOGIN_FAIL_COUNT
        {
            self.write_login_log_best_effort(ctx, "1", &crate::tr!("log.auth.password_locked"))
                .await;
            return Err(ServiceError::new(
                429,
                crate::tr!("error.auth.password_locked"),
            ));
        }
        Ok(())
    }

    /// 验证码校验（GETDEL 原子化，防重放攻击）
    ///
    /// 若 sys.account.captchaEnabled=false，则跳过验证码校验。
    /// captcha key 绑定 IP：captcha:{uuid}:{ip}，防止跨 IP 重放。
    /// 失败时写入登录日志并返回错误。
    ///
    /// M-6：区分 Redis 错误（fail-closed 返回 503）和 key 不存在（返回 captcha_expired）。
    /// 原实现用 `.ok().flatten()` 静默吞掉 Redis 错误，导致 Redis 故障时所有验证码均被
    /// 判定为"已过期"，既掩盖了基础设施故障，又误伤了正常用户。
    async fn verify_captcha(
        &self,
        redis: &mut redis::aio::ConnectionManager,
        ctx: &LoginContext<'_>,
        uuid: &str,
        code: &str,
    ) -> Result<(), ServiceError> {
        if self.is_captcha_enabled().await {
            let captcha_key = format!("captcha:{}:{}", uuid, ctx.login_ip);
            // M-6：显式 match 区分 Redis 错误（fail-closed 503）与 key 不存在（captcha_expired）
            // R11：命令级超时（fail-closed 503）
            let stored_code: Option<String> = match tokio::time::timeout(
                Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
                redis::cmd("GETDEL").arg(&captcha_key).query_async(redis),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    tracing::error!("Redis GETDEL 验证码失败（fail-closed）: {}", e);
                    return Err(ServiceError::new(
                        503,
                        crate::tr!("error.auth.auth_unavailable"),
                    ));
                }
                Err(_) => {
                    tracing::error!("Redis GETDEL 验证码超时（fail-closed）");
                    return Err(ServiceError::new(
                        503,
                        crate::tr!("error.auth.auth_unavailable"),
                    ));
                }
            };

            let stored = match stored_code {
                Some(c) => c,
                None => {
                    self.write_login_log_best_effort(
                        ctx,
                        "1",
                        &crate::tr!("log.auth.captcha_expired"),
                    )
                    .await;
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.auth.captcha_expired"
                    )));
                }
            };

            if stored.to_lowercase() != code.to_lowercase() {
                self.write_login_log_best_effort(ctx, "1", &crate::tr!("log.auth.captcha_wrong"))
                    .await;
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.auth.captcha_wrong"
                )));
            }
        }
        Ok(())
    }

    /// 用户查询 + 状态校验 + 密码校验
    ///
    /// 流程：
    /// 1. 用户查询（不存在则写日志 + 返回错误；H-2：Repository 已过滤 del_flag，无需重复判断）
    /// 2. status 校验（账号停用）
    /// 3. 密码校验（支持 MD5→Argon2 自动升级提示；不匹配则记录失败次数 + 写日志 + 返回错误）
    ///
    /// 返回 (user, verify_result)：verify_result 携带 needs_upgrade 标志，供 upgrade_password_if_needed 复用，
    /// 避免重复执行 Argon2 verify（每次约 50ms）。
    ///
    /// 安全说明：密码错误时返回"用户不存在/密码错误"，避免枚举攻击。
    ///
    /// H-2：Repository 层 `find_active_by_user_name` 已过滤 del_flag='0'，故删除原
    /// `del_flag == "2"` 检查。已删除用户会以 None 返回，与"用户不存在"走同一分支。
    ///
    /// L-1：用户不存在时不再调用 `record_login_failure`。原实现对任意用户名均计数，
    /// 攻击者可枚举不存在用户名将真实用户失败计数顶满导致其被锁；同时不存在的用户
    /// 也无对应密码，本就不会通过密码校验，无需计数。
    async fn verify_user_credentials(
        &self,
        ctx: &LoginContext<'_>,
        password: &str,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(SysUserModel, PasswordVerifyResult), ServiceError> {
        // 1. 用户查询（H-2：Repository 已过滤 del_flag='0'，已删除用户以 None 返回）
        let user = match self
            .user_service
            .get_active_user_by_username(ctx.username)
            .await?
        {
            Some(u) => u,
            None => {
                // L-1：用户不存在时不计数（避免无效用户名污染失败计数导致真实用户被锁）
                self.write_login_log_best_effort(ctx, "1", &crate::tr!("log.auth.login_failed"))
                    .await;
                return Err(ServiceError::unauthorized(&crate::tr!(
                    "error.auth.login_failed"
                )));
            }
        };

        // 2. 用户状态校验（H-2：del_flag 已在 Repository 过滤，此处仅校验 status）
        // C-1：账号停用统一返回 login_failed，避免攻击者通过差异错误消息枚举有效用户名。
        // 细分原因仅写入 sys_logininfor 日志（不返回客户端），供管理员审计。
        if user.status.as_deref() == Some("1") {
            self.write_login_log_best_effort(ctx, "1", &crate::tr!("log.auth.account_disabled"))
                .await;
            return Err(ServiceError::unauthorized(&crate::tr!(
                "error.auth.login_failed"
            )));
        }

        // 3. 密码校验（支持 MD5→Argon2 自动升级）
        // Argon2 verify 是 CPU 密集型同步操作，用 spawn_blocking 包裹避免阻塞 Tokio runtime（P0-31）
        let stored_password = user.password.as_deref().unwrap_or("").to_string();
        let password_for_verify = password.to_string();
        let verify_result = tokio::task::spawn_blocking(move || {
            verify_password_with_upgrade_hint(&password_for_verify, &stored_password)
        })
        .await
        .map_err(|e| {
            tracing::error!("密码验证 spawn_blocking 失败: {}", e);
            ServiceError::internal(&crate::tr!("error.auth.password_verify_failed"))
        })?;
        if !verify_result.is_valid {
            self.record_login_failure(ctx.username, redis).await?;
            self.write_login_log_best_effort(ctx, "1", &crate::tr!("log.auth.login_failed"))
                .await;
            return Err(ServiceError::unauthorized(&crate::tr!(
                "error.auth.login_failed"
            )));
        }

        Ok((user, verify_result))
    }

    /// 密码升级（MD5 → Argon2，best-effort）
    ///
    /// 若 verify_result.needs_upgrade 为 true（旧 MD5 哈希），重新用 Argon2 加密并存储。
    /// 失败不阻断登录（仅记录警告日志）。
    /// Argon2 hash 是 CPU 密集型同步操作，用 spawn_blocking 包裹（P0-31）。
    ///
    /// 注：verify_result 由 verify_user_credentials 返回，避免在此处重复执行 Argon2 verify。
    async fn upgrade_password_if_needed(
        &self,
        user: &SysUserModel,
        password: &str,
        verify_result: PasswordVerifyResult,
    ) -> Result<(), ServiceError> {
        if !verify_result.needs_upgrade {
            return Ok(());
        }

        // Argon2 hash 是 CPU 密集型同步操作，用 spawn_blocking 包裹（P0-31）
        let password_for_hash = password.to_string();
        let hash_result = tokio::task::spawn_blocking(move || encrypt_password(&password_for_hash))
            .await
            .map_err(|e| {
                tracing::error!("密码加密 spawn_blocking 失败: {}", e);
                ServiceError::internal(&crate::tr!("error.common.password_encrypt_failed"))
            })?;
        match hash_result {
            Ok(new_hash) => {
                if let Err(e) = self
                    .user_service
                    .upgrade_password_hash(user.user_id, &new_hash)
                    .await
                {
                    tracing::warn!(
                        "用户 {} 密码哈希升级失败（不阻断登录）: {}",
                        user.user_id,
                        e
                    );
                } else {
                    tracing::info!("用户 {} 密码哈希已从 MD5 升级为 Argon2", user.user_id);
                }
            }
            Err(e) => {
                tracing::warn!(
                    "用户 {} 密码哈希升级失败（加密失败，不阻断登录）: {}",
                    user.user_id,
                    e
                );
            }
        }
        Ok(())
    }

    /// JWT 签发 + 登录日志（成功）+ 在线用户映射 + 更新登录信息 + 清除失败计数
    ///
    /// 流程：
    /// 1. JWT 签发
    /// 2. 写入登录成功日志并获取 info_id
    /// 3. 存储 `online:{token_hash}` → `OnlineSession` JSON 到 Redis（用于在线用户列表 + 强退）
    /// 4. 更新 login_ip / login_date（失败不阻断登录）
    /// 5. 清除登录失败计数
    ///
    /// P1-19 方案 B：online key 由 `online:{info_id}` 改为 `online:{token_hash}`，
    /// value 由裸 token 改为 JSON（含 user_id/username/ip/login_time/browser/os/jti）。
    /// 解决旧方案两个 Bug：
    /// - logout 未 DEL online key，用户登出后仍显示在线 30 分钟
    /// - 30 分钟硬窗口与 JWT 24h 有效期不一致
    async fn finalize_login(
        &self,
        user: &SysUserModel,
        redis: &mut redis::aio::ConnectionManager,
        jwt_config: &JwtConfig,
        ctx: &LoginContext<'_>,
    ) -> Result<LoginVo, ServiceError> {
        // 1. JWT 签发（M-7：generate_token 同时返回 claims，避免后续重复 verify）
        //    P0-R81-007：读取当前密码版本号 pwd_ver:{user_id}（无则 0）写入 claim，
        //    auth 中间件据此判定 token 是否在密码变更前签发（旧 token 立即失效）。
        //    读取失败视为 0（fail-open，仅影响旧 token 失效判断；Redis 不可用时中间件会 fail-closed 拒绝）。
        let user_id = user.user_id.to_string();
        let pwd_ver_key = format!("pwd_ver:{}", user_id);
        let pwd_ver: Option<u64> = redis::cmd("GET")
            .arg(&pwd_ver_key)
            .query_async(redis)
            .await
            .unwrap_or(None);
        let (token, claims) = JwtUtils::generate_token(
            &user_id,
            ctx.username,
            jwt_config,
            pwd_ver.unwrap_or(0),
            // v5-N2 Phase 2：登录查库带出真实 tid（当前存量用户恒 0 = 平台单租户）
            user.tenant_id,
        )?;

        // 2. 登录日志写入（成功，best-effort）
        //    H-1/H-2 修复：日志写入失败不应阻断登录响应，仅记录警告日志
        //    info_id 仍保留用于登录日志关联，但不再作为 online key
        //    H-3：日志消息改用 tr!("log.auth.login_success") 支持多语言
        self.write_login_log_best_effort(ctx, "0", &crate::tr!("log.auth.login_success"))
            .await;

        // 3. 存储 `online:{token_hash}` → `OnlineSession` JSON，用于在线用户列表与强退
        //    - key 用 token_hash（与 blacklist:{token_hash} 对齐，强退时同一 key 命名空间）
        //    - value 改为 JSON（含 user_id/username/ip/login_time/browser/os/jti），
        //      list 接口可直接 SCAN + MGET 解析，无需查 sys_logininfor 表
        //    - TTL = jwt_config.expire_hours * SECS_PER_HOUR（与 JWT 过期时间对齐，避免硬编码 7200）
        //    - SETEX 失败不阻断登录（best-effort）：online key 不影响鉴权，仅影响在线列表展示
        let token_hash = crate::utils::crypto::token_hash(&token);
        let online_key = format!("online:{}", token_hash);
        let online_ttl = jwt_config.expire_hours * SECS_PER_HOUR;
        // M-7：claims 已由 generate_token 返回，无需 verify_token 重新解码
        // 查询用户部门名称（失败时填空字符串，不阻断登录）
        // 复用 user_service 的 dept 查询能力，避免 AuthService 直接依赖 SysDeptRepository
        let dept_name = self
            .user_service
            .get_dept_name_by_user_id(user.user_id)
            .await
            .unwrap_or_default();
        // M-3：记录 JWT exp（UTC 秒）用于 force_logout 精确计算黑名单 TTL
        //   旧方案用 jwt.expire_hours * SECS_PER_HOUR 作为黑名单 TTL（保守上界），
        //   导致用户登录 1 小时后被强退，黑名单仍保留 24 小时（多 23 小时内存浪费）。
        //   现写入 claims.exp（token 实际过期时间戳），force_logout 时用 exp - now 计算精确剩余 TTL。
        let session = crate::utils::crypto::OnlineSession {
            user_id: user.user_id,
            username: ctx.username.to_string(),
            ip: ctx.login_ip.to_string(),
            login_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            browser: ctx.browser.to_string(),
            os: ctx.os.to_string(),
            jti: claims.jti,
            dept_name,
            // v4-P0-A：会话来源标识（login=平台登录；sso=SSO 签发的 access_token）
            source: "login".to_string(),
            // R11：防 usize→i64 溢出（与 jwt/claims.rs:106 的 try_from 防御保持一致）
            exp: i64::try_from(claims.exp).unwrap_or(0),
        };
        let session_json = serde_json::to_string(&session)?;

        // 3.5 同用户同 IP+Browser 旧会话清理（P1-ONLINE-DEDUP）
        //   问题：原实现每次登录都创建新的 online:{token_hash} key，TTL=JWT 有效期，
        //   同一用户在相同浏览器重复登录会产生多个会话记录，污染在线用户列表。
        //   测试中 admin 反复登录导致列表显示 10 条 admin 记录，明显不合理。
        //
        //   方案：维护 `user_sessions:{user_id}:{ip}:{browser}` → 最新 token_hash
        //   - 同 IP+Browser 视为同一设备/浏览器会话，新登录替代旧会话
        //   - 不同 IP 或不同 Browser 视为多设备登录，互不影响（保留多设备共存能力）
        //   - 旧会话的 online key 立即删除，从在线列表消失；JWT 自身仍有效（不强制踢出）
        //     （如果立即让 JWT 失效需写黑名单，会破坏用户在旧标签页的会话，故仅清理展示）
        //
        //   失败处理：best-effort，不阻断登录
        let normalized_browser = ctx.browser.to_lowercase().replace(' ', "");
        let user_session_key = format!(
            "user_sessions:{}:{}:{}",
            user.user_id, ctx.login_ip, normalized_browser
        );

        // M-5：将原 5 次独立 Redis 往返（SETEX online / GET user_sessions / DEL old_online
        //   / SETEX user_sessions / DEL login_fail）合并为 2 次：
        //   1) 单独 GET user_sessions（需要结果判断是否 DEL 旧 online key）
        //   2) pipeline 批量执行 4 个写操作（SETEX online / 条件 DEL old_online / SETEX
        //      user_sessions / DEL login_fail），单次网络往返
        // GET 旧 token_hash（如有）——单独执行，因后续 pipeline 中条件 DEL 依赖其结果
        let old_token_hash_opt: Option<String> = redis::cmd("GET")
            .arg(&user_session_key)
            .query_async(redis)
            .await
            .unwrap_or(None);
        let need_del_old = match old_token_hash_opt.as_ref() {
            Some(old) if old != &token_hash => {
                tracing::info!(
                    "用户 {} 在相同浏览器(IP={})重复登录，将清理旧会话 {}",
                    ctx.username,
                    ctx.login_ip,
                    old
                );
                true
            }
            _ => false,
        };
        let old_online_key = old_token_hash_opt
            .as_ref()
            .filter(|old| *old != &token_hash)
            .map(|old| format!("online:{}", old));

        // 构造 pipeline：4 个写操作合并为单次网络往返
        let mut pipe = redis::pipe();
        // (a) SETEX online:{token_hash} session_json (TTL=online_ttl)
        pipe.cmd("SETEX")
            .arg(&online_key)
            .arg(online_ttl)
            .arg(&session_json);
        // (b) 若旧 token_hash 存在且与新不同，DEL 旧 online key
        if need_del_old && let Some(ref old_key) = old_online_key {
            pipe.cmd("DEL").arg(old_key);
        }
        // (c) SETEX user_sessions:{...} token_hash (TTL=online_ttl)
        pipe.cmd("SETEX")
            .arg(&user_session_key)
            .arg(online_ttl)
            .arg(&token_hash);
        // (d) DEL login_fail:{username}（清除失败计数）
        let fail_key = format!("login_fail:{}", ctx.username);
        pipe.cmd("DEL").arg(&fail_key);
        // pipeline 整体执行（best-effort：超时/任一命令失败仅记日志，不阻断登录）
        // R11：命令级超时
        match tokio::time::timeout(
            Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
            // pipeline 混有 SETEX（返回 Status "OK"）与 DEL（返回整数），
            // 结果类型不一致，不能用 Vec<i64>（会报 "not convertible to numeric"），
            // 用 () 忽略全部返回值（本 pipeline 为 best-effort 写操作）。
            pipe.query_async::<()>(redis),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::warn!(
                    "finalize_login pipeline 部分失败（不阻断登录，仅影响在线列表/会话去重/失败计数）: {}",
                    e
                );
            }
            Err(_) => {
                tracing::warn!(
                    "finalize_login pipeline 超时（不阻断登录，仅影响在线列表/会话去重/失败计数）"
                );
            }
        }

        // 4. 更新 login_ip / login_date（失败不阻断登录）
        if let Err(e) = self
            .user_service
            .update_login_info(user.user_id, ctx.login_ip)
            .await
        {
            tracing::warn!("更新用户登录信息失败（不阻断登录）: {}", e);
        }

        Ok(LoginVo { token })
    }

    /// 登出：token 加入 Redis 黑名单 + 删除 online 会话映射（fail-closed：黑名单写入失败返回错误）
    ///
    /// 流程：
    /// 1. 验证 token 获取 claims（计算剩余 TTL）
    /// 2. 计算剩余有效期 = exp - now
    /// 3. 若剩余 > 0：Redis SETEX blacklist:{token_hash} "1" EX {剩余秒数}（fail-closed）
    /// 4. DEL online:{token_hash}（best-effort：失败仅记日志，因 online key 会自然过期）
    ///
    /// P1-19 方案 B：新增步骤 4，修复旧方案 logout 未 DEL online key 的 Bug
    /// （旧方案用户登出后仍显示在线 30 分钟）。
    pub async fn logout(
        &self,
        token: &str,
        redis: &mut redis::aio::ConnectionManager,
        jwt_config: &JwtConfig,
    ) -> Result<(), ServiceError> {
        // 验证 token 获取 claims（计算剩余 TTL）
        let claims = JwtUtils::verify_token(token, jwt_config)?;

        // 计算剩余有效期
        // R5-TYPE-13：使用 try_from 替代 `as usize`，避免 32 位系统回绕
        let now = usize::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
        let remaining = claims.exp.saturating_sub(now);

        // token_hash：blacklist key 与 online key 共用同一哈希命名空间
        let token_hash = crate::utils::crypto::token_hash(token);

        // 若 token 仍有效，写入黑名单（fail-closed：失败返回错误）
        // 使用 token 的 SHA-256 哈希作为 key，节省 Redis 内存
        if remaining > 0 {
            let blacklist_key = format!("blacklist:{}", token_hash);
            // R11：命令级超时（fail-closed：超时则黑名单未写入，拒绝 logout 以避免 token 仍可用）
            tokio::time::timeout(
                Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
                redis::cmd("SETEX")
                    .arg(&blacklist_key)
                    .arg(remaining)
                    .arg("1")
                    .query_async::<()>(redis),
            )
            .await
            .map_err(|_| {
                tracing::error!("登出黑名单写入超时（fail-closed）");
                ServiceError::internal(&crate::tr!("error.auth.logout_failed"))
            })?
            .map_err(|e| {
                tracing::error!("登出黑名单写入失败（fail-closed）: {}", e);
                ServiceError::internal(&crate::tr!("error.auth.logout_failed"))
            })?;
        }

        // DEL online:{token_hash}（best-effort：失败不阻断 logout）
        //   修复 P1-19 Bug：旧方案 logout 仅写黑名单未 DEL online key，
        //   导致用户登出后仍显示在线 30 分钟。online key 会自然过期，DEL 失败仅影响展示及时性。
        let online_key = format!("online:{}", token_hash);
        let _: () = redis::cmd("DEL")
            .arg(&online_key)
            .query_async(redis)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "DEL online:{} 失败（不阻断 logout，key 会自然过期）: {}",
                    token_hash,
                    e
                );
            });

        // 清理 user_sessions 索引（H-3 修复：不再批量删除所有 user_sessions:{user_id}:* ）
        //   原实现 SCAN + 批量 DEL 会误删其他设备（不同 IP/Browser）的索引，导致其他设备
        //   下次登录时 finalize_login GET 不到旧 token_hash，无法清理旧 online key，产生孤儿会话。
        //   修复方案：完全不删 user_sessions 索引，让它自然过期（TTL 与 online 一致）。
        //   下次同浏览器登录时，finalize_login 会用新 token_hash 覆盖旧索引，并 DEL 旧 online key。
        //   不同浏览器的索引互不干扰，自然过期即可。
        //
        //   如果未来需要精确删除当前会话的索引，可在 OnlineSession 中存储 ip/browser，
        //   logout 时从 online:{token_hash} 读取 session，构造精确 key 后 DEL。

        Ok(())
    }

    /// 获取用户信息（user + roles + permissions）
    ///
    /// 优化：合并查询角色+权限（缓存命中时 0 次 DB），避免分别调用
    /// get_role_keys_by_user_id 和 get_permissions_by_user_id 导致的冗余 DB 往返
    /// （原 8 次 DB → 缓存命中时 3 次 DB + 1 次 Redis GET）
    pub async fn get_info(&self, user_id: i64) -> Result<GetInfoVo, ServiceError> {
        let vo = self.user_service.get_user_by_id(user_id).await?;
        let mut user = vo.user;
        // 清空密码，避免泄露密文（双重保险，entity 已 #[serde(skip_serializing)]）
        user.password = None;

        // 合并查询角色+权限（缓存命中时 0 次 DB，消除 4 次冗余 DB 查询）
        let (roles, permissions) = self
            .menu_service
            .get_roles_and_permissions_by_user_id(user_id)
            .await?;

        // 密码安全策略字段
        // pwd_chrtype：密码加密类型（当前固定为 "argon2"）
        let pwd_chrtype = Some("argon2".to_string());
        // is_default_modify_pwd：是否仍使用初始密码
        // user_type "00"=正常用户（非初始密码标识），不应作为初始密码判断依据
        // 当前无 pwd_update_time 字段，默认为 false（admin 密码已修改过）
        let is_default_modify_pwd = false;
        // is_password_expired：密码是否过期（当前无密码过期策略，固定为 false）
        let is_password_expired = false;

        Ok(GetInfoVo {
            user,
            roles,
            permissions,
            pwd_chrtype,
            is_default_modify_pwd,
            is_password_expired,
        })
    }

    /// 获取用户路由树
    ///
    /// 流程：
    /// 1. 查询用户菜单树（menu_service 已过滤 F 类型 + 组装树形结构）
    /// 2. 递归转换为 RouterVo（menu_to_router）
    pub async fn get_routers(&self, user_id: i64) -> Result<Vec<RouterVo>, ServiceError> {
        let menu_tree = self.menu_service.get_menu_tree_by_user_id(user_id).await?;
        let routers: Vec<RouterVo> = menu_tree.iter().map(|m| menu_to_router(m, "")).collect();
        Ok(routers)
    }

    /// 用户注册（公开接口，免鉴权）
    ///
    /// 流程：
    /// 1. 参数校验
    /// 2. 验证码校验（GETDEL 原子化，防重放攻击；开关关闭时跳过）
    /// 3. 用户名查重
    /// 4. Argon2 加密密码
    /// 5. 创建用户（默认昵称同用户名，状态正常，不分配角色/部门）
    /// 6. 返回成功
    ///
    /// 安全说明：注册成功后不自动登录，前端引导用户去登录页。
    pub async fn register(
        &self,
        dto: RegisterDto,
        ip: &str,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        // R19-1.3：密码复杂度校验（注册入口拦截弱口令）
        validate_password_complexity(&dto.password).map_err(|e| ServiceError::bad_request(&e))?;

        // 0. 注册开关校验（P0-R12-001）
        //    sys.account.registerUser 默认 false（安全失败：配置缺失时禁止注册）
        //    管理员需显式在 sys_config 中将 registerUser 设为 true 才开放注册
        //    状态码：403 Forbidden（业务策略禁止，非系统错误）
        if !self.is_register_enabled().await {
            return Err(ServiceError::forbidden(&crate::tr!(
                "error.auth.register_disabled"
            )));
        }

        // 1. 验证码校验（GETDEL 原子化，防重放攻击）
        //    若 sys.account.captchaEnabled=false，则跳过验证码校验
        //    captcha key 绑定 IP：captcha:{uuid}:{ip}，防止跨 IP 重放
        //    状态码：400 Bad Request（客户端输入问题，非系统错误）
        if self.is_captcha_enabled().await {
            let captcha_key = format!("captcha:{}:{}", dto.uuid, ip);
            // C-1：显式 match 区分 Redis 错误（fail-closed 503）与 key 不存在（captcha_expired）
            //      与 verify_captcha（464-478 行）保持一致，避免静默吞错掩盖基础设施故障。
            // R11：命令级超时（fail-closed 503）
            let stored_code: Option<String> = match tokio::time::timeout(
                Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
                redis::cmd("GETDEL").arg(&captcha_key).query_async(redis),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    tracing::error!("Redis GETDEL 验证码失败（fail-closed）: {}", e);
                    return Err(ServiceError::new(
                        503,
                        crate::tr!("error.auth.auth_unavailable"),
                    ));
                }
                Err(_) => {
                    tracing::error!("Redis GETDEL 验证码超时（fail-closed）");
                    return Err(ServiceError::new(
                        503,
                        crate::tr!("error.auth.auth_unavailable"),
                    ));
                }
            };

            let stored = match stored_code {
                Some(c) => c,
                None => {
                    return Err(ServiceError::bad_request(&crate::tr!(
                        "error.auth.captcha_expired"
                    )));
                }
            };

            if stored.to_lowercase() != dto.code.to_lowercase() {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.auth.captcha_wrong"
                )));
            }
        }

        // 2. 用户名查重
        //    状态码：400 Bad Request（客户端输入冲突，非系统错误）
        let existing = self
            .user_service
            .get_user_by_username(&dto.username)
            .await?;
        if existing.is_some() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.auth.register_exists"
            )));
        }

        // 3. 创建用户（复用 user_service.add_user，昵称默认同用户名）
        let add_dto = UserAddDto {
            dept_id: None,
            user_name: dto.username.clone(),
            nick_name: dto.username,
            email: None,
            phonenumber: None,
            country_code: None,
            sex: None,
            password: dto.password,
            status: Some("0".to_string()),
            role_ids: None,
            post_ids: None,
            dept_ids: None,
            remark: None,
        };
        self.user_service.add_user(add_dto, "register").await?;

        Ok(())
    }

    /// OAuth/SSO 登录完成（第三方已校验身份后，直接为该本地账号签发会话）
    ///
    /// 复用密码登录的 `finalize_login`：JWT 签发 + 登录日志（成功）+ 在线用户映射 +
    /// 同 IP+浏览器旧会话清理 + 清除失败计数，保证第三方登录与会话链路行为一致。
    /// `username` 为已通过 OAuth 身份校验的本地账号登录名。
    pub async fn oauth_finalize_login(
        &self,
        username: &str,
        login_ip: &str,
        user_agent: &str,
        redis: &mut redis::aio::ConnectionManager,
        jwt_config: &JwtConfig,
        ip_locator: &IpLocator,
    ) -> Result<LoginVo, ServiceError> {
        // 重新按用户名取活跃用户（沿用 Repository 已过滤 del_flag='0' 的语义）
        let user = self
            .user_service
            .get_active_user_by_username(username)
            .await?
            .ok_or_else(|| {
                ServiceError::unauthorized(&crate::tr!("error.oauth.local_user_not_found"))
            })?;
        // 账号停用统一拒绝（与密码登录 C-1 一致，不暴露细分原因）
        if user.status.as_deref() == Some("1") {
            return Err(ServiceError::unauthorized(&crate::tr!(
                "error.oauth.local_user_not_found"
            )));
        }

        let browser = parse_browser(user_agent);
        let os = parse_os(user_agent);
        // IP 归属地查询（mmdb 文件不存在或查询失败时返回空字符串）
        let login_location = ip_locator.locate(login_ip);
        let ctx = LoginContext {
            username: &user.user_name,
            login_ip,
            login_location: &login_location,
            browser: &browser,
            os: &os,
        };
        // 复用 finalize_login（JWT 签发 + 登录成功日志 + 在线映射 + 旧会话清理），
        // 正常路径仅一条登录日志，避免重复写入。
        self.finalize_login(&user, redis, jwt_config, &ctx).await
    }

    /// 锁屏解锁（需登录态，校验当前用户密码）
    ///
    /// 流程：
    /// 1. 参数校验
    /// 2. 查询用户
    /// 3. Argon2 校验密码（spawn_blocking 避免阻塞 Tokio runtime，P0-31）
    /// 4. 匹配成功返回 Ok(())，失败返回密码错误
    pub async fn unlock_screen(
        &self,
        user_id: i64,
        dto: UnlockScreenDto,
    ) -> Result<(), ServiceError> {
        crate::common::i18n::validate(&dto)?;

        let vo = self.user_service.get_user_by_id(user_id).await?;
        let user = vo.user;

        // Argon2 verify 是 CPU 密集型同步操作，用 spawn_blocking 包裹（P0-31）
        let stored_password = user.password.as_deref().unwrap_or("").to_string();
        let password_for_verify = dto.password;
        let verify_result = tokio::task::spawn_blocking(move || {
            verify_password_with_upgrade_hint(&password_for_verify, &stored_password)
        })
        .await
        .map_err(|e| {
            tracing::error!("密码验证 spawn_blocking 失败: {}", e);
            ServiceError::internal(&crate::tr!("error.auth.password_verify_failed"))
        })?;
        if !verify_result.is_valid {
            return Err(ServiceError::unauthorized(&crate::tr!(
                "error.auth.login_failed"
            )));
        }

        Ok(())
    }

    // ==================== 内部辅助方法 ====================

    /// 记录登录失败次数（Lua 脚本原子化 INCR + EXPIRE，防止计数永不过期）
    async fn record_login_failure(
        &self,
        username: &str,
        redis: &mut redis::aio::ConnectionManager,
    ) -> Result<(), ServiceError> {
        let fail_key = format!("login_fail:{}", username);
        // R11：命令级超时（fail-closed 503）
        let _: i64 = tokio::time::timeout(
            Duration::from_secs(REDIS_CMD_TIMEOUT_SECS),
            redis::Script::new(RATE_LIMIT_SCRIPT)
                .key(&fail_key)
                .arg(LOGIN_FAIL_TTL)
                .invoke_async(redis),
        )
        .await
        .map_err(|_| {
            tracing::error!("Redis 登录失败计数更新超时（fail-closed）");
            ServiceError::new(503, crate::tr!("error.auth.auth_unavailable"))
        })?
        .map_err(|e| {
            tracing::error!("Redis 登录失败计数更新失败（fail-closed）: {}", e);
            ServiceError::new(503, crate::tr!("error.auth.auth_unavailable"))
        })?;
        Ok(())
    }

    /// 写入登录日志
    ///
    /// 参数：
    /// - status: "0" 成功 / "1" 失败
    /// - msg: 日志消息
    /// - browser / os: 从 User-Agent 解析
    /// - login_location: IP 归属地（由 IpLocator 查询得到）
    async fn write_login_log(
        &self,
        ctx: &LoginContext<'_>,
        status: &str,
        msg: &str,
    ) -> Result<i64, ServiceError> {
        let now = crate::common::datetime::now_naive();
        let mut am = sys_logininfor::ActiveModel {
            ..Default::default()
        };
        am.user_name = Set(Some(ctx.username.to_string()));
        am.ipaddr = Set(Some(ctx.login_ip.to_string()));
        am.login_location = Set(if ctx.login_location.is_empty() {
            None
        } else {
            Some(ctx.login_location.to_string())
        });
        am.browser = Set(Some(ctx.browser.to_string()));
        am.os = Set(Some(ctx.os.to_string()));
        am.status = Set(Some(status.to_string()));
        am.msg = Set(Some(msg.to_string()));
        am.login_time = Set(Some(now));
        let model = self.logininfor_repo.insert(am).await?;
        Ok(model.info_id)
    }

    /// best-effort 版本的 write_login_log：失败仅记录警告日志，不传播错误
    ///
    /// 用于认证失败路径：日志写入失败不应掩盖原始的认证错误（如 401），
    /// 用户应看到 401 而非 500。同时避免同步 DB 写入阻塞响应（H-2）。
    async fn write_login_log_best_effort(&self, ctx: &LoginContext<'_>, status: &str, msg: &str) {
        if let Err(e) = self.write_login_log(ctx, status, msg).await {
            tracing::warn!(
                username = ctx.username,
                status,
                error = %e,
                "登录日志写入失败（best-effort，不影响认证结果）"
            );
        }
    }
}

// ==================== 辅助函数 ====================

/// 从 User-Agent 简单提取浏览器名称
///
/// 注意：Edge 判断必须在 Chrome 之前（Edge UA 含 "Chrome" 字符串）。
/// 现代 Edge（Chromium 内核）UA 使用 "Edg/"，旧版 Edge 使用 "Edge/"，
/// 统一用 "Edg" 子串匹配覆盖两者。
///
/// L-5 已知限制（低优先级，保留现状）：
/// - 仅做子串匹配，无法识别版本号、引擎分支、移动端浏览器（如 Chrome Mobile / Samsung Internet / Opera）
/// - UA 伪装场景下结果不准确（curl/Postman 自定义 UA 会被归类为 Unknown 或误判）
/// - 仅用于登录日志展示，不影响鉴权安全；如需精确解析请引入 `ua-parser` 等专门 crate
fn parse_browser(ua: &str) -> String {
    if ua.contains("Edg") {
        "Edge".to_string()
    } else if ua.contains("Chrome") {
        "Chrome".to_string()
    } else if ua.contains("Firefox") {
        "Firefox".to_string()
    } else if ua.contains("Safari") {
        "Safari".to_string()
    } else {
        "Unknown".to_string()
    }
}

/// 从 User-Agent 简单提取操作系统名称
///
/// 注意：iPhone/iPad UA 含 "Mac OS" 字符串，iOS 判断必须在 macOS 之前。
///
/// L-5 已知限制（低优先级，保留现状）：
/// - 无法区分 Windows 10 / 11、macOS 各版本、Android 各版本
/// - 无法识别 HarmonyOS、ChromeOS、各类 Linux 发行版
/// - 仅用于登录日志展示，不影响鉴权安全
fn parse_os(ua: &str) -> String {
    if ua.contains("Windows") {
        "Windows".to_string()
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS".to_string()
    } else if ua.contains("Android") {
        "Android".to_string()
    } else if ua.contains("Mac OS") {
        "macOS".to_string()
    } else if ua.contains("Linux") {
        "Linux".to_string()
    } else {
        "Unknown".to_string()
    }
}

/// 将 SysMenuModel 转换为 RouterVo（递归转换子节点）
///
/// 转换规则（按现有接口契约）：
/// - name: 优先 route_name，其次 path；子路由添加父路径前缀确保全局唯一
/// - path: 顶级目录（parent_id==0 且 type=="M"）加 `/` 前缀；其他原样
/// - hidden: status == "1"（禁用状态隐藏）
/// - redirect: is_frame==1 && type=="M" → "noRedirect"；否则 None
/// - component: None/空 → 顶级 "Layout" / 子级目录 "ParentView"；否则原样
/// - alwaysShow: visible=="0" && type!="C" && is_frame==1 → Some(true)
/// - meta.title: menu_name
/// - meta.icon: icon（默认空字符串）
/// - meta.noCache: is_cache == 1
/// - meta.link: is_frame == 0（外链）→ Some(path)
/// - children: 递归转换，过滤 F 类型，空则 None
///
/// name 唯一性：Vue Router 要求路由 name 全局唯一，后注册的同名路由会覆盖先注册的。
/// 之前 `/dashboard`(name=dashboard) 和 `/system/dashboard`(name=dashboard) 冲突，
/// 导致 `/dashboard` 路由被覆盖，其子路由全部 404。
/// 修复：子路由 name 添加父路径前缀，如 `system-dashboard`、`dashboard-workbench`。
fn menu_to_router(menu: &SysMenuModel, parent_path: &str) -> RouterVo {
    let menu_type = menu.menu_type.as_deref().unwrap_or("C");
    let is_frame = menu.is_frame.as_deref().unwrap_or("1");
    let is_cache = menu.is_cache.as_deref().unwrap_or("0");
    let visible = menu.visible.as_deref().unwrap_or("0");
    let status = menu.status.as_deref().unwrap_or("0");
    let parent_id = menu.parent_id.unwrap_or(0);

    // path 转换：顶级菜单（parent_id==0）一律加 / 前缀
    // 原因：Vue Router 要求顶层路由 path 必须以 "/" 开头，否则抛出
    // "Route paths should start with a '/': "xxx" should be "/xxx""
    // 修复前仅 type=="M" 加前缀，导致顶级 type=="C" 菜单（如数据看板 dashboard）缺斜杠
    // 例外：外链（is_frame=="0"）的 path 是完整 URL，不加前缀
    let path = if parent_id == 0 && is_frame != "0" {
        let raw = menu.path.as_deref().unwrap_or("");
        if raw.starts_with('/') || raw.starts_with("http") {
            raw.to_string()
        } else {
            format!("/{}", raw)
        }
    } else {
        menu.path.clone().unwrap_or_default()
    };

    // component 转换
    let component = match menu.component.as_deref() {
        None | Some("") => {
            if parent_id == 0 && menu_type == "M" {
                "Layout".to_string()
            } else if parent_id != 0 && menu_type == "M" {
                "ParentView".to_string()
            } else {
                String::new()
            }
        }
        Some(c) => c.to_string(),
    };

    // redirect 转换
    let redirect = if is_frame == "1" && menu_type == "M" {
        Some("noRedirect".to_string())
    } else {
        None
    };

    // alwaysShow 转换
    let always_show = if visible == "0" && menu_type != "C" && is_frame == "1" {
        Some(true)
    } else {
        None
    };

    // meta 转换
    let meta = MetaVo {
        title: menu.menu_name.clone(),
        icon: menu.icon.clone().unwrap_or_default(),
        no_cache: is_cache == "1",
        link: if is_frame == "0" {
            menu.path.clone()
        } else {
            None
        },
        i18n_key: menu.i18n_key.clone(),
    };

    // name 生成：优先 route_name，其次 path
    // 子路由添加父路径前缀确保全局唯一（避免 Vue Router name 冲突覆盖）
    let base_name = menu
        .route_name
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| menu.path.clone())
        .unwrap_or_default();
    let name = if parent_path.is_empty() {
        base_name.clone()
    } else {
        format!("{}-{}", parent_path, base_name)
    };

    // 用 name 作为子路由的 parent_path 传参
    // 这样嵌套层级越深，name 前缀越长，确保唯一
    let child_parent_path = name.clone();

    // children 递归转换（过滤 F 类型，防御性二次过滤）
    let children = if let Some(ref kids) = menu.children {
        let router_kids: Vec<RouterVo> = kids
            .iter()
            .filter(|k| k.menu_type.as_deref() != Some("F"))
            .map(|k| menu_to_router(k, &child_parent_path))
            .collect();
        if router_kids.is_empty() {
            None
        } else {
            Some(router_kids)
        }
    } else {
        None
    };

    RouterVo {
        name,
        path,
        hidden: status == "1",
        redirect,
        component,
        always_show,
        meta,
        query: menu.query.clone(),
        children,
    }
}

// ==================== 单元测试 ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::sys_menu::Model as SysMenuModel;

    /// 构造测试用菜单模型
    #[allow(clippy::too_many_arguments)]
    fn make_menu(
        menu_id: i64,
        parent_id: i64,
        menu_type: &str,
        path: &str,
        component: Option<&str>,
        is_frame: &str,
        is_cache: &str,
        status: &str,
        visible: &str,
        route_name: Option<&str>,
    ) -> SysMenuModel {
        SysMenuModel {
            menu_id,
            menu_name: format!("菜单{}", menu_id),
            parent_id: Some(parent_id),
            order_num: Some(0),
            path: Some(path.to_string()),
            component: component.map(|s| s.to_string()),
            query: None,
            route_name: route_name.map(|s| s.to_string()),
            is_frame: Some(is_frame.to_string()),
            is_cache: Some(is_cache.to_string()),
            menu_type: Some(menu_type.to_string()),
            visible: Some(visible.to_string()),
            status: Some(status.to_string()),
            perms: None,
            i18n_key: None,
            icon: Some("test-icon".to_string()),
            create_by: None,
            create_time: None,
            update_by: None,
            update_time: None,
            remark: None,
            del_flag: Some("0".to_string()),
            children: None,
        }
    }

    #[test]
    fn test_parse_browser_chrome() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(parse_browser(ua), "Chrome");
    }

    #[test]
    fn test_parse_browser_edge_priority() {
        // Edge UA 含 "Chrome" 字符串，Edge 判断必须优先
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
        assert_eq!(parse_browser(ua), "Edge");
    }

    #[test]
    fn test_parse_browser_firefox() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0";
        assert_eq!(parse_browser(ua), "Firefox");
    }

    #[test]
    fn test_parse_browser_safari() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        assert_eq!(parse_browser(ua), "Safari");
    }

    #[test]
    fn test_parse_browser_unknown() {
        let ua = "SomeUnknownBrowser/1.0";
        assert_eq!(parse_browser(ua), "Unknown");
    }

    #[test]
    fn test_parse_os_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        assert_eq!(parse_os(ua), "Windows");
    }

    #[test]
    fn test_parse_os_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)";
        assert_eq!(parse_os(ua), "macOS");
    }

    #[test]
    fn test_parse_os_android() {
        let ua = "Mozilla/5.0 (Linux; Android 13; Pixel 7)";
        assert_eq!(parse_os(ua), "Android");
    }

    #[test]
    fn test_parse_os_ios() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)";
        assert_eq!(parse_os(ua), "iOS");
    }

    #[test]
    fn test_parse_os_linux() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64)";
        assert_eq!(parse_os(ua), "Linux");
    }

    #[test]
    fn test_menu_to_router_top_directory() {
        // 顶级目录：parent_id=0, type=M
        let menu = make_menu(1, 0, "M", "system", None, "1", "0", "0", "0", None);
        let router = menu_to_router(&menu, "");

        assert_eq!(router.path, "/system"); // 顶级目录 path 加 / 前缀
        assert_eq!(router.component, "Layout"); // 顶级目录 component 默认 Layout
        assert_eq!(router.redirect, Some("noRedirect".to_string())); // M + is_frame=1
        assert!(!router.hidden); // status=0
        assert_eq!(router.always_show, Some(true)); // visible=0 && M && is_frame=1
        assert!(!router.meta.no_cache); // is_cache=0
        assert_eq!(router.meta.link, None); // is_frame=1 不是外链
        assert_eq!(router.name, "system"); // 无 route_name，用 path
    }

    #[test]
    fn test_menu_to_router_top_directory_with_route_name() {
        // name 优先使用 route_name
        let menu = make_menu(1, 0, "M", "system", None, "1", "0", "0", "0", Some("sys"));
        let router = menu_to_router(&menu, "");
        assert_eq!(router.name, "sys"); // route_name 优先
    }

    #[test]
    fn test_menu_to_router_sub_directory() {
        // 子级目录：parent_id!=0, type=M
        let menu = make_menu(2, 1, "M", "config", None, "1", "0", "0", "0", None);
        let router = menu_to_router(&menu, "");

        assert_eq!(router.path, "config"); // 非顶级目录不加 / 前缀
        assert_eq!(router.component, "ParentView"); // 子级目录默认 ParentView
    }

    #[test]
    fn test_menu_to_router_menu_type_c() {
        // 菜单类型 C：保留 component
        let menu = make_menu(
            3,
            1,
            "C",
            "user",
            Some("system/user/index"),
            "1",
            "0",
            "0",
            "0",
            None,
        );
        let router = menu_to_router(&menu, "");

        assert_eq!(router.component, "system/user/index"); // 原样保留
        assert_eq!(router.redirect, None); // 非 M 类型无 redirect
        assert_eq!(router.always_show, None); // C 类型无 alwaysShow
    }

    #[test]
    fn test_menu_to_router_external_link() {
        // 外链：is_frame=0
        let menu = make_menu(
            4,
            0,
            "C",
            "https://example.com",
            None,
            "0",
            "0",
            "0",
            "0",
            None,
        );
        let router = menu_to_router(&menu, "");

        assert_eq!(router.meta.link, Some("https://example.com".to_string())); // is_frame=0 → link
        assert_eq!(router.redirect, None); // is_frame=0 不满足 is_frame==1
        // 外链 path 不加 / 前缀（path 是完整 URL）
        assert_eq!(router.path, "https://example.com");
    }

    #[test]
    fn test_menu_to_router_top_level_c_menu_has_slash_prefix() {
        // 顶级 C 类型菜单（如数据看板）：path 应加 / 前缀
        // 修复前：仅 type=="M" 加前缀，导致顶级 C 菜单 path="dashboard" 缺斜杠
        // Vue Router 抛出 "Route paths should start with a "/": "dashboard" should be "/dashboard""
        let menu = make_menu(
            132,
            0,
            "C",
            "dashboard",
            Some("dashboard/index"),
            "1",
            "0",
            "0",
            "0",
            None,
        );
        let router = menu_to_router(&menu, "");
        assert_eq!(router.path, "/dashboard"); // 顶级 C 菜单也需 / 前缀
        assert_eq!(router.component, "dashboard/index"); // component 原样保留
    }

    #[test]
    fn test_menu_to_router_hidden_status() {
        // status=1 → hidden=true
        let menu = make_menu(5, 0, "M", "hidden-dir", None, "1", "0", "1", "0", None);
        let router = menu_to_router(&menu, "");
        assert!(router.hidden);
    }

    #[test]
    fn test_menu_to_router_no_cache() {
        // is_cache=1 → no_cache=true
        let menu = make_menu(6, 0, "M", "cached-dir", None, "1", "1", "0", "0", None);
        let router = menu_to_router(&menu, "");
        assert!(router.meta.no_cache);
    }

    #[test]
    fn test_menu_to_router_with_children() {
        // 带子菜单的顶级目录
        let child = make_menu(
            8,
            7,
            "C",
            "user",
            Some("system/user/index"),
            "1",
            "0",
            "0",
            "0",
            None,
        );
        let mut parent = make_menu(7, 0, "M", "system", None, "1", "0", "0", "0", None);
        parent.children = Some(vec![child]);

        let router = menu_to_router(&parent, "");
        assert!(router.children.is_some());
        let children = router.children.unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, "system-user"); // 子路由 name 添加父路径前缀
    }

    #[test]
    fn test_menu_to_router_filter_button_children() {
        // 子菜单含 F 类型（按钮），应被过滤
        let button = make_menu(9, 7, "F", "btn", None, "1", "0", "0", "0", None);
        let menu_c = make_menu(
            10,
            7,
            "C",
            "role",
            Some("system/role/index"),
            "1",
            "0",
            "0",
            "0",
            None,
        );
        let mut parent = make_menu(7, 0, "M", "system", None, "1", "0", "0", "0", None);
        parent.children = Some(vec![button, menu_c]);

        let router = menu_to_router(&parent, "");
        let children = router.children.unwrap();
        assert_eq!(children.len(), 1); // F 被过滤，只剩 C
        assert_eq!(children[0].name, "system-role"); // 子路由 name 添加父路径前缀
    }

    #[test]
    fn test_menu_to_router_empty_children_returns_none() {
        // 子菜单全为 F 类型 → children 为 None
        let button = make_menu(11, 7, "F", "btn", None, "1", "0", "0", "0", None);
        let mut parent = make_menu(7, 0, "M", "system", None, "1", "0", "0", "0", None);
        parent.children = Some(vec![button]);

        let router = menu_to_router(&parent, "");
        assert!(router.children.is_none()); // 全过滤后为 None
    }
}
