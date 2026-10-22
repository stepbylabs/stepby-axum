// stepby-axum/src/middleware/pwd_gate.rs
//! 强改密服务端闸门（批八十四 项 A：把"强制改密"从前端建议变成服务端事实）
//!
//! 背景：`sys.user.forceFirstLoginChangePwd` 自 B4 起只有**前端弹框**——`/getInfo` 下发
//! `mustChangePassword=true`，前端跳改密页。绕过前端（直接调 API）照常读写，
//! 属开关规范③明令禁止的"只做前端隐藏而不做服务端守卫"。
//!
//! ## 判定链（全部读同一份 `common::pwd_policy` 判据，与 `/getInfo` 不可能口径不一致）
//!
//! 1. `sys.user.pwdChangeGate` = `off`（默认）⇒ **直接放行，一次库都不查**（现状零开销零变化）；
//! 2. `sys.user.forceFirstLoginChangePwd` = false ⇒ 放行（平台开关是天花板，闸门只是它的执行面；
//!    单独开闸门而不开强改，语义上是"没人需要改密"，不得凭空拦人）；
//! 3. 取该账号的口令姿态（一次按主键的 SELECT，只在闸门开启时才发生）；
//!    `must_change_password` 为 false ⇒ 放行；
//! 4. 白名单：复用 `permission::is_login_only_path`（**不抄第二份清单**，b78 R-22 同族）——
//!    它已含改密流程所需的全部端点（`/getInfo`、`/getRouters`、`/system/user/profile`、
//!    `updatePwd`、`/logout`、TOTP/WebAuthn、前端异常上报…）；登录/验证码在 `public_routes`
//!    上，本中间件挂在受保护组，天然不在射程内；
//! 5. `deny_all` 拦一切非白名单；`deny_write` 只拦写方法（读放行）。
//!
//! ## 可完成性（这条决定"谁可以被拦"）
//!
//! 闸门只拦"能自己走出去"的状态：白名单里的自助改密要求**旧口令**。
//! 因此随机生成、无人可知的占位口令（OAuth 自动建号 / SCIM 供给）不记口令年龄
//! （`pwd_update_time = NULL` ⇒ 永不过期，见 `common::pwd_policy` 模块注释与写站点锁的豁免登记）。
//! 反过来，若把这类账号纳入拦截，用户既不知道旧口令、又进不了任何业务接口 = 永久死锁，
//! 只能靠管理员重置解救——那不是"更安全"，是不可用。
//!
//! ## 失败姿态
//!
//! 档位/开关读取失败 ⇒ 放行（fail-safe：不明确的姿态不得拦截用户；与
//! `get_info` 的 `force_pwd_change_enabled` 同口径）。**口令姿态查库失败 ⇒ 拒绝请求**
//! （fail-closed 的唯一例外理由：既然管理员已显式开启闸门，"查不到这个人"绝不能当成"放行"，
//! 否则删号/越权令牌可借一次 DB 抖动绕过闸门）。

use std::sync::Arc;

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};

use crate::common::AppError;
use crate::common::pwd_policy::{self, PwdChangeGate};
use crate::entity::sys_user;
use crate::jwt::Claims;
use crate::middleware::normalize_api_prefix;
use crate::middleware::permission::{is_login_only_path, spawn_permission_denied_audit};
use crate::state::AppState;

/// 闸门决策（纯函数）：是否拒绝这次请求。
///
/// 拆成纯函数的理由与本仓每一条判据相同——**能被单测穷举的判定才叫判定**。
/// `whitelisted` 由调用方用 `is_login_only_path` 算（路由模板口径），本函数不碰路径。
fn blocks_request(gate: PwdChangeGate, method: &str, whitelisted: bool) -> bool {
    !whitelisted && gate.blocks_method(method)
}

pub async fn pwd_gate_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| AppError::unauthorized(&crate::tr!("error.auth.login_info_missing")))?;

    // 1. 闸门档位：off（默认/缺行/不可解析）⇒ 立即放行，不查库
    let gate_raw = state
        .config_service
        .get_config_value_by_key_cached(pwd_policy::PWD_CHANGE_GATE_CONFIG_KEY, Some(claims.tid))
        .await
        .ok()
        .flatten();
    let gate = PwdChangeGate::parse(gate_raw.as_deref());
    if gate == PwdChangeGate::Off {
        return Ok(next.run(req).await);
    }

    // 2. 总闸：强改开关未开 ⇒ 无人"必须"改密，闸门不得凭空拦人
    let force_enabled = match state
        .config_service
        .get_config_value_by_key_cached(pwd_policy::FORCE_PWD_CHANGE_CONFIG_KEY, Some(claims.tid))
        .await
    {
        Ok(Some(v)) => v.eq_ignore_ascii_case("true"),
        _ => false,
    };
    if !force_enabled {
        return Ok(next.run(req).await);
    }

    // 3. 该账号的口令姿态（只在闸门开启时发生；两列都取自主键行，不引入 join）
    let user_id: i64 = match claims.sub.parse() {
        Ok(v) => v,
        // 身份串不可解析 = 令牌异常，本中间件之前就该被 auth 挡下；这里 fail-closed
        Err(_) => {
            tracing::warn!(sub = %claims.sub, "强改密闸门：claims.sub 非用户 ID（拒绝）");
            return Err(AppError::unauthorized(&crate::tr!(
                "error.auth.login_info_missing"
            )));
        }
    };
    let facts = sys_user::Entity::find()
        .filter(sys_user::Column::UserId.eq(user_id))
        .select_only()
        .column(sys_user::Column::MustChangePwd)
        .column(sys_user::Column::PwdUpdateTime)
        .into_tuple::<(Option<String>, Option<chrono::NaiveDateTime>)>()
        .one(&state.db)
        .await
        .map_err(|e| {
            // fail-closed：见模块注释"失败姿态"。错误串不含口令，直接带出可排障。
            tracing::error!(user_id, error = %e, "强改密闸门：口令姿态查询失败（拒绝）");
            AppError::internal(&crate::tr!("error.common.internal"))
        })?;
    let Some((must_change_pwd, pwd_update_time)) = facts else {
        // 令牌指向的账号已不存在 ⇒ 拒绝（不给"查无此人"继续访问的机会）
        tracing::warn!(user_id, "强改密闸门：账号不存在（拒绝）");
        return Err(AppError::unauthorized(&crate::tr!("error.user.not_found")));
    };

    let days = pwd_policy::parse_expire_days(
        state
            .config_service
            .get_config_value_by_key_cached(
                pwd_policy::PWD_EXPIRE_DAYS_CONFIG_KEY,
                Some(claims.tid),
            )
            .await
            .ok()
            .flatten()
            .as_deref(),
    );
    let reason = pwd_policy::classify(
        true,
        must_change_pwd.as_deref(),
        crate::common::datetime::now_naive(),
        pwd_update_time,
        days,
    );
    if !reason.any() {
        return Ok(next.run(req).await);
    }

    // 4. 白名单（与 RBAC 的仅登录放行**同一张表**）
    let method = req.method().clone();
    let matched = req
        .extensions()
        .get::<MatchedPath>()
        .cloned()
        .map(|p| normalize_api_prefix(p.as_str()).to_string());
    let whitelisted = matched
        .as_deref()
        .is_some_and(|p| is_login_only_path(method.as_str(), p));
    if !blocks_request(gate, method.as_str(), whitelisted) {
        return Ok(next.run(req).await);
    }

    // 5. 拒绝：审计留痕复用 permission 的同一落库通道（两份审计实现必漂），
    //    "所需权限"位写档位与原因，便于运维从 sys_oper_log 直接看出被哪一档拦的。
    let path_for_audit = matched.unwrap_or_else(|| req.uri().path().to_string());
    tracing::warn!(
        user_id,
        tenant_id = claims.tid,
        method = %method,
        path = %path_for_audit,
        gate = gate_rank_name(gate),
        initial_password_unused = reason.initial_password_unused,
        expired = reason.expired,
        "强改密闸门：拒绝访问（须先修改口令）"
    );
    spawn_permission_denied_audit(
        &state,
        &claims,
        &method,
        &path_for_audit,
        &format!(
            "pwd_change_gate={};initial={};expired={}",
            gate_rank_name(gate),
            reason.initial_password_unused,
            reason.expired
        ),
        &req,
    );
    // 文案两条分开取（`tr!` 只接受字面量键——把键名塞进变量会在编译期就拦下来，
    // 这正是"键名必须可被 i18n 锁静态解析"的结构保证）。
    let msg = if reason.expired && !reason.initial_password_unused {
        crate::tr!("error.user.password_expired")
    } else {
        crate::tr!("error.user.password_change_required")
    };
    Err(AppError::forbidden(&msg))
}

fn gate_rank_name(gate: PwdChangeGate) -> &'static str {
    match gate {
        PwdChangeGate::DenyAll => "deny_all",
        PwdChangeGate::DenyWrite => "deny_write",
        PwdChangeGate::Off => "off",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ① 三档 × 读/写 × 白名单的完整矩阵：拦的集合必须随档位单调，且白名单恒放行
    #[test]
    fn decision_matrix_covers_all_tiers() {
        for m in ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"] {
            // 白名单在任何档位下都必须放行——否则改密流程自己被闸门锁死（本功能的死锁形态）
            assert!(
                !blocks_request(PwdChangeGate::DenyAll, m, true),
                "白名单 {m} 不得被拦"
            );
            assert!(!blocks_request(PwdChangeGate::DenyWrite, m, true));
            assert!(!blocks_request(PwdChangeGate::Off, m, true));
        }
        assert!(blocks_request(PwdChangeGate::DenyAll, "GET", false));
        assert!(!blocks_request(PwdChangeGate::DenyWrite, "GET", false));
        assert!(blocks_request(PwdChangeGate::DenyWrite, "POST", false));
        assert!(!blocks_request(PwdChangeGate::Off, "POST", false));
    }

    /// ② 单调性：对同一 (方法, 白名单) 组合，放松档位绝不增加拦截
    #[test]
    fn loosening_tier_never_blocks_more() {
        let tiers = [
            PwdChangeGate::DenyAll,
            PwdChangeGate::DenyWrite,
            PwdChangeGate::Off,
        ];
        for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            for w in [true, false] {
                let v = tiers.map(|t| blocks_request(t, m, w));
                for pair in v.windows(2) {
                    assert!(
                        !(!pair[0] && pair[1]),
                        "{m}/whitelisted={w} 档位放松却拦得更多"
                    );
                }
            }
        }
    }

    /// ③ 档位名与档位一一对应（审计串里出现的就是配置里写的那个词）
    #[test]
    fn tier_names_are_stable_strings() {
        assert_eq!(gate_rank_name(PwdChangeGate::DenyAll), "deny_all");
        assert_eq!(gate_rank_name(PwdChangeGate::DenyWrite), "deny_write");
        assert_eq!(gate_rank_name(PwdChangeGate::Off), "off");
        // 与配置解析口径闭环：名字解析回原档位（写审计→运维照抄→再解析，必须同值）
        for t in [
            PwdChangeGate::DenyAll,
            PwdChangeGate::DenyWrite,
            PwdChangeGate::Off,
        ] {
            assert_eq!(PwdChangeGate::parse(Some(gate_rank_name(t))), t);
        }
    }
}
