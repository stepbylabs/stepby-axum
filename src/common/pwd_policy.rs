//! 口令有效期与服务端强改密闸门的**判据单一事实源**（批八十四 项 A）。
//!
//! ## 为什么需要这个模块（缺陷取证）
//!
//! 1. `auth_service::get_info` 里 `is_password_expired` 曾长期写死 `false`（注释"当前无密码
//!    过期策略"），而 `docs/auth-spec.md` 早已把"密码过期"当交付能力写进文档、前端
//!    `store/modules/user.ts` 也备好了对应弹框分支——**接口字段存在但恒假**就是假功能：
//!    用户改不掉、文档不说谎、没有任何判据报红。根因是库里没有"口令何时设置过"的事实：
//!    `sys_user` 只有 `create_time/update_time/login_date`，而 `update_time` 被
//!    `impl_timestamped_active_model!` 在任何更新上刷新（改昵称/传头像/软删都动它），
//!    结构上不能当口令年龄。
//! 2. `sys.user.forceFirstLoginChangePwd`（B4）只有**前端弹框**、服务端零闸门 ⇒ "强改密"
//!    是一个绕得开的建议（直接调 API 照常读写），正是开关规范③禁止的"只做前端隐藏"。
//!
//! ## 三条口径是设计而非风格
//!
//! - **`pwd_update_time` 只在"口令作为知识交付给了某个知道它的人"时写入**：用户自设、
//!   管理员下发初始口令、管理员重置。随机生成且**无人可知**的口令（OAuth 首登自动建号、
//!   SCIM 供给）写 `NULL`。`NULL` 的语义是"无本地口令年龄"⇒ 永不过期。
//!   这条不是偷懒的缺省，而是**可完成性（satisfiability）判据**：白名单里的自助改密
//!   `PUT /system/user/profile/updatePwd` 要求旧口令，把用户不可能知道的口令标成
//!   "过期须改"= 在 `deny_*` 档下把该账号永久锁死。闸门只能拦"能自己走出去"的状态。
//! - **闸门档位按开放度单调**（`deny_all < deny_write < off`，下标越大越开放），
//!   非法值回落 `off` 并 WARN（开关规范②③：拒绝静默失效，且默认姿态不拦人）。
//!   白名单复用 `permission::is_login_only_path`——**不抄第二份清单**（两份手抄路由清单
//!   必漂，b78 R-22 同族）。
//! - **键名与默认值由迁移侧单一定义处再导出**（`PWD_*_CONFIG_KEY`），本模块不得另写一份字面量。
//!
//! ## 默认值 = 现状
//!
//! `sys.user.pwdExpireDays = 0`（永不过期）与 `sys.user.pwdChangeGate = off`（不拦）
//! ⇒ 存量部署升级后行为逐字节不变；判定链在 `off` 档不查库、不算过期。

use chrono::NaiveDateTime;

/// 两个热键的键名与默认值：唯一事实源在迁移文件里（种子体与判定链共用，杜绝两处手抄）。
pub use migration::migrations::m20261022_000001_pwd_expire_policy::{
    PWD_CHANGE_GATE_CONFIG_DEFAULT, PWD_CHANGE_GATE_CONFIG_KEY, PWD_EXPIRE_DAYS_CONFIG_DEFAULT,
    PWD_EXPIRE_DAYS_CONFIG_KEY,
};

/// 既有开关：是否把"初始密码未改 / 口令过期"判为"必须改密"并下发前端。
pub use migration::migrations::m20261004_000003_force_pwd_change::{
    FORCE_PWD_CHANGE_CONFIG_DEFAULT, FORCE_PWD_CHANGE_CONFIG_KEY,
};

const SECONDS_PER_DAY: i64 = 86_400;

/// 强改密服务端闸门档位。**顺序即开放度**（下标越大越宽松），由
/// `gate_tiers_are_monotone_by_permissiveness` 单测机器证明，不靠注释声明。
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PwdChangeGate {
    /// 除"仅登录白名单"外一律 403（最严：只留改密出口）
    DenyAll,
    /// 只拦写方法（POST/PUT/DELETE/PATCH），读放行——给管理员"先看影响面再收紧"的台阶
    DenyWrite,
    /// 不拦（默认 = 本批之前的行为）
    Off,
}

impl PwdChangeGate {
    /// 档位序（0 = 最严）。用于单调性判据与"翻档只会更松"的断言。
    pub fn rank(self) -> u8 {
        match self {
            PwdChangeGate::DenyAll => 0,
            PwdChangeGate::DenyWrite => 1,
            PwdChangeGate::Off => 2,
        }
    }

    /// 解析配置值：`None`/空/仅空白 ⇒ `Off`（缺行=现状）；未知值 ⇒ `Off` + WARN。
    ///
    /// 取 `Off` 而非最严档作回落是**刻意的 fail-safe**：闸门拦错人是不可逆的业务事故
    /// （全站 403 且没人知道为什么），配错档位是可见的事故（运维调一次即恢复）。
    /// 与 `cache.mode` / `[ui]` 档位的既有回落口径一致。
    pub fn parse(raw: Option<&str>) -> Self {
        let v = raw.unwrap_or("").trim().to_ascii_lowercase();
        match v.as_str() {
            "" | "off" => PwdChangeGate::Off,
            "deny_all" => PwdChangeGate::DenyAll,
            "deny_write" => PwdChangeGate::DenyWrite,
            other => {
                tracing::warn!(
                    key = PWD_CHANGE_GATE_CONFIG_KEY,
                    value = other,
                    fallback = PWD_CHANGE_GATE_CONFIG_DEFAULT,
                    "非法档位，回落 off（拒绝静默失效：配错必须被看见，但不得因此拦人）"
                );
                PwdChangeGate::Off
            }
        }
    }

    /// 该档位下，此方法是否**可能**被拦（白名单在此之前已放行，故这里只判方法）。
    pub fn blocks_method(self, method: &str) -> bool {
        match self {
            PwdChangeGate::Off => false,
            PwdChangeGate::DenyAll => true,
            PwdChangeGate::DenyWrite => is_write_method(method),
        }
    }
}

/// 写方法判定：与 `oper_log_middleware` / 幂等中间件同一族口径（GET/HEAD/OPTIONS 之外）。
/// 收敛到一处，避免闸门与操作日志对"什么算写"各写一套。
pub fn is_write_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "DELETE" | "PATCH"
    )
}

/// 解析 `sys.user.pwdExpireDays`：非数字 / ≤0 / 溢出 ⇒ 0（永不过期 = 现状）并 WARN。
///
/// 上限 3650（10 年）：把明显是误填的值（如把毫秒当秒）收敛掉，而不是让它把全员判过期。
pub fn parse_expire_days(raw: Option<&str>) -> i64 {
    let s = raw.unwrap_or("").trim();
    if s.is_empty() {
        return 0;
    }
    match s.parse::<i64>() {
        Ok(n) if (1..=3650).contains(&n) => n,
        Ok(0) => 0,
        Ok(n) => {
            tracing::warn!(
                key = PWD_EXPIRE_DAYS_CONFIG_KEY,
                value = n,
                "有效期天数越界（合法域 1..=3650），按 0=永不过期处理"
            );
            0
        }
        Err(_) => {
            tracing::warn!(
                key = PWD_EXPIRE_DAYS_CONFIG_KEY,
                value = s,
                "有效期天数不可解析，按 0=永不过期处理"
            );
            0
        }
    }
}

/// 口令是否已过期。
///
/// - `days <= 0` ⇒ `false`（策略关闭，**不**看时间戳）；
/// - `pwd_update_time == None` ⇒ `false`（无本地口令年龄：随机不可知口令的账号，见模块注释）；
/// - 否则 `now >= 设置时刻 + days*86400`（恰好等于该时刻视为已过期——"满 N 天"）。
pub fn password_expired(
    now: NaiveDateTime,
    pwd_update_time: Option<NaiveDateTime>,
    days: i64,
) -> bool {
    if days <= 0 {
        return false;
    }
    let Some(set_at) = pwd_update_time else {
        return false;
    };
    now.signed_duration_since(set_at).num_seconds() >= days * SECONDS_PER_DAY
}

/// 判定链的**唯一**入口：是否处于"必须改密"状态。
///
/// `force_enabled`（`sys.user.forceFirstLoginChangePwd`）是总闸：关闭时 `must_change_pwd`
/// 标志仍然下发给前端（既有行为），但**不**驱动闸门，也不因过期而触发——
/// 三层收敛里"平台开关"是天花板，闸门只是它的执行面。
///
/// 读配置失败必须传 `false`（调用方 fail-safe），本函数不接受 `Result`：
/// 让"取不到配置"在类型层面就只有一个解释（关闭态）。
pub fn must_change_password(
    force_enabled: bool,
    must_change_pwd: Option<&str>,
    now: NaiveDateTime,
    pwd_update_time: Option<NaiveDateTime>,
    days: i64,
) -> bool {
    if !force_enabled {
        return false;
    }
    must_change_pwd == Some("1") || password_expired(now, pwd_update_time, days)
}

/// 把 `must_change_password` 拆成两个可分别下发的原因位（前端文案要知道"为什么被拦"：
/// 初始口令未改 vs 口令过期，恢复动作不同）。
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct PwdChangeReason {
    pub initial_password_unused: bool,
    pub expired: bool,
}

impl PwdChangeReason {
    pub fn any(self) -> bool {
        self.initial_password_unused || self.expired
    }
}

pub fn classify(
    force_enabled: bool,
    must_change_pwd: Option<&str>,
    now: NaiveDateTime,
    pwd_update_time: Option<NaiveDateTime>,
    days: i64,
) -> PwdChangeReason {
    if !force_enabled {
        return PwdChangeReason::default();
    }
    PwdChangeReason {
        initial_password_unused: must_change_pwd == Some("1"),
        expired: password_expired(now, pwd_update_time, days),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(sec: i64) -> NaiveDateTime {
        chrono::DateTime::from_timestamp(sec, 0)
            .unwrap()
            .naive_utc()
    }

    /// 时间位移（避免 `NaiveDateTime::timestamp` 这类 deprecated 取数口——
    /// chrono 0.4 对 naive 与 utc 的边界收紧，判据只算差值，不做时区断言）
    fn shift(t: NaiveDateTime, secs: i64) -> NaiveDateTime {
        t + chrono::Duration::seconds(secs)
    }

    /// ① 策略关闭态与"无口令年龄"两条都必须判不过期（恒假分支各自成立，不得靠彼此蒙绿）
    #[test]
    fn expired_requires_both_policy_and_fact() {
        let now = at(1_000_000_000);
        let long_ago = shift(now, -400 * SECONDS_PER_DAY);
        assert!(
            !password_expired(now, Some(long_ago), 0),
            "days=0 必须不过期"
        );
        assert!(
            !password_expired(now, Some(long_ago), -1),
            "负数天数按关闭处理"
        );
        assert!(!password_expired(now, None, 90), "无口令年龄必须不过期");
        assert!(
            password_expired(now, Some(long_ago), 90),
            "对照组：有年龄且超期必须过期"
        );
    }

    /// ② 边界：恰好满 N 天判过期，差一秒不判（"满 N 天"语义必须钉死）
    #[test]
    fn expiry_boundary_is_inclusive() {
        let set_at = at(500_000_000);
        let exactly = shift(set_at, 90 * SECONDS_PER_DAY);
        let one_sec_before = shift(set_at, 90 * SECONDS_PER_DAY - 1);
        assert!(password_expired(exactly, Some(set_at), 90));
        assert!(!password_expired(one_sec_before, Some(set_at), 90));
    }

    /// ③ 档位开放度单调：对写方法与读方法，拦的集合必须随 rank 单调收缩
    #[test]
    fn gate_tiers_are_monotone_by_permissiveness() {
        let tiers = [
            PwdChangeGate::DenyAll,
            PwdChangeGate::DenyWrite,
            PwdChangeGate::Off,
        ];
        assert!(
            tiers.windows(2).all(|w| w[0].rank() < w[1].rank()),
            "档位声明顺序必须即开放度顺序"
        );
        for method in ["POST", "GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let blocks: Vec<bool> = tiers.iter().map(|t| t.blocks_method(method)).collect();
            for w in blocks.windows(2) {
                assert!(
                    !(!w[0] && w[1]),
                    "{method}：更松的档位不得拦得更多（单调性被破坏）"
                );
            }
        }
        // 具体形态：deny_all 拦读，deny_write 只拦写，off 全放
        assert!(PwdChangeGate::DenyAll.blocks_method("GET"));
        assert!(!PwdChangeGate::DenyWrite.blocks_method("GET"));
        assert!(PwdChangeGate::DenyWrite.blocks_method("POST"));
        assert!(!PwdChangeGate::Off.blocks_method("POST"));
    }

    /// ④ 非法档位回落 off 且**只有**已知值不告警（配错必须被看见）
    #[test]
    fn illegal_gate_value_falls_back_to_off() {
        for bad in ["DENY-ALL", "denyall", "server", "true", "  "] {
            let got = PwdChangeGate::parse(Some(bad));
            if bad == "  " {
                assert_eq!(got, PwdChangeGate::Off, "空白=缺省=off");
            } else {
                assert_eq!(got, PwdChangeGate::Off, "{bad} 不可解析必须回落 off");
            }
        }
        // 正控：大小写不敏感、已知值各自成立
        assert_eq!(
            PwdChangeGate::parse(Some("DENY_WRITE")),
            PwdChangeGate::DenyWrite
        );
        assert_eq!(PwdChangeGate::parse(Some("Off")), PwdChangeGate::Off);
        assert_eq!(PwdChangeGate::parse(None), PwdChangeGate::Off);
    }

    /// ⑤ 天数解析：越界与不可解析一律 0，且合法域边界 1 / 3650 必须放行
    #[test]
    fn expire_days_parsing_is_conservative() {
        assert_eq!(parse_expire_days(None), 0);
        assert_eq!(parse_expire_days(Some("")), 0);
        assert_eq!(parse_expire_days(Some("abc")), 0);
        assert_eq!(parse_expire_days(Some("-5")), 0);
        assert_eq!(parse_expire_days(Some("999999")), 0, "越界必须回落 0");
        assert_eq!(parse_expire_days(Some("1")), 1);
        assert_eq!(parse_expire_days(Some("3650")), 3650);
        assert_eq!(parse_expire_days(Some(" 90 ")), 90);
    }

    /// ⑥ 总闸 `force_enabled=false` 时，标志与过期两条通道都必须失效（平台开关是天花板），
    ///    且必须有对照组证明"打开后确实生效"——否则本条判据可以靠恒假蒙过
    #[test]
    fn force_switch_is_the_ceiling() {
        let now = at(1_000_000_000);
        let long_ago = Some(shift(now, -400 * SECONDS_PER_DAY));
        assert!(!must_change_password(false, Some("1"), now, long_ago, 90));
        assert!(
            must_change_password(true, Some("1"), now, None, 0),
            "标志通道"
        );
        assert!(
            must_change_password(true, Some("0"), now, long_ago, 90),
            "过期通道"
        );
        assert!(
            !must_change_password(true, Some("0"), now, None, 0),
            "两支都不成立⇒不改"
        );
        let r = classify(true, Some("1"), now, long_ago, 90);
        assert!(
            r.initial_password_unused && r.expired && r.any(),
            "两因可同时成立"
        );
        assert!(!classify(false, Some("1"), now, long_ago, 90).any());
    }

    /// ⑦ 写站点自证：新增"替换口令"的代码路径必须同时登记口令年龄，或有带理由的豁免。
    ///    这条锁的是本模块最贵的复发形态——某条改密路径不写 `pwd_update_time`，
    ///    于是那次改密对过期策略完全不可见（有效期形同虚设，且无人报红）。
    #[test]
    fn password_write_sites_must_record_pwd_age() {
        // EXEMPT：写了 password 但**不该**刷新口令年龄的路径，逐条带理由。
        // - upgrade_password_hash：MD5→Argon2 静默换哈希，用户口令没变 ⇒ 刷新等于把过期时钟归零；
        // - anonymize_user：口令被清空（None）而非替换，账号不再具备口令登录面；
        // - auto_create_and_bind / create_user：随机生成、**无人可知**的占位口令，记年龄会让
        //   IdP / 第三方托管账号在 `deny_*` 档下被锁在"无法自助解除"的闸门里
        //   （白名单里的 updatePwd 要求旧口令）。
        const EXEMPT: &[(&str, &str)] = &[
            (
                "upgrade_password_hash",
                "哈希算法升级，口令未变：刷新即抹掉口令年龄",
            ),
            ("anonymize_user", "口令置 None（匿名化），不是新口令"),
            ("auto_create_and_bind", "OAuth 自动建号：占位口令无人可知"),
            ("create_user", "SCIM 供给：随机口令只进哈希"),
        ];
        // 两种写法都要扫：`password: Set(..)`（结构体字面量）与 `password = Set(..)`（逐字段赋值）。
        // 只扫前者会把赋值式写法整族漏掉——那正是"扫不到却判干净"的假绿形态。
        const PATTERNS: [&str; 2] = ["password: Set(", "password = Set("];
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service");
        let mut sites = 0usize;
        let mut violations: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("src/service 必须存在") {
            let path = entry.expect("目录项").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let production = strip_tests(&std::fs::read_to_string(&path).expect("读源码"));
            let mut idxs: Vec<usize> = Vec::new();
            for pat in PATTERNS {
                idxs.extend(production.match_indices(pat).map(|(i, _)| i));
            }
            idxs.sort_unstable();
            for (rank, idx) in idxs.iter().enumerate() {
                sites += 1;
                let owner = nearest_fn(&production, *idx);
                if EXEMPT.iter().any(|(f, _)| *f == owner) {
                    continue;
                }
                // 窗口止于**相邻站点**：否则上一条路径里的 pwd_update_time 会把这一条洗白
                // （与 fail_closed_guard"扫描窗口止于下一个 spawn"同一条纪律）。
                let lo = if rank == 0 {
                    idx.saturating_sub(400)
                } else {
                    idxs[rank - 1].max(idx.saturating_sub(400))
                };
                let hi = idxs.get(rank + 1).copied().unwrap_or(production.len());
                let win = &production[lo.min(hi)..hi.max(lo).min(production.len())];
                if !win.contains("pwd_update_time") {
                    violations.push(format!(
                        "{}:{owner}",
                        path.file_name().unwrap().to_string_lossy()
                    ));
                }
            }
        }
        assert!(
            sites >= 8,
            "扫描面自证：口令写站点下限 8，实得 {sites}——扫不到就判不出任何东西"
        );
        assert!(
            violations.is_empty(),
            "未登记口令年龄的改密路径: {violations:?}"
        );
        // 反证一：豁免表里的函数名必须真的在源码里存在（防"为不存在的函数编豁免"→虚锁）
        for (f, _) in EXEMPT {
            assert!(
                owned_by_existing_fn(f),
                "豁免条目 {f} 已失配（函数改名或删除后条目必须一并撤销）"
            );
        }
        // 反证二：豁免条目不得是"没占任何真站点"的空位（那是给未来违规预留的口子）
        for (f, _) in EXEMPT {
            assert!(
                exempt_has_site(f),
                "豁免条目 {f} 已不含口令写站点，条目必须一并撤销"
            );
        }
    }

    /// ⑧ 活性正控：判据必须真的抓得住"漏登记"这一族。
    ///
    /// 只在内存里合成、不改真实文件的活性对照不足为证（本仓立过案：抓不住不等于会抓），
    /// 所以这里读真实文件做"摘掉一条登记"的替换，断言三件事：
    /// (a) 真实树确有 ≥2 处逐字段登记；(b) 替换确实改变了文本（刀口落在存在的代码上）；
    /// (c) 摘掉后该站点向前 400 字符窗口内不再含 `pwd_update_time`（⑦ 据同类窗口才点名）。
    /// 生产文件本身不被写入——变异只作用于内存副本，跑完即弃。
    #[test]
    fn write_site_lock_is_live_not_a_dead_shape() {
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/service/sys_user_service.rs");
        let text = std::fs::read_to_string(&file).expect("读源码");
        let needle = "am.pwd_update_time = Set(Some(crate::common::datetime::now_naive()));";
        let count = text.matches(needle).count();
        assert!(
            count >= 2,
            "真实树必须有 ≥2 处逐字段登记（个人改密 + 管理员重置），实得 {count}"
        );
        let mutated = text.replace(needle, "");
        assert_ne!(
            mutated, text,
            "合成违规必须先真改到源码，否则测的是自己的算术"
        );
        // 摘掉登记后，个人改密站点所在窗口必须不再含 pwd_update_time（判据据此才会点名）
        let anchor = mutated
            .find("am.must_change_pwd = Set(Some(\"0\".to_string()));")
            .expect("个人改密站点必须存在");
        let lo = anchor.saturating_sub(400);
        assert!(
            !mutated[lo..anchor].contains("pwd_update_time"),
            "窗口里还留着 pwd_update_time ⇒ 摘除没落到该站点，锁的活性未被证明"
        );
    }

    fn exempt_has_site(name: &str) -> bool {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service");
        for entry in std::fs::read_dir(dir).expect("src/service 必须存在") {
            let path = entry.expect("目录项").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let production = strip_tests(&std::fs::read_to_string(&path).expect("读源码"));
            for pat in ["password: Set(", "password = Set("] {
                for (idx, _) in production.match_indices(pat) {
                    if nearest_fn(&production, idx) == name {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn owned_by_existing_fn(name: &str) -> bool {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service");
        for entry in std::fs::read_dir(dir).expect("src/service 必须存在") {
            let path = entry.expect("目录项").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("读源码");
            if text.contains(&format!("fn {name}(")) {
                return true;
            }
        }
        false
    }

    /// 截除 `#[cfg(test)]` 之后的测试码（刀口取属性行，注释里的字面量不参与——
    /// 与 `common/prod_scan.rs::cut_at_test_attr` 同口径，本模块只取最简形态）
    fn strip_tests(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for line in text.split_inclusive('\n') {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg(test)]") {
                break;
            }
            out.push_str(line);
        }
        out
    }

    fn nearest_fn(text: &str, idx: usize) -> String {
        let head = &text[..idx.min(text.len())];
        head.rfind("fn ")
            .map(|p| {
                let rest = &head[p + 3..];
                let end = rest.find(['(', ' ']).unwrap_or(rest.len());
                rest[..end].to_string()
            })
            .unwrap_or_default()
    }
}
