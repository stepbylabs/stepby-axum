//! 软删行的唯一键策略（b128 单一事实源）。
//!
//! 背景：`del_flag` 只是应用层可见性，**唯一索引不看它**。一张表只要有
//! 「`del_flag` 列 + 非主键唯一索引」，删除就必然留下占坑行；若删除路径只改 `del_flag`，
//! 重建同名会撞索引（数据库唯一约束错误映射成 500/400），而管理端又看不到占用它的行
//! —— 使用者只能去改库，这是死路。
//!
//! 本表为全部 19 张表逐条登记处置方式，并由三条判据双向钉住：
//! ① 迁移后的真实库枚举出的表集合必须与登记表**逐条相等**（未登记必红；登记了但库里
//!    没有这种形态必红，否则登记表会变成永不失效的历史垃圾）；
//! ② 每条策略的锚点必须在**生产码**（`prod_scan` 口径：剔注释、剔 `#[cfg(test)]` 之后）
//!    里仍命中指定次数，少一处必红；
//! ③ 声明为 `NoDeletePath` 的表，全仓生产码不得出现该实体的 `::delete_many`。
//!
//! 新增一张「`del_flag` + 唯一索引」表时这条锁会立刻变红——先在 `POLICIES` 里给出处置
//! 方式与理由，再谈合并。

use std::collections::{BTreeMap, BTreeSet};

use crate::common::prod_scan::{self, Scan};

/// 单张表的处置方式。一张表可以同时命中多种（例如"改名释放 + 同属主复活"）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// 软删时把唯一键改名为 `common::soft_delete_key::freed_key` 的产物（释放占用）。
    Rename,
    /// 软删保留原值；同属主重建时复活软删行（唯一键被"复用"而不是"让位"）。
    Revive,
    /// 删除即物理删除（`delete_many`），不存在软删残留。
    Physical,
    /// 有意保留占用（必须有不释放的安全理由，且创建路径要给出友好拒绝而不是撞索引）。
    Block,
    /// 表上没有删除入口（只有查询/更新），因此不会产生占坑行。
    NoDeletePath,
}

/// 生产码里的落地证据：`file` 中必须至少出现 `min_count` 次 `needle`。
pub struct Anchor {
    pub file: &'static str,
    pub needle: &'static str,
    pub min_count: usize,
}

pub const fn anchor(file: &'static str, needle: &'static str) -> Anchor {
    Anchor {
        file,
        needle,
        min_count: 1,
    }
}

pub const fn anchor2(file: &'static str, needle: &'static str) -> Anchor {
    Anchor {
        file,
        needle,
        min_count: 2,
    }
}

pub struct Policy {
    pub table: &'static str,
    /// 实体类型名（`NoDeletePath` 的负向扫描按它找 `::delete_many`）。
    pub entity: &'static str,
    pub modes: &'static [Mode],
    /// 自足理由：为什么是这种处置（≥12 个字符，禁"同上"类跨条目指代）。
    pub why: &'static str,
    pub anchors: &'static [Anchor],
}

pub const POLICIES: &[Policy] = &[
    Policy {
        table: "sys_user",
        entity: "SysUser",
        modes: &[Mode::Rename],
        why: "删除时把 user_name 与 scim_external_id 一并改名为 `{原名}_deleted_{id}`，释放 uk_sys_user_name / uk_sys_user_tenant_scim；user_name 列宽仅 30，改名必须按字符截断，否则 MySQL 严格模式下删长用户名直接 1406 失败。GDPR 擦除路径另用 `deleted_{id}` 抹掉原值，那是隐私要求，刻意不回填原名。",
        anchors: &[
            anchor2(
                "src/service/sys_user_service.rs",
                "soft_delete_key::freed_key(&existing.user_name, user_id, 30)",
            ),
            anchor(
                "src/service/sys_user_service.rs",
                "am.scim_external_id = Set(Some(ext))",
            ),
            anchor(
                "src/service/user_erasure_service.rs",
                "anonymized_user_name(user_id)",
            ),
        ],
    },
    Policy {
        table: "sys_role",
        entity: "SysRole",
        modes: &[Mode::Rename],
        why: "删除时改名释放 uk_sys_role_tenant_key（tenant_id + role_key）。租户级联软删**不改名**：那是回收站语义，且 tenant_id 已经隔开了命名空间，改名会让 restore 无法原样恢复。",
        anchors: &[anchor2(
            "src/service/sys_role_service.rs",
            "soft_delete_key::freed_key(&existing.role_key, role_id, 100)",
        )],
    },
    Policy {
        table: "sys_dict_type",
        entity: "SysDictType",
        modes: &[Mode::Rename],
        why: "删除时改名释放 uk_sys_dict_type_tenant；同事务内级联软删字典项（sys_dict_data 没有唯一索引，不需要改名，删掉字典类型后它本来就查不到）。",
        anchors: &[anchor(
            "src/service/sys_dict_service.rs",
            "soft_delete_key::freed_key(dict_type, *dict_id, 100)",
        )],
    },
    Policy {
        table: "sys_job",
        entity: "SysJob",
        modes: &[Mode::Rename],
        why: "删除时改名释放 uk_sys_job_name_group（job_name + job_group）。任务运行不按名称回读定义，改名不影响调度语义。",
        anchors: &[anchor(
            "src/service/sys_job_service.rs",
            "soft_delete_key::freed_key(&job.job_name, *job_id, 64)",
        )],
    },
    Policy {
        table: "sys_post",
        entity: "SysPost",
        modes: &[Mode::Rename],
        why: "删除时改名释放 uk_sys_post_code。岗位编码只用于唯一标识与展示，软删行改名后不会与任何在册岗位冲突。",
        anchors: &[anchor(
            "src/service/sys_post_service.rs",
            "soft_delete_key::freed_key(&existing.post_code, *post_id, 64)",
        )],
    },
    Policy {
        table: "sys_msg_channel",
        entity: "SysMsgChannel",
        modes: &[Mode::Physical],
        why: "渠道删除是物理删除（delete_many）；被启用模板引用时先拒绝删除，因此不会产生软删占坑行。",
        anchors: &[anchor(
            "src/repository/sys_msg_channel.rs",
            "SysMsgChannel::delete_many()",
        )],
    },
    Policy {
        table: "sys_msg_template",
        entity: "SysMsgTemplate",
        modes: &[Mode::Physical],
        why: "模板删除是物理删除（delete_many）。发送记录只保存渠道与模板快照，不依赖模板行继续存在。",
        anchors: &[anchor(
            "src/repository/sys_msg_template.rs",
            "SysMsgTemplate::delete_many()",
        )],
    },
    Policy {
        table: "sys_report",
        entity: "SysReport",
        modes: &[Mode::Rename],
        why: "报表定义软删时改名释放**全局唯一**的 report_code（列宽 64），级联软删订阅在同一事务；不释放则删掉报表后再建同 code 报「已存在」而管理端看不到占用者。",
        anchors: &[anchor(
            "src/service/sys_report_service.rs",
            "soft_delete_key::freed_key(&r.report_code, r.report_id, 64)",
        )],
    },
    Policy {
        table: "sys_oauth_client",
        entity: "SysOauthClient",
        modes: &[Mode::Block],
        why: "刻意不释放：重建同名 client 会让新客户端继承旧用户的授权记录（静默授权）。创建路径用**含软删**的 exists_by_client_id 先探测并返回 400，所以不会撞唯一索引 500。",
        anchors: &[
            anchor(
                "src/repository/sys_oauth_client.rs",
                "pub async fn exists_by_client_id",
            ),
            anchor(
                "src/service/sso_service.rs",
                "self.client_repo.exists_by_client_id(cid)",
            ),
        ],
    },
    Policy {
        table: "sys_oauth_consent",
        entity: "SysOauthConsent",
        modes: &[Mode::Physical],
        why: "授权记录用物理删除（revoke / delete_by_client），不留软删行；建表时的 UNIQUE 约束与显式唯一索引重复，属冗余索引，无行为差异。",
        anchors: &[
            anchor(
                "src/repository/sys_oauth_consent.rs",
                "row.delete(self.base.db())",
            ),
            anchor(
                "src/repository/sys_oauth_consent.rs",
                "Entity::delete_many()",
            ),
        ],
    },
    Policy {
        table: "sys_scim_group",
        entity: "ScimGroup",
        modes: &[Mode::Rename],
        why: "组软删时把 external_id 改名释放 uk_scim_group_tenant_external（列宽 255）；IdP 删组后经常用同一个 externalId 重新下发，不释放则 create 恒 409「已存在」而该组在管理端又已不可见。",
        anchors: &[anchor(
            "src/service/scim_group_service.rs",
            "soft_delete_key::freed_key(ext, group_id, 255)",
        )],
    },
    Policy {
        table: "sys_tenant",
        entity: "SysTenant",
        modes: &[Mode::Rename, Mode::Revive],
        why: "租户删除是回收站语义：tenant_code 改名为 `{原名}_deleted_{id}` 释放 uk_sys_tenant_code；restore 用 split_freed_key 反解原名，并兼容 b128 之前写入的 `_del_{id}` 存量形态。",
        anchors: &[
            anchor(
                "src/service/sys_tenant_service.rs",
                "soft_delete_key::freed_key(",
            ),
            anchor("src/service/sys_tenant_service.rs", "split_freed_key(code)"),
        ],
    },
    Policy {
        table: "sys_tenant_package",
        entity: "TenantPackage",
        modes: &[Mode::NoDeletePath],
        why: "套餐只有查询与 features 写面，没有删除入口，因此不会产生占坑行；不登记为 Rename，避免让人以为存在一条可以释放的删除路径。",
        anchors: &[anchor(
            "src/service/sys_tenant_service.rs",
            "pub async fn package_options(",
        )],
    },
    Policy {
        table: "sys_tenant_domain",
        entity: "SysTenantDomain",
        modes: &[Mode::Rename, Mode::Revive],
        why: "手工删除域名即放弃，改名释放**全局唯一**的 domain（列宽 255），否则换租户重新绑定只能改库；同租户仍有软删行时走复活分支（覆盖回收站租户恢复前的历史行）。租户级联删域名刻意不改名——restore 会把域名一起恢复。",
        anchors: &[
            anchor(
                "src/service/sys_tenant_domain_service.rs",
                "soft_delete_key::freed_key(&model.domain, domain_id, 255)",
            ),
            anchor(
                "src/service/sys_tenant_domain_service.rs",
                "error.tenant.domain_taken_by_other_tenant",
            ),
        ],
    },
    Policy {
        table: "sys_tenant_menu",
        entity: "SysTenantMenu",
        modes: &[Mode::Revive],
        why: "租户自建菜单删除保留原名，重建同一 ref_menu_id 时复活软删行（find_revivable_ref），保证自定义的排序与命名不因一次删除丢失。",
        anchors: &[anchor(
            "src/repository/sys_tenant_menu.rs",
            "pub async fn find_revivable_ref",
        )],
    },
    Policy {
        table: "sys_user_credential",
        entity: "SysUserCredential",
        modes: &[Mode::Physical],
        why: "WebAuthn 凭据物理删除（delete_owned / delete_by_credential_id）；凭据 ID 由认证器产生，保留软删行会让同一凭据永远无法重新绑定。",
        anchors: &[anchor(
            "src/repository/sys_user_credential.rs",
            "SysUserCredential::delete_many()",
        )],
    },
    Policy {
        table: "flow_definition",
        entity: "FlowDefinition",
        modes: &[Mode::Rename],
        why: "流程定义软删时改名释放 uq_flow_def_code_ver（tenant_id + flow_code + version，列宽 64）；不释放则删光某个 code 后再建同名会撞唯一索引，报出来的还是一句通用「数据重复」。",
        anchors: &[anchor(
            "src/service/flow_definition_service.rs",
            "soft_delete_key::freed_key(&m.flow_code, fid, 64)",
        )],
    },
    Policy {
        table: "report_dataset",
        entity: "ReportDataset",
        modes: &[Mode::Rename],
        why: "数据集软删时改名释放 uq_report_dataset_code（列宽 64）；每行新值含主键，无法用一条批量 UPDATE，故在事务内逐行改名。",
        anchors: &[anchor2(
            "src/service/report_dataset_service.rs",
            "soft_delete_key::freed_key(code, *id, 64)",
        )],
    },
    Policy {
        table: "report_dashboard",
        entity: "ReportDashboard",
        modes: &[Mode::Rename],
        why: "大屏软删时改名释放 uq_report_dashboard_code（列宽 64）；与数据集在同一个服务文件里各有一处 freed_key，锚点用出现次数钉住两处都在。",
        anchors: &[anchor2(
            "src/service/report_dataset_service.rs",
            "soft_delete_key::freed_key(code, *id, 64)",
        )],
    },
];

/// 登记表里的表名集合（重复登记会在这里被折叠，由 `registry_gaps` 判红）。
pub fn registered_tables() -> BTreeSet<&'static str> {
    POLICIES.iter().map(|p| p.table).collect()
}

/// 登记表自身的形状缺口：重复表名、理由过短/带跨条目指代、理由复制粘贴。
pub fn registry_gaps(policies: &[Policy]) -> Vec<String> {
    let mut gaps = Vec::new();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    let mut why_seen: BTreeMap<&str, &str> = BTreeMap::new();
    for p in policies {
        *seen.entry(p.table).or_insert(0) += 1;
        let why = p.why.trim();
        if why.chars().count() < 12 {
            gaps.push(format!(
                "{}: 理由过短（{} 字符，至少 12）",
                p.table,
                why.chars().count()
            ));
        }
        if why.contains("同上") {
            gaps.push(format!("{}: 理由不得用「同上」跨条目指代", p.table));
        }
        if let Some(other) = why_seen.insert(why, p.table) {
            gaps.push(format!(
                "{}: 理由与 {other} 完全相同（复制粘贴等于没写）",
                p.table
            ));
        }
        if p.modes.is_empty() {
            gaps.push(format!("{}: 未声明任何处置方式", p.table));
        }
        if p.modes.contains(&Mode::Rename)
            && !p.anchors.iter().any(|a| a.needle.contains("freed_key"))
        {
            gaps.push(format!(
                "{}: 声明 Rename 但没有任何 freed_key 锚点",
                p.table
            ));
        }
        if p.modes.contains(&Mode::Physical)
            && !p.anchors.iter().any(|a| a.needle.contains("delete_many"))
        {
            gaps.push(format!(
                "{}: 声明 Physical 但没有任何 delete_many 锚点",
                p.table
            ));
        }
    }
    for (table, n) in seen {
        if n > 1 {
            gaps.push(format!("{table}: 重复登记 {n} 次"));
        }
    }
    gaps
}

/// 双向对账：`actual` 是迁移后真实库枚举出的「有 del_flag 且存在非主键唯一索引」的表。
pub fn schema_gaps(policies: &[Policy], actual: &BTreeSet<String>) -> Vec<String> {
    let registered = policies.iter().map(|p| p.table).collect::<BTreeSet<&str>>();
    let mut gaps = Vec::new();
    for table in actual {
        if !registered.contains(table.as_str()) {
            gaps.push(format!(
                "{table}: 库里有「del_flag + 唯一索引」但未登记处置方式（新增表必须先在 POLICIES 表态）"
            ));
        }
    }
    for table in &registered {
        if !actual.contains(*table) {
            gaps.push(format!(
                "{table}: 已登记，但迁移后的库里没有「del_flag + 唯一索引」这种形态 —— 撤销这条登记"
            ));
        }
    }
    gaps
}

/// 锚点比对用的归一化：去掉全部空白与逗号后比 token 序列。
///
/// 为什么不是逐字节：`cargo fmt` 会把长调用折成多行并补尾逗号，锚点若按原样比对，
/// 一次格式化就能让「落地证据」从 2 次变 1 次、1 次变 0 次（b128 实测三条锚点如此归零），
/// 而代码事实一字未改——判据红在排版上，读起来却像"改名逻辑被删了"。
/// 这与 AGENTS ⑰「生成物的陈旧性只能判语义，不能判字节」同形。
fn anchor_form(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != ',')
        .collect()
}

/// 锚点活性：每条锚点在**生产码**里必须命中指定次数（格式无关，见 [`anchor_form`]）。
pub fn anchor_gaps(policies: &[Policy]) -> Vec<String> {
    let cfg = Scan::default();
    let mut gaps = Vec::new();
    for p in policies {
        for a in p.anchors {
            let file = prod_scan::prod_file(a.file, &cfg);
            let hay = anchor_form(&file.text());
            let hits = hay.matches(&anchor_form(a.needle)).count();
            if hits < a.min_count {
                gaps.push(format!(
                    "{}: 锚点在 {} 里命中 {hits} 次，少于 {} 次 —— 落地证据已消失（needle: {}）",
                    p.table, a.file, a.min_count, a.needle
                ));
            }
        }
    }
    gaps
}

/// `NoDeletePath` 的负向判据：该实体的删除调用在生产码里必须 0 处。
pub fn no_delete_path_gaps(policies: &[Policy]) -> Vec<String> {
    let cfg = Scan {
        exclude: &["src/common/soft_delete_policy.rs"],
        ..Default::default()
    };
    let files = prod_scan::prod_files(&cfg);
    let mut gaps = Vec::new();
    for p in policies
        .iter()
        .filter(|p| p.modes.contains(&Mode::NoDeletePath))
    {
        let needle = format!("{}::delete_many", p.entity);
        for f in &files {
            if f.text().contains(&needle) {
                gaps.push(format!(
                    "{}: 声明 NoDeletePath 但生产码 {} 出现了 {needle}",
                    p.table, f.rel
                ));
            }
        }
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};

    /// 迁移后的真实库：枚举「有 del_flag 列 + 非主键唯一索引」的表。
    async fn actual_tables(db: &DatabaseConnection) -> BTreeSet<String> {
        let rows = db
            .query_all_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type='table' \
                 AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'seaql_%'",
            ))
            .await
            .expect("枚举表失败");
        let tables: Vec<String> = rows
            .iter()
            .map(|r| r.try_get::<String>("", "name").expect("表名"))
            .collect();
        let mut out = BTreeSet::new();
        for t in tables {
            let cols = db
                .query_all_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("PRAGMA table_info(\"{t}\")"),
                ))
                .await
                .expect("PRAGMA table_info 失败");
            let has_del_flag = cols.iter().any(|c| {
                c.try_get::<String>("", "name")
                    .is_ok_and(|n| n == "del_flag")
            });
            if !has_del_flag {
                continue;
            }
            let idx = db
                .query_all_raw(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    format!("PRAGMA index_list(\"{t}\")"),
                ))
                .await
                .expect("PRAGMA index_list 失败");
            let has_unique = idx.iter().any(|i| {
                let unique = i.try_get::<i64>("", "unique").unwrap_or(0) == 1;
                let origin = i
                    .try_get::<String>("", "origin")
                    .unwrap_or_else(|_| "c".to_string());
                unique && origin != "pk"
            });
            if has_unique {
                out.insert(t);
            }
        }
        out
    }

    #[test]
    fn registry_is_well_formed() {
        let gaps = registry_gaps(POLICIES);
        assert!(gaps.is_empty(), "登记表形状缺口: {gaps:#?}");
        // 采集面自证：条数与表集合都由登记表自己给，但必须有量级地板，
        // 否则"登记表被删空"会以"0 个缺口"通过。
        assert!(
            POLICIES.len() >= 19,
            "登记表只剩 {} 条（地板 19）——b128 实测 19 张表",
            POLICIES.len()
        );
        assert_eq!(registered_tables().len(), POLICIES.len(), "表名重复");
    }

    #[tokio::test]
    async fn policies_match_migrated_schema() {
        let db = crate::repository::test_support::migrated_db()
            .await
            .expect("迁移库创建失败");
        let actual = actual_tables(&db).await;
        assert!(
            actual.len() >= 19,
            "迁移库里只扫到 {} 张「del_flag + 唯一索引」表（地板 19）——枚举逻辑腐化，\
             不得当作「登记表全对」",
            actual.len()
        );
        let gaps = schema_gaps(POLICIES, &actual);
        assert!(gaps.is_empty(), "登记表 ↔ 真实库不一致: {gaps:#?}");
    }

    #[test]
    fn anchors_are_live_in_production_code() {
        let gaps = anchor_gaps(POLICIES);
        assert!(gaps.is_empty(), "锚点活性缺口: {gaps:#?}");
        // 正向对照：真实的 freed_key 调用必须能被数到，否则本函数可能整体空转
        let cfg = Scan::default();
        let file = prod_scan::prod_file("src/service/sys_user_service.rs", &cfg);
        assert!(
            file.text().contains("freed_key("),
            "正向对照失败：sys_user_service 的生产码里应出现 freed_key("
        );
        // 真实文件上的格式无关对照（b128 实证形状）：sys_job 的改名调用被 rustfmt 折成四行，
        // 与 needle 的书写形态不同却必须算命中——否则再格式化一次，这条证据就会被读成"已消失"。
        let job = prod_scan::prod_file("src/service/sys_job_service.rs", &cfg);
        let wrapped = anchor_form("soft_delete_key::freed_key(&job.job_name, *job_id, 64)");
        assert!(
            anchor_form(&job.text()).contains(&wrapped),
            "格式无关比对失效：折行后的 freed_key 调用必须仍被识别"
        );
        assert!(
            !anchor_form(&job.text())
                .contains(&anchor_form("freed_key(&job.job_name, *job_id, 65)")),
            "反证失败：改掉列宽参数（64 → 65）后必须不再命中，否则归一化把判据放宽成了通配"
        );
    }

    #[test]
    fn no_delete_path_tables_have_no_delete_calls() {
        let gaps = no_delete_path_gaps(POLICIES);
        assert!(gaps.is_empty(), "NoDeletePath 负向缺口: {gaps:#?}");
    }

    // ---- 合成双向：每条腿都必须能单独转红 ----

    const RENAME: &[Mode] = &[Mode::Rename];
    const PHYSICAL: &[Mode] = &[Mode::Physical];
    const NO_MODES: &[Mode] = &[];
    const NO_DELETE_PATH: &[Mode] = &[Mode::NoDeletePath];
    const A_FREED: &[Anchor] = &[anchor("src/main.rs", "freed_key")];
    const A_NONE: &[Anchor] = &[];

    fn policy(table: &'static str, modes: &'static [Mode], anchors: &'static [Anchor]) -> Policy {
        Policy {
            table,
            entity: "SysMsgChannel",
            modes,
            why: "合成夹具：这是一条足够长的自足理由",
            anchors,
        }
    }

    #[test]
    fn schema_gaps_catch_both_directions() {
        let policies = vec![
            policy("t_known", RENAME, A_NONE),
            policy("t_stale", RENAME, A_NONE),
        ];
        let actual: BTreeSet<String> = ["t_known".to_string(), "t_new".to_string()]
            .into_iter()
            .collect();
        let gaps = schema_gaps(&policies, &actual);
        assert!(
            gaps.iter()
                .any(|g| g.contains("t_new") && g.contains("未登记")),
            "未登记的新表必须点名：{gaps:#?}"
        );
        assert!(
            gaps.iter()
                .any(|g| g.contains("t_stale") && g.contains("撤销")),
            "库里没有的形态必须报撤销：{gaps:#?}"
        );
        assert_eq!(gaps.len(), 2, "两个方向各报一条，不得连带：{gaps:#?}");
        // 完全一致的集合必须 0 缺口
        let exact: BTreeSet<String> = ["t_known".to_string(), "t_stale".to_string()]
            .into_iter()
            .collect();
        assert!(schema_gaps(&policies, &exact).is_empty());
    }

    #[test]
    fn registry_gaps_catch_bad_reasons_and_modes() {
        let mut short_why = policy("t_a", RENAME, A_FREED);
        short_why.why = "太短";
        let dup_a = policy("t_b", RENAME, A_FREED);
        let dup_b = policy("t_c", RENAME, A_FREED);
        let no_anchor = policy("t_d", RENAME, A_NONE);
        let no_physical = policy("t_e", PHYSICAL, A_NONE);
        let empty_modes = policy("t_f", NO_MODES, A_NONE);
        let gaps = registry_gaps(&[short_why, dup_a, dup_b, no_anchor, no_physical, empty_modes]);
        let text = gaps.join("\n");
        assert!(text.contains("理由过短"), "{text}");
        assert!(text.contains("完全相同"), "{text}");
        assert!(text.contains("t_d") && text.contains("freed_key"), "{text}");
        assert!(
            text.contains("t_e") && text.contains("delete_many"),
            "{text}"
        );
        assert!(text.contains("t_f") && text.contains("未声明"), "{text}");
    }

    #[test]
    fn anchor_gaps_and_no_delete_path_are_falsifiable() {
        // 锚点腿：指向真实存在但 needle 不存在 ⇒ 必红
        const A_BAD: &[Anchor] = &[anchor(
            "src/service/sys_user_service.rs",
            "freed_key(this_is_not_real",
        )];
        let bad_anchor = policy("t_anchor", RENAME, A_BAD);
        let gaps = anchor_gaps(&[bad_anchor]);
        assert_eq!(gaps.len(), 1, "{gaps:#?}");
        assert!(gaps[0].contains("命中 0 次"), "{gaps:#?}");

        // 负向腿：把一个**真实有 delete_many 调用**的实体声明成 NoDeletePath ⇒ 必红；
        // 这正是"永远扫描不到"与"扫描了且干净"可区分的地方。
        let fake = Policy {
            table: "t_neg",
            entity: "SysMsgChannel",
            modes: NO_DELETE_PATH,
            why: "合成夹具：用真实存在删除调用的实体反证负向判据不是恒绿",
            anchors: &[],
        };
        let gaps = no_delete_path_gaps(&[fake]);
        assert!(
            gaps.iter()
                .any(|g| g.contains("SysMsgChannel::delete_many")),
            "负向判据必须能抓到真实删除调用：{gaps:#?}"
        );
        // 真正没有删除入口的实体必须 0 缺口
        let clean = Policy {
            table: "t_clean",
            entity: "TenantPackage",
            modes: NO_DELETE_PATH,
            why: "合成夹具：套餐实体在生产码里确实没有删除调用",
            anchors: &[],
        };
        assert!(no_delete_path_gaps(&[clean]).is_empty());
    }
}
