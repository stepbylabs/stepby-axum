// stepby-axum/src/integration_tests/migration_registry.rs
//! 迁移登记一致性总锁（批七十六新增）
//!
//! 为什么要有它：`migration/src/lib.rs` 的注释里就写着一次真实事故——
//! `m20260806_000001_add_log_time_indexes` **文件写了、忘了登记**，索引从未生效。
//! 漏登记不报错、不告警，只在很久以后表现为"某个索引不存在"。同理，
//! `migrations/mod.rs` 少一行 `pub mod` 照样编译通过（无人引用的模块不是错误），
//! 而 `lib.rs` 的 Vec 少一行 `Box::new` 同样静默——迁移文件存在但永远不跑。
//!
//! 三条判据（均为机械比对，不做人工清单）：
//! 1. `migrations/*.rs` 文件集合 == `mod.rs` 的 `pub mod` 集合 == `lib.rs` 的
//!    `Box::new(<mod>::Migration)` 集合；
//! 2. 两处登记顺序都严格字典序（= 里程碑时间序，防止把新迁移插到中间，
//!    导致存量库判定为"已应用"而跳过）；
//! 3. 每个迁移文件里显式 `fn name()` 返回的字符串必须等于文件名 stem
//!    （`seaql_migrations` 按名字判定"已应用"；名字≠文件名时，2026-09-30 的
//!    目录重组会让存量库把它当成从未应用）。
//!
//! 第四条（批七十六 R-10，由本仓**第一次**全量回滚实测照出来的）：每条迁移都必须
//! 自己实现 `async fn down(`。`MigrationTrait::down` 的默认实现返回
//! `Err(Migration("We Don't Do That Here"))`，漏写既不编译报错也不影响前向迁移；
//! 实测 121 条里有 1 条（`m20260806_000002_add_task_operator_id`）漏写，
//! `cargo run -p migration --down` 跑到它时已经回滚掉 87 条、库停在半路——
//! 那正是最坏的回滚形态（回滚本身变成一次半成品变更）。
//!
//! 解析口径：逐行匹配并**跳过 `//` 注释行**——`lib.rs` 的文件头说明里就有一句
//! ``追加 `Box::new(<mod名>::Migration)` ``，不按行+注释过滤会把散文当成登记项
//! （实测会把本锁判成"Vec 里多了一个叫 `<mod名>` 的迁移"）。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn axum_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(p: &Path) -> String {
    // 读不到即硬失败：校验没跑不得当成通过
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("读取 {:?} 失败: {e}", p))
}

/// 迁移名合法形状：`m<8 位日期>_<6 位序号>_<slug>`，slug 只含小写字母/数字/下划线。
fn is_migration_ident(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 17 || b[0] != b'm' || b[1..9].iter().any(|c| !c.is_ascii_digit()) {
        return false;
    }
    if b[9] != b'_' || b[10..16].iter().any(|c| !c.is_ascii_digit()) {
        return false;
    }
    b[16] == b'_'
        && b[17..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// 逐行提取 `prefix … suffix` 的登记名；跳过注释行；只接受合法迁移名。
fn registry_names(src: &str, prefix: &str, suffix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
        let Some(p) = line.find(prefix) else { continue };
        let rest = &line[p + prefix.len()..];
        let Some(e) = rest.find(suffix) else { continue };
        let name = rest[..e].trim();
        if is_migration_ident(name) {
            out.push(name.to_string());
        } else {
            panic!("登记项名不合法（{name:?}）来自行: {}", line.trim());
        }
    }
    out
}

#[test]
fn test_migration_registry_is_complete_and_ordered() {
    let root = axum_dir();
    let mig_dir = root.join("migration/src/migrations");
    let mod_src = read(&mig_dir.join("mod.rs"));
    let lib_src = read(&root.join("migration/src/lib.rs"));

    // ① 文件集合
    let mut files = BTreeSet::new();
    let entries = std::fs::read_dir(&mig_dir)
        .unwrap_or_else(|e| panic!("读取迁移目录 {:?} 失败: {e}", mig_dir));
    for e in entries {
        let e = e.expect("read_dir 条目");
        let fname = e.file_name().to_string_lossy().to_string();
        if let Some(stem) = fname.strip_suffix(".rs")
            && stem != "mod"
        {
            assert!(
                is_migration_ident(stem),
                "迁移文件名不符合 m<yyyymmdd>_<seq>_<slug>.rs 规范: {fname}"
            );
            files.insert(stem.to_string());
        }
    }
    let pub_mods: BTreeSet<String> = registry_names(&mod_src, "pub mod ", ";")
        .into_iter()
        .collect();
    let boxed_list = registry_names(&lib_src, "Box::new(", "::Migration)");
    let boxed: BTreeSet<String> = boxed_list.iter().cloned().collect();

    assert!(
        files.len() > 100,
        "迁移文件仅识别到 {} 个，扫描逻辑疑似失效（当前应 120 上下）",
        files.len()
    );
    assert_eq!(
        boxed_list.len(),
        boxed.len(),
        "Migrator Vec 里有重复登记（同一迁移两次 ⇒ seaql 会重复应用或报错）"
    );
    let not_declared: Vec<_> = files.difference(&pub_mods).cloned().collect();
    let declared_but_missing: Vec<_> = pub_mods.difference(&files).cloned().collect();
    let not_registered: Vec<_> = pub_mods.difference(&boxed).cloned().collect();
    let registered_but_undeclared: Vec<_> = boxed.difference(&pub_mods).cloned().collect();
    assert!(
        not_declared.is_empty()
            && declared_but_missing.is_empty()
            && not_registered.is_empty()
            && registered_but_undeclared.is_empty(),
        "迁移登记三处不一致：\n  有文件未 pub mod: {not_declared:?}\n  \
         pub mod 无文件: {declared_but_missing:?}\n  \
         pub mod 未进 Migrator Vec: {not_registered:?}\n  \
         Vec 引用了未声明模块: {registered_but_undeclared:?}"
    );

    // ② 顺序：两处登记都必须严格字典序（新迁移只能追加在末尾）
    let mod_order = registry_names(&mod_src, "pub mod ", ";");
    let mut sorted = mod_order.clone();
    sorted.sort();
    assert_eq!(
        mod_order, sorted,
        "migrations/mod.rs 的 pub mod 顺序非字典序（时间序）"
    );
    let mut sorted_lib = boxed_list.clone();
    sorted_lib.sort();
    assert_eq!(
        boxed_list, sorted_lib,
        "lib.rs 的 Box::new 顺序非字典序（新迁移须追加在 Vec 末尾）"
    );
}

#[test]
fn test_migration_name_matches_file_stem() {
    let mig_dir = axum_dir().join("migration/src/migrations");
    let entries = std::fs::read_dir(&mig_dir)
        .unwrap_or_else(|e| panic!("读取迁移目录 {:?} 失败: {e}", mig_dir));
    let mut explicit = 0usize;
    let mut derived = 0usize;
    let mut offenders = Vec::new();
    for e in entries {
        let e = e.expect("read_dir 条目");
        let fname = e.file_name().to_string_lossy().to_string();
        let Some(stem) = fname.strip_suffix(".rs") else {
            continue;
        };
        if stem == "mod" {
            continue;
        }
        let src = read(&e.path());
        match src.find("fn name(&self) -> &str") {
            Some(pos) => {
                explicit += 1;
                let rest = &src[pos..];
                let Some(q1) = rest.find('"') else {
                    offenders.push((stem.to_string(), "<显式 name() 找不到字符串>".to_string()));
                    continue;
                };
                let after = &rest[q1 + 1..];
                let Some(q2) = after.find('"') else {
                    offenders.push((stem.to_string(), "<字符串未闭合>".to_string()));
                    continue;
                };
                let literal = &after[..q2];
                if literal != stem {
                    offenders.push((stem.to_string(), literal.to_string()));
                }
            }
            None => {
                assert!(
                    src.contains("DeriveMigrationName"),
                    "迁移 {stem} 既无 `#[derive(DeriveMigrationName)]` 也无显式 fn name()：\
                     无法确定 seaql 记录名"
                );
                derived += 1;
            }
        }
    }
    assert!(
        explicit > 50,
        "只解析到 {explicit} 个显式 name()，解析疑似失效"
    );
    assert!(
        derived > 0,
        "derive 形态一个都没识别到：第二条路径未被覆盖（缺对照组，锁可能是恒假）"
    );
    assert!(
        offenders.is_empty(),
        "以下迁移的 name() 与文件名不一致（存量库会错判已应用状态）: {offenders:?}"
    );
}

/// 恒真防护：解析器必须"抓得到"真实故障形态，否则本锁只是摆设。
/// 判断一条迁移源码是否**实现**了 `down()`（行首形态，注释里的散文不算）。
///
/// `MigrationTrait::down` 有默认实现，返回 `Err(DbErr::Migration("We Don't Do That Here"))`：
/// 漏写 `down()` 既不报错也不影响 `up`，只在真正回滚的那天才暴露——所以必须静态钉住。
fn down_impl_present(src: &str) -> bool {
    src.lines()
        .any(|l| l.trim_start().starts_with("async fn down("))
}

#[test]
fn test_every_migration_implements_down() {
    let mig_dir = axum_dir().join("migration/src/migrations");
    let entries = std::fs::read_dir(&mig_dir)
        .unwrap_or_else(|e| panic!("读取迁移目录 {:?} 失败: {e}", mig_dir));
    let mut checked = 0usize;
    let mut missing = Vec::new();
    for e in entries {
        let e = e.expect("read_dir 条目");
        let fname = e.file_name().to_string_lossy().to_string();
        let Some(stem) = fname.strip_suffix(".rs") else {
            continue;
        };
        if stem == "mod" || !is_migration_ident(stem) {
            continue;
        }
        checked += 1;
        if !down_impl_present(&read(&e.path())) {
            missing.push(stem.to_string());
        }
    }
    // 读不到任何迁移文件时本锁会"全绿"，那正是虚锁——必须核对条数与注册表同源
    assert!(
        checked >= 100,
        "只检查了 {checked} 条迁移的可回滚性，与迁移总数不符（目录读空？判红）"
    );
    assert!(
        missing.is_empty(),
        "以下迁移没有 async fn down() 实现，回滚链会在它们身上中断: {missing:?}\
         （补 down()：结构类用 DROP/ALTER 逆操作并按方言守卫；数据类至少写 Ok(()) + 为何不可逆）"
    );
}

#[test]
fn test_migration_registry_lock_is_not_vacuous() {
    // ① 注释行不得被当成登记项（lib.rs 文件头就有一句散文里带 Box::new(<mod名>::Migration)）
    let with_prose = "//! 3. 追加 `Box::new(<mod名>::Migration)`；\n\
                      Box::new(m20261018_000001_flow_action_dict::Migration),\n";
    let names = registry_names(with_prose, "Box::new(", "::Migration)");
    assert_eq!(
        names,
        vec!["m20261018_000001_flow_action_dict".to_string()],
        "散文行混进了登记项（或真登记项被漏掉）"
    );

    // ② 漏登记这一真实故障必须能被集合差集抓到
    let files: BTreeSet<String> = ["m20261018_000001_flow_action_dict"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let declared: BTreeSet<String> = BTreeSet::new();
    assert_eq!(
        files.difference(&declared).count(),
        1,
        "漏登记未被抓到 ⇒ 总锁恒真"
    );

    // ③ 非法名必须硬失败而不是被静默忽略（否则改名/写错会洗绿）
    assert!(!is_migration_ident("mod"));
    assert!(!is_migration_ident("m2026_1_flow"));
    assert!(!is_migration_ident("m20261018_000001_FlowBad"));
    assert!(is_migration_ident("m20261018_000001_flow_action_dict"));
    assert!(
        std::panic::catch_unwind(|| registry_names("pub mod notAName;\n", "pub mod ", ";"))
            .is_err()
    );

    // ④ `down()` 存在性判据必须真能区分"写了"与"只在注释里提到"（否则 R-10 锁恒真）
    let with_down = "// 说明\n#[async_trait]\nimpl MigrationTrait for Migration {\n    async fn down(&self, _m: &SchemaManager) -> Result<(), DbErr> {\n        Ok(())\n    }\n}\n";
    assert!(down_impl_present(with_down), "实现了 down() 却被判为缺失 ⇒ 判据恒假");
    let prose_only = "// async fn down(&self) 未实现\n//! `async fn down(` 见上\n";
    assert!(
        !down_impl_present(prose_only),
        "注释里的散文被当成实现 ⇒ 判据恒真（漏写 down() 将再次静默）"
    );
    assert!(
        !down_impl_present("impl MigrationTrait for Migration { async fn up(&self) {} }"),
        "只有 up() 的文件必须判为缺 down()"
    );
}
