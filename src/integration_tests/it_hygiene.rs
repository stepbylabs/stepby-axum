// stepby-axum/src/integration_tests/it_hygiene.rs
//! 隔离测试库的**卫生锁**（b88 立项）。
//!
//! 起因是一条实测事故：门禁整跑的一轮里 5 条集成用例同时红——三条在共用的登录辅助里
//! 报「login 业务码应为 200，实际 `用户名或密码错误`」，一条报
//! `UNIQUE constraint failed: sys_tenant_package.package_id`，一条断言"租户 A 只能看到本租户 1 条"
//! 却数到 2 条；`-j 2` 复跑这 5 条全绿、整跑复跑也全绿。三条线索合起来只有一种解释：
//! **这一轮的用例读到了上一轮的库**。
//!
//! 取证到代码（改造前，`git show HEAD:src/integration_tests/mod.rs`）：
//! 1. `unique_temp_db_path` 只**拼**一个 `stepby_it_{pid}_{seq}.db` 名字、从不碰磁盘，而连接串是
//!    `sqlite://…?mode=rwc`——**存在即原样打开**；Windows 会回收 pid ⇒ 跨轮撞名就是撞库；
//! 2. 全仓**没有任何删除通道**（`git show HEAD:src/integration_tests/mod.rs | grep -c remove_file` = **0**），
//!    而它的注释写着"不残留旧 schema/数据"；`repository::test_support` 更写着"用完即随临时目录清理"
//!    ——Windows 不会自己清 `%TEMP%` 里应用创建的文件。**注释与事实相反**（与 b85 那条 totp 同族）。
//!    实测遗留：`stepby_it_` **66,515 个 / 66.84 GB** + `stepby_repo_test_` **10,499 个 / 11.15 GB**。
//!    磁盘压力不是抽象风险：同一台机器上 `libtest` 178.5s → 360.75s、
//!    `action-inventory` 最慢一页 3.4s → 12.2s（都由轮内自证）。
//!
//! 本模块钉五件事（每件都有"必须被抓"与"必须放行"两侧）：
//! ① 唯一性必须由磁盘作证（`create_new`）；② 已存在的文件**绝不复用**，也不得被写入一个字节；
//! ③ 回收只碰"够旧的本族文件"，时刻取不到就不动，**族外文件与 Redis 槽位锁永不动**；
//! ④ 刚创建的库不得被回收器删掉；⑤ 两个家族**都**真的接在认领通道上（写了没接线=没写）。

use super::{TEMP_DB_COUNTER, unique_temp_db_path};
use crate::repository::test_support::{
    HARNESS_DB_FAMILIES, HARNESS_DB_STALE_SECS, HARNESS_DB_SUFFIXES, IT_DB_PREFIX, REPO_DB_PREFIX,
    claim_harness_db_path, is_stale_harness_file, sweep_stale_harness_dbs,
};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::Ordering;

/// 私有目录名的前缀：与 `IT_DB_PREFIX` **刻意不同**且不带 `.db` 后缀，
/// 于是回收器按后缀白名单不认它（用例结束时自己删）。
const PROBE_DIR_PREFIX: &str = "stepby_hygiene_probe_";

fn write_file_with_content(path: &Path, content: &[u8]) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap_or_else(|e| panic!("夹具创建失败 {}：{e}", path.display()));
    f.write_all(content).expect("夹具写入失败");
}

/// 把文件的修改时间推到过去（夹具用；回收判据只看 mtime）。
/// 抬 5 秒再减，避免"恰好等于阈值"的边界抖动把用例变成时序赌局。
fn age_file(path: &Path, secs_ago: u64) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap_or_else(|e| panic!("夹具打开失败 {}：{e}", path.display()));
    let t = std::time::SystemTime::now() - std::time::Duration::from_secs(secs_ago)
        + std::time::Duration::from_secs(5);
    file.set_times(std::fs::FileTimes::new().set_modified(t))
        .unwrap_or_else(|e| panic!("夹具改时间失败 {}：{e}", path.display()));
}

fn it_name(seq: &str) -> String {
    format!("{IT_DB_PREFIX}{seq}.db")
}

/// 数一遍目录里"本族且 sqlite 产物后缀"的文件与字节（**只用于打印证据，不进任何断言**）。
///
/// 为什么不把"本轮删了多少"写成判据：那会把结论和**机器上的历史轮次**绑在一起
/// （干净机器上第一次跑删 0 个，绿；同一份代码第二次跑删 6 万，也绿——两次的"绿"含义不同，
/// 于是这条数只能当证据看，不能当闸）。而"够旧的必须删、新的与族外的必须留"才是判据（下面逐条判）。
fn family_footprint(dir: &std::path::Path) -> (u64, u64) {
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !HARNESS_DB_FAMILIES.iter().any(|f| name.starts_with(f))
            || !HARNESS_DB_SUFFIXES.iter().any(|s| name.ends_with(s))
        {
            continue;
        }
        if let Ok(m) = entry.metadata() {
            files += 1;
            bytes += m.len();
        }
    }
    (files, bytes)
}

#[test]
fn stale_predicate_is_bidirectional() {
    let old = HARNESS_DB_STALE_SECS + 60;
    let must: Vec<(&str, String, Option<u64>)> = vec![
        ("集成族主文件", it_name("1_2"), Some(old)),
        ("集成族 WAL 边车", "stepby_it_1_2.db-wal".into(), Some(old)),
        ("集成族 SHM 边车", "stepby_it_1_2.db-shm".into(), Some(old)),
        // 第二个家族：`test_support::migrated_db()` 的库同样只产不删（10,499 个 / 11.15 GB）。
        (
            "repo 族主文件",
            "stepby_repo_test_1_2_3.db".into(),
            Some(old),
        ),
    ];
    let must_not: Vec<(&str, String, Option<u64>)> = vec![
        ("族外名字（别人的库）", "other_1_2.db".into(), Some(old)),
        ("本族前缀但无关后缀", "stepby_it_1_2.log".into(), Some(old)),
        (
            "Redis 槽位锁文件（同前缀，但它就是独占机制本身）",
            "stepby_it_redis_db_7.lock".into(),
            Some(old),
        ),
        ("还年轻", it_name("1_2"), Some(10)),
        (
            "恰好等于阈值（不得四舍五入成'够旧'）",
            it_name("1_2"),
            Some(HARNESS_DB_STALE_SECS),
        ),
        ("mtime 取不到 ⇒ 宁可留也不能删", it_name("1_2"), None),
    ];
    for (desc, name, age) in &must {
        println!("  {desc}({name}) ⇒ 回收");
        assert!(is_stale_harness_file(name, *age), "该回收的没回收：{desc}");
    }
    for (desc, name, age) in &must_not {
        assert!(
            !is_stale_harness_file(name, *age),
            "不该回收的被回收了：{desc}（{name}）"
        );
    }
    assert_eq!(
        HARNESS_DB_FAMILIES,
        &[IT_DB_PREFIX, REPO_DB_PREFIX],
        "回收作用面必须恰好是这两个家族（加家族要改这里，删家族也一样）"
    );
    println!(
        "SYNTH_OK 回收判据 {} 条双向（{} 必须回收 / {} 必须不动）+ 家族集合自证，家族 {:?}",
        must.len() + must_not.len(),
        must.len(),
        must_not.len(),
        HARNESS_DB_FAMILIES
    );
}

/// 合成侧：在**私有目录**里确定性地复现"序号已被占用"这一支，两个家族各来一遍。
///
/// 为什么不能只测 `unique_temp_db_path`：进程内计数器单调递增，同进程永远拿不到一个
/// 已存在的序号 ⇒ "已存在必须跳过"这条真实缺陷形状在本进程里结构上打不中，用例就成了恒真
/// （AGENTS 前言 ⑥）。所以认领动作可注入目录与序号，由用例把同一个序号用两次。
#[test]
fn claim_skips_existing_file_and_leaves_its_bytes() {
    let dir = std::env::temp_dir().join(format!("{PROBE_DIR_PREFIX}{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("私有目录建不出来：{e}"));
    for family in HARNESS_DB_FAMILIES {
        let first = claim_harness_db_path(family, 7, &dir).expect("空目录里的序号 7 必须认领成功");
        assert_eq!(
            first.file_name().unwrap().to_string_lossy(),
            format!("{family}{}_7.db", std::process::id())
        );
        assert_eq!(
            std::fs::metadata(&first).expect("认领即创建").len(),
            0,
            "{family}：认领出来的必须是刚创建的空文件"
        );
        // 把它"留给下一轮"：写入哨兵字节，模拟上一轮的库（旧种子 / 被改过的口令 / 残留行）。
        write_file_with_content(&first, b"SENTINEL-FROM-PREV-RUN");

        // 缺陷形状就在这里：改造前按 mode=rwc 会把这个文件当成本轮新库打开（并接着写）。
        let again = claim_harness_db_path(family, 7, &dir);
        assert!(
            again.is_none(),
            "{family}：已存在的序号被当成可复用的隔离库 ⇒ 这一轮读的是上一轮的库"
        );
        let kept = std::fs::read(&first).expect("哨兵文件必须还在");
        assert_eq!(
            &kept[..],
            b"SENTINEL-FROM-PREV-RUN",
            "{family}：哨兵内容被改动 ⇒ 有人往已存在的文件里写过东西（复用没被关掉）"
        );

        let second = claim_harness_db_path(family, 8, &dir).expect("下一个序号必须能认领");
        assert_ne!(second, first, "{family}：两个序号必须是两个文件");
        assert_eq!(
            std::fs::metadata(&second).expect("认领即创建").len(),
            0,
            "{family}：第二个序号也必须另建空文件"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    println!(
        "SYNTH_OK 认领由磁盘作证（两个家族各一轮）：已存在即跳过、哨兵一字节未动、下一个序号另建空文件"
    );
}

/// 真实通道正控：`unique_temp_db_path()` 在实际使用的临时目录里必须每次给出一个
/// **新创建**的 0 字节文件，且两次调用不得同路径。
///
/// 复用上一轮的遗留文件时"非 0 字节"必然成立（旧库带完整 schema 与种子），
/// 所以"0 字节"这一条就是这条通道的现场证据，不是装饰性断言。
#[test]
fn real_temp_dir_paths_are_claimed_fresh() {
    let a = unique_temp_db_path();
    let b = unique_temp_db_path();
    assert_ne!(a, b, "同一进程内两次取路径必须不同");
    for p in [&a, &b] {
        let name = std::path::Path::new(p)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        assert!(
            name.starts_with(IT_DB_PREFIX) && name.contains(&std::process::id().to_string()),
            "隔离库名字必须自证本族与本 pid：{name}"
        );
        assert_eq!(
            std::fs::metadata(p)
                .unwrap_or_else(|e| panic!("认领后文件不在：{e}"))
                .len(),
            0,
            "{p} 必须是刚创建的空文件（非 0 字节 ⇒ 打开的是别人的旧库）"
        );
        let _ = std::fs::remove_file(p);
    }
    assert!(
        TEMP_DB_COUNTER.load(Ordering::Relaxed) >= 2,
        "计数器必须真的前进（没前进说明这两条路径来自同一次认领）"
    );
    println!("SYNTH_OK 真实临时目录两次认领都是 0 字节新文件：{a} / {b}");
}

/// `migrated_db()` 真的走认领通道吗？——**写了没接线=没写**（AGENTS 前言 ⑮ 的同族）。
///
/// 判据取"函数体内"而不是"整份文件里有没有这个字符串"：`test_support.rs` 的模块文档本身就
/// 写着 `claim_harness_db_path`，按全文 `contains` 会匹配到自己那一行、恒绿。
#[test]
fn migrated_db_actually_claims_its_path_from_disk() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/repository/test_support.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("读不到 {}（采集面坏了必须响亮失败）：{e}", path.display()));
    let body =
        fn_body(&src, "pub async fn migrated_db").expect("migrated_db 必须存在于 test_support.rs");
    assert!(
        calls_claim(&body),
        "migrated_db 没有向磁盘认领路径，仍在按名字拼路径 ⇒ repo 族照样会跨轮串库：\n{body}"
    );
    // 反证 ①：改造前的函数体形状（按 pid+nanos 拼名字、直接交给 mode=rwc）必须判"没接线"。
    let pre_fix = "let p = temp_dir().join(name);\nlet url = format!(\"sqlite://{p}?mode=rwc\");";
    assert!(
        !calls_claim(pre_fix),
        "反证失效：按名字拼路径的旧形状也被认成'已接线'，这条判据就是恒真"
    );
    // 反证 ②：只在注释里提了一句、函数体没有调用点 ⇒ 不得放行。
    assert!(!calls_claim(
        "// claim_harness_db_path_loop 是唯一通道\nlet url = 1;"
    ));
    println!("SYNTH_OK migrated_db 的认领调用点确实生效（含两条'不得放行'反证）");
}

/// 取 `sig` 之后到下一个"顶格 `}`"之前的函数体（与 `env_discipline` 的块跨度同一口径：
/// 绑在 `cargo fmt` 唯一会写出的形态上，而不是在文本里做括号计数）。
fn fn_body(src: &str, sig: &str) -> Option<String> {
    let at = src.find(sig)?;
    let rest = &src[at..];
    let end = rest.find("\n}\n")?;
    Some(rest[..end + 1].to_string())
}

/// 函数体里是否有认领通道调用点（注释行不参与——否则"写了说明"会被当成"接了线"）。
fn calls_claim(body: &str) -> bool {
    body.lines()
        .any(|l| !l.trim().starts_with("//") && l.contains("claim_harness_db_path"))
}

/// 回收器在真实临时目录上的两侧：两个家族够旧的（含 WAL 边车）都删掉，
/// 本族新鲜的、族外的、**Redis 槽位锁**都留下。
///
/// ⚠ 这条用例会在第一次运行时把历史遗留的本族文件清掉——那正是修复本身
/// （遗留文件全部是本仓测试自己造的隔离库，零业务价值；阈值 2 小时远大于整跑最长一轮）。
#[test]
fn sweep_removes_stale_and_keeps_fresh() {
    let dir = std::env::temp_dir();
    let stale_it = dir.join(it_name("990011_990011"));
    let stale_it_wal = dir.join("stepby_it_990011_990011.db-wal");
    let stale_repo = dir.join("stepby_repo_test_990014_990014_990014.db");
    let fresh_it = dir.join(it_name("990012_990012"));
    let fresh_repo = dir.join("stepby_repo_test_990015_990015_990015.db");
    let foreign_db = dir.join("stepby_other_990013.db");
    // 槽位号取 99：1..=15 才是真实仲裁用的区间，这里只验"回收器不许碰 .lock"。
    let slot_lock = dir.join("stepby_it_redis_db_99.lock");
    let aged = [
        &stale_it,
        &stale_it_wal,
        &stale_repo,
        &foreign_db,
        &slot_lock,
    ];
    let kept = [&fresh_it, &fresh_repo, &foreign_db, &slot_lock];
    for p in aged.iter().chain(kept.iter()) {
        write_file_with_content(p, b"x");
    }
    let old = HARNESS_DB_STALE_SECS + 3600;
    for p in &aged {
        age_file(p, old);
    }

    let (before_files, before_bytes) = family_footprint(&dir);
    sweep_stale_harness_dbs();
    let (after_files, after_bytes) = family_footprint(&dir);

    for (desc, p) in [
        ("集成族主文件", &stale_it),
        ("集成族 WAL 边车", &stale_it_wal),
        ("repo 族主文件", &stale_repo),
    ] {
        assert!(
            !p.exists(),
            "超过阈值的本族遗留文件必须被回收（{desc}）：{}",
            p.display()
        );
    }
    for (desc, p) in [
        ("集成族新文件", &fresh_it),
        ("repo 族新文件", &fresh_repo),
        ("族外文件", &foreign_db),
        ("Redis 槽位锁", &slot_lock),
    ] {
        assert!(p.exists(), "{desc}不得被回收：{}", p.display());
    }
    for p in kept {
        let _ = std::fs::remove_file(p);
    }
    println!(
        "SYNTH_OK 回收器两侧都对：两个家族够旧的（含边车）删掉，新的 / 族外的 / 槽位锁留下（{} 个不同夹具）；\
         本族足迹证据（只打印、不判定）：回收前 {} 个 / {:.1} MiB ⇒ 回收后 {} 个 / {:.1} MiB（本次释放 {:.1} MiB）",
        aged.len() + kept.len() - 2,
        before_files,
        before_bytes as f64 / 1048576.0,
        after_files,
        after_bytes as f64 / 1048576.0,
        before_bytes.saturating_sub(after_bytes) as f64 / 1048576.0
    );
}
