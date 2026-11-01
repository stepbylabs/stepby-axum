//! v5-E6 回填面 ↔ 实体加密列的**双向**契约锁（b149 项 17a）。
//!
//! # 立项
//!
//! `ensure_runtime_secrets_encrypted` 的 `TARGETS` 是一份**手写清单**，而"哪些列是密文列"
//! 这个事实长在 `src/entity/*.rs` 的列类型（`EncryptedString`）上。模块文档写着
//! "新增加密列时必须同步登记进 TARGETS"——那是**注释不是判据**（AGENTS ⑮：承诺必须有
//! 生效路径）。
//!
//! 漏登记的后果不是"少加密一次"，而是让通用层的**降级明文永久留在库里**：
//! `Into<Value>` 由 sea-orm 内部调用、结构上没有失败通道，所以"密钥未配置"（`NoMasterKey`）
//! 与"加密失败"（`Degraded`）两档只能先写明文、等下次启动回填补上。回填只碰清单上的列
//! ⇒ 这条锁是那两个降级档**可自愈**的唯一前提。17b 让降级可见，17a 让降级可恢复。
//!
//! # 三条腿（方向都是双向）
//! 1. 实体声明是密文列、清单没有 ⇒ 红（漏登记）；
//! 2. 清单有、实体已不再声明 ⇒ 红（条目腐化：留着会让下一个人以为该列仍受保护）；
//! 3. 两边都有但主键列不一致 ⇒ 红（回填 SQL 是 `SELECT {pk} … WHERE {pk}` 拼出来的，
//!    主键名写错时每行读取失败被 warn 跳过 ⇒ **该列永不回填而集合看起来是对的**——
//!    这一型只有腿 3 看得见，所以三腿必须各自可证伪）。

use crate::common::prod_scan::{self, Scan};

type Triple = (String, String, String);

/// 从本仓生产码视图里取 `TARGETS` 的字面量条目。
///
/// 取 `prod_scan` 的**生产码视图**而不是 `include_str!` 全文：测试代码里的合成夹具不得被
/// 算进清单本体（否则"不得报"的反证会匹配到自己那一行而恒绿，AGENTS ㊴②）。
fn registered_targets() -> Vec<Triple> {
    let text = prod_scan::prod_file("src/initialize/oauth_sso.rs", &Scan::default()).text();
    let marker = "const TARGETS: &[(&str, &str, &str)] = &[";
    let (_, rest) = text.split_once(marker).unwrap_or_else(|| {
        panic!("TARGETS 清单读不到 ⇒ 判据的输入坏了；不得把\"没解析出来\"当成\"没有缺口\"")
    });
    let (block, _) = rest
        .split_once("];")
        .unwrap_or_else(|| panic!("TARGETS 清单没有收尾 ] ⇒ 本文件形状变了"));
    parse_rows(block)
}

/// 解析 `( "表", "主键列", "敏感列" )`：按 `)` 切元组、每段取最后一个 `(` 之后的内容，
/// 因此行内多条与跨行写法都能覆盖（按行匹配会漏掉换行折叠的形状）。
fn parse_rows(block: &str) -> Vec<Triple> {
    let mut out = Vec::new();
    for chunk in block.split(')') {
        let tail = chunk.split('(').next_back().unwrap_or("");
        let cells: Vec<String> = tail
            .split(',')
            .map(|c| c.trim().trim_matches('"').to_string())
            .filter(|c| !c.is_empty())
            .collect();
        if cells.len() == 3 {
            out.push((cells[0].clone(), cells[1].clone(), cells[2].clone()));
        }
    }
    out
}

/// 由**实体声明**派生加密列清单：`#[sea_orm(table_name = "…")]` + `#[sea_orm(primary_key)]`
/// + 类型为 `EncryptedString` 的字段。采集面 = `src/entity/` 下全部生产文件（不是文件名清单）。
fn encrypted_columns_from_entities() -> Vec<Triple> {
    let files = prod_scan::prod_files(&Scan::default());
    let face: Vec<_> = files
        .iter()
        .filter(|f| f.rel.starts_with("src/entity/"))
        .collect();
    assert!(
        face.len() >= 50,
        "实体采集面只有 {} 个文件 ⇒ 派生跑歪了（面大小由 prod_scan 给，不抄历史数）",
        face.len()
    );
    let mut out = Vec::new();
    for f in &face {
        let mut table = String::new();
        let mut pk = String::new();
        let mut pending_pk = false;
        for line in f.text().lines() {
            let t = line.trim();
            if let Some((_, rest)) = t.split_once("#[sea_orm(table_name = ") {
                table = rest
                    .split_once(')')
                    .map(|(a, _)| a.trim().trim_matches('"').to_string())
                    .unwrap_or_default();
                continue;
            }
            if t.starts_with("#[sea_orm(primary_key") {
                pending_pk = true;
                continue;
            }
            if let Some(field) = t.strip_prefix("pub ") {
                let name: String = field.split(':').next().unwrap_or("").trim().to_string();
                if pending_pk {
                    pk = name.clone();
                    pending_pk = false;
                }
                if field.contains("EncryptedString") && !table.is_empty() {
                    out.push((table.clone(), pk.clone(), name));
                }
            }
        }
    }
    assert!(
        !out.is_empty(),
        "实体面一个加密列都没派生出来 ⇒ 列类型写法变了，这条锁已经空转"
    );
    out
}

/// 腿 1：实体是密文列但不在回填面上。
fn missing_from_backfill_face(entity: &[Triple], registered: &[Triple]) -> Vec<String> {
    entity
        .iter()
        .filter(|(t, _, c)| !registered.iter().any(|(rt, _, rc)| rt == t && rc == c))
        .map(|(t, _, c)| format!("{t}.{c}"))
        .collect()
}

/// 腿 2：登记了但实体侧已不再是密文列。
fn stale_registrations(entity: &[Triple], registered: &[Triple]) -> Vec<String> {
    registered
        .iter()
        .filter(|(t, _, c)| !entity.iter().any(|(et, _, ec)| et == t && ec == c))
        .map(|(t, _, c)| format!("{t}.{c}"))
        .collect()
}

/// 腿 3：同列两边都在，但回填用的主键列与实体主键不一致。
fn primary_key_mismatches(entity: &[Triple], registered: &[Triple]) -> Vec<String> {
    let mut out = Vec::new();
    for (t, pk, c) in registered {
        let Some((_, epk, _)) = entity.iter().find(|(et, _, ec)| et == t && ec == c) else {
            continue;
        };
        if epk != pk {
            out.push(format!("{t}.{c}：回填用 {pk}，实体主键是 {epk}"));
        }
    }
    out
}

/// 正向：三腿都必须空。红的时候**先确认实体那一侧的形状**再动清单——
/// 把不存在的列签进清单等于制造一条"看着受保护"的假登记。
#[test]
fn backfill_face_and_entity_encrypted_columns_agree() {
    let entity = encrypted_columns_from_entities();
    let registered = registered_targets();
    let missing = missing_from_backfill_face(&entity, &registered);
    let stale = stale_registrations(&entity, &registered);
    let mismatched = primary_key_mismatches(&entity, &registered);
    assert!(
        missing.is_empty(),
        "这些密文列不在 v5-E6 回填面上：{missing:?}。通用层写降级（密钥未配 / seal 失败）\
         只能靠启动回填自愈，漏登记会让明文**永久**留在库里——请把它加进 TARGETS。"
    );
    assert!(
        stale.is_empty(),
        "TARGETS 里这些条目在实体侧已经不是 EncryptedString：{stale:?} ⇒ 请撤销这条登记，\
         留着只会让下一个人以为该列仍受保护。"
    );
    assert!(
        mismatched.is_empty(),
        "回填主键列与实体主键不一致：{mismatched:?} ⇒ 回填 SQL 每行读取失败被 warn 跳过，\
         该列实际永不回填。"
    );
}

/// 三条腿各自只在自己那一型输入下转红：缺这一条，"三腿全空"可能只是三腿互相顶班。
#[test]
fn each_direction_of_the_contract_is_falsifiable() {
    let row = || {
        vec![(
            "sys_web_hook".to_string(),
            "id".to_string(),
            "secret".to_string(),
        )]
    };
    let registered = row();

    // ① 实体多一列 ⇒ 只有腿 1 报
    let with_new_column = vec![
        registered[0].clone(),
        (
            "sys_new_vault".to_string(),
            "id".to_string(),
            "key".to_string(),
        ),
    ];
    assert_eq!(
        missing_from_backfill_face(&with_new_column, &registered),
        vec!["sys_new_vault.key".to_string()],
        "新增密文列必须被抓到"
    );
    assert!(
        stale_registrations(&with_new_column, &registered).is_empty(),
        "① 型缺陷不得串到腿 2"
    );
    assert!(
        primary_key_mismatches(&with_new_column, &registered).is_empty(),
        "① 型缺陷不得串到腿 3"
    );

    // ② 清单多一条实体已不声明的 ⇒ 只有腿 2 报
    let mut stale_row = row();
    stale_row.push((
        "sys_gone".to_string(),
        "id".to_string(),
        "token".to_string(),
    ));
    assert!(
        missing_from_backfill_face(&registered, &stale_row).is_empty(),
        "② 型缺陷不得串到腿 1"
    );
    assert_eq!(
        stale_registrations(&registered, &stale_row),
        vec!["sys_gone.token".to_string()],
        "腐化的登记条目必须被抓到"
    );

    // ③ 主键名写错 ⇒ 集合层面两条腿都看不见，只有腿 3 报
    let wrong_pk = vec![(
        "sys_web_hook".to_string(),
        "hook_id".to_string(),
        "secret".to_string(),
    )];
    assert!(
        missing_from_backfill_face(&registered, &wrong_pk).is_empty()
            && stale_registrations(&registered, &wrong_pk).is_empty(),
        "③ 型缺陷在 (表,列) 集合上是等价的——必须由腿 3 单独抓，否则这条腿就是装饰"
    );
    assert_eq!(
        primary_key_mismatches(&registered, &wrong_pk).len(),
        1,
        "主键不一致必须点名"
    );
}

/// 解析器自证：两侧都必须从**真文件**取出足量、无空名、形状对条目
/// （"解析出一个空集合"与"解析出一堆空串"都会让上面的对账看着干净，⑥）。
#[test]
fn both_sides_are_actually_parsed_from_real_files() {
    let registered = registered_targets();
    assert!(
        registered.len() >= 5,
        "TARGETS 只解析出 {registered:?} 条 ⇒ 解析器与本文件形状脱节"
    );
    for (t, pk, c) in &registered {
        assert!(
            !t.is_empty() && !pk.is_empty() && !c.is_empty(),
            "空名条目：表={t} 主键={pk} 列={c}"
        );
        assert!(t.contains('_'), "表名形状不对（应为 snake_case 表名）：{t}");
    }
    let entity = encrypted_columns_from_entities();
    assert!(
        entity.len() >= 5,
        "实体侧只派生出 {entity:?} 条 ⇒ 列类型写法变了，锁已空转"
    );
    for (t, pk, c) in &entity {
        assert!(!t.is_empty(), "实体侧表名解析失败：{c}");
        assert!(!pk.is_empty(), "实体侧主键解析失败：{t}.{c}");
    }
}

/// 合成夹具活性：`parse_rows` 必须能吃下"跨行 + 行内多条"两种写法，
/// 而不是只在现形（每行一条）下工作——现形将来被 `cargo fmt` 折叠就会静默失配（⑰）。
#[test]
fn row_parser_covers_wrapped_shapes() {
    let one_per_line = r#"("a", "x", "one"),
        ("b", "y", "two"),
    "#;
    assert_eq!(parse_rows(one_per_line).len(), 2);
    // 折叠成一条长行（cargo fmt 在 100 列内就会这么做）
    let folded = r#"("a", "x", "one"), ("b", "y", "two"), "#;
    assert_eq!(
        parse_rows(folded),
        parse_rows(one_per_line),
        "折叠与否都必须得到同一集合——否则「基线与本轮不同源」会在某次 cargo fmt 之后发生"
    );
    // 注释里写着同形状不得进面（`Scan::default()` 已剔注释；这里再钉一次解析器本身）
    let commented = r#"("a", "x", "one"), // ("b", "y", "two")
    "#;
    assert!(
        !parse_rows(commented).is_empty(),
        "解析器必须仍能取出真条目（不因注释而空转）"
    );
}
