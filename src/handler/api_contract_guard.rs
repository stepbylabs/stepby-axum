//! API 出口契约总锁（批七十四 轮 27，§一.4/§一.5/§一.16）
//!
//! 四族判据，全部是**反向**判据（问"该做的都做了吗"，不是"做了的对吗"）：
//!
//! 1. **错误/成功体契约**（C.8）：handler 不得手搓 `{"code":200,"msg":"ok"}`，
//!    也不得把返回类型写成 `Result<Json<serde_json::Value>, _>`。手搓体绕过 i18n、
//!    绕过 `trace_id`，而且让"契约守卫"永远看不见这一族端点（`data_rule_handler` 两处即此形）。
//! 2. **凭据列不得进无关链路**（§一.16）：`sys_user::Entity::find()` 未接 `select_only`
//!    就把行取出来，会把整行读进内存——含 `password` 的 argon2 摘要。群发/搜索/仪表盘三类聚合只需要两三个字段，
//!    凭据摘要出现在这些链路里没有任何功能理由，只有泄露理由（将来加一行日志或一次序列化就是事故）。
//! 3. **绝对路径折叠只许有『一处实现 + 一处刻意独立的出口探针』**（C.9）：正则实现只能住在
//!    `common::redact`；`/health` 出口侧允许一条**故意不复用** sanitizer 的独立断言
//!    （复用会让"sanitizer 失效"与"探针通过"同时成立＝自证清白的虚锁）。
//!    出现第三处就是复制实现 ⇒ 红。两处各写一遍必然漂移，而漂移的方向通常是"新出口没人管"。
//! 4. **garde 规则必须真的被执行**（批七十四 B2）：`#[derive(Validate)]` + `#[garde(..)]`
//!    写在一个从未校验的 DTO 上，视觉效果与"已校验"完全相同，测试也照样绿——它是**静默的死规则**。
//!    实测本批抓到 4 条（`BindOauthDto.handoff` / `ReportStatusDto.status` / `SubStatusDto.status` /
//!    `FlowGraphSubmitDto.{flow_code,title}`），全部已改为 `ValidatedJson`。
//!
//! 口径与同目录 [`fail_closed_guard`] / [`no_panic_guard`] 一致：只扫 `#[cfg(test)]` 之前的生产码，
//! 并剔除 `//` 行（治理点的注释会引用被禁写法作为说明）。
//! 每条判据都配**合成违规控制组**——证明扫描器真的能抓到，而不是一直返回 0。

#[cfg(test)]
mod api_contract_mod {
    use crate::common::prod_scan::{self, Comments, ProdFile, Scan};

    /// 本锁的采集口径：生产码 + **剔除**注释行（判据按语句序列匹配，注释会引用被禁形态）。
    /// 行号定位由另一把锁（`dead_face_guard`）负责，那边用 `Comments::Blank`。
    fn scan_cfg(exclude: &'static [&'static str], roots: &'static [&'static str]) -> Scan<'static> {
        Scan {
            comments: Comments::Drop,
            exclude,
            roots,
            ..Default::default()
        }
    }

    const SELF_EXCLUDE: &[&str] = &["src/handler/api_contract_guard.rs"];

    /// 生产码语句：`#[cfg(test)]` 之前 + 剔除 `//` 行注释
    fn prod_src(rel: &str) -> String {
        prod_scan::prod_file(rel, &scan_cfg(SELF_EXCLUDE, &["src"])).text()
    }

    fn to_rel_pairs(files: Vec<ProdFile>) -> Vec<(String, String)> {
        files
            .into_iter()
            .map(|f| (f.rel.clone(), f.text()))
            .collect()
    }

    // ==================== 判据本体（纯函数，供真实码与控制组共用） ====================

    /// 判据 1：返回**手搓契约体**的位置（字面 `"code": 200` / 裸 `Json<serde_json::Value>` 成功体）
    fn contract_hits(text: &str) -> Vec<String> {
        let mut hits = Vec::new();
        for line in text.lines() {
            let t = line.replace(' ', "");
            if t.contains("\"code\":200") {
                hits.push(format!("手搓 code=200 体: {}", line.trim()));
            }
            if line.contains("Result<Json<serde_json::Value>") {
                hits.push(format!("裸 Json<Value> 成功体: {}", line.trim()));
            }
        }
        hits
    }

    /// 判据 2：`sys_user::Entity::find()` 在**取行**（`.all(...)`）前未接 `select_only`
    ///
    /// 只 `.count(...)` 的语句不取行 ⇒ 不算违规（凭据列不会进内存）。
    /// 推进必须逐条走到"本条语句的第一个终结调用"再继续：遇到 count 就 `break` 会把
    /// 同文件后面所有未投影取行**整体吞掉**（控制组 ④ 正是为这条路径而存在——
    /// 初版就是这么漏的，被自己的控制组抓回，同 §测试门禁"回归锁必须变异证伪"）。
    fn unprojected_user_loads(text: &str) -> Vec<String> {
        let mut hits = Vec::new();
        let pat = "sys_user::Entity::find()";
        let mut rest = text;
        let mut line_no = 1usize;
        while let Some(pos) = rest.find(pat) {
            line_no += rest[..pos].matches('\n').count();
            let tail = &rest[pos + pat.len()..];
            let end_all = tail.find(".all(");
            let end_count = tail.find(".count(");
            let next = match (end_all, end_count) {
                (Some(a), Some(c)) => a.min(c),
                (Some(a), None) => a,
                (None, Some(c)) => c,
                (None, None) => break,
            };
            let takes_rows = end_all == Some(next);
            if takes_rows && !tail[..next].contains("select_only") {
                hits.push(format!("第 {line_no} 行附近 {pat} 未投影就 .all()"));
            }
            rest = &tail[next..];
        }
        hits
    }

    /// 判据 3：绝对路径正则的实现点计数（盘符字符类是这类正则的必经形态，
    /// 用它做锚比"整条正则字面量"稳——正则本体随口径演进（b74 轮 27 就从"任意 ≥3 段"
    /// 改成"已知文件系统根"），锚却不该跟着改）
    fn abs_path_impl_files(files: &[(String, String)]) -> Vec<String> {
        files
            .iter()
            .filter(|(_, text)| text.contains("[A-Za-z]:["))
            .map(|(rel, _)| rel.clone())
            .collect()
    }

    fn handler_files() -> Vec<(String, String)> {
        // 本守卫自身含判据字面量，必须排除（同 b74 轮 24 的"扫描器抓到自己"教训）
        to_rel_pairs(prod_scan::prod_files(&scan_cfg(
            SELF_EXCLUDE,
            &["src/handler"],
        )))
    }

    fn data_layer_files() -> Vec<(String, String)> {
        to_rel_pairs(prod_scan::prod_files(&scan_cfg(
            SELF_EXCLUDE,
            &["src/service", "src/repository", "src/handler"],
        )))
    }

    // ==================== 判据 4 的扫描器（纯函数，真实码与控制组共用） ====================

    /// 生产码**行**视图（`#[cfg(test)]` 之前；注释行置空而不是丢弃，以保持真实行号）
    ///
    /// 采集口径来自 [`crate::common::prod_scan`]（批七十五 B9）——同一份源码在 garde 锁、
    /// i18n 锁、死面锁里必须是**同一种形态**，否则一个锁红一个锁绿只是实现差异。
    /// 保留本包装函数：控制组要能直接喂合成源码，而合成源码不需要走文件系统。
    fn prod_lines(text: &str) -> Vec<String> {
        prod_scan::normalize(text, &Scan::default())
    }

    /// 全 `src` 生产码行视图（排除本守卫自身：判据字面量会命中自己的扫描器）
    fn src_line_files() -> Vec<(String, Vec<String>)> {
        let files = prod_scan::prod_files(&Scan {
            exclude: SELF_EXCLUDE,
            include_integration_tests: true,
            ..Default::default()
        });
        assert!(
            files.len() > 200,
            "扫描面必须覆盖全仓（实际 {} 个 .rs，过小说明遍历坏了）",
            files.len()
        );
        files.into_iter().map(|f| (f.rel, f.lines)).collect()
    }

    /// 把**跨行书写的属性**折成一条逻辑行（返回 `(首个物理行下标, 折叠后文本)`）。
    ///
    /// 存在的理由（批七十五 B5）：`derives_validate` / `garde_args` 原是按"一行写完"识别的，
    /// 于是把 `#[derive(...)]` 或 `#[garde(...)]` 换行写，整个 DTO 就**静默退出判据面**——
    /// 属性格式不该决定一条校验规则是否被检查。折叠后判据与书写格式无关。
    /// 只折以 `#[` 开头的行（属性），函数签名等保持原样；配不平或超过 12 行则原样返回，
    /// 避免把畸形片段并进下一段代码。
    fn logical_lines(lines: &[String]) -> Vec<(usize, String)> {
        let mut out: Vec<(usize, String)> = Vec::new();
        let mut i = 0usize;
        while i < lines.len() {
            let t = lines[i].trim_start();
            if t.starts_with("#[") {
                let mut acc = lines[i].clone();
                let mut j = i;
                while balance_delta(&acc) > 0 && j + 1 < lines.len() && j - i < 12 {
                    j += 1;
                    acc.push(' ');
                    acc.push_str(lines[j].trim());
                }
                if balance_delta(&acc) == 0 {
                    out.push((i, acc));
                    i = j + 1;
                    continue;
                }
            }
            out.push((i, lines[i].clone()));
            i += 1;
        }
        out
    }

    /// `(`/`[`/`{` 与闭合符的净差（字符串字面量内的括号不计）。
    fn balance_delta(s: &str) -> i32 {
        let mut d = 0i32;
        let mut in_str = false;
        let mut prev_bs = false;
        for c in s.chars() {
            if in_str {
                if c == '"' && !prev_bs {
                    in_str = false;
                }
                prev_bs = c == '\\' && !prev_bs;
                continue;
            }
            match c {
                '"' => {
                    in_str = true;
                    prev_bs = false;
                }
                '(' | '[' | '{' => d += 1,
                ')' | ']' | '}' => d -= 1,
                _ => {}
            }
        }
        d
    }

    /// 归属对账：每一条 `#[garde(` 必须落在一个**被识别为 derive(Validate)** 的结构体里。
    ///
    /// 这条补的是"格式即豁免"的另一半：即使折叠修好了多行 derive，仍然可能有 garde
    /// 属性挂在没 derive Validate 的结构上（garde 规则永不执行，且旧判据完全看不见它）。
    fn garde_attrs_without_validate_dto(
        files: &[(String, Vec<String>)],
        live: &std::collections::BTreeSet<String>,
    ) -> Vec<String> {
        let mut out = Vec::new();
        for (rel, lines) in files {
            let logical = logical_lines(lines);
            // 结构体作用域跟踪：(名字, 进入时的深度, 该结构是否被识别)
            let mut depth = 0i32;
            let mut scope: Option<(String, i32)> = None;
            for (idx, text) in &logical {
                let before = depth;
                depth += balance_delta(text);
                if let Some(name) = struct_name_of(text) {
                    scope = Some((name, before));
                }
                if let Some((_, enter)) = &scope
                    && depth <= *enter
                {
                    scope = None;
                }
                if garde_args(text).is_some() {
                    let named_struct = scope
                        .as_ref()
                        .map(|(n, _)| n.clone())
                        .unwrap_or_else(|| "<非结构体作用域>".to_string());
                    if !live.contains(&named_struct) {
                        out.push(format!(
                            "{rel}:{} garde 属性挂在 {named_struct} 上",
                            idx + 1
                        ));
                    }
                }
            }
        }
        out
    }

    /// `struct NAME` 行 ⇒ 结构体名（仅认 `pub struct` / `struct` 两种形态）
    fn struct_name_of(line: &str) -> Option<String> {
        let t = line.trim_start();
        let t = t.strip_prefix("pub ").unwrap_or(t);
        let rest = t.strip_prefix("struct ")?;
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    }

    /// `#[garde(<args>)]` ⇒ `<args>`（用 `rfind` 收尾，兼容 `custom(validate_x))` 嵌套括号）
    fn garde_args(line: &str) -> Option<&str> {
        let rest = line.trim_start().strip_prefix("#[garde(")?;
        let end = rest.rfind(")]")?;
        Some(&rest[..end])
    }

    /// derive 列表里是否含 `Validate`（含 `garde::Validate` 全路径形态）
    fn derives_validate(line: &str) -> bool {
        let Some(open) = line.find("#[derive(") else {
            return false;
        };
        let inner = &line[open + "#[derive(".len()..];
        let Some(close) = inner.find(")]") else {
            return false;
        };
        inner[..close].split(',').any(|d| {
            d.trim()
                .rsplit("::")
                .next()
                .is_some_and(|last| last == "Validate")
        })
    }

    /// derive 了 `Validate` 的结构体：`(名字, 是否含至少一条非 skip 规则)`。
    ///
    /// 一次遍历出两个事实，避免"活 DTO 集合"与"Validate 结构集合"各扫一遍源码后
    /// 对同一份文件得出不同结论（两把锁的输入必须来自同一次解析）。
    ///
    /// **窗口按 `logical` 的下标（位置）推进，不能按行号**：`logical_lines` 产出的是
    /// `(原始行号, 文本)`，`.skip(*i)` 里的 `*i` 是行号，把它当位置用会在文件前半段少跳、
    /// 后半段跳过整段 ⇒ 结构体"确实 derive 了 Validate 却没被认出来"（本轮实测：
    /// `sys_web_hook_service.rs:419` 的 `WebhookTestSendDto` 在 900 行文件里被 skip(419)
    /// 直接越过，归属对账把它报成孤儿）。这与本仓反复自曝的"扫描器把行号当字节号"同族，
    /// 且短合成源码里行号恰好等于位置 ⇒ 原控制组永远抓不到，故下面补了带空行填充的对照。
    fn derived_validate_structs(files: &[(String, Vec<String>)]) -> Vec<(String, bool)> {
        let mut out: Vec<(String, bool)> = Vec::new();
        for (rel, lines) in files {
            let _ = rel;
            // 折叠后判据与属性书写格式无关（批七十五 B5）
            let logical = logical_lines(lines);
            for (pos, (_, l)) in logical.iter().enumerate() {
                if !derives_validate(l) {
                    continue;
                }
                // 结构体名最多在 derive 之后 4 条逻辑行内（中间可夹 #[serde(...)]）
                // 窗口按 `logical` 的**位置**切（切片而非下标循环），返回的 `at` 也是位置，
                // 供下面 `.skip(at + 1)` 用——两处必须同一口径，否则又回到行号/下标混用。
                let mut found: Option<(String, usize)> = None;
                for (off, w) in logical[pos..(pos + 5).min(logical.len())]
                    .iter()
                    .enumerate()
                {
                    if let Some(n) = struct_name_of(&w.1) {
                        found = Some((n, pos + off));
                        break;
                    }
                }
                let Some((name, at)) = found else { continue };
                let mut live = false;
                for (_, bl) in logical.iter().skip(at + 1) {
                    let bt = bl.trim();
                    if bt == "}" {
                        break;
                    }
                    if let Some(args) = garde_args(bt)
                        && args.trim() != "skip"
                    {
                        live = true;
                        break;
                    }
                }
                out.push((name, live));
            }
        }
        out
    }

    /// 「derive 了 Validate 且**至少有一条非 skip 的 garde 规则**」的结构体名。
    ///
    /// 只写 `#[garde(skip)]` 的 DTO 不参与判据 4——它没有"本该生效却没生效"的规则，
    /// 把它算进来等于给锁加噪声。
    fn live_garde_dtos(files: &[(String, Vec<String>)]) -> std::collections::BTreeSet<String> {
        derived_validate_structs(files)
            .into_iter()
            .filter(|(_, live)| *live)
            .map(|(n, _)| n)
            .collect()
    }

    // ==================== 判据 5（批八十五）：DTO 的线上字段名必须显式声明 ====================

    /// 被 `ValidatedJson<T>` / `ValidatedQuery<T>` / `ValidatedForm<T>` 消费的 DTO 名。
    ///
    /// 取"提取点实际消费到的"而不是"所有 derive(Deserialize) 的结构"：只有走这三个提取器的
    /// DTO 才与本仓前端的 camelCase 约定直接相遇（其余结构要么是响应体、要么是内部类型）。
    ///
    /// **路径必须取最后一段**：`ValidatedJson<config_service::AiConfigUpdateDto>` 是全仓唯一
    /// 的限定名写法（`ai/handler.rs:214`）。按"标识符字符"截会截出模块名 `config_service`
    /// ——那个"DTO"当然定位不到定义，于是本条既误报一项、又**静默漏掉真正的 DTO**。
    fn validated_extractor_dtos(
        files: &[(String, Vec<String>)],
    ) -> std::collections::BTreeSet<String> {
        const MARKS: [&str; 3] = ["ValidatedJson<", "ValidatedQuery<", "ValidatedForm<"];
        let mut out = std::collections::BTreeSet::new();
        for (_, lines) in files {
            for l in lines {
                for mark in MARKS {
                    let mut rest = l.as_str();
                    while let Some(pos) = rest.find(mark) {
                        let tail = &rest[pos + mark.len()..];
                        let path: String = tail
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                            .collect();
                        let name = path.rsplit("::").next().unwrap_or("");
                        if !name.is_empty() && name != "T" {
                            out.insert(name.to_string());
                        }
                        rest = tail;
                    }
                }
            }
        }
        out
    }

    /// 结构体的"线上形状"：`(所在文件, 容器属性块折叠文本, 体内逻辑行)`；找不到定义返回 `None`。
    ///
    /// 属性块**向上**收集连续的 `#[...]`（`#[serde(rename_all)]` 就写在 `pub struct` 前一行），
    /// 且必须用 `logical_lines`：属性换行书写时物理行是残片，按物理行匹配会认不出 `rename_all`
    /// ——那正是批七十五 B5 立过的"格式即豁免"形状。
    fn struct_wire_shape(
        files: &[(String, Vec<String>)],
        name: &str,
    ) -> Option<(String, String, Vec<String>)> {
        for (rel, lines) in files {
            let logical = logical_lines(lines);
            for (pos, (_, l)) in logical.iter().enumerate() {
                if struct_name_of(l).as_deref() != Some(name) {
                    continue;
                }
                let mut attrs = String::new();
                let mut k = pos;
                while k > 0 {
                    let prev = logical[k - 1].1.trim().to_string();
                    if prev.starts_with("#[") {
                        attrs = format!("{prev} {attrs}");
                        k -= 1;
                    } else {
                        break;
                    }
                }
                let mut body: Vec<String> = Vec::new();
                for (_, bl) in logical.iter().skip(pos + 1) {
                    let bt = bl.trim();
                    if bt == "}" {
                        break;
                    }
                    body.push(bt.to_string());
                }
                return Some((rel.clone(), attrs, body));
            }
        }
        None
    }

    /// 字段名（`pub xxx: T` / `xxx: T` 的行首标识符），非字段行返回 `None`。
    fn field_name_of(line: &str) -> Option<String> {
        let head = line.split(':').next()?.trim();
        let head = head.strip_prefix("pub ").unwrap_or(head).trim();
        let owned = head.strip_prefix("pub(crate) ").unwrap_or(head).trim();
        if owned.is_empty()
            || !owned
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return None;
        }
        Some(owned.to_string())
    }

    /// 违规 = 字段名含下划线，而线上名没有任何声明（既无容器级 `rename_all`，也无字段级
    /// `rename` / `alias`）。serde 缺省按 Rust 字段名解键 ⇒ camelCase 的调用方**必然 400**。
    fn dto_wire_shape_hits(files: &[(String, Vec<String>)]) -> Vec<String> {
        let mut hits = Vec::new();
        for name in validated_extractor_dtos(files) {
            let Some((rel, attrs, body)) = struct_wire_shape(files, name.as_str()) else {
                hits.push(format!(
                    "{name}：被 Validated* 消费却定位不到结构体定义（采集面漏项，判据覆盖不到它）"
                ));
                continue;
            };
            let container_declared = attrs.contains("rename_all");
            let mut pending_serde = false;
            for ln in &body {
                if ln.starts_with("#[") {
                    if ln.starts_with("#[serde(") && (ln.contains("rename") || ln.contains("alias"))
                    {
                        pending_serde = true;
                    }
                    continue;
                }
                let Some(field) = field_name_of(ln) else {
                    pending_serde = false;
                    continue;
                };
                if field.contains('_') && !container_declared && !pending_serde {
                    hits.push(format!(
                        "{rel}::{name} 字段 `{field}` 未声明线上名（serde 按 snake_case 解键，camelCase 调用方必然 400 parse_failed）"
                    ));
                }
                pending_serde = false;
            }
        }
        hits
    }

    /// 行首（允许 `pub` / `async` / `pub(crate)` 修饰）的 `fn NAME` ⇒ `NAME`
    fn fn_def_name(line: &str) -> Option<String> {
        let t = line.trim_start();
        let idx = t.find("fn ")?;
        let prefix = &t[..idx];
        // 只认"函数头在行首"：`let f = fn`、`-> ` 位置、宏内字符串都被这个白名单挡掉
        if !prefix
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == ' ' || c == '(' || c == ')')
        {
            return None;
        }
        let rest = &t[idx + 3..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    }

    /// 从 `start`（函数头行）起做花括号配平，返回整个函数（含签名）
    fn fn_body(lines: &[String], start: usize) -> String {
        let mut depth = 0i32;
        let mut opened = false;
        let mut out = String::new();
        for l in lines.iter().skip(start) {
            out.push_str(l);
            out.push('\n');
            for c in l.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        opened = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if opened && depth <= 0 {
                break;
            }
        }
        out
    }

    /// 顶层逗号切分（忽略 `<>` / `()` / `[]` 内的逗号）——用于拆函数签名形参表
    fn split_top_level(s: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut depth = 0i32;
        let mut start = 0usize;
        for (i, c) in s.char_indices() {
            match c {
                '<' | '(' | '[' => depth += 1,
                '>' | ')' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    out.push(&s[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        out.push(&s[start..]);
        out
    }

    /// 在函数文本（头几行）里找"类型恰为 `dto`"的形参名（支持 `&Dto` / `&mut Dto` / 全路径类型）
    ///
    /// 只在**形参表内**拆分：整条签名一起按逗号拆是错的——参数表的 `(` 让所有顶层逗号
    /// 都落在 depth≥1，一次都拆不开（本函数初版就栽在这儿，被自己的控制组 ④ 抓回）。
    fn param_of_dto(fn_text: &str, dto: &str) -> Option<String> {
        let open = fn_text.find('(')?;
        let mut depth = 0i32;
        let mut close = None;
        for (i, c) in fn_text[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close?;
        for seg in split_top_level(&fn_text[open + 1..close]) {
            let s = seg.trim();
            let Some(colon) = s.find(':') else { continue };
            let raw_name = s[..colon].trim();
            let pname = raw_name
                .strip_prefix("mut ")
                .unwrap_or(raw_name)
                .trim()
                .to_string();
            if pname.is_empty() || !pname.chars().all(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            let mut ty = s[colon + 1..].trim();
            ty = ty.strip_prefix('&').unwrap_or(ty).trim();
            ty = ty.strip_prefix("mut ").unwrap_or(ty).trim();
            // 类型可能写成 `sys_oauth_service::BindOauthDto`，取最后一段路径
            let last = ty.rsplit("::").next().unwrap_or("");
            if last == dto {
                return Some(pname);
            }
        }
        None
    }

    /// `text` 中是否以**独立单词**形式出现 `word`（避免 `dto` 命中 `dto2` / `xdto`）
    fn contains_word(text: &str, word: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        let w: Vec<char> = word.chars().collect();
        if w.is_empty() {
            return false;
        }
        let is_ident = |c: char| c.is_alphanumeric() || c == '_';
        chars.windows(w.len()).enumerate().any(|(i, win)| {
            win == w
                && !chars.get(i.wrapping_sub(1)).is_some_and(|c| is_ident(*c))
                && !chars.get(i + w.len()).is_some_and(|c| is_ident(*c))
        })
    }

    /// 某个函数体是否真的对该形参执行了 garde 校验
    fn validates_param(body: &str, pname: &str) -> bool {
        [
            format!("i18n::validate(&{pname}"),
            format!("i18n::validate(&mut {pname}"),
            format!("{pname}.validate()"),
        ]
        .iter()
        .any(|needle| body.contains(needle.as_str()))
    }

    /// 从形参行取"被这个提取器包住的变量名"：`Json(dto): Json<Dto>` → `dto`；
    /// `axum::Json(mut dto): axum::Json<Dto>` → `dto`。取不到（如写在同一行的非常规形态）返回 None，
    /// 调用方按"无法证明已校验"处理——宁严勿松。
    fn binding_of_extractor_arg(line: &str, kw: &str, dto: &str) -> Option<String> {
        let mut from = 0usize;
        while let Some(o) = line[from..].find('(') {
            let open = from + o;
            from = open + 1;
            let rest = &line[open + 1..];
            let Some(close) = rest.find(')') else { break };
            let inner = rest[..close].trim();
            let name = inner.strip_prefix("mut ").unwrap_or(inner).trim();
            if name.is_empty()
                || !name.chars().all(|c| c.is_alphanumeric() || c == '_')
                || name.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                continue;
            }
            // 形参类型部分：`)`: `Json<Dto>` / `axum::Json<Dto>`
            let after = rest[close + 1..].trim_start();
            let Some(after) = after.strip_prefix(':') else {
                continue;
            };
            let ty = after.trim_start().replace(' ', "");
            if ty.contains(&format!("{kw}<{dto}>")) {
                return Some(name.to_string());
            }
        }
        None
    }

    /// 判据 4：返回「活 garde 规则的 DTO，其提取点既不是 `Validated*`、
    /// 所在函数也没有自行 `i18n::validate`，且转发目标也不校验」的位置。
    ///
    /// 三档放行（缺一即红），按"证明强度"从高到低：
    /// ① 提取器本身是 `ValidatedJson` / `ValidatedQuery`；
    /// ② 裸提取点**所在函数体内**有 `i18n::validate(&<该 binding>`；
    /// ③ 所在函数把该 binding 传给某方法，且**该方法签名里有类型为本 DTO 的形参**、
    ///    其函数体对该形参调用了 `i18n::validate`（仓内既有主路径：handler 裸取 → service 校验）。
    fn dead_garde_sites(files: &[(String, Vec<String>)]) -> Vec<String> {
        let live = live_garde_dtos(files);
        // 方法名 → (文件下标, 行下标)，供 ③ 的两跳解析
        let mut fn_index: std::collections::BTreeMap<String, Vec<(usize, usize)>> =
            std::collections::BTreeMap::new();
        for (fi, (_, lines)) in files.iter().enumerate() {
            for (li, l) in lines.iter().enumerate() {
                if let Some(n) = fn_def_name(l) {
                    fn_index.entry(n).or_default().push((fi, li));
                }
            }
        }
        let mut hits = Vec::new();
        for (rel, lines) in files.iter() {
            for (li, l) in lines.iter().enumerate() {
                for kw in ["Json", "Query", "Form", "Path"] {
                    let mut from = 0usize;
                    while let Some(p) = l[from..].find('<') {
                        let abs = from + p;
                        from = abs + 1;
                        // `<` 前必须紧跟关键字本体（`axum::Json<`、`ValidatedJson<` 都算紧跟）
                        let Some(pre) = l[..abs].strip_suffix(kw) else {
                            continue;
                        };
                        // 关键字前不得还有标识符字符（`MyJson<` 不是 axum 提取器）
                        let tail = pre.trim_end();
                        if tail
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_')
                        {
                            continue;
                        }
                        if tail.ends_with("Validated") {
                            continue; // ① 已是 Validated* 提取器
                        }
                        let dto = l[abs + 1..]
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect::<String>();
                        if dto.is_empty() || !live.contains(&dto) {
                            continue;
                        }
                        // binding：`Json(dto): Json<Dto>` / `axum::Json(mut dto): axum::Json<Dto>`
                        let binding = binding_of_extractor_arg(l, kw, &dto);
                        // 所在函数体
                        let fn_start = (0..=li).rev().find(|&k| fn_def_name(&lines[k]).is_some());
                        let body = match fn_start {
                            Some(s) => fn_body(lines, s),
                            None => l.clone(),
                        };
                        let b = binding.clone().unwrap_or_default();
                        if !b.is_empty()
                            && (body.contains(&format!("i18n::validate(&{b}"))
                                || body.contains(&format!("i18n::validate(&mut {b}"))
                                || body.contains(&format!("{b}.validate()")))
                        {
                            continue; // ② 同函数自校验
                        }
                        // ③ 转发目标校验：调用的方法里，形参类型 = 本 DTO 且校验了该形参
                        let mut covered = false;
                        for (name, defs) in fn_index.iter() {
                            for (fi2, li2) in defs.clone() {
                                let target_lines = &files[fi2].1;
                                let target_body = fn_body(target_lines, li2);
                                let Some(pname) = param_of_dto(&target_body, &dto) else {
                                    continue;
                                };
                                if !validates_param(&target_body, &pname) {
                                    continue;
                                }
                                // 本函数确实把该 binding 作为实参传进了这个方法
                                let mut call_from = 0usize;
                                while let Some(c) = body[call_from..].find(&format!(".{name}(")) {
                                    let call = call_from + c;
                                    call_from = call + 1;
                                    let args = &body[call + name.len() + 2..];
                                    let mut depth = 1i32;
                                    let mut end = args.len();
                                    for (k, ch) in args.char_indices() {
                                        match ch {
                                            '(' => depth += 1,
                                            ')' => {
                                                depth -= 1;
                                                if depth == 0 {
                                                    end = k;
                                                    break;
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                    if !b.is_empty() && contains_word(&args[..end], &b) {
                                        covered = true;
                                        break;
                                    }
                                }
                                if covered {
                                    break;
                                }
                            }
                            if covered {
                                break;
                            }
                        }
                        if !covered {
                            hits.push(format!(
                                "{rel}:{} 提取点 `{}` 的 DTO `{dto}` 带活 garde 规则却无任何校验执行点（改用 Validated{kw}，或在本函数/转发目标内 i18n::validate）",
                                li + 1,
                                l.trim()
                            ));
                        }
                    }
                }
            }
        }
        hits
    }

    // ==================== 真实码判据 ====================

    #[test]
    fn handlers_must_not_hand_roll_envelope() {
        let mut all: Vec<String> = Vec::new();
        for (rel, text) in handler_files() {
            for h in contract_hits(&text) {
                all.push(format!("{rel}: {h}"));
            }
        }
        assert!(
            all.is_empty(),
            "handler 仍含手搓契约体（C.8 要求走 AjaxResult/AppError 统一出口）:\n{}",
            all.join("\n")
        );
    }

    #[test]
    fn user_table_reads_must_project_columns() {
        let mut all: Vec<String> = Vec::new();
        for (rel, text) in data_layer_files() {
            for h in unprojected_user_loads(&text) {
                all.push(format!("{rel}: {h}"));
            }
        }
        assert!(
            all.is_empty(),
            "存在未投影就取 sys_user 整行的读路径（会把 password 摘要读进内存，§一.16）:\n{}",
            all.join("\n")
        );
    }

    #[test]
    fn absolute_path_folding_has_exactly_one_implementation() {
        let mut files: Vec<(String, String)> = Vec::new();
        for sub in ["src/common/redact.rs", "src/handler/health_probes.rs"] {
            files.push((sub.to_string(), prod_src(sub)));
        }
        // 全仓扫一遍实现点（不只看这两个文件，否则"第三处复制"看不见）
        for rel in prod_scan::rel_paths("src") {
            if rel.ends_with("api_contract_guard.rs") || files.iter().any(|(r, _)| *r == rel) {
                continue;
            }
            files.push((rel.clone(), prod_src(&rel)));
        }
        let impls = abs_path_impl_files(&files);
        assert_eq!(
            impls,
            vec![
                // 唯一实现
                "src/common/redact.rs".to_string(),
                // **出口侧独立探针**：`/health` detail 的绝对路径断言故意自带一份判据，
                // 不复用 sanitizer——否则 sanitizer 失效时那条锁会跟着恒真（自证清白＝虚锁）。
                // 允许它存在的代价是"两处需同步"，所以这里做**集合相等**而不是"只查第一处"：
                // 出现第三处（真的复制实现）立刻红。
                "src/integration_tests/common_handler.rs".to_string(),
            ],
            "绝对路径折叠判据只允许『一处实现 + 一处独立探针』（C.9 同源；第三处＝漂移起点）"
        );
    }

    /// `AppError` 出口必须真的折叠绝对路径（行为判据，不只是"有 sanitizer"）
    #[tokio::test]
    async fn app_error_body_folds_absolute_paths_but_keeps_urls() {
        use axum::response::IntoResponse;
        let body_of = |msg: String| async move {
            let resp = crate::common::AppError::internal(&msg).into_response();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("读错误体");
            String::from_utf8(bytes.to_vec()).expect("错误体应为 UTF-8")
        };
        // ① 该折叠：Windows 盘符形态
        let body = body_of(r"写入 D:\Projects\stepby\uploads\file.bin 失败".to_string()).await;
        assert!(
            body.contains("<path>"),
            "错误体未折叠绝对路径，实际: {body}"
        );
        assert!(
            !body.contains("Projects") && !body.contains("stepby"),
            "错误体仍含部署目录结构，实际: {body}"
        );
        // ② 对照组（不得误伤排障信息）：URL + 端口 + 单段 API 片段必须原样在体里
        let body = body_of(
            "路由 /system/user/list 未登记，依赖 https://oidc.example.com:8443/.well-known"
                .to_string(),
        )
        .await;
        assert!(
            body.contains("/system/user/list") && body.contains("https://oidc.example.com:8443"),
            "边界折叠误伤排障信息，实际: {body}"
        );
    }

    /// 判据 4（批七十四 B2）：活 garde 规则的 DTO，其每一处提取点都必须真的执行校验。
    ///
    /// 这条锁存在的理由：`#[garde(..)]` 写在裸 `Json<>` 提取的 DTO 上**不会有任何报错**——
    /// derive 照常生成代码、单测照常绿、接口照常 200，规则只是永不执行。
    /// 本批实测抓到 4 条（见模块头），全是这个形状。
    #[test]
    fn garde_rules_must_be_executed_at_every_extraction_site() {
        let files = src_line_files();
        let live = live_garde_dtos(&files);
        // 非零探针：扫描面必须真的看到"活规则 DTO"，否则下面的 0 是虚零（同 §测试门禁"每个 0 都要有非零对账"）
        assert!(
            live.len() > 40,
            "全仓活 garde DTO 数异常偏小（实际 {}），扫描器可能失效",
            live.len()
        );
        let hits = dead_garde_sites(&files);
        assert!(
            hits.is_empty(),
            "存在带活 garde 规则却从未被校验的提取点（规则形同虚设）:\n{}",
            hits.join("\n")
        );
    }

    /// 归属对账（批七十五 B5）：每一条 `#[garde(` 都必须落在被识别的 `derive(Validate)` 结构上。
    ///
    /// 补的是判据 4 的"看不见的那一半"：判据 4 只对**已识别**的活 DTO 查提取点，
    /// 一条挂在非 Validate 结构上的 garde 属性（或属性写法让识别器没认出来）从来就不在
    /// 它的输入里。本条把"garde 属性的总数"与"归属到被识别 Validate 结构的 garde 属性数"
    /// 对上，差集必须为空——否则"格式变化 ⇒ DTO 静默出局 ⇒ 锁也静默少一项"无法被发现。
    ///
    /// **输入集合必须用"被识别"而不是"活"**（本轮实测订正）：判据 4 刻意把"全字段
    /// `#[garde(skip)]` 的 DTO"排除在外（没有本该生效却没生效的规则，参与判据 4 只是加噪声），
    /// 但归属命题问的是"这个结构 derive 了 Validate 吗"，与有没有活规则无关。首轮本条把
    /// `live_garde_dtos` 直接喂进来，于是 `GenTableEditDto` / `GenTableColumnEditDto` /
    /// `DatasetPreviewDto` 三个 skip-only 但确实 derive(Validate) 的 DTO 的 41 条属性全被报成
    /// 孤儿——假阳性，且报的是"规则永不执行"这种根本不存在的问题。控制组②用的是"被识别"集，
    /// ①③用的活集里合成 DTO 恰好都带真规则，所以边界一直没被约束住（对照组没覆盖判据的
    /// 定义域，正是本仓反复自曝的那类锁缺陷）；现补④把这条边界钉住。
    #[test]
    fn every_garde_attribute_belongs_to_a_recognized_validate_dto() {
        let files = src_line_files();
        let validated: std::collections::BTreeSet<String> = derived_validate_structs(&files)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        let orphan = garde_attrs_without_validate_dto(&files, &validated);
        let total: usize = files
            .iter()
            .map(|(_, lines)| {
                logical_lines(lines)
                    .iter()
                    .filter(|(_, t)| garde_args(t).is_some())
                    .count()
            })
            .sum();
        // 非零探针：识别器必须真的认到一批 Validate 结构，否则"0 孤儿"只是"没输入"
        assert!(
            validated.len() > 40,
            "被识别的 derive(Validate) 结构数异常偏小（实际 {}），采集面或识别器失效",
            validated.len()
        );
        // 非零探针：仓内 garde 属性是数百条量级，个位数说明采集或识别坏了
        assert!(
            total > 200,
            "全仓 `#[garde(` 属性总数异常偏小（实际 {total}），采集面或识别器失效"
        );
        assert!(
            orphan.is_empty(),
            "存在没有归属到 derive(Validate) 结构体的 garde 属性（规则永不执行，且判据 4 看不见）:\n{}",
            orphan.join("\n")
        );
    }

    /// 控制组：属性**换行书写**不得让 DTO 静默退出判据面（"格式即豁免"），
    /// 而挂在非 Validate 结构上的 garde 必须被归属对账抓出来。
    #[test]
    fn garde_attribution_guard_catches_format_based_exemption() {
        let mk = |text: &str| -> Vec<(String, Vec<String>)> {
            vec![("src/synth.rs".to_string(), prod_lines(text))]
        };
        // ① 多行 derive + 多行 garde：折叠后必须仍被识别为活 DTO
        let multiline = concat!(
            "#[derive(Debug, Deserialize, garde::Validate)]\n",
            "pub struct MultiDto {\n",
            "    #[garde(\n",
            "        length(min = 1, max = 8)\n",
            "    )]\n",
            "    pub name: String,\n",
            "}\n",
        );
        let files = mk(multiline);
        assert!(
            live_garde_dtos(&files).contains("MultiDto"),
            "跨行书写的属性必须与单行写法等价识别，实际活 DTO: {:?}",
            live_garde_dtos(&files)
        );
        assert!(
            garde_attrs_without_validate_dto(&files, &live_garde_dtos(&files)).is_empty(),
            "已识别 DTO 内部的 garde 属性不得被报成孤儿"
        );
        // ② garde 挂在**没有** derive Validate 的结构上 ⇒ 必须报（旧判据对此完全沉默）
        let no_derive = concat!(
            "#[derive(Debug, Deserialize)]\n",
            "pub struct SilentDto {\n",
            "    #[garde(length(min = 1))]\n",
            "    pub name: String,\n",
            "}\n",
        );
        let files2 = mk(no_derive);
        let validated2: std::collections::BTreeSet<String> = derived_validate_structs(&files2)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        let orphan = garde_attrs_without_validate_dto(&files2, &validated2);
        assert_eq!(
            orphan.len(),
            1,
            "没有 Validate 的 garde 属性必须被抓到，实际: {orphan:?}"
        );
        // ③ 反向对照：同一段代码补上 derive 后必须立刻不再报（证明判据认的是语义而非字面）
        let fixed = no_derive.replace(
            "#[derive(Debug, Deserialize)]",
            "#[derive(Debug, Deserialize, garde::Validate)]",
        );
        let files3 = mk(&fixed);
        assert!(
            garde_attrs_without_validate_dto(&files3, &live_garde_dtos(&files3)).is_empty(),
            "补上 derive 后不得继续报，否则下一次没人愿意加规则"
        );
        // ④ 边界（本轮补）：**全字段 skip** 的 DTO 确实 derive(Validate) ⇒ 归属命题成立，
        //    但它在"活 DTO"集里没有名字（判据 4 刻意排除）。主判据一旦误用"活"集，这 41 条
        //    属性就会全被报成孤儿（首轮实测）。这里同时钉两件事：
        //    这里同时钉两件事：
        //    a) "被识别"集不得报 skip-only 的 Validate 结构（假阳性）；
        //    b) "活"集确实会报（证明两个集合定义不同，主判据选哪个是有后果的，不是随手一支）。
        let skip_only = concat!(
            "#[derive(Debug, Deserialize, garde::Validate)]\n",
            "pub struct SkipOnlyDto {\n",
            "    #[garde(skip)]\n",
            "    pub table_name: String,\n",
            "}\n",
        );
        let files4 = mk(skip_only);
        let validated4: std::collections::BTreeSet<String> = derived_validate_structs(&files4)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(
            validated4.contains("SkipOnlyDto"),
            "skip-only 结构也必须被认成 Validate 结构，实际: {validated4:?}"
        );
        assert!(
            garde_attrs_without_validate_dto(&files4, &validated4).is_empty(),
            "skip-only 但确实 derive(Validate) 的属性不得报成孤儿（首轮 41 条假阳性即此形状）"
        );
        assert_eq!(
            garde_attrs_without_validate_dto(&files4, &live_garde_dtos(&files4)).len(),
            1,
            "对照组：若主判据改回\"活 DTO\"集，此处必须能复现假阳性（否则本边界仍未受约束）"
        );
        // skip 属性挂在**没有** derive 的结构上仍须报（"被识别"集不得因 skip 而放宽）
        let files5 = mk(&skip_only.replace(
            "#[derive(Debug, Deserialize, garde::Validate)]",
            "#[derive(Debug, Deserialize)]",
        ));
        let validated5: std::collections::BTreeSet<String> = derived_validate_structs(&files5)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(
            garde_attrs_without_validate_dto(&files5, &validated5).len(),
            1,
            "没有 Validate 的 skip 属性同样属于\"永不执行\"，必须被抓到"
        );
        // ⑤ 边界（本轮补）：**跨行属性造成"行号 ≠ logical 下标"的偏移**时，识别窗口
        //    必须仍按下标推进。原实现写 `.skip(*i)`（`*i` 是原始行号），在文件后半段会
        //    从结构体之后开始找 ⇒ 确实 derive(Validate) 的结构认不出来 ⇒ 归属对账报假孤儿
        //    （实测 `sys_web_hook_service.rs` 的 `WebhookTestSendDto` 正落在这个盲区里）。
        //    ①②③④的合成源码都太短（行号恰好等于下标），永远抓不到这条 ⇒ 这里刻意放
        //    三组跨行属性把偏移做出来，并同时给"补上 derive 必须不报 / 缺 derive 必须报"
        //    的双向对照，证明报与不报都来自语义而不是位置巧合。
        let padded = concat!(
            "#[allow(\n    unused_imports\n)]\n",
            "#[allow(\n    unused_variables\n)]\n",
            "#[allow(\n    deprecated\n)]\n",
            "#[derive(Debug, Deserialize, garde::Validate)]\n",
            "pub struct DeepDto {\n",
            "    #[garde(length(min = 1))]\n",
            "    pub name: String,\n",
            "}\n",
        );
        let files6 = mk(padded);
        assert!(
            live_garde_dtos(&files6).contains("DeepDto"),
            "跨行属性造成的下标偏移不得让 DTO 静默退出识别面，实际: {:?}",
            derived_validate_structs(&files6)
        );
        let validated6: std::collections::BTreeSet<String> = derived_validate_structs(&files6)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(
            garde_attrs_without_validate_dto(&files6, &validated6).is_empty(),
            "带偏移的合法 DTO 不得报孤儿"
        );
        let files7 = mk(&padded.replace(", garde::Validate", ""));
        let validated7: std::collections::BTreeSet<String> = derived_validate_structs(&files7)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(
            garde_attrs_without_validate_dto(&files7, &validated7).len(),
            1,
            "同一偏移下摘掉 derive 必须仍然报（否则⑤只是恒绿）"
        );
    }

    /// 控制组：证明判据 4 的扫描器能抓合成违规，且不误报合规形态
    #[test]
    fn garde_execution_guard_catches_synthetic_violation() {
        // 合成源码走与真实文件**同一条**归一化管道（prod_lines），否则控制组证明的是
        // 另一条管道——批七十五 B9 顺带修掉的正是这类"锁与它自己的对照组不同源"
        let files = |text: &str| -> Vec<(String, Vec<String>)> {
            vec![("src/synth.rs".to_string(), prod_lines(text))]
        };
        let dto_def = concat!(
            "#[derive(Debug, Deserialize, garde::Validate)]\n",
            "pub struct FooDto {\n",
            "    #[garde(length(min = 1, max = 8))]\n",
            "    pub name: String,\n",
            "}\n",
            "\n",
        );
        // ① 裸 Json 且无任何校验 ⇒ 必须报
        let bad = format!(
            "{dto_def}{}\n",
            concat!(
                "pub async fn add_foo(Json(dto): Json<FooDto>) -> Result<(), AppError> {\n",
                "    Ok(())\n",
                "}\n",
            )
        );
        assert_eq!(
            dead_garde_sites(&files(&bad)).len(),
            1,
            "合成'裸提取 + 零校验'必须被抓到"
        );
        // ② ValidatedJson ⇒ 不报（判据不是"禁止 Json"）
        let good_extractor = format!(
            "{dto_def}{}\n",
            concat!(
                "pub async fn add_foo(ValidatedJson(dto): ValidatedJson<FooDto>) -> Result<(), AppError> {\n",
                "    Ok(())\n",
                "}\n",
            )
        );
        assert!(
            dead_garde_sites(&files(&good_extractor)).is_empty(),
            "ValidatedJson 形态被误报"
        );
        // ③ 裸提取 + 同函数自校验 ⇒ 不报（仓内既有主路径之一）
        let same_fn = format!(
            "{dto_def}{}\n",
            concat!(
                "pub async fn add_foo(\n",
                "    Json(dto): Json<FooDto>,\n",
                ") -> Result<(), AppError> {\n",
                "    crate::common::i18n::validate(&dto)?;\n",
                "    Ok(())\n",
                "}\n",
            )
        );
        assert!(
            dead_garde_sites(&files(&same_fn)).is_empty(),
            "同函数 i18n::validate 形态被误报"
        );
        // ④ 裸提取 + 转发目标校验（形参类型 = 本 DTO）⇒ 不报
        let hop = format!(
            "{dto_def}{}\n",
            concat!(
                "pub async fn add_foo(Json(dto): Json<FooDto>) -> Result<(), AppError> {\n",
                "    state.foo_service.upsert_foo(dto).await\n",
                "}\n",
                "impl FooService {\n",
                "    pub async fn upsert_foo(&self, dto: FooDto) -> Result<(), ServiceError> {\n",
                "        crate::common::i18n::validate(&dto)?;\n",
                "        Ok(())\n",
                "    }\n",
                "}\n",
            )
        );
        assert!(
            dead_garde_sites(&files(&hop)).is_empty(),
            "两跳（service 层校验同一 DTO 形参）被误报"
        );
        // ⑤ 反向：service 校验的是**别的**形参 ⇒ 必须报（④ 不是免费通行证）
        let wrong_param = format!(
            "{dto_def}{}\n",
            concat!(
                "pub async fn add_foo(Json(dto): Json<FooDto>) -> Result<(), AppError> {\n",
                "    state.foo_service.upsert_foo(dto).await\n",
                "}\n",
                "impl FooService {\n",
                "    pub async fn upsert_foo(&self, other: BarDto) -> Result<(), ServiceError> {\n",
                "        crate::common::i18n::validate(&other)?;\n",
                "        Ok(())\n",
                "    }\n",
                "}\n",
            )
        );
        assert_eq!(
            dead_garde_sites(&files(&wrong_param)).len(),
            1,
            "转发目标校验了别的形参，必须仍然报"
        );
        // ⑥ 反向：形参类型对得上，但实参没把 binding 传进去 ⇒ 必须报
        let wrong_arg = format!(
            "{dto_def}{}\n",
            concat!(
                "pub async fn add_foo(Json(dto): Json<FooDto>) -> Result<(), AppError> {\n",
                "    state.foo_service.upsert_foo(something_else).await\n",
                "}\n",
                "impl FooService {\n",
                "    pub async fn upsert_foo(&self, dto: FooDto) -> Result<(), ServiceError> {\n",
                "        crate::common::i18n::validate(&dto)?;\n",
                "        Ok(())\n",
                "    }\n",
                "}\n",
            )
        );
        assert_eq!(
            dead_garde_sites(&files(&wrong_arg)).len(),
            1,
            "实参不含该 binding，必须仍然报"
        );
        // ⑦ 全 skip 的 DTO ⇒ 不参与判据（没有"本该生效却没生效"的规则）
        let skip_only = format!(
            "{}{}\n",
            concat!(
                "#[derive(Debug, Deserialize, garde::Validate)]\n",
                "pub struct SkipDto {\n",
                "    #[garde(skip)]\n",
                "    pub name: String,\n",
                "}\n",
                "\n",
            ),
            concat!(
                "pub async fn add_skip(Json(dto): Json<SkipDto>) -> Result<(), AppError> {\n",
                "    Ok(())\n",
                "}\n",
            )
        );
        assert!(
            dead_garde_sites(&files(&skip_only)).is_empty(),
            "纯 skip DTO 被误报（本锁不是'禁止裸 Json'）"
        );
        // ⑧ 全路径形态 `axum::Json<Dto>` ⇒ 必须报（此前只测了裸 `Json<`，漏掉限定名就是盲区）
        let qualified = format!(
            "{dto_def}{}\n",
            concat!(
                "pub async fn add_foo(axum::Json(mut dto): axum::Json<FooDto>) -> Result<(), AppError> {\n",
                "    Ok(())\n",
                "}\n",
            )
        );
        assert_eq!(
            dead_garde_sites(&files(&qualified)).len(),
            1,
            "限定名 `axum::Json<Dto>` 形态必须被抓到"
        );
    }

    /// 控制组：三条既有判据各自的合成违规
    #[test]
    fn contract_guard_catches_synthetic_violation() {
        let synth = concat!(
            "pub async fn save(...) -> Result<Json<serde_json::Value>, AppError> {\n",
            "    Ok(Json(serde_json::json!({ \"code\": 200, \"msg\": \"ok\" })))\n",
            "}\n",
        );
        let hits = contract_hits(synth);
        assert_eq!(
            hits.len(),
            2,
            "合成违规必须被抓到两条（裸 Json 返回型 + 手搓 code 体），实际: {hits:?}"
        );
        // 合规形态不得报
        assert!(
            contract_hits(
                "pub async fn save(...) -> Result<AjaxResult<SavedVo>, AppError> {\n    Ok(AjaxResult::success(vo))\n}"
            )
            .is_empty()
        );
    }

    #[test]
    fn projection_guard_catches_synthetic_violation() {
        // ① 未投影就取行 ⇒ 必须报
        let bad = concat!(
            "let rows = sys_user::Entity::find()\n",
            "    .filter(UserColumn::Status.eq(\"0\"))\n",
            "    .all(db)\n",
            "    .await?;\n",
        );
        assert_eq!(
            unprojected_user_loads(bad).len(),
            1,
            "合成未投影取行必须被抓到，实际: {:?}",
            unprojected_user_loads(bad)
        );
        // ② 投影后取行 ⇒ 不报（判据不是"禁止查用户表"）
        let good = concat!(
            "let rows = sys_user::Entity::find()\n",
            "    .select_only()\n",
            "    .column(UserColumn::Email)\n",
            "    .all(db)\n",
            "    .await?;\n",
        );
        assert!(unprojected_user_loads(good).is_empty(), "投影形态被误报");
        // ③ 只 count 不取行 ⇒ 不报（凭据列不进内存）
        let count_only = concat!(
            "let n = sys_user::Entity::find()\n",
            "    .filter(UserColumn::DelFlag.ne(\"2\"))\n",
            "    .count(db)\n",
            "    .await?;\n",
        );
        assert!(
            unprojected_user_loads(count_only).is_empty(),
            "count 形态被误报（不取行，无泄露面）"
        );
        // ④ 同文件里"先投影取行、后 count"混合：投影那条不报、未投影那条报
        let mixed = format!("{good}{count_only}{bad}");
        assert_eq!(
            unprojected_user_loads(&mixed).len(),
            1,
            "混合形态必须逐条定位，实际: {:?}",
            unprojected_user_loads(&mixed)
        );
    }

    #[test]
    fn single_source_guard_catches_synthetic_copy() {
        let synth = vec![
            (
                "src/common/redact.rs".to_string(),
                r#"regex::Regex::new(r"(?P<boundary>^|\s)(?:/(?:var|etc)(?:/[A-Za-z0-9._-]+)+)+|[A-Za-z]:[\\/]")"#.to_string(),
            ),
            (
                "src/handler/other.rs".to_string(),
                r#"static COPY: &str = r"[A-Za-z]:[\\/](?:[A-Za-z0-9._-]+[\\/]?)+";"#.to_string(),
            ),
        ];
        let impls = abs_path_impl_files(&synth);
        assert_eq!(
            impls,
            vec![
                "src/common/redact.rs".to_string(),
                "src/handler/other.rs".to_string()
            ],
            "复制的第二处必须被抓到（否则本锁只证明「第一处存在」）"
        );
    }

    /// 判据 5 本体（批八十五）：DTO 的线上字段名必须显式声明。
    ///
    /// 立案实证：`AiReplayDto { pub history_id: i64 }` 没有 `rename_all`，而
    /// `views/ai/panel/index.vue` 发 `{historyId}` ⇒ **AI 面板的"重放"按钮自上线起每次都
    /// 400 `error.common.parse_failed`**，而两套件从没点过它（该端点登记的理由还写着"需要真实
    /// AI provider 凭据"，实际 `AiService::replay` 只重跑库里存的 SQL、一次网络都不发）。
    /// 全仓 48 个被 `Validated*` 消费的 DTO 里只有这一处漏了 camelCase，也就是说：
    /// 这条约定此前**只存在于其它 47 个文件的写法里**，没有任何判据钉住，所以"漏一个"是静默的。
    #[test]
    fn dto_field_wire_names_must_be_declared() {
        let files = src_line_files();
        let dtos = validated_extractor_dtos(&files);
        // 非零探针：采集面为空时"0 违规"毫无意义（同 `live_garde_dtos > 40` 那条纪律）
        assert!(
            dtos.len() > 40,
            "被 Validated* 消费的 DTO 数异常偏小（实际 {}），提取器识别或遍历失效",
            dtos.len()
        );
        let hits = dto_wire_shape_hits(&files);
        assert!(
            hits.is_empty(),
            "存在未声明线上名的 snake_case 字段:\n{}",
            hits.join("\n")
        );
        // 真实文件正控（AGENTS《门禁全景》⑬：锁的输入非空与锁的结论是两件事）：
        // 本批修掉的那个 DTO 必须**在采集面里**且被定位到——否则上面那个 0 可能是"没扫到它"。
        assert!(
            dtos.contains("AiReplayDto"),
            "AiReplayDto 被 ValidatedJson 消费，必须在本锁采集面里（不在=采集面漏项，这条锁是虚锁）"
        );
        let shape = struct_wire_shape(&files, "AiReplayDto");
        let Some((rel, attrs, body)) = shape else {
            panic!("AiReplayDto 定义定位失败：判据读不到它的形状，那个 0 不算证据");
        };
        assert_eq!(rel, "src/ai/handler.rs", "定位到的文件应当是 ai handler");
        assert!(
            attrs.contains("rename_all"),
            "AiReplayDto 必须带容器级 rename_all（属性块实得：{attrs}）"
        );
        assert!(
            body.iter().any(|l| l.contains("history_id")),
            "体内必须看得到 history_id 字段（体实得：{body:?}）"
        );
    }

    /// 控制组：四种"看着像违规"的合规写法必须不报，三种真违规形状必须报。
    /// 没有这一组，判据可以退化成"一律报"或"一律不报"而自检照样绿（AGENTS《门禁全景》⑥）。
    #[test]
    fn dto_wire_shape_guard_catches_synthetic_violations() {
        // ① 裸 snake_case 字段 ⇒ 必须报
        let s1 = r#"
pub struct BadDto {
    #[garde(range(min = 1))]
    pub history_id: i64,
}
async fn h(ValidatedJson(dto): ValidatedJson<BadDto>) {}
"#;
        assert_eq!(
            dto_wire_shape_hits(&[("src/x.rs".to_string(), prod_lines(s1))]).len(),
            1,
            "① 未声明线上名的 snake 字段必须被抓到"
        );
        // ② 容器级 camelCase ⇒ 不报（正控：同一字段只是加了声明）
        let s2 = r#"
#[serde(rename_all = "camelCase")]
pub struct GoodDto {
    pub history_id: i64,
}
async fn g(ValidatedJson(dto): ValidatedJson<GoodDto>) {}
"#;
        assert!(
            dto_wire_shape_hits(&[("src/y.rs".to_string(), prod_lines(s2))]).is_empty(),
            "② 容器级 rename_all 必须视为已声明"
        );
        // ③ 逐字段 rename ⇒ 不报
        let s3 = r#"
pub struct AliasDto {
    #[serde(rename = "historyId")]
    pub history_id: i64,
}
async fn a(ValidatedQuery(dto): ValidatedQuery<AliasDto>) {}
"#;
        assert!(
            dto_wire_shape_hits(&[("src/z.rs".to_string(), prod_lines(s3))]).is_empty(),
            "③ 字段级 rename 必须视为已声明（且 ValidatedQuery 也要在判据面里）"
        );
        // ④ 逐字段 alias（双向接受）⇒ 不报
        let s4 = r#"
pub struct BothDto {
    #[serde(alias = "history_id")]
    pub history_id: i64,
}
async fn b(ValidatedJson(dto): ValidatedJson<BothDto>) {}
"#;
        assert!(
            dto_wire_shape_hits(&[("src/w.rs".to_string(), prod_lines(s4))]).is_empty(),
            "④ 字段级 alias 必须视为已声明"
        );
        // ⑤ 字段名本来就没有下划线 ⇒ 不报（防把整族 DTO 都误伤）
        let s5 = r#"
pub struct PlainDto {
    pub question: String,
}
async fn p(ValidatedJson(dto): ValidatedJson<PlainDto>) {}
"#;
        assert!(
            dto_wire_shape_hits(&[("src/v.rs".to_string(), prod_lines(s5))]).is_empty(),
            "⑤ 无下划线字段不得误报"
        );
        // ⑥ 属性**换行书写**不得让 DTO 带着 rename_all 却被判违规（格式不得决定判定）
        let s6 = r#"
#[serde(
    rename_all = "camelCase"
)]
pub struct WrappedDto {
    pub job_group: String,
}
async fn w(ValidatedJson(dto): ValidatedJson<WrappedDto>) {}
"#;
        assert!(
            dto_wire_shape_hits(&[("src/u.rs".to_string(), prod_lines(s6))]).is_empty(),
            "⑥ 跨行属性里的 rename_all 必须被认出来"
        );
        // ⑦ 消费了却找不到定义 ⇒ 必须点名（不得静默跳过：跳过=这项永不判）
        let s7 = r#"
async fn m(ValidatedJson(dto): ValidatedJson<GhostDto>) {}
"#;
        let hits7 = dto_wire_shape_hits(&[("src/t.rs".to_string(), prod_lines(s7))]);
        assert!(
            hits7.len() == 1 && hits7[0].contains("GhostDto"),
            "⑦ 定位不到定义的 DTO 必须响亮报，实际: {hits7:?}"
        );
        // ⑧ 泛型形参 `T` 不是 DTO（提取器自身的 impl 会命中，误收就是每个文件一条假阳性）
        let s8 = r#"
impl<T, S> FromRequest<S> for ValidatedJson<T>
where T: DeserializeOwned + garde::Validate<Context = ()> {
    type Rejection = AppError;
}
"#;
        assert!(
            validated_extractor_dtos(&[("src/s.rs".to_string(), prod_lines(s8))]).is_empty(),
            "⑧ 泛型形参 T 不得被当成 DTO"
        );
        // ⑨ 同一 DTO 多处消费只判一次（否则一处违规报 N 遍，人会把重复当成"多处缺陷"）
        let s9 = r#"
pub struct TwiceDto {
    pub page_num: i64,
}
async fn t1(ValidatedJson(dto): ValidatedJson<TwiceDto>) {}
async fn t2(ValidatedJson(dto): ValidatedJson<TwiceDto>) {}
"#;
        assert_eq!(
            dto_wire_shape_hits(&[("src/r.rs".to_string(), prod_lines(s9))]).len(),
            1,
            "⑨ 同一 DTO 必须只报一条"
        );
        // ⑩ 限定名 `mod::Dto` 必须按**最后一段**取 DTO（本仓有一处就这么写）。
        //    截成模块名的后果是双向的：一边误报"定位不到定义"，一边把真 DTO 静默放出门采集面。
        let s10 = r#"
pub struct QdDto {
    pub base_url: String,
}
async fn q(ValidatedJson(dto): ValidatedJson cfg::QdDto) {}
"#;
        let s10 = s10.replace("ValidatedJson cfg::QdDto", "ValidatedJson<cfg::QdDto>");
        let files10 = vec![("src/q.rs".to_string(), prod_lines(&s10))];
        let names10 = validated_extractor_dtos(&files10);
        assert!(
            names10.contains("QdDto") && !names10.contains("cfg"),
            "⑩ 限定名必须解析成 DTO 本体，实得 {names10:?}"
        );
        assert_eq!(
            dto_wire_shape_hits(&files10).len(),
            1,
            "⑩ 限定名背后的真 DTO 必须仍被判定（这里它是违规的）"
        );
    }
}
