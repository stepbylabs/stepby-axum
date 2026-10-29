// stepby-axum/src/repository/sys_webhook_event.rs
//! WebHook 事件目录（sys_webhook_event 表）数据访问层
//!
//! 提供事件目录分页（过滤 + 动态排序白名单）、按 event_key 存在性校验
//! （订阅字段写入前的合法性闸门）。

use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::like_escape;
use crate::common::sort::SortOrder;
use crate::entity::sys_webhook_event::{Column, Entity as SysWebhookEvent, Model};

/// 事件目录 Repository
#[derive(Clone)]
pub struct SysWebhookEventRepository {
    db: DatabaseConnection,
}

impl SysWebhookEventRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// 分页查询事件目录（可选 event_key 模糊 / name 模糊 / enabled 精确过滤 + 动态排序）
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        event_key: Option<&str>,
        name: Option<&str>,
        enabled: Option<&str>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysWebhookEvent::find();
        // b132：与全仓 28 个 repository 同口径——模糊匹配必须走 like_escape。
        // 原 `.contains()` 把用户输入原样拼进 LIKE：搜一个 `%` 就命中整张表
        // （`%%%`），计数与分页跟着失真；这里统一转义（`_` 的取舍见 like_escape 文档）。
        if let Some(k) = event_key.filter(|s| !s.trim().is_empty()) {
            query = query.filter(Column::EventKey.like(format!("%{}%", like_escape(k.trim()))));
        }
        if let Some(n) = name.filter(|s| !s.trim().is_empty()) {
            query = query.filter(Column::Name.like(format!("%{}%", like_escape(n.trim()))));
        }
        if let Some(e) = enabled.filter(|s| !s.trim().is_empty()) {
            query = query.filter(Column::Enabled.eq(e.trim()));
        }
        let total = query.clone().count(&self.db).await?;
        let query = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_asc(Column::Id),
        };
        let rows = query.offset(offset).limit(limit).all(&self.db).await?;
        Ok((rows, total))
    }

    /// 按 event_key 查询目录事件（存在性校验 / 样例构造）
    pub async fn find_by_event_key(&self, event_key: &str) -> Result<Option<Model>, DbErr> {
        SysWebhookEvent::find()
            .filter(Column::EventKey.eq(event_key))
            .one(&self.db)
            .await
    }

    /// 按 event_key 批量查询目录事件（订阅写入前的批量合法性闸门）
    ///
    /// 订阅校验一次最多 `MAX_SUBSCRIBED_EVENT_KEYS` 个键，逐键查询会把一次保存变成
    /// N 次往返；目录键是精确匹配，`is_in` 与逐键 `eq` 结果集合相同。
    pub async fn find_by_event_keys(&self, event_keys: &[String]) -> Result<Vec<Model>, DbErr> {
        if event_keys.is_empty() {
            return Ok(Vec::new());
        }
        SysWebhookEvent::find()
            .filter(Column::EventKey.is_in(event_keys.to_vec()))
            .all(&self.db)
            .await
    }

    /// 更新目录事件 enabled（目录下架展示并拒绝新订阅；派发链不查目录，存量 hook 不中断）
    ///
    /// 返回影响行数（0 = 事件不存在，由调用方转 404）。
    pub async fn update_enabled(&self, id: i64, enabled: &str) -> Result<u64, DbErr> {
        let res = SysWebhookEvent::update_many()
            .col_expr(Column::Enabled, Expr::value(enabled.to_string()))
            .filter(Column::Id.eq(id))
            .exec(&self.db)
            .await?;
        Ok(res.rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::prod_scan::{self, Comments, Scan};
    use crate::entity::sys_webhook_event::ActiveModel;
    use crate::repository::test_support::migrated_db;

    async fn seeded_repo() -> SysWebhookEventRepository {
        let db = migrated_db().await.unwrap();
        let repo = SysWebhookEventRepository::new(db.clone());
        for (key, name) in [
            ("b132probe.alpha", "b132 探针甲"),
            ("b132probe.beta", "b132 探针乙"),
            ("b132probe.gamma", "b132 探针丙"),
        ] {
            SysWebhookEvent::insert(ActiveModel {
                event_key: Set(key.to_string()),
                name: Set(name.to_string()),
                description: Set(None),
                payload_example: Set(None),
                enabled: Set("1".to_string()),
                created_at: Set(None),
                updated_at: Set(None),
                ..Default::default()
            })
            .exec(&db)
            .await
            .unwrap();
        }
        repo
    }

    /// 通配符注入：`%` 搜索不得枚举全表（缺陷形状的活体对照 + 修复后的两条通道）
    #[tokio::test]
    async fn wildcard_search_cannot_enumerate_the_whole_table() {
        let repo = seeded_repo().await;
        let total_rows = SysWebhookEvent::find().count(&repo.db).await.unwrap();
        assert!(
            total_rows >= 3,
            "夹具必须真的有多行（种子事件 + 3 条探针），否则「没有匹配」证明不了任何事"
        );

        // 缺陷形状的活体对照：未转义的 LIKE 会被一个 `%` 命中整表。
        // 没有这一条，被测路径返回 0 行也可能是「表本来就空」或「条件写坏了」。
        let unescaped = SysWebhookEvent::find()
            .filter(Column::EventKey.contains("%"))
            .count(&repo.db)
            .await
            .unwrap();
        assert_eq!(unescaped, total_rows, "未转义 `%` 必须命中整表");

        // 修复后的仓库路径：event_key / name 两条通道都不得被通配符放大。
        let (rows, total) = repo
            .find_page_filtered(0, 20, Some("%"), None, None, None)
            .await
            .unwrap();
        assert_eq!(
            (rows.len() as u64, total),
            (0, 0),
            "event_key 通道被 `%` 枚举"
        );
        let (rows, total) = repo
            .find_page_filtered(0, 20, None, Some("%"), None, None)
            .await
            .unwrap();
        assert_eq!((rows.len() as u64, total), (0, 0), "name 通道被 `%` 枚举");
    }

    /// 正常关键字搜索照常可用（转义不得把真结果一起挡掉）
    #[tokio::test]
    async fn normal_keyword_search_still_returns_matching_rows() {
        let repo = seeded_repo().await;
        let (rows, total) = repo
            .find_page_filtered(0, 20, Some("b132probe."), None, None, None)
            .await
            .unwrap();
        assert_eq!(total, 3, "前缀搜索应命中 3 条探针");
        assert_eq!(
            rows.len() as u64,
            total,
            "total 与实际行数必须一致（分页契约）"
        );

        let (rows, total) = repo
            .find_page_filtered(0, 20, None, Some("探针乙"), None, None)
            .await
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0].event_key, "b132probe.beta");

        // 组合条件（精确 event_key + enabled）不受转义改动影响
        let (_, total) = repo
            .find_page_filtered(0, 20, Some("b132probe.alpha"), Some("1"), None, None)
            .await
            .unwrap();
        assert_eq!(total, 1);
    }

    /// 判据：一行归一化文本里有哪些「Repository 模糊搜索未走 like_escape」的违规
    ///
    /// 两条腿：① `Column::*.contains(`（SeaORM 自带 `%value%` 拼接，无法转义）；
    /// ② `.like(...)` 的实参里出现 `format!` 却没有 `like_escape`。
    /// `.like` 按**括号配对**取整段实参，所以 rustfmt 折行不会让它失效（行级判据会被排版骗过）。
    fn fuzzy_violations(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        // 第一版把 needle 写成 `Column::` 紧跟 `.contains(`（漏了列名本身）
        // ⇒ 结构上永远打不中，而真实树照样全绿。判据必须先被自己的正控抓到。
        let contains_re = regex::Regex::new(r"Column::[A-Za-z0-9_]+\s*\.\s*contains\s*\(").unwrap();
        for m in contains_re.find_iter(text) {
            let start = text[..m.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let end = text[m.end()..]
                .find('\n')
                .map(|i| m.end() + i)
                .unwrap_or(text.len());
            out.push(format!("Column::*.contains: {}", text[start..end].trim()));
        }
        let mut from = 0usize;
        while let Some(pos) = text[from..].find(".like(").map(|i| from + i) {
            let open = pos + ".like".len();
            let mut depth = 0i32;
            let mut close = None;
            for (off, ch) in text[open..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(open + off);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close) = close else {
                out.push(format!(
                    ".like( 实参括号未闭合（采集面坏了）: {}",
                    text[pos..(pos + 80).min(text.len())].trim()
                ));
                break;
            };
            let arg = &text[open + 1..close];
            if arg.contains("format!(") && !arg.contains("like_escape(") {
                out.push(format!(
                    ".like(format! 未转义: {}",
                    &text[pos..(close + 1).min(text.len())]
                ));
            }
            from = close + 1;
        }
        out
    }

    /// 形状锁：Repository 层不得再用未转义的模糊匹配
    ///
    /// 采集面 = `src` 生产码视图（剥 `#[cfg(test)]`、注释置空）里的 `src/repository/*.rs`。
    /// 真实树必须 0 违规；`fuzzy_violation_detector_is_falsifiable` 钉住判据本身能转红。
    #[test]
    fn repository_fuzzy_search_must_go_through_like_escape() {
        let cfg = Scan::default();
        let repos: Vec<prod_scan::ProdFile> = prod_scan::prod_files(&cfg)
            .into_iter()
            .filter(|f| f.rel.starts_with("src/repository/"))
            .collect();
        // 采集面自证：少扫了文件与「扫完是干净的」在报告里同形。
        prod_scan::require_volume(&repos, 45, 8_000, "repository 模糊搜索形状锁");

        let mut violations = Vec::new();
        let mut like_sites = 0usize;
        for f in &repos {
            let text = f.text();
            like_sites += text.matches(".like(").count();
            for v in fuzzy_violations(&text) {
                violations.push(format!("{}: {}", f.rel, v));
            }
        }
        assert!(
            like_sites >= 40,
            "LIKE 调用点只数到 {like_sites} 处（下限 40）⇒ 判据的采集面坏了，不是「没有违规」"
        );
        assert!(
            violations.is_empty(),
            "Repository 模糊搜索必须走 like_escape（{} 处）:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }

    /// 形状锁自检：双向 + 排版无关 + 注释/集合 `contains` 不误报
    #[test]
    fn fuzzy_violation_detector_is_falsifiable() {
        let cfg = Scan {
            comments: Comments::Blank,
            ..Scan::default()
        };
        // 缺陷形状（第二条故意折行）必须被抓
        let bad = r#"fn f() {
    let a = Column::Name.contains(k);
    let b = Column::EventKey
        .like(format!("%{}%", raw));
}
"#;
        let hits = fuzzy_violations(&prod_scan::normalize(bad, &cfg).join("\n"));
        assert_eq!(hits.len(), 2, "两类违规各一条，实测 {hits:?}");
        assert!(hits[0].contains("Column::*.contains"));
        assert!(hits[1].contains(".like(format! 未转义"));

        // 合规反例：转义后 / 集合 contains / 注释里的字面量都不得报
        let good = r#"fn f() {
    // 历史写法 Column::Name.contains(k) 已废弃
    let a = Column::Name.like(format!("%{}%", like_escape(k)));
    let b = held.contains(&id);
    let c = format!("%{}%", like_escape(name));
    let d = Column::Name.eq(k);
}
"#;
        let text = prod_scan::normalize(good, &cfg).join("\n");
        assert_eq!(fuzzy_violations(&text), Vec::<String>::new());

        // 同一行从注释改成代码就必须红（证明上面「不误报」不是把整类形态一起关了）
        let same_line_as_code = "fn f() {\n    let a = Column::Name.contains(k);\n}\n";
        assert_eq!(
            fuzzy_violations(&prod_scan::normalize(same_line_as_code, &cfg).join("\n")).len(),
            1
        );
    }
}
