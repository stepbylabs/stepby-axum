// stepby-axum/src/repository/sys_task.rs
//! sys_task 数据访问层（任务进度中心表）
//!
//! 继承 BaseRepository 通用 CRUD，扩展任务进度特有查询：
//! - 多条件分页查询（task_type / status / operator / 时间范围）
//! - 按 ID 查询
//! - 批量删除
//! - 更新进度

use chrono::NaiveDateTime;
use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::sort::SortOrder;
use crate::entity::sys_task::{ActiveModel, Column, Entity as SysTask, Model};
use crate::repository::base::BaseRepository;

/// 任务进度 Repository
#[derive(Clone)]
pub struct SysTaskRepository {
    base: BaseRepository<SysTask>,
}

impl SysTaskRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    /// 未结束态（可以被推进/落终态的状态）。
    ///
    /// 取值集合与前端 `TaskProgress` 的"进行中"过滤**同源**（`pending` / `running`），
    /// 终态即 `success` / `failed`——两侧各写一份必然漂，故这里只登记"未结束"那一侧，
    /// 新状态默认按"未结束"处理（漏登记的结果是进度被拒绝写入，而不是终态被覆盖）。
    pub const OPEN_STATUSES: &'static [&'static str] = &["pending", "running"];

    /// 多条件分页查询
    ///
    /// 多租户 Phase 2：tenant_scope=Some(tid) 仅返回本租户任务；None（平台 0）不过滤。
    ///
    /// `sort`：动态排序（方案 B，白名单已在 service 层解析为 `SortOrder`）；
    /// `None` 时回退默认 `create_time DESC`。
    #[allow(clippy::too_many_arguments)]
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        task_type: Option<&str>,
        status: Option<&str>,
        operator: Option<&str>,
        begin_time: Option<NaiveDateTime>,
        end_time: Option<NaiveDateTime>,
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = SysTask::find();
        if let Some(t) = tenant_scope {
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(tt) = task_type {
            query = query.filter(Column::TaskType.eq(tt));
        }
        if let Some(st) = status {
            query = query.filter(Column::Status.eq(st));
        }
        if let Some(op) = operator {
            // 安全：调用 like_escape 转义 %/_ 通配符，防止用户输入 % 匹配全表
            query = query
                .filter(Column::Operator.like(format!("%{}%", crate::common::like_escape(op))));
        }
        if let Some(begin) = begin_time {
            query = query.filter(Column::CreateTime.gte(begin));
        }
        if let Some(end) = end_time {
            query = query.filter(Column::CreateTime.lte(end));
        }

        let total = query.clone().count(self.base.db()).await?;
        // 动态排序（白名单已解析）或默认 create_time 倒序
        let rows = match sort {
            Some(s) => query.order_by(s.column, s.dir),
            None => query.order_by_desc(Column::CreateTime),
        }
        .offset(offset)
        .limit(limit)
        .all(self.base.db())
        .await?;
        Ok((rows, total))
    }

    /// 按 ID 查询
    pub async fn find_by_id(&self, task_id: i64) -> Result<Option<Model>, DbErr> {
        SysTask::find_by_id(task_id).one(self.base.db()).await
    }

    /// 按 ID 批查（b71 N+1 治理：delete_tasks 的租户校验由循环逐个 find_by_id 收敛为一次批查）
    pub async fn find_by_ids(&self, task_ids: Vec<i64>) -> Result<Vec<Model>, DbErr> {
        SysTask::find()
            .filter(Column::TaskId.is_in(task_ids))
            .all(self.base.db())
            .await
    }

    /// 插入一条记录
    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    // 刻意**不提供**整行 `update`：整行覆盖的前提是"我读到的那一行到现在还是它"，
    // 而本表恰恰有两个执行者会并发推进同一行——把已落终态的行又改回 `running`，
    // 进度条倒着走且没有任何错误。状态类写入只有下面两条带未结束态谓词的通道
    // （b144 A5；HEAD 曾留一个"与其它 repository 的 CRUD 面一致"的裸 `update`，
    //  实测生产码与测试**零调用点**，于是按"删掉可能性的载体"而不是"钉住用法"处置）。
    //
    // b145 收掉 b144 §7 N-144-G 登记的另一半：`pub fn base()` 访问器**已删**。
    // 它把 `BaseRepository<SysTask>` 整个交出去，而后者自带整行 `update(model)`——
    // 于是"只剩两条受闸通道"这句话当时靠的是"没人调用"，不是"结构上不可能"；
    // 谓词形状锁也抓不到这个逃逸形状（那条锁扫 `update_many(`，而它写的是 `.base().update(`）。
    // 取证（HEAD 口径实测）：全仓 158 处 `.base()` 无一指向 `SysTaskRepository`，
    // 该类型只在 `service/sys_task_service.rs` 被持有，而那个文件内零处 `.base()`。
    // 现在字段 `base` 是私有的、无公有访问器 ⇒ 结构性不可能；由
    // `sys_task_repository_exposes_no_raw_base_handle` 钉住"不得再长回来"。

    /// 进度推进（**仅当行仍处于未结束态**）——b144 A5。
    ///
    /// 为什么用条件 UPDATE 而不是"读出来判断再写回"：读与写之间没有任何锁，两个执行者
    /// （归档任务本体与它的超时兜底、重试的第二次投递）都能各自读到 `running`、各自写回，
    /// 后写的一方把已经落终态的行又改成 `running`——进度条从"已完成"倒着走回去，且没有任何
    /// 错误。把判断放进 `WHERE status IN (未结束态)`，判断与写就是**同一个原子决定**
    /// （AGENTS A.1 第三条的正解：不需要额外一把锁，也不需要赌没有并发）。
    ///
    /// 返回 `Ok(None)` = 没有行被写（行不存在，或已被别的执行者落终态）。调用方据此
    /// **不覆盖、不推 WS**——推送会把前端浮层的已完成条重新点亮。
    pub async fn advance_progress_if_open(
        &self,
        task_id: i64,
        progress: i32,
        current: i64,
        total: i64,
        now: NaiveDateTime,
    ) -> Result<Option<Model>, DbErr> {
        let res = SysTask::update_many()
            .col_expr(Column::Status, Expr::value("running".to_string()))
            .col_expr(Column::Progress, Expr::value(progress))
            .col_expr(Column::Current, Expr::value(current))
            .col_expr(Column::Total, Expr::value(total))
            .col_expr(Column::UpdateTime, Expr::value(Some(now)))
            .filter(Column::TaskId.eq(task_id))
            .filter(Column::Status.is_in(Self::OPEN_STATUSES.iter().copied()))
            .exec(self.base.db())
            .await?;
        if res.rows_affected == 0 {
            return Ok(None);
        }
        // 回读取"写完之后的真实行"（值由调用方计算，这里只是把结果交回去）
        self.find_by_id(task_id).await
    }

    /// 落终态（**仅当行仍处于未结束态**）——b144 A5。语义同上。
    ///
    /// `result_msg` 传 `None` 表示"不改写既有结果消息"（`col_expr` 只在需要写时追加）。
    pub async fn settle_if_open(
        &self,
        task_id: i64,
        status: &str,
        progress: i32,
        current: i64,
        result_msg: Option<String>,
        now: NaiveDateTime,
    ) -> Result<Option<Model>, DbErr> {
        let mut upd = SysTask::update_many()
            .col_expr(Column::Status, Expr::value(status.to_string()))
            .col_expr(Column::Progress, Expr::value(progress))
            .col_expr(Column::Current, Expr::value(current))
            .col_expr(Column::UpdateTime, Expr::value(Some(now)));
        if let Some(msg) = result_msg {
            upd = upd.col_expr(Column::ResultMsg, Expr::value(Some(msg)));
        }
        let res = upd
            .filter(Column::TaskId.eq(task_id))
            .filter(Column::Status.is_in(Self::OPEN_STATUSES.iter().copied()))
            .exec(self.base.db())
            .await?;
        if res.rows_affected == 0 {
            return Ok(None);
        }
        self.find_by_id(task_id).await
    }

    /// 批量删除（物理删除）
    pub async fn delete_by_ids(&self, ids: Vec<i64>) -> Result<DeleteResult, DbErr> {
        SysTask::delete_many()
            .filter(Column::TaskId.is_in(ids))
            .exec(self.base.db())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 双引号字符串字面量替换成**等长**空白（掩码后仍按 char 下标切片）。
    /// 必要性（b144 在 `link-audit` 上立的同一条）：配平不得读字面量里的括号——
    /// 一句 `"{bad"` 就能让深度永不归零，整段函数区间一个都产不出来，于是
    /// "扫不到"被读成"没有违规"。未闭合的引号**不掩码**（安全方向：宁可多算代码）。
    fn mask_literals(text: &str) -> Vec<char> {
        let chars: Vec<char> = text.chars().collect();
        let mut out = chars.clone();
        let mut i = 0usize;
        while i < chars.len() {
            if chars[i] == '"' {
                let mut j = i + 1;
                let mut closed = false;
                while j < chars.len() {
                    if chars[j] == '\\' {
                        j += 2;
                        continue;
                    }
                    if chars[j] == '"' {
                        closed = true;
                        break;
                    }
                    j += 1;
                }
                if closed {
                    for slot in &mut out[i..=j] {
                        if !slot.is_whitespace() {
                            *slot = ' ';
                        }
                    }
                    i = j + 1;
                    continue;
                }
            }
            i += 1;
        }
        out
    }

    /// 由掩码后的字符流取 `(函数名, 函数体)` 段。函数名取不到时记 `<unknown@偏移>`，
    /// 让红出来的文案能指到位置而不是把人支使去猜（AGENTS ⑨）。
    fn fn_segments(masked: &[char]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 3 <= masked.len() {
            if !(masked[i] == 'f' && masked[i + 1] == 'n' && masked[i + 2] == ' ') {
                i += 1;
                continue;
            }
            // 必须是声明位置：本行 `fn` 之前只允许空白与可见性/限定词
            let mut ls = i;
            while ls > 0 && masked[ls - 1] != '\n' {
                ls -= 1;
            }
            let prefix: String = masked[ls..i].iter().collect();
            let prefix = prefix.trim();
            let declared = prefix.is_empty()
                || prefix.split_whitespace().all(|w| {
                    [
                        "pub", "async", "unsafe", "const", "extern", "default", "safe",
                    ]
                    .contains(&w)
                        || w.starts_with("pub(")
                });
            if !declared {
                i += 3;
                continue;
            }
            let name: String = masked[i + 3..]
                .iter()
                .take_while(|c| c.is_alphanumeric() || **c == '_')
                .collect();
            // 函数体起点：签名之后的第一个 `{`（先遇到 `;` 则是函数指针/_trait_ 声明，跳过）
            let mut open = i + 3;
            while open < masked.len() && masked[open] != '{' && masked[open] != ';' {
                open += 1;
            }
            if open >= masked.len() || masked[open] != '{' {
                i = open + 1;
                continue;
            }
            let mut depth = 0usize;
            let mut end = open;
            let mut scan = open;
            while scan < masked.len() {
                match masked[scan] {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = scan;
                            break;
                        }
                    }
                    _ => {}
                }
                scan += 1;
            }
            out.push((
                if name.is_empty() {
                    format!("<unknown@{i}>")
                } else {
                    name
                },
                masked[open..=end].iter().collect(),
            ));
            i = end + 1;
        }
        out
    }

    /// 纯函数：返回「对本表做批量更新、却没带未结束态谓词」的函数名。
    ///
    /// 判据取**函数段**而不是"文件里出现过谓词"：同一文件别处有一条谓词，对这条写路径
    /// 毫无意义（AGENTS ㉘/66(c)：存在一次 ≠ 每个入口）。谓词只认 `Status.is_in(`
    /// 这一个事实——它正是两条咽喉方法共用的形态。
    fn unguarded_task_updates(segments: &[(String, String)]) -> Vec<String> {
        segments
            .iter()
            .filter(|(_, body)| body.contains("update_many(") && !body.contains("Status.is_in("))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// 生产码里对 sys_task 的批量更新**只有两条咽喉**：`advance_progress_if_open` 与
    /// `settle_if_open`。新增第三条不带未结束态谓词的写路径 ⇒ "读出来判断再写回"复活，
    /// 进度会从"已完成"倒着走回 `running` 且没有任何错误（b144 A5 立案的原形状）。
    #[test]
    fn every_task_bulk_update_carries_the_open_status_predicate() {
        let scan = crate::common::prod_scan::Scan {
            comments: crate::common::prod_scan::Comments::Drop,
            ..Default::default()
        };
        let mut offenders: Vec<String> = Vec::new();
        let mut gated = 0usize;
        let mut surface = 0usize;
        for f in crate::common::prod_scan::prod_files(&scan) {
            // 采集面由"这份文件引用了本表的实体"派生，不按文件名枚举（别名一出现
            // 按名字的锁整片失效——b140 §3 的同一条）
            if !f.text().contains("entity::sys_task") {
                continue;
            }
            surface += 1;
            let masked = mask_literals(&f.text());
            let segs = fn_segments(&masked);
            offenders.extend(
                unguarded_task_updates(&segs)
                    .into_iter()
                    .map(|name| format!("{}::{name}", f.rel)),
            );
            gated += segs
                .iter()
                .filter(|(_, b)| b.contains("update_many(") && b.contains("Status.is_in("))
                .count();
        }
        assert!(
            offenders.is_empty(),
            "以下函数对本表做批量更新却没有未结束态谓词（读-判断-写不是同一个原子决定）：\
             {offenders:?}"
        );
        assert!(
            surface >= 3,
            "采集面自证失效：引用本表实体的生产文件只有 {surface} 个（地板 3）——\
             是扫描口径坏了，不是『没有违规』"
        );
        assert!(
            gated >= 2,
            "带谓词的更新只数到 {gated} 条（期望 ≥2 = 两条咽喉）：此时『0 违规』不代表任何东西"
        );
    }

    /// 纯函数：定义侧是否把 `BaseRepository<…>` 整块交了出去。
    ///
    /// 只认「公有 + 返回裸 `&BaseRepository<`」这一个形状：私有字段与返回受闸视图的
    /// 访问器都不算（否则会把别的仓储一起判红，或者一个类型注解就绕过去）。
    fn hands_out_base_repository(text: &str) -> bool {
        text.lines().any(|l| {
            let t = l.trim_start();
            t.starts_with("pub fn") && t.contains("-> &BaseRepository<")
        })
    }

    /// b145 收 b144 N-144-G：本表仓储**不得**再暴露 `base()` 访问器。
    ///
    /// 上一把锁判的是"批量更新必须带谓词"，但它扫的是 `update_many(`——把整行 `update`
    /// 的载体交出去的那条路写的是 `.base().update(`，形状锁看不见它（b144 §7 原话：
    /// "只剩两条受闸通道"当时靠的是**没人调用**，不是**结构上不可能**）。
    /// 访问器已删，这条锁保证它不会被"为了跟别的仓储保持一致"再加回来。
    #[test]
    fn sys_task_repository_exposes_no_raw_base_handle() {
        let scan = crate::common::prod_scan::Scan {
            comments: crate::common::prod_scan::Comments::Drop,
            ..Default::default()
        };
        // 采集面由"这份文件定义了本表仓储"派生，不按文件名写死（改名/拆分都要能跟上）
        let owners: Vec<_> = crate::common::prod_scan::prod_files(&scan)
            .into_iter()
            .filter(|f| f.text().contains("pub struct SysTaskRepository"))
            .collect();
        assert!(
            !owners.is_empty(),
            "采集面自证失效：生产码里找不到定义 `SysTaskRepository` 的文件 ⇒ \
             本锁一条都没判就绿了（改名或整段删除都要先让它红）"
        );
        for f in &owners {
            assert!(
                !hands_out_base_repository(&f.text()),
                "{} 又把 `BaseRepository<SysTask>` 交了出去（公有 `-> &BaseRepository<` 访问器）：\
                 整行 update 的载体回归，谓词锁的覆盖面重新变成『靠没人调用』",
                f.rel
            );
        }
        // 双向：缺陷形状必抓
        assert!(
            hands_out_base_repository(
                "impl R {\n    pub fn base(&self) -> &BaseRepository<SysTask> { &self.base }\n}\n"
            ),
            "合成违规没被抓到 ⇒ 判据坏"
        );
        // 合规形状不得误报：私有字段、以及返回受闸视图（非裸句柄）的访问器
        assert!(
            !hands_out_base_repository(
                "impl R {\n    base: BaseRepository<SysTask>,\n    pub fn db(&self) -> &DatabaseConnection { self.base.db() }\n}\n"
            ),
            "合规形状被误判 ⇒ 每轮必红，结局是被放宽"
        );
    }

    /// 本锁自己必须可证伪：合成"没有谓词"必须被抓、合成"有谓词"不得误报，
    /// 且字面量里不成对的括号不得让整段区间消失（掩码失效的形状）。
    #[test]
    fn task_update_gate_judge_is_falsifiable() {
        let bad = "impl R {\n    pub async fn touch(&self) {\n        SysTask::update_many().col_expr(Column::Status, Expr::value(\"running\")).exec(db).await;\n    }\n}\n";
        assert_eq!(
            unguarded_task_updates(&fn_segments(&mask_literals(bad))),
            vec![String::from("touch")],
            "无谓词的批量更新必须被点名（点不到即虚锁）"
        );
        let good = "impl R {\n    pub async fn touch(&self) {\n        SysTask::update_many().filter(Column::Status.is_in(OPEN_STATUSES)).exec(db).await;\n    }\n}\n";
        assert!(
            unguarded_task_updates(&fn_segments(&mask_literals(good))).is_empty(),
            "带谓词的更新不得报红（否则每轮必红，结局是被放宽）"
        );
        let tricky = "impl R {\n    pub async fn touch(&self) {\n        let s = \"{bad\";\n        SysTask::update_many().col_expr(Column::Status, Expr::value(s)).exec(db).await;\n    }\n}\n";
        assert_eq!(
            unguarded_task_updates(&fn_segments(&mask_literals(tricky))),
            vec![String::from("touch")],
            "字面量里不成对的左花括号不得让配平走偏（b144 link-audit 同一条教训）"
        );
        // 反证：掩码失效时 `"{bad"` 的 `{` 会吃掉函数段 ⇒ 上一条必须能抓到；这里再证
        // "读不到的函数体不得被算成合规"——把 update_many 写进字符串里必须**不**进面
        let in_string = "impl R {\n    pub async fn note(&self) {\n        let s = \"SysTask::update_many( no predicate here )\";\n        db.exec(s).await;\n    }\n}\n";
        assert!(
            unguarded_task_updates(&fn_segments(&mask_literals(in_string))).is_empty(),
            "写在字符串里的形状不得算生产写路径（掩码后不存在）"
        );
    }

    /// 跨语言镜像：注释声称"取值集合与前端 TaskProgress 的进行中过滤同源"，那就让判据去读
    /// 前端（AGENTS 铁律：派生记录的成立前提不得只在注释里声明）。
    ///
    /// 漂了的后果不是"数据旧"：多出来的状态服务端认为未结束却不被浮层显示（进度看不见），
    /// 少掉的状态浮层一直转（用户以为任务还在跑）。读语义不读字节（AGENTS ⑰）：采集面只取
    /// **集合运算行**（`.filter(` / `.some(` / `.every(`）里的 `status === 'a' || status === 'b'`，
    /// `case 'pending':`、单个 `status === 'success'` 与模板里的 `v-if` 展示判断都不参与
    /// ——见下面的采集面说明与 `status_or_groups` 的双向用例。
    #[test]
    fn open_statuses_match_frontend_task_progress_filter() {
        let mirror = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../stepby-vue/src/components/TaskProgress/index.vue");
        let raw = std::fs::read_to_string(&mirror).unwrap_or_else(|e| {
            panic!(
                "读不到前端镜像 {}：{e}（判据源缺失必须响亮失败，不得静默跳过）",
                mirror.display()
            )
        });
        // 只数代码里的比较，注释里的示例不得进面：先剔 `/* */` 与 `//` 行
        let no_block = raw.replace("/*", "  ").replace("*/", "  ");
        let text: String = no_block
            .lines()
            .map(|l| {
                let cut = l.find("//").unwrap_or(l.len());
                &l[..cut]
            })
            .collect::<Vec<_>>()
            .join("\n");
        // 采集面只取「集合运算行里的 `status === 'a' || status === 'b'`」——那才是
        // "未结束态"过滤的形状。两次自曝都记在这里，因为它们是同一族：
        // ① 第一版取**所有** `status === '<lit>'`，于是把展示分支里的
        //    `t.status === 'success'` / `'failed'` 也算进"进行中"集合，报出
        //    「前端 [failed, pending, running, success] vs 后端 [pending, running]」；
        // ② 第二版按 `||` 手工续链时要求下一段**以标记开头**，而前端写的是
        //    `t.status === 'pending' || t.status === 'running'`——右操作数带接收者前缀 `t.`，
        //    链在第一步就断，于是真文件**一组都取不到**（红在解析通道上，不是红在漂移上）。
        // 两次都是判据自己的采集面假设坏了，两侧事实本来一致
        // （AGENTS ⑯(c)：前提不成立的判据不是"弱判据"，是每轮产出误导话的负资产；
        //  照着第一句提示去"把 success/failed 也变成未结束态"就是把手腕砍在错的地方）。
        let groups = status_or_groups(&text);
        assert!(
            !groups.is_empty(),
            "前端一处『集合运算行里的 status || 组』都没取到 ⇒ 采集口径腐化（锚点或切段坏了），本次对账不作数"
        );
        let mut back: Vec<String> = SysTaskRepository::OPEN_STATUSES
            .iter()
            .map(|s| String::from(*s))
            .collect();
        back.sort();
        for (i, g) in groups.iter().enumerate() {
            let mut got = g.clone();
            got.sort();
            got.dedup();
            assert_eq!(
                got, back,
                "第 {i} 组『进行中』过滤与后端 OPEN_STATUSES 不等（前端 {got:?} / 后端 {back:?}）"
            );
        }
    }

    /// 前端"状态集合运算"的锚点：只有出现在这些方法调用行里的 `status === 'a' || status === 'b'`
    /// 才是**集合声明**（"这一批算哪一类"）。模板里的 `v-if="task.status === 'success' || …"`
    /// 是单个任务的展示判断，不是集合——把它并进对账就是把"渲染 4 种状态"读成"4 种都未结束"。
    const SET_OP_ANCHORS: [&str; 3] = [".filter(", ".some(", ".every("];

    /// 取 `MARKER` 之后那段引号内的字面量，返回内容与闭合引号的下一个位置。
    /// 空串或跨行（说明这不是一个正常字面量）一律 `None`。
    fn quoted_after_quote(text: &str, from: usize) -> Option<(String, usize)> {
        let close = text[from..].find('\'')?;
        let lit = &text[from..from + close];
        if lit.is_empty() || lit.contains('\n') {
            return None;
        }
        Some((lit.to_string(), from + close + 1))
    }

    /// 取「集合运算行里的 `status === 'a' || status === 'b'`」中的字面量组。
    ///
    /// 逐行推进、按 `||` 切段，每段各取一个字面量；**任一段取不到就不成组**
    /// （方向取"宁可少一组"，由调用侧的"一组都没取到 ⇒ 本次对账不作数"兜住，
    /// 而不是把半截链当成一个可信的集合）。组内少于 2 个也不成组（单个比较是展示判断）。
    fn status_or_groups(text: &str) -> Vec<Vec<String>> {
        const MARKER: &str = "status === '";
        let mut out: Vec<Vec<String>> = Vec::new();
        for line in text.lines() {
            if !SET_OP_ANCHORS.iter().any(|anchor| line.contains(anchor)) {
                continue;
            }
            let mut group: Vec<String> = Vec::new();
            let mut well_formed = true;
            for part in line.split("||") {
                let Some(at) = part.find(MARKER) else {
                    well_formed = false;
                    break;
                };
                match quoted_after_quote(part, at + MARKER.len()) {
                    Some((lit, _)) => group.push(lit),
                    None => {
                        well_formed = false;
                        break;
                    }
                }
            }
            if well_formed && group.len() >= 2 {
                out.push(group);
            }
        }
        out
    }

    /// 解析通道的双向用例：成组比较必须成组取出（**含右操作数带接收者前缀**这一形状，
    /// 它就是第二版失效的地方），单个比较、无锚点行、半截链与注释里的示例都不得进面。
    #[test]
    fn status_or_groups_parser_is_falsifiable() {
        let two = "const x = tasks.filter((t) => t.status === 'pending' || t.status === 'running')";
        assert_eq!(
            status_or_groups(two),
            vec![vec![String::from("pending"), String::from("running")]],
            "成组比较必须取出（取不到即解析通道失效）"
        );
        // 真文件的两条形状：`.some(` 与 `.filter(`，右操作数都写成 `t.status === …`
        let some = "visibleTasks.value.some((t: TaskInfo) => t.status === 'pending' || t.status === 'running')";
        assert_eq!(
            status_or_groups(some).len(),
            1,
            "`.some(` 一行必须取到恰一组（带前缀的右操作数不得断链）"
        );
        // 模板里的展示判断成对出现，但**不是**集合运算 ⇒ 不得进面（进了就把"渲染 4 种状态"
        // 读成"4 种都未结束"，这正是第一版的错）
        let tpl = "v-if=\"task.status === 'success' || task.status === 'failed'\"";
        assert!(
            status_or_groups(tpl).is_empty(),
            "无集合运算锚点的行不得算成状态集合"
        );
        // 半截链：三段里有一段不是状态比较 ⇒ 整行不成组（宁可少一组，不得把半截当集合）
        let half =
            "x.filter((t) => t.status === 'pending' || t.id === 1 || t.status === 'running')";
        assert!(
            status_or_groups(half).is_empty(),
            "混入非状态比较的链不得被读成一个状态集合"
        );
        let one = "if (t.status === 'success') { done() }";
        assert!(
            status_or_groups(one).is_empty(),
            "单个比较是展示分支，不是未结束态集合，必须不进面"
        );
        let commented = "// t.status === 'aaa' || t.status === 'bbb'\nconst real = 1; // .filter(";
        let masked = commented
            .lines()
            .map(|l| {
                let cut = l.find("//").unwrap_or(l.len());
                &l[..cut]
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            status_or_groups(&masked).is_empty(),
            "注释里的形状不得算前端事实（掩码后必须为空）"
        );
        // 锚点与字面量分处两行（多行链）：当前口径**不**合并，真文件没有这种形状；
        // 若将来出现，判据红在"一组都没取到"那条响亮失败上，而不是静默放行
        let multiline = "x.filter((t) =>\n  t.status === 'pending' ||\n  t.status === 'running'\n)";
        assert!(
            status_or_groups(multiline).is_empty(),
            "跨行链不在本口径视野内（已知局限：取不到即由上限兜住，不得猜成合规）"
        );
    }
}
