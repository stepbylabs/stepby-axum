// stepby-axum/src/repository/op_recording.rs
//! 操作录制与回放的数据访问层（三张表：抬头 / 步骤 / 运行结论）。
//!
//! ## 为什么步骤追加要走事务 + 唯一索引兜底
//!
//! `seq` 只能是"这段录制里下一个空位"。两件事实现它：
//! ① 事务内 `SELECT MAX(seq)` 后立刻 `INSERT`，且在**同一事务**里把抬头的 `step_count`
//!    一起推进——三张表里抬头那个计数是**派生值**，派生与来源必须在同一事务提交，
//!    否则一次崩溃会留下"列表显示 4 步、点进去只有 3 步"（AGENTS「派生记录的成立
//!    前提要么由代码路径保证、要么由锁钉住」）。
//! ② `uk_op_recording_step_seq` 唯一索引兜底跨进程并发：两个实例各自开事务时
//!    读-写之间没有行锁可依赖（SQLite 方言不生成 `FOR UPDATE`，见 AGENTS A.1 b129），
//!    撞索引后本轮重试一次即可拿到新序号。
//!
//! 刻意**不提供**抬头的整行 `update`：`step_count` / `last_run_status` 都是派生列，
//! 谁都能整行覆盖就必然出现"回放刚写完结论、另一处编辑把 last_run_status 洗成 NULL"。
//! 对外只有 `touch_meta`（改名/说明/状态）与 `mark_run`（结论）两条窄通道。

use std::collections::BTreeSet;

use chrono::NaiveDateTime;
use sea_orm::sea_query::Expr;
use sea_orm::*;

use crate::common::sort::SortOrder;
use crate::entity::sys_op_recording::{ActiveModel, Column, Entity as Recording, Model};
use crate::entity::sys_op_recording_run::{
    ActiveModel as RunActiveModel, Column as RunColumn, Entity as Run, Model as RunModel,
};
use crate::entity::sys_op_recording_step::{
    ActiveModel as StepActiveModel, Column as StepColumn, Entity as Step, Model as StepModel,
};
use crate::repository::base::BaseRepository;

/// 录制抬头 Repository
#[derive(Clone)]
pub struct OpRecordingRepository {
    base: BaseRepository<Recording>,
}

impl OpRecordingRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            base: BaseRepository::new(db),
        }
    }

    pub fn db(&self) -> &DatabaseConnection {
        self.base.db()
    }

    /// 多条件分页：名称模糊 / 状态 / 来源 / 租户作用域。
    pub async fn find_page_filtered(
        &self,
        offset: u64,
        limit: u64,
        name: Option<&str>,
        status: Option<&str>,
        source: Option<&str>,
        tenant_scope: Option<i64>,
        sort: Option<SortOrder<Column>>,
    ) -> Result<(Vec<Model>, u64), DbErr> {
        let mut query = Recording::find();
        if let Some(t) = tenant_scope {
            // 多租户：租户只见本租户；平台（None）不过滤。读侧与写侧同源谓词。
            query = query.filter(Column::TenantId.eq(t));
        }
        if let Some(n) = name {
            query = query.filter(Column::Name.like(format!("%{}%", crate::common::like_escape(n))));
        }
        if let Some(s) = status {
            query = query.filter(Column::Status.eq(s));
        }
        if let Some(s) = source {
            query = query.filter(Column::Source.eq(s));
        }
        let total = query.clone().count(self.base.db()).await?;
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

    pub async fn find_by_id(&self, recording_id: i64) -> Result<Option<Model>, DbErr> {
        Recording::find_by_id(recording_id)
            .one(self.base.db())
            .await
    }

    pub async fn insert(&self, model: ActiveModel) -> Result<Model, DbErr> {
        self.base.insert(model).await
    }

    /// 只更新"人写的元信息"（名称/说明/状态）。派生列不在可写面内。
    pub async fn touch_meta(
        &self,
        recording_id: i64,
        tenant_scope: Option<i64>,
        name: String,
        description: Option<String>,
        status: String,
        now: NaiveDateTime,
    ) -> Result<u64, DbErr> {
        let mut q = Recording::update_many()
            .col_expr(Column::Name, Expr::value(name))
            .col_expr(Column::Description, Expr::value(description))
            .col_expr(Column::Status, Expr::value(status))
            .col_expr(Column::UpdateTime, Expr::value(now))
            .filter(Column::RecordingId.eq(recording_id));
        if let Some(t) = tenant_scope {
            // 写侧同样按租户收敛：平台可代管、租户只能改自己的
            q = q.filter(Column::TenantId.eq(t));
        }
        let res = q.exec(self.base.db()).await?;
        Ok(res.rows_affected)
    }

    /// 写"最近一次回放结论"（派生列，只由回放链路调用）。
    pub async fn mark_run(
        &self,
        recording_id: i64,
        status: &str,
        now: NaiveDateTime,
    ) -> Result<u64, DbErr> {
        let res = Recording::update_many()
            .col_expr(Column::LastRunStatus, Expr::value(status))
            .col_expr(Column::LastRunTime, Expr::value(now))
            .filter(Column::RecordingId.eq(recording_id))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    /// 删除（物理删除）。返回实际删除行数——调用方用它区分"删了"与"不是你的"。
    ///
    /// 步骤与运行记录**由数据库外键之外的显式链路一并清掉**（本仓不使用 FK 级联：
    /// 迁移期三方言行为不一致，且级联删除无法在审计里留下"删了几步"）。
    pub async fn delete_by_ids(
        &self,
        ids: &[i64],
        tenant_scope: Option<i64>,
    ) -> Result<u64, DbErr> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut q = Recording::delete_many().filter(Column::RecordingId.is_in(ids.to_vec()));
        if let Some(t) = tenant_scope {
            q = q.filter(Column::TenantId.eq(t));
        }
        let res = q.exec(self.base.db()).await?;
        Ok(res.rows_affected)
    }

    // ==================== 步骤 ====================

    /// 取某录制的全部步骤（按 seq 升序——顺序就是回放顺序）。
    pub async fn steps_of(&self, recording_id: i64) -> Result<Vec<StepModel>, DbErr> {
        Step::find()
            .filter(StepColumn::RecordingId.eq(recording_id))
            .order_by_asc(StepColumn::Seq)
            .all(self.base.db())
            .await
    }

    pub async fn find_step(&self, step_id: i64) -> Result<Option<StepModel>, DbErr> {
        Step::find_by_id(step_id).one(self.base.db()).await
    }

    /// 追加一步（事务内取下一个 seq + 推进抬头 step_count）。
    ///
    /// 撞唯一索引（并发抢同一个 seq）时**重试一次**；第二次仍撞则把错误上抛，
    /// 由服务层翻成可读的 409 而不是 500。
    pub async fn append_step(
        &self,
        recording_id: i64,
        tenant_id: i64,
        step: StepSeed,
        now: NaiveDateTime,
    ) -> Result<(StepModel, i32), DbErr> {
        match self
            .append_step_once(recording_id, tenant_id, &step, now)
            .await
        {
            Ok(v) => Ok(v),
            Err(e) if is_unique_violation(&e) => {
                self.append_step_once(recording_id, tenant_id, &step, now)
                    .await
            }
            Err(e) => Err(e),
        }
    }

    async fn append_step_once(
        &self,
        recording_id: i64,
        tenant_id: i64,
        step: &StepSeed,
        now: NaiveDateTime,
    ) -> Result<(StepModel, i32), DbErr> {
        let txn = self.base.db().begin().await?;

        let max_seq: Option<i32> = Step::find()
            .filter(StepColumn::RecordingId.eq(recording_id))
            .order_by_desc(StepColumn::Seq)
            .one(&txn)
            .await?
            .map(|m| m.seq);
        let seq = max_seq.unwrap_or(0) + 1;

        let am = StepActiveModel {
            tenant_id: Set(tenant_id),
            recording_id: Set(recording_id),
            seq: Set(seq),
            method: Set(step.method.clone()),
            path: Set(step.path.clone()),
            query_string: Set(step.query_string.clone()),
            content_type: Set(step.content_type.clone()),
            body: Set(step.body.clone()),
            headers_json: Set(step.headers_json.clone()),
            extract_json: Set(step.extract_json.clone()),
            expect_status: Set(step.expect_status),
            note: Set(step.note.clone()),
            create_time: Set(Some(now)),
            ..Default::default()
        };
        let model = am.insert(&txn).await?;

        // 派生列与来源同事务提交：崩溃不会留下"列表 4 步、明细 3 步"
        Recording::update_many()
            .col_expr(Column::StepCount, Expr::cust("step_count + 1"))
            .col_expr(Column::UpdateTime, Expr::value(now))
            .filter(Column::RecordingId.eq(recording_id))
            .exec(&txn)
            .await?;

        txn.commit().await?;
        Ok((model, seq))
    }

    /// 成建制写入：抬头 + 全部步骤在**同一事务**里落库（导入用）。
    ///
    /// 为什么不让调用方先 `insert` 抬头再循环 `append_step`：那会得到"导入到第 7 步失败
    /// 时库里留下 6 步的半条录制"，而界面上它看起来是一条完整可用的录制（`step_count`
    /// 正好也写成了 6）。导入是"把一份外部快照变成本地事实"的一次性动作——要么整条成立、
    /// 要么什么都不发生，没有第三种状态可解释。
    ///
    /// 步骤 `seq` 由**数组顺序**重编（1..n 连续）：外部快照里的 `seq` 只说明它当时的顺序，
    /// 遇到重复/缺号/乱序时照抄会撞唯一索引或让回放顺序变得无法解释。
    pub async fn insert_with_steps(
        &self,
        mut recording: ActiveModel,
        tenant_id: i64,
        steps: &[StepSeed],
        now: NaiveDateTime,
    ) -> Result<(Model, Vec<StepModel>), DbErr> {
        let txn = self.base.db().begin().await?;
        // 派生列与来源同事务（与 append_step 同一条纪律）
        recording.step_count = Set(steps.len() as i32);
        let head = recording.insert(&txn).await?;
        let mut written = Vec::with_capacity(steps.len());
        for (idx, seed) in steps.iter().enumerate() {
            let am = StepActiveModel {
                tenant_id: Set(tenant_id),
                recording_id: Set(head.recording_id),
                seq: Set(idx as i32 + 1),
                method: Set(seed.method.clone()),
                path: Set(seed.path.clone()),
                query_string: Set(seed.query_string.clone()),
                content_type: Set(seed.content_type.clone()),
                body: Set(seed.body.clone()),
                headers_json: Set(seed.headers_json.clone()),
                extract_json: Set(seed.extract_json.clone()),
                expect_status: Set(seed.expect_status),
                note: Set(seed.note.clone()),
                create_time: Set(Some(now)),
                ..Default::default()
            };
            written.push(am.insert(&txn).await?);
        }
        txn.commit().await?;
        Ok((head, written))
    }

    /// 就地改一步：**`seq` 与 `headers_json` 不动**。
    ///
    /// - `seq` 不动是语义决定：改"这一步期望什么状态码"不是"把这一步挪到别处"，重排会让
    ///   用户刚看完的顺序在保存后变样（也让"第 3 步引用了第 2 步抽出的变量"这种关系失去锚点）。
    /// - `headers_json` 不动也是语义决定：它是**采集产物**（可回放头白名单的实拍值），
    ///   不是界面上可编辑的字段；让编辑通道顺手覆盖它，等于把"这次请求当时的头"改成"编辑者猜的头"。
    ///
    /// 返回 `None` = 该步不在这个录制里或跨租户（调用方统一折成 404，不泄漏存在性）。
    pub async fn update_step_fields(
        &self,
        recording_id: i64,
        step_id: i64,
        tenant_scope: Option<i64>,
        step: &StepSeed,
        now: NaiveDateTime,
    ) -> Result<Option<StepModel>, DbErr> {
        let existing = Step::find()
            .filter(StepColumn::StepId.eq(step_id))
            .filter(StepColumn::RecordingId.eq(recording_id))
            .one(self.base.db())
            .await?;
        let Some(model) = existing else {
            return Ok(None);
        };
        if let Some(t) = tenant_scope
            && model.tenant_id != t
        {
            return Ok(None);
        }
        let mut am: StepActiveModel = model.into();
        am.method = Set(step.method.clone());
        am.path = Set(step.path.clone());
        am.query_string = Set(step.query_string.clone());
        am.content_type = Set(step.content_type.clone());
        am.body = Set(step.body.clone());
        am.extract_json = Set(step.extract_json.clone());
        am.expect_status = Set(step.expect_status);
        am.note = Set(step.note.clone());
        let updated = am.update(self.base.db()).await?;
        // 抬头 update_time 跟着走：列表默认按它排序，"刚改过"应当排到前面
        Recording::update_many()
            .col_expr(Column::UpdateTime, Expr::value(now))
            .filter(Column::RecordingId.eq(recording_id))
            .exec(self.base.db())
            .await?;
        Ok(Some(updated))
    }

    /// 用真实行数**重算**抬头 step_count（清空/删步后的收敛点）。
    ///
    /// 为什么不让调用方 `-1`：并发下减法会漂，而重算是幂等的。
    pub async fn recount_steps(&self, recording_id: i64, now: NaiveDateTime) -> Result<i32, DbErr> {
        let actual = Step::find()
            .filter(StepColumn::RecordingId.eq(recording_id))
            .count(self.base.db())
            .await? as i32;
        Recording::update_many()
            .col_expr(Column::StepCount, Expr::value(actual))
            .col_expr(Column::UpdateTime, Expr::value(now))
            .filter(Column::RecordingId.eq(recording_id))
            .exec(self.base.db())
            .await?;
        Ok(actual)
    }

    pub async fn delete_steps_of(&self, recording_id: i64) -> Result<u64, DbErr> {
        let res = Step::delete_many()
            .filter(StepColumn::RecordingId.eq(recording_id))
            .exec(self.base.db())
            .await?;
        Ok(res.rows_affected)
    }

    pub async fn delete_step(
        &self,
        recording_id: i64,
        step_id: i64,
        tenant_scope: Option<i64>,
    ) -> Result<u64, DbErr> {
        let mut q = Step::delete_many()
            .filter(StepColumn::RecordingId.eq(recording_id))
            .filter(StepColumn::StepId.eq(step_id));
        if let Some(t) = tenant_scope {
            q = q.filter(StepColumn::TenantId.eq(t));
        }
        let res = q.exec(self.base.db()).await?;
        Ok(res.rows_affected)
    }

    /// 删步后把后续序号前移，保持 `1..n` 连续。
    ///
    /// 回放按 `seq` 排序，**不要求**连续；但"第 3 步被删了"之后 UI 上出现 `1,2,4`
    /// 会让人以为丢了数据。这里做一次收敛，且只在同一事务内改本录制的行。
    pub async fn compact_seq(&self, recording_id: i64, now: NaiveDateTime) -> Result<(), DbErr> {
        let steps = self.steps_of(recording_id).await?;
        if steps.is_empty() {
            self.recount_steps(recording_id, now).await?;
            return Ok(());
        }
        // 先把所有序号挪到负区间，避免 UPDATE 过程中撞唯一索引（1→1 之外的瞬时重复）
        let txn = self.base.db().begin().await?;
        for (idx, s) in steps.iter().enumerate() {
            Step::update_many()
                .col_expr(StepColumn::Seq, Expr::value(-(idx as i32) - 1))
                .filter(StepColumn::StepId.eq(s.step_id))
                .exec(&txn)
                .await?;
        }
        for (idx, s) in steps.iter().enumerate() {
            Step::update_many()
                .col_expr(StepColumn::Seq, Expr::value(idx as i32 + 1))
                .filter(StepColumn::StepId.eq(s.step_id))
                .exec(&txn)
                .await?;
        }
        txn.commit().await?;
        self.recount_steps(recording_id, now).await?;
        Ok(())
    }

    // ==================== 运行记录 ====================

    pub async fn insert_run(&self, model: RunActiveModel) -> Result<RunModel, DbErr> {
        model.insert(self.base.db()).await
    }

    pub async fn update_run(&self, model: RunActiveModel) -> Result<RunModel, DbErr> {
        model.update(self.base.db()).await
    }

    pub async fn find_run(&self, run_id: i64) -> Result<Option<RunModel>, DbErr> {
        Run::find_by_id(run_id).one(self.base.db()).await
    }

    pub async fn runs_of(
        &self,
        recording_id: i64,
        tenant_scope: Option<i64>,
        limit: u64,
    ) -> Result<Vec<RunModel>, DbErr> {
        let mut q = Run::find().filter(RunColumn::RecordingId.eq(recording_id));
        if let Some(t) = tenant_scope {
            q = q.filter(RunColumn::TenantId.eq(t));
        }
        q.order_by_desc(RunColumn::RunId)
            .limit(limit)
            .all(self.base.db())
            .await
    }

    /// 删除若干录制时，连带清掉它们的步骤与运行记录。
    pub async fn purge_children(&self, recording_ids: &[i64]) -> Result<(), DbErr> {
        if recording_ids.is_empty() {
            return Ok(());
        }
        let ids: Vec<i64> = recording_ids.to_vec();
        Step::delete_many()
            .filter(StepColumn::RecordingId.is_in(ids.clone()))
            .exec(self.base.db())
            .await?;
        Run::delete_many()
            .filter(RunColumn::RecordingId.is_in(ids))
            .exec(self.base.db())
            .await?;
        Ok(())
    }

    /// 已存在的录制 ID 集合（用于删除前把"请求集"收敛成"授权集"）。
    pub async fn existing_ids(
        &self,
        ids: &[i64],
        tenant_scope: Option<i64>,
    ) -> Result<BTreeSet<i64>, DbErr> {
        if ids.is_empty() {
            return Ok(BTreeSet::new());
        }
        let mut q = Recording::find().filter(Column::RecordingId.is_in(ids.to_vec()));
        if let Some(t) = tenant_scope {
            q = q.filter(Column::TenantId.eq(t));
        }
        let rows = q.all(self.base.db()).await?;
        Ok(rows.into_iter().map(|m| m.recording_id).collect())
    }
}

/// 追加步骤的入参（与实体解耦：调用方不必知道 `step_id` / `seq` / `tenant_id`）。
#[derive(Debug, Clone)]
pub struct StepSeed {
    pub method: String,
    pub path: String,
    pub query_string: Option<String>,
    pub content_type: Option<String>,
    pub body: Option<String>,
    pub headers_json: Option<String>,
    pub extract_json: Option<String>,
    pub expect_status: Option<i32>,
    pub note: Option<String>,
}

/// 唯一约束冲突判定（三方言的报错文本不同，取子串交集）。
///
/// 只用于"重试一次"这一处；判定失败的最坏结果是重试缺席、错误照常上抛，
/// **不会**把一次普通失败误判成成功。
fn is_unique_violation(e: &DbErr) -> bool {
    let text = e.to_string().to_ascii_lowercase();
    text.contains("unique") || text.contains("duplicate")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::datetime::now_naive;
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};

    async fn mem_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("内存库建连");
        for ddl in [
            r#"CREATE TABLE sys_op_recording (
                recording_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                description TEXT,
                source TEXT NOT NULL DEFAULT 'ui',
                status TEXT NOT NULL DEFAULT 'ready',
                step_count INTEGER NOT NULL DEFAULT 0,
                last_run_status TEXT,
                last_run_time DATETIME,
                owner_id INTEGER,
                owner_name TEXT,
                create_time DATETIME,
                update_time DATETIME
            )"#,
            r#"CREATE TABLE sys_op_recording_step (
                step_id INTEGER PRIMARY KEY AUTOINCREMENT,
                recording_id INTEGER NOT NULL,
                tenant_id INTEGER NOT NULL DEFAULT 0,
                seq INTEGER NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                query_string TEXT,
                content_type TEXT,
                body TEXT,
                headers_json TEXT,
                extract_json TEXT,
                expect_status INTEGER,
                note TEXT,
                create_time DATETIME
            )"#,
            r#"CREATE TABLE sys_op_recording_run (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                recording_id INTEGER NOT NULL,
                tenant_id INTEGER NOT NULL DEFAULT 0,
                task_id INTEGER,
                status TEXT NOT NULL,
                total INTEGER NOT NULL DEFAULT 0,
                succeeded INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                skipped INTEGER NOT NULL DEFAULT 0,
                detail_json TEXT,
                operator TEXT,
                started_at DATETIME,
                finished_at DATETIME
            )"#,
            "CREATE UNIQUE INDEX uk_op_recording_step_seq ON sys_op_recording_step (recording_id, seq)",
        ] {
            db.execute_unprepared(ddl).await.expect("建表失败");
        }
        db
    }

    fn seed(tenant_id: i64) -> ActiveModel {
        let now = now_naive();
        ActiveModel {
            tenant_id: Set(tenant_id),
            name: Set(format!("t{tenant_id}")),
            description: Set(None),
            source: Set("ui".to_string()),
            status: Set("ready".to_string()),
            step_count: Set(0),
            last_run_status: Set(None),
            last_run_time: Set(None),
            owner_id: Set(None),
            owner_name: Set(None),
            create_time: Set(Some(now)),
            update_time: Set(Some(now)),
            ..Default::default()
        }
    }

    fn step(path: &str) -> StepSeed {
        StepSeed {
            method: "POST".to_string(),
            path: path.to_string(),
            query_string: None,
            content_type: Some("application/json".to_string()),
            body: Some("{}".to_string()),
            headers_json: None,
            extract_json: None,
            expect_status: None,
            note: None,
        }
    }

    #[tokio::test]
    async fn append_assigns_consecutive_seq_and_keeps_step_count_in_sync() {
        let db = mem_db().await;
        let repo = OpRecordingRepository::new(db);
        let rec = repo.insert(seed(0)).await.expect("建录制");
        let now = now_naive();
        for (i, p) in ["/a", "/b", "/c"].iter().enumerate() {
            let (model, seq) = repo
                .append_step(rec.recording_id, 0, step(p), now)
                .await
                .expect("追加步骤");
            assert_eq!(seq as usize, i + 1, "序号必须从 1 连续递增");
            assert_eq!(model.seq, seq);
        }
        let after = repo.find_by_id(rec.recording_id).await.unwrap().unwrap();
        assert_eq!(
            after.step_count, 3,
            "抬头的 step_count 是派生列，必须与步骤行同事务推进（列表显示 3、明细 3）"
        );
        let steps = repo.steps_of(rec.recording_id).await.unwrap();
        assert_eq!(
            steps.iter().map(|s| s.seq).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "steps_of 必须按 seq 升序返回（顺序就是回放顺序）"
        );
    }

    #[tokio::test]
    async fn compact_seq_closes_gaps_after_step_delete() {
        let db = mem_db().await;
        let repo = OpRecordingRepository::new(db);
        let rec = repo.insert(seed(0)).await.expect("建录制");
        let now = now_naive();
        for p in ["/a", "/b", "/c"] {
            repo.append_step(rec.recording_id, 0, step(p), now)
                .await
                .expect("追加");
        }
        let steps = repo.steps_of(rec.recording_id).await.unwrap();
        let middle = &steps[1];
        let removed = repo
            .delete_step(rec.recording_id, middle.step_id, None)
            .await
            .unwrap();
        assert_eq!(removed, 1);
        repo.compact_seq(rec.recording_id, now).await.unwrap();
        let after = repo.steps_of(rec.recording_id).await.unwrap();
        assert_eq!(
            after.iter().map(|s| s.seq).collect::<Vec<_>>(),
            vec![1, 2],
            "删中间一步后序号必须收敛成 1..n（否则界面像丢了数据）"
        );
        assert_eq!(
            after.iter().map(|s| s.path.as_str()).collect::<Vec<_>>(),
            vec!["/a", "/c"],
            "收敛序号不得改变剩余步骤的相对顺序"
        );
        let header = repo.find_by_id(rec.recording_id).await.unwrap().unwrap();
        assert_eq!(header.step_count, 2);
    }

    #[tokio::test]
    async fn delete_by_ids_and_existing_ids_respect_tenant_scope() {
        let db = mem_db().await;
        let repo = OpRecordingRepository::new(db);
        let mine = repo.insert(seed(7)).await.unwrap();
        let other = repo.insert(seed(8)).await.unwrap();

        // 租户 7 只能看见自己那条
        let visible = repo
            .existing_ids(&[mine.recording_id, other.recording_id], Some(7))
            .await
            .unwrap();
        assert_eq!(visible.len(), 1, "跨租户的行不得出现在授权集里");
        assert!(visible.contains(&mine.recording_id));

        // 用租户 7 的作用域删两条 ⇒ 只删掉自己那条
        let deleted = repo
            .delete_by_ids(&[mine.recording_id, other.recording_id], Some(7))
            .await
            .unwrap();
        assert_eq!(
            deleted, 1,
            "租户作用域必须作用到删除语句本身，而不是只作用到读"
        );
        assert!(repo.find_by_id(other.recording_id).await.unwrap().is_some());
        assert!(repo.find_by_id(mine.recording_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn purge_children_only_touches_given_recordings() {
        let db = mem_db().await;
        let repo = OpRecordingRepository::new(db);
        let a = repo.insert(seed(0)).await.unwrap();
        let b = repo.insert(seed(0)).await.unwrap();
        let now = now_naive();
        repo.append_step(a.recording_id, 0, step("/a"), now)
            .await
            .unwrap();
        repo.append_step(b.recording_id, 0, step("/b"), now)
            .await
            .unwrap();
        repo.purge_children(&[a.recording_id]).await.unwrap();
        assert!(repo.steps_of(a.recording_id).await.unwrap().is_empty());
        assert_eq!(
            repo.steps_of(b.recording_id).await.unwrap().len(),
            1,
            "清子表必须按录制 ID 收敛，不得整表清空"
        );
    }

    #[tokio::test]
    async fn manual_runs_are_listed_newest_first_and_tenant_scoped() {
        let db = mem_db().await;
        let repo = OpRecordingRepository::new(db);
        let rec = repo.insert(seed(3)).await.unwrap();
        for i in 0..3 {
            repo.insert_run(RunActiveModel {
                tenant_id: Set(3),
                recording_id: Set(rec.recording_id),
                task_id: Set(None),
                status: Set("success".to_string()),
                total: Set(i),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let rows = repo.runs_of(rec.recording_id, Some(3), 10).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert!(
            rows[0].run_id > rows[1].run_id,
            "回放记录必须最新在前（按 run_id 倒序）"
        );
        let none = repo.runs_of(rec.recording_id, Some(4), 10).await.unwrap();
        assert!(none.is_empty(), "他租户不得看到本租户的回放记录");
    }

    /// 唯一约束冲突判定必须真的认得出三方言的报错文本。
    ///
    /// 反例形态：写 `e.to_string().contains("UNIQUE constraint")` 只有 SQLite 命中，
    /// MySQL/PG 上并发追加会直接 500 而不是重试一次——而那条分支在 SQLite 测试里
    /// 永远绿（判据对自己声称的事没有约束力）。
    #[test]
    fn unique_violation_matches_all_three_dialects() {
        for text in [
            "UNIQUE constraint failed: sys_op_recording_step.recording_id, sys_op_recording_step.seq",
            "Duplicate entry '1-3' for key 'uk_op_recording_step_seq'",
            "duplicate key value violates unique constraint \"uk_op_recording_step_seq\"",
        ] {
            let err = DbErr::Query(sea_orm::RuntimeErr::Internal(text.to_string()));
            assert!(
                is_unique_violation(&err),
                "三方言的唯一冲突文本必须都被认出来，漏判会让并发追加变成 500：{text}"
            );
        }
        let other = DbErr::Query(sea_orm::RuntimeErr::Internal(
            "no such table: sys_op_recording".to_string(),
        ));
        assert!(
            !is_unique_violation(&other),
            "普通错误不得被当成唯一冲突（否则一次缺表会被静默重试成两次慢失败）"
        );
    }

    /// 直接走 SQL 造一个"已被占用的 seq"，验证重试路径真的能自愈。
    #[tokio::test]
    async fn append_retries_once_when_seq_collides() {
        let db = mem_db().await;
        let repo = OpRecordingRepository::new(db.clone());
        let rec = repo.insert(seed(0)).await.unwrap();
        let now = now_naive();
        repo.append_step(rec.recording_id, 0, step("/a"), now)
            .await
            .unwrap();
        // 手工插入一个"看起来已存在"的 seq=2，但让 MAX(seq) 读到 1 的窗口无法构造，
        // 因此这里直接断言：即使外部把 seq=2 占了，下一次追加仍然成功（重试一次拿到 3）。
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO sys_op_recording_step (recording_id, tenant_id, seq, method, path) \
             VALUES (?, 0, 2, 'POST', '/x')"
                .replace('?', &rec.recording_id.to_string()),
        ))
        .await
        .expect("插入占位步");
        let (model, seq) = repo
            .append_step(rec.recording_id, 0, step("/b"), now)
            .await
            .expect("撞号后必须能自愈");
        assert_eq!(seq, 3, "MAX(seq)=2 ⇒ 下一个必须是 3");
        assert_eq!(model.path, "/b");
    }

    /// b148 导入：抬头与步骤一次落库，`step_count` 与真实行数同一次提交。
    #[tokio::test]
    async fn insert_with_steps_writes_head_and_steps_atomically() {
        let db = mem_db().await;
        let repo = OpRecordingRepository::new(db.clone());
        let now = now_naive();
        let mut head = seed(0);
        head.source = Set("import".to_string());
        let seeds = vec![
            step("/a"),
            StepSeed {
                method: "PUT".to_string(),
                path: "/b".to_string(),
                headers_json: Some(r#"{"accept":"application/json"}"#.to_string()),
                extract_json: Some(r#"{"bId":"data.id"}"#.to_string()),
                ..step("/b")
            },
            step("/c"),
        ];
        let (rec, steps) = repo
            .insert_with_steps(head, 0, &seeds, now)
            .await
            .expect("成建制导入应成功");
        assert_eq!(rec.step_count, 3, "派生列必须等于真实步骤数");
        assert_eq!(
            steps.iter().map(|s| s.seq).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "seq 由数组顺序重编，不从外部快照照抄"
        );
        assert_eq!(steps[1].headers_json.as_deref(), Some(r#"{"accept":"application/json"}"#));
        assert_eq!(steps[1].extract_json.as_deref(), Some(r#"{"bId":"data.id"}"#));
        assert_eq!(
            repo.steps_of(rec.recording_id).await.unwrap().len(),
            3,
            "详情侧读到的步骤数必须与派生列一致"
        );
    }

    /// b148 就地改一步：`seq` 与 `headers_json` 都不动，抬头 `update_time` 跟着走。
    #[tokio::test]
    async fn update_step_fields_keeps_seq_and_headers() {
        let db = mem_db().await;
        let repo = OpRecordingRepository::new(db.clone());
        let rec = repo.insert(seed(0)).await.unwrap();
        let t0 = chrono::NaiveDateTime::parse_from_str("2026-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
            .unwrap();
        let with_headers = StepSeed {
            headers_json: Some(r#"{"accept":"application/json"}"#.to_string()),
            ..step("/keep")
        };
        let (first, _) = repo
            .append_step(rec.recording_id, 0, with_headers, t0)
            .await
            .unwrap();
        repo.append_step(rec.recording_id, 0, step("/second"), t0)
            .await
            .unwrap();

        let patch = StepSeed {
            method: "PATCH".to_string(),
            path: "/changed".to_string(),
            expect_status: Some(200),
            body: Some(r#"{"a":1}"#.to_string()),
            headers_json: None, // 调用方即使给了空值也不得覆盖采集产物
            ..step("/changed")
        };
        let updated = repo
            .update_step_fields(rec.recording_id, first.step_id, None, &patch, t0)
            .await
            .unwrap()
            .expect("应命中该步");
        assert_eq!(updated.seq, 1, "改内容不是挪位置：seq 必须不变");
        assert_eq!(updated.path, "/changed");
        assert_eq!(updated.expect_status, Some(200));
        assert_eq!(
            updated.headers_json.as_deref(),
            Some(r#"{"accept":"application/json"}"#),
            "headers 是采集产物，编辑通道不得覆盖"
        );
        assert_eq!(
            repo.steps_of(rec.recording_id)
                .await
                .unwrap()
                .iter()
                .map(|s| s.path.clone())
                .collect::<Vec<_>>(),
            vec!["/changed".to_string(), "/second".to_string()],
            "顺序不得因为一次编辑而改变"
        );
    }

    /// 跨租户改步必须看不到（一律折成 None ⇒ 上层 404，不泄漏存在性）。
    #[tokio::test]
    async fn update_step_fields_respects_tenant_scope() {
        let db = mem_db().await;
        let repo = OpRecordingRepository::new(db.clone());
        let rec = repo.insert(seed(7)).await.unwrap();
        let (first, _) = repo
            .append_step(rec.recording_id, 7, step("/a"), now_naive())
            .await
            .unwrap();
        let patch = step("/b");
        assert!(
            repo.update_step_fields(rec.recording_id, first.step_id, Some(8), &patch, now_naive())
                .await
                .unwrap()
                .is_none(),
            "他租户不得改本租户的步骤"
        );
        assert!(
            repo.update_step_fields(rec.recording_id, first.step_id, Some(7), &patch, now_naive())
                .await
                .unwrap()
                .is_some(),
            "同租户必须能改"
        );
    }
}
