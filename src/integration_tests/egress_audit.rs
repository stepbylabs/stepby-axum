//! b137：数据外带 GET 出口的**审计落库**端到端判据（`common::egress_audit`）。
//!
//! 为什么必须放在 HTTP 栈上：`record_egress` 是 fire-and-forget（`spawn_tracked`），
//! 公共件的单测只能证明"装配出的记录字段对、四条处理器都调了它"；「审计真的落进
//! `sys_oper_log`」与「失败路径确实不落审计」只有真实请求 + 真实库才看得见。
//! 三个 GET 出口各一条用例；备份下载（第四条）由 `sys_backup.rs` 的
//! `test_backup_chain` 在同一次真实下载之后断言（那里才有可下载的备份文件）。
//!
//! 断言口径（与 `common::egress_audit` 模块文档同源）：
//! - `status='0'`、`request_method='GET'`、`method`=路由模板、`oper_url` **不含查询串**；
//! - `title` 是可读的模块归类 key（`module.auditChange` / `module.operlog` / `module.ai`）；
//! - `oper_param` 记"导出了哪个子集"，`json_result` 记外带量（行数/字节数/对象 key）；
//! - **失败不落审计**：404 的下载不得在审计面留下任何行。

use std::time::Duration;

use axum::http::{Method, StatusCode};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};

use super::TestContext;
use crate::entity::sys_oper_log;
use crate::service::sys_oper_log_service::ARCHIVE_STORAGE_DIR;

/// 查某个精确 `oper_url` 的外带审计行（GET 方法，按 oper_id 升序）。
async fn rows_once(ctx: &TestContext, oper_url: &str) -> Vec<sys_oper_log::Model> {
    sys_oper_log::Entity::find()
        .filter(sys_oper_log::Column::RequestMethod.eq("GET"))
        .filter(sys_oper_log::Column::OperUrl.eq(oper_url))
        .order_by_asc(sys_oper_log::Column::OperId)
        .all(&ctx.state.db)
        .await
        .expect("查询外带审计行失败")
}

/// 全部 GET 审计行的 `(oper_url, title)`——只在超时 panic 里用，
/// 否则"一行都没写"与"写成了别的标题/URL"在报错里同形。
async fn all_get_rows(ctx: &TestContext) -> Vec<(Option<String>, Option<String>)> {
    sys_oper_log::Entity::find()
        .filter(sys_oper_log::Column::RequestMethod.eq("GET"))
        .order_by_asc(sys_oper_log::Column::OperId)
        .all(&ctx.state.db)
        .await
        .map(|rows| rows.into_iter().map(|r| (r.oper_url, r.title)).collect())
        .unwrap_or_default()
}

/// 轮询到落定（写库由 `spawn_tracked` 异步完成），返回该 URL 的全部审计行。
///
/// - `min_rows > 0`：轮询到"至少这么多"，再给 80ms 稳定窗口重读一次——重复写入
///   （例如处理器被误调两次）会在这一拍内出现，只读一次会把"两条"漏成"一条"。
/// - `min_rows == 0`：只给 150ms 落定窗口。`record_oper_log` 的首次尝试是**立即执行**的，
///   150ms 足以让"错误地在失败路径写审计"暴露出来，不必按上限空等。
pub(super) async fn settled_egress_rows(
    ctx: &TestContext,
    oper_url: &str,
    min_rows: usize,
) -> Vec<sys_oper_log::Model> {
    if min_rows == 0 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        return rows_once(ctx, oper_url).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let rows = rows_once(ctx, oper_url).await;
        if rows.len() >= min_rows {
            tokio::time::sleep(Duration::from_millis(80)).await;
            return rows_once(ctx, oper_url).await;
        }
        if tokio::time::Instant::now() >= deadline {
            let all = all_get_rows(ctx).await;
            panic!(
                "3s 内没有等到 {oper_url} 的外带审计行（需要 {min_rows} 条，现有 GET 审计: {all:?}）"
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// 通用字段断言：审计面必须能回答"谁、从哪、用什么方法、带走了什么"。
fn assert_common_audit_shape(
    record: &sys_oper_log::Model,
    expected_title: &str,
    expected_method: &str,
) {
    assert_eq!(
        record.title.as_deref(),
        Some(expected_title),
        "模块归类必须可读（module.* key）: {record:?}"
    );
    assert_eq!(
        record.method.as_deref(),
        Some(expected_method),
        "method 必须是路由模板（与限流档位同口径）: {record:?}"
    );
    assert_eq!(
        record.request_method.as_deref(),
        Some("GET"),
        "外带审计必须标明 GET: {record:?}"
    );
    assert_eq!(
        record.status.as_deref(),
        Some("0"),
        "只有数据真正可取才落审计（失败不应出现）: {record:?}"
    );
    assert_eq!(
        record.business_type,
        Some(5),
        "外带在审计面归 5=导出: {record:?}"
    );
    assert_eq!(
        record.oper_name.as_deref(),
        Some("admin"),
        "操作人必须落库: {record:?}"
    );
    assert_eq!(record.tenant_id, 0, "平台管理员审计挂在租户 0: {record:?}");
    assert!(
        !record.oper_url.as_deref().unwrap_or_default().contains('?'),
        "oper_url 不得带查询串（搜索词不进审计面）: {record:?}"
    );
    assert!(
        record.oper_ip.as_deref().is_some_and(|ip| !ip.is_empty()),
        "来源 IP 必须落库: {record:?}"
    );
}

fn detail_of(record: &sys_oper_log::Model) -> serde_json::Value {
    serde_json::from_str(record.json_result.as_deref().unwrap_or("null"))
        .unwrap_or_else(|e| panic!("json_result 必须是 JSON（外带量要可读）: {e} / {record:?}"))
}

/// ① 变更留痕 CSV 导出：`GET /system/audit-change/export` 是 GET 外带面，
/// 中间件只记写方法 ⇒ 必须由处理器自己补一条审计，且带上"导出了哪个子集"。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_change_export_leaves_a_get_audit_row() {
    let ctx = TestContext::new().await;
    let (status, headers, _body) = ctx
        .send_with_headers(ctx.request(
            Method::GET,
            "/system/audit-change/export?tableName=sys_user&action=update",
            None,
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "CSV 导出应成功");
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/csv"),
        "导出 content-type 应为 CSV，实际: {content_type}"
    );

    // 精确 URL 查询：若实现把查询串写进 oper_url，这里会读成 0 条（判据自己会点名）
    let rows = settled_egress_rows(&ctx, "/system/audit-change/export", 1).await;
    assert_eq!(rows.len(), 1, "一次外带恰好一条审计: {rows:?}");
    let r = &rows[0];
    assert_common_audit_shape(r, "module.auditChange", "/system/audit-change/export");
    assert!(
        r.target_tenant_id.is_none(),
        "无目标租户时 target_tenant_id 必须为 NULL: {r:?}"
    );
    let param = r.oper_param.as_deref().unwrap_or("");
    assert!(
        param.contains("\"tableName\":\"sys_user\"") && param.contains("\"action\":\"update\""),
        "oper_param 必须记下导出的子集（否则事后无法回答'导出了哪些数据'），实际: {param}"
    );
    let detail = detail_of(r);
    assert!(
        detail.get("rows").and_then(|v| v.as_i64()).is_some(),
        "json_result 必须记外带行数（0 行也是一次成功外带），实际: {detail}"
    );
}

/// ② 合规归档下载：`GET /monitor/operlog/archive/{anchorId}`（全租户混合 JSONL）。
/// 夹具直接写入存储对象 + 锚点行（下载只依赖这两样），失败分支用不存在的锚点。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oper_log_archive_download_leaves_a_get_audit_row() {
    use crate::entity::sys_log_archive_anchor::{
        ActiveModel as AnchorActive, Entity as AnchorEntity,
    };

    let ctx = TestContext::new().await;
    let storage = ctx.state.storage.clone();
    let key = format!("b137_it_{}.jsonl", uuid::Uuid::new_v4().simple());
    let payload = br#"{"operId":1,"requestMethod":"POST"}"#.to_vec();
    storage
        .save(ARCHIVE_STORAGE_DIR, 0, &key, "", &payload)
        .await
        .expect("写入归档对象失败");
    let anchor = AnchorEntity::insert(AnchorActive {
        anchor_id: sea_orm::NotSet,
        first_oper_id: Set(1),
        last_oper_id: Set(2),
        last_chain_hash: Set("a".repeat(64)),
        deleted_count: Set(2),
        mode: Set("archive".to_string()),
        archive_object_key: Set(Some(key.clone())),
        deleted_at: Set(chrono::Utc::now().naive_utc()),
    })
    .exec_with_returning(&ctx.state.db)
    .await
    .expect("插入归档锚点失败");

    let url = format!("/monitor/operlog/archive/{}", anchor.anchor_id);
    let (status, headers, _body) = ctx
        .send_with_headers(ctx.request(Method::GET, &url, None))
        .await;
    assert_eq!(status, StatusCode::OK, "归档下载应成功: {headers:?}");
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("octet-stream"),
        "归档下载 content-type 应为 octet-stream，实际: {content_type}"
    );

    let rows = settled_egress_rows(&ctx, &url, 1).await;
    assert_eq!(rows.len(), 1, "一次外带恰好一条审计: {rows:?}");
    let r = &rows[0];
    assert_common_audit_shape(r, "module.operlog", "/monitor/operlog/archive/{anchorId}");
    assert!(
        r.target_tenant_id.is_none(),
        "全租户混合归档没有单一目标租户: {r:?}"
    );
    let detail = detail_of(r);
    assert_eq!(
        detail.get("objectKey").and_then(|v| v.as_str()),
        Some(key.as_str()),
        "json_result 必须记下被带走的对象 key，实际: {detail}"
    );
    assert_eq!(
        detail.get("size").and_then(|v| v.as_i64()),
        Some(payload.len() as i64),
        "json_result 必须记外带字节数，实际: {detail}"
    );

    // 失败不落审计：不存在的锚点 ⇒ 404，且落定窗口之后审计面不得出现该 URL
    let missing = "/monitor/operlog/archive/999999";
    let (status, _) = ctx.send_raw(ctx.request(Method::GET, missing, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "不存在的锚点应 404");
    assert!(
        settled_egress_rows(&ctx, missing, 0).await.is_empty(),
        "探测失败的下载不得写进审计面（失败留痕是 WARN 日志的职责）"
    );

    storage
        .delete(ARCHIVE_STORAGE_DIR, 0, &key)
        .await
        .expect("清理归档对象失败");
}

/// ③ AI 历史管理导出：`GET /system/ai/history/admin/export` 跨租户带出问答与 SQL。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ai_history_export_leaves_a_get_audit_row() {
    let ctx = TestContext::new().await;
    let url = "/system/ai/history/admin/export";
    let (status, headers, _body) = ctx
        .send_with_headers(ctx.request(Method::GET, url, None))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "空库导出也应成功（表头文件同样是一次外带）: {headers:?}"
    );
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("spreadsheetml"),
        "AI 历史导出 content-type 应为 xlsx，实际: {content_type}"
    );

    let rows = settled_egress_rows(&ctx, url, 1).await;
    assert_eq!(rows.len(), 1, "一次外带恰好一条审计: {rows:?}");
    let r = &rows[0];
    assert_common_audit_shape(r, "module.ai", url);
    assert!(
        r.target_tenant_id.is_none(),
        "未指定 tenantFilter 时目标租户必须为 NULL: {r:?}"
    );
    let detail = detail_of(r);
    assert!(
        detail.get("rows").and_then(|v| v.as_i64()).is_some(),
        "json_result 必须记外带行数，实际: {detail}"
    );
}
