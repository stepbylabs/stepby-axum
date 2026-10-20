// stepby-axum/src/integration_tests/tenant_nav_mount.rs
//! 租户自建导航（L3）挂载 / 卸载 / **重新挂载**全链路（b80 P-A）。
//!
//! 立案缘由（本轮实测定位的真缺陷）：`sys_tenant_menu` 的唯一索引
//! `uk_sys_tenant_menu (tenant_id, ref_menu_id)` **不含 del_flag**，而"是否已挂载"的判据
//! `exists_ref` 只看 `del_flag='0'` ⇒ 卸载（软删）后重新挂载会绕过判据、直接 INSERT 撞索引，
//! 用户视角是"点挂载 ⇒ 500"。而 `/options` 恰恰把那条菜单标成 `selected=false` 供用户点，
//! 所以这不是"理论上可触发"，是页面上的必经路径。
//!
//! 改造前该模块**只有单机模式 403 的负路径**有测试（capability_features.rs），
//! 正向链路零覆盖——所以缺陷能长期存在。本文件补齐闭环并钉住"复活而非新增第二行"。

use axum::http::Method;
use sea_orm::{ConnectionTrait, Statement};

use super::TestContext;

/// 取（必要时造）一个可挂载的租户 id
///
/// 不硬编码 id：隔离库里有没有租户取决于种子与迁移顺序，硬编码会造出"换台机器就 SKIP"
/// 的环境耦合判据。库里没有就插一条最小夹具（`package_id = NULL` = 不设白名单）。
async fn ensure_tenant(ctx: &TestContext) -> i64 {
    let rows = ctx
        .state
        .db
        .query_all_raw(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "SELECT tenant_id FROM sys_tenant WHERE del_flag = '0' ORDER BY tenant_id LIMIT 1",
        ))
        .await
        .expect("查询 sys_tenant 失败");
    if let Some(r) = rows.first()
        && let Ok(id) = r.try_get::<i64>("", "tenant_id")
    {
        return id;
    }
    ctx.state
        .db
        .execute_raw(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "INSERT INTO sys_tenant (tenant_code, tenant_name, dept_id, package_id, account_count, \
             status, del_flag, create_by, create_time, remark) \
             VALUES ('it_nav', 'IT 导航夹具租户', 0, NULL, 0, '0', '0', 'it', datetime('now'), '集成测试夹具')"
                .to_string(),
        ))
        .await
        .expect("插入夹具租户失败");
    ctx.state
        .db
        .query_all_raw(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            "SELECT tenant_id FROM sys_tenant WHERE tenant_code = 'it_nav'".to_string(),
        ))
        .await
        .expect("回查夹具租户失败")
        .first()
        .expect("夹具租户应已存在")
        .try_get::<i64>("", "tenant_id")
        .expect("夹具租户 tenant_id 应为整数")
}

/// `(tenant_id, ref_menu_id)` 上的**全部**行数与各自的 del_flag（不筛软删）
async fn rows_for_ref(ctx: &TestContext, tid: i64, ref_menu_id: i64) -> Vec<String> {
    let rows = ctx
        .state
        .db
        .query_all_raw(Statement::from_sql_and_values(
            sea_orm::DatabaseBackend::Sqlite,
            "SELECT del_flag, visible, order_num, parent_id, l3_id FROM sys_tenant_menu \
             WHERE tenant_id = ? AND ref_menu_id = ?",
            [tid.into(), ref_menu_id.into()],
        ))
        .await
        .expect("查询 sys_tenant_menu 失败");
    rows.iter()
        .map(|r| {
            let del: String = r.try_get("", "del_flag").unwrap_or_default();
            let vis: Option<String> = r.try_get("", "visible").unwrap_or(None);
            let order: Option<i64> = r.try_get("", "order_num").unwrap_or(None);
            let parent: i64 = r.try_get("", "parent_id").unwrap_or(-1);
            let l3: i64 = r.try_get("", "l3_id").unwrap_or(-1);
            format!("l3={l3} del={del} visible={vis:?} order={order:?} parent={parent}")
        })
        .collect()
}

/// L3 导航挂载 / 卸载 / 重新挂载闭环
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tenant_nav_remount_after_unmount() {
    let ctx = TestContext::new().await;
    let tid = ensure_tenant(&ctx).await;

    // ① 候选菜单：取一个"尚未挂载"的可挂载项（与页面选择器同一个数据源，不自己猜 id）
    let opts = ctx
        .get_json(&format!("/system/tenant/menu/options?tenantId={tid}"))
        .await;
    let candidates = opts["data"].as_array().cloned().unwrap_or_default();
    let free: Vec<&serde_json::Value> = candidates
        .iter()
        .filter(|c| c["selected"].as_bool() == Some(false))
        .collect();
    assert!(
        !free.is_empty(),
        "租户 {tid} 应有可挂载（selected=false）的候选菜单，实际候选={}",
        candidates.len()
    );
    let ref_menu_id = free[0]["menuId"].as_i64().expect("候选 menuId 应为数字");

    // ② 首次挂载（显式给导航属性，便于复活路径的"属性被覆盖"判据）
    let add = ctx
        .post_json(
            "/system/tenant/menu",
            serde_json::json!({
                "tenantId": tid,
                "refMenuId": ref_menu_id,
                "parentId": 0,
                "orderNum": 7,
                "visible": "1"
            }),
        )
        .await;
    ctx.assert_ok(&add);
    let l3_first = add["data"]["l3Id"].as_i64().expect("挂载应返回 l3Id");
    assert_eq!(
        add["data"]["visible"].as_str(),
        Some("1"),
        "首次挂载应落 visible=1，实际: {}",
        add["data"]
    );

    // ③ 重复挂载必须被拒（对照组：证明修复没有把重复检查一起放开）
    let (dup_status, dup_body) = ctx
        .send_raw(ctx.request(
            Method::POST,
            "/system/tenant/menu",
            Some(serde_json::json!({ "tenantId": tid, "refMenuId": ref_menu_id })),
        ))
        .await;
    assert_eq!(
        dup_status,
        axum::http::StatusCode::BAD_REQUEST,
        "已挂载未卸载时重复挂载应 400，实际: {dup_status} {dup_body}"
    );
    assert!(
        !dup_body["msg"].as_str().unwrap_or("").contains("error."),
        "重复挂载的拒绝原因应是可读文案，实际: {dup_body}"
    );

    // ④ options 必须把它标成已挂载（前端据此禁用重复添加；同一事实源的另一侧）
    let opts2 = ctx
        .get_json(&format!("/system/tenant/menu/options?tenantId={tid}"))
        .await;
    let marked = opts2["data"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .find(|c| c["menuId"].as_i64() == Some(ref_menu_id));
    assert_eq!(
        marked.as_ref().and_then(|c| c["selected"].as_bool()),
        Some(true),
        "挂载后候选项应变为 selected=true，实际: {marked:?}"
    );

    // ⑤ 卸载（软删）
    let del = ctx
        .delete_json(&format!("/system/tenant/menu/{l3_first}"))
        .await;
    ctx.assert_ok(&del);
    let list_after_del = ctx
        .get_json(&format!("/system/tenant/menu/list?tenantId={tid}"))
        .await;
    let still = list_after_del["data"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .any(|r| r["l3Id"].as_i64() == Some(l3_first));
    assert!(
        !still,
        "卸载后列表不应再包含该导航行（l3={l3_first}），实际: {}",
        list_after_del["data"]
    );
    // 卸载必须是**软删**（留行留痕），且库里对该 (tenant, ref) 只剩这一行
    let after_unmount = rows_for_ref(&ctx, tid, ref_menu_id).await;
    assert_eq!(
        after_unmount.len(),
        1,
        "卸载后应只剩那条软删行，实际: {after_unmount:?}"
    );
    assert!(
        after_unmount[0].contains("del=2"),
        "卸载应是 del_flag='2' 软删，实际: {after_unmount:?}"
    );

    // ⑥ **重新挂载**：改造前这一步撞唯一索引返回 500（本文件的立案缺陷）
    let remount = ctx
        .post_json(
            "/system/tenant/menu",
            serde_json::json!({
                "tenantId": tid,
                "refMenuId": ref_menu_id,
                "parentId": 0,
                "orderNum": 3,
                "visible": "0"
            }),
        )
        .await;
    ctx.assert_ok(&remount);
    let l3_again = remount["data"]["l3Id"]
        .as_i64()
        .expect("重新挂载应返回 l3Id");
    assert_eq!(
        l3_again, l3_first,
        "重新挂载必须**复用原行**（复活），而不是新增一行：{l3_first} → {l3_again}"
    );
    assert_eq!(
        remount["data"]["visible"].as_str(),
        Some("0"),
        "复活路径必须覆盖导航属性（不得把卸载前的 visible=1 原样抬回来），实际: {}",
        remount["data"]
    );
    let after_remount = rows_for_ref(&ctx, tid, ref_menu_id).await;
    assert_eq!(
        after_remount.len(),
        1,
        "整个流程后该 (tenant, ref) 仍必须只有一行（不得留下软删残行 + 新行），实际: {after_remount:?}"
    );
    assert!(
        after_remount[0].contains("del=0")
            && after_remount[0].contains("visible=Some(\"0\")")
            && after_remount[0].contains("order=Some(3)"),
        "复活后的行应是活跃态且带新属性，实际: {after_remount:?}"
    );

    // ⑦ 收尾：卸载夹具导航，别给运行库留配置行
    ctx.assert_ok(
        &ctx.delete_json(&format!("/system/tenant/menu/{l3_again}"))
            .await,
    );
    // 软删行是**设计留痕**（唯一索引要求一行），但必须保持非活跃，否则残留会污染下一轮
    let final_rows = rows_for_ref(&ctx, tid, ref_menu_id).await;
    assert!(
        final_rows.iter().all(|r| r.contains("del=2")),
        "收尾后不得留下活跃导航行，实际: {final_rows:?}"
    );
}
