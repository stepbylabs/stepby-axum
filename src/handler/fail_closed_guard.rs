//! 安全/一致性守卫的**读取失败不得静默放行**总锁（批七十一）。
//!
//! 背景（本批实证的一类隐蔽缺陷形态）：`if let Ok(x) = …await { … }` 看着"有分支处理"，
//! 实际把**数据库故障**折叠成"没查到/不冲突/不是超管"——于是：
//! - 解锁接口的超管保护（P0-R81-006）在 DB 抖动时被绕过；
//! - SCIM `externalId` 唯一性校验静默通过，IdP 映射被写成重复值（后续按 externalId
//!   反查同步会互相覆盖）；而 PUT 入口更是**完全不校验**（同一字段两条写入口径不一致）；
//! - SSO `/sso/jwks` 在 DB 故障时发布 `{"keys":[]}` 这份**语法合法但内容错误**的文档，
//!   RP 用它校验会全部拒签并可能缓存一段时间（比 5xx 让 RP 沿用上一份更危险）；
//! - `user.updated` 事件的租户归属读失败时回落**操作者**租户 ⇒ 平台管理员代管编辑租户
//!   用户时，事件可能被投给另一个租户的回调组（跨租户投递）；
//! - 审计 `target_tenant_id` 归属预读失败静默 ⇒ 平台代管操作的留痕落到操作者租户。
//!
//! 这些点已在 b71 逐个改为 fail-closed（守卫依赖的读取一律 `?` 上抛）或"保留可用性取舍
//! 但必须 WARN 留痕"。本测试把治理形状**锁死**：复现旧写法即刻红。
//!
//! 口径与同目录 [`no_panic_guard`] 一致——只扫 `#[cfg(test)]` 之前的生产码。

#[cfg(test)]
mod fail_closed_mod {
    use std::path::Path;

    /// 取生产码**语句**：`#[cfg(test)]` 之前、并剔除 `//` 行。
    /// b71 治理点的注释会引用被禁的旧写法作为说明（"原写 `if let Ok(..)`"），
    /// 不排除注释就会把"文档"误判成"回归"。
    fn prod_src(rel: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("读取 {rel} 失败: {e}"));
        let prod = match src.find("#[cfg(test)]") {
            Some(idx) => &src[..idx],
            None => src.as_str(),
        };
        prod.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 断言生产码语句中**不存在**某段旧写法
    fn assert_absent(rel: &str, needle: &str, why: &str) {
        let prod = prod_src(rel);
        assert!(
            !prod.contains(needle),
            "{rel} 仍含 fail-open 写法 `{needle}` —— {why}\n（b71 已治理，回归请同步更新本锁）"
        );
    }

    #[test]
    fn unlock_guard_must_read_target_user_fail_closed() {
        assert_absent(
            "src/handler/sys_logininfor_handler.rs",
            "if let Ok(Some(user)) = state.user_service.get_user_by_username",
            "超管保护（P0-R81-006）不得因数据库故障被绕过",
        );
    }

    #[test]
    fn scim_external_id_uniqueness_must_not_swallow_db_error() {
        assert_absent(
            "src/service/scim_service.rs",
            "if let Ok(Some(other))",
            "externalId 唯一性校验必须把 DB 故障上抛（否则重复映射静默入库）",
        );
    }

    #[test]
    fn scim_put_and_patch_share_one_external_id_validator() {
        // 同一字段的三条写入口（PUT / PATCH path-op / PATCH no-path-op）必须全部经同一
        // helper 校验，防止再出现"PATCH 查重、PUT 裸写"的口径分叉。
        let prod = prod_src("src/service/scim_service.rs");
        let calls = prod
            .match_indices("self.ensure_external_id_available(")
            .count();
        assert!(
            calls >= 3,
            "scim_service externalId 写入口应有 ≥3 处调用统一校验器，实际 {calls} 处（PUT/PATCH path-op/PATCH no-path-op）"
        );
    }

    #[test]
    fn jwks_must_not_publish_empty_document_on_db_error() {
        assert_absent(
            "src/service/sso_service.rs",
            "if let Ok(clients) = self.client_repo.find_all_enabled()",
            "JWKS 不得在 DB 故障时发布空 keys（RP 会用它误拒所有 RS256 id_token）",
        );
        let prod = prod_src("src/service/sso_service.rs");
        assert!(
            prod.contains("pub async fn jwks(&self) -> Result<serde_json::Value, ServiceError>"),
            "sso_service::jwks 必须以 Result 表达读取失败"
        );
    }

    #[test]
    fn user_event_tenant_must_come_from_authoritative_read() {
        assert_absent(
            "src/handler/sys_user_handler.rs",
            ".unwrap_or(operator.tenant_id());",
            "user.updated 事件租户归属不得在读失败时回落操作者租户（跨租户投递风险）",
        );
        // 正向锁①：编辑路径必须 fail-closed 读目标用户（一次读取供两个消费者）
        let prod = prod_src("src/handler/sys_user_handler.rs");
        assert!(
            prod.contains("get_user_by_id(dto.user_id).await?"),
            "sys_user_handler::edit 必须以 `?` 读取目标用户租户归属（不得静默回落）"
        );
        // 正向锁②：匿名化路径**允许**预读未命中（幂等重放契约：已匿名化用户 get 返回
        // not_found，二次调用必须仍是 200 + 零计数报告——b71 曾误改 fail-closed，
        // 被 integration_tests::user_erasure 实测抓回），但必须留痕。
        assert!(
            prod.contains("匿名化审计归属预读未命中"),
            "匿名化的审计归属预读失败必须 WARN 留痕（静默回落会让平台代管留痕错租户）"
        );
    }

    #[test]
    fn audit_tenant_attribution_failures_are_logged() {
        // 平台代管场景的审计 target_tenant_id 预读允许"不阻断主操作"，但必须留痕。
        // （user 侧另有专测：编辑 fail-closed + 匿名化留痕，故此处不含 sys_user_handler.rs）
        let cases = [
            ("src/handler/sys_dept_handler.rs", 2),
            ("src/handler/sys_post_handler.rs", 1),
            ("src/handler/sys_role_handler.rs", 1),
        ];
        for (rel, expect_min) in cases {
            let prod = prod_src(rel);
            let hits = prod.match_indices("审计归属预读失败").count();
            assert!(
                hits >= expect_min,
                "{rel} 的审计归属预读失败必须有 WARN 留痕（至少 {expect_min} 处，实际 {hits} 处）"
            );
        }
    }

    #[test]
    fn site_preference_read_failure_is_logged_not_silent() {
        assert_absent(
            "src/service/sys_msg_service.rs",
            "if let Ok(Some(pref)) = self.pref_repo.find_by_user_id",
            "站内信偏好（免打扰）读取失败不得静默当作允许投递",
        );
    }
}
