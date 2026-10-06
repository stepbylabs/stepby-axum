// stepby-axum/src/service/data_rule_service.rs
//! DP-01 结构化数据权限规则引擎（§5.53）。
//!
//! **设计要点**（对标 JeecgBoot 数据权限规则、否决裸 SQL 改写与 PG RLS）：
//! 1. 规则挂角色（sys_role_data_rule），用户多角色的规则 **OR 合并**（任一命中即可见，
//!    对齐 data_scope"最宽松优先"）；
//! 2. 求值产物是 sea-orm `Condition`（值参数化，零字符串拼接——注入面仅剩表/列名，
//!    由录入期正则白名单 + 停用即失效收敛）；
//! 3. 无规则/未接入 = 零附加条件（opt-in 渐进，现状行为不变）；
//! 4. 多租户行级隔离：租户管理员仅能管理本租户规则；平台管理全量。

use crate::entity::{sys_data_rule, sys_role_data_rule};
use crate::common::error::ServiceError;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct DataRuleService {
    pub db: Arc<DatabaseConnection>,
}

/// 录入期表/列名白名单（防注入的单点闸门）
fn is_valid_identifier(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

const OPS: &[&str] = &["eq", "ne", "like", "gt", "lt", "ge", "le", "in"];
const VALUE_TYPES: &[&str] = &[
    "fixed",
    "current_user",
    "current_dept",
    "current_dept_children",
    "current_tenant",
];

/// 求值上下文（由调用方从 operator 会话构造）
#[derive(Debug, Clone)]
pub struct DataRuleContext {
    pub tenant_id: i64,
    pub user_id: i64,
    /// 用户主部门 ID（current_dept / current_dept_children 需要）
    pub dept_id: Option<i64>,
    /// 部门及后代部门 ID 集（含自身；current_dept_children 需要）
    pub dept_children: Vec<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataRuleDto {
    pub rule_id: Option<i64>,
    pub rule_name: String,
    pub table_name: String,
    pub field_name: String,
    pub op: String,
    pub value_type: String,
    pub rule_value: Option<String>,
    pub status: Option<String>,
    /// 分配给哪些角色（upsert 语义：全量覆盖关联）
    pub role_ids: Option<Vec<i64>>,
}

impl DataRuleService {
    pub fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }

    fn validate_dto(dto: &DataRuleDto) -> Result<(), ServiceError> {
        if dto.rule_name.trim().is_empty() || dto.rule_name.chars().count() > 64 {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.dataRule.name_invalid"
            )));
        }
        for (label, v) in [("表名", &dto.table_name), ("列名", &dto.field_name)] {
            if !is_valid_identifier(v) {
                return Err(ServiceError::bad_request(&crate::tr!(
                    "error.dataRule.identifier_invalid",
                    label = label,
                    value = v
                )));
            }
        }
        if !OPS.contains(&dto.op.as_str()) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.dataRule.op_invalid",
                value = &dto.op
            )));
        }
        if !VALUE_TYPES.contains(&dto.value_type.as_str()) {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.dataRule.value_type_invalid",
                value = &dto.value_type
            )));
        }
        if dto.value_type == "fixed" && dto.rule_value.as_deref().unwrap_or("").trim().is_empty() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.dataRule.fixed_value_required"
            )));
        }
        if dto.value_type == "in" && dto.rule_value.is_none() {
            return Err(ServiceError::bad_request(&crate::tr!(
                "error.dataRule.fixed_value_required"
            )));
        }
        Ok(())
    }

    /// 规则清单（平台全量 / 租户本租户；operator_tid=0 管理全量）
    pub async fn list(
        &self,
        operator_tid: i64,
        page: u64,
        size: u64,
    ) -> Result<(Vec<sys_data_rule::Model>, u64), ServiceError> {
        use sea_orm::QuerySelect;
        let mut sel = sys_data_rule::Entity::find()
            .filter(sys_data_rule::Column::DelFlag.eq("0"));
        if operator_tid != 0 {
            sel = sel.filter(sys_data_rule::Column::TenantId.eq(operator_tid));
        }
        let total = sel.clone().count(self.db.as_ref()).await?;
        let items = sel
            .order_by_desc(sys_data_rule::Column::RuleId)
            .offset((page.saturating_sub(1)) * size)
            .limit(size)
            .all(self.db.as_ref())
            .await?;
        Ok((items, total))
    }

    /// 新建/更新（rule_id 缺省 = 新建；tenant_id 按操作者归属）
    pub async fn save(
        &self,
        dto: DataRuleDto,
        operator_tid: i64,
        operator: &str,
    ) -> Result<i64, ServiceError> {
        Self::validate_dto(&dto)?;
        let now = chrono::Local::now().naive_local();
        let rule_id = match dto.rule_id {
            None => {
                let am = sys_data_rule::ActiveModel {
                    rule_name: Set(dto.rule_name.clone()),
                    table_name: Set(dto.table_name.clone()),
                    field_name: Set(dto.field_name.clone()),
                    op: Set(dto.op.clone()),
                    value_type: Set(dto.value_type.clone()),
                    rule_value: Set(dto.rule_value.clone()),
                    status: Set(dto.status.clone().unwrap_or_else(|| "0".into())),
                    tenant_id: Set(operator_tid),
                    create_by: Set(Some(operator.to_string())),
                    create_time: Set(Some(now)),
                    del_flag: Set(Some("0".into())),
                    ..Default::default()
                };
                let inserted = am.insert(self.db.as_ref()).await?;
                inserted.rule_id
            }
            Some(id) => {
                let existing = sys_data_rule::Entity::find_by_id(id)
                    .one(self.db.as_ref())
                    .await?
                    .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.dataRule.not_found")))?;
                // 行级越权防护：租户管理员不得改动他租户规则
                if operator_tid != 0 && existing.tenant_id != operator_tid {
                    return Err(ServiceError::forbidden(&crate::tr!("error.common.forbidden")));
                }
                let mut am: sys_data_rule::ActiveModel = existing.into();
                am.rule_name = Set(dto.rule_name.clone());
                am.table_name = Set(dto.table_name.clone());
                am.field_name = Set(dto.field_name.clone());
                am.op = Set(dto.op.clone());
                am.value_type = Set(dto.value_type.clone());
                am.rule_value = Set(dto.rule_value.clone());
                am.status = Set(dto.status.clone().unwrap_or_else(|| "0".into()));
                am.update_by = Set(Some(operator.to_string()));
                am.update_time = Set(Some(now));
                am.update(self.db.as_ref()).await?;
                id
            }
        };

        // 角色关联全量覆盖
        if let Some(role_ids) = &dto.role_ids {
            self.set_role_bindings(rule_id, role_ids).await?;
        }
        Ok(rule_id)
    }

    async fn set_role_bindings(&self, rule_id: i64, role_ids: &[i64]) -> Result<(), ServiceError> {
        use sea_orm::TransactionTrait;
        let txn = self.db.begin().await?;
        sys_role_data_rule::Entity::delete_many()
            .filter(sys_role_data_rule::Column::RuleId.eq(rule_id))
            .exec(&txn)
            .await?;
        for rid in role_ids {
            let am = sys_role_data_rule::ActiveModel {
                role_id: Set(*rid),
                rule_id: Set(rule_id),
            };
            am.insert(&txn).await?;
        }
        txn.commit().await?;
        Ok(())
    }

    /// 软删（del_flag=1）——停用语义保留审计；同时清除角色关联（即时收敛）
    pub async fn remove(&self, rule_id: i64, operator_tid: i64) -> Result<(), ServiceError> {
        let existing = sys_data_rule::Entity::find_by_id(rule_id)
            .one(self.db.as_ref())
            .await?
            .ok_or_else(|| ServiceError::not_found(&crate::tr!("error.dataRule.not_found")))?;
        if operator_tid != 0 && existing.tenant_id != operator_tid {
            return Err(ServiceError::forbidden(&crate::tr!("error.common.forbidden")));
        }
        let mut am: sys_data_rule::ActiveModel = existing.into();
        am.del_flag = Set(Some("1".into()));
        am.update(self.db.as_ref()).await?;
        sys_role_data_rule::Entity::delete_many()
            .filter(sys_role_data_rule::Column::RuleId.eq(rule_id))
            .exec(self.db.as_ref())
            .await?;
        Ok(())
    }

    /// 读取指定角色集的启用规则（租户域隔离：operator_tid!=0 时仅本租户规则）
    async fn rules_for_roles(
        &self,
        ctx: &DataRuleContext,
        role_ids: &[i64],
    ) -> Result<Vec<sys_data_rule::Model>, ServiceError> {
        if role_ids.is_empty() {
            return Ok(vec![]);
        }
        let bindings = sys_role_data_rule::Entity::find()
            .filter(sys_role_data_rule::Column::RoleId.is_in(role_ids.to_vec()))
            .all(self.db.as_ref())
            .await?;
        let rule_ids: Vec<i64> = bindings.iter().map(|b| b.rule_id).collect();
        if rule_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut sel = sys_data_rule::Entity::find()
            .filter(sys_data_rule::Column::RuleId.is_in(rule_ids))
            .filter(sys_data_rule::Column::Status.eq("0"))
            .filter(sys_data_rule::Column::DelFlag.eq("0"));
        if ctx.tenant_id != 0 {
            sel = sel.filter(sys_data_rule::Column::TenantId.eq(ctx.tenant_id));
        }
        Ok(sel.all(self.db.as_ref()).await?)
    }

    /// 求值：按目标表返回附加 Condition（多规则 OR 合并）。
    ///
    /// **返回 None = 无适用规则（调用方不得 and_where）**——空 Condition::any()
    /// 在 sea-orm 中编译为恒假谓词，误用会将数据面清空（fail-open 不可接受）。
    ///
    /// 调用方将其 `and_where(condition)` 进业务查询——**与 data_scope（部门维度）是
    /// 叠加关系（AND）**：data_scope 决定"看哪些部门"，规则引擎决定"行值满足什么业务条件"。
    pub async fn build_conditions(
        &self,
        ctx: &DataRuleContext,
        table_name: &str,
        role_ids: &[i64],
    ) -> Result<Option<Condition>, ServiceError> {
        use sea_orm::sea_query::Expr;
        use sea_orm::sea_query::ExprTrait;
        let rules = self.rules_for_roles(ctx, role_ids).await?;
        let rules: Vec<_> = rules
            .into_iter()
            .filter(|r| r.table_name == table_name)
            .collect();
        if rules.is_empty() {
            return Ok(None); // 无规则 = 不注入（opt-in 渐进）
        }
        let mut cond = Condition::any();
        let mut emitted = false;
        for r in rules {
            let field_expr = Expr::col((sea_orm::sea_query::Alias::new(&r.table_name), sea_orm::sea_query::Alias::new(&r.field_name)));
            // §5.53（类型感知绑定）：fixed 值可解析为 i64 时用数值绑定——
            // 避免 SQLite/PG 下 TEXT '1' 与 INTEGER 列比较的类型排序陷阱
            let value_expr: Expr = match r.value_type.as_str() {
                "fixed" => {
                    let v = r.rule_value.clone().unwrap_or_default();
                    match v.parse::<i64>() {
                        Ok(n) => Expr::value(n),
                        Err(_) => Expr::value(v),
                    }
                }
                "current_user" => Expr::value(ctx.user_id),
                "current_dept" => {
                    if let Some(d) = ctx.dept_id {
                        Expr::value(d)
                    } else {
                        continue; // 无部门信息无法求值——跳过该规则（不放宽也不收紧）
                    }
                }
                "current_dept_children" => {
                    if ctx.dept_children.is_empty() {
                        continue;
                    }
                    Expr::value(ctx.dept_children.clone())
                }
                "current_tenant" => Expr::value(ctx.tenant_id),
                _ => continue,
            };
            let single = match r.op.as_str() {
                "eq" => field_expr.eq(value_expr),
                "ne" => field_expr.ne(value_expr),
                "like" => field_expr.like(format!("%{}%", r.rule_value.clone().unwrap_or_default())),
                "gt" => field_expr.gt(value_expr),
                "lt" => field_expr.lt(value_expr),
                "ge" => field_expr.gte(value_expr),
                "le" => field_expr.lte(value_expr),
                "in" => {
                    let raw = r.rule_value.clone().unwrap_or_default();
                    let items: Vec<String> = raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                    if items.is_empty() {
                        continue;
                    }
                    field_expr.is_in(items)
                }
                _ => continue,
            };
            cond = cond.add(single);
            emitted = true;
        }
        if !emitted {
            return Ok(None);
        }
        Ok(Some(cond))
    }
}

/// 单元测试：录入校验与求值纯逻辑
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_bad_identifier() {
        let base = |table: &str, field: &str| DataRuleDto {
            rule_id: None,
            rule_name: "t".into(),
            table_name: table.into(),
            field_name: field.into(),
            op: "eq".into(),
            value_type: "current_user".into(),
            rule_value: None,
            status: None,
            role_ids: None,
        };
        assert!(DataRuleService::validate_dto(&base("sys_user", "create_by")).is_ok());
        assert!(DataRuleService::validate_dto(&base("sys_user; DROP TABLE x", "create_by")).is_err());
        assert!(DataRuleService::validate_dto(&base("SysUser", "create_by")).is_err());
        assert!(DataRuleService::validate_dto(&base("sys_user", "a b")).is_err());
        assert!(DataRuleService::validate_dto(&base("1user", "create_by")).is_err());
    }

    #[test]
    fn validate_rejects_bad_op_and_value_type() {
        let dto = |op: &str, vt: &str, rv: Option<&str>| DataRuleDto {
            rule_id: None,
            rule_name: "t".into(),
            table_name: "sys_user".into(),
            field_name: "create_by".into(),
            op: op.into(),
            value_type: vt.into(),
            rule_value: rv.map(|s| s.into()),
            status: None,
            role_ids: None,
        };
        assert!(DataRuleService::validate_dto(&dto("eq", "fixed", Some("1"))).is_ok());
        assert!(DataRuleService::validate_dto(&dto("union", "fixed", Some("1"))).is_err());
        assert!(DataRuleService::validate_dto(&dto("eq", "magic", Some("1"))).is_err());
        assert!(DataRuleService::validate_dto(&dto("eq", "fixed", None)).is_err());
    }
}
