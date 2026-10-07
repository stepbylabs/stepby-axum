//! G-02 M3：流程定义设计器前端上线，翻转页面菜单可见性（menu_id 4140）
//!
//! M1 落地时 4140（流程定义页面）为 `visible='1'` 隐藏态；M3 设计器三件
//! （定义列表/表单式设计器/版本对比）本批上线 ⇒ 翻转可见。
//! 4141-4145 为 F（按钮）行，visible 无导航语义，不翻；4146/4148 已由
//! m20261007_000008 翻转（G-01 M2）。
//!
//! 幂等：仅当 visible='1' 时置 '0'，可重复执行；行不存在零影响。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000009_flow_designer_menu_visible"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET visible = '0' WHERE menu_id = 4140 AND visible = '1'",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET visible = '1' WHERE menu_id = 4140 AND visible = '0'",
            )
            .await?;
        Ok(())
    }
}
