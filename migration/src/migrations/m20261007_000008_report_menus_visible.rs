//! G-01 M2：报表前端上线，翻转菜单可见性（menu_id 4146 报表数据集 / 4148 大屏管理）
//!
//! M1 落地时页面菜单为 `visible='1'`（隐藏态，防"点击即 404"死入口）；M2 前端三页
//! （dataset 管理 / view 运行·设计 / 图表组件）本批上线 ⇒ 按设计文档翻转可见性。
//! **仅翻 4146/4148**——4140-4145（G-02 流程定义）属 M3 前端，继续隐藏。
//!
//! 幂等：UPDATE 仅当 visible='1' 时置 '0'（可重复执行）；menu_id 不存在时零行受影响。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000008_report_menus_visible"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET visible = '0' WHERE menu_id IN (4146, 4148) AND visible = '1'",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "UPDATE sys_menu SET visible = '1' WHERE menu_id IN (4146, 4148) AND visible = '0'",
            )
            .await?;
        Ok(())
    }
}
