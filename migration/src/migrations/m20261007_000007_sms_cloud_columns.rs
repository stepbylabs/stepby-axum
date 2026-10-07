//! G-07 扩展：短信云运营商（阿里云/腾讯云）模板制投递支撑列
//!
//! - `sys_msg_template.sms_template_code`（VARCHAR(64) NULL）：**云端运营商模板 code**
//!   （如阿里云 `SMS_46512345`）。与 `template_code`（本系统消息模板编码）是两个概念：
//!   后者定位本表行，前者是运营商侧备案模板。NULL = 该模板不走云厂商模板制投递。
//! - `sys_msg_send_log.sms_params`（TEXT NULL）：**原始渲染参数 JSON 快照**。
//!   云厂商投递必须携带原始参数（TemplateParam/TemplateParamSet），而 send_log 仅存
//!   渲染后文本——无此快照则重试时无法还原参数（fail-closed 反复失败）。
//!
//! 幂等：has_column 守卫逐列判定；存量库兜底 `initialize::ensure_sms_template_code_columns`。

use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261007_000007_sms_cloud_columns"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let adds: [(&str, &str, &str, &str); 2] = [
            (
                "sys_msg_template",
                "sms_template_code",
                "VARCHAR(64) NULL",
                "云厂商短信模板 code（阿里云 SMS_xxxx / 腾讯云 2xxxxxxxx0）",
            ),
            (
                "sys_msg_send_log",
                "sms_params",
                "TEXT NULL",
                "短信投递原始渲染参数 JSON 快照（云厂商重试还原用）",
            ),
        ];
        for (table, col, ddl, _cmt) in adds {
            if !manager.has_column(table, col).await? {
                conn.execute_unprepared(&format!("ALTER TABLE {table} ADD COLUMN {col} {ddl}"))
                    .await?;
            }
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        for (table, col) in [
            ("sys_msg_template", "sms_template_code"),
            ("sys_msg_send_log", "sms_params"),
        ] {
            if manager.has_column(table, col).await? {
                conn.execute_unprepared(&format!("ALTER TABLE {table} DROP COLUMN {col}"))
                    .await?;
            }
        }
        Ok(())
    }
}
