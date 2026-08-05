-- ============================================================================
-- UTC 存量数据回填脚本（C4/C5 完整 UTC 迁移）
-- ============================================================================
-- 背景
--   迁移前：所有持久化时间戳由 chrono::Local（服务器本地时区）写入，
--           列类型为无时区的 NaiveDateTime（SQLite TEXT / PG timestamp / MySQL datetime）。
--   迁移后：统一由 Utc::now() 写入「UTC 语义」值，序列化到前端为 ISO 8601（T 分隔）。
--   本脚本将【存量】数据按「历史服务器时区偏移」折算为 UTC，使新旧数据语义一致，
--   前端才能正确按 UTC 解析并展示为用户本地时间。
--
-- ⚠️ 前提假设（务必先核对！）
--   默认假设历史服务器运行于 UTC+8（北京时间）。此时存量墙钟值比真实 UTC 早 8 小时，
--   需【减去 8 小时】得到 UTC 值。
--   若历史服务器实际为其他时区，请将下方所有偏移量改为对应值：
--     UTC+0 → 偏移 0（无需回填，存量已是 UTC）
--     UTC+8 → '-8 hours' / INTERVAL '8 hours'（默认）
--     其他   → 替换为对应 ±N hours
--
-- 执行前：【务必先备份数据库】。下方脚本对每张表的日期时间列执行偏移，不可逆。
-- 适用范围：所有 NaiveDateTime 列（create_time / update_time / oper_time / login_time 等）。
-- 新增表请参照同模式补充；SQLite 因无 information_schema 动态执行，需逐表列出。
-- 执行后请用 `SELECT create_time FROM sys_user LIMIT 1;` 抽样确认偏移正确。
-- ============================================================================


-- ----------------------------- SQLite（默认） -----------------------------
-- 偏移量：历史 UTC+8 → 减去 8 小时。仅需对「日期时间列」执行。
UPDATE sys_user            SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_role            SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_dept            SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_menu            SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_dict_type       SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_dict_data       SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_config          SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_post            SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_oper_log        SET oper_time   = datetime(oper_time,   '-8 hours'), create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE oper_time IS NOT NULL OR create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_logininfor      SET login_time  = datetime(login_time,  '-8 hours'), create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE login_time IS NOT NULL OR create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_job             SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_job_log         SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_notice          SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_notice_read     SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE gen_table           SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE gen_table_column    SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_backup_log      SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_task            SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;
UPDATE sys_rate_limit      SET create_time = datetime(create_time, '-8 hours'), update_time = datetime(update_time, '-8 hours') WHERE create_time IS NOT NULL OR update_time IS NOT NULL;


-- ----------------------------- PostgreSQL -----------------------------
-- 动态遍历所有 timestamp 类型列并统一偏移，无需逐表枚举（覆盖含 create_time/update_time 等所有表）。
DO $$
DECLARE
    r RECORD;
    offset_hours INTEGER := 8;  -- 历史 UTC+8：减去 8 小时；若历史 UTC+0 改为 0
BEGIN
    FOR r IN
        SELECT table_schema, table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND data_type IN ('timestamp without time zone', 'timestamp with time zone')
          AND column_name ~ '(time|date)$'
    LOOP
        EXECUTE format(
            'UPDATE %I.%I SET %I = %I - make_interval(hours => %L) WHERE %I IS NOT NULL;',
            r.table_schema, r.table_name, r.column_name, r.column_name, offset_hours, r.column_name
        );
    END LOOP;
END $$;


-- ----------------------------- MySQL -----------------------------
-- 动态遍历所有 datetime/timestamp 列并统一偏移。
SET @offset_hours = 8;  -- 历史 UTC+8：减去 8 小时；若历史 UTC+0 改为 0
DROP PROCEDURE IF EXISTS backfill_utc;
DELIMITER $$
CREATE PROCEDURE backfill_utc()
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE tname VARCHAR(64);
    DECLARE cname VARCHAR(64);
    DECLARE cur CURSOR FOR
        SELECT TABLE_NAME, COLUMN_NAME
        FROM information_schema.columns
        WHERE TABLE_SCHEMA = DATABASE()
          AND DATA_TYPE IN ('datetime', 'timestamp')
          AND COLUMN_NAME REGEXP 'time$|date$';
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
    OPEN cur;
    read_loop: LOOP
        FETCH cur INTO tname, cname;
        IF done THEN LEAVE read_loop; END IF;
        SET @sql = CONCAT('UPDATE `', tname, '` SET `', cname, '` = `', cname, '` - INTERVAL ', @offset_hours, ' HOUR WHERE `', cname, '` IS NOT NULL');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END LOOP;
    CLOSE cur;
END $$
DELIMITER ;
CALL backfill_utc();
DROP PROCEDURE IF EXISTS backfill_utc;
