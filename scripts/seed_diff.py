#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""seed_diff.py —— 种子库与运行库逐行逐列 diff 常驻审计工具（批次六十固化为 b54-b57 方法论）。

背景：存量库启动跳过 Migrator::up（initialize/mod.rs:45），initialize 兜底才是存量库
的实际交付机制，因此"迁移/initialize 种子定义"与"运行库实际值"可能漂移。本工具以
纯种子库为基准，逐表逐行逐列比对运行库，捕获种子漂移。

用法：
    # 1) 先用第二实例构建纯种子库（全新空 SQLite，启动即写种子）：
    #    ⚠️ 必须先 `touch data/seed-check.db`——sqlx 的 SqliteConnectOptions 默认
    #    **不创建文件**（create_if_not_exists 未开），直接指一个不存在的路径会在建池时
    #    报 code 14 "unable to open database file" 而退出（批七十六实测踩到）。
    #    touch data/seed-check.db
    #    DATABASE_URL=sqlite://./data/seed-check.db SERVER_PORT=8094 cargo run
    #    （后端起来即种子写完，Ctrl-C 退出即可；全新库会跑完整 Migrator::up）
    # 2) 比对（**两个参数都必须给**，单参数会让 seed 与 live 指到同一个文件）：
    #    python scripts/seed_diff.py data/seed-check.db data/stepby.db
    #    同文件调用被硬拒绝（退出码 2）：自比自恒得"零漂移"，属最坏的一种假绿。

比对口径三规则（b54-b57 实证沉淀）：
    R1 审计列豁免：create_time / update_time / update_by 为运行态审计列，不参与比对。
    R2 业务键优先：自增 PK 会因"键经迁移后期补种"而演进（合法），比对键优先用业务键；
       无业务键映射的表回退 PRAGMA 主键；复合主键（如 sys_role_menu）天然支持。
    R3 方向语义：种子有→运行库无 = 漂移(丢失)；两库都有但值不同 = 漂移(篡改)；
       运行库有→种子无 = 运行数据（e2e/运营产生），仅汇总不计失败。

已知合法差异（informational，不计失败）：
    K1 sys_config 中业务键以 "sys.ai." 开头的行级差异 = config.toml 值的合法物化。
       GET /system/aiConfig 返回双源合并 effective（sys 行空→回落 config.toml 默认），
       有效值零漂移——按行级误报即双源语义误判（RUN-RECIPE §3.46）。
       同理 sys.upload.s3.path_style：功能 89 PUT 回显 effective 值（toml 默认 true）
       物化进 sys 行，有效值零漂移。
    K2 sys_menu 装饰性元数据留档差异（防打地鼠纪律，b57 定性不迁移）：
       4102 remark / 4115 menu_type+icon / 4116 icon / 4117 remark。
       方向不明的生产手调运营态 vs 不可变迁移种子；功能层（perms/parent/path/component）
       零差异。schema 等价性总锁只锁 menu_id+perms，此类漂移靠本工具定期捕获定性。
    K3 代理主键演进合法（b57 ②）：登记业务键的表，自增 PK 列不参与比对——
       键经迁移后期补种时 PK 序必然不同，内容零差异即零漂移。
    K4 运行态列/表：账号态（password/头像/登录时间等）与缓存语义表（sys_shared_kv：
       config:def:* 为 TTL 300s 平台默认缓存层、读时重建；sso:v4_legacy_at_migrated
       为幂等 SETNX 标记、自愈）——内容随运行演进，只计数不比对。

    K5 有意运行态覆写（informational，不计失败）：运行时**可编辑**的配置键（config_type='Y'），
       种子给出的是生产安全默认，本地/e2e 运行库有意覆写为便利值——差异是设计使然。
       当前登记 1 项：sys.account.captchaEnabled（种子 true = 安全默认 vs 运行库 false = e2e 便利态，
       决策见 2026-10-13 批次：种子保持 true，e2e 侧显式维持 false）。

退出码：0 = 无漂移（informational/PENDING 不计）；1 = 存在真实漂移；2 = 用法/IO 错误。
依赖：仅 Python 标准库（sqlite3）。
"""

import os
import sqlite3
import sys

# 中文 Windows 上 stdout 默认 GBK：本脚本的输出里全是 `⇒`、`①`、破折号这类字符，
# 打完就 UnicodeEncodeError 裸栈 ⇒ "哪几条漂移"被编码异常吃掉，退出码与真失败不可区分
# （同 run-gates.py §7.11 那条，b79 在 seed_diff 的 FATAL 分支上再次实测到）。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - 换不了编码（重定向到管道等）不影响判据
        pass

# ---------------------------------------------------------------- 比对配置

# R1：审计列豁免（两库时间/操作人必然不同；sys_webhook_event 用蛇形复数变体）
AUDIT_COLUMNS = {"create_time", "update_time", "update_by", "created_at", "updated_at"}

# R2：业务键映射（优先于 PRAGMA 主键；键会因补种而演进的自增 PK 表必须登记）
BUSINESS_KEY = {
    "sys_config": ("config_key",),
    "sys_msg_template": ("template_code",),
    "sys_dict_type": ("dict_type",),
    "sys_dict_data": ("dict_type", "dict_value"),
    "sys_msg_channel": ("channel_code",),
    "sys_oauth_provider": ("provider_code",),
    # b72：限流档位表按 route_pattern 才是业务身份（中间件精确模板匹配 + `*` 兜底）。
    # 敏感度分档 18 行由 initialize 兜底追加 ⇒ 自增 PK 在两库必然错位（种子库从空库
    # 顺序写、运行库在既有行之后追加），按 PK 比对会报 19 处"假漂移"（b72 实测：
    # 两库 route_pattern 集合与 capacity/refill/enabled 逐条一致，零真实漂移）。
    "sys_rate_limit": ("route_pattern",),
}
# K1：双源合并语义（sys 行空→回落 config.toml，行级差异 = toml 合法物化）
DUAL_SOURCE_PREFIXES = {
    "sys_config": ("sys.ai.",),
}

# K3：代理主键列（登记业务键的表，PK 演进合法，不参与比对）
SURROGATE_PK = {
    "sys_config": "config_id",
    "sys_msg_template": "template_id",
    "sys_dict_type": "dict_id",
    "sys_dict_data": "dict_code",
    "sys_msg_channel": "channel_id",
    "sys_oauth_provider": "provider_id",
    # b72：与 BUSINESS_KEY["sys_rate_limit"] 配对——按 route_pattern 对齐后，
    # 自增 id 在两库必然错位（补种顺序不同），K3 判定为合法演进。
    "sys_rate_limit": "id",
}

# K4：运行态列（账号态随运行演进：口令升级 argon2id/头像上传/登录时间/资料修改）
RUNTIME_COLUMNS = {
    "sys_user": {"password", "password_version", "must_change_pwd", "login_date",
                 "country_code", "avatar"},
}

# K4：运行态表（缓存/标记语义，内容随运行演进，只计数不比对）
RUNTIME_TABLES = {"sys_shared_kv"}

# K1 补充：toml effective 值物化键（F89 PUT 回显物化，有效值零漂移）
MATERIALIZED_KEYS = {
    "sys_config": {
        "sys.upload.s3.path_style": "true",
    },
}

# K2：装饰性留档差异 {menu_id: {列名}}（b57 定性不迁移，防打地鼠；b60 补 4115/4116
# remark——同为生产手调态 vs 迁移种子，方向不明，功能层零差异）
DECORATIVE_MENU_DIFFS = {
    4102: {"remark"},
    4115: {"menu_type", "icon", "remark"},
    4116: {"icon", "remark"},
    4117: {"remark"},
}

# K5：有意运行态覆写（informational）——{(table, key0, col)}。
# 这些键是**运行时可编辑**的配置（config_type='Y'），种子给出的是**生产安全默认**，
# 本地/e2e 运行库有意覆写为便利值；差异是设计使然，非漂移、亦非待拍板。
#   sys.account.captchaEnabled：种子 `true`（RuoYi 上游默认 = 企业级安全默认，防撞库）
#     vs 运行库 `false`（e2e 用例卫生 `restoreCaptchaDisabled()` 主动维持的便利态）。
#     决策（2026-10-13）：**种子保持 true**（新装/生产默认开启验证码），e2e 侧显式维持 false。
INTENTIONAL_OVERRIDES = {
    ("sys_config", "sys.account.captchaEnabled", "config_value"),
}


def quote_ident(name: str) -> str:
    """SQLite 标识符转义（表/列名来自 sqlite_master，仍统一防御）。"""
    return '"' + name.replace('"', '""') + '"'


def list_tables(con: sqlite3.Connection):
    rows = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {r[0] for r in rows}


def table_columns(con: sqlite3.Connection, table: str):
    return [r[1] for r in con.execute(f"PRAGMA table_info({quote_ident(table)})")]


def primary_key(con: sqlite3.Connection, table: str):
    pk = [r[1] for r in con.execute(f"PRAGMA table_info({quote_ident(table)})") if r[5] > 0]
    return tuple(pk) if pk else None


def pick_key(con, table, cols):
    """R2：业务键 → PRAGMA 主键 → None（回退 rowid）。键列缺失则逐级回退。"""
    biz = BUSINESS_KEY.get(table)
    if biz and all(c in cols for c in biz):
        return biz
    pk = primary_key(con, table)
    if pk and all(c in cols for c in pk):
        return pk
    return None


def load_rows(con, table, cols):
    key = pick_key(con, table, cols)
    sel = ", ".join(quote_ident(c) for c in cols)
    out = {}
    if key:
        ksel = ", ".join(quote_ident(c) for c in key)
        for row in con.execute(f"SELECT {ksel}, {sel} FROM {quote_ident(table)}"):
            rec = dict(zip(cols, row[len(key):]))
            k = tuple(row[: len(key)])
            out[k] = rec
        return key, out
    # 无主键回退 rowid（仅种子/配置类小表会走到这里）
    out = {}
    for rowid, *vals in con.execute(
        f"SELECT rowid, {sel} FROM {quote_ident(table)}"
    ):
        out[(rowid,)] = dict(zip(cols, vals))
    return ("rowid",), out


def classify(table, key, col, seed_val, live_val):
    """单列差异分类：'drift' | 'benign' | 'pending'。"""
    k0 = key[0] if key else ""
    # K1 双源物化（sys.ai.* 前缀）+ toml effective 物化键
    for prefix in DUAL_SOURCE_PREFIXES.get(table, ()):
        if isinstance(k0, str) and k0.startswith(prefix):
            return "benign"
    # K1 补充：toml effective 物化键（仅当键显式登记，防 NULL==None 误判）
    if live_val == MATERIALIZED_KEYS.get(table, {}).get(k0) and k0 in MATERIALIZED_KEYS.get(table, {}):
        return "benign"
    # K3 代理主键演进（业务键已对齐，PK 序不同合法）
    if col == SURROGATE_PK.get(table):
        return "benign"
    # K4 运行态列
    if col in RUNTIME_COLUMNS.get(table, set()):
        return "benign"
    # K2 菜单装饰性留档
    if table == "sys_menu" and key:
        if k0 in DECORATIVE_MENU_DIFFS and col in DECORATIVE_MENU_DIFFS[k0]:
            return "benign"
    # K5 有意运行态覆写（种子=生产安全默认，运行库有意覆写；非漂移）
    if (table, k0, col) in INTENTIONAL_OVERRIDES:
        return "benign"
    return "drift"


def diff_table(seed, live, table):
    """返回 (drifts, benigns, pendings, live_only_n)。"""
    if table in RUNTIME_TABLES:
        return [], [], [], None  # None = 运行态表，只计数不比对
    s_cols = table_columns(seed, table)
    l_cols = table_columns(live, table)
    # 结构列集不同：取交集，缺失列单独记 drift（schema 漂移比值漂移更严重）
    common = [c for c in s_cols if c in l_cols and c not in AUDIT_COLUMNS]
    s_missing = [c for c in s_cols if c not in l_cols and c not in AUDIT_COLUMNS]
    l_missing = [c for c in l_cols if c not in s_cols and c not in AUDIT_COLUMNS]

    s_key, s_rows = load_rows(seed, table, s_cols)
    _, l_rows = load_rows(live, table, l_cols)

    drifts = []
    benigns = []
    pendings = []
    # 结构漂移：交集之外的新列在任一库出现
    for c in s_missing:
        drifts.append(("<schema>", c, "存在", "缺失"))
    for c in l_missing:
        drifts.append(("<schema>", c, "缺失", "存在"))

    for k, s_rec in s_rows.items():
        if k not in l_rows:
            drifts.append((k, "<row>", "种子有", "运行库无"))
            continue
        l_rec = l_rows[k]
        for c in common:
            sv, lv = s_rec.get(c), l_rec.get(c)
            if sv == lv:
                continue
            verdict = classify(table, k, c, sv, lv)
            if verdict == "benign":
                benigns.append((k, c, sv, lv))
            elif verdict == "pending":
                pendings.append((k, c, sv, lv))
            else:
                drifts.append((k, c, sv, lv))

    live_only_n = sum(1 for k in l_rows if k not in s_rows)
    return drifts, benigns, pendings, live_only_n


def count_live_rows(con, table):
    try:
        return con.execute(f"SELECT count(*) FROM {quote_ident(table)}").fetchone()[0]
    except sqlite3.Error:
        return -1


# 纯种子库的"真的有内容"下限：schema 面（表数）+ 三张哨兵表存在且非空。
# 下限取 40 而非 67：不同部署档位建的表数会变，但"第二实例根本没起来"那种情况是 **0 张表**，
# 任何合理下限都能抓住（b79 实测：cargo run 因运行中的后端占着 exe 而失败 ⇒ seed-check.db 是
# 0 字节空文件 ⇒ 公共表 0 张 ⇒ 漂移 0 ⇒ 旧版本打 PASS，属"没跑冒充干净"）。
MIN_SEED_TABLES = 40
SEED_SENTINELS = ("sys_menu", "sys_user", "sys_config")


def seed_db_verdict(s_tables, seed):
    """种子库不合格时返回一句原因（不合格 ⇒ 本次对账**不作数**），合格返回 None。"""
    if len(s_tables) < MIN_SEED_TABLES:
        return f"种子库只有 {len(s_tables)} 张表（下限 {MIN_SEED_TABLES}）"
    missing = [t for t in SEED_SENTINELS if t not in s_tables]
    if missing:
        return f"种子库缺哨兵表 {missing}"
    empty = [t for t in SEED_SENTINELS if count_live_rows(seed, t) <= 0]
    if empty:
        return f"种子库哨兵表 {empty} 零行（initialize 没跑完？）"
    return None


def seed_selftest():
    """合成双向：不合格的种子库必须拒绝，合格的必须放行（正控）。"""
    import tempfile

    checks = []
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "s.db")
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE sys_menu (menu_id int)")
        con.close()
        c = sqlite3.connect(p)
        reason = seed_db_verdict({"sys_menu"}, c)
        checks.append(("只有 1 张表 ⇒ 必须拒绝", reason is not None and "1 张表" in reason))
        many = {f"t{i}" for i in range(MIN_SEED_TABLES)}
        checks.append(("表数够但缺哨兵 ⇒ 必须拒绝", seed_db_verdict(many, c) is not None))
        c.close()

        p2 = os.path.join(d, "ok.db")
        c2 = sqlite3.connect(p2)
        for i in range(MIN_SEED_TABLES):
            c2.execute(f'CREATE TABLE "t{i}" (x int)')
        for t in SEED_SENTINELS:
            c2.execute(f"CREATE TABLE {t} (x int)")
            c2.execute(f"INSERT INTO {t} VALUES (1)")
        c2.commit()
        checks.append(("表数够 + 哨兵齐 + 有行 ⇒ 必须放行（正控）", seed_db_verdict(
            {t for (t,) in c2.execute("SELECT name FROM sqlite_master WHERE type='table'")} , c2) is None))
        # 哨兵存在但零行 ⇒ 必须拒绝（这是"库建了、种子没写"那一半）
        c2.execute("DELETE FROM sys_menu")
        c2.commit()
        checks.append(("哨兵零行 ⇒ 必须拒绝", seed_db_verdict({"sys_menu"}, c2) is not None))
        c2.close()
    bad = [name for name, ok in checks if not ok]
    if bad:
        print("[seed_diff] SYNTH_FAIL:")
        for name in bad:
            print(f"  · {name}")
        return 1
    print(f"[seed_diff] SYNTH_OK 种子库发现面 {len(checks)} 条双向（空库/缺哨兵/零行必须拒，合格库必须放行）")
    return 0


def main(argv):
    if "--selftest" in argv:
        return seed_selftest()
    if len(argv) not in (2, 3):
        print(__doc__)
        return 2
    seed_path = argv[1]
    live_path = argv[2] if len(argv) == 3 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "data", "stepby.db"
    )
    for p in (seed_path, live_path):
        if not os.path.isfile(p):
            print(f"[seed_diff] 数据库文件不存在: {p}")
            return 2

    # 单参数用法会把 live 缺省成 data/stepby.db——若 seed 也传同一个文件，比对就是
    # 拿库跟自己比，**恒得"零漂移"的假绿**（批七十六实测踩到：单参数跑出 PASS 0 漂移）。
    # 同文件必须硬失败并说明怎么建纯种子库，而不是给一个看起来通过的结果。
    if os.path.realpath(seed_path) == os.path.realpath(live_path):
        print(
            "[seed_diff] 种子库与运行库是同一个文件（%s）⇒ 校验没有跑，不得当成通过。\n"
            "  先建纯种子库：DATABASE_URL=sqlite://./data/seed-check.db SERVER_PORT=8094 cargo run\n"
            "  再比对：python scripts/seed_diff.py data/seed-check.db data/stepby.db"
            % seed_path
        )
        return 2

    seed = sqlite3.connect(f"file:{seed_path}?mode=ro", uri=True)
    live = sqlite3.connect(f"file:{live_path}?mode=ro", uri=True)

    s_tables = list_tables(seed)
    l_tables = list_tables(live)
    # **先证明"种子库真的建起来了"**，再证明"漂移有几条"。
    # 旧版本缺这一步：第二实例没建成时 seed-check.db 是 0 字节空文件 ⇒ 公共表 0 张 ⇒
    # 按 R3"运行库有、种子无 = 运行数据不计失败"的口径，漂移恒为 0 ⇒ **打 PASS**。
    # 这一条红不是"种子丢了"，而是"校验没有跑"，所以必须用 2（UNRUN）而不是 0。
    bad_seed = seed_db_verdict(s_tables, seed)
    if bad_seed:
        print(
            "[seed_diff] [FATAL] 种子库不合格：%s ⇒ 本次对账**不作数**。\n"
            "  常见原因：第二实例没跑起来（例如后端正占着 target/debug/stepby-axum.exe，"
            "cargo 报 `failed to remove file`）却继续比了那个空文件。\n"
            "  重建：touch data/seed-check.db && DATABASE_URL=sqlite://./data/seed-check.db "
            "SERVER_PORT=8094 cargo run（确认它退出码是 124/被掐，不是 101），\n"
            "  再比对：python scripts/seed_diff.py data/seed-check.db data/stepby.db"
            % bad_seed
        )
        return 2
    skip_seaql = {t for t in s_tables | l_tables if t == "seaql_migrations"}

    common = sorted((s_tables & l_tables) - skip_seaql)
    print(f"[seed_diff] seed={seed_path} live={live_path}")
    print(f"[seed_diff] 公共表 {len(common)} 张（比对）；"
          f"仅运行库 {sorted(l_tables - s_tables - skip_seaql)}（运行数据，跳过）；"
          f"仅种子库 {sorted(s_tables - l_tables - skip_seaql)}")

    total_drift, total_benign, total_live_only, total_pending = 0, 0, 0, 0
    for t in common:
        try:
            drifts, benigns, pendings, live_only = diff_table(seed, live, t)
        except sqlite3.Error as e:
            print(f"[seed_diff] {t}: 读取失败 {e}")
            total_drift += 1
            continue
        total_drift += len(drifts)
        total_benign += len(benigns)
        total_pending += len(pendings)
        if live_only is None:
            n = count_live_rows(live, t)
            total_live_only += n
            print(f"== {t}：运行态表（K4，只计数）运行库 {n} 行")
            continue
        total_live_only += live_only
        if drifts:
            print(f"\n== {t}：漂移 {len(drifts)} 处")
            for k, c, sv, lv in drifts:
                print(f"   key={k} col={c}: seed={sv!r} -> live={lv!r}")
        if benigns:
            print(f"== {t}：informational 豁免 {len(benigns)} 处")
            for k, c, sv, lv in benigns:
                print(f"   key={k} col={c}: seed={sv!r} -> live={lv!r}")
        if pendings:
            print(f"== {t}：PENDING 待拍板 {len(pendings)} 处（不计失败）")
            for k, c, sv, lv in pendings:
                print(f"   key={k} col={c}: seed={sv!r} -> live={lv!r}")
        if live_only:
            print(f"== {t}：运行库独有 {live_only} 行（运行数据，不计失败）")

    print(f"\n[seed_diff] 结论：漂移 {total_drift} | 豁免 {total_benign} | "
          f"PENDING {total_pending} | 运行库独有 {total_live_only} 行")
    if total_drift == 0:
        print("[seed_diff] PASS：种子零漂移")
        return 0
    print("[seed_diff] FAIL：存在真实漂移，须逐条定性后处理")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
