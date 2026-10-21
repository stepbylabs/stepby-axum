# Changelog

本文件记录 Stepby 的显著变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.3.0] - 2026-10-20

自 0.2.0 以来的累计发布：把此前"写进规范、没有实现"的五条工程硬基线（敏感操作独立限流、外部依赖
健康检查、组件级指标、异步任务统一范式、重资源背压）补齐到可证伪程度；迁移首次具备**可执行的回滚
通道**并在 SQLite/MySQL/PostgreSQL 三库真库跑通 `up → down → up`；补齐 Helm / Compose / Prometheus
交付面；集中根除上传链、权限指令、图表首绘、列头排序、公告已读、绝对路径泄露、非法数据权限档位等
用户可见缺陷。

### 新增

- **敏感操作独立限流**：`initialize/rate_limit.rs::SENSITIVE_LIMIT_TIERS` 为档位单一事实源，幂等播种
  **56 条**路由模板级限流（本人改密、重置他人密码、TOTP 绑定/校验/解绑、Passkey 注册、PAT AK 轮换与
  吊销、OAuth client secret 轮换、会话吊销、备份恢复与自导出、租户恢复、用户匿名化、批量删除/提权、
  各类 `*/clean` 审计销毁面），只补缺失 `route_pattern`、不覆盖管理员调过的值；三条形状锁（必须 ⊆
  router 注册模板 / 必须严格紧于全局默认 / 必须 `{id}` 占位符形态）常驻 `cargo test`，写成真实路径
  会静默失配回落 `*` 的坑当场判红
- **外部依赖健康探活**：`[health].external_probes = off|basic`（**默认 off，off 档响应体与 0.2.0 逐字段
  等价**并有契约锁）+ `handler/health_probes.rs` 五个零副作用探针（SMTP 只做 handshake、AI 只
  `GET /models` 零 token、对象存储写-删往返不留残留、webhook 只数库不投递、IP 库只 DNS TXT）；超时
  clamp 200..=10000ms + 结果缓存 + 同轮互斥，`SKIPPED` 在聚合中中性（可选依赖未配置 ≠ 实例不健康）
- **后台任务统一范式**：`common/background.rs::spawn_tracked(label, budget, metrics, fut)` = 超时 +
  panic 隔离 + 失败留痕 + `bg:<label>` 指标，13 处裸 `tokio::spawn` 全部改造；长驻循环（WS 读写环、
  调度器主循环、投递 worker）在 EXEMPT 表逐条带理由豁免，新增裸 spawn 被形状锁与 `spawn_unguarded`
  扫描器双双拦下；本层刻意不重试（重试策略属业务语义）
- **组件级出站指标**：`stepby_outbound_requests_total{component,outcome}` +
  `_duration_seconds{component}`（outcome ∈ `ok|error|timeout|rejected|panic`），多 `?` 出口的函数用
  RAII `OutboundGuard`；标签按**故障面**分桶（`oauth_token`/`oauth_userinfo` 拆开、
  `storage:<kind>:<op>` 带 op、webhook 排除审计写失败），对象存储用构造点装饰器 `TracedBackend`
  而非改实现或改调用点；后续补齐 acme/outbox/upload_scan/sso_logo/ai_config_test/ip_geo/http_debug
  等出网点，并由扫描器按"构造点 ⇒ 必被 guard 覆盖"常驻对账
- **重资源入口背压**：AI 推理并发闸 `[ai].max_concurrency`（默认 4，`/ai/chat` 与 `/ai/replay` 共用
  `ai/gate.rs::inference_gate`，闸满立即 **429 + Retry-After + `error.ai.busy`**）；WebHook 投递
  16 permits 取**排队**。两者语义刻意相反——可重来的人类请求取拒绝、不可重放的出站事实取排队
- **请求行长度上限**：`[server].max_uri_bytes`（默认 16384，`0` = 显式回退不设限）+
  `middleware::uri_limit`，超限 414 + 统一错误契约，日志只记长度（查询串常含 token/验证码）；
  判据含"8KB 合法查询必须照常 200"对照组，模板值与代码默认值双向钉死
- **凭据强度与可观测**：Argon2id 参数从依赖默认改为五个**显式常量**并以 `const _: () = assert!(…)`
  编译期钳住下限（弱档一旦合入即构建失败，PHC 前缀会随常量一起变）；新增
  `stepby_credential_verify_total{algorithm,outcome}` + `_duration_seconds{algorithm}`，`outcome` 区分
  `mismatch` 与 `malformed_hash`（避免"存储被截断"混进"密码错误"淹没暴力尝试信号）
- **保留期与补偿**：`[sys_log].retention_catchup_on_start`（默认开）——清理成功写 SharedStore
  `retention:last_success_at`，启动时标记缺失/不可解析/距今 ≥20h 即补跑（多副本经 `set_nx_ex` 收敛到
  单实例），阈值之间的结构不变式编译期钳住；读标记失败一律按"需要补跑"。新增
  `frontend_vital_retention_days` 分档（默认 `None` = 与错误日志同一谓词、行为不变），性能采样可
  按更长周期留档以便对照历史基线；`config.toml.example` 补齐此前"代码里有、模板里从没写过"的
  三个保留期键
- **数据权限档位白名单**：`common/data_scope.rs::DATA_SCOPE_VALUES = [1,2,3,4,5]` +
  `is_valid_data_scope()`（单字符 + 白名单双闸，同时挡下 `"9"` 与可解析但不合法的 `"02"`），挂在角色
  新增 / 编辑 / `update_data_scope` 三条写入路径，被拒载荷不落库
- **补齐"有引擎、无入口"的断头链路**：审批**减签**按钮
  （`POST /system/flow/task/{id}/countersign-del`，只挂会签族行——单审行减签必撞后端防线）+ 流程
  动作字典双语补全；报表**数据集编辑框回填 SQL 明文**（此前恒为空串，改个备注也被迫重敲整段 SQL）；
  消息发送记录**「标记待重试」批量入口**（受 `system:msg:log:retry` 授权，如实提示真正交回队列的条数）
- **公告已读态闭环**：`/system/notice/list` 与 `listTop` 改返 `NoticeRowVo`（`#[serde(flatten)]` 保证
  既有字段逐字段等价），按行下发 `isRead`；读侧新增按页规模收敛的 `find_read_notice_ids_in`，与铃铛
  `count_unread` **共用同一 `tenant_scope` 谓词**
- **前端错误来源反向过滤**：`excludeSource`（白名单校验 + `NOT IN`），"前端错误"页默认排除性能采样
- **部署形态**：`cargo run -p migration -- --down [步数]` 回滚入口（逐条步进、失败打印"卡在哪个迁移 /
  已退几条 / 仍余几条"，未知 flag 退出码 2）；补齐 `deploy/docker-compose.db.yml` 与两个生产编排
  （`compose config --quiet` 全绿）；完整 Helm 图表（`helm lint --strict` 0 失败 + 渲染矩阵含
  必须失败的反例 + values↔`settings.rs` env 名审计 + 渲染出的 nginx `default.conf` 与
  `stepby-vue/nginx.conf` 指令逐条一致）；Prometheus 规则多组（`promtool check rules` 通过，指标名
  对齐 `/metrics` 真实暴露的 `stepby_*`）；`build-all.ps1` / `rollback.sh` / `wrk-smoke.sh` /
  `k6-smoke.js` 入库
- **部署态环境变量**：新增 `TRUSTED_PROXIES` / `DOCS_ENABLED` 覆盖（此前两键在容器形态无任何注入口，
  而上线清单把 `trusted_proxies` 列为硬要求——不配则多租户域名链路静默回落平台租户）、
  `WEBAUTHN_ORIGIN` / `WEBAUTHN_RP_ID` 覆盖（容器与 E2E 自含注入，空白值忽略）
- **公开仓自治交付**：axum / vue 各自下发 CI + Security + Release 流水线；Release 增加**产物冒烟门禁**
  （下载 linux 产物零配置起服，断言 `/health` UP、`/` 返回嵌入 SPA、`/captchaImage`，不过则不发布）+
  `checksums.txt` + dependabot 周更；`RUSTDOCFLAGS="-D warnings" cargo doc` 文档门禁
  （rustdoc intra-doc 警告 107 → 0）

### 变更

- **落库时间口径单一事实源**：写入路径统一 `common::datetime::now_naive()`，迁移与启动兜底侧的
  `now_expr()` 副本归口为 `migration::seed_now_expr()`，三方言统一写 **UTC 字面量**
  （`NOW()` 取会话时区，换库即换口径）；新增静态形状锁禁止 DB 写入路径出现 `chrono::Local::now()`，
  合法的展示/调度用法逐处定性后进 EXEMPT 表（不做一刀切替换）
- **平台专属归属收敛为单一事实源**：凡挂 `platform_only_guard` 的路由组，其 perms 前缀必须进
  `PLATFORM_ONLY_PERM_PREFIXES`，反向亦然——根除"租户看得见『告警规则』菜单、点进去一律 403"的假入口
- **`common` 角色（role_id=2）写权限判据收敛**：`governance::COMMON_ROLE_*` 成为唯一判据，新增菜单的
  写按钮默认不发放，例外必须进 `COMMON_ROLE_WRITE_EXCEPTIONS` 并带理由；配套窄撤销迁移只挂在一次性
  迁移上，启动兜底不再回收；治理"收回"与"发放"的**顺序不变式**由常驻锁同时钉住生产与测试 harness 两侧
- **机器遥测通道不再写操作日志**：`/monitor/frontendError/report` 按精确路径排除（不用前缀通配），
  操作审计恢复信噪比（此前实测最近 100 条里 97 条是遥测流水）；上报链路零改动
- **磁盘日志去 ANSI**：文件层**先于** stdout 层注册（tracing 的 span 字段串由第一个 `on_new_span` 的层
  生成并复用），stdout 层颜色按 `IsTerminal` 判定——此前日志文件不可 grep、`/monitor/logtail` 显示乱码、
  按 `request_id=` 聚合完全失效
- **存储档位回显改为生效档位**（`effective_backend_mode()` 取代出厂快照），消除"管理端显示 S3、
  实际写本地"的行为分裂；依赖与安全升级：rustls 0.23.46（多条 RUSTSEC 公告）、ammonia 4.2.3、
  vue 3.5.43（GHSA XSS）、CI 与 Dockerfile 统一 Node 22（`engines.node >= 22.13` + `engine-strict`）

### 修复

- **最小镜像里后端根本起不来（发布产物级缺陷）**：`SysOauthService::new` / `SysWebHookService::new`
  挂在 AppState 构造里，出站 `reqwest::Client` 以 `.expect("不会失败")` 构建。宿主没有系统信任库时
  （`debian:bookworm-slim` 实测 `ca-certificates` 为 un、`/etc/ssl/certs` 不存在）rustls 的
  platform-verifier 取不到根证书 ⇒ 构造返回 Err ⇒ **启动即 panic**，于是"零配置单文件"产物在这类
  宿主上前端/接口/定时任务全不可用。出站客户端构造收进 `common::outbound_client` 单一事实源：
  主路径用系统信任库，失败时回落到**内嵌 Mozilla 根证书**（能力不砍、校验强度不降、WARN 留痕），
  8 处构造点取不到客户端时按各自既有终态降级——webhook 仍写审计行并记 `rejected`（未发起出站不混进
  `error`）、oauth 回 500 + `error.oauth.tls_unavailable`、调试器回 `transport_error`。
  本项由 v0.3.0 本机打包的 arm64 容器冒烟实测照出（`thread 'main' panicked at
  src/service/sys_oauth_service.rs:385`），非推断。

- **UI 上传的文件整体丢失**：axios 实例顶层默认 `Content-Type: application/json` 使 `FormData` 被
  `transformRequest` JSON 化，真实上线字节只有 `{"file":{"uid":…}}`，`POST /system/file/upload` 报
  `Invalid boundary`（该默认头自首个提交起污染全部经 `service` 的上传）；改为上传载荷一律压制
  Content-Type，并加 wire-level 回归锁与"禁手写 multipart 头"静态守卫。同族：MarkdownEditor 手动
  无 boundary 头 + 把成功响应误判为失败（URL 在 `data.url`），改走类型化 `uploadFile`
- **权限指令把按钮永久隐藏**：`hasPermi` / `hasRole` 的"恢复显示"分支把原值采集写在
  `display='none'` **之后**，权限由无到有后恢复的就是 `none`（授权页签来回切换必然触发）；
  抽 `hide()` 先采集再隐藏，四原值 `it.each` 矩阵 + 形状锁
- **缓存概览两张图表首屏纯空白**：`<Transition mode="out-in">` 使模板 ref 在 `nextTick` 后仍为 `null`，
  旧代码第一张失败就 `return` 且不置错误态；新增 `waitForRef` 轮询挂载、两图独立、无数据渲染
  `el-empty`，`local` 档基本信息改按真实 `mode` 诚实显示而非臆造
- **列头排序被页面自己丢掉**（点「操作日期」后仍是倒序）：`syncUrlQuery` 写 URL → `route.fullPath`
  为 key 重建组件 → `restoreQueryFromUrl` 只认初始查询里已声明的键，而 4 个页面从未声明
  `orderByColumn`/`isAsc`；四页补键 + 表头箭头回灌 + 重置拉回默认
- **公告"标记已读"重复点击报 400「数据重复」**：sea-orm 在 SQLite 上不注入无冲突目标的
  `ON CONFLICT`，改为 `on_conflict_do_nothing_on([notice_id, user_id])` 并删除方言分支
- **公告已读态刷新后整页退回未读，而角标显示 0 未读**：`isRead` 是"前端一直在读、后端从来没有发"的
  字段（列表端点返裸 `Model`），内存态每次刷新被恒为 `undefined` 的值重建为空集
- **表单校验失败导致整页被换成「页面加载失败」**：Element Plus 零参 `validate()` 失败返回被拒绝的
  Promise，裸 `await ref.value?.validate()` 让拒绝逸出到 ErrorBoundary，用户看不到"哪一格没填"；
  新增单一入口 `utils/formValidate` + 全仓形状锁
- **富文本"打开、一个字没改、点关闭"弹「内容尚未保存」**：Quill 初始化把纯文本规范化成 `<p>…</p>`
  回写表单，且这笔程序写入也被报成 `source='user'`（按 source 过滤无效）；改为以真实用户事件
  `userArmed` 作回写闸门，插图/删图走显式同步
- **打满一个敏感端点即饿死全站**（`/profile/updatePwd` 到第 6 次 429 后 `/system/user/list` 也 429）：
  桶键只按 (租户, IP) 分档共用；改为命中自有档位走路由级桶、回落 `*` 才走共享桶，端到端隔离锁
- **`/metrics` 首次抓取 `stepby_uptime_seconds` 恒为 0**：起算点在首次渲染指标时才初始化，
  改由路由装配路径打点
- **免鉴权的 `/health` 把文件系统绝对路径交给未认证访问者**：探针 detail 原样带出
  `D:\...\uploads\file`；双层修——源头只报 `file_name()` + 折叠判据抽成 `common::redact` 单一事实源，
  `AppError::into_response` 增加出口折叠（发生折叠时打 WARN），边界口径同时钉住"不误伤 URL/端口/
  单段 API 片段"
- **报错文案显示原始键名**：`dataRule` 整块 8 个键被追加在 yml 末尾的 `alert:` 节之下，
  `tr!` 查不到时把键名原样返回，而"与同一条 `tr!` 比较"的单测两侧同时是键名 ⇒ 恒真；移入 `error:` 节 +
  三把锁（键字面量必须在 zh/en 双语可解析、两份 yml 键集必须相等、扫描器自检）。同族修复：
  5 处 DTO `derive(Validate)` 却用裸提取器接收，garde 规则**编译通过但永不执行**（任意长度凭据被拼进
  SharedStore 键、任意长度状态直接落库），补齐 `ValidatedQuery<T>` 并加执行锁
- **角色数据权限非法档位被 200 接受并落库**：`PUT /system/role/dataScope` 传 `dataScope="9"` 返回
  「修改成功」，管理端显示"9"而实际过滤是"本部门"，`'02'` 一类还能压过其他角色的合法档；改为写入侧拒绝
- **畸形深链发成注定失败的出网请求**：四处 `Number(route.params.x)` 对 100 位数字串不抛错而折成
  `1.11e+99` 拼进 URL（实测 `GET /system/user/authRole/1.111111111111111e+99` → 400）；统一走
  `toPositiveInt`（`^\d{1,15}$` + `Number.isSafeInteger` 双闸），URL 注入查询对象改为"往返无损才接受"，
  并加全仓禁裸 `Number(route.` 的形状锁
- **自由字符串拼进 URL 路径段导致"清理/查询指令静默打错目标"**：缓存键名含 `#` 时后半段被当片段丢弃，
  `clearCacheKey` 会删掉**另一个**键；9 处统一 `encodeURIComponent` + 后端解码往返单测 + 键名两端闭合对账
- **消息「标记待重试」会把已送达的收件人再发一遍真实短信/邮件**（旧实现不带状态条件，批量勾选必然混入
  成功行），且失败终态行交回后既不发送也不再判定失败（死信变死循环）；改为只交回 `status='1'` 并同步
  `retry_count = 0`
- **MySQL 存量库每次启动在"初始化图驱动单据表"这一段硬失败**，且"MySQL 整段跳过、注释写交由
  migration 补齐"的 5 处使 `sys_pat.token_hash`、`sys_user_credential`、`sys_user_dept`、
  `sys_scim_group*`、flow 若干索引在只靠兜底段建表的库上**永远不存在**；索引 DDL 收口为唯一一份
  方言存在性探测实现（`ensure_index_ddl` / `ensure_index_ddl_in_tx`），删除全部按方言分支
- **迁移"可回滚"长期是注释里的承诺**（121 条 `down()` 从未被执行过）：演练照出 3 个缺陷——唯一未写
  `down()` 的迁移会把回滚停在半路、`DROP INDEX IF EXISTS` 在 MySQL 报 1064、
  `multitenant_phase2` 的 `down()` 对多张表无条件删只在少数大表建过的组合索引；现由常驻锁逐条要求
  每条迁移实现 `down()`
- **顶栏「刷新当前页」必然崩到 /500**：`delCachedView`/`delView` 是同步 action（返回数组非 Promise），
  `.then()` 同步抛 `TypeError` 且调用方 `.catch()` 兜不住；`useCrudTable` 重置按钮在全部 URL 同步页
  失效（重挂载实例的 EP `initialValue` 被搜索值污染），改为 URL 恢复前快照干净默认值；
  observability `local` 档把"不适用"渲染成 `0s/0 B/0`，改为后端下发 `storeKind` 单点判定
- **进程被杀后备份日志永久停在 `running`**（备份页显示一个"永远在跑"的备份，轮转口径也绕开它）：
  启动期 `reconcile_interrupted_backups()` 只把**早于阈值**的行收敛为终态、只改状态不删行、幂等
- **Passkey 绑定报「WebAuthn 响应无效」却无任何语境**：真因是 `OriginMismatch` 落进无日志的兜底分支，
  被误读为算法不支持；补专用分支与期望/实到来源日志（响应仍统一 400 不泄露信任锚）。同批订正
  「广播 RS256」的错误方向——`passkey-server` 只实现 P-256 验签，只广播 ES256 才是正确的
- **WebHook 批量重试把数据库故障折叠成"用快照 URL + 无密钥投递"并谎报成功**；
  分页 `offset` 在超大 `pageNum` 下饱和到 `u64::MAX` 后转 `i64` 翻负在 DB 层报错，改为钳到
  `i64::MAX` 并抽 `offset_of()` 单一事实源；handler 生产码 `.unwrap()` 清零并加防 panic 总锁；
  通知群发等处把整行 `sys_user`（含 argon2 摘要）读进内存改为列投影；模板裸绑把
  `PointerEvent` 洗成导出文件名（7 个页面）

### 测试与质量基线

- 后端 lib 测试 **1554 passed / 1 ignored**（含 `integration_tests::` 305 条，隔离临时库 + teardown）
- 前端单测 **100 文件 / 1253 例**（vitest）
- E2E 主套件 **144 features / 1260 断言 / 0 失败**；深测 deep-e2e **88 模块 / 1231 断言 / 0 失败 / 34 SKIP**
- a11y 全站 **56 条路由 / 560 检查 / 0 FAIL**
- criterion 热路径基准 **5 组**（`masking` / `ak_sign` / `sort` / `webhook_legacy_events` /
  `password_verify`），每组实测耗时写进基准文件顶部注释
- 常驻扫描器十把（断言棘轮、视图可达性、DB 状态审计、租户隔离门禁、种子漂移审计、Markdown 表格守卫、
  页状态判据自检、逐条 verdict 差集、测试数据态审计、出站请求密度棘轮、写端点触达对账）全部接入
  `run-gates.py` 与 `preflight-check.sh §7`；判据自身均带合成双向用例与变异证伪凭证

### 升级指引

- **数据库**：迁移全部前向，且本版起具备回滚通道
  `DATABASE_URL=<连接串> cargo run -p migration -- --down [步数]`（逐条步进，未知 flag 退出码 2）；
  启动期 `ensure_*` 兜底只补缺失项，不覆盖管理员调过的值。
- **新增配置键（默认值 = 现状，存量部署零行为变化）**：`[health].external_probes = "off"`（off 档
  `/health` 响应体与 0.2.0 逐字段等价）、`[sys_log].frontend_vital_retention_days`（缺省与错误日志
  同一谓词）、`[sys_log].retention_catchup_on_start = true`（删除幂等，漏跑补偿）。
- **两处"默认即新行为"需要知晓**：`[server].max_uri_bytes = 16384`——超长请求行/查询串现在返回 414
  而不再无声通过（写 `0` 可显式关闭）；`[ai].max_concurrency = 4`——AI 推理闸满立即
  429 + `Retry-After`（`/ai/chat` 与 `/ai/replay` 共用同一道闸）。
- **`sys_rate_limit` 行数增加**：敏感操作档位共 56 条，播种只补缺失 `route_pattern`，
  管理员已调过的值不被覆盖。
- **`common` 角色（role_id=2）的越权写权限由窄撤销迁移收回**：此前多批习惯性发放的写按钮已按
  `governance::COMMON_ROLE_*` 单一判据回收；依赖这些按钮的自定义角色需管理员重新授权
  （回收语句只挂在一次性迁移上，启动兜底不再回收）。
- **前端构建要求 Node ≥ 22.13**（`engines` + `engine-strict`），CI 与 Dockerfile 统一 Node 22、
  pnpm 11；低于该版本会在安装期直接 fail-fast 而不是留下看不懂的原生模块错误。

## [0.2.0] - 2026-10-12

自 0.1.0 开源基线以来的累计发布：审批工作流引擎深化、AI 问数助手、可视化大屏、
SSO/OIDC Provider 完整化、细粒度权限、审计归档与保留期治理、单文件零依赖部署。

### 新增

- **审批工作流引擎**：流程定义版本化与发布不可变、聚合判定单点收敛（`settle_node`）、
  加签/减签/委派后自动重新收敛、图驱动单据（flow_graph_doc）、超时扫描与提醒通知（防打扰）
- **AI 助手**：LLM 接入双源配置（`sys.ai.*` 运行时键覆盖 `config.toml [ai]`，热生效）、
  AI 问数（受控 NL2SQL，表级白名单防注入）、问数历史（平台跨租户 / 租户管理员本租户）
- **报表中心**：受控数据集（新增/编辑/删除/试跑，preview 权限合并模型）、
  可视化大屏（布局 JSON schema 校验）、报表订阅推送（cron 定时计算 + 邮件/站内信投递）
- **安全与身份**：OIDC Provider（RS256 签名 id_token、Refresh Token 轮换与重放拒绝、
  SCIM Group 同步、JWKS 公钥端点）、WebAuthn / Passkey、TOTP 双因子、
  PAT（Personal Access Token）、统一 OAuth 登录 consent 页
- **细粒度权限**：数据权限规则（挂角色生效、查询期显式注入）、字段级权限矩阵（全量覆盖）、
  敏感操作独立限流通道、权限 fail-closed 中间件
- **审计合规**：操作日志差异对比（变更前后明细）、审计变更留痕、
  审计日志归档（锚点编排 + 链完整性校验 + 归档下载）、
  **七类日志保留期自动清理**（frontend_error 7 天 / audit_change 180 天 /
  msg_send_log 90 天且待发送记录永不清 / oper_log·logininfor 90 天），
  cron 与手动触发完全同源
- **运维能力**：单文件零依赖部署（前端资源嵌入后端二进制，双击即跑）、
  SharedStore 双档共享态（local 纯 SQL / redis 双写）、告警规则、
  webhook 事件目录、IM 群机器人通知（企业微信 / 钉钉，webhookUrl + 加签）
- **工程化**：种子漂移审计常驻工具（`scripts/seed_diff.py`，纯种子库与运行库逐行列 diff，
  比对口径内建豁免、退出码可接 CI）；Helm 图表 `appVersion` 对齐

### 变更

- 前端构建升级 Vite 8（rolldown）；Element Plus 2.14
- axios 升级至 1.20.0（安全版本）
- 测试基线：后端 lib 测试 **1349**、e2e **135 features / 1173 断言**全绿、
  a11y 全站 **560 检查**、deep-e2e 84 模块

### 修复

- `edit_config` 部分更新语义：DTO `Option` 字段 `None` = 保留现值，
  杜绝部分载荷静默抹掉 config_name/value/type/remark 四列
- 菜单兜底与迁移种子对齐：4140-4147 remark 镜像迁移终态、4148 修正行 NULL 残留补齐、
  4122 畸形挂载收敛（initialize 幂等兜底，存量库交付机制）
- 皮肤/主题配置键治理：`platform_default` + 租户可覆盖/可见（全新库租户覆盖语义可用）
- 配置治理列补齐（config/模板按业务键比对，种子零漂移）

## [0.1.0] - 2026-10-01

首个开源基线发布。

- Rust (Axum) + Vue 3 中后台管理系统：用户/角色/菜单/部门/字典/岗位/参数/通知/
  定时任务/代码生成/系统监控
- SharedStore 双档共享态（`auto | local | redis`，单文件零依赖部署）
- 多租户（租户管理、套餐能力位、数据隔离）
- SSO / OIDC Provider 基础能力
- 审批工作流（两级审批）
- JWT 认证（argon2 密码哈希、TOTP）、权限 fail-closed
- 可观测性（Prometheus `/metrics`、慢请求/错误日志聚合、tracing 结构化日志）
- PWA 移动端可用、中英双语 i18n、a11y 无障碍支持
- GitHub Actions CI（fmt + clippy + test + 前端 typecheck/lint + cargo-audit/gitleaks）

[0.3.0]: https://github.com/stepbylabs/stepby-axum/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/stepbylabs/stepby-axum/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/stepbylabs/stepby-axum/releases/tag/v0.1.0
