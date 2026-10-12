# Changelog

本文件记录 Stepby 的显著变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

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

[0.2.0]: https://github.com/stepbylabs/stepby-axum/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/stepbylabs/stepby-axum/releases/tag/v0.1.0
