# -*- coding: utf-8 -*-
"""后端 detached 启动器（脱离 PowerShell 后台任务的 10 分钟 timeout 生命周期）。

用法:
  python _start_server.py [log文件名]        # 默认 server.log
  python _start_server.py server8.log

路径全部按脚本所在目录（仓库根）推导，可用环境变量覆盖:
  YEBOT_BACKEND_EXE   可执行文件路径（默认 <仓库根>/target/debug/axum-backend.exe）
  YEBOT_BACKEND_CWD   工作目录（默认 <仓库根>，config 相对路径依赖此目录）

前置: cargo build 已产出 debug exe；redis 等依赖已就绪。
完成后用 netstat -ano | findstr :8080 核对 PID 与日志确认就绪。
"""
import os
import subprocess
import sys

DETACHED = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP

ROOT = os.path.dirname(os.path.abspath(__file__))
EXE = os.environ.get('YEBOT_BACKEND_EXE', os.path.join(ROOT, 'target', 'debug', 'axum-backend.exe'))
CWD = os.environ.get('YEBOT_BACKEND_CWD', ROOT)
LOG = os.path.join(ROOT, sys.argv[1] if len(sys.argv) > 1 else 'server.log')

env = os.environ.copy()
# debug 构建默认"前端分离模式"（未匹配路由 JSON 404）；置 true 启用嵌入式前端
# （从 frontend-dist/ 服务 SPA）——e2e 的 SSO 同意页/RP 回跳/深链与功能 24 依赖该模式。
# detached 进程不继承交互会话环境变量，必须在启动器内固化。
env.setdefault('EMBEDDED_FRONTEND', 'true')

p = subprocess.Popen(
    [EXE],
    cwd=CWD,
    env=env,
    stdout=open(LOG, 'w', encoding='utf-8'),
    stderr=subprocess.STDOUT,
    creationflags=DETACHED,
)
print('detached PID:', p.pid, 'log:', LOG)
