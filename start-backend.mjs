/**
 * 后端启动器（detached 托管）：以 node 孤儿模式拉起 stepby-axum.exe，
 * 规避 PowerShell 后台任务死亡连带杀 cargo 的问题（node detached 已实证存活）。
 * CWD 必须为仓库根（main.rs 硬编码 config/config.toml）。
 */
import { execFileSync, spawn } from 'node:child_process'
import path from 'node:path'

// 路径按脚本所在目录推导：写死盘符/工作目录的启动器，仓库一搬家就指向别人的树
// （本仓踩过一次：跑 localhost:8080 的验证实际测的是另一棵恢复树里的旧 exe）。
const ROOT = import.meta.dirname
const EXE = path.join(ROOT, 'target', 'debug', 'stepby-axum.exe')
const PROBE = 'http://127.0.0.1:8080/captchaImage'

async function up() {
  try {
    const r = await fetch(PROBE, { signal: AbortSignal.timeout(3000) })
    return r.ok
  } catch {
    return false
  }
}

/**
 * 8080 上那个进程到底是哪个 exe。
 * /health 不打印构建身份（未鉴权端点不宜暴露构建信息，见 C.9），所以只能在本地侧核对
 * 监听进程的可执行路径——否则"服务已就绪"这个早退分支会把**另一棵树/上一轮的 exe**
 * 当成当前构建，整套浏览器验证跟着失效（2026-10-19 实测踩中：恢复树里的 debug 进程
 * 从 09:12 起一直占着 8080，之后的 e2e 全打在过期二进制上却毫无提示）。
 */
function listenerExe() {
  const cmd =
    '$c = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; ' +
    'if ($c) { (Get-CimInstance Win32_Process -Filter "ProcessId=$($c.OwningProcess)").ExecutablePath }'
  try {
    return (execFileSync('powershell', ['-NoProfile', '-Command', cmd], { encoding: 'utf8', timeout: 20000 }) || '').trim()
  } catch {
    return ''
  }
}

if (await up()) {
  const running = listenerExe()
  if (!running) {
    console.log('ALREADY_UP（取不到监听进程镜像路径：非本机 Windows 服务，跳过身份核对）')
  } else if (path.resolve(running).toLowerCase() === path.resolve(EXE).toLowerCase()) {
    console.log(`ALREADY_UP（${running}，与本启动器同产物）`)
  } else {
    console.log(`[FATAL] 8080 被**另一个二进制**占用：\n  实际运行：${running}\n  本仓期望：${EXE}\n` +
      `  继续跑测的就是那棵树的代码，不是当前工作树。先停掉该进程；确实要连远端/容器服务时加 --allow-remote。`)
    process.exit(process.argv.includes('--allow-remote') ? 0 : 1)
  }
  process.exit(0)
}

// 与 _start_server.py 同口径：debug 构建默认"前端分离模式"（未匹配路由返回 JSON 404），
// e2e 的 SPA 深链/SSO 同意页必须走嵌入式前端，否则 8080 直连渲染不出登录表单。
const child = spawn(EXE, [], {
  cwd: ROOT,
  detached: true,
  stdio: 'ignore',
  env: { ...process.env, EMBEDDED_FRONTEND: process.env.EMBEDDED_FRONTEND ?? 'true' },
})
child.unref()

for (let i = 0; i < 45; i++) {
  await new Promise((r) => setTimeout(r, 2000))
  if (await up()) {
    console.log(`BACKEND_UP pid=${child.pid} after=${(i + 1) * 2}s`)
    process.exit(0)
  }
}
console.log('TIMEOUT_NOT_UP')
process.exit(1)
