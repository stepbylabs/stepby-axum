/**
 * 后端启动器（detached 托管）：以 node 孤儿模式拉起 stepby-axum.exe，
 * 规避 PowerShell 后台任务死亡连带杀 cargo 的问题（node detached 已实证存活）。
 * CWD 必须为仓库根（main.rs 硬编码 config/config.toml）。
 */
import { spawn } from 'node:child_process'

const EXE = 'D:/Projects/stepby/stepby-axum/target/debug/stepby-axum.exe'
const CWD = 'D:/Projects/stepby/stepby-axum'
const PROBE = 'http://127.0.0.1:8080/captchaImage'

async function up() {
  try {
    const r = await fetch(PROBE, { signal: AbortSignal.timeout(3000) })
    return r.ok
  } catch {
    return false
  }
}

if (await up()) {
  console.log('ALREADY_UP')
  process.exit(0)
}

const child = spawn(EXE, [], { cwd: CWD, detached: true, stdio: 'ignore' })
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
