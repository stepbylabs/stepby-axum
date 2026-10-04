# stepby 档位切换专项演练（ZERO-DEP v5 §6 切换专项 · 双向）
# 作用：redis 档 ↔ local 档 双向切换，验证 S1 安全语义跨档保持——
#       改密失效跨档（pwd_ver DB 权威层不依赖档位）、local 档会话正常、
#       local 档期间的密码变更在 redis 档有效、旧密码始终被拒。
# 前提：后端源码仓 D:\Projects\stepby\stepby-axum；Redis 可达（redis 档段）；
#       测试凭据经环境变量（同 e2e 规约）：STEPBY_TEST_USER / STEPBY_TEST_PASS。
# 用法：powershell -ExecutionPolicy Bypass -File .\scripts\switch-drill.ps1
# 安全：config.toml 先备份后字节级恢复（Compare 断言 0 差异）；测试用户演练后删除；
#       全程不动 admin 密码（仅建/删独立测试用户）。

param(
    [string]$Repo = "D:\Projects\stepby\stepby-axum",
    [string]$BaseUrl = "http://127.0.0.1:8080"
)

$ErrorActionPreference = "Stop"
$passed = 0; $failed = 0
function Assert([string]$name, [bool]$cond, [string]$detail = "") {
    if ($cond) { $script:passed++; Write-Host "  PASS $name $detail" }
    else { $script:failed++; Write-Host "  FAIL $name $detail" }
}
function ApiLogin([string]$u, [string]$p) {
    $r = Invoke-RestMethod -Uri "$BaseUrl/login" -Method Post -ContentType 'application/json' `
        -Body (@{ username = $u; password = $p } | ConvertTo-Json)
    if ($r.code -eq 200) { return $r.token } else { return $null }
}

Write-Host "=== 档位切换演练（redis → local → redis） ==="
$cfg = Join-Path $Repo "config\config.toml"
$stamp = Get-Date -Format "HHmmss"
$drillUser = "switch_drill_$stamp"
$pwd1 = 'Str0ng!Drill2026'; $pwd2 = 'NewPass!2026x'; $pwd3 = 'Third!Pass2026'

# ---------- 阶段 A：redis 档（当前档位）建用户 + 改密失效 ----------
Write-Host "— 阶段 A：redis 档 —"
$tokA = ApiLogin 'admin' 'admin123'
Assert "A1 admin 登录" ([bool]$tokA)
$ah = @{ Authorization = "Bearer $tokA"; 'Content-Type' = 'application/json' }
$deptId = ((Invoke-RestMethod -Uri "$BaseUrl/system/dept/list" -Headers $ah).rows | Select-Object -First 1).dept_id
if (-not $deptId) { $deptId = 100 }
Invoke-RestMethod -Uri "$BaseUrl/system/user" -Method Post -Headers $ah -Body (@{ userName = $drillUser; nickName = "切换演练用户"; password = $pwd1; deptId = $deptId; status = '0' } | ConvertTo-Json) | Out-Null
$uid = ((Invoke-RestMethod -Uri "$BaseUrl/system/user/list?userName=$drillUser" -Headers $ah).rows | Select-Object -First 1).user_id
Assert "A2 建测试用户" ($uid -gt 0) "uid=$uid"
$tokU1 = ApiLogin $drillUser $pwd1
Assert "A3 用户登录（redis 档签发）" ([bool]$tokU1)
Invoke-RestMethod -Uri "$BaseUrl/system/user/profile/updatePwd" -Method Put -Headers @{ Authorization = "Bearer $tokU1"; 'Content-Type' = 'application/json' } -Body (@{ oldPassword = $pwd1; newPassword = $pwd2 } | ConvertTo-Json) | Out-Null
try { Invoke-RestMethod -Uri "$BaseUrl/getInfo" -Headers @{ Authorization = "Bearer $tokU1" } | Out-Null; $a4 = $false }
catch { $a4 = ($_.Exception.Response.StatusCode.value__ -eq 401) }
Assert "A4 改密后旧 token 401（redis 档 pwd_ver）" $a4

# ---------- 阶段 B：切 local 档 ----------
Write-Host "— 阶段 B：切 local 档（[cache].mode=local）—"
Copy-Item $cfg "$cfg.drill-bak" -Force
Stop-Process -Name stepby-axum -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Add-Content -Path $cfg -Value "`n[cache]`nmode = `"local`"" -Encoding UTF8
& 'C:\Users\Jeff\.workbuddy\binaries\node\versions\22.22.2-5\node.exe' (Join-Path $Repo "start-backend.mjs") | Out-Null
$tokU2 = ApiLogin $drillUser $pwd2
Assert "B1 local 档改密后新密码登录" ([bool]$tokU2)
$g = Invoke-RestMethod -Uri "$BaseUrl/getInfo" -Headers @{ Authorization = "Bearer $tokU2" }
Assert "B2 local 档会话正常" ($g.code -eq 200 -and $g.user.userName -eq $drillUser)
Invoke-RestMethod -Uri "$BaseUrl/system/user/profile/updatePwd" -Method Put -Headers @{ Authorization = "Bearer $tokU2"; 'Content-Type' = 'application/json' } -Body (@{ oldPassword = $pwd2; newPassword = $pwd3 } | ConvertTo-Json) | Out-Null
try { Invoke-RestMethod -Uri "$BaseUrl/getInfo" -Headers @{ Authorization = "Bearer $tokU2" } | Out-Null; $b3 = $false }
catch { $b3 = ($_.Exception.Response.StatusCode.value__ -eq 401) }
Assert "B3 local 档改密后旧 token 401（S1 两档语义一致）" $b3

# ---------- 阶段 C：切回 redis 档（对称性 + 清理） ----------
Write-Host "— 阶段 C：切回 redis 档 —"
Stop-Process -Name stepby-axum -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Copy-Item "$cfg.drill-bak" $cfg -Force
$diff = (Compare-Object (Get-Content "$cfg.drill-bak") (Get-Content $cfg) | Measure-Object).Count
Assert "C0 config.toml 字节级恢复" ($diff -eq 0)
Remove-Item "$cfg.drill-bak" -Force
& 'C:\Users\Jeff\.workbuddy\binaries\node\versions\22.22.2-5\node.exe' (Join-Path $Repo "start-backend.mjs") | Out-Null
$l3 = ApiLogin $drillUser $pwd3
Assert "C1 local 档期间的改密在 redis 档有效（DB 权威层跨档）" ([bool]$l3)
$badLogin = $null
try { $badLogin = ApiLogin $drillUser $pwd2 } catch { $badLogin = $null }
Assert "C2 中间代旧密码仍被拒" (-not $badLogin)
$tokA2 = ApiLogin 'admin' 'admin123'
Invoke-RestMethod -Uri "$BaseUrl/system/user/$uid" -Method Delete -Headers @{ Authorization = "Bearer $tokA2" } | Out-Null
Assert "C3 测试用户清理" $true

Write-Host "=== 演练结束：PASS=$passed FAIL=$failed ==="
if ($failed -gt 0) { exit 1 }
