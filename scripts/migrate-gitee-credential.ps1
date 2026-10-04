# gitee remote 凭据迁移一键脚本（B2 处置交付物）
# 作用：把 stepby-axum / stepby-vue 两仓 gitee remote URL 内嵌的明文 token
#       迁移到 Windows 凭据管理器（git credential），并从 URL 移除 token。
# 用法：在用户终端（PowerShell 7 / 5.1 均可）执行：
#       powershell -ExecutionPolicy Bypass -File .\scripts\migrate-gitee-credential.ps1
# 可选参数：-Repos D:\Projects\stepby\stepby-axum,D:\Projects\stepby\stepby-vue
# 回退：凭据迁移后若 push 401，可在凭据管理器删除对应条目并用原 URL 恢复
#       （脚本运行前的 remote URL 会备份到 <repo>/.git/gitee-remote-backup.txt）。

param(
    [string[]]$Repos = @(
        "D:\Projects\stepby\stepby-axum",
        "D:\Projects\stepby\stepby-vue"
    )
)

$ErrorActionPreference = "Stop"

foreach ($repo in $Repos) {
    if (-not (Test-Path (Join-Path $repo ".git"))) {
        Write-Warning "跳过（非 git 仓库）：$repo"
        continue
    }
    Push-Location $repo
    try {
        $remoteName = $null
        $url = $null
        # 优先 labs（gitee stepbylabs），其次 origin（gitcode bmate 内嵌 token 的仅本地仓）
        foreach ($name in @("labs", "origin")) {
            $u = git remote get-url $name 2>$null
            if ($LASTEXITCODE -eq 0 -and $u -and $u -match "^https://[^@/]+@") {
                $remoteName = $name
                $url = $u
                break
            }
        }
        if (-not $url) {
            Write-Host "[OK] $repo ：未发现 URL 内嵌凭据，无需迁移"
            continue
        }

        # 1. 解析 https://user:token@host/path 形态
        if ($url -match "^https://([^:/@]+):([^@]+)@([^/]+)/(.+)$") {
            $user = $Matches[1]; $token = $Matches[2]; $hostName = $Matches[3]; $path = $Matches[4]
        } elseif ($url -match "^https://([^:@]+)@([^/]+)/(.+)$") {
            $user = $Matches[1]; $token = $Matches[1]; $hostName = $Matches[2]; $path = $Matches[3]
        } else {
            Write-Warning "[SKIP] $repo ：URL 形态未识别：$url"
            continue
        }

        # 2. 备份原 URL
        $backup = Join-Path $repo ".git\gitee-remote-backup.txt"
        "$remoteName = $url  (backed up $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))" |
            Add-Content -Path $backup -Encoding UTF8

        # 3. 写入 Windows 凭据管理器（经 git credential 管道；helper=manager 落地）
        $input = "protocol=https`nhost=$hostName`nusername=$user`npassword=$token`n"
        $input | git credential approve
        if ($LASTEXITCODE -ne 0) { throw "git credential approve 失败（$repo）" }

        # 4. 重写 remote URL（去除凭据）
        $cleanUrl = "https://$hostName/$path"
        git remote set-url $remoteName $cleanUrl
        if ($LASTEXITCODE -ne 0) { throw "git remote set-url 失败（$repo）" }

        # 5. 验证 helper 通路（credential fill 应取回凭据；-c 指定 helper 避免交互）
        $query = "protocol=https`nhost=$hostName`nusername=$user`n"
        $filled = $query | git -c credential.helper=manager credential fill 2>$null
        $ok = ($LASTEXITCODE -eq 0) -and ($filled -match "password=$token")
        if ($ok) {
            Write-Host "[OK] $repo ：token 已入凭据管理器，URL 已清理为 $cleanUrl（备份：$backup）"
        } else {
            Write-Warning "[WARN] $repo ：URL 已清理但 helper 验证未通过——首次 push 时按提示输入 token 一次即可（用户 $user）"
        }
    } finally {
        Pop-Location
    }
}
Write-Host "`n完成。验证：git -C D:\Projects\stepby\stepby-axum push --dry-run labs"
