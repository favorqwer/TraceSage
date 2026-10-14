# Neo4j Desktop 实例：一键后台启动（双击同目录的 neo4j_desktop_start.cmd 即可）
#
# 作用：把 Neo4j Desktop 托管的数据库实例，以隐藏窗口的独立后台进程方式启动，
#       不依赖命令窗口，也不依赖 Desktop 界面；内存占用由实例自身配置决定（本机约 1~1.5 GB）。
# 边界：不做开机自启；同一套数据不要与 Neo4j Desktop 同时启停（一个管家原则）。

$ErrorActionPreference = "Stop"

function Find-JavaHome {
    # 自动扫描 Neo4j Desktop 自带的 Java 运行环境，按目录名中的主版本号选最新的一份
    # （例如 zulu21 优先于 zulu17；Desktop 升级后路径变化也能找到）
    $runtimeRoot = Join-Path $env:USERPROFILE ".Neo4jDesktop2\Cache\runtime"
    if (Test-Path $runtimeRoot) {
        $candidates = Get-ChildItem $runtimeRoot -Directory | Where-Object {
            Test-Path (Join-Path $_.FullName "bin\java.exe")
        } | ForEach-Object {
            $m = [regex]::Match($_.Name, '(\d+)')
            [pscustomobject]@{
                Path      = $_.FullName
                Major     = if ($m.Success) { [int]$m.Groups[1].Value } else { -1 }
                LastWrite = $_.LastWriteTime
            }
        }
        $hit = $candidates | Sort-Object Major, LastWrite -Descending | Select-Object -First 1
        if ($hit) { return $hit.Path }
    }
    throw "找不到 Neo4j Desktop 自带的 Java 运行环境（目录：$runtimeRoot）。请先在 Desktop 中创建并启动过一次实例。"
}

function Find-DbmsHome {
    # 自动定位包含 attack 场景库的实例目录
    $dbmssRoot = Join-Path $env:USERPROFILE ".Neo4jDesktop2\Data\dbmss"
    $hit = Get-ChildItem $dbmssRoot -Directory -ErrorAction SilentlyContinue | Where-Object {
        Test-Path (Join-Path $_.FullName "data\databases\attack-1-web-exploit-ransomware")
    } | Select-Object -First 1
    if ($hit) { return $hit.FullName }
    throw "找不到包含 attack 场景库的 Neo4j 实例目录（目录：$dbmssRoot）。"
}

Write-Host "== Neo4j 后台启动 =="

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "注意：当前是管理员权限窗口。由此启动的数据库进程，普通权限窗口无法停止（停止时会提示以管理员身份运行）。建议在普通窗口启动。"
}

$running = Get-NetTCPConnection -LocalPort 7687 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($running) {
    $proc = Get-Process -Id $running.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "已在运行，无需重复启动。进程号 $($proc.Id)，启动时间 $($proc.StartTime)"
    exit 0
}

$javaHome = Find-JavaHome
$dbmsHome = Find-DbmsHome
$env:JAVA_HOME = $javaHome
$logs = Join-Path $dbmsHome "logs"

Write-Host "实例目录: $dbmsHome"
Write-Host "Java 环境: $javaHome"
Write-Host "正在后台启动，最多等待 90 秒 ..."

$argLine = "/c", "`"`"$dbmsHome\bin\neo4j.bat`" console`""
Start-Process -FilePath "cmd.exe" -ArgumentList $argLine -WorkingDirectory $dbmsHome -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $logs "console-out.log") `
    -RedirectStandardError (Join-Path $logs "console-err.log") | Out-Null

$deadline = (Get-Date).AddSeconds(90)
$listening = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    $listening = Get-NetTCPConnection -LocalPort 7687 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($listening) { break }
}

if ($listening) {
    $proc = Get-Process -Id $listening.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "启动成功：端口 7687 在线，进程号 $($proc.Id)（启动时间 $($proc.StartTime)）"
    Write-Host "停止方式：双击同目录的 neo4j_desktop_stop.cmd"
    exit 0
}

Write-Host "启动失败：90 秒内端口未就绪。请查看日志："
Write-Host "  $logs\console-out.log"
Write-Host "  $logs\console-err.log"
exit 1
