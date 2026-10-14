# Neo4j Desktop 实例：一键停止（双击同目录的 neo4j_desktop_stop.cmd 即可）
#
# 作用：停止监听 7687 端口的后台数据库进程，并等待端口释放。
# 说明：因实例未安装为系统服务，官方停止命令不可用，这里按监听端口定位进程后停止；
#       进程是强制结束，Neo4j 下次启动会自动做日志恢复，数据不受影响。

$ErrorActionPreference = "Stop"

Write-Host "== Neo4j 停止 =="

$conns = Get-NetTCPConnection -LocalPort 7687 -State Listen -ErrorAction SilentlyContinue
if (-not $conns) {
    Write-Host "未在运行，无需停止。"
    exit 0
}

$procIds = $conns.OwningProcess | Select-Object -Unique
$failedIds = @()
foreach ($procId in $procIds) {
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "正在停止进程号 $procId（$($proc.ProcessName)）..."
        try {
            Stop-Process -Id $procId -Force -ErrorAction Stop
        } catch {
            $failedIds += $procId
            Write-Host "停止失败：$($_.Exception.Message)"
        }
    }
}

$deadline = (Get-Date).AddSeconds(30)
$still = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 1
    $still = Get-NetTCPConnection -LocalPort 7687 -State Listen -ErrorAction SilentlyContinue
    if (-not $still) { break }
}

if ($still) {
    if ($failedIds.Count -gt 0) {
        Write-Host ""
        Write-Host "原因：该数据库进程由更高权限的会话启动（例如管理员窗口或自动化工具），普通权限无法停止它。"
        Write-Host "解决办法（任选其一）："
        Write-Host "  1) 关闭本窗口，右键 neo4j_desktop_stop.cmd，选择「以管理员身份运行」；"
        Write-Host "  2) 在启动它的那个窗口或工具里执行停止；"
        Write-Host "  3) 在任务管理器里结束进程号 $($failedIds -join '、')。"
    } else {
        Write-Host "端口 7687 仍被占用，请重试或检查任务管理器。"
    }
    exit 1
}

Write-Host "已停止，端口 7687 已释放。"
exit 0
