$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class CephalonCollectorProbeState {
  [DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint state);
}
'@
$taskStarted = [DateTimeOffset]::UtcNow.ToString('o')
$taskHeld = [CephalonCollectorProbeState]::SetThreadExecutionState(2147483649)
if ($taskHeld -eq 0) { throw 'Cannot hold task-owned idle-sleep guard.' }
$taskExit = -1
try {
    @{ startedAtUtc=$taskStarted; automaticIdleSleepInhibited=$true; persistentPowerPlanChanged=$false } | ConvertTo-Json | Set-Content -LiteralPath 'D:/Cephalon/Cehpalon-Engine-Samples/.local/collector-probe-windows-launcher-01.json' -Encoding utf8
    & wsl -d Ubuntu --cd /mnt/d/Cephalon/Cehpalon-Engine-Samples python3 tools/probe_small_api_collector.py --dotnet /home/tom/.local/share/cehpalon-benchmark-deployment/tuning-20261028/sdk/dotnet --assembly /home/tom/.local/share/cehpalon-benchmark-deployment/collector-20261028/app-final-02/SmallApi.Benchmark.dll --server-working-directory /home/tom/.local/share/cehpalon-benchmark-deployment/collector-20261028/app-final-02 --output /home/tom/.local/share/cehpalon-benchmark-runs/collector-readiness-probe-01
    $taskExit = $LASTEXITCODE
}
finally {
    $taskReleased = [CephalonCollectorProbeState]::SetThreadExecutionState(2147483648)
    @{ startedAtUtc=$taskStarted; completedAtUtc=[DateTimeOffset]::UtcNow.ToString('o'); automaticIdleSleepInhibitedDuringRun=$true; guardReleased=($taskReleased -ne 0); persistentPowerPlanChanged=$false; exitCode=$taskExit } | ConvertTo-Json | Set-Content -LiteralPath 'D:/Cephalon/Cehpalon-Engine-Samples/.local/collector-probe-windows-launcher-01.json' -Encoding utf8
}
exit $taskExit
